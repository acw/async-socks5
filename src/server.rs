use crate::errors::{AuthenticationError, DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionRequest, ClientGreeting,
    ClientUsernamePassword, ServerAuthResponse, ServerChoice, ServerResponse, ServerResponseStatus,
};
use crate::network::address::HasLocalAddress;
use crate::network::generic::Networklike;
use crate::network::listener::{GenericListener, Listenerlike};
use crate::network::stream::GenericStream;
use crate::network::SOCKSv5Address;
use async_std::io;
use async_std::io::prelude::WriteExt;
use async_std::sync::{Arc, Mutex};
use async_std::task;
use log::{error, info, trace, warn};
use thiserror::Error;

pub struct SOCKSv5Server<N: Networklike> {
    network: N,
    security_parameters: SecurityParameters,
    listener: GenericListener<N::Error>,
}

#[derive(Clone)]
pub struct SecurityParameters {
    pub allow_unauthenticated: bool,
    pub allow_connection: Option<fn(&SOCKSv5Address, u16) -> bool>,
    pub check_password: Option<fn(&str, &str) -> bool>,
    pub connect_tls: Option<fn(GenericStream) -> Option<GenericStream>>,
}

impl SecurityParameters {
    /// Generates a `SecurityParameters` object that does not, in any way,
    /// restrict who can log in. It also will not induce any transition into
    /// TLS. Use this at your own risk ... or, really, just don't use this,
    /// ever, and certainly not in production.
    pub fn unrestricted() -> SecurityParameters {
        SecurityParameters {
            allow_unauthenticated: true,
            allow_connection: None,
            check_password: None,
            connect_tls: None,
        }
    }
}

impl<N: Networklike + Send + 'static> SOCKSv5Server<N> {
    pub fn new<S: Listenerlike<Error = N::Error> + 'static>(
        network: N,
        security_parameters: SecurityParameters,
        stream: S,
    ) -> SOCKSv5Server<N> {
        SOCKSv5Server {
            network,
            security_parameters,
            listener: GenericListener {
                internal: Box::new(stream),
            },
        }
    }

    pub async fn run(self) -> Result<(), N::Error> {
        let (my_addr, my_port) = self.listener.local_addr();
        info!("Starting SOCKSv5 server on {}:{}", my_addr, my_port);
        let locked_network = Arc::new(Mutex::new(self.network));

        loop {
            let (stream, their_addr, their_port) = self.listener.accept().await?;

            trace!(
                "Initial accept of connection from {}:{}",
                their_addr,
                their_port
            );
            if let Some(checker) = &self.security_parameters.allow_connection {
                if !checker(&their_addr, their_port) {
                    info!(
                        "Rejecting attempted connection from {}:{}",
                        their_addr, their_port
                    );
                    continue;
                }
            }

            let params = self.security_parameters.clone();
            let network_mutex_copy = locked_network.clone();
            task::spawn(async move {
                match run_authentication(params, stream).await {
                    Ok(authed_stream) => {
                        match run_main_loop(network_mutex_copy, authed_stream).await {
                            Ok(_) => {}
                            Err(e) => warn!("Failure in main loop: {}", e),
                        }
                    }
                    Err(e) => warn!(
                        "Failure running authentication from {}:{}: {}",
                        their_addr, their_port, e
                    ),
                }
            });
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
enum ChosenMethod {
    TLS(fn(GenericStream) -> Option<GenericStream>),
    Password(fn(&str, &str) -> bool),
    None,
}

impl From<ChosenMethod> for AuthenticationMethod {
    fn from(x: ChosenMethod) -> Self {
        match x {
            ChosenMethod::TLS(_) => AuthenticationMethod::SSL,
            ChosenMethod::Password(_) => AuthenticationMethod::UsernameAndPassword,
            ChosenMethod::None => AuthenticationMethod::None,
        }
    }
}

// This is an opinionated function that tries to pick the most security-advantageous
// authentication method that we can handle and our peer will be willing to accept.
// If we find one we like, we return it. If we can't, we return `None`.
fn choose_authentication_method(
    params: &SecurityParameters,
    client_suggestions: &[AuthenticationMethod],
) -> Option<ChosenMethod> {
    // First: everything is better with encryption. So if they offer it, and we can
    // support it, we choose TLS.
    if client_suggestions.contains(&AuthenticationMethod::SSL) {
        if let Some(converter) = params.connect_tls {
            return Some(ChosenMethod::TLS(converter));
        }
    }

    // If they've got a username and password to give us, and we've got something
    // that will check them, then let's use that.
    if client_suggestions.contains(&AuthenticationMethod::UsernameAndPassword) {
        if let Some(matcher) = params.check_password {
            return Some(ChosenMethod::Password(matcher));
        }
    }

    // Meh. OK, if we're both cool with an unauthenticated session, I guess we can
    // do that.
    if client_suggestions.contains(&AuthenticationMethod::None) && params.allow_unauthenticated {
        return Some(ChosenMethod::None);
    }

    // if we get all the way here, there was nothing for us to settle on, so we
    // give up.
    None
}

#[test]
fn reasonable_auth_method_choices() {
    let mut params = SecurityParameters::unrestricted();
    let mut client_suggestions = Vec::new();

    // if the client's a jerk and send us nothing, we should get nothing, no matter what.
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );
    // but if they send us none, then we're cool with that with the unrestricted item.
    client_suggestions.push(AuthenticationMethod::None);
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::None)
    );
    // of course, if we set ourselves back to not allowing randos ... which we should do ...
    // then we should get none again, even if the client's OK with it.
    params.allow_unauthenticated = false;
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );

    // Even if we allow unauthenticated sessions, though, we'll take a username and password
    // if someone will give them to us.
    params.allow_unauthenticated = true;
    params.check_password = Some(|_, _| true);
    client_suggestions.push(AuthenticationMethod::UsernameAndPassword);
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::UsernameAndPassword)
    );
    // which shouldn't matter if we turn off unauthenticated connections
    params.allow_unauthenticated = false;
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::UsernameAndPassword)
    );
    // ... or whether we don't offer None
    client_suggestions.remove(0);
    // That being said, if we don't have a way to check a password, we're hooped
    params.check_password = None;
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );
    // Or, come to think of it, if we have a way to check a password, but they don't offer it up
    params.check_password = Some(|_, _| true);
    client_suggestions[0] = AuthenticationMethod::None;
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );

    // OK, cool. If we have a TLS handler, that shouldn't actually make a difference.
    params.connect_tls = Some(|_| unimplemented!());
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );
    // or if they suggest it, but we don't have one: same deal
    params.connect_tls = None;
    client_suggestions[0] = AuthenticationMethod::SSL;
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        None
    );
    // but if we have a handler, and they go for it, we use it.
    params.connect_tls = Some(|_| unimplemented!());
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::SSL)
    );
    // even if the client's cool with passwords and we can handle it
    params.check_password = Some(|_, _| true);
    client_suggestions.push(AuthenticationMethod::UsernameAndPassword);
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::SSL)
    );
    // even if they offer nothing at all and we're cool with it.
    params.allow_unauthenticated = true;
    client_suggestions.push(AuthenticationMethod::None);
    assert_eq!(
        choose_authentication_method(&params, &client_suggestions).map(AuthenticationMethod::from),
        Some(AuthenticationMethod::SSL)
    );
}

async fn run_authentication(
    params: SecurityParameters,
    mut stream: GenericStream,
) -> Result<GenericStream, AuthenticationError> {
    let greeting = ClientGreeting::read(&mut stream).await?;

    match choose_authentication_method(&params, &greeting.acceptable_methods) {
        // it's not us, it's you
        None => {
            trace!("Failed to find acceptable authentication method.");
            let rejection_letter = ServerChoice::rejection();

            rejection_letter.write(&mut stream).await?;
            stream.flush().await?;

            Err(AuthenticationError::ItsNotUsItsYou)
        }

        // the gold standard. great choice.
        Some(ChosenMethod::TLS(converter)) => {
            trace!("Choosing TLS for authentication.");
            let lets_do_this = ServerChoice::option(AuthenticationMethod::SSL);
            lets_do_this.write(&mut stream).await?;
            stream.flush().await?;

            converter(stream).ok_or(AuthenticationError::FailedTLSHandshake)
        }

        // well, I guess this is something?
        Some(ChosenMethod::Password(checker)) => {
            trace!("Choosing Username/Password for authentication.");
            let ok_lets_do_password =
                ServerChoice::option(AuthenticationMethod::UsernameAndPassword);
            ok_lets_do_password.write(&mut stream).await?;
            stream.flush().await?;

            let their_info = ClientUsernamePassword::read(&mut stream).await?;
            if checker(&their_info.username, &their_info.password) {
                let its_all_good = ServerAuthResponse::success();
                its_all_good.write(&mut stream).await?;
                stream.flush().await?;
                Ok(stream)
            } else {
                let yeah_no = ServerAuthResponse::failure();
                yeah_no.write(&mut stream).await?;
                stream.flush().await?;
                Err(AuthenticationError::FailedUsernamePassword(
                    their_info.username,
                ))
            }
        }

        Some(ChosenMethod::None) => {
            trace!("Just skipping the whole authentication thing.");
            let nothin_i_guess = ServerChoice::option(AuthenticationMethod::None);
            nothin_i_guess.write(&mut stream).await?;
            stream.flush().await?;
            Ok(stream)
        }
    }
}

#[derive(Error, Debug)]
enum ServerError {
    #[error("Error in deserialization: {0}")]
    DeserializationError(#[from] DeserializationError),
    #[error("Error in serialization: {0}")]
    SerializationError(#[from] SerializationError),
}

async fn run_main_loop<N>(
    network: Arc<Mutex<N>>,
    mut stream: GenericStream,
) -> Result<(), ServerError>
where
    N: Networklike,
    N::Error: 'static,
{
    loop {
        let ccr = ClientConnectionRequest::read(&mut stream).await?;

        match ccr.command_code {
            ClientConnectionCommand::AssociateUDPPort => {}

            ClientConnectionCommand::EstablishTCPPortBinding => {}

            ClientConnectionCommand::EstablishTCPStream => {
                let target = format!("{}:{}", ccr.destination_address, ccr.destination_port);

                info!(
                    "Client requested connection to {}:{}",
                    ccr.destination_address, ccr.destination_port
                );
                let connection_res = {
                    let mut network = network.lock().await;
                    network
                        .connect(ccr.destination_address.clone(), ccr.destination_port)
                        .await
                };
                let outgoing_stream = match connection_res {
                    Ok(x) => x,
                    Err(e) => {
                        error!("Failed to connect to {}: {}", target, e);
                        let response = ServerResponse::error(e);
                        response.write(&mut stream).await?;
                        continue;
                    }
                };
                trace!(
                    "Connection established to {}:{}",
                    ccr.destination_address,
                    ccr.destination_port
                );

                let incoming_res = {
                    let mut network = network.lock().await;
                    network.listen("127.0.0.1", 0).await
                };
                let incoming_listener = match incoming_res {
                    Ok(x) => x,
                    Err(e) => {
                        error!("Failed to bind server port for new TCP stream: {}", e);
                        let response = ServerResponse::error(e);
                        response.write(&mut stream).await?;
                        continue;
                    }
                };
                let (bound_address, bound_port) = incoming_listener.local_addr();
                trace!(
                    "Set up {}:{} to address request for {}:{}",
                    bound_address,
                    bound_port,
                    ccr.destination_address,
                    ccr.destination_port
                );

                let response = ServerResponse {
                    status: ServerResponseStatus::RequestGranted,
                    bound_address,
                    bound_port,
                };
                response.write(&mut stream).await?;

                task::spawn(async move {
                    let (incoming_stream, from_addr, from_port) = match incoming_listener
                        .accept()
                        .await
                    {
                        Err(e) => {
                            error!("Miscellaneous error waiting for someone to connect for proxying: {}", e);
                            return;
                        }
                        Ok(s) => s,
                    };
                    trace!(
                        "Accepted connection from {}:{} to attach to {}:{}",
                        from_addr,
                        from_port,
                        ccr.destination_address,
                        ccr.destination_port
                    );

                    let mut from_left = incoming_stream.clone();
                    let mut from_right = outgoing_stream.clone();
                    let mut to_left = incoming_stream;
                    let mut to_right = outgoing_stream;
                    let from = format!("{}:{}", from_addr, from_port);
                    let to = format!("{}:{}", ccr.destination_address, ccr.destination_port);

                    task::spawn(async move {
                        info!(
                            "Spawned {}:{} >--> {}:{} task",
                            from_addr, from_port, ccr.destination_address, ccr.destination_port
                        );
                        if let Err(e) = io::copy(&mut from_left, &mut to_right).await {
                            warn!(
                                "{}:{} >--> {}:{} connection failed with: {}",
                                from_addr,
                                from_port,
                                ccr.destination_address,
                                ccr.destination_port,
                                e
                            );
                        }
                    });

                    task::spawn(async move {
                        info!("Spawned {} <--< {} task", from, to);
                        if let Err(e) = io::copy(&mut from_right, &mut to_left).await {
                            warn!("{} <--< {} connection failed with: {}", from, to, e);
                        }
                    });
                });
            }
        }
    }
}
