use crate::errors::{DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionRequest, ClientGreeting,
    ClientUsernamePassword, ServerChoice, ServerResponse, ServerResponseStatus,
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
                if let Some(authed_stream) =
                    run_authentication(params, stream, their_addr.clone(), their_port).await
                {
                    if let Err(e) = run_main_loop(network_mutex_copy, authed_stream).await {
                        warn!("Failure in main loop: {}", e);
                    }
                }
            });
        }
    }
}

async fn run_authentication(
    params: SecurityParameters,
    mut stream: GenericStream,
    addr: SOCKSv5Address,
    port: u16,
) -> Option<GenericStream> {
    match ClientGreeting::read(&mut stream).await {
        Err(e) => {
            error!(
                "Client hello deserialization error from {}:{}:  {}",
                addr, port, e
            );
            None
        }

        // So we get opinionated here, based on what we think should be our first choice if the
        // server offers something up. So we'll first see if we can make this a TLS connection.
        Ok(cg)
            if cg.acceptable_methods.contains(&AuthenticationMethod::SSL)
                && params.connect_tls.is_some() =>
        {
            match params.connect_tls {
                None => {
                    error!("Internal error: TLS handler was there, but is now gone");
                    None
                }
                Some(converter) => match converter(stream) {
                    None => {
                        info!("Rejecting bad TLS handshake from {}:{}", addr, port);
                        None
                    }
                    Some(new_stream) => Some(new_stream),
                },
            }
        }

        // if we can't do that, we'll see if we can get a username and password
        Ok(cg)
            if cg
                .acceptable_methods
                .contains(&AuthenticationMethod::UsernameAndPassword)
                && params.check_password.is_some() =>
        {
            match ClientUsernamePassword::read(&mut stream).await {
                Err(e) => {
                    warn!(
                        "Error reading username/password from {}:{}: {}",
                        addr, port, e
                    );
                    None
                }
                Ok(userinfo) => {
                    let checker = params.check_password.unwrap_or(|_, _| false);
                    if checker(&userinfo.username, &userinfo.password) {
                        Some(stream)
                    } else {
                        None
                    }
                }
            }
        }

        // and, in the worst case, we'll see if our user is cool with unauthenticated connections
        Ok(cg)
            if cg.acceptable_methods.contains(&AuthenticationMethod::None)
                && params.allow_unauthenticated =>
        {
            Some(stream)
        }

        Ok(_) => {
            let rejection_letter = ServerChoice {
                chosen_method: AuthenticationMethod::NoAcceptableMethods,
            };

            if let Err(e) = rejection_letter.write(&mut stream).await {
                warn!(
                    "Error sending rejection letter in authentication response: {}",
                    e
                );
            }

            if let Err(e) = stream.flush().await {
                warn!(
                    "Error flushing buffer after rejection latter in authentication response: {}",
                    e
                );
            }

            None
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
