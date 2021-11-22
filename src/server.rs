//! An implementation of a SOCKSv5 server, parameterizable by the security parameters
//! and network stack you want to use. You should implement the server by first
//! setting up the `SecurityParameters`, then initializing the server object, and
//! then running it, as follows:
//!
//! ```
//! use async_socks5::network::Builtin;
//! use async_socks5::server::{SecurityParameters, SOCKSv5Server};
//! use std::io;
//!
//! async {
//!     let parameters = SecurityParameters::new()
//!                                        .password_check(|u,p| { u == "adam" && p == "evil" });
//!     let network = Builtin::new();
//!     let server = SOCKSv5Server::new(network, parameters);
//!     server.start("localhost", 9999).await;
//!     // ... do other stuff ...
//! };
//!
//! ```
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
use futures::Stream;
use log::{error, info, trace, warn};
use std::collections::HashMap;
use std::default::Default;
use std::fmt::{Debug, Display};
use thiserror::Error;

/// A convenient bit of shorthand for an address and port
pub type AddressAndPort = (SOCKSv5Address, u16);

// Just some shorthand for us.
type ResultHandle = task::JoinHandle<Result<(), String>>;

/// A handle representing a SOCKSv5 server, parameterized by the underlying network
/// stack it runs over.
#[derive(Clone)]
pub struct SOCKSv5Server<N: Networklike> {
    network: Arc<Mutex<N>>,
    running_servers: Arc<Mutex<HashMap<AddressAndPort, ResultHandle>>>,
    security_parameters: SecurityParameters,
}

/// The security parameters that you can assign to the server, to make decisions
/// about the weirdos it accepts as users. It is recommended that you only use
/// wide open connections when you're 100% sure that the server will only be
/// accessible locally.
#[derive(Clone)]
pub struct SecurityParameters {
    /// Allow completely unauthenticated connections. You should be very, very
    /// careful about setting this to true, especially if you don't provide a
    /// guard to ensure that you're getting connections from reasonable places.
    pub allow_unauthenticated: bool,
    /// An optional function that can serve as a firewall for new connections.
    /// Return true if the connection should be allowed to continue, false if
    /// it shouldn't. This check happens before any data is read from or written
    /// to the connecting party.
    pub allow_connection: Option<fn(&SOCKSv5Address, u16) -> bool>,
    /// An optional function to check a user name (first argument) and password
    /// (second argument). Return true if the username / password is good, false
    /// if not.
    pub check_password: Option<fn(&str, &str) -> bool>,
    /// An optional function to transition the stream from an unencrypted one to
    /// an encrypted on. The assumption is you're using something like `rustls`
    /// to make this happen; the exact mechanism is outside the scope of this
    /// particular crate. If the connection shouldn't be allowed for some reason
    /// (a bad certificate or handshake, for example), then return None; otherwise,
    /// return the new stream.
    pub connect_tls: Option<fn(GenericStream) -> Option<GenericStream>>,
}

impl SecurityParameters {
    /// Generates a `SecurityParameters` object that's empty. It won't accept
    /// anything, because it has no mechanisms it can use to actually authenticate
    /// a user and yet won't allow unauthenticated connections.
    pub fn new() -> SecurityParameters {
        SecurityParameters {
            allow_unauthenticated: false,
            allow_connection: None,
            check_password: None,
            connect_tls: None,
        }
    }

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

    /// Use the provided function to check incoming connections before proceeding
    /// with the rest of the handshake.
    pub fn check_connections(
        mut self,
        checker: fn(&SOCKSv5Address, u16) -> bool,
    ) -> SecurityParameters {
        self.allow_connection = Some(checker);
        self
    }

    /// Use the provided function to check usernames and passwords provided
    /// to the server.
    pub fn password_check(mut self, checker: fn(&str, &str) -> bool) -> SecurityParameters {
        self.check_password = Some(checker);
        self
    }

    /// Use the provide function to validate a TLS connection, and transition it
    /// to the new stream type. If the handshake fails, return `None` instead of
    /// `Some`. (And maybe log it somewhere, you know.)
    pub fn tls_converter(
        mut self,
        converter: fn(GenericStream) -> Option<GenericStream>,
    ) -> SecurityParameters {
        self.connect_tls = Some(converter);
        self
    }
}

impl Default for SecurityParameters {
    fn default() -> Self {
        Self::new()
    }
}

impl<N: Networklike + Clone + Send + 'static> SOCKSv5Server<N> {
    /// Initialize a SOCKSv5 server for use later on. Once initialize, you can listen on
    /// as many addresses and ports as you like; the metadata about the server will be
    /// sync'd across all of the instances, should you want to gather that data for some
    /// reason.
    pub fn new(network: N, security_parameters: SecurityParameters) -> SOCKSv5Server<N> {
        SOCKSv5Server {
            network: Arc::new(Mutex::new(network)),
            running_servers: Arc::new(Mutex::new(HashMap::new())),
            security_parameters,
        }
    }

    /// Start a server on the given address and port. This function returns when it has
    /// set up its listening socket, but spawns a separate task to actually wait for
    /// connections. You can query which ones are still active, or see which ones have
    /// failed, using some of the other items in this structure.
    pub async fn start<A: Send + Into<SOCKSv5Address>>(
        &self,
        addr: A,
        port: u16,
    ) -> Result<(), N::Error> {
        // This might seem a little weird, but we do this in a separate block to make it
        // as clear as possible to the borrow checker (and the reader) that we only want
        // to hold the lock while we're actually calling listen.
        let listener = {
            let mut network = self.network.lock().await;
            network.listen(addr, port).await
        }?;

        // this should really be the same as the input, but technically they could've
        // thrown some zeros in there and let the underlying network stack decide. So
        // we'll just pull this information post-initialization, and maybe get something
        // a bit more detailed.
        let (my_addr, my_port) = listener.local_addr();
        info!("Starting SOCKSv5 server on {}:{}", my_addr, my_port);

        // OK, spawn off the server loop, and then we'll register this in our list of
        // things running.
        let new_self = self.clone();
        let task_id = task::spawn(async move {
            new_self
                .server_loop(listener)
                .await
                .map_err(|x| format!("Server network error: {}", x))
        });

        let mut server_map = self.running_servers.lock().await;
        server_map.insert((my_addr, my_port), task_id);

        Ok(())
    }

    /// Provide a list of open sockets on the server.
    pub async fn open_sockets(&self) -> Vec<AddressAndPort> {
        let server_map = self.running_servers.lock().await;
        server_map.keys().cloned().collect()
    }

    pub fn subserver_results(&mut self) -> impl Stream<Item = Result<(), String>> {
        futures::stream::unfold(self.running_servers.clone(), |locked_map| async move {
            let first_server = {
                let mut server_map = locked_map.lock().await;
                let first_key = server_map.keys().next().cloned()?;

                server_map.remove(&first_key)
            }?;

            let result = first_server.await;
            Some((result, locked_map))
        })
    }

    async fn server_loop(self, listener: GenericListener<N::Error>) -> Result<(), N::Error> {
        loop {
            let (stream, their_addr, their_port) = listener.accept().await?;
            trace!(
                "Initial accept of connection from {}:{}",
                their_addr,
                their_port
            );

            // before we do anything, make sure this connection is cool. we don't want to
            // waste resources (or parse any data) if this isn't someone we actually care
            // about it.
            if let Some(checker) = &self.security_parameters.allow_connection {
                if !checker(&their_addr, their_port) {
                    info!(
                        "Rejecting attempted connection from {}:{}",
                        their_addr, their_port
                    );
                    continue;
                }
            }

            // throw this off into another task to take from here. We could to the rest
            // of this handshake here, but there's a chance that an adversarial connection
            // could just stall us out, and keep us from doing the next connection. So ...
            // we'll potentially spin off the task early.
            let me_again = self.clone();
            task::spawn(async move {
                me_again
                    .authenticate_step(their_addr, their_port, stream)
                    .await;
            });
        }
    }

    async fn authenticate_step(
        self,
        their_addr: SOCKSv5Address,
        their_port: u16,
        base_stream: GenericStream,
    ) {
        // Turn this stream into one where we've authenticated the other side. Or, you
        // know, don't, and just restart this loop.
        let mut authenticated_stream =
            match run_authentication(&self.security_parameters, base_stream).await {
                Ok(authed_stream) => authed_stream,
                Err(e) => {
                    warn!(
                        "Failure running authentication from {}:{}: {}",
                        their_addr, their_port, e
                    );
                    return;
                }
            };

        // Figure out what the client actually wants from this connection, and
        // then dispatch a task to deal with that.
        let mccr = ClientConnectionRequest::read(&mut authenticated_stream).await;
        match mccr {
            Err(e) => warn!("Failure figuring out what the client wanted: {}", e),
            Ok(ccr) => match ccr.command_code {
                ClientConnectionCommand::AssociateUDPPort => self
                    .handle_udp_request(authenticated_stream, ccr, their_addr, their_port)
                    .await
                    .unwrap_or_else(|e| warn!("Internal server error in UDP association: {}", e)),
                ClientConnectionCommand::EstablishTCPPortBinding => self
                    .handle_tcp_bind(authenticated_stream, ccr, their_addr, their_port)
                    .await
                    .unwrap_or_else(|e| warn!("Internal server error in TCP bind: {}", e)),
                ClientConnectionCommand::EstablishTCPStream => self
                    .handle_tcp_forward(authenticated_stream, ccr, their_addr, their_port)
                    .await
                    .unwrap_or_else(|e| warn!("Internal server error in TCP forward: {}", e)),
            },
        }
    }

    async fn handle_udp_request(
        self,
        stream: GenericStream,
        ccr: ClientConnectionRequest,
        their_addr: SOCKSv5Address,
        their_port: u16,
    ) -> Result<(), ServerError<N::Error>> {
        // Let the user know that we're maybe making progress
        let (my_addr, my_port) = stream.local_addr();
        info!(
            "[{}:{}] Handling UDP bind request from {}:{}, seeking to bind {}:{}",
            my_addr, my_port, their_addr, their_port, ccr.destination_address, ccr.destination_port
        );

        unimplemented!()
    }

    async fn handle_tcp_forward(
        self,
        mut stream: GenericStream,
        ccr: ClientConnectionRequest,
        their_addr: SOCKSv5Address,
        their_port: u16,
    ) -> Result<(), ServerError<N::Error>> {
        // Let the user know that we're maybe making progress
        let (my_addr, my_port) = stream.local_addr();
        info!(
            "[{}:{}] Handling TCP forward request from {}:{}, seeking to connect to {}:{}",
            my_addr, my_port, their_addr, their_port, ccr.destination_address, ccr.destination_port
        );

        // OK, first thing's first: We need to actually connect to the server that the user
        // wants us to connect to.
        let connection_res = {
            let mut network = self.network.lock().await;
            network
                .connect(ccr.destination_address.clone(), ccr.destination_port)
                .await
        };

        let outgoing_stream = match connection_res {
            Ok(x) => x,
            Err(e) => {
                error!("Failed to connect to {}: {}", ccr.destination_address, e);
                let response = ServerResponse::error(&e);
                response.write(&mut stream).await?;
                return Err(ServerError::NetworkError(e));
            }
        };

        trace!(
            "Connection established to {}:{}",
            ccr.destination_address,
            ccr.destination_port
        );

        // Now, for whatever reason -- and this whole thing sent me down a garden path
        // in understanding how this whole protocol works -- we tell the user what address
        // and port we bound for that connection.
        let (bound_address, bound_port) = outgoing_stream.local_addr();
        let response = ServerResponse {
            status: ServerResponseStatus::RequestGranted,
            bound_address,
            bound_port,
        };
        response.write(&mut stream).await?;

        // Now that we've informed them of that, we set up one task to transfer information
        // from the current stream (`stream`) to the connection (`outgoing_stream`), and
        // another task that goes in the reverse direction.
        //
        // I've chosen to start two fresh tasks and let this one die; I'm not sure that
        // this is the right approach. My only rationale is that this might let some
        // memory we might have accumulated along the way drop more easily, but that
        // might not actually matter.
        let mut from_left = stream.clone();
        let mut from_right = outgoing_stream.clone();
        let mut to_left = stream;
        let mut to_right = outgoing_stream;
        let from = format!("{}:{}", their_addr, their_port);
        let to = format!("{}:{}", ccr.destination_address, ccr.destination_port);

        task::spawn(async move {
            info!(
                "Spawned {}:{} >--> {}:{} task",
                their_addr, their_port, ccr.destination_address, ccr.destination_port
            );
            if let Err(e) = io::copy(&mut from_left, &mut to_right).await {
                warn!(
                    "{}:{} >--> {}:{} connection failed with: {}",
                    their_addr, their_port, ccr.destination_address, ccr.destination_port, e
                );
            }
        });

        task::spawn(async move {
            info!("Spawned {} <--< {} task", from, to);
            if let Err(e) = io::copy(&mut from_right, &mut to_left).await {
                warn!("{} <--< {} connection failed with: {}", from, to, e);
            }
        });

        Ok(())
    }

    async fn handle_tcp_bind(
        self,
        stream: GenericStream,
        ccr: ClientConnectionRequest,
        their_addr: SOCKSv5Address,
        their_port: u16,
    ) -> Result<(), ServerError<N::Error>> {
        // Let the user know that we're maybe making progress
        let (my_addr, my_port) = stream.local_addr();
        info!(
            "[{}:{}] Handling UDP bind request from {}:{}, seeking to bind {}:{}",
            my_addr, my_port, their_addr, their_port, ccr.destination_address, ccr.destination_port
        );

        unimplemented!()
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
    params: &SecurityParameters,
    mut stream: GenericStream,
) -> Result<GenericStream, AuthenticationError> {
    let greeting = ClientGreeting::read(&mut stream).await?;

    match choose_authentication_method(params, &greeting.acceptable_methods) {
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
pub enum ServerError<E: Debug + Display> {
    #[error("Error in deserialization: {0}")]
    DeserializationError(#[from] DeserializationError),
    #[error("Error in serialization: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("Underlying network error: {0}")]
    NetworkError(E),
}
