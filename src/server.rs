use std::net::SocketAddr;

use crate::address::SOCKSv5Address;
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionCommandReadError,
    ClientConnectionRequest, ClientConnectionRequestReadError, ClientGreeting,
    ClientGreetingReadError, ClientUsernamePassword, ClientUsernamePasswordReadError,
    ServerAuthResponse, ServerAuthResponseWriteError, ServerChoice, ServerChoiceWriteError,
    ServerResponse, ServerResponseStatus, ServerResponseWriteError,
};
use crate::security_parameters::SecurityParameters;
use thiserror::Error;
use tokio::io::{copy_bidirectional, AsyncWriteExt};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

#[derive(Clone)]
pub struct SOCKSv5Server {
    security_parameters: SecurityParameters,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SOCKSv5ServerError {
    #[error("Underlying networking error: {0}")]
    NetworkingError(String),
    #[error("Couldn't negotiate authentication with client.")]
    ItsNotUsItsYou,
    #[error("Client greeting read problem: {0}")]
    GreetingReadProblem(#[from] ClientGreetingReadError),
    #[error("Server choice write problem: {0}")]
    ChoiceWriteProblem(#[from] ServerChoiceWriteError),
    #[error("Failed username/password authentication for user {0}")]
    FailedUsernamePassword(String),
    #[error("Server authentication response problem: {0}")]
    ServerAuthWriteProblem(#[from] ServerAuthResponseWriteError),
    #[error("Error reading client username/password: {0}")]
    UserPassReadProblem(#[from] ClientUsernamePasswordReadError),
    #[error("Error reading client connection command: {0}")]
    ClientConnReadProblem(#[from] ClientConnectionCommandReadError),
    #[error("Error reading client connection request: {0}")]
    ClientRequestReadProblem(#[from] ClientConnectionRequestReadError),
    #[error("Error writing server response: {0}")]
    ServerResponseWriteProblem(#[from] ServerResponseWriteError),
}

impl From<std::io::Error> for SOCKSv5ServerError {
    fn from(x: std::io::Error) -> SOCKSv5ServerError {
        SOCKSv5ServerError::NetworkingError(format!("{}", x))
    }
}

impl SOCKSv5Server {
    /// Initialize a SOCKSv5 server for use later on. Once initialized, you can listen
    /// on as many addresses and ports as you like; the metadata about the server will
    /// be synced across all the instances.
    pub fn new(security_parameters: SecurityParameters) -> Self {
        SOCKSv5Server {
            security_parameters,
        }
    }

    /// Start a server on the given address and port. This function returns when it has
    /// set up its listening socket, but spawns a separate task to actually wait for
    /// connections. You can query which ones are still active, or see which ones have
    /// failed, using some of the other functions for this structure.
    ///
    /// If you don't care what port is assigned to this server, pass 0 in as the port
    /// number and one will be chosen for you by the OS.
    ///
    pub async fn start<A: Send + Into<SOCKSv5Address>>(
        &self,
        addr: A,
        port: u16,
    ) -> Result<(), std::io::Error> {
        let listener = match addr.into() {
            SOCKSv5Address::IP4(x) => TcpListener::bind((x, port)).await?,
            SOCKSv5Address::IP6(x) => TcpListener::bind((x, port)).await?,
            SOCKSv5Address::Hostname(x) => TcpListener::bind((x, port)).await?,
        };

        let sockaddr = listener.local_addr()?;
        tracing::info!(
            "Starting SOCKSv5 server on {}:{}",
            sockaddr.ip(),
            sockaddr.port()
        );

        let second_life = self.clone();

        tokio::task::spawn(async move {
            if let Err(e) = second_life.server_loop(listener).await {
                tracing::error!(
                    "{}:{}: server network error: {}",
                    sockaddr.ip(),
                    sockaddr.port(),
                    e
                );
            }
        });

        Ok(())
    }

    /// Run the server loop for a particular listener. This routine will never actually
    /// return except in error conditions.
    async fn server_loop(self, listener: TcpListener) -> Result<(), std::io::Error> {
        loop {
            let (socket, their_addr) = listener.accept().await?;

            // before we do anything of note, make sure this connection is cool. we don't want
            // to waste any resources (and certainly don't want to handle any data!) if this
            // isn't someone we want to accept connections from.
            tracing::trace!("Initial accept of connection from {}", their_addr);
            if let Some(checker) = self.security_parameters.allow_connection {
                if !checker(&their_addr) {
                    tracing::info!("Rejecting attempted connection from {}", their_addr,);
                }
                continue;
            }

            // continue this work in another task. we could absolutely do this work here,
            // but just in case someone starts doing slow responses (or other nasty things),
            // we want to make sure that that doesn't slow down our ability to accept other
            // requests.
            let me_again = self.clone();
            tokio::task::spawn(async move {
                if let Err(e) = me_again.start_authentication(their_addr, socket).await {
                    tracing::error!("{}: server handler failure: {}", their_addr, e);
                }
            });
        }
    }

    /// Start the authentication phase of the SOCKS handshake. This may be very short, and
    /// is the first stage of handling a request. This will only really return on errors.
    async fn start_authentication(
        self,
        their_addr: SocketAddr,
        mut socket: TcpStream,
    ) -> Result<(), SOCKSv5ServerError> {
        let greeting = ClientGreeting::read(&mut socket).await?;

        match choose_authentication_method(&self.security_parameters, &greeting.acceptable_methods)
        {
            // it's not us, it's you. (we're just going to say no.)
            None => {
                tracing::trace!(
                    "{}: Failed to find acceptable authentication method.",
                    their_addr,
                );
                let rejection_letter = ServerChoice::rejection();

                rejection_letter.write(&mut socket).await?;
                socket.flush().await?;

                Err(SOCKSv5ServerError::ItsNotUsItsYou)
            }

            // the gold standard. great choice.
            Some(ChosenMethod::TLS(_converter)) => {
                unimplemented!()
            }

            // well, I guess this is something?
            Some(ChosenMethod::Password(checker)) => {
                tracing::trace!(
                    "{}: Choosing username/password for authentication.",
                    their_addr,
                );
                let ok_lets_do_password =
                    ServerChoice::option(AuthenticationMethod::UsernameAndPassword);
                ok_lets_do_password.write(&mut socket).await?;
                socket.flush().await?;

                let their_info = ClientUsernamePassword::read(&mut socket).await?;
                if checker(&their_info.username, &their_info.password) {
                    let its_all_good = ServerAuthResponse::success();
                    its_all_good.write(&mut socket).await?;
                    socket.flush().await?;
                    self.choose_mode(socket, their_addr).await
                } else {
                    let yeah_no = ServerAuthResponse::failure();
                    yeah_no.write(&mut socket).await?;
                    socket.flush().await?;
                    Err(SOCKSv5ServerError::FailedUsernamePassword(
                        their_info.username,
                    ))
                }
            }

            // Um. I guess we're doing this unchecked. Yay?
            Some(ChosenMethod::None) => {
                tracing::trace!(
                    "{}: Just skipping the whole authentication thing.",
                    their_addr,
                );
                let nothin_i_guess = ServerChoice::option(AuthenticationMethod::None);
                nothin_i_guess.write(&mut socket).await?;
                socket.flush().await?;
                self.choose_mode(socket, their_addr).await
            }
        }
    }

    /// Determine which of the modes we might want this particular connection to run
    /// in.
    async fn choose_mode(
        self,
        mut socket: TcpStream,
        their_addr: SocketAddr,
    ) -> Result<(), SOCKSv5ServerError> {
        let ccr = ClientConnectionRequest::read(&mut socket).await?;
        match ccr.command_code {
            ClientConnectionCommand::AssociateUDPPort => {
                self.handle_udp_request(socket, their_addr, ccr).await?
            }
            ClientConnectionCommand::EstablishTCPStream => {
                self.handle_tcp_request(socket, their_addr, ccr).await?
            }
            ClientConnectionCommand::EstablishTCPPortBinding => {
                self.handle_tcp_binding_request(socket, their_addr, ccr)
                    .await?
            }
        }
        Ok(())
    }

    /// Handle UDP forwarding requests
    #[allow(unreachable_code)]
    async fn handle_udp_request(
        self,
        stream: TcpStream,
        their_addr: SocketAddr,
        ccr: ClientConnectionRequest,
    ) -> Result<(), SOCKSv5ServerError> {
        let my_addr = stream.local_addr()?;
        tracing::info!(
            "[{}:{}] Handling UDP bind request from {}:{}, seeking to bind towards {}:{}",
            my_addr.ip(),
            my_addr.port(),
            their_addr.ip(),
            their_addr.port(),
            ccr.destination_address,
            ccr.destination_port
        );

        let _socket = match ccr.destination_address.clone() {
            SOCKSv5Address::IP4(x) => UdpSocket::bind((x, ccr.destination_port)).await?,
            SOCKSv5Address::IP6(x) => UdpSocket::bind((x, ccr.destination_port)).await?,
            SOCKSv5Address::Hostname(x) => UdpSocket::bind((x, ccr.destination_port)).await?,
        };

        // OK, it worked. In order to mitigate an infinitesimal chance of a race condition, we're
        // going to set up our forwarding tasks first, and then return the result to the user. (Note,
        // we'd have to be slightly more precious in order to ensure a lack of race conditions, as
        // the runtime could take forever to actually start these tasks, but I'm not ready to be
        // bothered by this, yet. FIXME.)
        unimplemented!();

        // Cool; now we can get the result out to the user.
        let bound_address = _socket.local_addr()?;
        let response = ServerResponse {
            status: ServerResponseStatus::RequestGranted,
            bound_address: bound_address.ip().into(),
            bound_port: bound_address.port(),
        };

        response.write(&mut stream).await?;
        Ok(())
    }

    /// Handle TCP forwarding requests
    async fn handle_tcp_request(
        self,
        mut stream: TcpStream,
        their_addr: SocketAddr,
        ccr: ClientConnectionRequest,
    ) -> Result<(), SOCKSv5ServerError> {
        // Let the user know that we're maybe making progress
        let my_addr = stream.local_addr()?;
        tracing::info!(
            "[{}] Handling TCP forward request from {}, seeking to connect to {}:{}",
            my_addr,
            their_addr,
            ccr.destination_address,
            ccr.destination_port
        );

        // OK, first thing's first: We need to actually connect to the server that the user
        // wants us to connect to.
        let outgoing_stream = match &ccr.destination_address {
            SOCKSv5Address::IP4(x) => TcpStream::connect((*x, ccr.destination_port)).await?,
            SOCKSv5Address::IP6(x) => TcpStream::connect((*x, ccr.destination_port)).await?,
            SOCKSv5Address::Hostname(x) => {
                TcpStream::connect((x.as_ref(), ccr.destination_port)).await?
            }
        };

        tracing::trace!(
            "Connection established to {}:{}",
            ccr.destination_address,
            ccr.destination_port
        );

        // Now, for whatever reason -- and this whole thing sent me down a garden path
        // in understanding how this whole protocol works -- we tell the user what address
        // and port we bound for that connection.
        let bound_address = outgoing_stream.local_addr()?;
        let response = ServerResponse {
            status: ServerResponseStatus::RequestGranted,
            bound_address: bound_address.ip().into(),
            bound_port: bound_address.port(),
        };
        response.write(&mut stream).await?;

        // so now tie our streams together, and we're good to go
        tie_streams(stream, outgoing_stream).await;

        Ok(())
    }

    /// Handle TCP binding requests
    async fn handle_tcp_binding_request(
        self,
        mut stream: TcpStream,
        their_addr: SocketAddr,
        ccr: ClientConnectionRequest,
    ) -> Result<(), SOCKSv5ServerError> {
        // Let the user know that we're maybe making progress
        let my_addr = stream.local_addr()?;
        tracing::info!(
            "[{}] Handling TCP bind request from {}, seeking to bind {}:{}",
            my_addr,
            their_addr,
            ccr.destination_address,
            ccr.destination_port
        );

        // OK, we have to bind the darn socket first.
        let listener_port = match &their_addr {
            SocketAddr::V4(_) => TcpSocket::new_v4(),
            SocketAddr::V6(_) => TcpSocket::new_v6(),
        }?;
        // FIXME: Might want to bind on a particular interface, based on a
        // config flag, at some point.
        let listener = listener_port.listen(1)?;

        // Tell them what we bound, just in case they want to inform anyone.
        let bound_address = listener.local_addr()?;
        let response = ServerResponse {
            status: ServerResponseStatus::RequestGranted,
            bound_address: bound_address.ip().into(),
            bound_port: bound_address.port(),
        };
        response.write(&mut stream).await?;

        // Wait politely for someone to talk to us.
        let (other, other_addr) = listener.accept().await?;
        let info = ServerResponse {
            status: ServerResponseStatus::RequestGranted,
            bound_address: other_addr.ip().into(),
            bound_port: other_addr.port(),
        };
        info.write(&mut stream).await?;

        tie_streams(stream, other).await;

        Ok(())
    }
}

async fn tie_streams(mut left: TcpStream, mut right: TcpStream) {
    let left_local_addr = left
        .local_addr()
        .expect("couldn't get left local address in tie_streams");
    let left_peer_addr = left
        .peer_addr()
        .expect("couldn't get left peer address in tie_streams");
    let right_local_addr = right
        .local_addr()
        .expect("couldn't get right local address in tie_streams");
    let right_peer_addr = right
        .peer_addr()
        .expect("couldn't get right peer address in tie_streams");

    tokio::task::spawn(async move {
        tracing::info!(
            "Setting up linkage {}/{} <-> {}/{}",
            left_peer_addr,
            left_local_addr,
            right_local_addr,
            right_peer_addr
        );
        match copy_bidirectional(&mut left, &mut right).await {
            Ok((l2r, r2l)) => tracing::info!(
                "Shutting down linkage {}/{} <-> {}/{} (sent {} and {} bytes, respectively)",
                left_peer_addr,
                left_local_addr,
                right_local_addr,
                right_peer_addr,
                l2r,
                r2l
            ),
            Err(e) => tracing::warn!(
                "Shutting down linkage {}/{} <-> {}/{} with error: {}",
                left_peer_addr,
                left_local_addr,
                right_local_addr,
                right_peer_addr,
                e
            ),
        }
    });
}

#[allow(clippy::upper_case_acronyms)]
enum ChosenMethod {
    TLS(fn() -> Option<()>),
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
    params.connect_tls = Some(|| unimplemented!());
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
    params.connect_tls = Some(|| unimplemented!());
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
