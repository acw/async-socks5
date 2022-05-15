use crate::address::SOCKSv5Address;
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionCommandWriteError,
    ClientConnectionRequest, ClientGreeting, ClientGreetingWriteError, ClientUsernamePassword,
    ClientUsernamePasswordWriteError, ServerAuthResponse, ServerAuthResponseReadError,
    ServerChoice, ServerChoiceReadError, ServerResponse, ServerResponseReadError,
    ServerResponseStatus,
};
use std::future::Future;
use thiserror::Error;
use tokio::net::TcpStream;

#[derive(Debug, Error)]
pub enum SOCKSv5ClientError {
    #[error("Underlying networking error: {0}")]
    NetworkingError(String),
    #[error("Client greeting write error: {0}")]
    ClientWriteError(#[from] ClientGreetingWriteError),
    #[error("Server choice error: {0}")]
    ServerChoiceError(#[from] ServerChoiceReadError),
    #[error("Error writing credentials: {0}")]
    CredentialWriteError(#[from] ClientUsernamePasswordWriteError),
    #[error("Server auth read error: {0}")]
    AuthResponseError(#[from] ServerAuthResponseReadError),
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("No authentication methods allowed")]
    NoAuthMethodsAllowed,
    #[error("Unsupported authentication method chosen ({0})")]
    UnsupportedAuthMethodChosen(AuthenticationMethod),
    #[error("Client connection command write error: {0}")]
    ClientCommandWriteError(#[from] ClientConnectionCommandWriteError),
    #[error("Server said no: {0}")]
    ServerRejected(#[from] ServerResponseStatus),
    #[error("Server response read failure: {0}")]
    ServerResponseError(#[from] ServerResponseReadError),
}

impl From<std::io::Error> for SOCKSv5ClientError {
    fn from(x: std::io::Error) -> SOCKSv5ClientError {
        SOCKSv5ClientError::NetworkingError(format!("{}", x))
    }
}

pub struct LoginInfo {
    pub username_password: Option<UsernamePassword>,
}

impl Default for LoginInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl LoginInfo {
    /// Generate an empty bit of login information.
    pub fn new() -> LoginInfo {
        LoginInfo {
            username_password: None,
        }
    }

    /// Turn this information into a list of authentication methods that we can handle,
    /// to send to the server. The RFC isn't super clear if the order of these matters
    /// at all, but we'll try to keep it in our preferred order.
    fn acceptable_methods(&self) -> Vec<AuthenticationMethod> {
        let mut acceptable_methods = vec![AuthenticationMethod::None];

        if self.username_password.is_some() {
            acceptable_methods.push(AuthenticationMethod::UsernameAndPassword);
        }

        acceptable_methods
    }
}

pub struct UsernamePassword {
    pub username: String,
    pub password: String,
}

pub struct SOCKSv5Client {
    login_info: LoginInfo,
    address: SOCKSv5Address,
    port: u16,
}

impl SOCKSv5Client {
    /// Create a new SOCKSv5 client connection over the given steam, using the given
    /// authentication information. As part of the process of building this object, we
    /// do a little test run to make sure that we can login effectively; this should save
    /// from *some* surprises later on. If you'd rather *not* do that, though, you can
    /// try `unchecked_new`.
    pub async fn new<A: Into<SOCKSv5Address>>(
        login: LoginInfo,
        server_addr: A,
        server_port: u16,
    ) -> Result<Self, SOCKSv5ClientError> {
        let base_version = SOCKSv5Client::unchecked_new(login, server_addr, server_port);
        let _ = base_version.start_session().await?;
        Ok(base_version)
    }
    /// Create a new SOCKSv5Client within the given parameters, but don't do a quick
    /// check to see if this connection has a chance of working. This saves you a TCP
    /// connection sequence at the expense of an increased possibility of an error
    /// later on down the road.
    pub fn unchecked_new<A: Into<SOCKSv5Address>>(
        login_info: LoginInfo,
        address: A,
        port: u16,
    ) -> Self {
        SOCKSv5Client {
            login_info,
            address: address.into(),
            port,
        }
    }

    /// This runs the connection and negotiates login, as required, and then returns
    /// the stream the caller should use to do ... whatever it wants to do.
    async fn start_session(&self) -> Result<TcpStream, SOCKSv5ClientError> {
        // create the initial stream
        let mut stream = match &self.address {
            SOCKSv5Address::IP4(x) => TcpStream::connect((*x, self.port)).await?,
            SOCKSv5Address::IP6(x) => TcpStream::connect((*x, self.port)).await?,
            SOCKSv5Address::Hostname(x) => TcpStream::connect((x.as_ref(), self.port)).await?,
        };

        // compute how we can log in
        let acceptable_methods = self.login_info.acceptable_methods();
        tracing::trace!(
            "Computed acceptable methods -- {:?} -- sending client greeting.",
            acceptable_methods
        );

        // Negotiate with the server. Well. "Negotiate."
        let client_greeting = ClientGreeting { acceptable_methods };
        client_greeting.write(&mut stream).await?;
        tracing::trace!("Write client greeting, waiting for server's choice.");
        let server_choice = ServerChoice::read(&mut stream).await?;
        tracing::trace!("Received server's choice: {}", server_choice.chosen_method);

        // Let's do it!
        match server_choice.chosen_method {
            AuthenticationMethod::None => {}

            AuthenticationMethod::UsernameAndPassword => {
                let (username, password) = if let Some(ref linfo) =
                    self.login_info.username_password
                {
                    tracing::trace!(
                        "Server requested username/password, getting data from login info."
                    );
                    (linfo.username.clone(), linfo.password.clone())
                } else {
                    tracing::warn!("Server requested username/password, but we weren't provided one. Very weird.");
                    ("".to_string(), "".to_string())
                };

                let auth_request = ClientUsernamePassword { username, password };

                tracing::trace!("Writing password information.");
                auth_request.write(&mut stream).await?;
                let server_response = ServerAuthResponse::read(&mut stream).await?;
                tracing::trace!("Got server response: {}", server_response.success);

                if !server_response.success {
                    return Err(SOCKSv5ClientError::AuthenticationFailed);
                }
            }

            AuthenticationMethod::NoAcceptableMethods => {
                return Err(SOCKSv5ClientError::NoAuthMethodsAllowed)
            }

            x => return Err(SOCKSv5ClientError::UnsupportedAuthMethodChosen(x)),
        }

        Ok(stream)
    }

    /// Listen for one connection on the proxy server, and then wire back a socket
    /// that can talk to whoever connects. This handshake is a little odd, because
    /// we don't necessarily know what port or address we should tell the other
    /// person to listen on. So this function takes an async function, which it
    /// will pass this information to once it has it. It's up to that function,
    /// then, to communicate this to its peer.
    pub async fn remote_listen<A, Fut: Future<Output = Result<(), SOCKSv5ClientError>>>(
        self,
        addr: A,
        port: u16,
        callback: impl FnOnce(SOCKSv5Address, u16) -> Fut,
    ) -> Result<(SOCKSv5Address, u16, TcpStream), SOCKSv5ClientError>
    where
        A: Into<SOCKSv5Address>,
    {
        let mut stream = self.start_session().await?;
        let target = addr.into();
        let ccr = ClientConnectionRequest {
            command_code: ClientConnectionCommand::EstablishTCPPortBinding,
            destination_address: target.clone(),
            destination_port: port,
        };

        ccr.write(&mut stream).await?;

        let initial_response = ServerResponse::read(&mut stream).await?;
        if initial_response.status != ServerResponseStatus::RequestGranted {
            return Err(initial_response.status.into());
        }

        tracing::info!(
            "Proxy port binding of {}:{} established; server listening on {}:{}",
            target,
            port,
            initial_response.bound_address,
            initial_response.bound_port
        );

        callback(initial_response.bound_address, initial_response.bound_port).await?;

        let secondary_response = ServerResponse::read(&mut stream).await?;
        if secondary_response.status != ServerResponseStatus::RequestGranted {
            return Err(secondary_response.status.into());
        }

        tracing::info!(
            "Proxy bind got a connection from {}:{}",
            secondary_response.bound_address,
            secondary_response.bound_port
        );

        Ok((
            secondary_response.bound_address,
            secondary_response.bound_port,
            stream,
        ))
    }

    pub async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<TcpStream, SOCKSv5ClientError> {
        let mut stream = self.start_session().await?;
        let target = addr.into();

        let ccr = ClientConnectionRequest {
            command_code: ClientConnectionCommand::EstablishTCPStream,
            destination_address: target.clone(),
            destination_port: port,
        };
        ccr.write(&mut stream).await?;
        let response = ServerResponse::read(&mut stream).await?;

        if response.status == ServerResponseStatus::RequestGranted {
            tracing::info!(
                "Proxy connection to {}:{} established; server is using {}:{}",
                target,
                port,
                response.bound_address,
                response.bound_port
            );
            Ok(stream)
        } else {
            Err(response.status.into())
        }
    }
}
