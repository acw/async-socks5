use crate::errors::{DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionRequest, ClientGreeting,
    ClientUsernamePassword, ServerAuthResponse, ServerChoice, ServerResponse, ServerResponseStatus,
};
use crate::network::datagram::GenericDatagramSocket;
use crate::network::generic::{IntoErrorResponse, Networklike};
use crate::network::listener::GenericListener;
use crate::network::stream::GenericStream;
use crate::network::SOCKSv5Address;
use async_std::io;
use async_std::sync::{Arc, Mutex};
use async_trait::async_trait;
use log::{info, trace, warn};
use std::fmt::{Debug, Display};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SOCKSv5Error<E: Debug + Display> {
    #[error("SOCKSv5 serialization error: {0}")]
    SerializationError(#[from] SerializationError),
    #[error("SOCKSv5 deserialization error: {0}")]
    DeserializationError(#[from] DeserializationError),
    #[error("No acceptable authentication methods available")]
    NoAuthMethodsAllowed,
    #[error("Authentication failed")]
    AuthenticationFailed,
    #[error("Server chose an unsupported authentication method ({0}")]
    UnsupportedAuthMethodChosen(AuthenticationMethod),
    #[error("Server said no: {0}")]
    ServerFailure(#[from] ServerResponseStatus),
    #[error("Connection error: {0}")]
    ConnectionError(#[from] io::Error),
    #[error("Underlying network error: {0}")]
    UnderlyingNetwork(E),
}

impl<E: Debug + Display> IntoErrorResponse for SOCKSv5Error<E> {
    fn into_response(&self) -> ServerResponseStatus {
        match self {
            SOCKSv5Error::ServerFailure(v) => v.clone(),
            _ => ServerResponseStatus::GeneralFailure,
        }
    }
}

pub struct SOCKSv5Client<N: Networklike + Sync> {
    network: Arc<Mutex<N>>,
    login_info: LoginInfo,
    address: SOCKSv5Address,
    port: u16,
}

pub struct LoginInfo {
    pub username_password: Option<UsernamePassword>,
}

impl LoginInfo {
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

impl<N> SOCKSv5Client<N>
where
    N: Networklike + Sync,
{
    /// Create a new SOCKSv5 client connection over the given steam, using the given
    /// authentication information. As part of the process of building this object, we
    /// do a little test run to make sure that we can login effectively; this should save
    /// from *some* surprises later on. If you'd rather *not* do that, though, you can
    /// try `unchecked_new`.
    pub async fn new<A: Into<SOCKSv5Address>>(
        network: N,
        login: LoginInfo,
        server_addr: A,
        server_port: u16,
    ) -> Result<Self, SOCKSv5Error<N::Error>> {
        let base_version = SOCKSv5Client::unchecked_new(network, login, server_addr, server_port);
        let _ = base_version.start_session().await?;
        Ok(base_version)
    }
    /// Create a new SOCKSv5Client within the given parameters, but don't do a quick
    /// check to see if this connection has a chance of working. This saves you a TCP
    /// connection sequence at the expense of an increased possibility of an error
    /// later on down the road.
    pub fn unchecked_new<A: Into<SOCKSv5Address>>(
        network: N,
        login_info: LoginInfo,
        address: A,
        port: u16,
    ) -> Self {
        SOCKSv5Client {
            network: Arc::new(Mutex::new(network)),
            login_info,
            address: address.into(),
            port,
        }
    }

    /// This runs the connection and negotiates login, as required, and then returns
    /// the stream the caller should use to do ... whatever it wants to do.
    async fn start_session(&self) -> Result<GenericStream, SOCKSv5Error<N::Error>> {
        // create the initial stream
        let mut stream = {
            let mut network = self.network.lock().await;
            network.connect(self.address.clone(), self.port).await
        }
        .map_err(SOCKSv5Error::UnderlyingNetwork)?;

        // compute how we can log in
        let acceptable_methods = self.login_info.acceptable_methods();
        trace!(
            "Computed acceptable methods -- {:?} -- sending client greeting.",
            acceptable_methods
        );

        // Negotiate with the server. Well. "Negotiate."
        let client_greeting = ClientGreeting { acceptable_methods };
        client_greeting.write(&mut stream).await?;
        trace!("Write client greeting, waiting for server's choice.");
        let server_choice = ServerChoice::read(&mut stream).await?;
        trace!("Received server's choice: {}", server_choice.chosen_method);

        // Let's do it!
        match server_choice.chosen_method {
            AuthenticationMethod::None => {}

            AuthenticationMethod::UsernameAndPassword => {
                let (username, password) = if let Some(ref linfo) =
                    self.login_info.username_password
                {
                    trace!("Server requested username/password, getting data from login info.");
                    (linfo.username.clone(), linfo.password.clone())
                } else {
                    warn!("Server requested username/password, but we weren't provided one. Very weird.");
                    ("".to_string(), "".to_string())
                };

                let auth_request = ClientUsernamePassword { username, password };

                trace!("Writing password information.");
                auth_request.write(&mut stream).await?;
                let server_response = ServerAuthResponse::read(&mut stream).await?;
                trace!("Got server response: {}", server_response.success);

                if !server_response.success {
                    return Err(SOCKSv5Error::AuthenticationFailed);
                }
            }

            AuthenticationMethod::NoAcceptableMethods => {
                return Err(SOCKSv5Error::NoAuthMethodsAllowed)
            }

            x => return Err(SOCKSv5Error::UnsupportedAuthMethodChosen(x)),
        }

        Ok(stream)
    }

    /// Listen for one connection on the proxy server, and then wire back a socket
    /// that can talk to whoever connects. This handshake is a little odd, because
    /// we don't necessarily know what port or address we should tell the other
    /// person to listen on. So this function takes an async function, which it
    /// will pass this information to once it has it. It's up to that function,
    /// then, to communicate this to its peer.
    pub async fn remote_listen<A, E: Debug + Display>(
        self,
        _addr: A,
        _port: u16,
    ) -> Result<GenericStream, SOCKSv5Error<E>>
    where
        A: Into<SOCKSv5Address>,
    {
        unimplemented!()
    }
}

#[async_trait]
impl<N> Networklike for SOCKSv5Client<N>
where
    N: Networklike + Sync + Send,
{
    type Error = SOCKSv5Error<N::Error>;

    async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error> {
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
            info!(
                "Proxy connection to {}:{} established; server is using {}:{}",
                target, port, response.bound_address, response.bound_port
            );
            Ok(stream)
        } else {
            Err(response.status.into())
        }
    }

    async fn listen<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        _addr: A,
        _port: u16,
    ) -> Result<GenericListener<Self::Error>, Self::Error> {
        unimplemented!()
    }

    async fn bind<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        _addr: A,
        _port: u16,
    ) -> Result<GenericDatagramSocket<Self::Error>, Self::Error> {
        unimplemented!()
    }
}
