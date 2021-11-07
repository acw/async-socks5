use crate::errors::{DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionRequest, ClientGreeting,
    ClientUsernamePassword, ServerAuthResponse, ServerChoice, ServerResponse, ServerResponseStatus,
};
use crate::network::datagram::GenericDatagramSocket;
use crate::network::generic::Networklike;
use crate::network::listener::GenericListener;
use crate::network::stream::GenericStream;
use crate::network::SOCKSv5Address;
use async_std::io;
use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncWrite};
use log::{trace, warn};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum SOCKSv5Error {
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
}

impl From<SOCKSv5Error> for ServerResponseStatus {
    fn from(x: SOCKSv5Error) -> Self {
        match x {
            SOCKSv5Error::ServerFailure(v) => v,
            _ => ServerResponseStatus::GeneralFailure,
        }
    }
}

pub struct SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite + Sync,
    N: Networklike + Sync,
{
    network: N,
    stream: S,
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

impl<S, N> SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + Sync,
    N: Networklike + Sync,
{
    /// Create a new SOCKSv5 client connection over the given steam, using the given
    /// authentication information.
    pub async fn new(network: N, mut stream: S, login: &LoginInfo) -> Result<Self, SOCKSv5Error> {
        let acceptable_methods = login.acceptable_methods();
        trace!(
            "Computed acceptable methods -- {:?} -- sending client greeting.",
            acceptable_methods
        );

        let client_greeting = ClientGreeting { acceptable_methods };
        client_greeting.write(&mut stream).await?;
        trace!("Write client greeting, waiting for server's choice.");
        let server_choice = ServerChoice::read(&mut stream).await?;
        trace!("Received server's choice: {}", server_choice.chosen_method);

        match server_choice.chosen_method {
            AuthenticationMethod::None => {}

            AuthenticationMethod::UsernameAndPassword => {
                let (username, password) = if let Some(ref linfo) = login.username_password {
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

        trace!("Returning new SOCKSv5Client object!");
        Ok(SOCKSv5Client {
            network,
            stream,
        })
    }
}

#[async_trait]
impl<S, N> Networklike for SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + Sync,
    N: Networklike + Sync + Send,
{
    type Error = SOCKSv5Error;

    async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error> {
        let request = ClientConnectionRequest {
            command_code: ClientConnectionCommand::EstablishTCPStream,
            destination_address: addr.into(),
            destination_port: port,
        };

        request.write(&mut self.stream).await?;

        let response = ServerResponse::read(&mut self.stream).await?;

        if response.status == ServerResponseStatus::RequestGranted {
            self.network
                .connect(response.bound_address, response.bound_port)
                .await
                .map_err(|e| {
                    SOCKSv5Error::ConnectionError(io::Error::new(
                        io::ErrorKind::Other,
                        format!("{}", e),
                    ))
                })
        } else {
            Err(SOCKSv5Error::ServerFailure(response.status))
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
