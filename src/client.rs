use crate::errors::{DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientConnectionCommand, ClientConnectionRequest, ClientGreeting,
    ClientUsernamePassword, ServerAuthResponse, ServerChoice, ServerResponse, ServerResponseStatus,
};
use crate::network::{Network, SOCKSv5Address};
use async_std::net::IpAddr;
use futures::io::{AsyncRead, AsyncWrite};
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
}

pub struct SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite,
    N: Network,
{
    _network: N,
    stream: S,
}

pub struct LoginInfo {
    username_password: Option<UsernamePassword>,
}

pub struct UsernamePassword {
    username: String,
    password: String,
}

impl<S, N> SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
    N: Network,
{
    /// Create a new SOCKSv5 client connection over the given steam, using the given
    /// authentication information.
    pub async fn new(_network: N, mut stream: S, login: &LoginInfo) -> Result<Self, SOCKSv5Error> {
        let mut acceptable_methods = vec![AuthenticationMethod::None];

        if login.username_password.is_some() {
            acceptable_methods.push(AuthenticationMethod::UsernameAndPassword);
        }

        let client_greeting = ClientGreeting { acceptable_methods };

        client_greeting.write(&mut stream).await?;
        let server_choice = ServerChoice::read(Pin::new(&mut stream)).await?;

        match server_choice.chosen_method {
            AuthenticationMethod::None => {}

            AuthenticationMethod::UsernameAndPassword => {
                let (username, password) = if let Some(ref linfo) = login.username_password {
                    (linfo.username.clone(), linfo.password.clone())
                } else {
                    ("".to_string(), "".to_string())
                };

                let auth_request = ClientUsernamePassword { username, password };

                auth_request.write(&mut stream).await?;
                let server_response = ServerAuthResponse::read(Pin::new(&mut stream)).await?;

                if !server_response.success {
                    return Err(SOCKSv5Error::AuthenticationFailed);
                }
            }

            AuthenticationMethod::NoAcceptableMethods => {
                return Err(SOCKSv5Error::NoAuthMethodsAllowed)
            }

            x => return Err(SOCKSv5Error::UnsupportedAuthMethodChosen(x)),
        }

        Ok(SOCKSv5Client { _network, stream })
    }

    async fn connect_internal(
        &mut self,
        addr: SOCKSv5Address,
        port: u16,
    ) -> Result<N::Stream, SOCKSv5Error> {
        let request = ClientConnectionRequest {
            command_code: ClientConnectionCommand::EstablishTCPStream,
            destination_address: addr,
            destination_port: port,
        };

        request.write(&mut self.stream).await?;
        let response = ServerResponse::read(Pin::new(&mut self.stream)).await?;

        if response.status == ServerResponseStatus::RequestGranted {
            unimplemented!()
        } else {
            Err(SOCKSv5Error::from(response.status))
        }
    }

    pub async fn connect(&mut self, addr: IpAddr, port: u16) -> Result<N::Stream, SOCKSv5Error> {
        assert!(port != 0);
        match addr {
            IpAddr::V4(a) => self.connect_internal(SOCKSv5Address::IP4(a), port).await,
            IpAddr::V6(a) => self.connect_internal(SOCKSv5Address::IP6(a), port).await,
        }
    }

    pub async fn connect_name(
        &mut self,
        name: String,
        port: u16,
    ) -> Result<N::Stream, SOCKSv5Error> {
        format!("hello {}", 'a');
        self.connect_internal(SOCKSv5Address::Name(name), port)
            .await
    }
}
