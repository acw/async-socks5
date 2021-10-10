use crate::errors::{DeserializationError, SerializationError};
use crate::messages::{
    AuthenticationMethod, ClientGreeting, ClientUsernamePassword, ServerAuthResponse, ServerChoice,
    ServerResponseStatus,
};
use crate::network::generic::Networklike;
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
}

pub struct SOCKSv5Client<S, N>
where
    S: AsyncRead + AsyncWrite,
    N: Networklike,
{
    _network: N,
    _stream: S,
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
    S: AsyncRead + AsyncWrite + Send + Unpin,
    N: Networklike,
{
    /// Create a new SOCKSv5 client connection over the given steam, using the given
    /// authentication information.
    pub async fn new(_network: N, mut stream: S, login: &LoginInfo) -> Result<Self, SOCKSv5Error> {
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
            _network,
            _stream: stream,
        })
    }
}
