use crate::messages::authentication_method::{
    AuthenticationMethod, AuthenticationMethodReadError, AuthenticationMethodWriteError,
};
#[cfg(test)]
use proptest_derive::Arbitrary;
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Client greetings are the first message sent in a SOCKSv5 session. They
/// identify that there's a client that wants to talk to a server, and that
/// they can support any of the provided mechanisms for authenticating to
/// said server. (It feels weird that the offer/choice goes this way instead
/// of the reverse, but whatever.)
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ClientGreeting {
    pub acceptable_methods: Vec<AuthenticationMethod>,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientGreetingReadError {
    #[error("Invalid version in client request: {0} (expected 5)")]
    InvalidVersion(u8),
    #[error(transparent)]
    AuthMethodReadError(#[from] AuthenticationMethodReadError),
    #[error("Underlying read error: {0}")]
    ReadError(String),
}

impl From<std::io::Error> for ClientGreetingReadError {
    fn from(x: std::io::Error) -> ClientGreetingReadError {
        ClientGreetingReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientGreetingWriteError {
    #[error("Too many methods provided; need <256, saw {0}")]
    TooManyMethods(usize),
    #[error(transparent)]
    AuthMethodWriteError(#[from] AuthenticationMethodWriteError),
    #[error("Underlying write error: {0}")]
    WriteError(String),
}

impl From<std::io::Error> for ClientGreetingWriteError {
    fn from(x: std::io::Error) -> ClientGreetingWriteError {
        ClientGreetingWriteError::WriteError(format!("{}", x))
    }
}

impl ClientGreeting {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<ClientGreeting, ClientGreetingReadError> {
        let version = r.read_u8().await?;

        if version != 5 {
            return Err(ClientGreetingReadError::InvalidVersion(version));
        }

        let num_methods = r.read_u8().await? as usize;

        let mut acceptable_methods = Vec::with_capacity(num_methods);
        for _ in 0..num_methods {
            acceptable_methods.push(AuthenticationMethod::read(r).await?);
        }

        Ok(ClientGreeting { acceptable_methods })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ClientGreetingWriteError> {
        if self.acceptable_methods.len() > 255 {
            return Err(ClientGreetingWriteError::TooManyMethods(
                self.acceptable_methods.len(),
            ));
        }

        let mut buffer = Vec::with_capacity(self.acceptable_methods.len() + 2);
        buffer.push(5);
        buffer.push(self.acceptable_methods.len() as u8);
        w.write_all(&buffer).await?;
        for authmeth in self.acceptable_methods.iter() {
            authmeth.write(w).await?;
        }
        Ok(())
    }
}

crate::standard_roundtrip!(client_greeting_roundtrips, ClientGreeting);

#[tokio::test]
async fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientGreeting::read(&mut cursor).await;
    assert!(matches!(ys, Err(ClientGreetingReadError::ReadError(_))));

    let no_len = vec![5];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientGreeting::read(&mut cursor).await;
    assert!(matches!(ys, Err(ClientGreetingReadError::ReadError(_))));

    let bad_len = vec![5, 9];
    let mut cursor = Cursor::new(bad_len);
    let ys = ClientGreeting::read(&mut cursor).await;
    assert!(matches!(
        ys,
        Err(ClientGreetingReadError::AuthMethodReadError(
            AuthenticationMethodReadError::ReadError(_)
        ))
    ));
}

#[tokio::test]
async fn check_bad_version() {
    let no_len = vec![6, 1, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientGreeting::read(&mut cursor).await;
    assert_eq!(Err(ClientGreetingReadError::InvalidVersion(6)), ys);
}

#[tokio::test]
async fn check_too_many() {
    let mut auth_methods = Vec::with_capacity(512);
    auth_methods.resize(512, AuthenticationMethod::ChallengeHandshake);
    let greet = ClientGreeting {
        acceptable_methods: auth_methods,
    };
    let mut output = vec![0; 1024];
    assert_eq!(
        Err(ClientGreetingWriteError::TooManyMethods(512)),
        greet.write(&mut output).await
    );
}
