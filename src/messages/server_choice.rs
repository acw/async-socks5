use crate::messages::authentication_method::{
    AuthenticationMethod, AuthenticationMethodReadError, AuthenticationMethodWriteError,
};
#[cfg(test)]
use proptest_derive::Arbitrary;
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ServerChoice {
    pub chosen_method: AuthenticationMethod,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerChoiceReadError {
    #[error(transparent)]
    AuthMethodError(#[from] AuthenticationMethodReadError),
    #[error("Error in underlying buffer: {0}")]
    ReadError(String),
    #[error("Invalid version; expected 5, got {0}")]
    InvalidVersion(u8),
}

impl From<std::io::Error> for ServerChoiceReadError {
    fn from(x: std::io::Error) -> ServerChoiceReadError {
        ServerChoiceReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerChoiceWriteError {
    #[error(transparent)]
    AuthMethodError(#[from] AuthenticationMethodWriteError),
    #[error("Error in underlying buffer: {0}")]
    WriteError(String),
}

impl From<std::io::Error> for ServerChoiceWriteError {
    fn from(x: std::io::Error) -> ServerChoiceWriteError {
        ServerChoiceWriteError::WriteError(format!("{}", x))
    }
}

impl ServerChoice {
    pub fn rejection() -> ServerChoice {
        ServerChoice {
            chosen_method: AuthenticationMethod::NoAcceptableMethods,
        }
    }

    pub fn option(method: AuthenticationMethod) -> ServerChoice {
        ServerChoice {
            chosen_method: method,
        }
    }

    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, ServerChoiceReadError> {
        let version = r.read_u8().await?;

        if version != 5 {
            return Err(ServerChoiceReadError::InvalidVersion(version));
        }

        let chosen_method = AuthenticationMethod::read(r).await?;

        Ok(ServerChoice { chosen_method })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ServerChoiceWriteError> {
        w.write_u8(5).await?;
        self.chosen_method.write(w).await?;
        Ok(())
    }
}

crate::standard_roundtrip!(server_choice_roundtrips, ServerChoice);

#[tokio::test]
async fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerChoice::read(&mut cursor).await;
    assert!(matches!(ys, Err(ServerChoiceReadError::ReadError(_))));

    let bad_len = vec![5];
    let mut cursor = Cursor::new(bad_len);
    let ys = ServerChoice::read(&mut cursor).await;
    assert!(matches!(ys, Err(ServerChoiceReadError::AuthMethodError(_))));
}

#[tokio::test]
async fn check_bad_version() {
    let no_len = vec![9, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerChoice::read(&mut cursor).await;
    assert_eq!(Err(ServerChoiceReadError::InvalidVersion(9)), ys);
}
