use crate::messages::string::{SOCKSv5String, SOCKSv5StringReadError, SOCKSv5StringWriteError};
#[cfg(test)]
use proptest::prelude::{Arbitrary, BoxedStrategy, Strategy};
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientUsernamePassword {
    pub username: String,
    pub password: String,
}

#[cfg(test)]
const USERNAME_REGEX: &str = "[a-zA-Z0-9~!@#$%^&*_\\-+=:;?<>]+";
#[cfg(test)]
const PASSWORD_REGEX: &str = "[a-zA-Z0-9~!@#$%^&*_\\-+=:;?<>]+";

#[cfg(test)]
impl Arbitrary for ClientUsernamePassword {
    type Parameters = Option<u8>;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let max_len = args.unwrap_or(12) as usize;
        (USERNAME_REGEX, PASSWORD_REGEX)
            .prop_map(move |(mut username, mut password)| {
                username.shrink_to(max_len);
                password.shrink_to(max_len);
                ClientUsernamePassword { username, password }
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientUsernamePasswordReadError {
    #[error("Underlying buffer read error: {0}")]
    ReadError(String),
    #[error("Invalid username/password version; expected 1, saw {0}")]
    InvalidVersion(u8),
    #[error(transparent)]
    StringError(#[from] SOCKSv5StringReadError),
}

impl From<std::io::Error> for ClientUsernamePasswordReadError {
    fn from(x: std::io::Error) -> ClientUsernamePasswordReadError {
        ClientUsernamePasswordReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientUsernamePasswordWriteError {
    #[error("Underlying buffer read error: {0}")]
    WriteError(String),
    #[error(transparent)]
    StringError(#[from] SOCKSv5StringWriteError),
}

impl From<std::io::Error> for ClientUsernamePasswordWriteError {
    fn from(x: std::io::Error) -> ClientUsernamePasswordWriteError {
        ClientUsernamePasswordWriteError::WriteError(format!("{}", x))
    }
}

impl ClientUsernamePassword {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, ClientUsernamePasswordReadError> {
        let version = r.read_u8().await?;

        if version != 1 {
            return Err(ClientUsernamePasswordReadError::InvalidVersion(version));
        }

        let username = SOCKSv5String::read(r).await?.into();
        let password = SOCKSv5String::read(r).await?.into();

        Ok(ClientUsernamePassword { username, password })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ClientUsernamePasswordWriteError> {
        w.write_u8(1).await?;
        SOCKSv5String::from(self.username.as_str()).write(w).await?;
        SOCKSv5String::from(self.password.as_str()).write(w).await?;
        Ok(())
    }
}

crate::standard_roundtrip!(username_password_roundtrips, ClientUsernamePassword);

#[tokio::test]
async fn heck_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientUsernamePassword::read(&mut cursor).await;
    assert!(matches!(
        ys,
        Err(ClientUsernamePasswordReadError::ReadError(_))
    ));

    let user_only = vec![1, 3, 102, 111, 111];
    let mut cursor = Cursor::new(user_only);
    let ys = ClientUsernamePassword::read(&mut cursor).await;
    println!("ys: {:?}", ys);
    assert!(matches!(
        ys,
        Err(ClientUsernamePasswordReadError::StringError(_))
    ));
}

#[tokio::test]
async fn check_bad_version() {
    let bad_len = vec![5];
    let mut cursor = Cursor::new(bad_len);
    let ys = ClientUsernamePassword::read(&mut cursor).await;
    assert_eq!(Err(ClientUsernamePasswordReadError::InvalidVersion(5)), ys);
}
