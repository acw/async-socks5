#[cfg(test)]
use proptest_derive::Arbitrary;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ServerAuthResponse {
    pub success: bool,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerAuthResponseReadError {
    #[error("Underlying buffer read error: {0}")]
    ReadError(String),
    #[error("Invalid username/password version; expected 1, saw {0}")]
    InvalidVersion(u8),
}

impl From<std::io::Error> for ServerAuthResponseReadError {
    fn from(x: std::io::Error) -> ServerAuthResponseReadError {
        ServerAuthResponseReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerAuthResponseWriteError {
    #[error("Underlying buffer read error: {0}")]
    WriteError(String),
}

impl From<std::io::Error> for ServerAuthResponseWriteError {
    fn from(x: std::io::Error) -> ServerAuthResponseWriteError {
        ServerAuthResponseWriteError::WriteError(format!("{}", x))
    }
}

impl ServerAuthResponse {
    pub fn success() -> ServerAuthResponse {
        ServerAuthResponse { success: true }
    }

    pub fn failure() -> ServerAuthResponse {
        ServerAuthResponse { success: false }
    }

    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, ServerAuthResponseReadError> {
        let version = r.read_u8().await?;

        if version != 1 {
            return Err(ServerAuthResponseReadError::InvalidVersion(version));
        }

        Ok(ServerAuthResponse {
            success: r.read_u8().await? == 0,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ServerAuthResponseWriteError> {
        w.write_all(&[1]).await?;
        w.write_all(&[if self.success { 0x00 } else { 0xde }])
            .await?;
        Ok(())
    }
}

crate::standard_roundtrip!(server_auth_response, ServerAuthResponse);

#[tokio::test]
async fn check_short_reads() {
    use std::io::Cursor;

    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerAuthResponse::read(&mut cursor).await;
    assert!(matches!(ys, Err(ServerAuthResponseReadError::ReadError(_))));

    let no_len = vec![1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerAuthResponse::read(&mut cursor).await;
    assert!(matches!(ys, Err(ServerAuthResponseReadError::ReadError(_))));
}

#[tokio::test]
async fn check_bad_version() {
    use std::io::Cursor;

    let no_len = vec![6, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerAuthResponse::read(&mut cursor).await;
    assert_eq!(Err(ServerAuthResponseReadError::InvalidVersion(6)), ys);
}
