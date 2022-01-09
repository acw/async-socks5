use crate::errors::{DeserializationError, SerializationError};
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use proptest::proptest;
#[cfg(test)]
use proptest_derive::Arbitrary;

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ServerAuthResponse {
    pub success: bool,
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
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 1];

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 1 {
            return Err(DeserializationError::InvalidVersion(1, buffer[0]));
        }

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        Ok(ServerAuthResponse {
            success: buffer[0] == 0,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[1]).await?;
        w.write_all(&[if self.success { 0x00 } else { 0xde }])
            .await?;
        Ok(())
    }
}

standard_roundtrip!(server_auth_response, ServerAuthResponse);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerAuthResponse::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let no_len = vec![1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerAuthResponse::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));
}

#[test]
fn check_bad_version() {
    let no_len = vec![6, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerAuthResponse::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidVersion(1, 6)),
        task::block_on(ys)
    );
}
