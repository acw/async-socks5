use crate::errors::{DeserializationError, SerializationError};
#[cfg(test)]
use crate::messages::utils::arbitrary_socks_string;
use crate::serialize::{read_string, write_string};
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientUsernamePassword {
    pub username: String,
    pub password: String,
}

impl ClientUsernamePassword {
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

        let username = read_string(r).await?;
        let password = read_string(r).await?;

        Ok(ClientUsernamePassword { username, password })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[1]).await?;
        write_string(&self.username, w).await?;
        write_string(&self.password, w).await
    }
}

#[cfg(test)]
impl Arbitrary for ClientUsernamePassword {
    fn arbitrary(g: &mut Gen) -> Self {
        let username = arbitrary_socks_string(g);
        let password = arbitrary_socks_string(g);

        ClientUsernamePassword { username, password }
    }
}

standard_roundtrip!(username_password_roundtrips, ClientUsernamePassword);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientUsernamePassword::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let user_only = vec![1, 3, 102, 111, 111];
    let mut cursor = Cursor::new(user_only);
    let ys = ClientUsernamePassword::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));
}

#[test]
fn check_bad_version() {
    let bad_len = vec![5];
    let mut cursor = Cursor::new(bad_len);
    let ys = ClientUsernamePassword::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidVersion(1, 5)),
        task::block_on(ys)
    );
}
