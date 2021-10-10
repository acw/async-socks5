#[cfg(test)]
use crate::errors::AuthenticationDeserializationError;
use crate::errors::{DeserializationError, SerializationError};
use crate::messages::AuthenticationMethod;
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerChoice {
    pub chosen_method: AuthenticationMethod,
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
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 1];

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        let chosen_method = AuthenticationMethod::read(r).await?;

        Ok(ServerChoice { chosen_method })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[5]).await?;
        self.chosen_method.write(w).await
    }
}

#[cfg(test)]
impl Arbitrary for ServerChoice {
    fn arbitrary(g: &mut Gen) -> ServerChoice {
        ServerChoice {
            chosen_method: AuthenticationMethod::arbitrary(g),
        }
    }
}

standard_roundtrip!(server_choice_roundtrips, ServerChoice);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerChoice::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let bad_len = vec![5];
    let mut cursor = Cursor::new(bad_len);
    let ys = ServerChoice::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::AuthenticationMethodError(
            AuthenticationDeserializationError::NoDataFound
        )),
        task::block_on(ys)
    );
}

#[test]
fn check_bad_version() {
    let no_len = vec![9, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ServerChoice::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidVersion(5, 9)),
        task::block_on(ys)
    );
}
