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

/// Client greetings are the first message sent in a SOCKSv5 session. They
/// identify that there's a client that wants to talk to a server, and that
/// they can support any of the provided mechanisms for authenticating to
/// said server. (It feels weird that the offer/choice goes this way instead
/// of the reverse, but whatever.)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientGreeting {
    pub acceptable_methods: Vec<AuthenticationMethod>,
}

impl ClientGreeting {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<ClientGreeting, DeserializationError> {
        let mut buffer = [0; 1];

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        let mut acceptable_methods = Vec::with_capacity(buffer[0] as usize);
        for _ in 0..buffer[0] {
            acceptable_methods.push(AuthenticationMethod::read(r).await?);
        }

        Ok(ClientGreeting { acceptable_methods })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        if self.acceptable_methods.len() > 255 {
            return Err(SerializationError::TooManyAuthMethods(
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

#[cfg(test)]
impl Arbitrary for ClientGreeting {
    fn arbitrary(g: &mut Gen) -> ClientGreeting {
        let amt = u8::arbitrary(g);
        let mut acceptable_methods = Vec::with_capacity(amt as usize);

        for _ in 0..amt {
            acceptable_methods.push(AuthenticationMethod::arbitrary(g));
        }

        ClientGreeting { acceptable_methods }
    }
}

standard_roundtrip!(client_greeting_roundtrips, ClientGreeting);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientGreeting::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let no_len = vec![5];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientGreeting::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let bad_len = vec![5, 9];
    let mut cursor = Cursor::new(bad_len);
    let ys = ClientGreeting::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::AuthenticationMethodError(
            AuthenticationDeserializationError::NoDataFound
        )),
        task::block_on(ys)
    );
}

#[test]
fn check_bad_version() {
    let no_len = vec![6, 1, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientGreeting::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidVersion(5, 6)),
        task::block_on(ys)
    );
}

#[test]
fn check_too_many() {
    let mut auth_methods = Vec::with_capacity(512);
    auth_methods.resize(512, AuthenticationMethod::ChallengeHandshake);
    let greet = ClientGreeting {
        acceptable_methods: auth_methods,
    };
    let mut output = vec![0; 1024];
    assert_eq!(
        Err(SerializationError::TooManyAuthMethods(512)),
        task::block_on(greet.write(&mut output))
    );
}
