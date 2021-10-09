use crate::errors::{AuthenticationDeserializationError, DeserializationError, SerializationError};
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};
use std::fmt;

#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticationMethod {
    None,
    GSSAPI,
    UsernameAndPassword,
    ChallengeHandshake,
    ChallengeResponse,
    SSL,
    NDS,
    MultiAuthenticationFramework,
    JSONPropertyBlock,
    PrivateMethod(u8),
    NoAcceptableMethods,
}

impl fmt::Display for AuthenticationMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AuthenticationMethod::None => write!(f, "No authentication"),
            AuthenticationMethod::GSSAPI => write!(f, "GSS-API"),
            AuthenticationMethod::UsernameAndPassword => write!(f, "Username and password"),
            AuthenticationMethod::ChallengeHandshake => write!(f, "Challenge/Handshake"),
            AuthenticationMethod::ChallengeResponse => write!(f, "Challenge/Response"),
            AuthenticationMethod::SSL => write!(f, "SSL"),
            AuthenticationMethod::NDS => write!(f, "NDS Authentication"),
            AuthenticationMethod::MultiAuthenticationFramework => {
                write!(f, "Multi-Authentication Framework")
            }
            AuthenticationMethod::JSONPropertyBlock => write!(f, "JSON Property Block"),
            AuthenticationMethod::PrivateMethod(m) => write!(f, "Private Method {:x}", m),
            AuthenticationMethod::NoAcceptableMethods => write!(f, "No Acceptable Methods"),
        }
    }
}

impl AuthenticationMethod {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<AuthenticationMethod, DeserializationError> {
        let mut byte_buffer = [0u8; 1];
        let amount_read = r.read(&mut byte_buffer).await?;

        if amount_read == 0 {
            return Err(AuthenticationDeserializationError::NoDataFound.into());
        }

        match byte_buffer[0] {
            0 => Ok(AuthenticationMethod::None),
            1 => Ok(AuthenticationMethod::GSSAPI),
            2 => Ok(AuthenticationMethod::UsernameAndPassword),
            3 => Ok(AuthenticationMethod::ChallengeHandshake),
            5 => Ok(AuthenticationMethod::ChallengeResponse),
            6 => Ok(AuthenticationMethod::SSL),
            7 => Ok(AuthenticationMethod::NDS),
            8 => Ok(AuthenticationMethod::MultiAuthenticationFramework),
            9 => Ok(AuthenticationMethod::JSONPropertyBlock),
            x if (0x80..=0xfe).contains(&x) => Ok(AuthenticationMethod::PrivateMethod(x)),
            0xff => Ok(AuthenticationMethod::NoAcceptableMethods),
            e => Err(AuthenticationDeserializationError::InvalidAuthenticationByte(e).into()),
        }
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        let value = match self {
            AuthenticationMethod::None => 0,
            AuthenticationMethod::GSSAPI => 1,
            AuthenticationMethod::UsernameAndPassword => 2,
            AuthenticationMethod::ChallengeHandshake => 3,
            AuthenticationMethod::ChallengeResponse => 5,
            AuthenticationMethod::SSL => 6,
            AuthenticationMethod::NDS => 7,
            AuthenticationMethod::MultiAuthenticationFramework => 8,
            AuthenticationMethod::JSONPropertyBlock => 9,
            AuthenticationMethod::PrivateMethod(pm) => *pm,
            AuthenticationMethod::NoAcceptableMethods => 0xff,
        };

        Ok(w.write_all(&[value]).await?)
    }
}

#[cfg(test)]
impl Arbitrary for AuthenticationMethod {
    fn arbitrary(g: &mut Gen) -> AuthenticationMethod {
        let mut vals = vec![
            AuthenticationMethod::None,
            AuthenticationMethod::GSSAPI,
            AuthenticationMethod::UsernameAndPassword,
            AuthenticationMethod::ChallengeHandshake,
            AuthenticationMethod::ChallengeResponse,
            AuthenticationMethod::SSL,
            AuthenticationMethod::NDS,
            AuthenticationMethod::MultiAuthenticationFramework,
            AuthenticationMethod::JSONPropertyBlock,
            AuthenticationMethod::NoAcceptableMethods,
        ];
        for x in 0x80..0xffu8 {
            vals.push(AuthenticationMethod::PrivateMethod(x));
        }
        g.choose(&vals).unwrap().clone()
    }
}

standard_roundtrip!(auth_byte_roundtrips, AuthenticationMethod);

#[test]
fn bad_byte() {
    let no_len = vec![42];
    let mut cursor = Cursor::new(no_len);
    let ys = AuthenticationMethod::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::AuthenticationMethodError(
            AuthenticationDeserializationError::InvalidAuthenticationByte(42)
        )),
        task::block_on(ys)
    );
}

#[test]
fn display_isnt_empty() {
    let vals = vec![
        AuthenticationMethod::None,
        AuthenticationMethod::GSSAPI,
        AuthenticationMethod::UsernameAndPassword,
        AuthenticationMethod::ChallengeHandshake,
        AuthenticationMethod::ChallengeResponse,
        AuthenticationMethod::SSL,
        AuthenticationMethod::NDS,
        AuthenticationMethod::MultiAuthenticationFramework,
        AuthenticationMethod::JSONPropertyBlock,
        AuthenticationMethod::NoAcceptableMethods,
        AuthenticationMethod::PrivateMethod(42),
    ];

    for method in vals.iter() {
        let str = format!("{}", method);
        assert!(str.is_ascii());
        assert!(!str.is_empty());
    }
}
