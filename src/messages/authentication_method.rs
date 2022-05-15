#[cfg(test)]
use proptest::prelude::{prop_oneof, Arbitrary, Just, Strategy};
#[cfg(test)]
use proptest::strategy::BoxedStrategy;
use std::fmt;
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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

#[derive(Clone, Debug, Error, PartialEq)]
pub enum AuthenticationMethodReadError {
    #[error("Invalid authentication method #{0}")]
    UnknownAuthenticationMethod(u8),
    #[error("Error in underlying buffer: {0}")]
    ReadError(String),
}

impl From<std::io::Error> for AuthenticationMethodReadError {
    fn from(x: std::io::Error) -> AuthenticationMethodReadError {
        AuthenticationMethodReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum AuthenticationMethodWriteError {
    #[error("Trying to write invalid authentication method #{0}")]
    InvalidAuthMethod(u8),
    #[error("Error in underlying buffer: {0}")]
    WriteError(String),
}

impl From<std::io::Error> for AuthenticationMethodWriteError {
    fn from(x: std::io::Error) -> AuthenticationMethodWriteError {
        AuthenticationMethodWriteError::WriteError(format!("{}", x))
    }
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

#[cfg(test)]
impl Arbitrary for AuthenticationMethod {
    type Parameters = ();
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(_args: Self::Parameters) -> BoxedStrategy<Self> {
        prop_oneof![
            Just(AuthenticationMethod::None),
            Just(AuthenticationMethod::GSSAPI),
            Just(AuthenticationMethod::UsernameAndPassword),
            Just(AuthenticationMethod::ChallengeHandshake),
            Just(AuthenticationMethod::ChallengeResponse),
            Just(AuthenticationMethod::SSL),
            Just(AuthenticationMethod::NDS),
            Just(AuthenticationMethod::MultiAuthenticationFramework),
            Just(AuthenticationMethod::JSONPropertyBlock),
            Just(AuthenticationMethod::NoAcceptableMethods),
            (0x80u8..=0xfe).prop_map(AuthenticationMethod::PrivateMethod),
        ]
        .boxed()
    }
}

impl AuthenticationMethod {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<AuthenticationMethod, AuthenticationMethodReadError> {
        match r.read_u8().await? {
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
            e => Err(AuthenticationMethodReadError::UnknownAuthenticationMethod(
                e,
            )),
        }
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        self,
        w: &mut W,
    ) -> Result<(), AuthenticationMethodWriteError> {
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
            AuthenticationMethod::PrivateMethod(pm) if (0x80..=0xfe).contains(&pm) => pm,
            AuthenticationMethod::PrivateMethod(pm) => {
                return Err(AuthenticationMethodWriteError::InvalidAuthMethod(pm))
            }
            AuthenticationMethod::NoAcceptableMethods => 0xff,
        };

        Ok(w.write_u8(value).await?)
    }
}

crate::standard_roundtrip!(auth_byte_roundtrips, AuthenticationMethod);

#[tokio::test]
async fn bad_byte() {
    let no_len = vec![42];
    let mut cursor = Cursor::new(no_len);
    let ys = AuthenticationMethod::read(&mut cursor).await.unwrap_err();
    assert_eq!(
        AuthenticationMethodReadError::UnknownAuthenticationMethod(42),
        ys
    );
}

#[tokio::test]
async fn display_isnt_empty() {
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
