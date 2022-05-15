#[cfg(test)]
use proptest::prelude::{Arbitrary, BoxedStrategy, Strategy};
use std::convert::TryFrom;
use std::string::FromUtf8Error;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, PartialEq)]
pub struct SOCKSv5String(String);

#[cfg(test)]
const STRING_REGEX: &str = "[a-zA-Z0-9_.|!@#$%^]+";

#[cfg(test)]
impl Arbitrary for SOCKSv5String {
    type Parameters = Option<u16>;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let max_len = args.unwrap_or(32) as usize;

        STRING_REGEX
            .prop_map(move |mut str| {
                str.shrink_to(max_len);
                SOCKSv5String(str)
            })
            .boxed()
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SOCKSv5StringReadError {
    #[error("Underlying buffer read error: {0}")]
    ReadError(String),
    #[error("SOCKSv5 string encoding error; encountered empty string (?)")]
    ZeroStringLength,
    #[error("Invalid UTF-8 string: {0}")]
    InvalidUtf8Error(#[from] FromUtf8Error),
}

impl From<std::io::Error> for SOCKSv5StringReadError {
    fn from(x: std::io::Error) -> SOCKSv5StringReadError {
        SOCKSv5StringReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SOCKSv5StringWriteError {
    #[error("Underlying buffer write error: {0}")]
    WriteError(String),
    #[error("String too large to encode according to SOCKSv5 reuls ({0} bytes long)")]
    TooBig(usize),
    #[error("Cannot serialize the empty string in SOCKSv5")]
    ZeroStringLength,
}

impl From<std::io::Error> for SOCKSv5StringWriteError {
    fn from(x: std::io::Error) -> SOCKSv5StringWriteError {
        SOCKSv5StringWriteError::WriteError(format!("{}", x))
    }
}

impl SOCKSv5String {
    pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> Result<Self, SOCKSv5StringReadError> {
        let length = r.read_u8().await? as usize;

        if length == 0 {
            return Err(SOCKSv5StringReadError::ZeroStringLength);
        }

        let mut bytestring = vec![0; length];
        r.read_exact(&mut bytestring).await?;

        Ok(SOCKSv5String(String::from_utf8(bytestring)?))
    }

    pub async fn write<W: AsyncWrite + Unpin>(
        self,
        w: &mut W,
    ) -> Result<(), SOCKSv5StringWriteError> {
        let bytestring = self.0.as_bytes();

        if bytestring.is_empty() {
            return Err(SOCKSv5StringWriteError::ZeroStringLength);
        }

        let length = match u8::try_from(bytestring.len()) {
            Err(_) => return Err(SOCKSv5StringWriteError::TooBig(bytestring.len())),
            Ok(x) => x,
        };

        w.write_u8(length).await?;
        w.write_all(bytestring).await?;

        Ok(())
    }
}

impl From<String> for SOCKSv5String {
    fn from(x: String) -> Self {
        SOCKSv5String(x)
    }
}

impl<'a> From<&'a str> for SOCKSv5String {
    fn from(x: &str) -> Self {
        SOCKSv5String(x.to_string())
    }
}

impl From<SOCKSv5String> for String {
    fn from(x: SOCKSv5String) -> Self {
        x.0
    }
}

crate::standard_roundtrip!(socks_string_roundtrips, SOCKSv5String);
