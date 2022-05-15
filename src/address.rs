use crate::messages::string::{SOCKSv5String, SOCKSv5StringReadError, SOCKSv5StringWriteError};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SOCKSv5Address {
    IP4(Ipv4Addr),
    IP6(Ipv6Addr),
    Hostname(String),
}

impl From<IpAddr> for SOCKSv5Address {
    fn from(x: IpAddr) -> SOCKSv5Address {
        match x {
            IpAddr::V4(a) => SOCKSv5Address::IP4(a),
            IpAddr::V6(a) => SOCKSv5Address::IP6(a),
        }
    }
}

impl From<Ipv4Addr> for SOCKSv5Address {
    fn from(x: Ipv4Addr) -> SOCKSv5Address {
        SOCKSv5Address::IP4(x)
    }
}

impl From<Ipv6Addr> for SOCKSv5Address {
    fn from(x: Ipv6Addr) -> SOCKSv5Address {
        SOCKSv5Address::IP6(x)
    }
}

impl From<SOCKSv5String> for SOCKSv5Address {
    fn from(x: SOCKSv5String) -> SOCKSv5Address {
        SOCKSv5Address::Hostname(x.into())
    }
}

impl<'a> From<&'a str> for SOCKSv5Address {
    fn from(x: &str) -> SOCKSv5Address {
        SOCKSv5Address::Hostname(x.to_string())
    }
}

impl From<String> for SOCKSv5Address {
    fn from(x: String) -> SOCKSv5Address {
        SOCKSv5Address::Hostname(x)
    }
}

impl fmt::Display for SOCKSv5Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SOCKSv5Address::IP4(a) => write!(f, "{}", a),
            SOCKSv5Address::IP6(a) => write!(f, "{}", a),
            SOCKSv5Address::Hostname(a) => write!(f, "{}", a),
        }
    }
}

#[cfg(test)]
const HOSTNAME_REGEX: &str = "[a-zA-Z0-9_.]+";

#[cfg(test)]
use proptest::prelude::{any, prop_oneof, Arbitrary, BoxedStrategy, Strategy};

#[cfg(test)]
impl Arbitrary for SOCKSv5Address {
    type Parameters = Option<u16>;
    type Strategy = BoxedStrategy<Self>;

    fn arbitrary_with(args: Self::Parameters) -> Self::Strategy {
        let max_len = args.unwrap_or(32) as usize;

        prop_oneof![
            any::<Ipv4Addr>().prop_map(SOCKSv5Address::IP4),
            any::<Ipv6Addr>().prop_map(SOCKSv5Address::IP6),
            HOSTNAME_REGEX.prop_map(move |mut hostname| {
                hostname.shrink_to(max_len);
                SOCKSv5Address::Hostname(hostname)
            }),
        ]
        .boxed()
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SOCKSv5AddressReadError {
    #[error("Bad address type {0} (expected 1, 3, or 4)")]
    BadAddressType(u8),
    #[error("Read buffer error: {0}")]
    ReadError(String),
    #[error(transparent)]
    SOCKSv5StringError(#[from] SOCKSv5StringReadError),
}

impl From<std::io::Error> for SOCKSv5AddressReadError {
    fn from(x: std::io::Error) -> SOCKSv5AddressReadError {
        SOCKSv5AddressReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum SOCKSv5AddressWriteError {
    #[error(transparent)]
    SOCKSv5StringError(#[from] SOCKSv5StringWriteError),
    #[error("Write buffer error: {0}")]
    WriteError(String),
}

impl From<std::io::Error> for SOCKSv5AddressWriteError {
    fn from(x: std::io::Error) -> SOCKSv5AddressWriteError {
        SOCKSv5AddressWriteError::WriteError(format!("{}", x))
    }
}

impl SOCKSv5Address {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, SOCKSv5AddressReadError> {
        match r.read_u8().await? {
            1 => {
                let mut addr_buffer = [0; 4];
                r.read_exact(&mut addr_buffer).await?;
                let ip4 = Ipv4Addr::from(addr_buffer);
                Ok(SOCKSv5Address::IP4(ip4))
            }

            3 => {
                let string = SOCKSv5String::read(r).await?;
                Ok(SOCKSv5Address::from(string))
            }

            4 => {
                let mut addr_buffer = [0; 16];
                r.read_exact(&mut addr_buffer).await?;
                let ip6 = Ipv6Addr::from(addr_buffer);
                Ok(SOCKSv5Address::IP6(ip6))
            }

            x => Err(SOCKSv5AddressReadError::BadAddressType(x)),
        }
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SOCKSv5AddressWriteError> {
        match self {
            SOCKSv5Address::IP4(x) => {
                w.write_u8(1).await?;
                w.write_all(&x.octets()).await?;
                Ok(())
            }

            SOCKSv5Address::IP6(x) => {
                w.write_u8(4).await?;
                w.write_all(&x.octets()).await?;
                Ok(())
            }

            SOCKSv5Address::Hostname(x) => {
                w.write_u8(3).await?;
                let string = SOCKSv5String::from(x.clone());
                string.write(w).await?;
                Ok(())
            }
        }
    }
}

crate::standard_roundtrip!(socks_address_roundtrips, SOCKSv5Address);
