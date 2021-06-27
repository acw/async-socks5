use crate::errors::{DeserializationError, SerializationError};
#[cfg(test)]
use crate::messages::utils::arbitrary_socks_string;
use crate::serialize::{read_amt, read_string, write_string};
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;

pub trait ToSOCKSAddress: Send {
    fn to_socks_address(&self) -> SOCKSv5Address;
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SOCKSv5Address {
    IP4(Ipv4Addr),
    IP6(Ipv6Addr),
    Name(String),
}

impl ToSOCKSAddress for SOCKSv5Address {
    fn to_socks_address(&self) -> SOCKSv5Address {
        self.clone()
    }
}

impl ToSOCKSAddress for IpAddr {
    fn to_socks_address(&self) -> SOCKSv5Address {
        match self {
            IpAddr::V4(a) => SOCKSv5Address::IP4(*a),
            IpAddr::V6(a) => SOCKSv5Address::IP6(*a),
        }
    }
}

impl ToSOCKSAddress for Ipv4Addr {
    fn to_socks_address(&self) -> SOCKSv5Address {
        SOCKSv5Address::IP4(*self)
    }
}

impl ToSOCKSAddress for Ipv6Addr {
    fn to_socks_address(&self) -> SOCKSv5Address {
        SOCKSv5Address::IP6(*self)
    }
}

impl ToSOCKSAddress for String {
    fn to_socks_address(&self) -> SOCKSv5Address {
        SOCKSv5Address::Name(self.clone())
    }
}

impl<'a> ToSOCKSAddress for &'a str {
    fn to_socks_address(&self) -> SOCKSv5Address {
        SOCKSv5Address::Name(self.to_string())
    }
}

impl fmt::Display for SOCKSv5Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            SOCKSv5Address::IP4(a) => write!(f, "{}", a),
            SOCKSv5Address::IP6(a) => write!(f, "{}", a),
            SOCKSv5Address::Name(a) => write!(f, "{}", a),
        }
    }
}

impl From<IpAddr> for SOCKSv5Address {
    fn from(addr: IpAddr) -> SOCKSv5Address {
        match addr {
            IpAddr::V4(a) => SOCKSv5Address::IP4(a),
            IpAddr::V6(a) => SOCKSv5Address::IP6(a),
        }
    }
}

impl SOCKSv5Address {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        mut r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut byte_buffer = [0u8; 1];
        let amount_read = r.read(&mut byte_buffer).await?;

        if amount_read == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        match byte_buffer[0] {
            1 => {
                let mut addr_buffer = [0; 4];
                read_amt(r, 4, &mut addr_buffer).await?;
                Ok(SOCKSv5Address::IP4(Ipv4Addr::from(addr_buffer)))
            }
            3 => {
                let mut addr_buffer = [0; 16];
                read_amt(r, 16, &mut addr_buffer).await?;
                Ok(SOCKSv5Address::IP6(Ipv6Addr::from(addr_buffer)))
            }
            4 => {
                let name = read_string(r).await?;
                Ok(SOCKSv5Address::Name(name))
            }
            x => Err(DeserializationError::InvalidAddressType(x)),
        }
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        match self {
            SOCKSv5Address::IP4(x) => {
                w.write_all(&[1]).await?;
                w.write_all(&x.octets())
                    .await
                    .map_err(SerializationError::IOError)
            }
            SOCKSv5Address::IP6(x) => {
                w.write_all(&[3]).await?;
                w.write_all(&x.octets())
                    .await
                    .map_err(SerializationError::IOError)
            }
            SOCKSv5Address::Name(x) => {
                w.write_all(&[4]).await?;
                write_string(x, w).await
            }
        }
    }
}

#[cfg(test)]
impl Arbitrary for SOCKSv5Address {
    fn arbitrary(g: &mut Gen) -> Self {
        let ip4 = Ipv4Addr::arbitrary(g);
        let ip6 = Ipv6Addr::arbitrary(g);
        let nm = arbitrary_socks_string(g);

        g.choose(&[
            SOCKSv5Address::IP4(ip4),
            SOCKSv5Address::IP6(ip6),
            SOCKSv5Address::Name(nm),
        ])
        .unwrap()
        .clone()
    }
}

standard_roundtrip!(address_roundtrips, SOCKSv5Address);
