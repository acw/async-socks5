use crate::errors::{DeserializationError, SerializationError};
use crate::serialize::{read_amt, read_string, write_string};
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use proptest::prelude::proptest;
#[cfg(test)]
use proptest::prelude::{Arbitrary, BoxedStrategy, Strategy, any, prop_oneof};
use std::convert::TryFrom;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use thiserror::Error;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum SOCKSv5Address {
    IP4(Ipv4Addr),
    IP6(Ipv6Addr),
    Name(String),
}

#[cfg(test)]
const HOSTNAME_REGEX: &str = "[a-zA-Z0-9_.]+";

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
                SOCKSv5Address::Name(hostname)
            }),
        ].boxed()
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum AddressConversionError {
    #[error("Couldn't convert IPv4 address into destination type")]
    CouldntConvertIP4,
    #[error("Couldn't convert IPv6 address into destination type")]
    CouldntConvertIP6,
    #[error("Couldn't convert name into destination type")]
    CouldntConvertName,
}

impl From<IpAddr> for SOCKSv5Address {
    fn from(x: IpAddr) -> SOCKSv5Address {
        match x {
            IpAddr::V4(a) => SOCKSv5Address::IP4(a),
            IpAddr::V6(a) => SOCKSv5Address::IP6(a),
        }
    }
}

impl TryFrom<SOCKSv5Address> for IpAddr {
    type Error = AddressConversionError;

    fn try_from(value: SOCKSv5Address) -> Result<Self, Self::Error> {
        match value {
            SOCKSv5Address::IP4(a) => Ok(IpAddr::V4(a)),
            SOCKSv5Address::IP6(a) => Ok(IpAddr::V6(a)),
            SOCKSv5Address::Name(_) => Err(AddressConversionError::CouldntConvertName),
        }
    }
}

impl From<Ipv4Addr> for SOCKSv5Address {
    fn from(x: Ipv4Addr) -> Self {
        SOCKSv5Address::IP4(x)
    }
}

impl TryFrom<SOCKSv5Address> for Ipv4Addr {
    type Error = AddressConversionError;

    fn try_from(value: SOCKSv5Address) -> Result<Self, Self::Error> {
        match value {
            SOCKSv5Address::IP4(a) => Ok(a),
            SOCKSv5Address::IP6(_) => Err(AddressConversionError::CouldntConvertIP6),
            SOCKSv5Address::Name(_) => Err(AddressConversionError::CouldntConvertName),
        }
    }
}

impl From<Ipv6Addr> for SOCKSv5Address {
    fn from(x: Ipv6Addr) -> Self {
        SOCKSv5Address::IP6(x)
    }
}

impl TryFrom<SOCKSv5Address> for Ipv6Addr {
    type Error = AddressConversionError;

    fn try_from(value: SOCKSv5Address) -> Result<Self, Self::Error> {
        match value {
            SOCKSv5Address::IP4(_) => Err(AddressConversionError::CouldntConvertIP4),
            SOCKSv5Address::IP6(a) => Ok(a),
            SOCKSv5Address::Name(_) => Err(AddressConversionError::CouldntConvertName),
        }
    }
}

impl From<String> for SOCKSv5Address {
    fn from(x: String) -> Self {
        SOCKSv5Address::Name(x)
    }
}

impl<'a> From<&'a str> for SOCKSv5Address {
    fn from(x: &str) -> SOCKSv5Address {
        SOCKSv5Address::Name(x.to_string())
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

impl SOCKSv5Address {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
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

pub trait HasLocalAddress {
    fn local_addr(&self) -> (SOCKSv5Address, u16);
}

standard_roundtrip!(address_roundtrips, SOCKSv5Address);

proptest! {
    #[test]
    fn ip_conversion(x: IpAddr) {
        match x {
            IpAddr::V4(ref a) =>
                assert_eq!(Err(AddressConversionError::CouldntConvertIP4),
                           Ipv6Addr::try_from(SOCKSv5Address::from(*a))),
            IpAddr::V6(ref a) =>
                assert_eq!(Err(AddressConversionError::CouldntConvertIP6),
                           Ipv4Addr::try_from(SOCKSv5Address::from(*a))),
        }
        assert_eq!(x, IpAddr::try_from(SOCKSv5Address::from(x)).unwrap());
    }

    #[test]
    fn ip4_conversion(x: Ipv4Addr) {
        assert_eq!(x, Ipv4Addr::try_from(SOCKSv5Address::from(x)).unwrap());
    }

    #[test]
    fn ip6_conversion(x: Ipv6Addr) {
        assert_eq!(x, Ipv6Addr::try_from(SOCKSv5Address::from(x)).unwrap());
    }

    #[test]
    fn display_matches(x: SOCKSv5Address) {
        match x {
            SOCKSv5Address::IP4(a) => assert_eq!(format!("{}", a), format!("{}", x)),
            SOCKSv5Address::IP6(a) => assert_eq!(format!("{}", a), format!("{}", x)),
            SOCKSv5Address::Name(ref a) => assert_eq!(*a, x.to_string()),
        }
    }

    #[test]
    fn bad_read_key(x: u8) {
        match x {
            1 | 3 | 4 => {}
            _ => {
                let buffer = [x, 0, 1, 2, 9, 10];
                let mut cursor = Cursor::new(buffer);
                let meh = SOCKSv5Address::read(&mut cursor);
                assert_eq!(Err(DeserializationError::InvalidAddressType(x)), task::block_on(meh));
            }
        }
    }
}

#[test]
fn domain_name_sanity() {
    let name = "uhsure.com";
    let strname = name.to_string();

    let addr1 = SOCKSv5Address::from(name);
    let addr2 = SOCKSv5Address::from(strname);

    assert_eq!(addr1, addr2);
    assert_eq!(
        Err(AddressConversionError::CouldntConvertName),
        IpAddr::try_from(addr1.clone())
    );
    assert_eq!(
        Err(AddressConversionError::CouldntConvertName),
        Ipv4Addr::try_from(addr1.clone())
    );
    assert_eq!(
        Err(AddressConversionError::CouldntConvertName),
        Ipv6Addr::try_from(addr1)
    );
}
