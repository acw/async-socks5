use crate::errors::{DeserializationError, SerializationError};
use crate::network::generic::IntoErrorResponse;
use crate::network::SOCKSv5Address;
use crate::serialize::read_amt;
use crate::standard_roundtrip;
#[cfg(test)]
use async_std::io::ErrorKind;
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use log::warn;
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};
use std::net::Ipv4Addr;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ServerResponseStatus {
    #[error("Actually, everything's fine (weird to see this in an error)")]
    RequestGranted,
    #[error("General server failure")]
    GeneralFailure,
    #[error("Connection not allowed by policy rule")]
    ConnectionNotAllowedByRule,
    #[error("Network unreachable")]
    NetworkUnreachable,
    #[error("Host unreachable")]
    HostUnreachable,
    #[error("Connection refused")]
    ConnectionRefused,
    #[error("TTL expired")]
    TTLExpired,
    #[error("Command not supported")]
    CommandNotSupported,
    #[error("Address type not supported")]
    AddressTypeNotSupported,
}

impl IntoErrorResponse for ServerResponseStatus {
    fn into_response(&self) -> ServerResponseStatus {
        self.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerResponse {
    pub status: ServerResponseStatus,
    pub bound_address: SOCKSv5Address,
    pub bound_port: u16,
}

impl ServerResponse {
    pub fn error<E: IntoErrorResponse>(resp: &E) -> ServerResponse {
        ServerResponse {
            status: resp.into_response(),
            bound_address: SOCKSv5Address::IP4(Ipv4Addr::new(0, 0, 0, 0)),
            bound_port: 0,
        }
    }
}

impl ServerResponse {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 3];

        read_amt(r, 3, &mut buffer).await?;

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        if buffer[2] != 0 {
            warn!(target: "async-socks5", "Hey, this isn't terrible, but the server is sending invalid reserved bytes.");
        }

        let status = match buffer[1] {
            0x00 => ServerResponseStatus::RequestGranted,
            0x01 => ServerResponseStatus::GeneralFailure,
            0x02 => ServerResponseStatus::ConnectionNotAllowedByRule,
            0x03 => ServerResponseStatus::NetworkUnreachable,
            0x04 => ServerResponseStatus::HostUnreachable,
            0x05 => ServerResponseStatus::ConnectionRefused,
            0x06 => ServerResponseStatus::TTLExpired,
            0x07 => ServerResponseStatus::CommandNotSupported,
            0x08 => ServerResponseStatus::AddressTypeNotSupported,
            x => return Err(DeserializationError::InvalidServerResponse(x)),
        };

        let bound_address = SOCKSv5Address::read(r).await?;
        read_amt(r, 2, &mut buffer).await?;
        let bound_port = ((buffer[0] as u16) << 8) + (buffer[1] as u16);

        Ok(ServerResponse {
            status,
            bound_address,
            bound_port,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        let status_code = match self.status {
            ServerResponseStatus::RequestGranted => 0x00,
            ServerResponseStatus::GeneralFailure => 0x01,
            ServerResponseStatus::ConnectionNotAllowedByRule => 0x02,
            ServerResponseStatus::NetworkUnreachable => 0x03,
            ServerResponseStatus::HostUnreachable => 0x04,
            ServerResponseStatus::ConnectionRefused => 0x05,
            ServerResponseStatus::TTLExpired => 0x06,
            ServerResponseStatus::CommandNotSupported => 0x07,
            ServerResponseStatus::AddressTypeNotSupported => 0x08,
        };

        w.write_all(&[5, status_code, 0]).await?;
        self.bound_address.write(w).await?;
        w.write_all(&[
            (self.bound_port >> 8) as u8,
            (self.bound_port & 0xffu16) as u8,
        ])
        .await
        .map_err(SerializationError::IOError)
    }
}

#[cfg(test)]
impl Arbitrary for ServerResponseStatus {
    fn arbitrary(g: &mut Gen) -> ServerResponseStatus {
        let options = [
            ServerResponseStatus::RequestGranted,
            ServerResponseStatus::GeneralFailure,
            ServerResponseStatus::ConnectionNotAllowedByRule,
            ServerResponseStatus::NetworkUnreachable,
            ServerResponseStatus::HostUnreachable,
            ServerResponseStatus::ConnectionRefused,
            ServerResponseStatus::TTLExpired,
            ServerResponseStatus::CommandNotSupported,
            ServerResponseStatus::AddressTypeNotSupported,
        ];
        g.choose(&options).unwrap().clone()
    }
}

#[cfg(test)]
impl Arbitrary for ServerResponse {
    fn arbitrary(g: &mut Gen) -> Self {
        let status = ServerResponseStatus::arbitrary(g);
        let bound_address = SOCKSv5Address::arbitrary(g);
        let bound_port = u16::arbitrary(g);

        ServerResponse {
            status,
            bound_address,
            bound_port,
        }
    }
}

standard_roundtrip!(server_response_roundtrips, ServerResponse);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerResponse::read(&mut cursor);
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));
}

#[test]
fn check_bad_version() {
    let bad_ver = vec![6, 1, 1];
    let mut cursor = Cursor::new(bad_ver);
    let ys = ServerResponse::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidVersion(5, 6)),
        task::block_on(ys)
    );
}

#[test]
fn check_bad_command() {
    let bad_cmd = vec![5, 32, 0x42];
    let mut cursor = Cursor::new(bad_cmd);
    let ys = ServerResponse::read(&mut cursor);
    assert_eq!(
        Err(DeserializationError::InvalidServerResponse(32)),
        task::block_on(ys)
    );
}

#[test]
fn short_write_fails_right() {
    let mut buffer = [0u8; 2];
    let cmd = ServerResponse::error(&ServerResponseStatus::AddressTypeNotSupported);
    let mut cursor = Cursor::new(&mut buffer as &mut [u8]);
    let result = task::block_on(cmd.write(&mut cursor));
    match result {
        Ok(_) => assert!(false, "Mysteriously able to fit > 2 bytes in 2 bytes."),
        Err(SerializationError::IOError(x)) => assert_eq!(ErrorKind::WriteZero, x.kind()),
        Err(e) => assert!(false, "Got the wrong error writing too much data: {}", e),
    }
}
