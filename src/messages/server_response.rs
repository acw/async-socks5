use crate::address::{SOCKSv5Address, SOCKSv5AddressReadError, SOCKSv5AddressWriteError};
#[cfg(test)]
use proptest_derive::Arbitrary;
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
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

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ServerResponse {
    pub status: ServerResponseStatus,
    pub bound_address: SOCKSv5Address,
    pub bound_port: u16,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerResponseReadError {
    #[error("Error reading from underlying buffer: {0}")]
    ReadError(String),
    #[error(transparent)]
    AddressReadError(#[from] SOCKSv5AddressReadError),
    #[error("Invalid version; expected 5, got {0}")]
    InvalidVersion(u8),
    #[error("Invalid reserved byte; saw {0}, should be 0")]
    InvalidReservedByte(u8),
    #[error("Invalid (or just unknown) server response value {0}")]
    InvalidServerResponse(u8),
}

impl From<std::io::Error> for ServerResponseReadError {
    fn from(x: std::io::Error) -> ServerResponseReadError {
        ServerResponseReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ServerResponseWriteError {
    #[error("Error reading from underlying buffer: {0}")]
    WriteError(String),
    #[error(transparent)]
    AddressWriteError(#[from] SOCKSv5AddressWriteError),
}

impl From<std::io::Error> for ServerResponseWriteError {
    fn from(x: std::io::Error) -> ServerResponseWriteError {
        ServerResponseWriteError::WriteError(format!("{}", x))
    }
}

impl ServerResponse {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, ServerResponseReadError> {
        let version = r.read_u8().await?;
        if version != 5 {
            return Err(ServerResponseReadError::InvalidVersion(version));
        }

        let status_byte = r.read_u8().await?;

        let reserved_byte = r.read_u8().await?;
        if reserved_byte != 0 {
            return Err(ServerResponseReadError::InvalidReservedByte(reserved_byte));
        }

        let status = match status_byte {
            0x00 => ServerResponseStatus::RequestGranted,
            0x01 => ServerResponseStatus::GeneralFailure,
            0x02 => ServerResponseStatus::ConnectionNotAllowedByRule,
            0x03 => ServerResponseStatus::NetworkUnreachable,
            0x04 => ServerResponseStatus::HostUnreachable,
            0x05 => ServerResponseStatus::ConnectionRefused,
            0x06 => ServerResponseStatus::TTLExpired,
            0x07 => ServerResponseStatus::CommandNotSupported,
            0x08 => ServerResponseStatus::AddressTypeNotSupported,
            x => return Err(ServerResponseReadError::InvalidServerResponse(x)),
        };

        let bound_address = SOCKSv5Address::read(r).await?;
        let bound_port = r.read_u16().await?;

        Ok(ServerResponse {
            status,
            bound_address,
            bound_port,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ServerResponseWriteError> {
        w.write_u8(5).await?;

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
        w.write_u8(status_code).await?;
        w.write_u8(0).await?;
        self.bound_address.write(w).await?;
        w.write_u16(self.bound_port).await?;

        Ok(())
    }
}

crate::standard_roundtrip!(server_response_roundtrips, ServerResponse);

#[tokio::test]
async fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ServerResponse::read(&mut cursor).await;
    assert!(matches!(ys, Err(ServerResponseReadError::ReadError(_))));
}

#[tokio::test]
async fn check_bad_version() {
    let bad_ver = vec![6, 1, 1];
    let mut cursor = Cursor::new(bad_ver);
    let ys = ServerResponse::read(&mut cursor).await;
    assert_eq!(Err(ServerResponseReadError::InvalidVersion(6)), ys);
}

#[tokio::test]
async fn check_bad_reserved() {
    let bad_cmd = vec![5, 32, 0x42];
    let mut cursor = Cursor::new(bad_cmd);
    let ys = ServerResponse::read(&mut cursor).await;
    assert_eq!(Err(ServerResponseReadError::InvalidReservedByte(0x42)), ys);
}

#[tokio::test]
async fn check_bad_command() {
    let bad_cmd = vec![5, 32, 0];
    let mut cursor = Cursor::new(bad_cmd);
    let ys = ServerResponse::read(&mut cursor).await;
    assert_eq!(Err(ServerResponseReadError::InvalidServerResponse(32)), ys);
}

#[tokio::test]
async fn short_write_fails_right() {
    let mut buffer = [0u8; 2];
    let cmd = ServerResponse {
        status: ServerResponseStatus::AddressTypeNotSupported,
        bound_address: SOCKSv5Address::Hostname("tester.com".to_string()),
        bound_port: 99,
    };
    let mut cursor = Cursor::new(&mut buffer as &mut [u8]);
    let result = cmd.write(&mut cursor).await;
    assert!(matches!(
        result,
        Err(ServerResponseWriteError::WriteError(_))
    ));
}
