use crate::address::{SOCKSv5Address, SOCKSv5AddressReadError, SOCKSv5AddressWriteError};
#[cfg(test)]
use proptest_derive::Arbitrary;
#[cfg(test)]
use std::io::Cursor;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub enum ClientConnectionCommand {
    EstablishTCPStream,
    EstablishTCPPortBinding,
    AssociateUDPPort,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientConnectionCommandReadError {
    #[error("Invalid client connection command code: {0}")]
    InvalidClientConnectionCommand(u8),
    #[error("Underlying buffer read error: {0}")]
    ReadError(String),
}

impl From<std::io::Error> for ClientConnectionCommandReadError {
    fn from(x: std::io::Error) -> ClientConnectionCommandReadError {
        ClientConnectionCommandReadError::ReadError(format!("{}", x))
    }
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientConnectionCommandWriteError {
    #[error("Underlying buffer write error: {0}")]
    WriteError(String),
    #[error(transparent)]
    SOCKSAddressWriteError(#[from] SOCKSv5AddressWriteError),
}

impl From<std::io::Error> for ClientConnectionCommandWriteError {
    fn from(x: std::io::Error) -> ClientConnectionCommandWriteError {
        ClientConnectionCommandWriteError::WriteError(format!("{}", x))
    }
}

impl ClientConnectionCommand {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<ClientConnectionCommand, ClientConnectionCommandReadError> {
        match r.read_u8().await? {
            0x01 => Ok(ClientConnectionCommand::EstablishTCPStream),
            0x02 => Ok(ClientConnectionCommand::EstablishTCPPortBinding),
            0x03 => Ok(ClientConnectionCommand::AssociateUDPPort),
            x => Err(ClientConnectionCommandReadError::InvalidClientConnectionCommand(x)),
        }
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), std::io::Error> {
        match self {
            ClientConnectionCommand::EstablishTCPStream => w.write_u8(0x01).await,
            ClientConnectionCommand::EstablishTCPPortBinding => w.write_u8(0x02).await,
            ClientConnectionCommand::AssociateUDPPort => w.write_u8(0x03).await,
        }
    }
}

crate::standard_roundtrip!(client_command_roundtrips, ClientConnectionCommand);

#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg_attr(test, derive(Arbitrary))]
pub struct ClientConnectionRequest {
    pub command_code: ClientConnectionCommand,
    pub destination_address: SOCKSv5Address,
    pub destination_port: u16,
}

#[derive(Clone, Debug, Error, PartialEq)]
pub enum ClientConnectionRequestReadError {
    #[error("Invalid version in client request: {0} (expected 5)")]
    InvalidVersion(u8),
    #[error("Invalid command for client request: {0}")]
    InvalidCommand(#[from] ClientConnectionCommandReadError),
    #[error("Invalid reserved byte: {0} (expected 0)")]
    InvalidReservedByte(u8),
    #[error("Underlying read error: {0}")]
    ReadError(String),
    #[error(transparent)]
    AddressReadError(#[from] SOCKSv5AddressReadError),
}

impl From<std::io::Error> for ClientConnectionRequestReadError {
    fn from(x: std::io::Error) -> ClientConnectionRequestReadError {
        ClientConnectionRequestReadError::ReadError(format!("{}", x))
    }
}

impl ClientConnectionRequest {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: &mut R,
    ) -> Result<Self, ClientConnectionRequestReadError> {
        let version = r.read_u8().await?;
        if version != 5 {
            return Err(ClientConnectionRequestReadError::InvalidVersion(version));
        }

        let command_code = ClientConnectionCommand::read(r).await?;

        let reserved = r.read_u8().await?;
        if reserved != 0 {
            return Err(ClientConnectionRequestReadError::InvalidReservedByte(
                reserved,
            ));
        }

        let destination_address = SOCKSv5Address::read(r).await?;
        let destination_port = r.read_u16().await?;

        Ok(ClientConnectionRequest {
            command_code,
            destination_address,
            destination_port,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), ClientConnectionCommandWriteError> {
        w.write_u8(5).await?;
        self.command_code.write(w).await?;
        w.write_u8(0).await?;
        self.destination_address.write(w).await?;
        w.write_u16(self.destination_port).await?;
        Ok(())
    }
}

crate::standard_roundtrip!(client_request_roundtrips, ClientConnectionRequest);

#[tokio::test]
async fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientConnectionRequest::read(&mut cursor).await;
    assert!(matches!(
        ys,
        Err(ClientConnectionRequestReadError::ReadError(_))
    ));

    let no_len = vec![5, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientConnectionRequest::read(&mut cursor).await;
    assert!(matches!(
        ys,
        Err(ClientConnectionRequestReadError::ReadError(_))
    ));
}

#[tokio::test]
async fn check_bad_version() {
    let bad_ver = vec![6, 1, 1];
    let mut cursor = Cursor::new(bad_ver);
    let ys = ClientConnectionRequest::read(&mut cursor).await;
    assert_eq!(Err(ClientConnectionRequestReadError::InvalidVersion(6)), ys);
}

#[tokio::test]
async fn check_bad_command() {
    let bad_cmd = vec![5, 32, 1];
    let mut cursor = Cursor::new(bad_cmd);
    let ys = ClientConnectionRequest::read(&mut cursor).await;
    assert_eq!(
        Err(ClientConnectionRequestReadError::InvalidCommand(
            ClientConnectionCommandReadError::InvalidClientConnectionCommand(32)
        )),
        ys
    );
}

#[tokio::test]
async fn short_write_fails_right() {
    use std::net::Ipv4Addr;

    let mut buffer = [0u8; 2];
    let cmd = ClientConnectionRequest {
        command_code: ClientConnectionCommand::AssociateUDPPort,
        destination_address: SOCKSv5Address::IP4(Ipv4Addr::from(0)),
        destination_port: 22,
    };
    let mut cursor = Cursor::new(&mut buffer as &mut [u8]);
    let result = cmd.write(&mut cursor).await;
    match result {
        Ok(_) => panic!("Mysteriously able to fit > 2 bytes in 2 bytes."),
        Err(ClientConnectionCommandWriteError::WriteError(x)) => {
            assert!(x.contains("write zero"));
        }
        Err(e) => panic!("Got the wrong error writing too much data: {}", e),
    }
}
