use crate::errors::{DeserializationError, SerializationError};
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
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};
#[cfg(test)]
use std::net::Ipv4Addr;
use std::pin::Pin;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClientConnectionCommand {
    EstablishTCPStream,
    EstablishTCPPortBinding,
    AssociateUDPPort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientConnectionRequest {
    pub command_code: ClientConnectionCommand,
    pub destination_address: SOCKSv5Address,
    pub destination_port: u16,
}

impl ClientConnectionRequest {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 2];
        let raw_r = Pin::into_inner(r);

        read_amt(Pin::new(raw_r), 2, &mut buffer).await?;

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        let command_code = match buffer[1] {
            0x01 => ClientConnectionCommand::EstablishTCPStream,
            0x02 => ClientConnectionCommand::EstablishTCPPortBinding,
            0x03 => ClientConnectionCommand::AssociateUDPPort,
            x => return Err(DeserializationError::InvalidClientCommand(x)),
        };

        let destination_address = SOCKSv5Address::read(Pin::new(raw_r)).await?;

        read_amt(Pin::new(raw_r), 2, &mut buffer).await?;
        let destination_port = ((buffer[0] as u16) << 8) + (buffer[1] as u16);

        Ok(ClientConnectionRequest {
            command_code,
            destination_address,
            destination_port,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        let command = match self.command_code {
            ClientConnectionCommand::EstablishTCPStream => 1,
            ClientConnectionCommand::EstablishTCPPortBinding => 2,
            ClientConnectionCommand::AssociateUDPPort => 3,
        };

        w.write_all(&[5, command]).await?;
        self.destination_address.write(w).await?;
        w.write_all(&[
            (self.destination_port >> 8) as u8,
            (self.destination_port & 0xffu16) as u8,
        ])
        .await
        .map_err(SerializationError::IOError)
    }
}

#[cfg(test)]
impl Arbitrary for ClientConnectionCommand {
    fn arbitrary(g: &mut Gen) -> ClientConnectionCommand {
        let options = [
            ClientConnectionCommand::EstablishTCPStream,
            ClientConnectionCommand::EstablishTCPPortBinding,
            ClientConnectionCommand::AssociateUDPPort,
        ];
        g.choose(&options).unwrap().clone()
    }
}

#[cfg(test)]
impl Arbitrary for ClientConnectionRequest {
    fn arbitrary(g: &mut Gen) -> Self {
        let command_code = ClientConnectionCommand::arbitrary(g);
        let destination_address = SOCKSv5Address::arbitrary(g);
        let destination_port = u16::arbitrary(g);

        ClientConnectionRequest {
            command_code,
            destination_address,
            destination_port,
        }
    }
}

standard_roundtrip!(client_request_roundtrips, ClientConnectionRequest);

#[test]
fn check_short_reads() {
    let empty = vec![];
    let mut cursor = Cursor::new(empty);
    let ys = ClientConnectionRequest::read(Pin::new(&mut cursor));
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));

    let no_len = vec![5, 1];
    let mut cursor = Cursor::new(no_len);
    let ys = ClientConnectionRequest::read(Pin::new(&mut cursor));
    assert_eq!(Err(DeserializationError::NotEnoughData), task::block_on(ys));
}

#[test]
fn check_bad_version() {
    let bad_ver = vec![6, 1, 1];
    let mut cursor = Cursor::new(bad_ver);
    let ys = ClientConnectionRequest::read(Pin::new(&mut cursor));
    assert_eq!(
        Err(DeserializationError::InvalidVersion(5, 6)),
        task::block_on(ys)
    );
}

#[test]
fn check_bad_command() {
    let bad_cmd = vec![5, 32, 1];
    let mut cursor = Cursor::new(bad_cmd);
    let ys = ClientConnectionRequest::read(Pin::new(&mut cursor));
    assert_eq!(
        Err(DeserializationError::InvalidClientCommand(32)),
        task::block_on(ys)
    );
}

#[test]
fn short_write_fails_right() {
    let mut buffer = [0u8; 2];
    let cmd = ClientConnectionRequest {
        command_code: ClientConnectionCommand::AssociateUDPPort,
        destination_address: SOCKSv5Address::IP4(Ipv4Addr::from(0)),
        destination_port: 22,
    };
    let mut cursor = Cursor::new(&mut buffer as &mut [u8]);
    let result = task::block_on(cmd.write(&mut cursor));
    match result {
        Ok(_) => assert!(false, "Mysteriously able to fit > 2 bytes in 2 bytes."),
        Err(SerializationError::IOError(x)) => assert_eq!(ErrorKind::WriteZero, x.kind()),
        Err(e) => assert!(false, "Got the wrong error writing too much data: {}", e),
    }
}