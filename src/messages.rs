use crate::errors::{AuthenticationDeserializationError, DeserializationError, SerializationError};
use crate::network::SOCKSv5Address;
use crate::serialize::{read_amt, read_string, write_string};
#[cfg(test)]
use async_std::task;
#[cfg(test)]
use futures::io::Cursor;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use log::warn;
#[cfg(test)]
use quickcheck::{quickcheck, Arbitrary, Gen};
use std::fmt;
use std::net::Ipv4Addr;
use std::pin::Pin;
use thiserror::Error;

/// Client greetings are the first message sent in a SOCKSv5 session. They
/// identify that there's a client that wants to talk to a server, and that
/// they can support any of the provided mechanisms for authenticating to
/// said server. (It feels weird that the offer/choice goes this way instead
/// of the reverse, but whatever.)
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientGreeting {
    pub acceptable_methods: Vec<AuthenticationMethod>,
}

impl ClientGreeting {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: Pin<&mut R>,
    ) -> Result<ClientGreeting, DeserializationError> {
        let mut buffer = [0; 1];
        let raw_r = Pin::into_inner(r);

        if raw_r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        if raw_r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        let mut acceptable_methods = Vec::with_capacity(buffer[0] as usize);
        for _ in 0..buffer[0] {
            acceptable_methods.push(AuthenticationMethod::read(Pin::new(raw_r)).await?);
        }

        Ok(ClientGreeting { acceptable_methods })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        if self.acceptable_methods.len() > 255 {
            return Err(SerializationError::TooManyAuthMethods(
                self.acceptable_methods.len(),
            ));
        }

        let mut buffer = Vec::with_capacity(self.acceptable_methods.len() + 2);
        buffer.push(5);
        buffer.push(self.acceptable_methods.len() as u8);
        w.write_all(&buffer).await?;
        for authmeth in self.acceptable_methods.iter() {
            authmeth.write(w).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
impl Arbitrary for ClientGreeting {
    fn arbitrary(g: &mut Gen) -> ClientGreeting {
        let amt = u8::arbitrary(g);
        let mut acceptable_methods = Vec::with_capacity(amt as usize);

        for _ in 0..amt {
            acceptable_methods.push(AuthenticationMethod::arbitrary(g));
        }

        ClientGreeting { acceptable_methods }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerChoice {
    pub chosen_method: AuthenticationMethod,
}

impl ServerChoice {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        mut r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 1];

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 5 {
            return Err(DeserializationError::InvalidVersion(5, buffer[0]));
        }

        let chosen_method = AuthenticationMethod::read(r).await?;

        Ok(ServerChoice { chosen_method })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[5]).await?;
        self.chosen_method.write(w).await
    }
}

#[cfg(test)]
impl Arbitrary for ServerChoice {
    fn arbitrary(g: &mut Gen) -> ServerChoice {
        ServerChoice {
            chosen_method: AuthenticationMethod::arbitrary(g),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClientUsernamePassword {
    pub username: String,
    pub password: String,
}

impl ClientUsernamePassword {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 1];
        let raw_r = Pin::into_inner(r);

        if raw_r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 1 {
            return Err(DeserializationError::InvalidVersion(1, buffer[0]));
        }

        let username = read_string(Pin::new(raw_r)).await?;
        let password = read_string(Pin::new(raw_r)).await?;

        Ok(ClientUsernamePassword { username, password })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[1]).await?;
        write_string(&self.username, w).await?;
        write_string(&self.password, w).await
    }
}

#[cfg(test)]
impl Arbitrary for ClientUsernamePassword {
    fn arbitrary(g: &mut Gen) -> Self {
        let username = arbitrary_socks_string(g);
        let password = arbitrary_socks_string(g);

        ClientUsernamePassword { username, password }
    }
}

#[cfg(test)]
pub fn arbitrary_socks_string(g: &mut Gen) -> String {
    loop {
        let mut potential = String::arbitrary(g);

        potential.truncate(255);
        let bytestring = potential.as_bytes();

        if bytestring.len() > 0 && bytestring.len() < 256 {
            return potential;
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerAuthResponse {
    pub success: bool,
}

impl ServerAuthResponse {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        mut r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 1];

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        if buffer[0] != 1 {
            return Err(DeserializationError::InvalidVersion(1, buffer[0]));
        }

        if r.read(&mut buffer).await? == 0 {
            return Err(DeserializationError::NotEnoughData);
        }

        Ok(ServerAuthResponse {
            success: buffer[0] == 0,
        })
    }

    pub async fn write<W: AsyncWrite + Send + Unpin>(
        &self,
        w: &mut W,
    ) -> Result<(), SerializationError> {
        w.write_all(&[1]).await?;
        w.write_all(&[if self.success { 0x00 } else { 0xde }])
            .await?;
        Ok(())
    }
}

#[cfg(test)]
impl Arbitrary for ServerAuthResponse {
    fn arbitrary(g: &mut Gen) -> ServerAuthResponse {
        let success = bool::arbitrary(g);
        ServerAuthResponse { success }
    }
}

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
        mut r: Pin<&mut R>,
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
        g.choose(&[
            ClientConnectionCommand::EstablishTCPStream,
            ClientConnectionCommand::EstablishTCPPortBinding,
            ClientConnectionCommand::AssociateUDPPort,
        ])
        .unwrap()
        .clone()
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ServerResponse {
    pub status: ServerResponseStatus,
    pub bound_address: SOCKSv5Address,
    pub bound_port: u16,
}

impl ServerResponse {
    pub fn error<E: Into<ServerResponseStatus>>(resp: E) -> ServerResponse {
        ServerResponse {
            status: resp.into(),
            bound_address: SOCKSv5Address::IP4(Ipv4Addr::new(0, 0, 0, 0)),
            bound_port: 0,
        }
    }
}

impl ServerResponse {
    pub async fn read<R: AsyncRead + Send + Unpin>(
        r: Pin<&mut R>,
    ) -> Result<Self, DeserializationError> {
        let mut buffer = [0; 3];
        let raw_r = Pin::into_inner(r);

        read_amt(Pin::new(raw_r), 3, &mut buffer).await?;

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

        let bound_address = SOCKSv5Address::read(Pin::new(raw_r)).await?;
        read_amt(Pin::new(raw_r), 2, &mut buffer).await?;
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
        g.choose(&[
            ServerResponseStatus::RequestGranted,
            ServerResponseStatus::GeneralFailure,
            ServerResponseStatus::ConnectionNotAllowedByRule,
            ServerResponseStatus::NetworkUnreachable,
            ServerResponseStatus::HostUnreachable,
            ServerResponseStatus::ConnectionRefused,
            ServerResponseStatus::TTLExpired,
            ServerResponseStatus::CommandNotSupported,
            ServerResponseStatus::AddressTypeNotSupported,
        ])
        .unwrap()
        .clone()
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

macro_rules! standard_roundtrip {
    ($name: ident, $t: ty) => {
        #[cfg(test)]
        quickcheck! {
            fn $name(xs: $t) -> bool {
                let mut buffer = vec![];
                task::block_on(xs.write(&mut buffer)).unwrap();
                let mut cursor = Cursor::new(buffer);
                let ys = <$t>::read(Pin::new(&mut cursor));
                xs == task::block_on(ys).unwrap()
            }
        }
    };
}

standard_roundtrip!(auth_byte_roundtrips, AuthenticationMethod);
standard_roundtrip!(client_greeting_roundtrips, ClientGreeting);
standard_roundtrip!(server_choice_roundtrips, ServerChoice);
standard_roundtrip!(username_password_roundtrips, ClientUsernamePassword);
standard_roundtrip!(server_auth_response, ServerAuthResponse);
standard_roundtrip!(address_roundtrips, SOCKSv5Address);
standard_roundtrip!(client_request_roundtrips, ClientConnectionRequest);
standard_roundtrip!(server_response_roundtrips, ServerResponse);
