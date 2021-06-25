pub mod address;
pub mod datagram;
pub mod generic;
pub mod listener;
pub mod standard;
pub mod stream;

use crate::messages::ServerResponseStatus;
pub use crate::network::address::{SOCKSv5Address, ToSOCKSAddress};
pub use crate::network::standard::Builtin;
use async_trait::async_trait;
use futures::{AsyncRead, AsyncWrite};
use std::fmt;

#[async_trait]
pub trait Network {
    type Stream: AsyncRead + AsyncWrite + Clone + Send + Sync + Unpin + 'static;
    type Listener: SingleShotListener<Self::Stream, Self::Error> + Send + Sync + 'static;
    type UdpSocket;
    type Error: fmt::Debug + fmt::Display + Into<ServerResponseStatus>;

    async fn connect<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<Self::Stream, Self::Error>;
    async fn udp_socket<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: Option<u16>,
    ) -> Result<Self::UdpSocket, Self::Error>;
    async fn listen<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: Option<u16>,
    ) -> Result<Self::Listener, Self::Error>;
}

#[async_trait]
pub trait SingleShotListener<Stream, Error> {
    async fn accept(self) -> Result<Stream, Error>;
    fn info(&self) -> Result<(SOCKSv5Address, u16), Error>;
}
