use crate::messages::ServerResponseStatus;
use crate::network::address::{SOCKSv5Address, ToSOCKSAddress};
use crate::network::datagram::{Datagramlike, GenericDatagramSocket};
use crate::network::generic::Networklike;
use crate::network::listener::{GenericListener, Listenerlike};
use crate::network::stream::{GenericStream, Streamlike};
use async_std::io;
use async_std::net::{TcpListener, TcpStream, UdpSocket};
use async_trait::async_trait;
use log::error;
use std::net::Ipv4Addr;

pub struct Builtin {}

impl Builtin {
    pub fn new() -> Builtin {
        Builtin {}
    }
}

impl Streamlike for TcpStream {}

#[async_trait]
impl Listenerlike for TcpListener {
    type Error = io::Error;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error> {
        let (base, addrport) = self.accept().await?;
        let addr = addrport.ip();
        let port = addrport.port();
        Ok((GenericStream::from(base), SOCKSv5Address::from(addr), port))
    }

    fn info(&self) -> (SOCKSv5Address, u16) {
        match self.local_addr() {
            Ok(x) => {
                let addr = SOCKSv5Address::from(x.ip());
                let port = x.port();
                (addr, port)
            }
            Err(e) => {
                error!("Someone asked for a listener address, and we got an error ({}); returning 0.0.0.0:0", e);
                (SOCKSv5Address::IP4(Ipv4Addr::from(0)), 0)
            }
        }
    }
}

#[async_trait]
impl Datagramlike for UdpSocket {
    type Error = io::Error;

    async fn send_to(
        &self,
        buf: &[u8],
        addr: SOCKSv5Address,
        port: u16,
    ) -> Result<usize, Self::Error> {
        match addr {
            SOCKSv5Address::IP4(a) => self.send_to(buf, (a, port)).await,
            SOCKSv5Address::IP6(a) => self.send_to(buf, (a, port)).await,
            SOCKSv5Address::Name(n) => self.send_to(buf, (n.as_str(), port)).await,
        }
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SOCKSv5Address, u16), Self::Error> {
        let (amt, addrport) = self.recv_from(buf).await?;
        let addr = addrport.ip();
        let port = addrport.port();
        Ok((amt, SOCKSv5Address::from(addr), port))
    }
}

#[async_trait]
impl Networklike for Builtin {
    type Error = io::Error;

    async fn connect<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error> {
        let target = addr.to_socks_address();

        let base_stream = match target {
            SOCKSv5Address::IP4(a) => TcpStream::connect((a, port)).await?,
            SOCKSv5Address::IP6(a) => TcpStream::connect((a, port)).await?,
            SOCKSv5Address::Name(n) => TcpStream::connect((n.as_str(), port)).await?,
        };

        Ok(GenericStream::from(base_stream))
    }

    async fn listen<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericListener<Self::Error>, Self::Error> {
        let target = addr.to_socks_address();

        let base_stream = match target {
            SOCKSv5Address::IP4(a) => TcpListener::bind((a, port)).await?,
            SOCKSv5Address::IP6(a) => TcpListener::bind((a, port)).await?,
            SOCKSv5Address::Name(n) => TcpListener::bind((n.as_str(), port)).await?,
        };

        Ok(GenericListener {
            internal: Box::new(base_stream),
        })
    }

    async fn bind<A: ToSOCKSAddress>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericDatagramSocket<Self::Error>, Self::Error> {
        let target = addr.to_socks_address();

        let base_socket = match target {
            SOCKSv5Address::IP4(a) => UdpSocket::bind((a, port)).await?,
            SOCKSv5Address::IP6(a) => UdpSocket::bind((a, port)).await?,
            SOCKSv5Address::Name(n) => UdpSocket::bind((n.as_str(), port)).await?,
        };

        Ok(GenericDatagramSocket {
            internal: Box::new(base_socket),
        })
    }
}

// pub struct StandardNetworking {}
//
// impl StandardNetworking {
//     pub fn new() -> StandardNetworking {
//         StandardNetworking {}
//     }
// }
//
impl From<io::Error> for ServerResponseStatus {
    fn from(e: io::Error) -> ServerResponseStatus {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => ServerResponseStatus::ConnectionRefused,
            io::ErrorKind::NotFound => ServerResponseStatus::HostUnreachable,
            _ => ServerResponseStatus::GeneralFailure,
        }
    }
}
//
// #[async_trait]
// impl Network for StandardNetworking {
//     type Stream = TcpStream;
//     type Listener = TcpListener;
//     type UdpSocket = UdpSocket;
//     type Error = io::Error;
//
//     async fn connect<A: ToSOCKSAddress>(
//         &mut self,
//         addr: A,
//         port: u16,
//     ) -> Result<Self::Stream, Self::Error> {
//         let target = addr.to_socks_address();
//
//         match target {
//             SOCKSv5Address::IP4(a) => TcpStream::connect((a, port)).await,
//             SOCKSv5Address::IP6(a) => TcpStream::connect((a, port)).await,
//             SOCKSv5Address::Name(n) => TcpStream::connect((n.as_str(), port)).await,
//         }
//     }
//
//     async fn udp_socket<A: ToSOCKSAddress>(
//         &mut self,
//         addr: A,
//         port: Option<u16>,
//     ) -> Result<Self::UdpSocket, Self::Error> {
//         let me = addr.to_socks_address();
//         let real_port = port.unwrap_or(0);
//
//         match me {
//             SOCKSv5Address::IP4(a) => UdpSocket::bind((a, real_port)).await,
//             SOCKSv5Address::IP6(a) => UdpSocket::bind((a, real_port)).await,
//             SOCKSv5Address::Name(n) => UdpSocket::bind((n.as_str(), real_port)).await,
//         }
//     }
//
//     async fn listen<A: ToSOCKSAddress>(
//         &mut self,
//         addr: A,
//         port: Option<u16>,
//     ) -> Result<Self::Listener, Self::Error> {
//         let me = addr.to_socks_address();
//         let real_port = port.unwrap_or(0);
//
//         match me {
//             SOCKSv5Address::IP4(a) => TcpListener::bind((a, real_port)).await,
//             SOCKSv5Address::IP6(a) => TcpListener::bind((a, real_port)).await,
//             SOCKSv5Address::Name(n) => TcpListener::bind((n.as_str(), real_port)).await,
//         }
//     }
// }
//
// #[async_trait]
// impl SingleShotListener<TcpStream, io::Error> for TcpListener {
//     async fn accept(self) -> Result<TcpStream, io::Error> {
//         self.accept().await
//     }
//
//     fn info(&self) -> Result<(SOCKSv5Address, u16), io::Error> {
//         match self.local_addr()? {
//             SocketAddr::V4(a) => Ok((SOCKSv5Address::IP4(*a.ip()), a.port())),
//             SocketAddr::V6(a) => Ok((SOCKSv5Address::IP6(*a.ip()), a.port())),
//         }
//     }
// }
//
