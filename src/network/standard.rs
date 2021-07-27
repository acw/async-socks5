use crate::messages::ServerResponseStatus;
use crate::network::address::{HasLocalAddress, SOCKSv5Address};
use crate::network::datagram::{Datagramlike, GenericDatagramSocket};
use crate::network::generic::Networklike;
use crate::network::listener::{GenericListener, Listenerlike};
use crate::network::stream::{GenericStream, Streamlike};
use async_std::io;
#[cfg(test)]
use async_std::io::ReadExt;
use async_std::net::{TcpListener, TcpStream, UdpSocket};
use async_trait::async_trait;
#[cfg(test)]
use futures::AsyncWriteExt;
use log::error;

pub struct Builtin {}

impl Builtin {
    pub fn new() -> Builtin {
        Builtin {}
    }
}

macro_rules! local_address_impl {
    ($t: ty) => {
       impl HasLocalAddress for $t {
            fn local_addr(&self) -> (SOCKSv5Address, u16) {
                match self.local_addr() {
                     Ok(a) =>
                         (SOCKSv5Address::from(a.ip()), a.port()),
                     Err(e) => {
                         error!("Couldn't translate (Streamlike) local address to SOCKS local address: {}", e);
                         (SOCKSv5Address::from("localhost"), 0)
                     }
                }
            }
       } 
    };
}

local_address_impl!(TcpStream);
local_address_impl!(TcpListener);
local_address_impl!(UdpSocket);

impl Streamlike for TcpStream {}

#[async_trait]
impl Listenerlike for TcpListener {
    type Error = io::Error;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error> {
        let (base, addrport) = self.accept().await?;
        let addr = addrport.ip();
        let port = addrport.port();
        Ok((GenericStream::new(base), SOCKSv5Address::from(addr), port))
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

    async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error> {
        let target = addr.into();

        let base_stream = match target {
            SOCKSv5Address::IP4(a) => TcpStream::connect((a, port)).await?,
            SOCKSv5Address::IP6(a) => TcpStream::connect((a, port)).await?,
            SOCKSv5Address::Name(n) => TcpStream::connect((n.as_str(), port)).await?,
        };

        Ok(GenericStream::from(base_stream))
    }

    async fn listen<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericListener<Self::Error>, Self::Error> {
        let target = addr.into();

        let base_stream = match target {
            SOCKSv5Address::IP4(a) => TcpListener::bind((a, port)).await?,
            SOCKSv5Address::IP6(a) => TcpListener::bind((a, port)).await?,
            SOCKSv5Address::Name(n) => TcpListener::bind((n.as_str(), port)).await?,
        };

        Ok(GenericListener {
            internal: Box::new(base_stream),
        })
    }

    async fn bind<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericDatagramSocket<Self::Error>, Self::Error> {
        let target = addr.into();

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

#[test]
fn check_sanity() {
    async_std::task::block_on(async {
        // Technically, this is UDP, and UDP is lossy. We're going to assume we're not
        // going to get any dropped data along here ... which is a very questionable
        // assumption, morally speaking, but probably fine for most purposes.
        let mut network = Builtin::new();
        let receiver = network.bind("localhost", 0).await.expect("Failed to bind receiver socket.");
        let sender = network.bind("localhost", 0).await.expect("Failed to bind sender socket.");
        let buffer = [0xde, 0xea, 0xbe, 0xef];
        let (receiver_addr, receiver_port) = receiver.local_addr();
        sender.send_to(&buffer, receiver_addr, receiver_port).await.expect("Failure sending datagram!");
        let mut recvbuffer = [0; 4];
        let (s, f, p) = receiver.recv_from(&mut recvbuffer).await.expect("Didn't receive UDP message?");
        let (sender_addr, sender_port) = sender.local_addr();
        assert_eq!(s, 4);
        assert_eq!(f, sender_addr);
        assert_eq!(p, sender_port);
        assert_eq!(recvbuffer, buffer);
    });

    // This whole block should be pretty solid, though, unless the system we're
    // on is in a pretty weird place.
    let mut network = Builtin::new();

    let listener = async_std::task::block_on(network.listen("localhost", 0)).expect("Couldn't set up listener on localhost");
    let (listener_address, listener_port) = listener.local_addr();

    let listener_task_handle = async_std::task::spawn(async move {
        let (mut stream, addr, port) = listener.accept().await.expect("Didn't get connection");
        let mut result_buffer = [0u8; 4];
        println!("Starting read!");
        stream.read_exact(&mut result_buffer).await.expect("Read failure in TCP test");
        (result_buffer, addr, port)
    });

    let sender_task_handle = async_std::task::spawn(async move {
        let mut sender = network.connect(listener_address, listener_port).await.expect("Coudln't connect to listener?");
        let (sender_address, sender_port) = sender.local_addr();
        let send_buffer = [0xa, 0xff, 0xab, 0x1e];
        sender.write_all(&send_buffer).await.expect("Couldn't send the write buffer");
        sender.flush().await.expect("Couldn't flush the write buffer");
        sender.close().await.expect("Couldn't close the write buffer");
        (sender_address, sender_port)
    });

    async_std::task::block_on(async {
        let (result, result_from, result_from_port) = listener_task_handle.await;
        assert_eq!(result, [0xa, 0xff, 0xab, 0x1e]);
        let (sender_address, sender_port) = sender_task_handle.await;
        assert_eq!(result_from, sender_address);
        assert_eq!(result_from_port, sender_port);
    });
}

impl From<io::Error> for ServerResponseStatus {
    fn from(e: io::Error) -> ServerResponseStatus {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => ServerResponseStatus::ConnectionRefused,
            io::ErrorKind::NotFound => ServerResponseStatus::HostUnreachable,
            _ => ServerResponseStatus::GeneralFailure,
        }
    }
}