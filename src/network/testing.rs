mod datagram;
mod stream;

use crate::messages::ServerResponseStatus;
use crate::network::address::{HasLocalAddress, SOCKSv5Address};
#[cfg(test)]
use crate::network::datagram::Datagramlike;
use crate::network::datagram::GenericDatagramSocket;
use crate::network::generic::Networklike;
use crate::network::listener::{GenericListener, Listenerlike};
use crate::network::stream::GenericStream;
use crate::network::testing::datagram::TestDatagram;
use crate::network::testing::stream::TestingStream;
use async_std::channel::{bounded, Receiver, Sender};
use async_std::sync::{Arc, Mutex};
#[cfg(test)]
use async_std::task;
use async_trait::async_trait;
#[cfg(test)]
use futures::{AsyncReadExt, AsyncWriteExt};
use std::collections::HashMap;
use std::fmt;

/// A "network", based purely on internal Rust datatypes, for testing
/// networking code. This stack operates purely in memory, so shouldn't
/// suffer from any weird networking effects ... which makes it a good
/// functional test, but not great at actually testing real-world failure
/// modes.
#[allow(clippy::type_complexity)]
#[derive(Clone)]
pub struct TestingStack {
    tcp_listeners: Arc<Mutex<HashMap<(SOCKSv5Address, u16), Sender<TestingStream>>>>,
    udp_sockets: Arc<Mutex<HashMap<(SOCKSv5Address, u16), Sender<(SOCKSv5Address, u16, Vec<u8>)>>>>,
    next_random_socket: u16,
}

impl TestingStack {
    pub fn new() -> TestingStack {
        TestingStack {
            tcp_listeners: Arc::new(Mutex::new(HashMap::new())),
            udp_sockets: Arc::new(Mutex::new(HashMap::new())),
            next_random_socket: 23,
        }
    }
}

impl Default for TestingStack {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub enum TestStackError {
    AcceptFailed,
    AddressBusy(SOCKSv5Address, u16),
    ConnectionFailed,
    FailureToSend,
    NoTCPHostFound(SOCKSv5Address, u16),
    ReceiveFailure,
}

impl fmt::Display for TestStackError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TestStackError::AcceptFailed => write!(f, "Accept failed; the other side died (?)"),
            TestStackError::AddressBusy(ref addr, port) => {
                write!(f, "Address {}:{} already in use", addr, port)
            }
            TestStackError::ConnectionFailed => write!(f, "Couldn't connect to host."),
            TestStackError::FailureToSend => write!(
                f,
                "Weird internal error in testing infrastructure; channel send failed"
            ),
            TestStackError::NoTCPHostFound(ref addr, port) => {
                write!(f, "No host found at {} for TCP port {}", addr, port)
            }
            TestStackError::ReceiveFailure => {
                write!(f, "Failed to process a UDP receive (this is weird)")
            }
        }
    }
}

impl From<TestStackError> for ServerResponseStatus {
    fn from(_: TestStackError) -> Self {
        ServerResponseStatus::GeneralFailure
    }
}

#[async_trait]
impl Networklike for TestingStack {
    type Error = TestStackError;

    async fn connect<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        port: u16,
    ) -> Result<GenericStream, Self::Error> {
        let table = self.tcp_listeners.lock().await;
        let target = addr.into();

        match table.get(&(target.clone(), port)) {
            None => Err(TestStackError::NoTCPHostFound(target, port)),
            Some(result) => {
                let stream = TestingStream::new(target, port);
                let retval = stream.clone();
                match result.send(stream).await {
                    Ok(()) => Ok(GenericStream::new(retval)),
                    Err(_) => Err(TestStackError::FailureToSend),
                }
            }
        }
    }

    async fn listen<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        mut port: u16,
    ) -> Result<GenericListener<Self::Error>, Self::Error> {
        let mut table = self.tcp_listeners.lock().await;
        let target = addr.into();
        let (sender, receiver) = bounded(5);

        if port == 0 {
            port = self.next_random_socket;
            self.next_random_socket += 1;
        }

        table.insert((target.clone(), port), sender);
        Ok(GenericListener {
            internal: Box::new(TestListener::new(target, port, receiver)),
        })
    }

    async fn bind<A: Send + Into<SOCKSv5Address>>(
        &mut self,
        addr: A,
        mut port: u16,
    ) -> Result<GenericDatagramSocket<Self::Error>, Self::Error> {
        let mut table = self.udp_sockets.lock().await;
        let target = addr.into();
        let (sender, receiver) = bounded(5);

        if port == 0 {
            port = self.next_random_socket;
            self.next_random_socket += 1;
        }

        table.insert((target.clone(), port), sender);
        Ok(GenericDatagramSocket {
            internal: Box::new(TestDatagram::new(self.clone(), target, port, receiver)),
        })
    }
}

struct TestListener {
    address: SOCKSv5Address,
    port: u16,
    receiver: Receiver<TestingStream>,
}

impl TestListener {
    fn new(address: SOCKSv5Address, port: u16, receiver: Receiver<TestingStream>) -> Self {
        TestListener {
            address,
            port,
            receiver,
        }
    }
}

impl HasLocalAddress for TestListener {
    fn local_addr(&self) -> (SOCKSv5Address, u16) {
        (self.address.clone(), self.port)
    }
}

#[async_trait]
impl Listenerlike for TestListener {
    type Error = TestStackError;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error> {
        match self.receiver.recv().await {
            Ok(next) => {
                let (addr, port) = next.local_addr();
                Ok((GenericStream::new(next), addr, port))
            }
            Err(_) => Err(TestStackError::AcceptFailed),
        }
    }
}

#[test]
fn check_sanity() {
    task::block_on(async {
        // Technically, this is UDP, and UDP is lossy. We're going to assume we're not
        // going to get any dropped data along here ... which is a very questionable
        // assumption, morally speaking, but probably fine for most purposes.
        let mut network = TestingStack::new();
        let receiver = network
            .bind("localhost", 0)
            .await
            .expect("Failed to bind receiver socket.");
        let sender = network
            .bind("localhost", 0)
            .await
            .expect("Failed to bind sender socket.");
        let buffer = [0xde, 0xea, 0xbe, 0xef];
        let (receiver_addr, receiver_port) = receiver.local_addr();
        sender
            .send_to(&buffer, receiver_addr, receiver_port)
            .await
            .expect("Failure sending datagram!");
        let mut recvbuffer = [0; 4];
        let (s, f, p) = receiver
            .recv_from(&mut recvbuffer)
            .await
            .expect("Didn't receive UDP message?");
        let (sender_addr, sender_port) = sender.local_addr();
        assert_eq!(s, 4);
        assert_eq!(f, sender_addr);
        assert_eq!(p, sender_port);
        assert_eq!(recvbuffer, buffer);
    });

    task::block_on(async {
        let mut network = TestingStack::new();

        let listener = network
            .listen("localhost", 0)
            .await
            .expect("Couldn't set up listener on localhost");
        let (listener_address, listener_port) = listener.local_addr();

        let listener_task_handle = task::spawn(async move {
            dbg!("Starting listener task!!");
            let (mut stream, addr, port) = listener.accept().await.expect("Didn't get connection");
            let mut result_buffer = [0u8; 4];
            if let Err(e) = stream.read_exact(&mut result_buffer).await {
                dbg!("Error reading buffer from stream: {}", e);
            } else {
                dbg!("made it through read_exact");
            }
            (result_buffer, addr, port)
        });

        let sender_task_handle = task::spawn(async move {
            let mut sender = network
                .connect(listener_address, listener_port)
                .await
                .expect("Coudln't connect to listener?");
            let (sender_address, sender_port) = sender.local_addr();
            let send_buffer = [0xa, 0xff, 0xab, 0x1e];
            sender
                .write_all(&send_buffer)
                .await
                .expect("Couldn't send the write buffer");
            sender
                .flush()
                .await
                .expect("Couldn't flush the write buffer");
            sender
                .close()
                .await
                .expect("Couldn't close the write buffer");
            (sender_address, sender_port)
        });

        let (result, result_from, result_from_port) = listener_task_handle.await;
        assert_eq!(result, [0xa, 0xff, 0xab, 0x1e]);
        let (sender_address, sender_port) = sender_task_handle.await;
        assert_eq!(result_from, sender_address);
        assert_eq!(result_from_port, sender_port);
    });
}
