use crate::network::address::HasLocalAddress;
use crate::network::datagram::Datagramlike;
use crate::network::testing::{TestStackError, TestingStack};
use crate::network::SOCKSv5Address;
use async_std::channel::Receiver;
use async_trait::async_trait;
use std::cmp::Ordering;

pub struct TestDatagram {
    context: TestingStack,
    my_address: SOCKSv5Address,
    my_port: u16,
    input_stream: Receiver<(SOCKSv5Address, u16, Vec<u8>)>,
}

impl TestDatagram {
    pub fn new(
        context: TestingStack,
        my_address: SOCKSv5Address,
        my_port: u16,
        input_stream: Receiver<(SOCKSv5Address, u16, Vec<u8>)>,
    ) -> Self {
        TestDatagram {
            context,
            my_address,
            my_port,
            input_stream,
        }
    }
}

impl HasLocalAddress for TestDatagram {
    fn local_addr(&self) -> (SOCKSv5Address, u16) {
        (self.my_address.clone(), self.my_port)
    }
}

#[async_trait]
impl Datagramlike for TestDatagram {
    type Error = TestStackError;

    async fn send_to(
        &self,
        buf: &[u8],
        target: SOCKSv5Address,
        port: u16,
    ) -> Result<usize, Self::Error> {
        let table = self.context.udp_sockets.lock().await;
        match table.get(&(target, port)) {
            None => Ok(buf.len()),
            Some(sender) => {
                sender
                    .send((self.my_address.clone(), self.my_port, buf.to_vec()))
                    .await
                    .map_err(|_| TestStackError::FailureToSend)?;
                Ok(buf.len())
            }
        }
    }

    async fn recv_from(
        &self,
        buffer: &mut [u8],
    ) -> Result<(usize, SOCKSv5Address, u16), Self::Error> {
        let (from_addr, from_port, message) = self
            .input_stream
            .recv()
            .await
            .map_err(|_| TestStackError::ReceiveFailure)?;

        match message.len().cmp(&buffer.len()) {
            Ordering::Greater => {
                buffer.copy_from_slice(&message[..buffer.len()]);
                Ok((message.len(), from_addr, from_port))
            }

            Ordering::Less => {
                (&mut buffer[..message.len()]).copy_from_slice(&message);
                Ok((message.len(), from_addr, from_port))
            }

            Ordering::Equal => {
                buffer.copy_from_slice(message.as_ref());
                Ok((message.len(), from_addr, from_port))
            }
        }
    }
}
