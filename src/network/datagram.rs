use crate::network::address::SOCKSv5Address;
use async_trait::async_trait;

#[async_trait]
pub trait Datagramlike: Send + Sync {
    type Error;

    async fn send_to(
        &self,
        buf: &[u8],
        addr: SOCKSv5Address,
        port: u16,
    ) -> Result<usize, Self::Error>;
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SOCKSv5Address, u16), Self::Error>;
}

pub struct GenericDatagramSocket<E> {
    pub internal: Box<dyn Datagramlike<Error = E>>,
}

#[async_trait]
impl<E> Datagramlike for GenericDatagramSocket<E> {
    type Error = E;

    async fn send_to(
        &self,
        buf: &[u8],
        addr: SOCKSv5Address,
        port: u16,
    ) -> Result<usize, Self::Error> {
        Ok(self.internal.send_to(buf, addr, port).await?)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SOCKSv5Address, u16), Self::Error> {
        Ok(self.internal.recv_from(buf).await?)
    }
}
