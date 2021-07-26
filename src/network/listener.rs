use crate::network::address::{HasLocalAddress, SOCKSv5Address};
use crate::network::stream::GenericStream;
use async_trait::async_trait;

#[async_trait]
pub trait Listenerlike: Send + Sync + HasLocalAddress {
    type Error;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error>;
}

pub struct GenericListener<E> {
    pub internal: Box<dyn Listenerlike<Error = E>>,
}

#[async_trait]
impl<E> Listenerlike for GenericListener<E> {
    type Error = E;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error> {
        Ok(self.internal.accept().await?)
    }
}

impl<E> HasLocalAddress for GenericListener<E> {
    fn local_addr(&self) -> (SOCKSv5Address, u16) {
        self.internal.local_addr()
    }
}
