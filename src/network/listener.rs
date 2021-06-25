use crate::network::address::SOCKSv5Address;
use crate::network::stream::GenericStream;
use async_trait::async_trait;

#[async_trait]
pub trait Listenerlike: Send + Sync {
    type Error;

    async fn accept(&self) -> Result<(GenericStream, SOCKSv5Address, u16), Self::Error>;
    fn info(&self) -> (SOCKSv5Address, u16);
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

    fn info(&self) -> (SOCKSv5Address, u16) {
        self.internal.info()
    }
}
