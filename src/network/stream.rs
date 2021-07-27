use crate::network::SOCKSv5Address;
use async_std::task::{Context, Poll};
use futures::io;
use futures::io::{AsyncRead, AsyncWrite};
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use super::address::HasLocalAddress;

pub trait Streamlike: AsyncRead + AsyncWrite + HasLocalAddress + Send + Sync + Unpin {}

#[derive(Clone)]
pub struct GenericStream {
    internal: Arc<Mutex<dyn Streamlike>>,
}

impl GenericStream {
    pub fn new<T: Streamlike + 'static>(x: T) -> GenericStream {
        GenericStream {
            internal: Arc::new(Mutex::new(x)),
        }
    }
}

impl HasLocalAddress for GenericStream {
    fn local_addr(&self) -> (SOCKSv5Address, u16) {
        let item = self.internal.lock().unwrap();
        item.local_addr()
    }
}

impl AsyncRead for GenericStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut item = self.internal.lock().unwrap();
        let pinned = Pin::new(&mut *item);
        pinned.poll_read(cx, buf)
    }
}

impl AsyncWrite for GenericStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut item = self.internal.lock().unwrap();
        let pinned = Pin::new(&mut *item);
        pinned.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut item = self.internal.lock().unwrap();
        let pinned = Pin::new(&mut *item);
        pinned.poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut item = self.internal.lock().unwrap();
        let pinned = Pin::new(&mut *item);
        pinned.poll_close(cx)
    }
}

impl<T: Streamlike + 'static> From<T> for GenericStream {
    fn from(x: T) -> GenericStream {
        GenericStream {
            internal: Arc::new(Mutex::new(x)),
        }
    }
}
