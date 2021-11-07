use crate::network::address::HasLocalAddress;
use crate::network::stream::Streamlike;
use crate::network::SOCKSv5Address;
use async_std::io;
use async_std::io::{Read, Write};
use async_std::task::{Context, Poll, Waker};
use std::cell::UnsafeCell;
use std::pin::Pin;
use std::ptr::NonNull;
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone)]
pub struct TestingStream {
    address: SOCKSv5Address,
    port: u16,
    read_side: NonNull<TestingStreamData>,
    write_side: NonNull<TestingStreamData>,
}

unsafe impl Send for TestingStream {}
unsafe impl Sync for TestingStream {}

struct TestingStreamData {
    lock: AtomicBool,
    writer_dead: AtomicBool,
    waiters: UnsafeCell<Vec<Waker>>,
    buffer: UnsafeCell<Vec<u8>>,
}

unsafe impl Send for TestingStreamData {}
unsafe impl Sync for TestingStreamData {}

impl TestingStream {
    /// Generate a testing stream. Note that this is directional. So, if you want to
    /// talk to this stream, you should also generate an `invert()` and pass that to
    /// the other thread(s).
    pub fn new(address: SOCKSv5Address, port: u16) -> TestingStream {
        let read_side_data = TestingStreamData {
            lock: AtomicBool::new(false),
            writer_dead: AtomicBool::new(false),
            waiters: UnsafeCell::new(Vec::new()),
            buffer: UnsafeCell::new(Vec::with_capacity(16 * 1024)),
        };

        let write_side_data = TestingStreamData {
            lock: AtomicBool::new(false),
            writer_dead: AtomicBool::new(false),
            waiters: UnsafeCell::new(Vec::new()),
            buffer: UnsafeCell::new(Vec::with_capacity(16 * 1024)),
        };

        let boxed_rsd = Box::new(read_side_data);
        let boxed_wsd = Box::new(write_side_data);
        let raw_read_ptr = Box::leak(boxed_rsd);
        let raw_write_ptr = Box::leak(boxed_wsd);

        TestingStream {
            address,
            port,
            read_side: NonNull::new(raw_read_ptr).unwrap(),
            write_side: NonNull::new(raw_write_ptr).unwrap(),
        }
    }

    /// Get the flip side of this stream; reads from the inverted side will catch the writes
    /// of the original, etc.
    pub fn invert(&self) -> TestingStream {
        TestingStream {
            address: self.address.clone(),
            port: self.port,
            read_side: self.write_side,
            write_side: self.read_side,
        }
    }
}

impl TestingStreamData {
    fn acquire(&mut self) {
        loop {
            match self
                .lock
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            {
                Err(_) => continue,
                Ok(_) => return,
            }
        }
    }

    fn release(&mut self) {
        self.lock.store(false, Ordering::SeqCst);
    }
}

impl HasLocalAddress for TestingStream {
    fn local_addr(&self) -> (SOCKSv5Address, u16) {
        (self.address.clone(), self.port)
    }
}

impl Read for TestingStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        // so, we're going to spin here, which is less than ideal but should work fine
        // in practice. we'll obviously need to be very careful to ensure that we keep
        // the stuff internal to this spin really short.
        let internals = unsafe { self.read_side.as_mut() };

        internals.acquire();

        let stream_buffer = internals.buffer.get_mut();
        let amount_available = stream_buffer.len();

        if amount_available == 0 {
            // we wait to do this check until we've determined the buffer is empty,
            // so that we make sure to drain any residual stuff in there.
            if internals.writer_dead.load(Ordering::SeqCst) {
                internals.release();
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "Writer closed the socket.",
                )));
            } else {
                let waker = cx.waker().clone();
                internals.waiters.get_mut().push(waker);
                internals.release();
                return Poll::Pending;
            }
        }

        let amt_written = if buf.len() >= amount_available {
            (&mut buf[0..amount_available]).copy_from_slice(stream_buffer);
            stream_buffer.clear();
            amount_available
        } else {
            let amt_to_copy = buf.len();
            buf.copy_from_slice(&stream_buffer[0..amt_to_copy]);
            stream_buffer.copy_within(amt_to_copy.., 0);
            let amt_left = amount_available - amt_to_copy;
            stream_buffer.resize(amt_left, 0);
            amt_to_copy
        };

        internals.release();

        Poll::Ready(Ok(amt_written))
    }
}

impl Write for TestingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let internals = unsafe { self.write_side.as_mut() };
        internals.acquire();
        let stream_buffer = internals.buffer.get_mut();
        stream_buffer.extend_from_slice(buf);
        for waiter in internals.waiters.get_mut().drain(0..) {
            waiter.wake();
        }
        internals.release();

        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // FIXME: Might consider having this wait until the buffer is empty
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(())) // FIXME: Might consider putting in some open/closed logic here
    }
}

impl Streamlike for TestingStream {}

impl Drop for TestingStream {
    fn drop(&mut self) {
        let internals = unsafe { self.write_side.as_mut() };
        internals.writer_dead.store(true, Ordering::SeqCst);
        internals.acquire();
        for waiter in internals.waiters.get_mut().drain(0..) {
            waiter.wake();
        }
        internals.release();
    }
}
