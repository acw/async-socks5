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
    internals: NonNull<TestingStreamData>,
}

unsafe impl Send for TestingStream {}
unsafe impl Sync for TestingStream {}

struct TestingStreamData {
    lock: AtomicBool,
    waiters: UnsafeCell<Vec<Waker>>,
    buffer: UnsafeCell<Vec<u8>>,
}

unsafe impl Send for TestingStreamData {}
unsafe impl Sync for TestingStreamData {}

impl TestingStream {
    pub fn new(address: SOCKSv5Address, port: u16) -> TestingStream {
        let tsd = TestingStreamData {
            lock: AtomicBool::new(false),
            waiters: UnsafeCell::new(Vec::new()),
            buffer: UnsafeCell::new(Vec::with_capacity(16 * 1024)),
        };

        let boxed_tsd = Box::new(tsd);
        let raw_ptr = Box::leak(boxed_tsd);

        TestingStream {
            address,
            port,
            internals: NonNull::new(raw_ptr).unwrap(),
        }
    }

    pub fn acquire_lock(&mut self) {
        loop {
            let internals = unsafe { self.internals.as_mut() };

            match internals
                .lock
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            {
                Err(_) => continue,
                Ok(_) => return,
            }
        }
    }

    pub fn release_lock(&mut self) {
        let internals = unsafe { self.internals.as_mut() };
        internals.lock.store(false, Ordering::SeqCst);
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
        self.acquire_lock();

        let internals = unsafe { self.internals.as_mut() };
        let stream_buffer = internals.buffer.get_mut();

        let amount_available = stream_buffer.len();

        if amount_available == 0 {
            let waker = cx.waker().clone();
            internals.waiters.get_mut().push(waker);
            self.release_lock();
            return Poll::Pending;
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

        self.release_lock();

        Poll::Ready(Ok(amt_written))
    }
}

impl Write for TestingStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.acquire_lock();
        let internals = unsafe { self.internals.as_mut() };
        let stream_buffer = internals.buffer.get_mut();

        stream_buffer.extend_from_slice(buf);
        for waiter in internals.waiters.get_mut().drain(0..) {
            waiter.wake();
        }
        self.release_lock();

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
