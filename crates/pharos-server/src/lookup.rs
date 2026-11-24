//! Reusable buffers and future slots for Self Lookup, so a warmed Listener serves it
//! without allocating. Every pool is bounded and never locked across an await.

use std::{
    any::Any,
    future::Future,
    net::SocketAddr,
    ops::Deref,
    pin::Pin,
    sync::{Arc, Mutex, MutexGuard, PoisonError},
    task::{Context as TaskContext, Poll},
};

use crate::{Action, Protocol};

/// Idle items kept per pool. This bounds retained memory; bursts beyond it allocate and free.
const POOL_LIMIT: usize = 16;
const WIRE_CAPACITY: usize = 512;
const RESPONSE_CAPACITY: usize = u16::MAX as usize;

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

struct BufferPool {
    idle: Mutex<Vec<Vec<u8>>>,
    capacity: usize,
}

impl BufferPool {
    fn new(capacity: usize) -> Self {
        Self {
            idle: Mutex::new(Vec::with_capacity(POOL_LIMIT)),
            capacity,
        }
    }

    fn take(&self) -> Vec<u8> {
        let idle = lock(&self.idle).pop();
        idle.unwrap_or_else(|| Vec::with_capacity(self.capacity))
    }

    fn put(&self, mut buffer: Vec<u8>) {
        buffer.clear();
        let mut idle = lock(&self.idle);
        if idle.len() < POOL_LIMIT {
            idle.push(buffer);
        }
    }
}

/// A Query for one Self Lookup, owned so it can outlive the caller's borrows.
pub(crate) struct LookupRequest {
    pub(crate) wire: Vec<u8>,
    pub(crate) response: Vec<u8>,
    pub(crate) peer: SocketAddr,
    pub(crate) protocol: Protocol,
    pub(crate) depth: u8,
    pub(crate) siit: bool,
    pub(crate) autopath: bool,
}

pub(crate) struct LookupOutput {
    pub(crate) action: Action,
    pub(crate) response: Vec<u8>,
}

/// A type-erased, reusable home for one Self Lookup future.
trait Slot: Send {
    fn arm(&mut self, args: &mut dyn Any);
    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<LookupOutput>;
    fn clear(&mut self);
}

struct Entry<A, F, M> {
    future: Pin<Box<Option<F>>>,
    make: M,
    _args: std::marker::PhantomData<fn(A)>,
}

impl<A, F, M> Slot for Entry<A, F, M>
where
    A: 'static,
    F: Future<Output = LookupOutput> + Send,
    M: Fn(A) -> F + Send,
{
    fn arm(&mut self, args: &mut dyn Any) {
        let args = args
            .downcast_mut::<Option<A>>()
            .and_then(Option::take)
            .expect("Slot is armed with its pool's argument type");
        self.future.set(Some((self.make)(args)));
    }

    fn poll(&mut self, cx: &mut TaskContext<'_>) -> Poll<LookupOutput> {
        let Some(future) = self.future.as_mut().as_pin_mut() else {
            return Poll::Pending;
        };
        let poll = future.poll(cx);
        if poll.is_ready() {
            self.future.set(None);
        }
        poll
    }

    fn clear(&mut self) {
        self.future.set(None);
    }
}

/// Per-Listener pools shared by every clone of its Server.
pub(crate) struct LookupPools {
    wires: BufferPool,
    responses: BufferPool,
    slots: Mutex<Vec<Box<dyn Slot>>>,
}

impl Default for LookupPools {
    fn default() -> Self {
        Self {
            wires: BufferPool::new(WIRE_CAPACITY),
            responses: BufferPool::new(RESPONSE_CAPACITY),
            slots: Mutex::new(Vec::with_capacity(POOL_LIMIT)),
        }
    }
}

impl LookupPools {
    pub(crate) fn take_wire(&self) -> Vec<u8> {
        self.wires.take()
    }

    pub(crate) fn put_wire(&self, wire: Vec<u8>) {
        self.wires.put(wire);
    }

    pub(crate) fn take_response(&self) -> Vec<u8> {
        self.responses.take()
    }

    pub(crate) fn put_response(&self, response: Vec<u8>) {
        self.responses.put(response);
    }

    /// Run `make(args)` in a pooled slot. Every call on a pool must use the same `make`.
    pub(crate) fn lookup<A, F, M>(self: &Arc<Self>, make: M, args: A) -> Lookup
    where
        A: Send + 'static,
        F: Future<Output = LookupOutput> + Send + 'static,
        M: Fn(A) -> F + Send + 'static,
    {
        let idle = lock(&self.slots).pop();
        let mut slot = idle.unwrap_or_else(|| {
            Box::new(Entry {
                future: Box::pin(None),
                make,
                _args: std::marker::PhantomData,
            })
        });
        slot.arm(&mut Some(args));
        Lookup {
            slot: Some(slot),
            pools: Arc::clone(self),
        }
    }
}

/// A running Self Lookup. Dropping it cancels the future and recycles its slot.
pub(crate) struct Lookup {
    slot: Option<Box<dyn Slot>>,
    pools: Arc<LookupPools>,
}

impl Future for Lookup {
    type Output = LookupOutput;

    fn poll(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<LookupOutput> {
        match self.slot.as_mut() {
            Some(slot) => slot.poll(cx),
            None => Poll::Pending,
        }
    }
}

impl Drop for Lookup {
    fn drop(&mut self) {
        if let Some(mut slot) = self.slot.take() {
            // Drop the future first so cancellation releases what it holds before reuse.
            slot.clear();
            let mut idle = lock(&self.pools.slots);
            if idle.len() < POOL_LIMIT {
                idle.push(slot);
            }
        }
    }
}

/// The wire Response of a Self Lookup. Dropping it returns the buffer to its Listener's pool.
pub struct LookupResponse {
    buffer: Option<Vec<u8>>,
    pools: Arc<LookupPools>,
}

impl LookupResponse {
    pub(crate) fn new(buffer: Vec<u8>, pools: Arc<LookupPools>) -> Self {
        Self {
            buffer: Some(buffer),
            pools,
        }
    }

    /// Take the buffer out of the pool, for callers that must keep it.
    #[must_use]
    pub fn into_vec(mut self) -> Vec<u8> {
        self.buffer.take().unwrap_or_default()
    }
}

impl Deref for LookupResponse {
    type Target = Vec<u8>;

    fn deref(&self) -> &Vec<u8> {
        self.buffer.as_ref().expect("buffer is present until drop")
    }
}

impl AsRef<[u8]> for LookupResponse {
    fn as_ref(&self) -> &[u8] {
        self
    }
}

impl std::fmt::Debug for LookupResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LookupResponse")
            .field("len", &self.len())
            .finish()
    }
}

impl Drop for LookupResponse {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            self.pools.put_response(buffer);
        }
    }
}
