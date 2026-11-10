#![forbid(unsafe_code)]
//! Plugin Chain contract. A Plugin returns an Outcome rather than writing to a
//! Listener; earlier Plugins may inspect and modify the caller-owned Response
//! buffer after awaiting Next. The Listener handles unanswered codes and errors.

use std::net::SocketAddr;

use pharos_proto::{BuildError, Message, Name, Rcode};

/// Transport named by a Server Block Key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Transport {
    Dns,
    Tls,
    Quic,
    Grpc,
    Https,
    Https3,
}

/// Protocol used by a Query.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Protocol {
    Udp,
    Tcp,
}

/// A placeholder for a future Zone Transfer stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stream;

/// Explicit result of running a Plugin Chain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outcome {
    Response,
    Stream(Stream),
    Drop,
    Unanswered(Rcode),
    Error(Error),
}

/// Errors for the Listener to log and answer with SERVFAIL.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    Build(BuildError),
    InvalidQuery,
    ResponseBufferTooSmall,
    NotImplemented,
}

/// Caller-provided, fixed-capacity Metadata slots.
pub struct Metadata<'a> {
    slots: &'a mut [Option<(&'a str, &'a str)>],
}

impl<'a> Metadata<'a> {
    pub fn new(slots: &'a mut [Option<(&'a str, &'a str)>]) -> Self {
        Self { slots }
    }

    /// Insert or replace a named value; returns false when no slot is free.
    pub fn insert(&mut self, name: &'a str, value: &'a str) -> bool {
        if let Some(slot) = self
            .slots
            .iter_mut()
            .find(|slot| slot.is_some_and(|(existing, _)| existing == name))
        {
            *slot = Some((name, value));
            return true;
        }
        if let Some(slot) = self.slots.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some((name, value));
            return true;
        }
        false
    }

    #[must_use]
    pub fn get(&self, name: &str) -> Option<&str> {
        self.slots
            .iter()
            .flatten()
            .find_map(|(key, value)| (*key == name).then_some(*value))
    }
}

/// Borrowed Query state and reusable, preallocated Response buffer.
pub struct Context<'a> {
    pub query: Message<'a>,
    pub client: SocketAddr,
    pub transport: Transport,
    pub protocol: Protocol,
    pub domain: &'a Name,
    pub metadata: Metadata<'a>,
    pub response: &'a mut Vec<u8>,
    pub max_response_size: usize,
}
