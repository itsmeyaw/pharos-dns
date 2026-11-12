//! Compiled expressions over borrowed Queries and Metadata.

use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};
use std::net::SocketAddr;

/// Borrowed Query and transport information.
pub struct Query<'a> {
    pub message: &'a Message<'a>,
    pub client: SocketAddr,
    pub local: SocketAddr,
    pub protocol: Protocol,
}

impl<'a> Query<'a> {
    pub fn new(
        message: &'a Message<'a>,
        client: SocketAddr,
        local: SocketAddr,
        protocol: Protocol,
    ) -> Self {
        Self {
            message,
            client,
            local,
            protocol,
        }
    }
}

/// Reusable caller-owned evaluation storage.
pub struct Scratch<'a> {
    _buffer: &'a mut [u8],
}

impl<'a> Scratch<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { _buffer: buffer }
    }
}

/// A result produced by an expression.
#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    Bool(bool),
    Int(i64),
    String(&'a str),
}

/// An expression parsed once at setup.
pub struct Expression(bool);

impl Expression {
    pub fn compile(source: &str) -> Result<Self, String> {
        match source.trim() {
            "true" => Ok(Self(true)),
            "false" => Ok(Self(false)),
            _ => Err(format!("unsupported expression: {source}")),
        }
    }

    pub fn evaluate<'a>(
        &'a self,
        _query: &'a Query<'_>,
        _metadata: &'a Metadata<'_>,
        _scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        Ok(Value::Bool(self.0))
    }
}
