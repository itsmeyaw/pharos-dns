//! Compiled expressions over borrowed Queries and Metadata.

use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};
use std::{
    fmt::{self, Write},
    net::SocketAddr,
};

mod parser;

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
    buffer: &'a mut [u8],
    len: usize,
}

impl<'a> Scratch<'a> {
    pub fn new(buffer: &'a mut [u8]) -> Self {
        Self { buffer, len: 0 }
    }
}

impl Write for Scratch<'_> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self.len.checked_add(value.len()).ok_or(fmt::Error)?;
        let destination = self.buffer.get_mut(self.len..end).ok_or(fmt::Error)?;
        destination.copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
}

/// A result produced by an expression.
#[derive(Debug, PartialEq)]
pub enum Value<'a> {
    Bool(bool),
    Int(i64),
    String(&'a str),
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Bool,
    Int,
    String,
}

#[derive(Clone, Copy)]
enum Unary {
    Not,
    Neg,
}

#[derive(Clone, Copy)]
enum Binary {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Rem,
}

enum Node {
    Bool(bool),
    Int(i64),
    String(String),
    Call(String, Vec<Node>, Kind),
    Unary(Unary, Box<Node>),
    Binary(Binary, Box<Node>, Box<Node>, Kind),
}

impl Node {
    fn kind(&self) -> Kind {
        match self {
            Self::Bool(_) | Self::Unary(Unary::Not, _) => Kind::Bool,
            Self::Int(_) | Self::Unary(Unary::Neg, _) => Kind::Int,
            Self::String(_) => Kind::String,
            Self::Call(_, _, kind) => *kind,
            Self::Binary(_, _, _, kind) => *kind,
        }
    }

    fn eval<'a>(
        &'a self,
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        scratch: &mut Scratch<'_>,
    ) -> Result<Temporary<'a>, &'static str> {
        match self {
            Self::Bool(value) => Ok(Temporary::Bool(*value)),
            Self::Int(value) => Ok(Temporary::Int(*value)),
            Self::String(value) => Ok(Temporary::Borrowed(value)),
            Self::Call(name, args, _) => call(name, args, query, metadata, scratch),
            Self::Unary(Unary::Not, node) => match node.eval(query, metadata, scratch)? {
                Temporary::Bool(value) => Ok(Temporary::Bool(!value)),
                _ => Err("expected bool"),
            },
            Self::Unary(Unary::Neg, node) => match node.eval(query, metadata, scratch)? {
                Temporary::Int(value) => Ok(Temporary::Int(value.wrapping_neg())),
                _ => Err("expected integer"),
            },
            Self::Binary(op, left, right, _) => {
                let left = left.eval(query, metadata, scratch)?;
                if matches!(
                    (op, &left),
                    (Binary::And, Temporary::Bool(false)) | (Binary::Or, Temporary::Bool(true))
                ) {
                    return Ok(left);
                }
                let right = right.eval(query, metadata, scratch)?;
                use Binary::*;
                match (op, left, right) {
                    (And, Temporary::Bool(a), Temporary::Bool(b)) => Ok(Temporary::Bool(a && b)),
                    (Or, Temporary::Bool(a), Temporary::Bool(b)) => Ok(Temporary::Bool(a || b)),
                    (Add, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_add(b)))
                    }
                    (Sub, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_sub(b)))
                    }
                    (Mul, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_mul(b)))
                    }
                    (Div, Temporary::Int(a), Temporary::Int(b)) => a
                        .checked_div(b)
                        .map(Temporary::Int)
                        .ok_or("integer division error"),
                    (Rem, Temporary::Int(a), Temporary::Int(b)) => a
                        .checked_rem(b)
                        .map(Temporary::Int)
                        .ok_or("integer division error"),
                    (op @ (Eq | Ne | Lt | Le | Gt | Ge), a, b) => {
                        let ordering = match (a, b) {
                            (Temporary::Bool(a), Temporary::Bool(b)) => a.cmp(&b),
                            (Temporary::Int(a), Temporary::Int(b)) => a.cmp(&b),
                            (a, b) => a.text(scratch)?.cmp(b.text(scratch)?),
                        };
                        Ok(Temporary::Bool(match op {
                            Eq => ordering.is_eq(),
                            Ne => !ordering.is_eq(),
                            Lt => ordering.is_lt(),
                            Le => ordering.is_le(),
                            Gt => ordering.is_gt(),
                            Ge => ordering.is_ge(),
                            _ => unreachable!(),
                        }))
                    }
                    _ => Err("incompatible operands"),
                }
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Temporary<'a> {
    Bool(bool),
    Int(i64),
    Borrowed(&'a str),
    Stored(usize, usize),
}

impl<'a> Temporary<'a> {
    fn text<'s>(&'s self, scratch: &'s Scratch<'_>) -> Result<&'s str, &'static str> {
        match self {
            Self::Borrowed(value) => Ok(value),
            Self::Stored(start, end) => {
                std::str::from_utf8(&scratch.buffer[*start..*end]).map_err(|_| "invalid UTF-8")
            }
            _ => Err("expected string"),
        }
    }
}

fn call<'a>(
    name: &str,
    args: &'a [Node],
    query: &'a Query<'_>,
    metadata: &'a Metadata<'_>,
    scratch: &mut Scratch<'_>,
) -> Result<Temporary<'a>, &'static str> {
    if name == "metadata" {
        let label = args[0].eval(query, metadata, scratch)?;
        return Ok(Temporary::Borrowed(
            metadata.get(label.text(scratch)?).unwrap_or(""),
        ));
    }
    let message = query.message;
    match name {
        "id" => return Ok(Temporary::Int(i64::from(message.id()))),
        "opcode" => return Ok(Temporary::Int(i64::from(message.opcode().0))),
        "size" => {
            return Ok(Temporary::Int(
                crate::message_len::message_len(*message) as i64
            ));
        }
        // RFC 6891 §6.2.5: the OPT record carries the advertised UDP payload size.
        "bufsize" => {
            return Ok(Temporary::Int(
                pharos_server::response_limit(*message, query.protocol) as i64,
            ));
        }
        // RFC 3225 §3: the EDNS DO bit requests DNSSEC records.
        "do" => {
            return Ok(Temporary::Bool(
                message.opt().is_some_and(|opt| opt.dnssec_ok()),
            ));
        }
        "proto" => {
            return Ok(Temporary::Borrowed(match query.protocol {
                Protocol::Udp => "udp",
                Protocol::Tcp => "tcp",
            }));
        }
        _ => {}
    }
    let start = scratch.len;
    let result = match name {
        "name" => {
            if let Some(question) = message.questions().next() {
                write!(scratch, "{}", question.name)
            } else {
                scratch.write_str(".")
            }
        }
        "type" => {
            if let Some(question) = message.questions().next() {
                write!(scratch, "{}", question.qtype)
            } else {
                Ok(())
            }
        }
        "class" => {
            if let Some(question) = message.questions().next() {
                write!(scratch, "{}", question.qclass)
            } else {
                Ok(())
            }
        }
        "client_ip" => write!(scratch, "{}", query.client.ip()),
        "server_ip" => write!(scratch, "{}", query.local.ip()),
        "port" => write!(scratch, "{}", query.client.port()),
        "server_port" => write!(scratch, "{}", query.local.port()),
        _ => return Err("unknown function"),
    };
    result.map_err(|_| "expression scratch buffer is too small")?;
    if name == "name" {
        scratch.buffer[start..scratch.len].make_ascii_lowercase();
    }
    Ok(Temporary::Stored(start, scratch.len))
}

/// An expression parsed once at setup.
pub struct Expression(Node);

impl Expression {
    pub fn compile(source: &str) -> Result<Self, String> {
        parser::parse(source).map(Self)
    }

    pub fn evaluate<'a>(
        &'a self,
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        scratch.len = 0;
        let value = self.0.eval(query, metadata, scratch)?;
        match value {
            Temporary::Bool(value) => Ok(Value::Bool(value)),
            Temporary::Int(value) => Ok(Value::Int(value)),
            Temporary::Borrowed(value) => Ok(Value::String(value)),
            Temporary::Stored(start, end) => Ok(Value::String(
                std::str::from_utf8(&scratch.buffer[start..end]).map_err(|_| "invalid UTF-8")?,
            )),
        }
    }
}
