//! Compiled expressions over borrowed Queries and Metadata.

use pharos_proto::Message;
use pharos_server::{Metadata, Protocol};
use std::net::SocketAddr;

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
    Unary(Unary, Box<Node>),
    Binary(Binary, Box<Node>, Box<Node>, Kind),
}

impl Node {
    fn kind(&self) -> Kind {
        match self {
            Self::Bool(_) | Self::Unary(Unary::Not, _) => Kind::Bool,
            Self::Int(_) | Self::Unary(Unary::Neg, _) => Kind::Int,
            Self::String(_) => Kind::String,
            Self::Binary(_, _, _, kind) => *kind,
        }
    }

    fn eval(&self) -> Result<Value<'_>, &'static str> {
        match self {
            Self::Bool(value) => Ok(Value::Bool(*value)),
            Self::Int(value) => Ok(Value::Int(*value)),
            Self::String(value) => Ok(Value::String(value)),
            Self::Unary(Unary::Not, node) => match node.eval()? {
                Value::Bool(value) => Ok(Value::Bool(!value)),
                _ => Err("expected bool"),
            },
            Self::Unary(Unary::Neg, node) => match node.eval()? {
                Value::Int(value) => Ok(Value::Int(value.wrapping_neg())),
                _ => Err("expected integer"),
            },
            Self::Binary(op, left, right, _) => {
                let left = left.eval()?;
                if matches!(
                    (op, &left),
                    (Binary::And, Value::Bool(false)) | (Binary::Or, Value::Bool(true))
                ) {
                    return Ok(left);
                }
                let right = right.eval()?;
                use Binary::*;
                match (op, left, right) {
                    (And, Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a && b)),
                    (Or, Value::Bool(a), Value::Bool(b)) => Ok(Value::Bool(a || b)),
                    (Add, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_add(b))),
                    (Sub, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_sub(b))),
                    (Mul, Value::Int(a), Value::Int(b)) => Ok(Value::Int(a.wrapping_mul(b))),
                    (Div, Value::Int(a), Value::Int(b)) => a
                        .checked_div(b)
                        .map(Value::Int)
                        .ok_or("integer division error"),
                    (Rem, Value::Int(a), Value::Int(b)) => a
                        .checked_rem(b)
                        .map(Value::Int)
                        .ok_or("integer division error"),
                    (op @ (Eq | Ne | Lt | Le | Gt | Ge), a, b) => {
                        let ordering = match (a, b) {
                            (Value::Bool(a), Value::Bool(b)) => a.cmp(&b),
                            (Value::Int(a), Value::Int(b)) => a.cmp(&b),
                            (Value::String(a), Value::String(b)) => a.cmp(b),
                            _ => return Err("incompatible operands"),
                        };
                        Ok(Value::Bool(match op {
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

/// An expression parsed once at setup.
pub struct Expression(Node);

impl Expression {
    pub fn compile(source: &str) -> Result<Self, String> {
        parser::parse(source).map(Self)
    }

    pub fn evaluate<'a>(
        &'a self,
        _query: &'a Query<'_>,
        _metadata: &'a Metadata<'_>,
        _scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        self.0.eval()
    }
}
