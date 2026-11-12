//! Compiled expressions over borrowed Queries and Metadata.

use pharos_proto::Message;
use pharos_server::{Metadata, MetadataSource, Protocol};
use std::{
    fmt::{self, Write},
    net::SocketAddr,
};

mod parser;

const MAX_DEPTH: usize = 16;

/// Borrowed Query and transport information.
pub struct Query<'a> {
    pub message: &'a Message<'a>,
    pub client: SocketAddr,
    pub local: SocketAddr,
    pub protocol: Protocol,
    pub groups: &'a [(&'a str, &'a str)],
    pub matches: &'a [&'a str],
    pub variables: &'a [(&'a str, Value<'a>)],
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
            groups: &[],
            matches: &[],
            variables: &[],
        }
    }
}

#[derive(Clone, Copy)]
pub(crate) struct ScopedQuery<'a, 'v> {
    base: &'a Query<'a>,
    pub message: &'a Message<'a>,
    pub client: SocketAddr,
    pub local: SocketAddr,
    pub protocol: Protocol,
    pub groups: &'a [(&'a str, &'a str)],
    pub matches: &'a [&'a str],
    pub variables: &'v [(&'a str, Value<'a>)],
}

impl<'a, 'v> ScopedQuery<'a, 'v> {
    pub(crate) fn new(query: &'a Query<'a>, variables: &'v [(&'a str, Value<'a>)]) -> Self {
        Self {
            base: query,
            message: query.message,
            client: query.client,
            local: query.local,
            protocol: query.protocol,
            groups: query.groups,
            matches: query.matches,
            variables,
        }
    }
}

#[cfg(test)]
mod scoped_tests {
    use super::*;

    #[test]
    fn variable_slice_can_grow_after_scoped_evaluation() {
        let wire = b"\0\x01\x01\0\0\x01\0\0\0\0\0\0\x01x\0\0\x01\0\x01";
        let message = Message::parse(wire).unwrap();
        let query = Query::new(
            &message,
            "127.0.0.1:1234".parse().unwrap(),
            "127.0.0.1:53".parse().unwrap(),
            Protocol::Udp,
        );
        let mut metadata_slots = [];
        let metadata = Metadata::new(&mut metadata_slots);
        let first = Expression::compile("name").unwrap();
        let second =
            Expression::compile_with_variables("f", &[("f", ValueType::Function)]).unwrap();
        let mut variables = Vec::with_capacity(2);
        let mut buffer = [0; 16];
        let scoped = ScopedQuery::new(&query, &variables);
        let (function, rest) = first
            .evaluate_scoped_split(&scoped, &metadata, &mut buffer)
            .unwrap();
        variables.push(("f", function));
        let scoped = ScopedQuery::new(&query, &variables);
        let (copy, _) = second
            .evaluate_scoped_split(&scoped, &metadata, rest)
            .unwrap();
        variables.push(("copy", copy));
        assert!(matches!(variables[1].1, Value::Function(_)));
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
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Value<'a> {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(&'a str),
    Function(Callable<'a>),
}

/// A query function bound to the Query where it was evaluated.
#[derive(Clone, Copy)]
pub struct Callable<'a> {
    name: &'a str,
    query: &'a Query<'a>,
    metadata: &'a dyn MetadataSource,
}

impl fmt::Debug for Callable<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_tuple("Callable").field(&self.name).finish()
    }
}

impl PartialEq for Callable<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
            && std::ptr::eq(self.query, other.query)
            && std::ptr::eq(self.metadata, other.metadata)
    }
}

impl Callable<'_> {
    pub(crate) fn type_name(&self) -> &'static str {
        match self.name {
            "do" => "func() bool",
            "size" | "id" | "opcode" | "bufsize" => "func() int",
            "metadata" => "func(string) string",
            "incidr" => "func(string, string) (bool, error)",
            "group" => "func(interface {}) string",
            _ => "func() string",
        }
    }
    pub(crate) fn invoke<'a>(
        &'a self,
        args: &[Value<'_>],
        buffer: &'a mut [u8],
    ) -> Result<Value<'a>, &'static str> {
        let query = ScopedQuery::new(self.query, &[]);
        match (self.name, args) {
            ("metadata", [Value::String(label)]) => {
                return Ok(Value::String(self.metadata.get(label).unwrap_or("")));
            }
            ("incidr", [Value::String(ip), Value::String(cidr)]) => {
                return Ok(Value::Bool(incidr(ip, cidr)?));
            }
            ("group", [value]) => {
                return Ok(Value::String(match value {
                    Value::Int(index) => usize::try_from(*index)
                        .ok()
                        .and_then(|index| self.query.matches.get(index).copied())
                        .unwrap_or(""),
                    Value::String(name) => group_name(&query, name),
                    _ => "",
                }));
            }
            ("metadata" | "incidr" | "group", _) => return Err("invalid function arguments"),
            (_, []) => {}
            _ => return Err("invalid function arguments"),
        }
        let mut slots = [];
        let metadata = Metadata::new(&mut slots);
        let mut scratch = Scratch::new(buffer);
        let value = call(self.name, &[], &query, &metadata, &mut scratch, None)?;
        match value {
            Temporary::Bool(value) => Ok(Value::Bool(value)),
            Temporary::Int(value) => Ok(Value::Int(value)),
            Temporary::Borrowed(value) => {
                let start = scratch.len;
                scratch
                    .write_str(value)
                    .map_err(|_| "expression scratch buffer is too small")?;
                let end = scratch.len;
                Ok(Value::String(
                    std::str::from_utf8(&scratch.buffer[start..end])
                        .map_err(|_| "invalid UTF-8")?,
                ))
            }
            Temporary::Stored(start, end) => Ok(Value::String(
                std::str::from_utf8(&scratch.buffer[start..end]).map_err(|_| "invalid UTF-8")?,
            )),
            _ => Err("unsupported query function"),
        }
    }
}

/// Types of variables declared before this expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    Nil,
    Bool,
    Int,
    Float,
    String,
    Function,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Dynamic,
    Nil,
    Bool,
    Int,
    Float,
    String,
    List,
    Function,
}

impl From<ValueType> for Kind {
    fn from(value: ValueType) -> Self {
        match value {
            ValueType::Nil => Self::Nil,
            ValueType::Bool => Self::Bool,
            ValueType::Int => Self::Int,
            ValueType::Float => Self::Float,
            ValueType::String => Self::String,
            ValueType::Function => Self::Function,
        }
    }
}

impl Kind {
    fn numeric(self) -> bool {
        matches!(self, Self::Int | Self::Float)
    }

    fn accepts(self, expected: Self) -> bool {
        self == expected || self == Self::Dynamic
    }
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
    In,
    Contains,
    StartsWith,
    EndsWith,
    Matches,
}

enum Node {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    String(String),
    Function(String),
    Variable(String, Kind),
    List(Vec<Node>),
    Current(Kind),
    Any(Vec<Node>, Box<Node>),
    Call(String, Vec<Node>, Kind),
    Matches(Box<Node>, Box<crate::regex_match::ThreadRegex>),
    Unary(Unary, Box<Node>),
    Binary(Binary, Box<Node>, Box<Node>, Kind),
}

impl Node {
    fn kind(&self) -> Kind {
        match self {
            Self::Nil => Kind::Nil,
            Self::Bool(_) | Self::Unary(Unary::Not, _) => Kind::Bool,
            Self::Int(_) => Kind::Int,
            Self::Float(_) => Kind::Float,
            Self::Unary(Unary::Neg, node) => node.kind(),
            Self::String(_) => Kind::String,
            Self::Function(_) => Kind::Function,
            Self::Variable(_, kind) => *kind,
            Self::List(_) => Kind::List,
            Self::Current(kind) => *kind,
            Self::Any(..) => Kind::Bool,
            Self::Call(_, _, kind) => *kind,
            Self::Matches(..) => Kind::Bool,
            Self::Binary(_, _, _, kind) => *kind,
        }
    }

    fn eval<'a>(
        &'a self,
        query: &ScopedQuery<'a, '_>,
        metadata: &'a Metadata<'_>,
        scratch: &mut Scratch<'_>,
        current: Option<Temporary<'a>>,
    ) -> Result<Temporary<'a>, &'static str> {
        match self {
            Self::Nil => Ok(Temporary::Nil),
            Self::Bool(value) => Ok(Temporary::Bool(*value)),
            Self::Int(value) => Ok(Temporary::Int(*value)),
            Self::Float(value) => Ok(Temporary::Float(*value)),
            Self::String(value) => Ok(Temporary::Borrowed(value)),
            Self::Function(name) => Ok(Temporary::Function(Callable {
                name,
                query: query.base,
                metadata,
            })),
            Self::Variable(name, kind) => {
                let value = query
                    .variables
                    .iter()
                    .find_map(|(key, value)| (*key == name).then_some(*value))
                    .ok_or("missing expression variable")?;
                match (kind, value) {
                    (Kind::Nil, Value::Nil) => Ok(Temporary::Nil),
                    (Kind::Bool, Value::Bool(value)) => Ok(Temporary::Bool(value)),
                    (Kind::Int, Value::Int(value)) => Ok(Temporary::Int(value)),
                    (Kind::Float, Value::Float(value)) => Ok(Temporary::Float(value)),
                    (Kind::String, Value::String(value)) => Ok(Temporary::Borrowed(value)),
                    (Kind::Function, Value::Function(value)) => Ok(Temporary::Function(value)),
                    _ => Err("expression variable has wrong type"),
                }
            }
            Self::List(_) => Err("list cannot be evaluated alone"),
            Self::Current(_) => current.ok_or("missing any predicate value"),
            Self::Any(items, predicate) => {
                for item in items {
                    let saved = scratch.len;
                    let value = item.eval(query, metadata, scratch, current)?;
                    let matched = predicate.eval(query, metadata, scratch, Some(value))?;
                    let Temporary::Bool(matched) = matched else {
                        return Err("any predicate must be boolean");
                    };
                    scratch.len = saved;
                    if matched {
                        return Ok(Temporary::Bool(true));
                    }
                }
                Ok(Temporary::Bool(false))
            }
            Self::Call(name, args, _) => call(name, args, query, metadata, scratch, current),
            Self::Matches(value, regex) => {
                let value = value.eval(query, metadata, scratch, current)?;
                Ok(Temporary::Bool(regex.is_match(value.text(scratch)?)))
            }
            Self::Unary(Unary::Not, node) => match node.eval(query, metadata, scratch, current)? {
                Temporary::Bool(value) => Ok(Temporary::Bool(!value)),
                _ => Err("expected bool"),
            },
            Self::Unary(Unary::Neg, node) => match node.eval(query, metadata, scratch, current)? {
                Temporary::Int(value) => Ok(Temporary::Int(value.wrapping_neg())),
                Temporary::Float(value) => Ok(Temporary::Float(-value)),
                _ => Err("expected integer"),
            },
            Self::Binary(op, left, right, _) => {
                let left = left.eval(query, metadata, scratch, current)?;
                if matches!(
                    (op, &left),
                    (Binary::And, Temporary::Bool(false)) | (Binary::Or, Temporary::Bool(true))
                ) {
                    return Ok(left);
                }
                if matches!(op, Binary::In) {
                    let Self::List(items) = &**right else {
                        return Err("expected list");
                    };
                    for item in items {
                        let value = item.eval(query, metadata, scratch, current)?;
                        if equal(left, value, scratch)? {
                            return Ok(Temporary::Bool(true));
                        }
                    }
                    return Ok(Temporary::Bool(false));
                }
                let right = right.eval(query, metadata, scratch, current)?;
                use Binary::*;
                match (op, left, right) {
                    (And, Temporary::Bool(a), Temporary::Bool(b)) => Ok(Temporary::Bool(a && b)),
                    (Or, Temporary::Bool(a), Temporary::Bool(b)) => Ok(Temporary::Bool(a || b)),
                    (Add, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_add(b)))
                    }
                    (
                        Add,
                        a @ (Temporary::Float(_) | Temporary::Int(_)),
                        b @ (Temporary::Float(_) | Temporary::Int(_)),
                    ) => Ok(Temporary::Float(a.number()? + b.number()?)),
                    (Add, a, b) => {
                        let start = scratch.len;
                        scratch.append(a)?;
                        scratch.append(b)?;
                        Ok(Temporary::Stored(start, scratch.len))
                    }
                    (Sub, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_sub(b)))
                    }
                    (Mul, Temporary::Int(a), Temporary::Int(b)) => {
                        Ok(Temporary::Int(a.wrapping_mul(b)))
                    }
                    (Sub, a, b) => Ok(Temporary::Float(a.number()? - b.number()?)),
                    (Mul, a, b) => Ok(Temporary::Float(a.number()? * b.number()?)),
                    (Div, a, b) => Ok(Temporary::Float(a.number()? / b.number()?)),
                    (Rem, Temporary::Int(a), Temporary::Int(b)) => {
                        if b == 0 {
                            Err("integer division error")
                        } else {
                            Ok(Temporary::Int(a.wrapping_rem(b)))
                        }
                    }
                    (op @ (Contains | StartsWith | EndsWith), a, b) => {
                        let (a, b) = (a.text(scratch)?, b.text(scratch)?);
                        Ok(Temporary::Bool(match op {
                            Contains => a.contains(b),
                            StartsWith => a.starts_with(b),
                            EndsWith => a.ends_with(b),
                            _ => return Err("invalid string operator"),
                        }))
                    }
                    (Eq, a, b) => Ok(Temporary::Bool(equal(a, b, scratch)?)),
                    (Ne, a, b) => Ok(Temporary::Bool(!equal(a, b, scratch)?)),
                    (op @ (Lt | Le | Gt | Ge), a, b) => {
                        let ordering = match (a, b) {
                            (Temporary::Nil, Temporary::Nil) => Some(std::cmp::Ordering::Equal),
                            (Temporary::Nil, _) | (_, Temporary::Nil) => {
                                Some(std::cmp::Ordering::Less)
                            }
                            (Temporary::Bool(a), Temporary::Bool(b)) => Some(a.cmp(&b)),
                            (Temporary::Int(a), Temporary::Int(b)) => Some(a.cmp(&b)),
                            (
                                a @ (Temporary::Int(_) | Temporary::Float(_)),
                                b @ (Temporary::Int(_) | Temporary::Float(_)),
                            ) => a.number()?.partial_cmp(&b.number()?),
                            (a, b) => Some(a.text(scratch)?.cmp(b.text(scratch)?)),
                        };
                        Ok(Temporary::Bool(match op {
                            Lt => ordering.is_some_and(|value| value.is_lt()),
                            Le => ordering.is_some_and(|value| value.is_le()),
                            Gt => ordering.is_some_and(|value| value.is_gt()),
                            Ge => ordering.is_some_and(|value| value.is_ge()),
                            _ => return Err("invalid comparison operator"),
                        }))
                    }
                    _ => Err("incompatible operands"),
                }
            }
        }
    }
}

fn equal(a: Temporary<'_>, b: Temporary<'_>, scratch: &Scratch<'_>) -> Result<bool, &'static str> {
    match (a, b) {
        (Temporary::Nil, Temporary::Nil) => Ok(true),
        (Temporary::Bool(a), Temporary::Bool(b)) => Ok(a == b),
        (Temporary::Int(a), Temporary::Int(b)) => Ok(a == b),
        (
            a @ (Temporary::Int(_) | Temporary::Float(_)),
            b @ (Temporary::Int(_) | Temporary::Float(_)),
        ) => Ok(a.number()? == b.number()?),
        (
            a @ (Temporary::Borrowed(_) | Temporary::Stored(_, _)),
            b @ (Temporary::Borrowed(_) | Temporary::Stored(_, _)),
        ) => Ok(a.text(scratch)? == b.text(scratch)?),
        _ => Ok(false),
    }
}

#[derive(Clone, Copy)]
enum Temporary<'a> {
    Nil,
    Bool(bool),
    Int(i64),
    Float(f64),
    Borrowed(&'a str),
    Stored(usize, usize),
    Function(Callable<'a>),
}

impl<'a> Temporary<'a> {
    fn number(self) -> Result<f64, &'static str> {
        match self {
            Self::Int(value) => Ok(value as f64),
            Self::Float(value) => Ok(value),
            _ => Err("expected number"),
        }
    }
    fn text<'s>(&'s self, scratch: &'s Scratch<'_>) -> Result<&'s str, &'static str> {
        match self {
            Self::Borrowed(value) => Ok(value),
            Self::Stored(start, end) => {
                std::str::from_utf8(&scratch.buffer[*start..*end]).map_err(|_| "invalid UTF-8")
            }
            _ => Err("expected string"),
        }
    }

    fn slice(self, start: usize, end: usize) -> Result<Self, &'static str> {
        match self {
            Self::Borrowed(value) => Ok(Self::Borrowed(
                value.get(start..end).ok_or("invalid string slice")?,
            )),
            Self::Stored(offset, limit) if offset + end <= limit && start <= end => {
                Ok(Self::Stored(offset + start, offset + end))
            }
            _ => Err("invalid string slice"),
        }
    }
}

impl Scratch<'_> {
    fn append(&mut self, value: Temporary<'_>) -> Result<(), &'static str> {
        match value {
            Temporary::Borrowed(value) => self
                .write_str(value)
                .map_err(|_| "expression scratch buffer is too small"),
            Temporary::Stored(start, end) => {
                let new_end = self
                    .len
                    .checked_add(end - start)
                    .filter(|end| *end <= self.buffer.len())
                    .ok_or("expression scratch buffer is too small")?;
                self.buffer.copy_within(start..end, self.len);
                self.len = new_end;
                Ok(())
            }
            _ => Err("expected string"),
        }
    }
}

fn replace<'a>(
    input: Temporary<'a>,
    from: Temporary<'a>,
    to: Temporary<'a>,
    mut count: i64,
    scratch: &mut Scratch<'_>,
) -> Result<Temporary<'a>, &'static str> {
    let output = scratch.len;
    let len = input.text(scratch)?.len();
    let from_len = from.text(scratch)?.len();
    let mut pos = 0;
    if from_len == 0 {
        loop {
            if count == 0 {
                scratch.append(input.slice(pos, len)?)?;
                break;
            }
            scratch.append(to)?;
            if count > 0 {
                count -= 1;
            }
            if pos == len {
                break;
            }
            let next = pos
                + input.text(scratch)?[pos..]
                    .chars()
                    .next()
                    .ok_or("invalid string")?
                    .len_utf8();
            scratch.append(input.slice(pos, next)?)?;
            pos = next;
        }
    } else {
        while count != 0
            && let Some(relative) = input.text(scratch)?[pos..].find(from.text(scratch)?)
        {
            let found = pos + relative;
            scratch.append(input.slice(pos, found)?)?;
            scratch.append(to)?;
            if count > 0 {
                count -= 1;
            }
            pos = found + from_len;
        }
        scratch.append(input.slice(pos, len)?)?;
    }
    Ok(Temporary::Stored(output, scratch.len))
}

fn call<'a>(
    name: &str,
    args: &'a [Node],
    query: &ScopedQuery<'a, '_>,
    metadata: &'a Metadata<'_>,
    scratch: &mut Scratch<'_>,
    current: Option<Temporary<'a>>,
) -> Result<Temporary<'a>, &'static str> {
    if name == "replace" {
        let input = args[0].eval(query, metadata, scratch, current)?;
        let from = args[1].eval(query, metadata, scratch, current)?;
        let to = args[2].eval(query, metadata, scratch, current)?;
        let count = if args.len() == 4 {
            let Temporary::Int(count) = args[3].eval(query, metadata, scratch, current)? else {
                return Err("replace count must be an integer");
            };
            count
        } else {
            -1
        };
        return replace(input, from, to, count, scratch);
    }
    if name == "group" {
        let value = args[0].eval(query, metadata, scratch, current)?;
        let group = match value {
            Temporary::Int(index) => usize::try_from(index)
                .ok()
                .and_then(|index| query.matches.get(index).copied())
                .unwrap_or(""),
            value => {
                let key = value.text(scratch)?;
                group_name(query, key)
            }
        };
        return Ok(Temporary::Borrowed(group));
    }
    if name == "int" {
        let value = args[0].eval(query, metadata, scratch, current)?;
        return match value {
            Temporary::Int(value) => Ok(Temporary::Int(value)),
            Temporary::Float(value) => Ok(Temporary::Int(value as i64)),
            value => value
                .text(scratch)?
                .parse::<i64>()
                .map(Temporary::Int)
                .map_err(|_| "invalid integer"),
        };
    }
    if name == "incidr" {
        let ip = args[0].eval(query, metadata, scratch, current)?;
        let cidr = args[1].eval(query, metadata, scratch, current)?;
        return Ok(Temporary::Bool(incidr(
            ip.text(scratch)?,
            cidr.text(scratch)?,
        )?));
    }
    if name == "metadata" {
        let label = args[0].eval(query, metadata, scratch, current)?;
        if !metadata.enabled() {
            return Ok(Temporary::Borrowed(""));
        }
        return Ok(Temporary::Borrowed(
            metadata.get(label.text(scratch)?).unwrap_or(""),
        ));
    }
    let message = query.message;
    match name {
        // RFC 1035 §4.1.1: ID and OPCODE are fields of the Message header.
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
        // RFC 1035 §4.1.2: the Question holds QNAME, QTYPE, and QCLASS.
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
        "client_ip" => write_ip(scratch, query.client),
        "server_ip" => write_ip(scratch, query.local),
        "port" => write!(scratch, "{}", query.client.port()),
        "server_port" => write!(scratch, "{}", query.local.port()),
        _ => return Err("unknown function"),
    };
    result.map_err(|_| "expression scratch buffer is too small")?;
    if name == "name" {
        // RFC 4343 §2: DNS label comparisons ignore ASCII case.
        scratch.buffer[start..scratch.len].make_ascii_lowercase();
    }
    Ok(Temporary::Stored(start, scratch.len))
}

fn group_name<'a>(query: &ScopedQuery<'a, '_>, key: &str) -> &'a str {
    query
        .groups
        .iter()
        .find_map(|(name, group)| (*name == key).then_some(*group))
        .or_else(|| {
            if !key.bytes().all(|byte| byte.is_ascii_digit())
                || (key.len() > 1 && key.starts_with('0'))
            {
                return None;
            }
            key.parse::<usize>()
                .ok()
                .and_then(|index| query.matches.get(index).copied())
        })
        .unwrap_or("")
}

fn write_ip(output: &mut Scratch<'_>, address: SocketAddr) -> fmt::Result {
    match address {
        SocketAddr::V4(address) => write!(output, "{}", address.ip()),
        SocketAddr::V6(address) => {
            // RFC 4291 §2.5.5.2: IPv4-mapped addresses embed an IPv4 address.
            if let Some(ip) = address.ip().to_ipv4_mapped() {
                write!(output, "{ip}")
            } else if address.scope_id() == 0 {
                write!(output, "{}", address.ip())
            } else {
                write!(output, "{}%{}", address.ip(), address.scope_id())
            }
        }
    }
}

fn incidr(ip: &str, cidr: &str) -> Result<bool, &'static str> {
    use std::net::IpAddr;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| "first argument is not an IP address")?;
    let (network, prefix) = cidr.split_once('/').ok_or("invalid CIDR")?;
    let network: IpAddr = network.parse().map_err(|_| "invalid CIDR address")?;
    if prefix.is_empty() || !prefix.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid CIDR prefix");
    }
    let prefix: u8 = prefix.parse().map_err(|_| "invalid CIDR prefix")?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err("invalid CIDR prefix");
    }
    // RFC 4291 §2.5.5.2: treat IPv4-mapped addresses as their embedded IPv4 address.
    let ip = match ip {
        IpAddr::V6(value) => value.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        _ => ip,
    };
    let (network, prefix) = match network {
        IpAddr::V6(value) if prefix >= 96 => value
            .to_ipv4_mapped()
            .map_or((network, prefix), |v4| (IpAddr::V4(v4), prefix - 96)),
        _ => (network, prefix),
    };
    Ok(crate::ipnet::contains(network, prefix, ip))
}

/// An expression parsed once at setup.
pub struct Expression {
    root: Node,
    value_type: ValueType,
}

impl Expression {
    pub fn compile(source: &str) -> Result<Self, String> {
        Self::compile_with_variables(source, &[])
    }

    /// Compile with names and types of previously declared variables.
    pub fn compile_with_variables(
        source: &str,
        variables: &[(&str, ValueType)],
    ) -> Result<Self, String> {
        let root = parser::parse(source, variables)?;
        let value_type = match root.kind() {
            Kind::Nil => ValueType::Nil,
            Kind::Bool => ValueType::Bool,
            Kind::Int => ValueType::Int,
            Kind::Float => ValueType::Float,
            Kind::String => ValueType::String,
            Kind::Function => ValueType::Function,
            Kind::List | Kind::Dynamic => return Err("unsupported expression result type".into()),
        };
        Ok(Self { root, value_type })
    }

    /// Type of this expression, for compiling subsequent variables.
    pub fn value_type(&self) -> ValueType {
        self.value_type
    }

    /// Evaluate while retaining the used portion of the caller's buffer.
    pub fn evaluate_split<'a>(
        &'a self,
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        buffer: &'a mut [u8],
    ) -> Result<(Value<'a>, &'a mut [u8]), &'static str> {
        let scoped = ScopedQuery::new(query, query.variables);
        self.evaluate_scoped_split(&scoped, metadata, buffer)
    }

    pub(crate) fn evaluate_scoped_split<'a>(
        &'a self,
        query: &ScopedQuery<'a, '_>,
        metadata: &'a Metadata<'_>,
        buffer: &'a mut [u8],
    ) -> Result<(Value<'a>, &'a mut [u8]), &'static str> {
        let mut scratch = Scratch::new(buffer);
        let value = self.root.eval(query, metadata, &mut scratch, None)?;
        let (used, remaining) = scratch.buffer.split_at_mut(scratch.len);
        let value = match value {
            Temporary::Nil => Value::Nil,
            Temporary::Bool(value) => Value::Bool(value),
            Temporary::Int(value) => Value::Int(value),
            Temporary::Float(value) => Value::Float(value),
            Temporary::Function(value) => Value::Function(value),
            Temporary::Borrowed(value) => Value::String(value),
            Temporary::Stored(start, end) => {
                Value::String(std::str::from_utf8(&used[start..end]).map_err(|_| "invalid UTF-8")?)
            }
        };
        Ok((value, remaining))
    }

    pub fn evaluate<'a>(
        &'a self,
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        let scoped = ScopedQuery::new(query, query.variables);
        self.evaluate_scoped(&scoped, metadata, scratch)
    }

    pub(crate) fn evaluate_scoped<'a>(
        &'a self,
        query: &ScopedQuery<'a, '_>,
        metadata: &'a Metadata<'_>,
        scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        scratch.len = 0;
        let value = self.root.eval(query, metadata, scratch, None)?;
        match value {
            Temporary::Nil => Ok(Value::Nil),
            Temporary::Bool(value) => Ok(Value::Bool(value)),
            Temporary::Int(value) => Ok(Value::Int(value)),
            Temporary::Float(value) => Ok(Value::Float(value)),
            Temporary::Function(value) => Ok(Value::Function(value)),
            Temporary::Borrowed(value) => Ok(Value::String(value)),
            Temporary::Stored(start, end) => Ok(Value::String(
                std::str::from_utf8(&scratch.buffer[start..end]).map_err(|_| "invalid UTF-8")?,
            )),
        }
    }
}
