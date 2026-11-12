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
    Bool(bool),
    Int(i64),
    String(&'a str),
}

/// Types of variables declared before this expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    Bool,
    Int,
    String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Kind {
    Bool,
    Int,
    String,
    List,
}

impl From<ValueType> for Kind {
    fn from(value: ValueType) -> Self {
        match value {
            ValueType::Bool => Self::Bool,
            ValueType::Int => Self::Int,
            ValueType::String => Self::String,
        }
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
    Bool(bool),
    Int(i64),
    String(String),
    Variable(String, Kind),
    List(Vec<Node>),
    Current(Kind),
    Any(Vec<Node>, Box<Node>),
    Call(String, Vec<Node>, Kind),
    Matches(Box<Node>, crate::regex_match::Regex),
    Unary(Unary, Box<Node>),
    Binary(Binary, Box<Node>, Box<Node>, Kind),
}

impl Node {
    fn kind(&self) -> Kind {
        match self {
            Self::Bool(_) | Self::Unary(Unary::Not, _) => Kind::Bool,
            Self::Int(_) | Self::Unary(Unary::Neg, _) => Kind::Int,
            Self::String(_) => Kind::String,
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
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        scratch: &mut Scratch<'_>,
        current: Option<Temporary<'a>>,
    ) -> Result<Temporary<'a>, &'static str> {
        match self {
            Self::Bool(value) => Ok(Temporary::Bool(*value)),
            Self::Int(value) => Ok(Temporary::Int(*value)),
            Self::String(value) => Ok(Temporary::Borrowed(value)),
            Self::Variable(name, kind) => {
                let value = query
                    .variables
                    .iter()
                    .find_map(|(key, value)| (*key == name).then_some(*value))
                    .ok_or("missing expression variable")?;
                match (kind, value) {
                    (Kind::Bool, Value::Bool(value)) => Ok(Temporary::Bool(value)),
                    (Kind::Int, Value::Int(value)) => Ok(Temporary::Int(value)),
                    (Kind::String, Value::String(value)) => Ok(Temporary::Borrowed(value)),
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
                    (Div, Temporary::Int(a), Temporary::Int(b)) => a
                        .checked_div(b)
                        .map(Temporary::Int)
                        .ok_or("integer division error"),
                    (Rem, Temporary::Int(a), Temporary::Int(b)) => a
                        .checked_rem(b)
                        .map(Temporary::Int)
                        .ok_or("integer division error"),
                    (op @ (Contains | StartsWith | EndsWith), a, b) => {
                        let (a, b) = (a.text(scratch)?, b.text(scratch)?);
                        Ok(Temporary::Bool(match op {
                            Contains => a.contains(b),
                            StartsWith => a.starts_with(b),
                            EndsWith => a.ends_with(b),
                            _ => unreachable!(),
                        }))
                    }
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

fn equal(a: Temporary<'_>, b: Temporary<'_>, scratch: &Scratch<'_>) -> Result<bool, &'static str> {
    match (a, b) {
        (Temporary::Bool(a), Temporary::Bool(b)) => Ok(a == b),
        (Temporary::Int(a), Temporary::Int(b)) => Ok(a == b),
        (a, b) => Ok(a.text(scratch)? == b.text(scratch)?),
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
    query: &'a Query<'_>,
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
        };
        return Ok(Temporary::Borrowed(group));
    }
    if name == "int" {
        let value = args[0].eval(query, metadata, scratch, current)?;
        return match value {
            Temporary::Int(value) => Ok(Temporary::Int(value)),
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

fn incidr(ip: &str, cidr: &str) -> Result<bool, &'static str> {
    use std::net::IpAddr;
    let ip: IpAddr = ip
        .parse()
        .map_err(|_| "first argument is not an IP address")?;
    let (network, prefix) = cidr.split_once('/').ok_or("invalid CIDR")?;
    let network: IpAddr = network.parse().map_err(|_| "invalid CIDR address")?;
    if prefix.is_empty()
        || !prefix.bytes().all(|b| b.is_ascii_digit())
        || (prefix.len() > 1 && prefix.starts_with('0'))
    {
        return Err("invalid CIDR prefix");
    }
    let prefix: u8 = prefix.parse().map_err(|_| "invalid CIDR prefix")?;
    let max = if network.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return Err("invalid CIDR prefix");
    }
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
pub struct Expression(Node);

impl Expression {
    pub fn compile(source: &str) -> Result<Self, String> {
        Self::compile_with_variables(source, &[])
    }

    /// Compile with names and types of previously declared variables.
    pub fn compile_with_variables(
        source: &str,
        variables: &[(&str, ValueType)],
    ) -> Result<Self, String> {
        parser::parse(source, variables).map(Self)
    }

    /// Type of this expression, for compiling subsequent variables.
    pub fn value_type(&self) -> ValueType {
        match self.0.kind() {
            Kind::Bool => ValueType::Bool,
            Kind::Int => ValueType::Int,
            Kind::String => ValueType::String,
            Kind::List => unreachable!("list results are rejected at compile time"),
        }
    }

    pub fn evaluate<'a>(
        &'a self,
        query: &'a Query<'_>,
        metadata: &'a Metadata<'_>,
        scratch: &'a mut Scratch<'_>,
    ) -> Result<Value<'a>, &'static str> {
        scratch.len = 0;
        let value = self.0.eval(query, metadata, scratch, None)?;
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
