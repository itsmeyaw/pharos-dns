//! Streaming presentation-format Zone records.

mod rdata;
pub use rdata::parse_rdata;

use std::{
    fmt,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};

use crate::{Class, Name, Type};

/// An owned Zone record with uncompressed wire-format RDATA.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneRecord {
    pub owner: Name,
    pub ttl: u32,
    pub class: Class,
    pub rtype: Type,
    pub rdata: Vec<u8>,
}

/// Location and reason for a malformed Zone file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneError {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub message: String,
}

impl fmt::Display for ZoneError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}:{}:{}: {}",
            self.file, self.line, self.column, self.message
        )
    }
}

impl std::error::Error for ZoneError {}

/// Incrementally reads Zone records; an error terminates the iterator.
pub struct ZoneParser<R> {
    reader: R,
    origin: Name,
    file: String,
    line: usize,
    owner: Option<Name>,
    ttl: Option<u32>,
    directive_ttl: bool,
    finished: bool,
    input: String,
    include_allowed: bool,
    depth: u8,
    child: Option<Box<ZoneParser<BufReader<File>>>>,
    generate: Option<Generate>,
}

struct Generate {
    current: i64,
    end: i64,
    step: i64,
    tokens: Vec<String>,
    line: usize,
    ttl: Option<u32>,
    directive_ttl: bool,
    owner: Option<Name>,
}

impl<R: BufRead> ZoneParser<R> {
    #[must_use]
    pub fn new(reader: R, origin: Name, filename: impl Into<String>) -> Self {
        Self {
            reader,
            origin,
            file: filename.into(),
            line: 0,
            owner: None,
            ttl: None,
            directive_ttl: false,
            finished: false,
            input: String::new(),
            include_allowed: false,
            depth: 0,
            child: None,
            generate: None,
        }
    }

    /// Sets the initial default TTL, as if specified on a prior record.
    pub fn set_default_ttl(&mut self, ttl: u32) {
        self.ttl = Some(ttl);
        self.directive_ttl = false;
    }

    /// Enables reading files named by $INCLUDE. Disabled by default.
    pub fn set_include_allowed(&mut self, allowed: bool) {
        self.include_allowed = allowed;
    }

    fn error(&self, line: usize, column: usize, message: impl Into<String>) -> ZoneError {
        ZoneError {
            file: self.file.clone(),
            line,
            column,
            message: message.into(),
        }
    }

    // RFC 1035 §5.1: parentheses join physical lines and semicolons start comments.
    // shortcut: token storage allocates per record; reuse it to meet the allocation goal.
    fn read_entry(&mut self) -> Result<Option<(Vec<String>, bool, usize)>, ZoneError> {
        let mut tokens = Vec::new();
        let mut token = String::new();
        let mut active = false;
        let mut quote = false;
        let mut parens = false;
        let mut start = 0;
        let mut inherited = false;
        loop {
            self.input.clear();
            let n = self
                .reader
                .read_line(&mut self.input)
                .map_err(|e| self.error(self.line + 1, 1, e.to_string()))?;
            if n == 0 {
                if quote || parens {
                    return Err(self.error(self.line, 1, "unterminated record"));
                }
                if active {
                    tokens.push(std::mem::take(&mut token));
                }
                return Ok((!tokens.is_empty()).then_some((tokens, inherited, start)));
            }
            self.line += 1;
            let line = self.input.as_bytes();
            if start == 0 && line.iter().any(|b| !b.is_ascii_whitespace()) {
                start = self.line;
                inherited = line.first().is_some_and(|b| b.is_ascii_whitespace());
            }
            let mut i = 0;
            while i < line.len() {
                let b = line[i];
                if b == b'\\' {
                    if i + 1 >= line.len() || line[i + 1] == b'\n' {
                        return Err(self.error(self.line, i + 1, "incomplete escape"));
                    }
                    token.push('\\');
                    i += 1;
                    let ch = self.input[i..].chars().next().expect("character exists");
                    token.push(ch);
                    i += ch.len_utf8() - 1;
                    active = true;
                } else if b == b'"' {
                    quote = !quote;
                    active = true;
                } else if !quote && b == b';' {
                    break;
                } else if !quote && (b == b'(' || b == b')') {
                    if active {
                        tokens.push(std::mem::take(&mut token));
                        active = false;
                    }
                    if (b == b'(') == parens {
                        return Err(self.error(self.line, i + 1, "unbalanced parentheses"));
                    }
                    parens = b == b'(';
                } else if !quote && b.is_ascii_whitespace() {
                    if active {
                        tokens.push(std::mem::take(&mut token));
                        active = false;
                    }
                } else if b == b'\n' || b == b'\r' {
                    if quote {
                        return Err(self.error(self.line, i + 1, "unterminated quote"));
                    }
                } else {
                    let ch = self.input[i..].chars().next().expect("character exists");
                    token.push(ch);
                    i += ch.len_utf8() - 1;
                    active = true;
                }
                i += 1;
            }
            if quote {
                return Err(self.error(self.line, line.len(), "unterminated quote"));
            }
            if !parens {
                if active {
                    tokens.push(std::mem::take(&mut token));
                }
                if !tokens.is_empty() {
                    return Ok(Some((tokens, inherited, start)));
                }
                start = 0;
            }
        }
    }

    fn parse_entry(
        &mut self,
        tokens: &[String],
        inherited: bool,
        line: usize,
    ) -> Result<Option<ZoneRecord>, ZoneError> {
        let err = |message: &str| self.error(line, 1, message);
        if tokens[0].starts_with('$') {
            if tokens[0].eq_ignore_ascii_case("$ORIGIN") {
                if tokens.len() != 2 {
                    return Err(err("invalid origin"));
                }
                self.origin =
                    Name::parse(&tokens[1], &self.origin).map_err(|e| err(&e.to_string()))?;
            } else if tokens[0].eq_ignore_ascii_case("$TTL") {
                if tokens.len() != 2 {
                    return Err(err("invalid TTL"));
                }
                self.ttl = Some(parse_ttl(&tokens[1]).ok_or_else(|| err("invalid TTL"))?);
                self.directive_ttl = true;
            } else if tokens[0].eq_ignore_ascii_case("$INCLUDE") {
                if !self.include_allowed {
                    return Err(err("$INCLUDE not allowed"));
                }
                if self.depth >= 7 || !(2..=3).contains(&tokens.len()) {
                    return Err(err("invalid $INCLUDE"));
                }
                let path = Path::new(&tokens[1]);
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    Path::new(&self.file)
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .join(path)
                };
                let file = File::open(&path).map_err(|e| err(&e.to_string()))?;
                let origin = if tokens.len() == 3 {
                    Name::parse(&tokens[2], &self.origin).map_err(|e| err(&e.to_string()))?
                } else {
                    self.origin.clone()
                };
                let mut child =
                    ZoneParser::new(BufReader::new(file), origin, path.to_string_lossy());
                child.ttl = self.ttl;
                child.directive_ttl = self.directive_ttl;
                child.depth = self.depth + 1;
                child.include_allowed = true;
                self.child = Some(Box::new(child));
            } else if tokens[0].eq_ignore_ascii_case("$GENERATE") {
                if tokens.len() < 4 {
                    return Err(err("invalid $GENERATE"));
                }
                let (range, step) = tokens[1].split_once('/').unwrap_or((&tokens[1], "1"));
                let (start, end) = range
                    .split_once('-')
                    .ok_or_else(|| err("invalid generate range"))?;
                let start: i64 = start.parse().map_err(|_| err("invalid generate start"))?;
                let end: i64 = end.parse().map_err(|_| err("invalid generate end"))?;
                let step: i64 = step.parse().map_err(|_| err("invalid generate step"))?;
                if start < 0 || end < start || step <= 0 || (end - start) / step > 65535 {
                    return Err(err("invalid generate range"));
                }
                self.generate = Some(Generate {
                    current: start,
                    end,
                    step,
                    tokens: tokens[2..].to_vec(),
                    line,
                    ttl: Some(3600),
                    directive_ttl: false,
                    owner: None,
                });
            } else {
                return Err(err("unsupported directive"));
            }
            return Ok(None);
        }
        // RFC 1035 §5.1: a blank owner inherits the previous owner; class defaults to IN.
        let mut i = 0;
        let owner = if inherited {
            self.owner.clone().ok_or_else(|| err("missing owner"))?
        } else {
            i += 1;
            Name::parse(&tokens[0], &self.origin).map_err(|e| err(&e.to_string()))?
        };
        let mut ttl = self.ttl;
        let mut class = Class::IN;
        let mut saw_class = false;
        let mut saw_ttl = false;
        let rtype = loop {
            let field = tokens.get(i).ok_or_else(|| err("missing record type"))?;
            i += 1;
            if field.eq_ignore_ascii_case("ANY") {
                return Err(err("invalid record header"));
            }
            if !saw_class && let Some(value) = parse_class(field) {
                class = value;
                saw_class = true;
                continue;
            }
            if let Some(rtype) = parse_type(field) {
                break rtype;
            }
            if !saw_ttl && let Some(value) = parse_ttl(field) {
                ttl = Some(value);
                saw_ttl = true;
                continue;
            }
            return Err(err("invalid record header"));
        };
        let ttl = ttl.ok_or_else(|| err("missing TTL"))?;
        if rtype == Type::TSIG && tokens.get(i).is_none_or(|field| field != r"\#") {
            return Err(err("TSIG has no zone presentation format"));
        }
        let fields: Vec<&str> = tokens[i..].iter().map(String::as_str).collect();
        let rdata = parse_rdata(rtype, &fields, &self.origin).map_err(|e| err(&e))?;
        if saw_ttl && !self.directive_ttl {
            self.ttl = Some(ttl);
        }
        self.owner = Some(owner.clone());
        Ok(Some(ZoneRecord {
            owner,
            ttl,
            class,
            rtype,
            rdata,
        }))
    }
}

impl<R: BufRead> Iterator for ZoneParser<R> {
    type Item = Result<ZoneRecord, ZoneError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if let Some(child) = &mut self.child {
                if let Some(record) = child.next() {
                    if record.is_err() {
                        self.finished = true;
                    }
                    return Some(record);
                }
                self.child = None;
            }
            if let Some(mut generate) = self.generate.take() {
                let expanded = generate
                    .tokens
                    .iter()
                    .map(|s| expand_generate(s, generate.current, generate.end))
                    .collect::<Result<Vec<_>, _>>();
                let line = generate.line;
                std::mem::swap(&mut self.ttl, &mut generate.ttl);
                std::mem::swap(&mut self.directive_ttl, &mut generate.directive_ttl);
                std::mem::swap(&mut self.owner, &mut generate.owner);
                let result = expanded
                    .map_err(|e| self.error(line, 1, e))
                    .and_then(|tokens| {
                        if tokens.first().is_some_and(|t| t.starts_with('$')) {
                            return Err(self.error(line, 1, "nested $GENERATE"));
                        }
                        self.parse_entry(&tokens, false, line)
                    });
                std::mem::swap(&mut self.ttl, &mut generate.ttl);
                std::mem::swap(&mut self.directive_ttl, &mut generate.directive_ttl);
                std::mem::swap(&mut self.owner, &mut generate.owner);
                if let Some(next) = generate
                    .current
                    .checked_add(generate.step)
                    .filter(|next| *next <= generate.end)
                {
                    generate.current = next;
                    self.generate = Some(generate);
                }
                match result {
                    Ok(Some(record)) => return Some(Ok(record)),
                    Ok(None) => continue,
                    Err(error) => {
                        self.finished = true;
                        return Some(Err(error));
                    }
                }
            }
            let result = match self.read_entry() {
                Ok(Some((tokens, inherited, line))) => self.parse_entry(&tokens, inherited, line),
                Ok(None) => {
                    self.finished = true;
                    return None;
                }
                Err(e) => Err(e),
            };
            match result {
                Ok(Some(record)) => return Some(Ok(record)),
                Ok(None) => {}
                Err(error) => {
                    self.finished = true;
                    return Some(Err(error));
                }
            }
        }
    }
}

fn expand_generate(input: &str, value: i64, end: i64) -> Result<String, String> {
    let mut chars = input.chars().peekable();
    let mut output = String::new();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            output.push(ch);
            output.push(chars.next().ok_or("incomplete escape")?);
        } else if ch != '$' {
            output.push(ch);
        } else if chars.peek() == Some(&'$') {
            chars.next();
            output.push('$');
        } else {
            let (mut offset, mut width, mut base) = (0_i64, 0_usize, 'd');
            let modified = chars.peek() == Some(&'{');
            if modified {
                chars.next();
                let mut modifier = String::new();
                loop {
                    match chars.next() {
                        Some('}') => break,
                        Some(ch) => modifier.push(ch),
                        None => return Err("invalid modifier".into()),
                    }
                }
                let mut parts = modifier.split(',');
                offset = parts
                    .next()
                    .ok_or("invalid offset")?
                    .parse()
                    .map_err(|_| "invalid offset")?;
                if let Some(part) = parts.next() {
                    width = part.parse::<u8>().map_err(|_| "invalid width")? as usize;
                }
                if let Some(part) = parts.next() {
                    base = match part {
                        "d" => 'd',
                        "o" => 'o',
                        "x" => 'x',
                        "X" => 'X',
                        _ => return Err("invalid base".into()),
                    };
                }
                if parts.next().is_some() {
                    return Err("invalid modifier".into());
                }
            }
            let number = value.checked_add(offset).ok_or("invalid offset")?;
            if number < 0
                || (modified
                    && end
                        .checked_add(offset)
                        .is_none_or(|n| n > i64::from(i32::MAX)))
            {
                return Err("invalid offset".into());
            }
            output.push_str(&match base {
                'o' => format!("{number:0width$o}"),
                'x' => format!("{number:0width$x}"),
                'X' => format!("{number:0width$X}"),
                _ => format!("{number:0width$}"),
            });
        }
    }
    Ok(output)
}

// RFC 2308 §4: a default TTL may be written using unit suffixes.
fn parse_ttl(value: &str) -> Option<u32> {
    let mut result = 0_u32;
    let mut number = 0_u32;
    let mut digits = false;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .checked_mul(10)?
                .checked_add(u32::from(byte - b'0'))?;
            digits = true;
        } else {
            if !digits {
                return None;
            }
            let unit = match byte.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => return None,
            };
            result = result.checked_add(number.checked_mul(unit)?)?;
            number = 0;
            digits = false;
        }
    }
    if value.is_empty() {
        return None;
    }
    result.checked_add(number)
}

fn parse_class(value: &str) -> Option<Class> {
    let upper = value.to_ascii_uppercase();
    Some(match upper.as_str() {
        "IN" => Class::IN,
        "CH" | "CHAOS" => Class::CH,
        "HS" | "HESIOD" => Class::HS,
        "CS" => Class::CS,
        "NONE" => Class::NONE,
        "ANY" => Class::ANY,
        _ => Class(upper.strip_prefix("CLASS")?.parse().ok()?),
    })
}

fn parse_type(value: &str) -> Option<Type> {
    let upper = value.to_ascii_uppercase();
    if let Some(number) = upper.strip_prefix("TYPE") {
        return (!number.is_empty() && number.bytes().all(|b| b.is_ascii_digit()))
            .then(|| number.parse().ok().map(Type))
            .flatten();
    }
    Type::from_mnemonic(&upper)
}
