//! Streaming presentation-format Zone records.

mod rdata;
pub use rdata::parse_rdata;

use std::{
    fmt::{self, Write},
    fs::File,
    io::{BufRead, BufReader},
    path::{Path, PathBuf},
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
    file_path: PathBuf,
    line: usize,
    entry_end: (usize, usize),
    owner: Option<Name>,
    ttl: Option<u32>,
    directive_ttl: bool,
    finished: bool,
    input: Vec<u8>,
    include_allowed: bool,
    depth: u8,
    child: Option<Box<ZoneParser<BufReader<File>>>>,
    generate: Option<Generate>,
}

struct Generate {
    current: i64,
    end: i64,
    step: i64,
    tokens: Vec<Token>,
    line: usize,
    ttl: Option<u32>,
    directive_ttl: bool,
    owner: Option<Name>,
}

#[derive(Clone)]
struct Token {
    text: String,
    line: usize,
    column: usize,
    followed_by_blank: bool,
    columns: Vec<usize>,
    raw: Vec<u8>,
    quotes: Vec<(usize, usize, usize)>,
}

impl std::ops::Deref for Token {
    type Target = str;

    fn deref(&self) -> &str {
        &self.text
    }
}

impl<R: BufRead> ZoneParser<R> {
    #[must_use]
    pub fn new(reader: R, origin: Name, filename: impl Into<String>) -> Self {
        let file = filename.into();
        Self {
            reader,
            origin,
            file_path: PathBuf::from(&file),
            file,
            line: 0,
            entry_end: (1, 1),
            owner: None,
            ttl: None,
            directive_ttl: false,
            finished: false,
            input: Vec::new(),
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
    fn read_entry(&mut self) -> Result<Option<(Vec<Token>, bool, usize)>, ZoneError> {
        let mut tokens = Vec::new();
        let mut token = String::new();
        let mut columns = Vec::new();
        let mut raw = Vec::new();
        let mut quotes = Vec::new();
        let mut position = (0, 0);
        let mut active = false;
        let mut quote = false;
        let mut quote_start = None;
        let mut parens = Vec::new();
        let mut start = 0;
        let mut inherited = false;
        loop {
            self.input.clear();
            let n = self
                .reader
                .read_until(b'\n', &mut self.input)
                .map_err(|e| self.error(self.line + 1, 1, e.to_string()))?;
            if n == 0 {
                if let Some((line, column)) = quote_start.or_else(|| parens.last().copied()) {
                    return Err(self.error(line, column, "unterminated record"));
                }
                if active {
                    tokens.push(Token {
                        text: std::mem::take(&mut token),
                        line: position.0,
                        column: position.1,
                        followed_by_blank: false,
                        columns: std::mem::take(&mut columns),
                        raw: std::mem::take(&mut raw),
                        quotes: std::mem::take(&mut quotes),
                    });
                }
                return Ok((!tokens.is_empty()).then_some((tokens, inherited, start)));
            }
            self.line += 1;
            let line = &self.input;
            self.entry_end = (self.line, line.len() + usize::from(!line.ends_with(b"\n")));
            // RFC 1035 §5.1: tabs and spaces delimit the items of an entry.
            let mut content = line.iter().filter(|&&b| b != b'\r');
            if start == 0 && content.clone().any(|&b| !matches!(b, b' ' | b'\t' | b'\n')) {
                start = self.line;
                inherited = content.next().is_some_and(|&b| matches!(b, b' ' | b'\t'));
            }
            let mut i = 0;
            while i < line.len() {
                let b = line[i];
                let column = i + 1;
                if !active && !matches!(b, b';' | b'(' | b')' | b' ' | b'\t' | b'\r' | b'\n') {
                    position = (self.line, i + 1);
                }
                if b == b'\\' {
                    if i + 1 >= line.len() || (line[i + 1] == b'\n' && !quote) {
                        return Err(self.error(self.line, i + 1, "incomplete escape"));
                    }
                    i += 1;
                    if line[i] == b'\r' && !quote {
                        raw.push(b'\\');
                        token.push('\\');
                    } else if line[i] >= 128 {
                        raw.extend([b'\\', line[i]]);
                        write!(token, "\\{:03}", line[i]).expect("writing to a String");
                    } else {
                        raw.extend([b'\\', line[i]]);
                        token.push('\\');
                        token.push(char::from(line[i]));
                    }
                    active = true;
                } else if b == b'"' {
                    quotes.push((token.len(), self.line, i + 1));
                    quote_start = if quote {
                        None
                    } else {
                        Some((self.line, column))
                    };
                    quote = !quote;
                    active = true;
                } else if !quote && b == b';' {
                    self.entry_end = (self.line, column);
                    break;
                } else if !quote && (b == b'(' || b == b')') {
                    if active {
                        tokens.push(Token {
                            text: std::mem::take(&mut token),
                            line: position.0,
                            column: position.1,
                            followed_by_blank: false,
                            columns: std::mem::take(&mut columns),
                            raw: std::mem::take(&mut raw),
                            quotes: std::mem::take(&mut quotes),
                        });
                        active = false;
                    }
                    if b == b'(' {
                        parens.push((self.line, column));
                    } else if parens.pop().is_none() {
                        return Err(self.error(self.line, column, "unbalanced parentheses"));
                    }
                } else if !quote && matches!(b, b' ' | b'\t' | b'\n') {
                    if active {
                        tokens.push(Token {
                            text: std::mem::take(&mut token),
                            line: position.0,
                            column: position.1,
                            followed_by_blank: b != b'\n' && b != b'\r',
                            columns: std::mem::take(&mut columns),
                            raw: std::mem::take(&mut raw),
                            quotes: std::mem::take(&mut quotes),
                        });
                        active = false;
                    }
                } else if b == b'\n' || b == b'\r' {
                    if quote {
                        raw.push(b);
                        token.push(char::from(b));
                        active = true;
                    }
                } else {
                    raw.push(b);
                    if b >= 128 {
                        write!(token, "\\{b:03}").expect("writing to a String");
                    } else {
                        token.push(char::from(b));
                    }
                    active = true;
                }
                columns.resize(token.len(), column);
                i += 1;
            }
            if parens.is_empty() && !quote {
                if active {
                    tokens.push(Token {
                        text: std::mem::take(&mut token),
                        line: position.0,
                        column: position.1,
                        followed_by_blank: false,
                        columns: std::mem::take(&mut columns),
                        raw: std::mem::take(&mut raw),
                        quotes: std::mem::take(&mut quotes),
                    });
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
        tokens: &[Token],
        inherited: bool,
        line: usize,
    ) -> Result<Option<ZoneRecord>, ZoneError> {
        let err_at = |index: usize, message: &str| {
            let (line, column) = tokens
                .get(index)
                .map_or(self.entry_end, |t| (t.line, t.column));
            self.error(line, column, message)
        };
        let err = |message: &str| err_at(0, message);
        let reject_quote = |token: &Token| {
            if let Some(&(_, line, column)) = token.quotes.first() {
                Err(self.error(line, column, "unexpected quote"))
            } else {
                Ok(())
            }
        };
        reject_quote(&tokens[0])?;
        if tokens[0].starts_with('$') {
            if tokens[0].eq_ignore_ascii_case("$ORIGIN") {
                if tokens.len() != 2 {
                    return Err(err_at(2, "invalid origin"));
                }
                reject_quote(&tokens[1])?;
                self.origin = Name::parse(&normalize_escapes(&tokens[1]), &self.origin)
                    .map_err(|e| err_at(1, &e.to_string()))?;
            } else if tokens[0].eq_ignore_ascii_case("$TTL") {
                if tokens.len() != 2 {
                    return Err(err_at(2, "invalid TTL"));
                }
                reject_quote(&tokens[1])?;
                self.ttl = Some(parse_ttl(&tokens[1]).ok_or_else(|| err_at(1, "invalid TTL"))?);
                self.directive_ttl = true;
            } else if tokens[0].eq_ignore_ascii_case("$INCLUDE") {
                if !self.include_allowed {
                    return Err(err("$INCLUDE not allowed"));
                }
                if self.depth >= 7 {
                    return Err(err("invalid $INCLUDE"));
                }
                if !(2..=3).contains(&tokens.len()) {
                    return Err(err_at(3, "invalid $INCLUDE"));
                }
                #[cfg(unix)]
                let path = {
                    use std::os::unix::ffi::OsStrExt;
                    Path::new(std::ffi::OsStr::from_bytes(&tokens[1].raw))
                };
                #[cfg(not(unix))]
                let path = Path::new(
                    std::str::from_utf8(&tokens[1].raw)
                        .map_err(|_| err_at(1, "invalid include path"))?,
                );
                let path = if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    self.file_path
                        .parent()
                        .unwrap_or_else(|| Path::new(""))
                        .join(path)
                };
                let file = File::open(&path).map_err(|e| err_at(1, &e.to_string()))?;
                let origin = if tokens.len() == 3 {
                    Name::parse(&normalize_escapes(&tokens[2]), &self.origin)
                        .map_err(|e| err_at(2, &e.to_string()))?
                } else {
                    self.origin.clone()
                };
                let mut child =
                    ZoneParser::new(BufReader::new(file), origin, path.to_string_lossy());
                child.file_path = path;
                child.ttl = self.ttl;
                child.directive_ttl = self.directive_ttl;
                child.depth = self.depth + 1;
                child.include_allowed = true;
                self.child = Some(Box::new(child));
            } else if tokens[0].eq_ignore_ascii_case("$GENERATE") {
                if tokens.len() < 4 {
                    return Err(err("invalid $GENERATE"));
                }
                let (range, step) = tokens[1].split_once('/').unwrap_or((&tokens[1].text, "1"));
                let (start, end) = range
                    .split_once('-')
                    .ok_or_else(|| err_at(1, "invalid generate range"))?;
                let start: i64 = start
                    .parse()
                    .map_err(|_| err_at(1, "invalid generate start"))?;
                let end: i64 = end.parse().map_err(|_| err_at(1, "invalid generate end"))?;
                let step: i64 = step
                    .parse()
                    .map_err(|_| err_at(1, "invalid generate step"))?;
                if start < 0 || end < start || step <= 0 || (end - start) / step > 65535 {
                    return Err(err_at(1, "invalid generate range"));
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
            Name::parse(&normalize_escapes(&tokens[0]), &self.origin)
                .map_err(|e| err(&e.to_string()))?
        };
        let mut ttl = self.ttl;
        let mut class = Class::IN;
        let mut saw_class = false;
        let mut saw_ttl = false;
        let rtype = loop {
            let field = tokens
                .get(i)
                .ok_or_else(|| err_at(i, "missing record type"))?;
            reject_quote(field)?;
            i += 1;
            if field.eq_ignore_ascii_case("ANY") {
                return Err(err_at(i - 1, "invalid record header"));
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
            return Err(err_at(i - 1, "invalid record header"));
        };
        // RFC 1035 §5.1: class and TTL may appear in either order before the type.
        let ttl = ttl
            .or_else(|| saw_class.then_some(0))
            .ok_or_else(|| err_at(i - 1, "missing TTL"))?;
        let empty = if i == tokens.len()
            && !tokens[i - 1].followed_by_blank
            && Type::from_mnemonic(&tokens[i - 1].to_ascii_uppercase()).is_some()
        {
            empty_rdata(rtype)
        } else {
            None
        };
        if empty.is_none()
            && rtype == Type::TSIG
            && tokens.get(i).is_none_or(|field| field.text != r"\#")
        {
            return Err(err_at(i - 1, "TSIG has no zone presentation format"));
        }
        // RFC 1035 §5.1: quotes delimit character-strings, not merely whitespace.
        let generic = tokens.get(i).is_some_and(|t| t.text == r"\#");
        let split_strings = !generic
            && matches!(
                rtype,
                Type::TXT
                    | Type::SPF
                    | Type::HINFO
                    | Type::ISDN
                    | Type::AVC
                    | Type::NINFO
                    | Type::RESINFO
                    | Type::UINFO
            );
        let mut normalized = Vec::new();
        let mut field_tokens = Vec::new();
        for (index, token) in tokens[i..].iter().enumerate() {
            let svc_param = !generic && (rtype == Type::SVCB || rtype == Type::HTTPS) && index >= 2;
            let quoted_string = !generic
                && ((rtype == Type::NAPTR && (2..5).contains(&index))
                    || ((rtype == Type::CAA || rtype == Type::URI) && index == 2));
            if !generic
                && rtype == Type::NAPTR
                && (2..5).contains(&index)
                && (token.quotes.len() != 2
                    || token.quotes[0].0 != 0
                    || token.quotes[1].0 != token.text.len())
            {
                return Err(err_at(i + index, "NAPTR field must be quoted"));
            }
            if !token.quotes.is_empty() && !split_strings && !svc_param && !quoted_string {
                let (_, line, column) = token.quotes[0];
                return Err(self.error(line, column, "unexpected quote in RDATA"));
            }
            let parts = text_parts(token);
            if quoted_string && parts.len() != 1 {
                let (_, line, column) = token.quotes[0];
                return Err(self.error(line, column, "unexpected quote in RDATA"));
            }
            if split_strings {
                for part in parts {
                    normalized.push(normalize_escapes(part));
                    field_tokens.push(i + index);
                }
            } else {
                normalized.push(if svc_param {
                    token.text.clone()
                } else {
                    normalize_escapes(&token.text)
                });
                field_tokens.push(i + index);
            }
        }
        let fields: Vec<&str> = normalized.iter().map(String::as_str).collect();
        if (rtype == Type::SVCB || rtype == Type::HTTPS)
            && let Some(index) = fields
                .iter()
                .skip(2)
                .position(|field| invalid_svc_escape(field))
        {
            return Err(err_at(i + 2 + index, "invalid SvcParam escape"));
        }
        let rdata = match empty {
            Some(data) => data,
            None => rdata::parse_rdata_located(rtype, &fields, &self.origin).map_err(
                |(index, message)| {
                    err_at(
                        field_tokens.get(index).copied().unwrap_or(tokens.len()),
                        &message,
                    )
                },
            )?,
        };
        // RFC 1035 §4.2.2: a wire Message cannot exceed 65,535 octets.
        if owner.as_wire().len() + 10 + rdata.len() > usize::from(u16::MAX) {
            return Err(err_at(i, "record exceeds DNS wire size"));
        }
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

fn text_parts(token: &Token) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut quote = false;
    for &(offset, _, _) in &token.quotes {
        if offset > start || quote {
            parts.push(&token.text[start..offset]);
        }
        start = offset;
        quote = !quote;
    }
    if start < token.text.len() || token.quotes.is_empty() {
        parts.push(&token.text[start..]);
    }
    parts
}

// RFC 1035 §5.1: decimal escapes denote octets; miekg truncates larger values.
fn normalize_escapes(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::with_capacity(value.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if let Some(digits) = bytes
                .get(i + 1..i + 4)
                .filter(|d| d.iter().all(u8::is_ascii_digit))
            {
                let number = (u16::from(digits[0] - b'0') * 100
                    + u16::from(digits[1] - b'0') * 10
                    + u16::from(digits[2] - b'0')) as u8;
                write!(output, "\\{number:03}").expect("writing to a String");
                i += 4;
            } else {
                if !bytes[i + 1].is_ascii_digit() {
                    output.push('\\');
                }
                output.push(char::from(bytes[i + 1]));
                i += 2;
            }
        } else {
            output.push(char::from(bytes[i]));
            i += 1;
        }
    }
    output
}

// RFC 9460 §2.1: SvcParam decimal escapes must encode a single octet.
fn invalid_svc_escape(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 1 < bytes.len() {
            if let Some(digits) = bytes
                .get(i + 1..i + 4)
                .filter(|d| d.iter().all(u8::is_ascii_digit))
            {
                let number = u16::from(digits[0] - b'0') * 100
                    + u16::from(digits[1] - b'0') * 10
                    + u16::from(digits[2] - b'0');
                if number > 255 {
                    return true;
                }
                i += 4;
            } else {
                i += 2;
            }
        } else {
            i += 1;
        }
    }
    false
}

// RFC 2136 §2.5: empty update records use type-specific zero-value wire fields.
fn empty_rdata(rtype: Type) -> Option<Vec<u8>> {
    let len = match rtype.0 {
        1..=5
        | 7..=10
        | 12
        | 14
        | 16
        | 17
        | 23
        | 28
        | 30..=32
        | 39
        | 41
        | 42
        | 47
        | 49
        | 56
        | 58
        | 61
        | 99
        | 128
        | 258
        | 261 => 0,
        19 | 100 => 1,
        13 | 15 | 18 | 20 | 21 | 26 | 36 | 44 | 64 | 65 | 105 | 107 | 257 | 260 => 2,
        27 | 45 | 52 | 53 => 3,
        25 | 43 | 48 | 55 | 57 | 59 | 60 | 101 | 102 | 256 | 32768 | 32769 => 4,
        37 | 51 => 5,
        33 | 50 | 62 | 63 | 108 => 6,
        35 => 7,
        109 => 8,
        104 | 106 => 10,
        29 | 249 | 250 => 16,
        24 | 46 => 18,
        6 => 20,
        _ => return None,
    };
    Some(vec![0; len])
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
                    .map(|s| {
                        (|| -> Result<Token, String> {
                            let mut text = String::new();
                            let mut quotes = Vec::new();
                            let mut start = 0;
                            for &(offset, line, column) in &s.quotes {
                                text.push_str(&expand_generate(
                                    &s.text[start..offset],
                                    generate.current,
                                    generate.end,
                                )?);
                                quotes.push((text.len(), line, column));
                                start = offset;
                            }
                            text.push_str(&expand_generate(
                                &s.text[start..],
                                generate.current,
                                generate.end,
                            )?);
                            let raw_input: String = s.raw.iter().copied().map(char::from).collect();
                            let raw = expand_generate(&raw_input, generate.current, generate.end)?
                                .chars()
                                .map(|ch| ch as u8)
                                .collect();
                            Ok(Token {
                                raw,
                                text,
                                line: s.line,
                                column: s.column,
                                followed_by_blank: s.followed_by_blank,
                                columns: s.columns.clone(),
                                quotes,
                            })
                        })()
                        .map_err(|e| {
                            let offset = s
                                .match_indices("${")
                                .find_map(|(index, _)| {
                                    let end =
                                        s[index..].find('}').map_or(s.len(), |n| index + n + 1);
                                    expand_generate(&s[index..end], generate.current, generate.end)
                                        .is_err()
                                        .then_some(index)
                                })
                                .unwrap_or(0);
                            let message = match e.as_str() {
                                "invalid base" => "bad base in $GENERATE",
                                "invalid offset" => "bad offset in $GENERATE",
                                "invalid width" => "bad width in $GENERATE",
                                "invalid modifier" => "bad modifier in $GENERATE",
                                _ => &e,
                            };
                            self.error(
                                s.line,
                                s.columns.get(offset).copied().unwrap_or(s.column),
                                message,
                            )
                        })
                    })
                    .collect::<Result<Vec<_>, _>>();
                let line = generate.line;
                std::mem::swap(&mut self.ttl, &mut generate.ttl);
                std::mem::swap(&mut self.directive_ttl, &mut generate.directive_ttl);
                std::mem::swap(&mut self.owner, &mut generate.owner);
                let origin = self.origin.clone();
                let result = expanded.and_then(|tokens| {
                    if tokens
                        .first()
                        .is_some_and(|t| t.eq_ignore_ascii_case("$GENERATE"))
                    {
                        return Err(self.error(line, 1, "nested $GENERATE"));
                    }
                    self.parse_entry(&tokens, false, line)
                });
                self.origin = origin;
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
    let mut result = 0_usize;
    let mut number = 0_usize;
    for byte in value.bytes() {
        if byte.is_ascii_digit() {
            number = number
                .wrapping_mul(10)
                .wrapping_add(usize::from(byte - b'0'));
        } else {
            let unit = match byte.to_ascii_lowercase() {
                b's' => 1,
                b'm' => 60,
                b'h' => 3600,
                b'd' => 86400,
                b'w' => 604800,
                _ => return None,
            };
            result = result.wrapping_add(number.wrapping_mul(unit));
            number = 0;
        }
    }
    if value.is_empty() {
        return None;
    }
    u32::try_from(result.wrapping_add(number)).ok()
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
