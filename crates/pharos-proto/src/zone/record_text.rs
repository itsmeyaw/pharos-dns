use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

use crate::{Class, Name, Type};

use super::{parse_class, parse_ttl, parse_type};

const MAX_RDATA: usize = u16::MAX as usize;
const MAX_LABEL: usize = 63;
const MAX_NAME: usize = 255;

/// One record parsed into a caller-supplied buffer; `owner` and `rdata` borrow it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecordText<'b> {
    /// Uncompressed wire-format owner name.
    pub owner: &'b [u8],
    pub ttl: u32,
    pub class: Class,
    pub rtype: Type,
    /// Uncompressed wire-format RDATA.
    pub rdata: &'b [u8],
}

/// Why [`parse_record_text`] produced no record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordTextError {
    /// The text is malformed; `ZoneParser` rejects it too.
    Invalid,
    /// The text needs a feature this parser lacks, so it was not judged; use `ZoneParser`.
    Unsupported,
    /// The buffer cannot hold the owner and RDATA.
    BufferTooSmall,
}

impl fmt::Display for RecordTextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Invalid => "invalid record text",
            Self::Unsupported => "record text needs the Zone parser",
            Self::BufferTooSmall => "record buffer too small",
        })
    }
}

impl std::error::Error for RecordTextError {}

struct Out<'b> {
    buffer: &'b mut [u8],
    len: usize,
}

impl Out<'_> {
    fn put(&mut self, bytes: &[u8]) -> Result<(), RecordTextError> {
        let end = self.len + bytes.len();
        self.buffer
            .get_mut(self.len..end)
            .ok_or(RecordTextError::BufferTooSmall)?
            .copy_from_slice(bytes);
        self.len = end;
        Ok(())
    }

    // RFC 1035 §3.1: a domain name is a sequence of length-prefixed labels ending in the root label.
    fn name(&mut self, text: &str, origin: &Name) -> Result<(), RecordTextError> {
        // RFC 1035 §5.1: @ denotes the current origin.
        if text == "@" {
            return self.put(origin.as_wire());
        }
        if text == "." {
            return self.put(&[0]);
        }
        let start = self.len;
        let absolute = text.ends_with('.');
        let body = if absolute {
            &text[..text.len() - 1]
        } else {
            text
        };
        for label in body.split('.') {
            // RFC 1035 §2.3.4: labels are 1 to 63 octets.
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(RecordTextError::Invalid);
            }
            self.put(&[label.len() as u8])?;
            self.put(label.as_bytes())?;
        }
        // RFC 1035 §5.1: a name not ending in a dot is relative to the origin.
        self.put(if absolute { &[0] } else { origin.as_wire() })?;
        // RFC 1035 §2.3.4: names are limited to 255 octets.
        if self.len - start > MAX_NAME {
            return Err(RecordTextError::Invalid);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    quoted: bool,
}

struct Tokens<'a>(&'a str);

impl<'a> Tokens<'a> {
    // RFC 1035 §5.1: blanks separate items; a quoted item may contain blanks.
    fn next(&mut self) -> Result<Option<Token<'a>>, RecordTextError> {
        let rest = self.0.trim_start_matches([' ', '\t']);
        if rest.is_empty() {
            self.0 = rest;
            return Ok(None);
        }
        if let Some(quoted) = rest.strip_prefix('"') {
            let end = quoted.find('"').ok_or(RecordTextError::Unsupported)?;
            let after = &quoted[end + 1..];
            if !after.is_empty() && !after.starts_with([' ', '\t']) {
                return Err(RecordTextError::Unsupported);
            }
            self.0 = after;
            return Ok(Some(Token {
                text: &quoted[..end],
                quoted: true,
            }));
        }
        let end = rest.find([' ', '\t']).unwrap_or(rest.len());
        let text = &rest[..end];
        if text.contains('"') {
            return Err(RecordTextError::Unsupported);
        }
        self.0 = &rest[end..];
        Ok(Some(Token {
            text,
            quoted: false,
        }))
    }

    fn field(&mut self) -> Result<&'a str, RecordTextError> {
        let token = self.next()?.ok_or(RecordTextError::Invalid)?;
        if token.quoted {
            return Err(RecordTextError::Unsupported);
        }
        Ok(token.text)
    }

    fn finish(&mut self) -> Result<(), RecordTextError> {
        match self.next()? {
            None => Ok(()),
            Some(_) => Err(RecordTextError::Invalid),
        }
    }
}

// Accepts only printable ASCII, blanks and well-formed quotes; anything else needs the Zone parser.
fn lexically_simple(text: &str) -> Result<&str, RecordTextError> {
    let text = text.trim_end_matches([' ', '\t', '\r', '\n']);
    if text.is_empty() || text.starts_with([' ', '\t', '\r', '\n']) {
        return Err(RecordTextError::Unsupported);
    }
    let mut quote = false;
    for &byte in text.as_bytes() {
        let ok = match byte {
            b'"' => {
                quote = !quote;
                true
            }
            // RFC 1035 §5.1: inside quotes `;` and parentheses are literal.
            b';' | b'(' | b')' => quote,
            b'\\' => false,
            b' ' | b'\t' | 0x21..=0x7e => true,
            _ => false,
        };
        if !ok {
            return Err(RecordTextError::Unsupported);
        }
    }
    if quote {
        return Err(RecordTextError::Unsupported);
    }
    Ok(text)
}

fn decimal<T: FromStr>(value: &str) -> Result<T, RecordTextError> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(RecordTextError::Invalid);
    }
    value.parse().map_err(|_| RecordTextError::Invalid)
}

/// Parses one presentation-format record into `buffer` without allocating.
///
/// Relative names resolve against `origin`. `default_ttl` applies when the text has no TTL.
/// Accepts the same text as the first entry of [`ZoneParser`](super::ZoneParser) and yields the
/// same record, for A, AAAA, NS, CNAME, PTR, DNAME, MX, SOA, SRV, TXT and SPF written on one
/// line without escapes, parentheses, comments or directives. Anything else returns
/// [`RecordTextError::Unsupported`], so the caller can fall back to `ZoneParser`.
pub fn parse_record_text<'b>(
    text: &str,
    origin: &Name,
    default_ttl: Option<u32>,
    buffer: &'b mut [u8],
) -> Result<RecordText<'b>, RecordTextError> {
    let mut tokens = Tokens(lexically_simple(text)?);
    let mut out = Out { buffer, len: 0 };
    let owner = tokens.next()?.ok_or(RecordTextError::Unsupported)?;
    // RFC 1035 §5.1: `$` starts a control entry, not a record.
    if owner.quoted || owner.text.starts_with('$') {
        return Err(RecordTextError::Unsupported);
    }
    out.name(owner.text, origin)?;
    let owner_len = out.len;

    // RFC 1035 §5.1: class and TTL may appear in either order before the type.
    let mut ttl = default_ttl;
    let mut class = Class::IN;
    let (mut saw_class, mut saw_ttl) = (false, false);
    let rtype = loop {
        let field = tokens.field()?;
        if field.eq_ignore_ascii_case("ANY") {
            return Err(RecordTextError::Invalid);
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
        return Err(RecordTextError::Invalid);
    };
    let ttl = ttl
        .or_else(|| saw_class.then_some(0))
        .ok_or(RecordTextError::Invalid)?;
    // RFC 6895 §3.2: NONE, ANY, and reserved CLASS0 are not zone RR classes.
    if matches!(class, Class::NONE | Class::ANY | Class(0)) {
        return Err(RecordTextError::Invalid);
    }
    rdata(rtype, &mut tokens, &mut out, origin)?;
    let rdata_len = out.len - owner_len;
    // RFC 1035 §4.2.2: a wire Message cannot exceed 65,535 octets.
    if rdata_len > MAX_RDATA || owner_len + 10 + rdata_len > MAX_RDATA {
        return Err(RecordTextError::Invalid);
    }
    let (owner, rdata) = out.buffer[..out.len].split_at(owner_len);
    Ok(RecordText {
        owner,
        ttl,
        class,
        rtype,
        rdata,
    })
}

fn rdata(
    rtype: Type,
    tokens: &mut Tokens<'_>,
    out: &mut Out<'_>,
    origin: &Name,
) -> Result<(), RecordTextError> {
    match rtype {
        // RFC 1035 §3.4.1: an A RDATA is one IPv4 address.
        Type::A => {
            let address = tokens
                .field()?
                .parse::<Ipv4Addr>()
                .map_err(|_| RecordTextError::Invalid)?;
            out.put(&address.octets())?;
        }
        // RFC 3596 §2.2: an AAAA RDATA is one IPv6 address.
        Type::AAAA => {
            let address = tokens
                .field()?
                .parse::<Ipv6Addr>()
                .map_err(|_| RecordTextError::Invalid)?;
            out.put(&address.octets())?;
        }
        // RFC 1035 §3.3 and RFC 6672 §2.1: these RDATA hold one domain name.
        Type::NS | Type::CNAME | Type::PTR | Type::DNAME => out.name(tokens.field()?, origin)?,
        // RFC 1035 §3.3.9: MX has a 16-bit preference and an exchange name.
        Type::MX => {
            out.put(&decimal::<u16>(tokens.field()?)?.to_be_bytes())?;
            out.name(tokens.field()?, origin)?;
        }
        // RFC 1035 §3.3.13: SOA has two names and five 32-bit fields.
        Type::SOA => {
            out.name(tokens.field()?, origin)?;
            out.name(tokens.field()?, origin)?;
            out.put(&decimal::<u32>(tokens.field()?)?.to_be_bytes())?;
            for _ in 0..4 {
                // RFC 2308 §4: SOA timers accept TTL unit suffixes.
                let timer = parse_ttl(tokens.field()?).ok_or(RecordTextError::Invalid)?;
                out.put(&timer.to_be_bytes())?;
            }
        }
        // RFC 2782: SRV has priority, weight, port and target.
        Type::SRV => {
            for _ in 0..3 {
                out.put(&decimal::<u16>(tokens.field()?)?.to_be_bytes())?;
            }
            out.name(tokens.field()?, origin)?;
        }
        // RFC 1035 §3.3.14 and RFC 7208 §3.1: TXT and SPF hold character-strings of at most 255 octets.
        Type::TXT | Type::SPF => {
            let mut any = false;
            while let Some(token) = tokens.next()? {
                any = true;
                if token.text.is_empty() {
                    out.put(&[0])?;
                }
                for chunk in token.text.as_bytes().chunks(255) {
                    out.put(&[chunk.len() as u8])?;
                    out.put(chunk)?;
                }
            }
            return if any {
                Ok(())
            } else {
                Err(RecordTextError::Invalid)
            };
        }
        _ => return Err(RecordTextError::Unsupported),
    }
    tokens.finish()
}
