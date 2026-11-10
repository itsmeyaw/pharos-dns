use std::fmt;

use crate::{Class, NameError, NameRef, Opcode, Rcode, Type};

const HEADER_LEN: usize = 12;

/// An invalid DNS Message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MessageError {
    /// A field or record extends beyond the Message.
    Truncated,
    /// A domain name is invalid.
    Name(NameError),
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated DNS Message"),
            Self::Name(err) => write!(f, "invalid name: {err}"),
        }
    }
}
impl std::error::Error for MessageError {}
impl From<NameError> for MessageError {
    fn from(value: NameError) -> Self {
        Self::Name(value)
    }
}

fn read_u16(wire: &[u8], offset: usize) -> Result<u16, MessageError> {
    let bytes = wire
        .get(offset..offset + 2)
        .ok_or(MessageError::Truncated)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}
fn read_u32(wire: &[u8], offset: usize) -> Result<u32, MessageError> {
    let bytes = wire
        .get(offset..offset + 4)
        .ok_or(MessageError::Truncated)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

/// A validated, allocation-free view of a DNS Message.
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    wire: &'a [u8],
    starts: [usize; 4],
    counts: [u16; 4],
}

/// A Question in a Message.
#[derive(Clone, Copy, Debug)]
pub struct Question<'a> {
    pub name: NameRef<'a>,
    pub qtype: Type,
    pub qclass: Class,
}

/// A resource record in a Message.
#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub name: NameRef<'a>,
    pub rtype: Type,
    pub class: Class,
    pub ttl: u32,
    pub rdata: &'a [u8],
    pub rdata_offset: usize,
    pub ttl_offset: usize,
}

fn question(wire: &[u8], offset: usize) -> Result<(Question<'_>, usize), MessageError> {
    let name = NameRef::parse(wire, offset)?;
    let offset = offset + name.wire_len();
    let result = Question {
        name,
        qtype: Type(read_u16(wire, offset)?),
        qclass: Class(read_u16(wire, offset + 2)?),
    };
    Ok((result, offset + 4))
}
fn record(wire: &[u8], offset: usize) -> Result<(Record<'_>, usize), MessageError> {
    let name = NameRef::parse(wire, offset)?;
    let offset = offset + name.wire_len();
    let rtype = Type(read_u16(wire, offset)?);
    let class = Class(read_u16(wire, offset + 2)?);
    let ttl = read_u32(wire, offset + 4)?;
    let len = usize::from(read_u16(wire, offset + 8)?);
    let rdata_offset = offset + 10;
    let rdata = wire
        .get(rdata_offset..rdata_offset + len)
        .ok_or(MessageError::Truncated)?;
    Ok((
        Record {
            name,
            rtype,
            class,
            ttl,
            rdata,
            rdata_offset,
            ttl_offset: offset + 4,
        },
        rdata_offset + len,
    ))
}

impl<'a> Message<'a> {
    /// Validates all section boundaries and names before exposing the view.
    /// Bytes after the declared sections are ignored, as in CoreDNS.
    pub fn parse(wire: &'a [u8]) -> Result<Self, MessageError> {
        if wire.len() < HEADER_LEN {
            return Err(MessageError::Truncated);
        }
        let counts = [
            read_u16(wire, 4)?,
            read_u16(wire, 6)?,
            read_u16(wire, 8)?,
            read_u16(wire, 10)?,
        ];
        let mut starts = [0; 4];
        let mut offset = HEADER_LEN;
        for section in 0..4 {
            starts[section] = offset;
            for _ in 0..counts[section] {
                offset = if section == 0 {
                    question(wire, offset)?.1
                } else {
                    record(wire, offset)?.1
                };
            }
        }
        Ok(Self {
            wire,
            starts,
            counts,
        })
    }
    #[must_use]
    pub fn id(&self) -> u16 {
        u16::from_be_bytes([self.wire[0], self.wire[1]])
    }
    #[must_use]
    pub fn flags(&self) -> u16 {
        u16::from_be_bytes([self.wire[2], self.wire[3]])
    }
    #[must_use]
    pub fn qr(&self) -> bool {
        self.flags() & 0x8000 != 0
    }
    #[must_use]
    pub fn opcode(&self) -> Opcode {
        Opcode(((self.flags() >> 11) & 15) as u8)
    }
    #[must_use]
    pub fn aa(&self) -> bool {
        self.flags() & 0x0400 != 0
    }
    #[must_use]
    pub fn tc(&self) -> bool {
        self.flags() & 0x0200 != 0
    }
    #[must_use]
    pub fn rd(&self) -> bool {
        self.flags() & 0x0100 != 0
    }
    #[must_use]
    pub fn ra(&self) -> bool {
        self.flags() & 0x0080 != 0
    }
    #[must_use]
    pub fn z(&self) -> bool {
        self.flags() & 0x0040 != 0
    }
    #[must_use]
    pub fn ad(&self) -> bool {
        self.flags() & 0x0020 != 0
    }
    #[must_use]
    pub fn cd(&self) -> bool {
        self.flags() & 0x0010 != 0
    }
    #[must_use]
    pub fn rcode(&self) -> Rcode {
        Rcode(self.flags() & 15)
    }
    #[must_use]
    pub const fn question_count(&self) -> u16 {
        self.counts[0]
    }
    #[must_use]
    pub const fn answer_count(&self) -> u16 {
        self.counts[1]
    }
    #[must_use]
    pub const fn authority_count(&self) -> u16 {
        self.counts[2]
    }
    #[must_use]
    pub const fn additional_count(&self) -> u16 {
        self.counts[3]
    }
    #[must_use]
    pub fn questions(&self) -> Questions<'a> {
        Questions {
            wire: self.wire,
            offset: self.starts[0],
            remaining: self.counts[0],
        }
    }
    #[must_use]
    pub fn answers(&self) -> Records<'a> {
        self.records(1)
    }
    #[must_use]
    pub fn authorities(&self) -> Records<'a> {
        self.records(2)
    }
    #[must_use]
    pub fn additionals(&self) -> Records<'a> {
        self.records(3)
    }
    fn records(&self, section: usize) -> Records<'a> {
        Records {
            wire: self.wire,
            offset: self.starts[section],
            remaining: self.counts[section],
        }
    }
}

/// Questions of a validated Message.
pub struct Questions<'a> {
    wire: &'a [u8],
    offset: usize,
    remaining: u16,
}
impl<'a> Iterator for Questions<'a> {
    type Item = Question<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (item, next) = question(self.wire, self.offset).ok()?;
        self.remaining -= 1;
        self.offset = next;
        Some(item)
    }
}
/// Records of one validated Message section.
pub struct Records<'a> {
    wire: &'a [u8],
    offset: usize,
    remaining: u16,
}
impl<'a> Iterator for Records<'a> {
    type Item = Record<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 {
            return None;
        }
        let (item, next) = record(self.wire, self.offset).ok()?;
        self.remaining -= 1;
        self.offset = next;
        Some(item)
    }
}

/// An in-place editor for a validated DNS Message.
pub struct MessageMut<'a> {
    wire: &'a mut [u8],
    starts: [usize; 4],
    counts: [u16; 4],
}
impl<'a> MessageMut<'a> {
    /// Validates the Message before allowing any mutation.
    pub fn parse(wire: &'a mut [u8]) -> Result<Self, MessageError> {
        let parsed = Message::parse(wire)?;
        let starts = parsed.starts;
        let counts = parsed.counts;
        Ok(Self {
            wire,
            starts,
            counts,
        })
    }
    pub fn set_id(&mut self, id: u16) {
        self.wire[0..2].copy_from_slice(&id.to_be_bytes());
    }
    pub fn set_flags(&mut self, flags: u16) {
        self.wire[2..4].copy_from_slice(&flags.to_be_bytes());
    }
    /// Rewrites record TTLs, leaving OPT's non-TTL field intact.
    pub fn rewrite_ttls(&mut self, mut rewrite: impl FnMut(u32) -> u32) {
        for section in 1..4 {
            let mut offset = self.starts[section];
            for _ in 0..self.counts[section] {
                // The already-validated local encoding stays intact even if a
                // pointer happens to refer to a TTL changed earlier in the pass.
                loop {
                    let length = self.wire[offset];
                    offset += 1;
                    match length {
                        0 => break,
                        1..=63 => offset += usize::from(length),
                        _ => {
                            offset += 1;
                            break;
                        }
                    }
                }
                let is_opt = read_u16(self.wire, offset).expect("validated Message") == 41;
                let ttl_offset = offset + 4;
                let ttl = read_u32(self.wire, ttl_offset).expect("validated Message");
                let len = usize::from(read_u16(self.wire, offset + 8).expect("validated Message"));
                offset += 10 + len;
                if !is_opt {
                    self.wire[ttl_offset..ttl_offset + 4]
                        .copy_from_slice(&rewrite(ttl).to_be_bytes());
                }
            }
        }
    }
}
