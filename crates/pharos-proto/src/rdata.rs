use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{BuildError, NameRef, RdataWriter, Type};

// shortcut: reject unsupported name-bearing types until their names can be relocated.
fn unsupported_name_type(rtype: Type) -> bool {
    matches!(
        rtype,
        Type::MD
            | Type::MF
            | Type::MB
            | Type::MG
            | Type::MR
            | Type::MINFO
            | Type::RP
            | Type::AFSDB
            | Type::RT
            | Type::NSAP_PTR
            | Type::SIG
            | Type::PX
            | Type::NXT
            | Type::KX
            | Type::DNAME
            | Type::IPSECKEY
            | Type::RRSIG
            | Type::NSEC
            | Type::HIP
            | Type::TALINK
            | Type::SVCB
            | Type::HTTPS
            | Type::LP
            | Type::TKEY
            | Type::TSIG
            | Type::AMTRELAY
    )
}

/// Malformed or unsupported typed record data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RdataError;

fn character_string(bytes: &[u8]) -> Result<(&[u8], &[u8]), RdataError> {
    let (&len, rest) = bytes.split_first().ok_or(RdataError)?;
    let len = usize::from(len);
    if len > rest.len() {
        return Err(RdataError);
    }
    Ok(rest.split_at(len))
}

fn valid_txt(mut bytes: &[u8]) -> Result<(), RdataError> {
    if bytes.is_empty() {
        return Err(RdataError);
    }
    while !bytes.is_empty() {
        bytes = character_string(bytes)?.1;
    }
    Ok(())
}

fn display_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for &byte in bytes {
        match byte {
            b'"' | b'\\' => write!(f, "\\{}", char::from(byte))?,
            32..=126 => write!(f, "{}", char::from(byte))?,
            _ => write!(f, "\\{byte:03}")?,
        }
    }
    Ok(())
}

fn write_character_string(
    writer: &mut RdataWriter<'_, '_>,
    bytes: &[u8],
) -> Result<(), BuildError> {
    let len = u8::try_from(bytes.len()).map_err(|_| BuildError::InvalidRdata)?;
    writer.write_bytes(&[len])?;
    writer.write_bytes(bytes)
}

fn display_quoted(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("\"")?;
    display_bytes(f, bytes)?;
    f.write_str("\"")
}

fn display_octets(f: &mut fmt::Formatter<'_>, mut bytes: &[u8]) -> fmt::Result {
    f.write_str("\"")?;
    while let Some((&byte, rest)) = bytes.split_first() {
        bytes = rest;
        if byte != b'\\' {
            display_bytes(f, &[byte])?;
        } else if let Some((&next, rest)) = bytes.split_first() {
            if next == b'.' {
                f.write_str("\\.")?;
                bytes = rest;
            } else if bytes.len() >= 3 && bytes[..3].iter().all(u8::is_ascii_digit) {
                let value = u16::from(bytes[0] - b'0') * 100
                    + u16::from(bytes[1] - b'0') * 10
                    + u16::from(bytes[2] - b'0');
                display_bytes(f, &[value as u8])?;
                bytes = &bytes[3..];
            } else {
                display_bytes(f, &[next])?;
                bytes = rest;
            }
        }
    }
    f.write_str("\"")
}

impl fmt::Display for RdataError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid or unsupported RDATA")
    }
}

impl std::error::Error for RdataError {}

/// A borrowed view of resource record data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Rdata<'a> {
    A(Ipv4Addr),
    Aaaa(Ipv6Addr),
    Ns(NameRef<'a>),
    Cname(NameRef<'a>),
    Ptr(NameRef<'a>),
    Mx {
        preference: u16,
        exchange: NameRef<'a>,
    },
    Soa {
        mname: NameRef<'a>,
        rname: NameRef<'a>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    /// Length-prefixed character strings, including their wire length octets.
    Txt(&'a [u8]),
    Hinfo {
        cpu: &'a [u8],
        os: &'a [u8],
    },
    Caa {
        flags: u8,
        tag: &'a [u8],
        value: &'a [u8],
    },
    Uri {
        priority: u16,
        weight: u16,
        target: &'a [u8],
    },
    Srv {
        priority: u16,
        weight: u16,
        port: u16,
        target: NameRef<'a>,
    },
    Naptr {
        order: u16,
        preference: u16,
        flags: &'a [u8],
        services: &'a [u8],
        regexp: &'a [u8],
        replacement: NameRef<'a>,
    },
    /// Opaque data in RFC 3597 format. Re-encoding preserves the original bytes,
    /// so it is only safe to relocate data that contains no compression pointers.
    Unknown(Type, &'a [u8]),
}

impl<'a> Rdata<'a> {
    /// Parses standalone data. Embedded compression pointers refer to `bytes`.
    pub fn parse(rtype: Type, bytes: &'a [u8]) -> Result<Self, RdataError> {
        Self::parse_in_message(rtype, bytes, 0, bytes.len())
    }

    /// Iterates over TXT character strings without copying. Returns `None` for
    /// other types; manually constructed malformed TXT data stops at the error.
    pub fn txt_strings(&self) -> Option<impl Iterator<Item = &'a [u8]>> {
        let Self::Txt(mut bytes) = *self else {
            return None;
        };
        Some(std::iter::from_fn(move || {
            let (text, rest) = character_string(bytes).ok()?;
            bytes = rest;
            Some(text)
        }))
    }

    pub(crate) fn parse_in_message(
        rtype: Type,
        wire: &'a [u8],
        offset: usize,
        len: usize,
    ) -> Result<Self, RdataError> {
        let bytes = wire
            .get(offset..offset.checked_add(len).ok_or(RdataError)?)
            .ok_or(RdataError)?;
        match rtype {
            Type::A => Ok(Self::A(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| RdataError)?,
            ))),
            Type::AAAA => Ok(Self::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| RdataError)?,
            ))),
            Type::NS | Type::CNAME | Type::PTR => {
                let name = NameRef::parse(wire, offset).map_err(|_| RdataError)?;
                if name.wire_len() != len {
                    return Err(RdataError);
                }
                Ok(match rtype {
                    Type::NS => Self::Ns(name),
                    Type::CNAME => Self::Cname(name),
                    _ => Self::Ptr(name),
                })
            }
            Type::MX => {
                let preference = u16::from_be_bytes(
                    bytes
                        .get(..2)
                        .ok_or(RdataError)?
                        .try_into()
                        .map_err(|_| RdataError)?,
                );
                let name_offset = offset + 2;
                let exchange = NameRef::parse(wire, name_offset).map_err(|_| RdataError)?;
                if 2 + exchange.wire_len() != len {
                    return Err(RdataError);
                }
                Ok(Self::Mx {
                    preference,
                    exchange,
                })
            }
            Type::SOA => {
                let mname = NameRef::parse(wire, offset).map_err(|_| RdataError)?;
                if mname.wire_len() >= len {
                    return Err(RdataError);
                }
                let rname =
                    NameRef::parse(wire, offset + mname.wire_len()).map_err(|_| RdataError)?;
                let numbers = bytes
                    .get(mname.wire_len() + rname.wire_len()..)
                    .ok_or(RdataError)?;
                if numbers.len() != 20 {
                    return Err(RdataError);
                }
                let number = |index| {
                    u32::from_be_bytes(
                        numbers[index..index + 4]
                            .try_into()
                            .expect("validated length"),
                    )
                };
                Ok(Self::Soa {
                    mname,
                    rname,
                    serial: number(0),
                    refresh: number(4),
                    retry: number(8),
                    expire: number(12),
                    minimum: number(16),
                })
            }
            Type::TXT => {
                valid_txt(bytes)?;
                Ok(Self::Txt(bytes))
            }
            Type::HINFO => {
                let (cpu, rest) = character_string(bytes)?;
                let (os, rest) = character_string(rest)?;
                if !rest.is_empty() {
                    return Err(RdataError);
                }
                Ok(Self::Hinfo { cpu, os })
            }
            Type::CAA => {
                let (&flags, rest) = bytes.split_first().ok_or(RdataError)?;
                let (tag, value) = character_string(rest)?;
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(RdataError);
                }
                Ok(Self::Caa { flags, tag, value })
            }
            Type::URI => {
                let header = bytes.get(..4).ok_or(RdataError)?;
                Ok(Self::Uri {
                    priority: u16::from_be_bytes([header[0], header[1]]),
                    weight: u16::from_be_bytes([header[2], header[3]]),
                    target: &bytes[4..],
                })
            }
            Type::SRV => {
                let header = bytes.get(..6).ok_or(RdataError)?;
                let target = NameRef::parse(wire, offset + 6).map_err(|_| RdataError)?;
                if 6 + target.wire_len() != len {
                    return Err(RdataError);
                }
                Ok(Self::Srv {
                    priority: u16::from_be_bytes([header[0], header[1]]),
                    weight: u16::from_be_bytes([header[2], header[3]]),
                    port: u16::from_be_bytes([header[4], header[5]]),
                    target,
                })
            }
            Type::NAPTR => {
                let header = bytes.get(..4).ok_or(RdataError)?;
                let (flags, rest) = character_string(&bytes[4..])?;
                let (services, rest) = character_string(rest)?;
                let (regexp, rest) = character_string(rest)?;
                let name_start = len - rest.len();
                let replacement =
                    NameRef::parse(wire, offset + name_start).map_err(|_| RdataError)?;
                if replacement.wire_len() != rest.len() {
                    return Err(RdataError);
                }
                Ok(Self::Naptr {
                    order: u16::from_be_bytes([header[0], header[1]]),
                    preference: u16::from_be_bytes([header[2], header[3]]),
                    flags,
                    services,
                    regexp,
                    replacement,
                })
            }
            _ if unsupported_name_type(rtype) => Err(RdataError),
            // shortcut: other record types stay opaque, add typed formats before zone parsing.
            _ => Ok(Self::Unknown(rtype, bytes)),
        }
    }

    /// Returns the type associated with this data.
    #[must_use]
    pub fn rtype(&self) -> Type {
        match self {
            Self::A(_) => Type::A,
            Self::Aaaa(_) => Type::AAAA,
            Self::Ns(_) => Type::NS,
            Self::Cname(_) => Type::CNAME,
            Self::Ptr(_) => Type::PTR,
            Self::Mx { .. } => Type::MX,
            Self::Soa { .. } => Type::SOA,
            Self::Txt(_) => Type::TXT,
            Self::Hinfo { .. } => Type::HINFO,
            Self::Caa { .. } => Type::CAA,
            Self::Uri { .. } => Type::URI,
            Self::Srv { .. } => Type::SRV,
            Self::Naptr { .. } => Type::NAPTR,
            Self::Unknown(rtype, _) => *rtype,
        }
    }

    /// Writes this data with a Message builder's RDATA hook.
    pub fn write(&self, writer: &mut RdataWriter<'_, '_>) -> Result<(), BuildError> {
        match self {
            Self::A(addr) => writer.write_bytes(&addr.octets()),
            Self::Aaaa(addr) => writer.write_bytes(&addr.octets()),
            Self::Ns(name) | Self::Cname(name) | Self::Ptr(name) => writer.write_name(*name),
            Self::Mx {
                preference,
                exchange,
            } => {
                writer.write_bytes(&preference.to_be_bytes())?;
                writer.write_name(*exchange)
            }
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => {
                writer.write_name(*mname)?;
                writer.write_name(*rname)?;
                for value in [serial, refresh, retry, expire, minimum] {
                    writer.write_bytes(&value.to_be_bytes())?;
                }
                Ok(())
            }
            Self::Txt(bytes) => {
                valid_txt(bytes).map_err(|_| BuildError::InvalidRdata)?;
                writer.write_bytes(bytes)
            }
            Self::Hinfo { cpu, os } => {
                write_character_string(writer, cpu)?;
                write_character_string(writer, os)
            }
            Self::Caa { flags, tag, value } => {
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&[*flags])?;
                write_character_string(writer, tag)?;
                writer.write_bytes(value)
            }
            Self::Uri {
                priority,
                weight,
                target,
            } => {
                writer.write_bytes(&priority.to_be_bytes())?;
                writer.write_bytes(&weight.to_be_bytes())?;
                writer.write_bytes(target)
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                writer.write_bytes(&priority.to_be_bytes())?;
                writer.write_bytes(&weight.to_be_bytes())?;
                writer.write_bytes(&port.to_be_bytes())?;
                writer.write_uncompressed_name(*target)
            }
            Self::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                writer.write_bytes(&order.to_be_bytes())?;
                writer.write_bytes(&preference.to_be_bytes())?;
                write_character_string(writer, flags)?;
                write_character_string(writer, services)?;
                write_character_string(writer, regexp)?;
                writer.write_uncompressed_name(*replacement)
            }
            Self::Unknown(rtype, _)
                if unsupported_name_type(*rtype)
                    || matches!(
                        *rtype,
                        Type::A
                            | Type::AAAA
                            | Type::NS
                            | Type::CNAME
                            | Type::PTR
                            | Type::MX
                            | Type::SOA
                            | Type::TXT
                            | Type::HINFO
                            | Type::CAA
                            | Type::URI
                            | Type::SRV
                            | Type::NAPTR
                    ) =>
            {
                Err(BuildError::InvalidRdata)
            }
            Self::Unknown(_, bytes) => writer.write_bytes(bytes),
        }
    }
}

// shortcut: presentation parsing is deferred until zone-file parsing is implemented.
impl fmt::Display for Rdata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            Self::Aaaa(addr) => write!(f, "{addr}"),
            Self::Ns(name) | Self::Cname(name) | Self::Ptr(name) => write!(f, "{name}"),
            Self::Mx {
                preference,
                exchange,
            } => write!(f, "{preference} {exchange}"),
            Self::Soa {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => write!(
                f,
                "{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"
            ),
            &Self::Txt(mut bytes) => {
                if valid_txt(bytes).is_err() {
                    return write!(f, "{}", Self::Unknown(Type::TXT, bytes));
                }
                let mut first = true;
                while !bytes.is_empty() {
                    let (text, rest) = character_string(bytes).map_err(|_| fmt::Error)?;
                    if !first {
                        f.write_str(" ")?;
                    }
                    display_quoted(f, text)?;
                    bytes = rest;
                    first = false;
                }
                Ok(())
            }
            Self::Hinfo { cpu, os } => {
                display_quoted(f, cpu)?;
                f.write_str(" ")?;
                display_quoted(f, os)
            }
            Self::Caa { flags, tag, value } => {
                write!(f, "{flags} ")?;
                display_bytes(f, tag)?;
                f.write_str(" ")?;
                display_octets(f, value)
            }
            Self::Uri {
                priority,
                weight,
                target,
            } => {
                write!(f, "{priority} {weight} ")?;
                display_octets(f, target)
            }
            Self::Srv {
                priority,
                weight,
                port,
                target,
            } => {
                write!(f, "{priority} {weight} {port} {target}")
            }
            Self::Naptr {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => {
                write!(f, "{order} {preference} ")?;
                display_quoted(f, flags)?;
                f.write_str(" ")?;
                display_quoted(f, services)?;
                f.write_str(" ")?;
                display_quoted(f, regexp)?;
                write!(f, " {replacement}")
            }
            Self::Unknown(_, bytes) => {
                write!(f, "\\# {} ", bytes.len())?;
                for byte in *bytes {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}
