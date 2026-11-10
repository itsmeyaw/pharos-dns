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
            | Type::SRV
            | Type::NAPTR
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
    /// Opaque data in RFC 3597 format. Re-encoding preserves the original bytes,
    /// so it is only safe to relocate data that contains no compression pointers.
    Unknown(Type, &'a [u8]),
}

impl<'a> Rdata<'a> {
    /// Parses standalone data. Embedded compression pointers refer to `bytes`.
    pub fn parse(rtype: Type, bytes: &'a [u8]) -> Result<Self, RdataError> {
        Self::parse_in_message(rtype, bytes, 0, bytes.len())
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
