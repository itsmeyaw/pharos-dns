use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// A malformed EDNS option or an option that cannot fit in its wire length field.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdnsOptionError {
    Truncated,
    InvalidOption { code: u16 },
    OptionTooLong,
}

impl fmt::Display for EdnsOptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated EDNS option"),
            Self::InvalidOption { code } => write!(f, "invalid EDNS option {code}"),
            Self::OptionTooLong => f.write_str("EDNS option exceeds 65535 bytes"),
        }
    }
}

impl std::error::Error for EdnsOptionError {}

/// A validated, borrowed sequence of EDNS option TLVs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EdnsOptions<'a> {
    bytes: &'a [u8],
}

impl<'a> EdnsOptions<'a> {
    /// Validate option framing and supported structured payloads without allocating.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, EdnsOptionError> {
        let mut remaining = bytes;
        while !remaining.is_empty() {
            if remaining.len() < 4 {
                return Err(EdnsOptionError::Truncated);
            }
            let code = u16::from_be_bytes([remaining[0], remaining[1]]);
            let len = usize::from(u16::from_be_bytes([remaining[2], remaining[3]]));
            if remaining.len() - 4 < len {
                return Err(EdnsOptionError::Truncated);
            }
            parse_option(code, &remaining[4..4 + len])?;
            remaining = &remaining[4 + len..];
        }
        Ok(Self { bytes })
    }

    /// Return the original wire bytes.
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Iterate over validated options in wire order.
    pub fn iter(&self) -> EdnsOptionIter<'a> {
        EdnsOptionIter {
            remaining: self.bytes,
        }
    }
}

impl<'a> IntoIterator for EdnsOptions<'a> {
    type Item = EdnsOption<'a>;
    type IntoIter = EdnsOptionIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &EdnsOptions<'a> {
    type Item = EdnsOption<'a>;
    type IntoIter = EdnsOptionIter<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Iterator over a validated option sequence.
#[derive(Clone, Debug)]
pub struct EdnsOptionIter<'a> {
    remaining: &'a [u8],
}

impl<'a> Iterator for EdnsOptionIter<'a> {
    type Item = EdnsOption<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.is_empty() {
            return None;
        }
        let code = u16::from_be_bytes([self.remaining[0], self.remaining[1]]);
        let len = usize::from(u16::from_be_bytes([self.remaining[2], self.remaining[3]]));
        let data = &self.remaining[4..4 + len];
        self.remaining = &self.remaining[4 + len..];
        Some(parse_option(code, data).expect("validated EDNS option"))
    }
}

/// A client subnet, with its address masked to the source prefix.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClientSubnet {
    family: u16,
    source_prefix: u8,
    scope_prefix: u8,
    address: IpAddr,
}

impl ClientSubnet {
    /// Construct an IPv4 or IPv6 subnet, masking host bits.
    pub fn new(
        address: IpAddr,
        source_prefix: u8,
        scope_prefix: u8,
    ) -> Result<Self, EdnsOptionError> {
        let (family, bits) = if address.is_ipv4() { (1, 32) } else { (2, 128) };
        if source_prefix > bits || scope_prefix > bits {
            return Err(EdnsOptionError::InvalidOption { code: 8 });
        }
        let address = match address {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(
                u32::from(ip)
                    & (u32::MAX
                        .checked_shl(u32::from(32 - source_prefix))
                        .unwrap_or(0)),
            )),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
                u128::from(ip)
                    & (u128::MAX
                        .checked_shl(u32::from(128 - source_prefix))
                        .unwrap_or(0)),
            )),
        };
        Ok(Self {
            family,
            source_prefix,
            scope_prefix,
            address,
        })
    }

    pub fn family(&self) -> u16 {
        self.family
    }
    pub fn source_prefix(&self) -> u8 {
        self.source_prefix
    }
    pub fn scope_prefix(&self) -> u8 {
        self.scope_prefix
    }
    pub fn address(&self) -> IpAddr {
        self.address
    }
}

/// A typed option view. Byte slices borrow the original wire buffer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EdnsOption<'a> {
    Nsid(&'a [u8]),
    Cookie(&'a [u8]),
    ExtendedError {
        info_code: u16,
        extra_text: &'a [u8],
    },
    Padding(&'a [u8]),
    ClientSubnet(ClientSubnet),
    /// Timeout in 100 ms units; `None` means the timeout is omitted.
    TcpKeepalive(Option<u16>),
    Unknown {
        code: u16,
        data: &'a [u8],
    },
}

impl EdnsOption<'_> {
    pub fn code(&self) -> u16 {
        match self {
            Self::Nsid(_) => 3,
            Self::Cookie(_) => 10,
            Self::ExtendedError { .. } => 15,
            Self::Padding(_) => 12,
            Self::ClientSubnet(_) => 8,
            Self::TcpKeepalive(_) => 11,
            Self::Unknown { code, .. } => *code,
        }
    }

    /// Append the complete option TLV. Errors leave `output` unchanged.
    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), EdnsOptionError> {
        let mut fixed = [0u8; 20];
        let data: &[u8] = match self {
            Self::Nsid(data)
            | Self::Cookie(data)
            | Self::Padding(data)
            | Self::Unknown { data, .. } => data,
            Self::ExtendedError {
                info_code,
                extra_text,
            } => {
                let len = extra_text
                    .len()
                    .checked_add(2)
                    .ok_or(EdnsOptionError::OptionTooLong)?;
                let len = u16::try_from(len).map_err(|_| EdnsOptionError::OptionTooLong)?;
                output.extend_from_slice(&self.code().to_be_bytes());
                output.extend_from_slice(&len.to_be_bytes());
                output.extend_from_slice(&info_code.to_be_bytes());
                output.extend_from_slice(extra_text);
                return Ok(());
            }
            Self::TcpKeepalive(timeout) => {
                if let Some(timeout) = timeout {
                    fixed[..2].copy_from_slice(&timeout.to_be_bytes());
                    &fixed[..2]
                } else {
                    &fixed[..0]
                }
            }
            Self::ClientSubnet(subnet) => {
                fixed[..2].copy_from_slice(&subnet.family.to_be_bytes());
                fixed[2] = subnet.source_prefix;
                fixed[3] = subnet.scope_prefix;
                let len = usize::from(subnet.source_prefix).div_ceil(8);
                match subnet.address {
                    IpAddr::V4(ip) => fixed[4..4 + len].copy_from_slice(&ip.octets()[..len]),
                    IpAddr::V6(ip) => fixed[4..4 + len].copy_from_slice(&ip.octets()[..len]),
                }
                &fixed[..4 + len]
            }
        };
        let len = u16::try_from(data.len()).map_err(|_| EdnsOptionError::OptionTooLong)?;
        parse_option(self.code(), data)?;
        output.extend_from_slice(&self.code().to_be_bytes());
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(data);
        Ok(())
    }
}

fn parse_option(code: u16, data: &[u8]) -> Result<EdnsOption<'_>, EdnsOptionError> {
    let invalid = || EdnsOptionError::InvalidOption { code };
    Ok(match code {
        3 => EdnsOption::Nsid(data),
        10 => EdnsOption::Cookie(data),
        12 => EdnsOption::Padding(data),
        15 => {
            if data.len() < 2 {
                return Err(invalid());
            }
            EdnsOption::ExtendedError {
                info_code: u16::from_be_bytes([data[0], data[1]]),
                extra_text: &data[2..],
            }
        }
        11 => match data {
            [] => EdnsOption::TcpKeepalive(None),
            [hi, lo] => EdnsOption::TcpKeepalive(Some(u16::from_be_bytes([*hi, *lo]))),
            _ => return Err(invalid()),
        },
        8 => {
            if data.len() < 4 {
                return Err(invalid());
            }
            let family = u16::from_be_bytes([data[0], data[1]]);
            let source_prefix = data[2];
            let scope_prefix = data[3];
            let bits = match family {
                0 => 0,
                1 => 32,
                2 => 128,
                _ => return Err(invalid()),
            };
            if source_prefix > bits
                || (family != 0 && scope_prefix > bits)
                || data.len() != 4 + usize::from(source_prefix).div_ceil(8)
                || (!source_prefix.is_multiple_of(8)
                    && data[data.len() - 1] & (0xff >> (source_prefix % 8)) != 0)
            {
                return Err(invalid());
            }
            let mut address = [0u8; 16];
            address[..data.len() - 4].copy_from_slice(&data[4..]);
            let address = if family == 2 {
                IpAddr::V6(Ipv6Addr::from(address))
            } else {
                IpAddr::V4(Ipv4Addr::new(
                    address[0], address[1], address[2], address[3],
                ))
            };
            EdnsOption::ClientSubnet(ClientSubnet {
                family,
                source_prefix,
                scope_prefix,
                address,
            })
        }
        _ => EdnsOption::Unknown { code, data },
    })
}

impl fmt::Display for EdnsOption<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nsid(data) | Self::Cookie(data) => hex(f, data, false),
            Self::Padding(data) => hex(f, data, true),
            Self::Unknown { code, data } => {
                write!(f, "{code}:0x")?;
                hex(f, data, false)
            }
            Self::ClientSubnet(subnet) => {
                match subnet.address {
                    IpAddr::V4(ip) => write!(f, "{ip}")?,
                    IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
                        Some(ip) => write!(f, "{ip}")?,
                        None => write!(f, "[{ip}]")?,
                    },
                }
                write!(f, "/{}/{}", subnet.source_prefix, subnet.scope_prefix)
            }
            Self::TcpKeepalive(None | Some(0)) => {
                f.write_str("use tcp keep-alive, timeout omitted")
            }
            Self::TcpKeepalive(Some(timeout)) => write!(
                f,
                "use tcp keep-alive, timeout {}ms",
                u32::from(*timeout) * 100
            ),
            Self::ExtendedError {
                info_code,
                extra_text,
            } => {
                write!(f, "{info_code}")?;
                if let Some(description) = EDE_DESCRIPTIONS.get(usize::from(*info_code)) {
                    write!(f, " ({description})")?;
                }
                write!(f, ": ({})", String::from_utf8_lossy(extra_text))
            }
        }
    }
}

fn hex(f: &mut fmt::Formatter<'_>, data: &[u8], upper: bool) -> fmt::Result {
    for byte in data {
        if upper {
            write!(f, "{byte:02X}")?;
        } else {
            write!(f, "{byte:02x}")?;
        }
    }
    Ok(())
}

const EDE_DESCRIPTIONS: [&str; 31] = [
    "Other",
    "Unsupported DNSKEY Algorithm",
    "Unsupported DS Digest Type",
    "Stale Answer",
    "Forged Answer",
    "DNSSEC Indeterminate",
    "DNSSEC Bogus",
    "Signature Expired",
    "Signature Not Yet Valid",
    "DNSKEY Missing",
    "RRSIGs Missing",
    "No Zone Key Bit Set",
    "NSEC Missing",
    "Cached Error",
    "Not Ready",
    "Blocked",
    "Censored",
    "Filtered",
    "Prohibited",
    "Stale NXDOMAIN Answer",
    "Not Authoritative",
    "Not Supported",
    "No Reachable Authority",
    "Network Error",
    "Invalid Data",
    "Signature Expired Before Valid",
    "Too Early",
    "Unsupported NSEC3 Iterations Value",
    "Unable To Conform To Policy",
    "Synthesized",
    "Invalid Query Type",
];
