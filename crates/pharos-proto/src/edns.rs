use std::fmt;

use crate::{BuildError, EdnsOption, EdnsOptions, Rcode, Record};

/// A borrowed EDNS OPT record. The options have already been validated.
#[derive(Clone, Copy, Debug)]
pub struct Opt<'a> {
    size: u16,
    ttl: u32,
    options: EdnsOptions<'a>,
}

impl<'a> Opt<'a> {
    /// The fresh OPT CoreDNS uses for a BADVERS Response.
    #[must_use]
    pub fn badvers() -> Opt<'static> {
        Opt::new(0, 1, 0, 0, EdnsOptions::parse(&[]).expect("empty options"))
    }

    /// Creates an OPT from its wire fields and validated option data.
    #[must_use]
    pub const fn new(
        size: u16,
        extended_rcode: u8,
        version: u8,
        flags: u16,
        options: EdnsOptions<'a>,
    ) -> Self {
        Self {
            size,
            ttl: ((extended_rcode as u32) << 24) | ((version as u32) << 16) | flags as u32,
            options,
        }
    }

    pub(crate) fn from_record(record: Record<'a>) -> Self {
        Self {
            size: record.class.0,
            ttl: record.ttl,
            options: EdnsOptions::parse(record.rdata).expect("validated OPT"),
        }
    }

    #[must_use]
    pub const fn udp_payload_size(self) -> u16 {
        self.size
    }
    #[must_use]
    pub const fn extended_rcode(self) -> u8 {
        (self.ttl >> 24) as u8
    }
    #[must_use]
    pub const fn version(self) -> u8 {
        (self.ttl >> 16) as u8
    }
    #[must_use]
    pub const fn flags(self) -> u16 {
        self.ttl as u16
    }
    #[must_use]
    pub const fn dnssec_ok(self) -> bool {
        self.flags() & 0x8000 != 0
    }
    #[must_use]
    pub const fn options(self) -> EdnsOptions<'a> {
        self.options
    }
    /// Whether CoreDNS returns BADVERS before invoking the Plugin Chain.
    #[must_use]
    pub const fn bad_version(self) -> bool {
        self.version() != 0
    }

    /// Encodes an OPT record into the caller's buffer.
    pub fn encode(self, output: &mut Vec<u8>) -> Result<(), BuildError> {
        let len =
            u16::try_from(self.options.as_bytes().len()).map_err(|_| BuildError::RdataTooLong)?;
        output.extend_from_slice(&[0, 0, 41]);
        output.extend_from_slice(&self.size.to_be_bytes());
        output.extend_from_slice(&self.ttl.to_be_bytes());
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(self.options.as_bytes());
        Ok(())
    }

    /// Applies CoreDNS SizeAndDo to an optional existing Response OPT.
    /// Only registered option codes are copied when the Response had no OPT.
    #[must_use]
    pub fn response<'b>(
        self,
        existing: Option<Opt<'a>>,
        supported: &'b [u16],
        rcode: Rcode,
    ) -> ResponseOpt<'a, 'b> {
        let mut source = existing.unwrap_or(self);
        source.size = self.size;
        source.ttl = (u32::from((rcode.0 >> 4) as u8) << 24)
            | (source.ttl & 0xff00)
            | if self.dnssec_ok() { 0x8000 } else { 0 };
        ResponseOpt {
            source,
            supported,
            copy_all: existing.is_some(),
        }
    }
}

/// OPT to append to a Response, filtering Query options without allocating.
#[derive(Clone, Copy, Debug)]
pub struct ResponseOpt<'a, 'b> {
    source: Opt<'a>,
    supported: &'b [u16],
    copy_all: bool,
}

impl ResponseOpt<'_, '_> {
    fn selected(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest = self.source.options.as_bytes();
        std::iter::from_fn(move || {
            while !rest.is_empty() {
                let code = u16::from_be_bytes([rest[0], rest[1]]);
                let len = usize::from(u16::from_be_bytes([rest[2], rest[3]])) + 4;
                let (option, tail) = rest.split_at(len);
                rest = tail;
                if self.copy_all || self.supported.contains(&code) {
                    return Some(option);
                }
            }
            None
        })
    }
    /// Number of wire octets needed for this OPT.
    #[must_use]
    pub fn wire_len(&self) -> usize {
        11 + self.selected().map(<[u8]>::len).sum::<usize>()
    }

    pub(crate) fn encode(&self, output: &mut Vec<u8>) -> Result<(), BuildError> {
        let len = u16::try_from(self.wire_len() - 11).map_err(|_| BuildError::RdataTooLong)?;
        output.extend_from_slice(&[0, 0, 41]);
        output.extend_from_slice(&self.source.size.to_be_bytes());
        output.extend_from_slice(&self.source.ttl.to_be_bytes());
        output.extend_from_slice(&len.to_be_bytes());
        for option in self.selected() {
            output.extend_from_slice(option);
        }
        Ok(())
    }
}

impl fmt::Display for Opt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "\n;; OPT PSEUDOSECTION:\n; EDNS: version {}; flags:",
            self.version()
        )?;
        if self.dnssec_ok() {
            f.write_str(" do")?;
        }
        if self.flags() & 0x4000 != 0 {
            f.write_str(" co")?;
        }
        f.write_str("; ")?;
        if self.flags() & 0x3fff != 0 {
            write!(f, "MBZ: 0x{:04x}, ", self.flags() & 0x3fff)?;
        }
        write!(f, "udp: {}", self.size)?;
        for option in self.options.iter() {
            let label = match option {
                EdnsOption::Nsid(_) => "NSID",
                EdnsOption::Cookie(_) => "COOKIE",
                EdnsOption::ExtendedError { .. } => "EDE",
                EdnsOption::Padding(_) => "PADDING",
                EdnsOption::ClientSubnet(_) => "SUBNET",
                EdnsOption::TcpKeepalive(_) => "KEEPALIVE",
                EdnsOption::Unknown { .. } => "LOCAL OPT",
            };
            write!(f, "\n; {label}: {option}")?;
            if let EdnsOption::Nsid(bytes) = option {
                f.write_str("  ")?;
                for byte in bytes {
                    write!(f, "({})", char::from(*byte))?;
                }
            }
        }
        Ok(())
    }
}

/// CoreDNS's advertised UDP size normalization; TCP always permits 65535 bytes.
#[must_use]
pub const fn normalized_udp_size(size: u16, tcp: bool) -> u16 {
    if tcp {
        u16::MAX
    } else if size < 512 {
        512
    } else {
        size
    }
}
