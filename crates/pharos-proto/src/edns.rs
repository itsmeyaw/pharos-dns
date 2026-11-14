use std::{
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{BuildError, EdnsOption, EdnsOptions, Message, MessageBuilder, Opcode, Rcode, Record};

static REGISTERED_OPTIONS: [AtomicU64; 1024] = [const { AtomicU64::new(0) }; 1024];

/// Register an EDNS option for copying from Queries to Responses across Server Blocks.
pub fn register_edns_option(code: u16) {
    let code = usize::from(code);
    REGISTERED_OPTIONS[code / 64].fetch_or(1_u64 << (code % 64), Ordering::Release);
}

/// Whether an EDNS option has been registered by a configured Plugin.
#[must_use]
pub fn edns_option_registered(code: u16) -> bool {
    let code = usize::from(code);
    REGISTERED_OPTIONS[code / 64].load(Ordering::Acquire) & (1_u64 << (code % 64)) != 0
}

impl Message<'_> {
    /// Builds CoreDNS's BADVERS Response for a Query with a nonzero EDNS version.
    /// A Query without OPT or with version zero leaves `wire` unchanged.
    pub fn badvers_response<'a>(
        &self,
        wire: &'a mut Vec<u8>,
    ) -> Result<Option<&'a mut Vec<u8>>, BuildError> {
        // RFC 6891 §6.1.3: unsupported EDNS versions require a BADVERS response.
        if !self.opt().is_some_and(Opt::bad_version) {
            return Ok(None);
        }
        let flags = 0x8000
            | (self.flags() & 0x7800)
            | if self.opcode() == Opcode::QUERY {
                self.flags() & 0x0110
            } else {
                0
            };
        let mut builder = MessageBuilder::new(wire, usize::from(u16::MAX), self.id(), flags)?;
        let opt = Opt::badvers();
        let response = opt.response(None, &[], Rcode::BADVERS);
        builder.reserve_response_opt(&response)?;
        if let Some(question) = self.questions().next()
            && !builder.question(question.name, question.qtype, question.qclass)?
        {
            return Err(BuildError::SizeLimit);
        }
        builder.finish_with_response_opt(&response).map(Some)
    }
}

/// A borrowed EDNS OPT record. The options have already been validated.
#[derive(Clone, Copy, Debug)]
pub struct Opt<'a> {
    size: u16,
    ttl: u32,
    options: EdnsOptions<'a>,
}

impl<'a> Opt<'a> {
    /// The fresh OPT CoreDNS uses for a BADVERS Response, including its zero UDP size.
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
        // RFC 6891 §6.1.3: OPT's TTL field carries extended RCODE, version, and flags.
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
    /// The 14 reserved EDNS flag bits, excluding DO and CO.
    #[must_use]
    pub const fn z(self) -> u16 {
        self.flags() & 0x3fff
    }
    // RFC 6891 §6.1.4: DO is the top bit of the 16-bit OPT flags.
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
        // RFC 6891 §6.1.2: OPT uses root NAME, TYPE 41, payload size, TTL fields, and options.
        output.extend_from_slice(&[0, 0, 41]);
        output.extend_from_slice(&self.size.to_be_bytes());
        output.extend_from_slice(&self.ttl.to_be_bytes());
        output.extend_from_slice(&len.to_be_bytes());
        output.extend_from_slice(self.options.as_bytes());
        Ok(())
    }

    // RFC 6891 §6.1.3: responses use the highest EDNS version implemented by the responder.
    /// Applies CoreDNS SizeAndDo to an optional existing Response OPT.
    /// Only registered option codes are copied when the Response had no OPT.
    /// The Response version is reset to zero, even for an existing OPT.
    #[must_use]
    pub fn response<'b>(
        self,
        existing: Option<Opt<'a>>,
        supported: &'b [u16],
        rcode: Rcode,
    ) -> ResponseOpt<'a, 'b> {
        let mut source = existing.unwrap_or(self);
        source.size = self.size;
        // RFC 6891 §6.1.3: responses carry version 0, the highest EDNS version implemented here.
        source.ttl = (u32::from((rcode.0 >> 4) as u8) << 24)
            | (source.ttl & 0xff00)
            | if self.dnssec_ok() { 0x8000 } else { 0 };
        ResponseOpt {
            source,
            supported,
            copy_all: existing.is_some(),
            registered: false,
        }
    }

    /// Apply SizeAndDo using process-wide registered option codes.
    #[must_use]
    pub fn response_registered(
        self,
        existing: Option<Opt<'a>>,
        rcode: Rcode,
    ) -> ResponseOpt<'a, 'static> {
        let mut response = self.response(existing, &[], rcode);
        response.registered = true;
        response
    }
}

/// OPT to append to a Response, filtering Query options without allocating.
#[derive(Clone, Copy, Debug)]
pub struct ResponseOpt<'a, 'b> {
    source: Opt<'a>,
    supported: &'b [u16],
    copy_all: bool,
    registered: bool,
}

impl ResponseOpt<'_, '_> {
    // RFC 6891 §6.1.2: selected options retain received order, though their order has no meaning.
    fn selected(&self) -> impl Iterator<Item = &[u8]> {
        let mut rest = self.source.options.as_bytes();
        std::iter::from_fn(move || {
            while !rest.is_empty() {
                let code = u16::from_be_bytes([rest[0], rest[1]]);
                let len = usize::from(u16::from_be_bytes([rest[2], rest[3]])) + 4;
                let (option, tail) = rest.split_at(len);
                rest = tail;
                if self.copy_all
                    || self.supported.contains(&code)
                    || (self.registered && edns_option_registered(code))
                {
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

    /// Append this Response OPT to a caller-owned Message buffer.
    pub fn encode(&self, output: &mut Vec<u8>) -> Result<(), BuildError> {
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
        // RFC 9824 §9: CO is the allocated EDNS flag bit 1.
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
        // RFC 6891 §6.2.5: advertised UDP sizes below 512 are treated as 512.
        512
    } else {
        size
    }
}
