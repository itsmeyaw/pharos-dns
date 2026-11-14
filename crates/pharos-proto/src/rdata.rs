use std::{
    fmt,
    net::{Ipv4Addr, Ipv6Addr},
};

use crate::{BuildError, MessageBuffer, NameRef, RdataWriter, Type};

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
            | Type::IPSECKEY
            | Type::HIP
            | Type::TALINK
            | Type::LP
            | Type::TKEY
            | Type::AMTRELAY
    )
}

/// Malformed or unsupported typed record data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RdataError;

/// Validated, borrowed SVCB parameter sequence in wire order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SvcParams<'a>(&'a [u8]);

impl<'a> SvcParams<'a> {
    /// Validates framing, key order, and each parameter's wire value.
    pub fn parse(bytes: &'a [u8]) -> Result<Self, RdataError> {
        let mut rest = bytes;
        let mut previous = None;
        // RFC 9460 §2.2: SvcParams are length-framed and strictly increasing by key.
        while !rest.is_empty() {
            let header = rest.get(..4).ok_or(RdataError)?;
            let key = u16::from_be_bytes([header[0], header[1]]);
            let len = usize::from(u16::from_be_bytes([header[2], header[3]]));
            let value = rest.get(4..4 + len).ok_or(RdataError)?;
            if key == u16::MAX || previous.is_some_and(|p| key <= p) {
                return Err(RdataError);
            }
            valid_svc_param(key, value)?;
            previous = Some(key);
            rest = &rest[4 + len..];
        }
        validate_svc_param_relations(bytes)?;
        Ok(Self(bytes))
    }

    /// Returns the original parameter encoding.
    #[must_use]
    pub fn as_bytes(self) -> &'a [u8] {
        self.0
    }

    /// Iterates over parameter keys and their borrowed wire values.
    pub fn iter(self) -> impl Iterator<Item = (u16, &'a [u8])> {
        let mut rest = self.0;
        std::iter::from_fn(move || {
            if rest.is_empty() {
                return None;
            }
            let key = u16::from_be_bytes([rest[0], rest[1]]);
            let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
            let value = &rest[4..4 + len];
            rest = &rest[4 + len..];
            Some((key, value))
        })
    }
}

// RFC 9460 §§2.4.1, 7.1.1: mandatory keys must exist, and no-default-alpn needs alpn.
pub(crate) fn validate_svc_param_relations(bytes: &[u8]) -> Result<(), RdataError> {
    let mut rest = bytes;
    let mut mandatory = None;
    let mut has_alpn = false;
    let mut no_default_alpn = false;
    while !rest.is_empty() {
        let key = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        let value = &rest[4..4 + len];
        has_alpn |= key == 1;
        no_default_alpn |= key == 2;
        if key == 0 {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                return Err(RdataError);
            }
            let mut previous = 0;
            for pair in value.as_chunks::<2>().0 {
                let required = u16::from_be_bytes(*pair);
                if required <= previous || required == u16::MAX {
                    return Err(RdataError);
                }
                previous = required;
            }
            mandatory = Some(value);
        }
        rest = &rest[4 + len..];
    }
    if no_default_alpn && !has_alpn {
        return Err(RdataError);
    }
    if let Some(required) = mandatory {
        let mut actual = bytes;
        let key0_len = usize::from(u16::from_be_bytes([actual[2], actual[3]]));
        actual = &actual[4 + key0_len..];
        let mut required = required.as_chunks::<2>().0.iter().copied().peekable();
        while !actual.is_empty() {
            let actual_key = u16::from_be_bytes([actual[0], actual[1]]);
            let actual_len = usize::from(u16::from_be_bytes([actual[2], actual[3]]));
            if required
                .peek()
                .is_some_and(|pair| u16::from_be_bytes(*pair) < actual_key)
            {
                return Err(RdataError);
            }
            if required
                .peek()
                .is_some_and(|pair| u16::from_be_bytes(*pair) == actual_key)
            {
                required.next();
            }
            actual = &actual[4 + actual_len..];
        }
        if required.next().is_some() {
            return Err(RdataError);
        }
    }
    Ok(())
}

fn valid_svc_param(key: u16, value: &[u8]) -> Result<(), RdataError> {
    match key {
        // RFC 9460 §8: mandatory keys are nonempty, ordered, and exclude mandatory itself.
        0 => {
            if value.is_empty() || !value.len().is_multiple_of(2) {
                return Err(RdataError);
            }
            let mut previous = 0;
            for pair in value.chunks(2) {
                let key = u16::from_be_bytes([pair[0], pair[1]]);
                if key <= previous || key == u16::MAX {
                    return Err(RdataError);
                }
                previous = key;
            }
        }
        // RFC 9460 §7.1.1: alpn contains one or more nonempty length-prefixed IDs.
        1 => {
            if value.is_empty() {
                return Err(RdataError);
            }
            let mut rest = value;
            while !rest.is_empty() {
                let (id, next) = character_string(rest)?;
                if id.is_empty() {
                    return Err(RdataError);
                }
                rest = next;
            }
        }
        // RFC 9460 §7.1.1: no-default-alpn has an empty wire value.
        // RFC 9540 §4: ohttp has an empty wire value.
        2 | 8 if !value.is_empty() => return Err(RdataError),
        // RFC 9460 §7.2: the port value is a two-octet network-order integer.
        3 if value.len() != 2 => return Err(RdataError),
        // RFC 9460 §7.3: address hints are nonempty sequences of addresses.
        4 if value.is_empty() || !value.len().is_multiple_of(4) => return Err(RdataError),
        6 if value.is_empty() || !value.len().is_multiple_of(16) => return Err(RdataError),
        _ => {}
    }
    Ok(())
}

fn character_string(bytes: &[u8]) -> Result<(&[u8], &[u8]), RdataError> {
    // RFC 1035 §3.3: a character-string is one length octet followed by its data.
    let (&len, rest) = bytes.split_first().ok_or(RdataError)?;
    let len = usize::from(len);
    if len > rest.len() {
        return Err(RdataError);
    }
    Ok(rest.split_at(len))
}

pub(crate) fn compressible_names(
    rtype: Type,
    wire: &[u8],
    offset: usize,
    len: usize,
) -> Result<[Option<NameRef<'_>>; 2], RdataError> {
    let end = offset.checked_add(len).ok_or(RdataError)?;
    let bytes = wire.get(offset..end).ok_or(RdataError)?;
    // RFC 1035 §4.1.4 and RFC 3597 §4: RDATA name layouts; SRV follows miekg/dns.
    let (prefix, count, trailing) = match rtype {
        Type::NS
        | Type::CNAME
        | Type::PTR
        | Type::MD
        | Type::MF
        | Type::MB
        | Type::MG
        | Type::MR => (0, 1, Some(0)),
        Type::MINFO | Type::RP => (0, 2, Some(0)),
        Type::SOA => (0, 2, Some(20)),
        Type::MX | Type::AFSDB | Type::RT => (2, 1, Some(0)),
        Type::PX => (2, 2, Some(0)),
        Type::SIG => (18, 1, None),
        Type::NXT => (0, 1, None),
        Type::SRV => (6, 1, Some(0)),
        Type::NAPTR => {
            let mut rest = bytes.get(4..).ok_or(RdataError)?;
            for _ in 0..3 {
                rest = character_string(rest)?.1;
            }
            (len - rest.len(), 1, Some(0))
        }
        _ => return Ok([None, None]),
    };
    let mut cursor = offset.checked_add(prefix).ok_or(RdataError)?;
    let mut names = [None, None];
    for slot in names.iter_mut().take(count) {
        if cursor >= end {
            return Err(RdataError);
        }
        let name = NameRef::parse(wire, cursor).map_err(|_| RdataError)?;
        cursor = cursor.checked_add(name.wire_len()).ok_or(RdataError)?;
        if cursor > end {
            return Err(RdataError);
        }
        *slot = Some(name);
    }
    if trailing.is_some_and(|trailing| end - cursor != trailing) {
        return Err(RdataError);
    }
    Ok(names)
}

fn valid_txt(mut bytes: &[u8]) -> Result<(), RdataError> {
    // RFC 1035 §3.3.14: TXT RDATA contains one or more character-strings.
    if bytes.is_empty() {
        return Err(RdataError);
    }
    while !bytes.is_empty() {
        bytes = character_string(bytes)?.1;
    }
    Ok(())
}

// RFC 6840 §6.4: An NSEC3 type bitmap may be empty for an empty non-terminal.
fn valid_bitmap(mut bytes: &[u8]) -> Result<(), RdataError> {
    // RFC 4034 §4.1.2: bitmap windows are ordered, 1–32 octets, and have no trailing zeros.
    let mut previous = None;
    while !bytes.is_empty() {
        let header = bytes.get(..2).ok_or(RdataError)?;
        let (window, len) = (header[0], usize::from(header[1]));
        if previous.is_some_and(|p| window <= p) || !(1..=32).contains(&len) {
            return Err(RdataError);
        }
        let block = bytes.get(2..2 + len).ok_or(RdataError)?;
        // RFC 4034 §4.1.2: Ignore TYPE0's reserved bit instead of rejecting the bitmap.
        if block.last() == Some(&0) {
            return Err(RdataError);
        }
        previous = Some(window);
        bytes = &bytes[2 + len..];
    }
    Ok(())
}

fn valid_nsec_bitmap(bytes: &[u8]) -> Result<(), RdataError> {
    if bytes.is_empty() {
        return Err(RdataError);
    }
    valid_bitmap(bytes)
}

fn display_bitmap(f: &mut fmt::Formatter<'_>, mut bytes: &[u8]) -> fmt::Result {
    if valid_bitmap(bytes).is_err() {
        return f.write_str(" <invalid bitmap>");
    }
    while !bytes.is_empty() {
        let window = u16::from(bytes[0]);
        let len = usize::from(bytes[1]);
        for (index, byte) in bytes[2..2 + len].iter().enumerate() {
            for bit in 0..8 {
                if byte & (0x80 >> bit) != 0 {
                    let code = window * 256 + (index * 8 + bit) as u16;
                    // RFC 4034 §4.1.2: Receivers ignore the reserved TYPE0 bitmap bit.
                    if code != 0 {
                        write!(f, " {}", Type(code))?;
                    }
                }
            }
        }
        bytes = &bytes[2 + len..];
    }
    Ok(())
}

// RFC 4648 §8: Encode each octet as two hexadecimal characters.
fn display_hex(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    for byte in bytes {
        write!(f, "{byte:02X}")?;
    }
    Ok(())
}

// RFC 4648 §§3.2,3.5,4,7: Encode bit groups with zero pad bits and optional padding.
fn display_base(
    f: &mut fmt::Formatter<'_>,
    bytes: &[u8],
    alphabet: &[u8],
    bits: u32,
    pad: bool,
) -> fmt::Result {
    let mut buffer = 0u32;
    let mut available = 0u32;
    let mut count = 0usize;
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        available += 8;
        while available >= bits {
            available -= bits;
            let index = ((buffer >> available) & ((1 << bits) - 1)) as usize;
            write!(f, "{}", char::from(alphabet[index]))?;
            count += 1;
        }
    }
    if available != 0 {
        let index = ((buffer << (bits - available)) & ((1 << bits) - 1)) as usize;
        write!(f, "{}", char::from(alphabet[index]))?;
        count += 1;
    }
    if pad {
        while !count.is_multiple_of(4) {
            f.write_str("=")?;
            count += 1;
        }
    }
    Ok(())
}

// RFC 4034 §3.2: RRSIG times use YYYYMMDDHHmmSS presentation.
fn display_date(f: &mut fmt::Formatter<'_>, seconds: u64) -> fmt::Result {
    // Gregorian civil date from days since the Unix epoch.
    let days = (seconds / 86400) as i64 + 719468;
    let era = days / 146097;
    let day_of_era = days - era * 146097;
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36524 - day_of_era / 146096) / 365;
    let mut year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = month_prime + if month_prime < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let time = seconds % 86400;
    write!(
        f,
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}

// RFC 1035 §5.1: Escape quotes and backslashes; encode non-printable octets as decimal.
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

fn write_character_string<B: MessageBuffer>(
    writer: &mut RdataWriter<'_, '_, B>,
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

fn display_octets(f: &mut fmt::Formatter<'_>, bytes: &[u8]) -> fmt::Result {
    f.write_str("\"")?;
    display_bytes(f, bytes)?;
    f.write_str("\"")
}

fn display_svc_key(f: &mut fmt::Formatter<'_>, key: u16) -> fmt::Result {
    match key {
        0 => f.write_str("mandatory"),
        1 => f.write_str("alpn"),
        2 => f.write_str("no-default-alpn"),
        3 => f.write_str("port"),
        4 => f.write_str("ipv4hint"),
        5 => f.write_str("ech"),
        6 => f.write_str("ipv6hint"),
        7 => f.write_str("dohpath"),
        8 => f.write_str("ohttp"),
        _ => write!(f, "key{key}"),
    }
}

fn display_svc_bytes(f: &mut fmt::Formatter<'_>, bytes: &[u8], alpn: bool) -> fmt::Result {
    for &byte in bytes {
        match byte {
            b',' if alpn => f.write_str(r"\\\044")?,
            b'\\' if alpn => f.write_str(r"\\\092")?,
            b'"' | b';' | b' ' | b'\\' => write!(f, "\\{}", char::from(byte))?,
            32..=126 => write!(f, "{}", char::from(byte))?,
            _ => write!(f, "\\{byte:03}")?,
        }
    }
    Ok(())
}

// RFC 9460 §2.1: SvcParam presentation uses registered names or keyNNNNN for unknown keys.
fn display_svc_params(f: &mut fmt::Formatter<'_>, params: SvcParams<'_>) -> fmt::Result {
    for (key, value) in params.iter() {
        f.write_str(" ")?;
        display_svc_key(f, key)?;
        f.write_str("=\"")?;
        match key {
            0 => {
                for (i, pair) in value.chunks(2).enumerate() {
                    if i != 0 {
                        f.write_str(",")?;
                    }
                    display_svc_key(f, u16::from_be_bytes([pair[0], pair[1]]))?;
                }
            }
            1 => {
                let mut rest = value;
                let mut first = true;
                while !rest.is_empty() {
                    let (id, next) = character_string(rest).map_err(|_| fmt::Error)?;
                    if !first {
                        f.write_str(",")?;
                    }
                    display_svc_bytes(f, id, true)?;
                    first = false;
                    rest = next;
                }
            }
            // RFC 9540 §4: The ohttp SvcParam has an empty presentation and wire value.
            2 | 8 => {}
            3 => write!(f, "{}", u16::from_be_bytes([value[0], value[1]]))?,
            4 => {
                for (i, ip) in value.chunks(4).enumerate() {
                    if i != 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}", Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]))?;
                }
            }
            5 => display_base(
                f,
                value,
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                6,
                true,
            )?,
            6 => {
                for (i, ip) in value.chunks(16).enumerate() {
                    if i != 0 {
                        f.write_str(",")?;
                    }
                    let octets: [u8; 16] = ip.try_into().map_err(|_| fmt::Error)?;
                    // RFC 5952 §4: Emit IPv6 addresses in canonical text form.
                    write!(f, "{}", Ipv6Addr::from(octets))?;
                }
            }
            _ => display_svc_bytes(f, value, false)?,
        }
        f.write_str("\"")?;
    }
    Ok(())
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
    Dname(NameRef<'a>),
    Ptr(NameRef<'a>),
    Mx {
        preference: u16,
        exchange: NameRef<'a>,
    },
    // RFC 1982 §7: DNS SOA serials are unsigned 32-bit serial numbers.
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
    /// Service binding with raw, ordered wire-format parameters.
    Svcb {
        priority: u16,
        target: NameRef<'a>,
        params: &'a [u8],
    },
    /// HTTPS service binding with raw, ordered wire-format parameters.
    Https {
        priority: u16,
        target: NameRef<'a>,
        params: &'a [u8],
    },
    Ds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &'a [u8],
    },
    Cds {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: &'a [u8],
    },
    Dnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: &'a [u8],
    },
    Cdnskey {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: &'a [u8],
    },
    Rrsig {
        type_covered: Type,
        algorithm: u8,
        labels: u8,
        original_ttl: u32,
        expiration: u32,
        inception: u32,
        key_tag: u16,
        signer: NameRef<'a>,
        signature: &'a [u8],
    },
    Nsec {
        next: NameRef<'a>,
        bitmap: &'a [u8],
    },
    Nsec3 {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
        next_owner: &'a [u8],
        bitmap: &'a [u8],
    },
    Nsec3param {
        hash_algorithm: u8,
        flags: u8,
        iterations: u16,
        salt: &'a [u8],
    },
    Tlsa {
        usage: u8,
        selector: u8,
        matching_type: u8,
        certificate: &'a [u8],
    },
    Sshfp {
        algorithm: u8,
        fingerprint_type: u8,
        fingerprint: &'a [u8],
    },
    Zonemd {
        serial: u32,
        scheme: u8,
        hash_algorithm: u8,
        digest: &'a [u8],
    },
    Tsig {
        algorithm: NameRef<'a>,
        time_signed: u64,
        fudge: u16,
        mac: &'a [u8],
        original_id: u16,
        error: u16,
        other: &'a [u8],
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

    /// Returns validated service parameters, or `None` for other or malformed data.
    pub fn svc_params(&self) -> Option<SvcParams<'a>> {
        match *self {
            Self::Svcb { params, .. } | Self::Https { params, .. } => SvcParams::parse(params).ok(),
            _ => None,
        }
    }

    // RFC 1035 §3.3: Standard RR RDATA formats are identical across classes.
    pub(crate) fn parse_in_message(
        rtype: Type,
        wire: &'a [u8],
        offset: usize,
        len: usize,
    ) -> Result<Self, RdataError> {
        let bytes = wire
            .get(offset..offset.checked_add(len).ok_or(RdataError)?)
            .ok_or(RdataError)?;
        // RFC 1035 §4.1.3: RDLENGTH is an unsigned 16-bit octet count.
        if matches!(rtype, Type::TLSA | Type::SSHFP | Type::ZONEMD | Type::TSIG)
            && len > usize::from(u16::MAX)
        {
            return Err(RdataError);
        }
        match rtype {
            // RFC 1035 §3.4.1: A RDATA is a four-octet Internet address.
            Type::A => Ok(Self::A(Ipv4Addr::from(
                <[u8; 4]>::try_from(bytes).map_err(|_| RdataError)?,
            ))),
            // RFC 3596 §2.2: AAAA RDATA is a 128-bit IPv6 address in network order.
            Type::AAAA => Ok(Self::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(bytes).map_err(|_| RdataError)?,
            ))),
            // RFC 1035 §3.3.1: CNAME RDATA names the canonical domain name.
            Type::NS | Type::CNAME | Type::DNAME | Type::PTR => {
                let name = NameRef::parse(wire, offset).map_err(|_| RdataError)?;
                if name.wire_len() != len {
                    return Err(RdataError);
                }
                Ok(match rtype {
                    Type::NS => Self::Ns(name),
                    Type::CNAME => Self::Cname(name),
                    Type::DNAME => Self::Dname(name),
                    _ => Self::Ptr(name),
                })
            }
            // RFC 1035 §3.3.9: MX RDATA contains a preference and exchange name.
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
            // RFC 1035 §3.3.13: SOA has two names followed by five 32-bit fields.
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
            // RFC 1035 §3.3.2: HINFO contains CPU and OS character-strings.
            Type::HINFO => {
                let (cpu, rest) = character_string(bytes)?;
                let (os, rest) = character_string(rest)?;
                if !rest.is_empty() {
                    return Err(RdataError);
                }
                Ok(Self::Hinfo { cpu, os })
            }
            // RFC 8659 §4.1: CAA has flags, a nonempty alphanumeric tag, and value.
            Type::CAA => {
                let (&flags, rest) = bytes.split_first().ok_or(RdataError)?;
                let (tag, value) = character_string(rest)?;
                // RFC 8659 §4.1: Ignore reserved flag bits on receipt.
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(RdataError);
                }
                Ok(Self::Caa { flags, tag, value })
            }
            // RFC 7553 §4.5: URI RDATA has 16-bit priority and weight followed by target.
            Type::URI => {
                let header = bytes.get(..4).ok_or(RdataError)?;
                // RFC 7553 §4.4: URI Target must contain at least one octet.
                if bytes.len() == 4 {
                    return Err(RdataError);
                }
                Ok(Self::Uri {
                    priority: u16::from_be_bytes([header[0], header[1]]),
                    weight: u16::from_be_bytes([header[2], header[3]]),
                    target: &bytes[4..],
                })
            }
            // RFC 2782 §The format of the SRV RR: SRV has priority, weight, port, and target.
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
            // RFC 3403 §4.1: NAPTR has order, preference, three strings, and replacement.
            Type::NAPTR => {
                // RFC 3403 §3: Preserve received strings as octets for CoreDNS compatibility.
                let header = bytes.get(..4).ok_or(RdataError)?;
                let (flags, rest) = character_string(&bytes[4..])?;
                let (services, rest) = character_string(rest)?;
                let (regexp, rest) = character_string(rest)?;
                let name_start = len - rest.len();
                // RFC 3403 §4.1: NAPTR replacement is a fully qualified domain name.
                let replacement =
                    NameRef::parse(wire, offset + name_start).map_err(|_| RdataError)?;
                if replacement.wire_len() != rest.len()
                    || !flags.iter().all(u8::is_ascii_alphanumeric)
                    || (!regexp.is_empty() && rest != [0])
                {
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
            // RFC 9460 §2.2: SVCB RDATA contains priority, target, and SvcParams.
            // RFC 9460 §6: SVCB and HTTPS use the same RDATA processing.
            Type::SVCB | Type::HTTPS => {
                let header = bytes.get(..2).ok_or(RdataError)?;
                let priority = u16::from_be_bytes([header[0], header[1]]);
                let target = NameRef::parse(wire, offset + 2).map_err(|_| RdataError)?;
                let params = bytes.get(2 + target.wire_len()..).ok_or(RdataError)?;
                SvcParams::parse(params)?;
                Ok(if rtype == Type::SVCB {
                    Self::Svcb {
                        priority,
                        target,
                        params,
                    }
                } else {
                    Self::Https {
                        priority,
                        target,
                        params,
                    }
                })
            }
            // RFC 4034 §5.1: DS RDATA contains key tag, algorithm, digest type, and digest.
            // RFC 7344 §3.1: CDS uses the DS wire format and field layout.
            Type::DS | Type::CDS => {
                let h = bytes.get(..4).ok_or(RdataError)?;
                // RFC 4034 §5.1.3: The DS digest type identifies the digest algorithm.
                let (key_tag, algorithm, digest_type, digest) =
                    // RFC 4034 §5.1.1: DS key tags are in network byte order.
                    (u16::from_be_bytes([h[0], h[1]]), h[2], h[3], &bytes[4..]);
                // RFC 4509 §2.2: SHA-256 DS digest is exactly 32 octets.
                if digest_type == 2 && digest.len() != 32 {
                    return Err(RdataError);
                }
                Ok(if rtype == Type::DS {
                    Self::Ds {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest,
                    }
                } else {
                    Self::Cds {
                        key_tag,
                        algorithm,
                        digest_type,
                        digest,
                    }
                })
            }
            // RFC 7043 §§3.1, 4.1: EUI48 and EUI64 have fixed six- and eight-octet lengths.
            Type::EUI48 | Type::EUI64 => {
                let expected = if rtype == Type::EUI48 { 6 } else { 8 };
                if bytes.len() != expected {
                    return Err(RdataError);
                }
                Ok(Self::Unknown(rtype, bytes))
            }
            // RFC 4034 §2.1: DNSKEY has flags, protocol, algorithm, and public key.
            // RFC 7344 §3.2: CDNSKEY RDATA has the DNSKEY field layout.
            Type::DNSKEY | Type::CDNSKEY => {
                // RFC 4034 §§2.1.1–2.1.2: Ignore reserved flags and protocol values on receipt.
                let h = bytes.get(..4).ok_or(RdataError)?;
                let (flags, protocol, algorithm, public_key) =
                    (u16::from_be_bytes([h[0], h[1]]), h[2], h[3], &bytes[4..]);
                Ok(if rtype == Type::DNSKEY {
                    Self::Dnskey {
                        flags,
                        protocol,
                        algorithm,
                        public_key,
                    }
                } else {
                    Self::Cdnskey {
                        flags,
                        protocol,
                        algorithm,
                        public_key,
                    }
                })
            }
            // RFC 4034 §3.1: RRSIG has an 18-octet fixed prefix, signer name, and signature.
            Type::RRSIG => {
                let h = bytes.get(..18).ok_or(RdataError)?;
                let signer = NameRef::parse(wire, offset + 18).map_err(|_| RdataError)?;
                let signature = bytes.get(18 + signer.wire_len()..).ok_or(RdataError)?;
                Ok(Self::Rrsig {
                    // RFC 4034 §3.1.1: Type Covered identifies the RR type covered by RRSIG.
                    type_covered: Type(u16::from_be_bytes([h[0], h[1]])),
                    // RFC 4034 §3.1.2: Algorithm identifies the signature algorithm.
                    algorithm: h[2],
                    labels: h[3],
                    original_ttl: u32::from_be_bytes([h[4], h[5], h[6], h[7]]),
                    expiration: u32::from_be_bytes([h[8], h[9], h[10], h[11]]),
                    inception: u32::from_be_bytes([h[12], h[13], h[14], h[15]]),
                    key_tag: u16::from_be_bytes([h[16], h[17]]),
                    signer,
                    signature,
                })
            }
            // RFC 4034 §4.1: NSEC contains a next-domain name and type bitmaps.
            // RFC 4034 §4: NSEC RDATA is independent of RR class.
            Type::NSEC => {
                let next = NameRef::parse(wire, offset).map_err(|_| RdataError)?;
                let bitmap = bytes.get(next.wire_len()..).ok_or(RdataError)?;
                valid_nsec_bitmap(bitmap)?;
                Ok(Self::Nsec { next, bitmap })
            }
            // RFC 5155 §3.2: NSEC3 adds a next hash and bitmap after the salt.
            // RFC 5155 §4.2: NSEC3PARAM ends after its length-prefixed salt.
            // RFC 5155 §4.1: NSEC3PARAM mirrors the first four NSEC3 RDATA fields.
            Type::NSEC3 | Type::NSEC3PARAM => {
                let h = bytes.get(..4).ok_or(RdataError)?;
                let (salt, rest) = character_string(&bytes[4..])?;
                // RFC 5155 §4.1.1: NSEC3PARAM carries an NSEC3 hash-algorithm identifier.
                let (hash_algorithm, flags, iterations) =
                    (h[0], h[1], u16::from_be_bytes([h[2], h[3]]));
                // RFC 5155 §3.1.2: only NSEC3 Opt-Out bit is defined.
                if rtype == Type::NSEC3 && flags & !1 != 0 {
                    return Err(RdataError);
                }
                if rtype == Type::NSEC3PARAM {
                    if !rest.is_empty() {
                        return Err(RdataError);
                    }
                    Ok(Self::Nsec3param {
                        hash_algorithm,
                        // RFC 5155 §4.1.2: Ignore non-zero flags on received NSEC3PARAM RRs.
                        flags: 0,
                        iterations,
                        salt,
                    })
                } else {
                    // RFC 5155 §3.1.7: The next owner stores the binary hash, not the zone.
                    // RFC 5155 §3.1.6: Next Hashed Owner Name length is 1–255 octets.
                    let (next_owner, bitmap) = character_string(rest)?;
                    if next_owner.is_empty() {
                        return Err(RdataError);
                    }
                    valid_bitmap(bitmap)?;
                    Ok(Self::Nsec3 {
                        hash_algorithm,
                        flags,
                        iterations,
                        salt,
                        next_owner,
                        bitmap,
                    })
                }
            }
            // RFC 7477 §2.1.1.2: IMMEDIATE and SOAMINIMUM are the two defined flags.
            Type::CSYNC => {
                let header = bytes.get(..6).ok_or(RdataError)?;
                let flags = u16::from_be_bytes([header[4], header[5]]);
                let bitmap = bytes.get(6..).ok_or(RdataError)?;
                if flags & !3 != 0 {
                    return Err(RdataError);
                }
                valid_nsec_bitmap(bitmap)?;
                Ok(Self::Unknown(rtype, bytes))
            }
            // RFC 6698 §2.1.4: TLSA association data is the unparsed remainder after fixed fields.
            Type::TLSA => {
                let h = bytes.get(..3).ok_or(RdataError)?;
                Ok(Self::Tlsa {
                    usage: h[0],
                    selector: h[1],
                    matching_type: h[2],
                    certificate: &bytes[3..],
                })
            }
            // RFC 4255 §3.1: SSHFP stores algorithm, fingerprint type, then fingerprint bytes.
            Type::SSHFP => {
                let h = bytes.get(..2).ok_or(RdataError)?;
                Ok(Self::Sshfp {
                    algorithm: h[0],
                    fingerprint_type: h[1],
                    fingerprint: &bytes[2..],
                })
            }
            // RFC 8976 §2.2.4: a ZONEMD digest is at least 12 octets.
            Type::ZONEMD => {
                let h = bytes.get(..18).ok_or(RdataError)?;
                let expected = match h[5] {
                    1 => Some(48),
                    2 => Some(64),
                    _ => None,
                };
                if expected.is_some_and(|size| bytes.len() - 6 != size) {
                    return Err(RdataError);
                }
                Ok(Self::Zonemd {
                    // RFC 8976 §2.2.1: Serial is a 32-bit unsigned network-order integer.
                    serial: u32::from_be_bytes([h[0], h[1], h[2], h[3]]),
                    // RFC 8976 §2.2.2: Scheme is an 8-bit unsigned method identifier.
                    scheme: h[4],
                    hash_algorithm: h[5],
                    // RFC 8976 §2.2.3: SHA384 and SHA512 digests are not truncated.
                    digest: &bytes[6..],
                })
            }
            // RFC 8945 §4.2: TSIG uses a 48-bit time and length-prefixed MAC and other data.
            Type::TSIG => {
                let algorithm = NameRef::parse(wire, offset).map_err(|_| RdataError)?;
                let rest = bytes.get(algorithm.wire_len()..).ok_or(RdataError)?;
                let h = rest.get(..10).ok_or(RdataError)?;
                let time_signed = u64::from_be_bytes([0, 0, h[0], h[1], h[2], h[3], h[4], h[5]]);
                let fudge = u16::from_be_bytes([h[6], h[7]]);
                let mac_len = usize::from(u16::from_be_bytes([h[8], h[9]]));
                let mac = rest.get(10..10 + mac_len).ok_or(RdataError)?;
                let rest = rest.get(10 + mac_len..).ok_or(RdataError)?;
                let h = rest.get(..6).ok_or(RdataError)?;
                let other_len = usize::from(u16::from_be_bytes([h[4], h[5]]));
                let other = rest.get(6..).ok_or(RdataError)?;
                if other.len() != other_len {
                    return Err(RdataError);
                }
                Ok(Self::Tsig {
                    algorithm,
                    time_signed,
                    fudge,
                    mac,
                    original_id: u16::from_be_bytes([h[0], h[1]]),
                    error: u16::from_be_bytes([h[2], h[3]]),
                    other,
                })
            }
            _ if unsupported_name_type(rtype) => Err(RdataError),
            // shortcut: other record types stay opaque, add typed formats before zone parsing.
            // RFC 4701 §3.1: DHCID RDATA stays opaque bytes, not parsed.
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
            Self::Dname(_) => Type::DNAME,
            Self::Ptr(_) => Type::PTR,
            Self::Mx { .. } => Type::MX,
            Self::Soa { .. } => Type::SOA,
            Self::Txt(_) => Type::TXT,
            Self::Hinfo { .. } => Type::HINFO,
            Self::Caa { .. } => Type::CAA,
            Self::Uri { .. } => Type::URI,
            Self::Srv { .. } => Type::SRV,
            Self::Naptr { .. } => Type::NAPTR,
            Self::Svcb { .. } => Type::SVCB,
            Self::Https { .. } => Type::HTTPS,
            Self::Ds { .. } => Type::DS,
            Self::Cds { .. } => Type::CDS,
            Self::Dnskey { .. } => Type::DNSKEY,
            Self::Cdnskey { .. } => Type::CDNSKEY,
            Self::Rrsig { .. } => Type::RRSIG,
            Self::Nsec { .. } => Type::NSEC,
            Self::Nsec3 { .. } => Type::NSEC3,
            Self::Nsec3param { .. } => Type::NSEC3PARAM,
            Self::Tlsa { .. } => Type::TLSA,
            Self::Sshfp { .. } => Type::SSHFP,
            Self::Zonemd { .. } => Type::ZONEMD,
            Self::Tsig { .. } => Type::TSIG,
            Self::Unknown(rtype, _) => *rtype,
        }
    }

    /// Writes this data with a Message builder's RDATA hook.
    pub fn write<B: MessageBuffer>(
        &self,
        writer: &mut RdataWriter<'_, '_, B>,
    ) -> Result<(), BuildError> {
        match self {
            // RFC 1035 §3.4.1: A RDATA carries one 32-bit Internet address.
            Self::A(addr) => writer.write_bytes(&addr.octets()),
            // RFC 3596 §2.2: AAAA RDATA is a 128-bit IPv6 address in network order.
            Self::Aaaa(addr) => writer.write_bytes(&addr.octets()),
            // RFC 3597 §4: Embedded names in RFC 1035 well-known RDATA may be compressed.
            Self::Ns(name) | Self::Cname(name) | Self::Ptr(name) => writer.write_name(*name),
            // RFC 6672 §2.1 and §2.5: DNAME target names must not be compressed.
            Self::Dname(name) => writer.write_uncompressed_name(*name),
            // RFC 1035 §3.3.9: MX RDATA contains a preference and exchange name.
            Self::Mx {
                preference,
                exchange,
            } => {
                writer.write_bytes(&preference.to_be_bytes())?;
                writer.write_name(*exchange)
            }
            // RFC 1035 §3.3.13: SOA has two names followed by five unsigned 32-bit fields.
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
            // RFC 1035 §3.3.14: TXT RDATA contains one or more character-strings.
            Self::Txt(bytes) => {
                valid_txt(bytes).map_err(|_| BuildError::InvalidRdata)?;
                writer.write_bytes(bytes)
            }
            // RFC 1035 §3.3.2: HINFO RDATA contains CPU and OS character-strings.
            Self::Hinfo { cpu, os } => {
                write_character_string(writer, cpu)?;
                write_character_string(writer, os)
            }
            // RFC 8659 §4.1: CAA writes flags, a length-prefixed tag, and value octets.
            Self::Caa { flags, tag, value } => {
                if tag.is_empty() || !tag.iter().all(u8::is_ascii_alphanumeric) {
                    return Err(BuildError::InvalidRdata);
                }
                // RFC 8659 §4.1: Clear reserved flag bits when re-encoding received data.
                writer.write_bytes(&[*flags & 0x80])?;
                write_character_string(writer, tag)?;
                writer.write_bytes(value)
            }
            // RFC 7553 §4.5: URI Priority and Weight precede Target in network byte order.
            Self::Uri {
                priority,
                weight,
                target,
            } => {
                // RFC 7553 §4.4: URI Target must contain at least one octet.
                if target.is_empty() {
                    return Err(BuildError::InvalidRdata);
                }
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
                // RFC 3597 §4: SRV target names are not compressed by senders.
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
                // RFC 3403 §4.1: flags are alphanumeric; a nonempty regexp requires root replacement.
                if !flags.iter().all(u8::is_ascii_alphanumeric)
                    || (!regexp.is_empty() && replacement.labels().next().is_some())
                {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&order.to_be_bytes())?;
                writer.write_bytes(&preference.to_be_bytes())?;
                write_character_string(writer, flags)?;
                write_character_string(writer, services)?;
                write_character_string(writer, regexp)?;
                // RFC 3403 §4.1: the NAPTR replacement name is not compressed.
                writer.write_uncompressed_name(*replacement)
            }
            Self::Svcb {
                priority,
                target,
                params,
            }
            | Self::Https {
                priority,
                target,
                params,
            } => {
                SvcParams::parse(params).map_err(|_| BuildError::InvalidRdata)?;
                writer.write_bytes(&priority.to_be_bytes())?;
                // RFC 9460 §2.2: the SVCB TargetName is uncompressed.
                writer.write_uncompressed_name(*target)?;
                writer.write_bytes(params)
            }
            // RFC 7344 §3.1: CDS RDATA uses the DS wire format.
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | Self::Cds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                // RFC 4509 §2.2: SHA-256 DS digest is exactly 32 octets.
                if *digest_type == 2 && digest.len() != 32 {
                    return Err(BuildError::InvalidRdata);
                }
                // RFC 4034 §5.1.1: DS key tags are serialized in network byte order.
                writer.write_bytes(&key_tag.to_be_bytes())?;
                writer.write_bytes(&[*algorithm, *digest_type])?;
                writer.write_bytes(digest)
            }
            Self::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            }
            | Self::Cdnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                // RFC 4034 §2.1.1: Clear reserved DNSKEY flag bits when re-encoding.
                writer.write_bytes(&(*flags & 0x0181).to_be_bytes())?;
                // RFC 4034 §2.1.2: Preserve protocol; values other than 3 remain unusable keys.
                writer.write_bytes(&[*protocol, *algorithm])?;
                writer.write_bytes(public_key)
            }
            Self::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                writer.write_bytes(&type_covered.0.to_be_bytes())?;
                writer.write_bytes(&[*algorithm, *labels])?;
                for value in [original_ttl, expiration, inception] {
                    writer.write_bytes(&value.to_be_bytes())?;
                }
                // RFC 4034 §3.1.6: The DNSKEY key tag is encoded in network byte order.
                writer.write_bytes(&key_tag.to_be_bytes())?;
                // RFC 4034 §3.1.7: senders must not compress the RRSIG signer name.
                writer.write_uncompressed_name(*signer)?;
                writer.write_bytes(signature)
            }
            Self::Nsec { next, bitmap } => {
                valid_nsec_bitmap(bitmap).map_err(|_| BuildError::InvalidRdata)?;
                // RFC 4034 §4.1.1: senders must not compress the NSEC next domain name.
                writer.write_uncompressed_name(*next)?;
                writer.write_bytes(bitmap)
            }
            Self::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_owner,
                bitmap,
            } => {
                // RFC 5155 §3.2: NSEC3 fields use wire order and network-byte-order integers.
                valid_bitmap(bitmap).map_err(|_| BuildError::InvalidRdata)?;
                // RFC 5155 §3.1.2: only the Opt-Out flag bit is defined.
                // RFC 5155 §3.1.6: Next Hashed Owner Name length is 1–255 octets.
                if *flags & !1 != 0 || next_owner.is_empty() {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&[*hash_algorithm, *flags])?;
                writer.write_bytes(&iterations.to_be_bytes())?;
                write_character_string(writer, salt)?;
                // RFC 5155 §3.1.7: The next owner stores the binary hash, not the zone.
                write_character_string(writer, next_owner)?;
                writer.write_bytes(bitmap)
            }
            Self::Nsec3param {
                hash_algorithm,
                flags: _,
                iterations,
                salt,
            } => {
                // RFC 5155 §4.2: NSEC3PARAM carries algorithm, flags, iterations, and salt.
                // RFC 5155 §4.1.2: Ignore received flags and emit the required zero value.
                writer.write_bytes(&[*hash_algorithm, 0])?;
                writer.write_bytes(&iterations.to_be_bytes())?;
                // RFC 5155 §4.1.4: Salt Length counts the following salt octets.
                write_character_string(writer, salt)
            }
            // RFC 6698 §2.1.4: TLSA association data follows the three fixed fields verbatim.
            Self::Tlsa {
                usage,
                selector,
                matching_type,
                certificate,
            } => {
                if certificate.len() > usize::from(u16::MAX) - 3 {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&[*usage, *selector, *matching_type])?;
                writer.write_bytes(certificate)
            }
            // RFC 4255 §3.1: SSHFP encodes algorithm, fingerprint type, then fingerprint bytes.
            Self::Sshfp {
                algorithm,
                fingerprint_type,
                fingerprint,
            } => {
                if fingerprint.len() > usize::from(u16::MAX) - 2 {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&[*algorithm, *fingerprint_type])?;
                writer.write_bytes(fingerprint)
            }
            // RFC 8976 §2.2: ZONEMD carries serial, scheme, hash algorithm, and digest in order.
            Self::Zonemd {
                serial,
                scheme,
                hash_algorithm,
                digest,
            } => {
                // RFC 8976 §2.2.3: SHA384 and SHA512 digests have exact lengths.
                if !(12..=usize::from(u16::MAX) - 6).contains(&digest.len())
                    || matches!(*hash_algorithm, 1 | 2)
                        && digest.len() != if *hash_algorithm == 1 { 48 } else { 64 }
                {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(&serial.to_be_bytes())?;
                writer.write_bytes(&[*scheme, *hash_algorithm])?;
                writer.write_bytes(digest)
            }
            Self::Tsig {
                algorithm,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other,
            } => {
                if *time_signed > 0xffff_ffff_ffff {
                    return Err(BuildError::InvalidRdata);
                }
                let mac_len = u16::try_from(mac.len()).map_err(|_| BuildError::InvalidRdata)?;
                let other_len = u16::try_from(other.len()).map_err(|_| BuildError::InvalidRdata)?;
                let name_len = 1 + algorithm
                    .labels()
                    .map(|label| label.len() + 1)
                    .sum::<usize>();
                if name_len + 16 + mac.len() + other.len() > usize::from(u16::MAX) {
                    return Err(BuildError::InvalidRdata);
                }
                // RFC 8945 §4.2: the TSIG algorithm name must not be compressed.
                writer.write_uncompressed_name(*algorithm)?;
                writer.write_bytes(&time_signed.to_be_bytes()[2..])?;
                writer.write_bytes(&fudge.to_be_bytes())?;
                writer.write_bytes(&mac_len.to_be_bytes())?;
                writer.write_bytes(mac)?;
                writer.write_bytes(&original_id.to_be_bytes())?;
                writer.write_bytes(&error.to_be_bytes())?;
                writer.write_bytes(&other_len.to_be_bytes())?;
                writer.write_bytes(other)
            }
            Self::Unknown(rtype, _)
                if unsupported_name_type(*rtype)
                    || matches!(
                        *rtype,
                        Type::A
                            | Type::AAAA
                            | Type::NS
                            | Type::CNAME
                            | Type::DNAME
                            | Type::PTR
                            | Type::MX
                            | Type::SOA
                            | Type::TXT
                            | Type::HINFO
                            | Type::CAA
                            | Type::URI
                            | Type::SRV
                            | Type::NAPTR
                            | Type::SVCB
                            | Type::HTTPS
                            | Type::DS
                            | Type::CDS
                            | Type::DNSKEY
                            | Type::CDNSKEY
                            | Type::RRSIG
                            | Type::NSEC
                            | Type::NSEC3
                            | Type::NSEC3PARAM
                            | Type::TLSA
                            | Type::SSHFP
                            | Type::ZONEMD
                            | Type::TSIG
                    ) =>
            {
                Err(BuildError::InvalidRdata)
            }
            // RFC 7043 §§3.1, 4.1: EUI48 and EUI64 have fixed wire lengths.
            Self::Unknown(rtype, bytes)
                if *rtype == Type::EUI48 && bytes.len() != 6
                    || *rtype == Type::EUI64 && bytes.len() != 8 =>
            {
                Err(BuildError::InvalidRdata)
            }
            // RFC 7477 §2.1.1.2: CSYNC permits its two defined flags and a nonempty bitmap.
            Self::Unknown(rtype, bytes) if *rtype == Type::CSYNC => {
                if bytes.len() < 7
                    || u16::from_be_bytes([bytes[4], bytes[5]]) & !3 != 0
                    || valid_nsec_bitmap(&bytes[6..]).is_err()
                {
                    return Err(BuildError::InvalidRdata);
                }
                writer.write_bytes(bytes)
            }
            // RFC 3597 §3: Unknown RDATA is transmitted unchanged as binary data.
            Self::Unknown(_, bytes) => writer.write_bytes(bytes),
        }
    }
}

impl fmt::Display for Rdata<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::A(addr) => write!(f, "{addr}"),
            // RFC 5952 §4.3: Display hexadecimal letters in lowercase.
            Self::Aaaa(addr) => write!(f, "{addr}"),
            Self::Ns(name) | Self::Cname(name) | Self::Dname(name) | Self::Ptr(name) => {
                write!(f, "{name}")
            }
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
                // RFC 8659 §4.1.1: Canonical CAA presentation lowercases tag octets.
                for &byte in tag.iter() {
                    display_bytes(f, &[byte.to_ascii_lowercase()])?;
                }
                f.write_str(" ")?;
                display_octets(f, value)
            }
            // RFC 7553 §4.4: URI Target uses double quotes in presentation format.
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
                // RFC 3403 §4.3: Flags, Services, and Regexp are quoted character-strings.
                write!(f, "{order} {preference} ")?;
                display_quoted(f, flags)?;
                f.write_str(" ")?;
                display_quoted(f, services)?;
                f.write_str(" ")?;
                display_quoted(f, regexp)?;
                write!(f, " {replacement}")
            }
            Self::Svcb {
                priority,
                target,
                params,
            }
            | Self::Https {
                priority,
                target,
                params,
            } => {
                write!(f, "{priority} {target}")?;
                match SvcParams::parse(params) {
                    Ok(params) => display_svc_params(f, params),
                    Err(_) => write!(f, " {}", Self::Unknown(self.rtype(), params)),
                }
            }
            // RFC 7344 §3.1: CDS presentation format matches DS.
            Self::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            }
            | Self::Cds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => {
                // RFC 4034 §5.3: DS fields use decimal numbers and a hexadecimal digest.
                write!(f, "{key_tag} {algorithm} {digest_type} ")?;
                display_hex(f, digest)
            }
            Self::Dnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            }
            | Self::Cdnskey {
                flags,
                protocol,
                algorithm,
                public_key,
            } => {
                // RFC 4034 §2.2: The DNSKEY public key uses Base64 presentation.
                write!(f, "{flags} {protocol} {algorithm} ")?;
                display_base(
                    f,
                    public_key,
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                    6,
                    true,
                )
            }
            // RFC 4034 §3.2: RRSIG fields use the specified presentation forms.
            Self::Rrsig {
                type_covered,
                algorithm,
                labels,
                original_ttl,
                expiration,
                inception,
                key_tag,
                signer,
                signature,
            } => {
                // RFC 4034 §3.2: RRSIG uses decimal fields, UTC timestamps, and Base64.
                write!(f, "{type_covered} {algorithm} {labels} {original_ttl} ")?;
                display_date(f, u64::from(*expiration))?;
                f.write_str(" ")?;
                display_date(f, u64::from(*inception))?;
                write!(f, " {key_tag} {signer} ")?;
                display_base(
                    f,
                    signature,
                    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                    6,
                    true,
                )
            }
            // RFC 4034 §4.2: NSEC presents the next name and type mnemonics or TYPE numbers.
            Self::Nsec { next, bitmap } => {
                write!(f, "{next}")?;
                if bitmap.is_empty() {
                    f.write_str(" <invalid bitmap>")
                } else {
                    display_bitmap(f, bitmap)
                }
            }
            // RFC 5155 §3.3: The next hashed owner uses unpadded base32hex presentation.
            Self::Nsec3 {
                hash_algorithm,
                flags,
                iterations,
                salt,
                next_owner,
                bitmap,
            } => {
                // RFC 5155 §3.3: NSEC3 uses decimal fields, hex salt, base32hex hash, and types.
                write!(f, "{hash_algorithm} {flags} {iterations} ")?;
                if salt.is_empty() {
                    f.write_str("-")?;
                } else {
                    display_hex(f, salt)?;
                }
                f.write_str(" ")?;
                display_base(f, next_owner, b"0123456789ABCDEFGHIJKLMNOPQRSTUV", 5, false)?;
                display_bitmap(f, bitmap)
            }
            // RFC 5155 §4.3: NSEC3PARAM uses decimal fields and "-" for an empty salt.
            Self::Nsec3param {
                hash_algorithm,
                flags,
                iterations,
                salt,
            } => {
                write!(f, "{hash_algorithm} {flags} {iterations} ")?;
                if salt.is_empty() {
                    f.write_str("-")
                } else {
                    display_hex(f, salt)
                }
            }
            Self::Tlsa {
                usage,
                selector,
                matching_type,
                certificate,
            } => {
                // RFC 6698 §2.2: Certificate association data is presented in hexadecimal.
                write!(f, "{usage} {selector} {matching_type} ")?;
                for byte in *certificate {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            // RFC 4255 §3.2: SSHFP uses decimal identifiers and a hexadecimal fingerprint.
            Self::Sshfp {
                algorithm,
                fingerprint_type,
                fingerprint,
            } => {
                write!(f, "{algorithm} {fingerprint_type} ")?;
                display_hex(f, fingerprint)
            }
            Self::Zonemd {
                serial,
                scheme,
                hash_algorithm,
                digest,
            } => {
                // RFC 8976 §2.3: ZONEMD uses decimal fields and a hexadecimal digest.
                write!(f, "{serial} {scheme} {hash_algorithm} ")?;
                for byte in *digest {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Tsig {
                algorithm,
                time_signed,
                fudge,
                mac,
                original_id,
                error,
                other,
            } => {
                write!(f, "{algorithm} ")?;
                display_date(f, *time_signed)?;
                write!(f, " {fudge} {} ", mac.len())?;
                display_hex(f, mac)?;
                write!(f, " {original_id} {error} {} ", other.len())?;
                for byte in *other {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
            Self::Unknown(_, bytes) => {
                // RFC 3597 §5: unknown RDATA is presented as length and hexadecimal octets.
                write!(f, "\\# {} ", bytes.len())?;
                for byte in *bytes {
                    write!(f, "{byte:02x}")?;
                }
                Ok(())
            }
        }
    }
}
