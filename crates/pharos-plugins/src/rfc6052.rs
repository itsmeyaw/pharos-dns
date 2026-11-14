use std::net::Ipv6Addr;

pub(crate) const WELL_KNOWN_PREFIX: [u8; 16] =
    [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];

pub(crate) enum PrefixError {
    Format,
    Length,
    WellKnownLength,
    ReservedOctet,
}

pub(crate) fn parse(value: &str) -> Result<([u8; 16], u8), PrefixError> {
    let (ip, len) = value.split_once('/').ok_or(PrefixError::Format)?;
    // RFC 4291 §2.2: IPv6 addresses use conventional textual address forms.
    let ip: Ipv6Addr = ip.parse().map_err(|_| PrefixError::Format)?;
    let len: u8 = len.parse().map_err(|_| PrefixError::Format)?;
    let mut bytes = ip.octets();
    normalize(&mut bytes, len)?;
    Ok((bytes, len))
}

fn normalize(bytes: &mut [u8; 16], len: u8) -> Result<(), PrefixError> {
    // RFC 6052 §2.2: only the six defined prefix lengths are valid.
    if !matches!(len, 32 | 40 | 48 | 56 | 64 | 96) {
        return Err(PrefixError::Length);
    }
    bytes[usize::from(len / 8)..].fill(0);
    // RFC 6052 §2.1: check the masked prefix so host bits cannot hide the WKP.
    if len != 96 && bytes[..12] == WELL_KNOWN_PREFIX[..12] {
        return Err(PrefixError::WellKnownLength);
    }
    // RFC 6052 §2.2: the reserved octet must be zero.
    if bytes[8] != 0 {
        return Err(PrefixError::ReservedOctet);
    }
    Ok(())
}
