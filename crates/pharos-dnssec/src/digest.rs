use aws_lc_rs::digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use pharos_proto::Name;

/// The digest algorithm used in DS and CDS records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestType {
    Sha1,
    Sha256,
    Sha384,
}

/// Calculates the key tag from DNSKEY RDATA, or rejects a truncated record.
#[must_use]
pub fn key_tag(rdata: &[u8]) -> Option<u16> {
    if rdata.len() > u16::MAX as usize {
        return None;
    }
    let algorithm = *rdata.get(3)?;
    // RFC 4034 Appendix B: algorithm 1 uses the third and second last octets.
    if algorithm == 1 {
        return (rdata.len() >= 7)
            .then(|| u16::from_be_bytes([rdata[rdata.len() - 3], rdata[rdata.len() - 2]]));
    }
    let mut accumulator = 0_u32;
    for (index, byte) in rdata.iter().enumerate() {
        accumulator += if index % 2 == 0 {
            u32::from(*byte) << 8
        } else {
            u32::from(*byte)
        };
    }
    accumulator += (accumulator >> 16) & 0xffff;
    Some(accumulator as u16)
}

/// Calculates the digest over the canonical owner and DNSKEY RDATA.
#[must_use]
pub fn ds_digest(owner: &Name, rdata: &[u8], algorithm: DigestType) -> Vec<u8> {
    // RFC 4034 §5.1.4: the digest covers the canonical owner followed by DNSKEY RDATA.
    let algorithm = match algorithm {
        DigestType::Sha1 => &SHA1_FOR_LEGACY_USE_ONLY,
        DigestType::Sha256 => &SHA256,
        DigestType::Sha384 => &SHA384,
    };
    let mut context = digest::Context::new(algorithm);
    let canonical: Vec<u8> = owner.as_wire().iter().map(u8::to_ascii_lowercase).collect();
    context.update(&canonical);
    context.update(rdata);
    context.finish().as_ref().to_vec()
}

/// Tests a signature's inclusive serial-arithmetic validity window.
#[must_use]
pub fn signature_valid_at(inception: u32, expiration: u32, now: u32) -> bool {
    // RFC 4034 §3.1.5 and RFC 1982 §3.2: intervals must be less than half the serial space.
    let duration = expiration.wrapping_sub(inception);
    duration < (1 << 31) && now.wrapping_sub(inception) <= duration
}
