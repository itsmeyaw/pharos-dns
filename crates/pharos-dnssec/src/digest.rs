use aws_lc_rs::digest::{self, SHA1_FOR_LEGACY_USE_ONLY, SHA256, SHA384};
use pharos_proto::Name;

/// The digest algorithm used in DS and CDS records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DigestType {
    Sha1,
    Sha256,
    Sha384,
}

// RFC 4034 §5.1.1: DS and RRSIG use the same DNSKEY key-tag value.
/// Calculates the key tag from DNSKEY RDATA, or rejects a truncated record.
#[must_use]
pub fn key_tag(rdata: &[u8]) -> Option<u16> {
    if rdata.len() > u16::MAX as usize {
        return None;
    }
    let algorithm = *rdata.get(3)?;
    // RFC 4034 Appendix B: algorithm 1 uses the third and second last octets.
    // RFC 6840 §5.5 and RFC 4034 §B.1 (Erratum 193): Use modulus octets -3 and -2.
    if algorithm == 1 {
        return (rdata.len() >= 7)
            .then(|| u16::from_be_bytes([rdata[rdata.len() - 3], rdata[rdata.len() - 2]]));
    }
    // RFC 4034 §B (Erratum 4552): Sum 16-bit groups, fold carries, and return 16 bits.
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
    // RFC 4509 §3: DS digest calculation supports SHA-256.
    let algorithm = match algorithm {
        DigestType::Sha1 => &SHA1_FOR_LEGACY_USE_ONLY,
        // RFC 4509 §2.1: SHA-256 DS digests use digest type 2 and all 32 digest octets.
        DigestType::Sha256 => &SHA256,
        DigestType::Sha384 => &SHA384,
    };
    let mut context = digest::Context::new(algorithm);
    // RFC 4509 §2.1: Hash the canonical DNSKEY owner name followed by DNSKEY RDATA.
    let canonical: Vec<u8> = owner.as_wire().iter().map(u8::to_ascii_lowercase).collect();
    context.update(&canonical);
    context.update(rdata);
    // RFC 4509 §2.1: SHA-256 returns all 32 digest bytes without truncation.
    context.finish().as_ref().to_vec()
}

/// Produces CDS RDATA for a DNSKEY.
#[must_use]
pub fn cds_rdata(owner: &Name, dnskey: &[u8], algorithm: DigestType) -> Option<Vec<u8>> {
    // RFC 7344 §3.1: CDS has the same RDATA format and digest as DS.
    let tag = key_tag(dnskey)?;
    let digest_type = match algorithm {
        DigestType::Sha1 => 1,
        // RFC 4509 §2.1: SHA-256 uses digest type 2.
        DigestType::Sha256 => 2,
        // RFC 6605 §7: DS digest type 4 identifies SHA-384.
        DigestType::Sha384 => 4,
    };
    // RFC 4509 §2.1: Preserve the DNSKEY key tag and algorithm in DS RDATA.
    let mut result = tag.to_be_bytes().to_vec();
    result.extend_from_slice(&[dnskey[3], digest_type]);
    result.extend_from_slice(&ds_digest(owner, dnskey, algorithm));
    Some(result)
}

/// Produces CDNSKEY RDATA for a DNSKEY.
#[must_use]
pub fn cdnskey_rdata(dnskey: &[u8]) -> Option<Vec<u8>> {
    // RFC 7344 §3.2: CDNSKEY RDATA is identical to DNSKEY RDATA.
    key_tag(dnskey)?;
    Some(dnskey.to_vec())
}

/// Tests a signature's inclusive serial-arithmetic validity window.
#[must_use]
pub fn signature_valid_at(inception: u32, expiration: u32, now: u32) -> bool {
    // RFC 4034 §3.1.5 and RFC 1982 §3.2: intervals must be less than half the serial space.
    let duration = expiration.wrapping_sub(inception);
    duration < (1 << 31) && now.wrapping_sub(inception) <= duration
}
