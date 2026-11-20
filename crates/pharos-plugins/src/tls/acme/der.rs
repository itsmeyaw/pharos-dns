//! The few ASN.1 DER structures ACME needs: a PKCS#10 certificate request (RFC 2986) and a certificate's validity (RFC 5280).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair},
};

// ITU-T X.690 §8.1.2: universal tag numbers with the constructed bit where it applies.
const INTEGER: u8 = 0x02;
const BIT_STRING: u8 = 0x03;
const OCTET_STRING: u8 = 0x04;
const OID: u8 = 0x06;
const UTF8_STRING: u8 = 0x0c;
const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
// RFC 2986 §4.1: attributes are [0] IMPLICIT SET OF; RFC 5280 §4.2.1.6: a dNSName is [2] IMPLICIT IA5String.
const CONTEXT_0: u8 = 0xa0;
const DNS_NAME: u8 = 0x82;

// RFC 5480 §2.1.1: id-ecPublicKey 1.2.840.10045.2.1 and secp256r1 1.2.840.10045.3.1.7.
const EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const SECP256R1: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
// RFC 5758 §3.2: ecdsa-with-SHA256 1.2.840.10045.4.3.2.
const ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
// RFC 2985 §5.4.2: extensionRequest 1.2.840.113549.1.9.14.
const EXTENSION_REQUEST: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x0e];
// RFC 5280 §4.2.1.6: subjectAltName 2.5.29.17; RFC 5280 Appendix A.1: commonName 2.5.4.3.
const SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
// RFC 5280 §4.1.2.6: a commonName is at most 64 characters (ub-common-name).
const MAX_COMMON_NAME: usize = 64;

/// ITU-T X.690 §8.1.3: a definite length, short form below 128 octets and long form above.
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    out.push(tag);
    match u16::try_from(content.len()) {
        Ok(len @ 0..=0x7f) => out.push(len as u8),
        Ok(len @ 0x80..=0xff) => out.extend_from_slice(&[0x81, len as u8]),
        Ok(len) => out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]),
        Err(_) => unreachable!("an ACME structure is far below 64 KiB"),
    }
    out.extend_from_slice(content);
    out
}

pub(crate) fn sequence(parts: &[&[u8]]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

fn algorithm(oid: &[u8], parameters: Option<&[u8]>) -> Vec<u8> {
    let oid = tlv(OID, oid);
    match parameters {
        Some(parameters) => sequence(&[&oid, &tlv(OID, parameters)]),
        None => sequence(&[&oid]),
    }
}

/// The SubjectPublicKeyInfo (RFC 5480 §2) of an uncompressed P-256 point.
pub(crate) fn p256_spki(point: &[u8]) -> Vec<u8> {
    let mut bits = vec![0];
    bits.extend_from_slice(point);
    sequence(&[
        &algorithm(EC_PUBLIC_KEY, Some(SECP256R1)),
        &tlv(BIT_STRING, &bits),
    ])
}

/// A PKCS#10 request for `names` (DNS names), signed with `key` (RFC 2986 §4).
// RFC 8555 §7.4: the CSR carries every identifier of the order as a subjectAltName dNSName.
pub(crate) fn csr(
    key: &EcdsaKeyPair,
    names: &[String],
) -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
    let general_names = tlv(
        SEQUENCE,
        &names
            .iter()
            .flat_map(|name| tlv(DNS_NAME, name.as_bytes()))
            .collect::<Vec<u8>>(),
    );
    let extension = sequence(&[
        &tlv(OID, SUBJECT_ALT_NAME),
        &tlv(OCTET_STRING, &general_names),
    ]);
    let attribute = sequence(&[
        &tlv(OID, EXTENSION_REQUEST),
        &tlv(SET, &sequence(&[&sequence(&[&extension])])),
    ]);
    // Some CAs still require a commonName (certmagic notes ZeroSSL); it must repeat a SAN and fit 64 characters.
    let subject = match names.first().filter(|name| name.len() <= MAX_COMMON_NAME) {
        Some(name) => sequence(&[&tlv(
            SET,
            &sequence(&[&tlv(OID, COMMON_NAME), &tlv(UTF8_STRING, name.as_bytes())]),
        )]),
        None => sequence(&[]),
    };
    let info = sequence(&[
        &tlv(INTEGER, &[0]),
        &subject,
        &p256_spki(key.public_key().as_ref()),
        &tlv(CONTEXT_0, &attribute),
    ]);
    let signature = key.sign(&SystemRandom::new(), &info)?;
    let mut bits = vec![0];
    bits.extend_from_slice(signature.as_ref());
    Ok(sequence(&[
        &info,
        &algorithm(ECDSA_SHA256, None),
        &tlv(BIT_STRING, &bits),
    ]))
}

/// A cursor over consecutive DER elements.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    /// The next element as `(tag, content, whole element)`.
    pub(crate) fn next(&mut self) -> Option<(u8, &'a [u8], &'a [u8])> {
        let (&tag, rest) = self.0.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            // ITU-T X.690 §8.1.3.5: long form; only lengths that fit 16 bits occur in a certificate.
            let count = usize::from(first & 0x7f);
            if count == 0 || count > 2 || rest.len() < count {
                return None;
            }
            let len = rest[..count]
                .iter()
                .fold(0_usize, |len, byte| len << 8 | usize::from(*byte));
            (len, &rest[count..])
        };
        let content = rest.get(..len)?;
        let whole = &self.0[..self.0.len() - rest.len() + len];
        self.0 = &rest[len..];
        Some((tag, content, whole))
    }

    pub(crate) fn expect(&mut self, tag: u8) -> Option<&'a [u8]> {
        self.next()
            .filter(|(found, ..)| *found == tag)
            .map(|(_, content, _)| content)
    }
}

/// When a certificate stops being valid and when its validity began (RFC 5280 §4.1.2.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Validity {
    pub not_before: SystemTime,
    pub not_after: SystemTime,
}

/// The validity period of a DER certificate.
pub(crate) fn validity(certificate: &[u8]) -> Option<Validity> {
    let mut certificate = Reader::new(Reader::new(certificate).expect(SEQUENCE)?);
    let mut tbs = Reader::new(certificate.expect(SEQUENCE)?);
    let (mut tag, ..) = tbs.next()?;
    // RFC 5280 §4.1: the optional [0] version precedes the serial number.
    if tag == CONTEXT_0 {
        (tag, ..) = tbs.next()?;
    }
    if tag != INTEGER {
        return None;
    }
    // signature AlgorithmIdentifier, issuer, then validity.
    tbs.expect(SEQUENCE)?;
    tbs.expect(SEQUENCE)?;
    let mut validity = Reader::new(tbs.expect(SEQUENCE)?);
    let (not_before, not_after) = (validity.next()?, validity.next()?);
    Some(Validity {
        not_before: time(not_before.0, not_before.1)?,
        not_after: time(not_after.0, not_after.1)?,
    })
}

// RFC 5280 §4.1.2.5.1 and §4.1.2.5.2: UTCTime is YYMMDDHHMMSSZ, GeneralizedTime YYYYMMDDHHMMSSZ.
fn time(tag: u8, content: &[u8]) -> Option<SystemTime> {
    // RFC 5280 §4.1.2.5: times are ASCII digits; refusing other bytes keeps the slicing below on char boundaries.
    let text = std::str::from_utf8(content).ok()?.strip_suffix('Z')?;
    if !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let (year, rest) = match tag {
        UTC_TIME if text.len() == 12 => {
            let year: i64 = text[..2].parse().ok()?;
            // RFC 5280 §4.1.2.5.1: years 50 to 99 are 19YY, years 00 to 49 are 20YY.
            (
                if year >= 50 { 1900 + year } else { 2000 + year },
                &text[2..],
            )
        }
        GENERALIZED_TIME if text.len() == 14 => (text[..4].parse().ok()?, &text[4..]),
        _ => return None,
    };
    let field = |at: usize| rest[at..at + 2].parse::<i64>().ok();
    let (month, day, hour, minute, second) =
        (field(0)?, field(2)?, field(4)?, field(6)?, field(8)?);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        || second > 60
    {
        return None;
    }
    let seconds = days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second;
    let seconds = u64::try_from(seconds).ok()?;
    Some(UNIX_EPOCH + Duration::from_secs(seconds))
}

// Howard Hinnant's days_from_civil: days since 1970-01-01 of a proleptic Gregorian date.
pub(super) fn days_from_civil(year: i64, month: i64, day: i64) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year.div_euclid(400);
    let year_of_era = year - era * 400;
    let day_of_year = (153 * (month + if month > 2 { -3 } else { 9 }) + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// A new P-256 key for signing certificate requests, as PKCS#8.
pub(crate) fn generate_certificate_key() -> Result<Vec<u8>, aws_lc_rs::error::Unspecified> {
    Ok(
        EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, &SystemRandom::new())?
            .as_ref()
            .to_vec(),
    )
}

/// Load a PKCS#8 P-256 key for signing certificate requests.
pub(crate) fn certificate_key(pkcs8: &[u8]) -> Result<EcdsaKeyPair, aws_lc_rs::error::KeyRejected> {
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_ASN1_SIGNING, pkcs8)
}

#[cfg(test)]
mod tests;
