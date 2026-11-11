//! Loading DNSKEY records and their BIND or PKCS#8 private keys.

use std::{collections::HashMap, fmt, fs, path::Path};

use aws_lc_rs::{
    encoding::{AsDer, Pkcs8V1Der},
    signature::{self, KeyPair as _},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use pharos_proto::Name;

/// A DNSKEY record and its decoded public-key field.
#[derive(Debug)]
pub struct Dnskey {
    pub owner: Name,
    pub ttl: Option<u32>,
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

/// A validated private signing key.
#[derive(Debug)]
pub enum PrivateKey {
    Rsa(signature::RsaKeyPair),
    Ecdsa(signature::EcdsaKeyPair),
    Ed25519(signature::Ed25519KeyPair),
}

impl PrivateKey {
    /// Exports the private key as unencrypted PKCS#8 DER for the signing API.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>, KeyError> {
        // RFC 5958 §2: private keys are wrapped in a OneAsymmetricKey structure.
        match self {
            Self::Rsa(key) => AsDer::<Pkcs8V1Der>::as_der(key).map(|doc| doc.as_ref().to_vec()),
            Self::Ecdsa(key) => key.to_pkcs8v1().map(|doc| doc.as_ref().to_vec()),
            Self::Ed25519(key) => key.to_pkcs8v1().map(|doc| doc.as_ref().to_vec()),
        }
        .map_err(|_| invalid("could not encode PKCS#8 key"))
    }
}

/// A DNSKEY and the corresponding private signing key.
#[derive(Debug)]
pub struct KeyPair {
    pub public: Dnskey,
    pub private: PrivateKey,
}

/// A malformed, unsupported, mismatched, or unreadable key.
#[derive(Debug)]
pub struct KeyError(String);

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KeyError {}

fn invalid(message: &str) -> KeyError {
    KeyError(message.to_owned())
}

fn refuse_sha1(algorithm: u8) -> Result<(), KeyError> {
    // RFC 9905 §2: RSASHA1 and RSASHA1-NSEC3-SHA1 MUST NOT be used to create RRSIG records.
    if matches!(algorithm, 5 | 7) {
        return Err(KeyError(format!(
            "DNSSEC algorithm {algorithm} (SHA-1) must not be used for signing (RFC 9905 §2); \
             perform an algorithm rollover to 8, 13 or 15 (RFC 6781 §4.1.4)"
        )));
    }
    Ok(())
}

impl KeyPair {
    /// Reads a `.key` file and a BIND `.private` file.
    pub fn from_files(
        public: impl AsRef<Path>,
        private: impl AsRef<Path>,
    ) -> Result<Self, KeyError> {
        let public = fs::read_to_string(public).map_err(|e| KeyError(e.to_string()))?;
        let private = fs::read_to_string(private).map_err(|e| KeyError(e.to_string()))?;
        parse_key_pair(&public, &private)
    }
}

/// Parses one DNSKEY record and its BIND v1.2/v1.3 private key.
pub fn parse_key_pair(public: &str, private: &str) -> Result<KeyPair, KeyError> {
    let public = parse_dnskey(public)?;
    refuse_sha1(public.algorithm)?;
    let mut fields = HashMap::new();
    for line in private.lines() {
        let line = line.split(';').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| invalid("invalid private-key field"))?;
        if fields
            .insert(key.trim().to_ascii_lowercase(), value.trim())
            .is_some()
        {
            return Err(invalid("duplicate private-key field"));
        }
    }
    if !matches!(fields.get("private-key-format"), Some(&"v1.2" | &"v1.3")) {
        return Err(invalid("unsupported private-key format"));
    }
    let algorithm = fields
        .get("algorithm")
        .and_then(|v| v.split_whitespace().next())
        .and_then(|v| v.parse::<u8>().ok())
        .ok_or_else(|| invalid("invalid private-key algorithm"))?;
    if algorithm != public.algorithm {
        return Err(invalid("DNSKEY and private-key algorithms differ"));
    }
    let field = |name: &str| -> Result<Vec<u8>, KeyError> {
        let value = fields
            .get(name)
            .ok_or_else(|| invalid("missing private-key field"))?;
        STANDARD
            .decode(value)
            .map_err(|_| invalid("invalid private-key base64"))
    };
    let private = match algorithm {
        8 | 10 => {
            // RFC 8017 Appendix A.1.2: RSAPrivateKey is a sequence of nine integers.
            let mut body = vec![2, 1, 0];
            for name in [
                "modulus",
                "publicexponent",
                "privateexponent",
                "prime1",
                "prime2",
                "exponent1",
                "exponent2",
                "coefficient",
            ] {
                body.extend(der_integer(&field(name)?)?);
            }
            PrivateKey::Rsa(
                signature::RsaKeyPair::from_der(&der(0x30, &body))
                    .map_err(|_| invalid("invalid RSA private key"))?,
            )
        }
        13 | 14 => {
            // RFC 6605 §4: ECDSA DNSKEY public keys are the concatenated X and Y coordinates.
            let mut point = vec![4];
            point.extend_from_slice(&public.public_key);
            let key = signature::EcdsaKeyPair::from_private_key_and_public_key(
                ecdsa_algorithm(algorithm)?,
                &field("privatekey")?,
                &point,
            )
            .map_err(|_| invalid("invalid or mismatched ECDSA key"))?;
            PrivateKey::Ecdsa(key)
        }
        15 => {
            // RFC 8032 §5.1.5: an Ed25519 private key seed is 32 octets.
            let seed = field("privatekey")?;
            if seed.len() != 32 {
                return Err(invalid("invalid Ed25519 seed length"));
            }
            PrivateKey::Ed25519(
                signature::Ed25519KeyPair::from_seed_unchecked(&seed)
                    .map_err(|_| invalid("invalid Ed25519 private key"))?,
            )
        }
        _ => return Err(invalid("unsupported DNSSEC algorithm")),
    };
    validate_pair(public, private)
}

/// Parses a DNSKEY record with an unencrypted PKCS#8 DER or PEM private key.
pub fn parse_pkcs8(public: &str, private: &[u8]) -> Result<KeyPair, KeyError> {
    let public = parse_dnskey(public)?;
    refuse_sha1(public.algorithm)?;
    // RFC 7468 §10: a PKCS#8 PEM uses the PRIVATE KEY textual label.
    let decoded;
    let private = if private.starts_with(b"-----BEGIN") {
        let text = std::str::from_utf8(private)
            .map_err(|_| invalid("invalid PEM"))?
            .trim();
        let body = text
            .strip_prefix("-----BEGIN PRIVATE KEY-----")
            .and_then(|s| s.strip_suffix("-----END PRIVATE KEY-----"))
            .ok_or_else(|| invalid("invalid PKCS#8 PEM"))?;
        decoded = STANDARD
            .decode(body.split_whitespace().collect::<String>())
            .map_err(|_| invalid("invalid PEM base64"))?;
        decoded.as_slice()
    } else {
        private
    };
    // RFC 5958 §2: the algorithm identifier determines the private key representation.
    let private = match public.algorithm {
        8 | 10 => PrivateKey::Rsa(
            signature::RsaKeyPair::from_pkcs8(private)
                .map_err(|_| invalid("invalid RSA PKCS#8"))?,
        ),
        13 | 14 => PrivateKey::Ecdsa(
            signature::EcdsaKeyPair::from_pkcs8(ecdsa_algorithm(public.algorithm)?, private)
                .map_err(|_| invalid("invalid ECDSA PKCS#8"))?,
        ),
        15 => PrivateKey::Ed25519(
            signature::Ed25519KeyPair::from_pkcs8(private)
                .map_err(|_| invalid("invalid Ed25519 PKCS#8"))?,
        ),
        _ => return Err(invalid("unsupported DNSSEC algorithm")),
    };
    validate_pair(public, private)
}

fn ecdsa_algorithm(algorithm: u8) -> Result<&'static signature::EcdsaSigningAlgorithm, KeyError> {
    match algorithm {
        13 => Ok(&signature::ECDSA_P256_SHA256_FIXED_SIGNING),
        14 => Ok(&signature::ECDSA_P384_SHA384_FIXED_SIGNING),
        _ => Err(invalid("unsupported ECDSA algorithm")),
    }
}

fn validate_pair(public: Dnskey, private: PrivateKey) -> Result<KeyPair, KeyError> {
    let matches = match &private {
        PrivateKey::Rsa(key) => rsa_public_der(&public.public_key)? == key.public_key().as_ref(),
        PrivateKey::Ecdsa(key) => {
            key.public_key().as_ref().strip_prefix(&[4]) == Some(public.public_key.as_slice())
        }
        PrivateKey::Ed25519(key) => key.public_key().as_ref() == public.public_key,
    };
    if !matches {
        return Err(invalid("DNSKEY and private key do not match"));
    }
    Ok(KeyPair { public, private })
}

/// Parses a single DNSKEY presentation-format record.
pub fn parse_dnskey(input: &str) -> Result<Dnskey, KeyError> {
    // shortcut: only standalone DNSKEY records are supported; switch to the #46 zone parser when available.
    let mut text = String::new();
    for line in input.lines() {
        text.push_str(line.split(';').next().unwrap_or(""));
        text.push(' ');
    }
    // RFC 1035 §5.1: parentheses group a logical record across lines.
    let mut in_group = false;
    for byte in text.bytes() {
        match byte {
            b'(' if !in_group => in_group = true,
            b')' if in_group => in_group = false,
            b'(' | b')' => return Err(invalid("invalid DNSKEY parentheses")),
            _ => {}
        }
    }
    if in_group {
        return Err(invalid("unterminated DNSKEY parentheses"));
    }
    let text = text.replace(['(', ')'], " ");
    let tokens: Vec<_> = text.split_whitespace().collect();
    let index = tokens
        .iter()
        .position(|t| t.eq_ignore_ascii_case("DNSKEY"))
        .ok_or_else(|| invalid("no DNSKEY record"))?;
    if !(1..=3).contains(&index) || tokens.len() < index + 5 {
        return Err(invalid("invalid DNSKEY record"));
    }
    let owner = tokens[0]
        .parse()
        .map_err(|_| invalid("invalid DNSKEY owner"))?;
    let mut ttl = None;
    let mut class_seen = false;
    for token in &tokens[1..index] {
        if token.eq_ignore_ascii_case("IN") && !class_seen {
            class_seen = true;
        } else if ttl.is_none() {
            ttl = Some(
                token
                    .parse()
                    .map_err(|_| invalid("invalid DNSKEY TTL or class"))?,
            );
        } else {
            return Err(invalid("invalid DNSKEY header"));
        }
    }
    let flags = tokens[index + 1]
        .parse()
        .map_err(|_| invalid("invalid DNSKEY flags"))?;
    let protocol = tokens[index + 2]
        .parse()
        .map_err(|_| invalid("invalid DNSKEY protocol"))?;
    let algorithm = tokens[index + 3]
        .parse()
        .map_err(|_| invalid("invalid DNSKEY algorithm"))?;
    // RFC 4034 §2.1.2: the DNSKEY protocol field MUST be 3.
    if protocol != 3 {
        return Err(invalid("DNSKEY protocol must be 3"));
    }
    let public_key = STANDARD
        .decode(tokens[index + 4..].concat())
        .map_err(|_| invalid("invalid DNSKEY base64"))?;
    if public_key.is_empty() {
        return Err(invalid("empty DNSKEY public key"));
    }
    Ok(Dnskey {
        owner,
        ttl,
        flags,
        protocol,
        algorithm,
        public_key,
    })
}

// RFC 3110 §2: RSA DNSKEY contains an exponent length, exponent, and modulus.
fn rsa_public_der(public: &[u8]) -> Result<Vec<u8>, KeyError> {
    let (length, start) = match public.first() {
        Some(0) if public.len() >= 3 => (
            usize::from(u16::from_be_bytes([public[1], public[2]])),
            3usize,
        ),
        Some(&n) if n != 0 => (usize::from(n), 1),
        _ => return Err(invalid("invalid RSA DNSKEY exponent length")),
    };
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("invalid RSA DNSKEY"))?;
    if length == 0 || end >= public.len() {
        return Err(invalid("invalid RSA DNSKEY"));
    }
    let mut body = der_integer(&public[end..])?;
    body.extend(der_integer(&public[start..end])?);
    Ok(der(0x30, &body))
}

// ITU-T X.690 §8.3: DER integers use minimal signed two's-complement representation.
fn der_integer(bytes: &[u8]) -> Result<Vec<u8>, KeyError> {
    let start = bytes
        .iter()
        .position(|&b| b != 0)
        .ok_or_else(|| invalid("zero RSA component"))?;
    let bytes = &bytes[start..];
    let mut value = Vec::with_capacity(bytes.len() + 1);
    if bytes[0] & 0x80 != 0 {
        value.push(0);
    }
    value.extend_from_slice(bytes);
    Ok(der(2, &value))
}

// ITU-T X.690 §8.1.3: DER length uses short or minimal long form.
fn der(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if body.len() < 128 {
        out.push(body.len() as u8);
    } else {
        let length = body.len().to_be_bytes();
        let start = length
            .iter()
            .position(|&b| b != 0)
            .unwrap_or(length.len() - 1);
        out.push(0x80 | (length.len() - start) as u8);
        out.extend_from_slice(&length[start..]);
    }
    out.extend_from_slice(body);
    out
}
