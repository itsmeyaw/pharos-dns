//! Sign pre-canonicalized RRSIG data using DNSSEC wire-format signatures.

use std::fmt;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{self, EcdsaKeyPair, Ed25519KeyPair, RsaKeyPair},
};

/// A signing key or signing operation could not be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignError {
    /// The DNSSEC algorithm is not supported for signing.
    UnsupportedAlgorithm(u8),
    /// The PKCS#8 key is malformed or does not match the algorithm.
    InvalidKey,
    /// The cryptographic signing operation failed.
    SigningFailed,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedAlgorithm(algorithm) => {
                write!(f, "unsupported DNSSEC signing algorithm {algorithm}")
            }
            Self::InvalidKey => f.write_str("invalid DNSSEC private key"),
            Self::SigningFailed => f.write_str("DNSSEC signing failed"),
        }
    }
}

impl std::error::Error for SignError {}

/// Verifies an RFC 6605 DNSSEC ECDSA signature against DNSKEY `x || y` public bytes.
#[must_use]
pub fn verify_ecdsa(algorithm: u8, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    // RFC 6605 §4: DNSKEY stores x || y; RRSIG stores fixed-width r || s.
    let (algorithm, coordinate_len, signature_len) = match algorithm {
        13 => (&signature::ECDSA_P256_SHA256_FIXED, 32, 64),
        14 => (&signature::ECDSA_P384_SHA384_FIXED, 48, 96),
        _ => return false,
    };
    if public_key.len() != coordinate_len * 2 || signature.len() != signature_len {
        return false;
    }
    let mut point = [0; 97];
    point[0] = 4;
    let point_len = public_key.len() + 1;
    point[1..point_len].copy_from_slice(public_key);
    signature::UnparsedPublicKey::new(algorithm, &point[..point_len])
        .verify(data, signature)
        .is_ok()
}

enum Key {
    Rsa(RsaKeyPair, &'static dyn signature::RsaEncoding),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// A parsed private key, reusable for signing multiple canonical RRsets.
pub struct SigningKey(Key);

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(<redacted>)")
    }
}

impl SigningKey {
    /// Use a parsed RSA private key with DNSSEC algorithm 8.
    pub fn from_rsa(algorithm: u8, key: RsaKeyPair) -> Result<Self, SignError> {
        // RFC 9904 §3: Do not create signatures with the NOT RECOMMENDED algorithm 10.
        let encoding: &'static dyn signature::RsaEncoding = match algorithm {
            // RFC 9904 §3: Support algorithm 8, required for DNSSEC signing.
            8 => &signature::RSA_PKCS1_SHA256,
            _ => return Err(SignError::UnsupportedAlgorithm(algorithm)),
        };
        // RFC 3110 §2 and RFC 5702 §§2.1–2.2: RSA modulus MUST NOT exceed 4096 bits.
        if key.public_modulus_len() > 512 {
            return Err(SignError::InvalidKey);
        }
        Ok(Self(Key::Rsa(key, encoding)))
    }

    /// Parse an unencrypted DER PKCS#8 private key for a DNSSEC algorithm number.
    ///
    /// Supported algorithms are 8, 13, 14 and 15. Algorithms 5 and 7 are
    /// refused because SHA-1 signing is prohibited; algorithm 10 is rejected as
    /// NOT RECOMMENDED by RFC 9904 §3. RSA keys must be 2048–4096 bits.
    pub fn from_pkcs8(algorithm: u8, der: &[u8]) -> Result<Self, SignError> {
        // RFC 5702 §3, RFC 6605 §4 and RFC 8080 §5: DNSSEC algorithm numbers.
        // RFC 6944 §2.3: RSAMD5 is not implemented for DNSSEC signing.
        match algorithm {
            8 => {
                let key = RsaKeyPair::from_pkcs8(der).map_err(|_| SignError::InvalidKey)?;
                Self::from_rsa(algorithm, key)
            }
            // RFC 9904 §3; RFC 6605 §4: ECDSA signatures use fixed-width r || s output.
            13 | 14 => {
                let encoding = match algorithm {
                    13 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    _ => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                };
                EcdsaKeyPair::from_pkcs8(encoding, der)
                    .map(|key| Self(Key::Ecdsa(key)))
                    .map_err(|_| SignError::InvalidKey)
            }
            // RFC 9904 §3: Support algorithm 15, recommended for DNSSEC signing.
            15 => Ed25519KeyPair::from_pkcs8(der)
                .map(|key| Self(Key::Ed25519(key)))
                .map_err(|_| SignError::InvalidKey),
            _ => Err(SignError::UnsupportedAlgorithm(algorithm)),
        }
    }

    /// Sign the complete canonical RRSIG input, including the RRSIG fields.
    ///
    /// The caller must construct and canonicalize the input as specified by
    /// RFC 4034 §3.1.8; this function does not hash it in advance.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        // RFC 5702 §2.2: RSA modulus is at most 4096 bits, so no signature exceeds 512 octets.
        let mut output = vec![0; 512];
        let len = self.sign_into(data, &mut output)?;
        output.truncate(len);
        Ok(output)
    }

    /// Signs into caller-owned storage and returns the signature length.
    pub fn sign_into(&self, data: &[u8], output: &mut [u8]) -> Result<usize, SignError> {
        let random = SystemRandom::new();
        match &self.0 {
            // RFC 8017 §9.2: RSA PKCS#1 v1.5 encodes the hash as DER DigestInfo with FF padding.
            // RFC 5702 §3: RSA signatures use RSASSA-PKCS1-v1_5.
            // RFC 8017 §8.2: RSASSA-PKCS1-v1_5 combines RSASP1 with EMSA-PKCS1-v1_5.
            Key::Rsa(key, encoding) => {
                // RFC 8017 §4.1: RSA signatures use fixed-length integer-to-octet conversion.
                // shortcut: aws-lc-rs allocates a temporary signature Vec; switch backend if RSA must not allocate.
                let len = key.public_modulus_len();
                if output.len() < len {
                    return Err(SignError::SigningFailed);
                }
                // RFC 8017 §5.2.1: The RSA signature primitive uses the private key.
                key.sign(*encoding, &random, data, &mut output[..len])
                    .map_err(|_| SignError::SigningFailed)?;
                Ok(len)
            }
            // RFC 6605 §4: ECDSA signatures are fixed-width r || s, not DER.
            Key::Ecdsa(key) => copy_signature(key.sign(&random, data), output),
            // RFC 8080 §4: The Ed25519 signature is encoded directly.
            // RFC 8032 §5.1.6: Sign the complete message with Ed25519.
            Key::Ed25519(key) => copy_signature(Ok(key.sign(data)), output),
        }
    }
}

fn copy_signature(
    signature: Result<signature::Signature, aws_lc_rs::error::Unspecified>,
    output: &mut [u8],
) -> Result<usize, SignError> {
    let signature = signature.map_err(|_| SignError::SigningFailed)?;
    let signature = signature.as_ref();
    output
        .get_mut(..signature.len())
        .ok_or(SignError::SigningFailed)?
        .copy_from_slice(signature);
    Ok(signature.len())
}
