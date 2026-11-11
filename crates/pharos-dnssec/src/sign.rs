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

enum Key {
    Rsa(RsaKeyPair, &'static dyn signature::RsaEncoding),
    Ecdsa(EcdsaKeyPair),
    Ed25519(Ed25519KeyPair),
}

/// A parsed private key, reusable for signing multiple canonical RRsets.
pub struct SigningKey(Key);

impl SigningKey {
    /// Use a parsed RSA private key with DNSSEC algorithm 8 or 10.
    pub fn from_rsa(algorithm: u8, key: RsaKeyPair) -> Result<Self, SignError> {
        // RFC 5702 §3: algorithm 8 uses SHA-256 and algorithm 10 uses SHA-512.
        let encoding: &'static dyn signature::RsaEncoding = match algorithm {
            8 => &signature::RSA_PKCS1_SHA256,
            10 => &signature::RSA_PKCS1_SHA512,
            _ => return Err(SignError::UnsupportedAlgorithm(algorithm)),
        };
        Ok(Self(Key::Rsa(key, encoding)))
    }

    /// Use a parsed ECDSA key whose curve and encoding match algorithm 13 or 14.
    pub fn from_ecdsa(algorithm: u8, key: EcdsaKeyPair) -> Result<Self, SignError> {
        // RFC 6605 §4: ECDSA signatures use the curve-specific fixed-width format.
        let expected = match algorithm {
            13 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            14 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => return Err(SignError::UnsupportedAlgorithm(algorithm)),
        };
        if key.algorithm() != expected {
            return Err(SignError::InvalidKey);
        }
        Ok(Self(Key::Ecdsa(key)))
    }

    /// Use a parsed Ed25519 private key for DNSSEC algorithm 15.
    pub fn from_ed25519(key: Ed25519KeyPair) -> Self {
        Self(Key::Ed25519(key))
    }

    /// Parse an unencrypted DER PKCS#8 private key for a DNSSEC algorithm number.
    ///
    /// Supported algorithms are 8, 10, 13, 14 and 15. Algorithms 5 and 7 are
    /// unavailable because aws-lc-rs does not expose RSA/SHA-1 signing. RSA
    /// keys must be 2048–8192 bits, as required by aws-lc-rs.
    pub fn from_pkcs8(algorithm: u8, der: &[u8]) -> Result<Self, SignError> {
        // RFC 5702 §3, RFC 6605 §4 and RFC 8080 §3: DNSSEC algorithm numbers.
        match algorithm {
            8 | 10 => {
                let key = RsaKeyPair::from_pkcs8(der).map_err(|_| SignError::InvalidKey)?;
                Self::from_rsa(algorithm, key)
            }
            13 | 14 => {
                let encoding = match algorithm {
                    13 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
                    _ => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
                };
                let key =
                    EcdsaKeyPair::from_pkcs8(encoding, der).map_err(|_| SignError::InvalidKey)?;
                Self::from_ecdsa(algorithm, key)
            }
            15 => Ok(Self::from_ed25519(
                Ed25519KeyPair::from_pkcs8(der).map_err(|_| SignError::InvalidKey)?,
            )),
            _ => Err(SignError::UnsupportedAlgorithm(algorithm)),
        }
    }

    /// Sign the complete canonical RRSIG input, including the RRSIG fields.
    ///
    /// The caller must construct and canonicalize the input as specified by
    /// RFC 4034 §3.1.8; this function does not hash it in advance.
    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, SignError> {
        let random = SystemRandom::new();
        match &self.0 {
            // RFC 5702 §3: RSA signatures use RSASSA-PKCS1-v1_5.
            Key::Rsa(key, encoding) => {
                let mut output = vec![0; key.public_modulus_len()];
                key.sign(*encoding, &random, data, &mut output)
                    .map_err(|_| SignError::SigningFailed)?;
                Ok(output)
            }
            // RFC 6605 §4: ECDSA signatures are fixed-width r || s, not DER.
            Key::Ecdsa(key) => key
                .sign(&random, data)
                .map(|signature| signature.as_ref().to_vec())
                .map_err(|_| SignError::SigningFailed),
            // RFC 8080 §3: the Ed25519 signature is encoded directly.
            Key::Ed25519(key) => Ok(key.sign(data).as_ref().to_vec()),
        }
    }
}
