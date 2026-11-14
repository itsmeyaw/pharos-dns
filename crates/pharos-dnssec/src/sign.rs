//! Sign pre-canonicalized RRSIG data using DNSSEC wire-format signatures.

use std::fmt;

use aws_lc_rs::{
    rand::SystemRandom,
    signature::{self, RsaKeyPair},
};
use ed25519_dalek::{Signer as _, pkcs8::DecodePrivateKey as _};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::{Digest, Sha256, Sha384};

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
    P256(p256::ecdsa::SigningKey),
    P384(p384::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
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
            // RFC 9904 §3; RFC 6605 §4: P-256 signatures use fixed-width r || s output.
            13 => p256::ecdsa::SigningKey::from_pkcs8_der(der)
                .map(|key| Self(Key::P256(key)))
                .map_err(|_| SignError::InvalidKey),
            // RFC 9904 §3; RFC 6605 §4: P-384 signatures use fixed-width r || s output.
            14 => p384::ecdsa::SigningKey::from_pkcs8_der(der)
                .map(|key| Self(Key::P384(key)))
                .map_err(|_| SignError::InvalidKey),
            // RFC 9904 §3: Support algorithm 15, recommended for DNSSEC signing.
            15 => ed25519_dalek::SigningKey::from_pkcs8_der(der)
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
        let mut output = vec![0; self.signature_len()];
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
            // RFC 6605 §4; RFC 6979 §3.3: P-256 uses fixed-width, deterministic ECDSA.
            Key::P256(key) => {
                let digest = Sha256::digest(data);
                let signature: p256::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| SignError::SigningFailed)?;
                let signature = signature.to_bytes();
                if output.len() < signature.len() {
                    return Err(SignError::SigningFailed);
                }
                output[..signature.len()].copy_from_slice(&signature);
                Ok(signature.len())
            }
            // RFC 6605 §4; RFC 6979 §3.3: P-384 uses fixed-width, deterministic ECDSA.
            Key::P384(key) => {
                let digest = Sha384::digest(data);
                let signature: p384::ecdsa::Signature = key
                    .sign_prehash(&digest)
                    .map_err(|_| SignError::SigningFailed)?;
                let signature = signature.to_bytes();
                if output.len() < signature.len() {
                    return Err(SignError::SigningFailed);
                }
                output[..signature.len()].copy_from_slice(&signature);
                Ok(signature.len())
            }
            // RFC 8080 §4: The Ed25519 signature is encoded directly.
            // RFC 8032 §5.1.6: Sign the complete message with Ed25519.
            Key::Ed25519(key) => {
                let signature = key.sign(data).to_bytes();
                if output.len() < signature.len() {
                    return Err(SignError::SigningFailed);
                }
                output[..signature.len()].copy_from_slice(&signature);
                Ok(signature.len())
            }
        }
    }

    fn signature_len(&self) -> usize {
        match &self.0 {
            Key::Rsa(key, _) => key.public_modulus_len(),
            Key::P256(_) => 64,
            Key::P384(_) => 96,
            Key::Ed25519(_) => 64,
        }
    }
}
