use std::collections::HashMap;
use std::fmt;

use base64::Engine;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};

/// An invalid TSIG secret or BIND key file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TsigKeyError {
    MissingKeyName { line: usize },
    DuplicateKey { name: String },
    MissingSecret { line: usize },
    UnexpectedToken { line: usize },
    InvalidBase64,
}

impl fmt::Display for TsigKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingKeyName { line } => write!(f, "missing key name on line {line}"),
            Self::DuplicateKey { name } => write!(f, "key {name:?} redefined"),
            Self::MissingSecret { line } => write!(f, "missing secret for key on line {line}"),
            Self::UnexpectedToken { line } => write!(f, "unexpected token on line {line}"),
            Self::InvalidBase64 => f.write_str("invalid Base64 secret"),
        }
    }
}

impl std::error::Error for TsigKeyError {}

/// Decode a standard Base64 TSIG secret.
pub fn decode_secret(secret: &str) -> Result<Vec<u8>, TsigKeyError> {
    // RFC 4648 §4: use the standard Base64 alphabet and padding.
    // Go's standard decoder also ignores CR/LF and accepts non-zero trailing bits.
    let engine = GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        GeneralPurposeConfig::new()
            .with_decode_padding_mode(DecodePaddingMode::RequireCanonical)
            .with_decode_allow_trailing_bits(true),
    );
    let secret = secret.replace(['\r', '\n'], "");
    engine
        .decode(secret)
        .map_err(|_| TsigKeyError::InvalidBase64)
}

/// Encode a TSIG secret using standard padded Base64.
pub fn encode_secret(secret: &[u8]) -> String {
    // RFC 4648 §§3.1,3.2,3.5,4: Encode standard Base64 with padding and zero pad bits.
    STANDARD.encode(secret)
}

/// Parse the line-oriented BIND key-file format accepted by CoreDNS.
///
/// The map contains normalized key names and their still-encoded secrets. Algorithm
/// lines are ignored, as in CoreDNS; use `decode_secret` when loading a key.
pub fn parse_key_file(input: &str) -> Result<HashMap<String, String>, TsigKeyError> {
    let mut secrets = HashMap::new();
    let mut lines = input.lines().enumerate();
    while let Some((index, line)) = lines.next() {
        let mut fields = line.split_whitespace();
        let Some(token) = fields.next() else { continue };
        if token != "key" {
            return Err(TsigKeyError::UnexpectedToken { line: index + 1 });
        }
        let key = fields.next().unwrap_or("").trim_matches(['"', '{']);
        if key.is_empty() {
            return Err(TsigKeyError::MissingKeyName { line: index + 1 });
        }
        let mut key = key.to_lowercase();
        // RFC 1035 §5.1: a final unescaped dot marks an absolute domain name.
        let absolute = key.strip_suffix('.').is_some_and(|prefix| {
            prefix
                .as_bytes()
                .iter()
                .rev()
                .take_while(|&&b| b == b'\\')
                .count()
                % 2
                == 0
        });
        if !absolute {
            key.push('.');
        }
        if secrets.contains_key(&key) {
            return Err(TsigKeyError::DuplicateKey { name: key });
        }
        for (inner_index, inner) in lines.by_ref() {
            let mut fields = inner.split_whitespace();
            match fields.next() {
                None | Some("algorithm") => {}
                Some("secret") => {
                    let secret = fields.next().unwrap_or("").trim_matches(['"', ';']);
                    if secret.is_empty() {
                        return Err(TsigKeyError::MissingSecret {
                            line: inner_index + 1,
                        });
                    }
                    secrets.insert(key.clone(), secret.to_owned());
                }
                Some("}" | "};") => break,
                Some(_) => {
                    return Err(TsigKeyError::UnexpectedToken {
                        line: inner_index + 1,
                    });
                }
            }
        }
        if !secrets.contains_key(&key) {
            return Err(TsigKeyError::MissingSecret { line: index + 1 });
        }
    }
    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_file_normalizes_names_and_keeps_encoded_secrets() {
        let keys = parse_key_file(
            "key \"Mixed.Example\" {\n algorithm hmac-sha256;\n secret \"c2VjcmV0\";\n};\n",
        )
        .unwrap();
        assert_eq!(
            keys.get("mixed.example.").map(String::as_str),
            Some("c2VjcmV0")
        );
    }

    #[test]
    fn base64_secret_round_trips_and_rejects_invalid_encoding() {
        assert_eq!(decode_secret("c2VjcmV0").unwrap(), b"secret");
        assert_eq!(encode_secret(b"secret"), "c2VjcmV0");
        assert!(decode_secret("c2VjcmV0!").is_err());
    }

    #[test]
    fn base64_matches_standard_go_decoder() {
        assert_eq!(decode_secret("/x=\r\n=").unwrap(), [255]);
        assert_eq!(encode_secret(&[255]), "/w==");
        assert!(decode_secret("/w").is_err());
        assert!(decode_secret("/w== ").is_err());
        assert!(decode_secret("/w==AAAA").is_err());
    }

    #[test]
    fn key_file_rejects_duplicates_and_malformed_entries() {
        let duplicate = "key KEY {\n secret YQ==;\n};\nkey key. {\n secret Yg==;\n};";
        assert_eq!(
            parse_key_file(duplicate),
            Err(TsigKeyError::DuplicateKey {
                name: "key.".into()
            })
        );
        for input in [
            "key {",
            "bad key",
            "key a {\n secret\n}",
            "key a {\n}",
            "key a {\n other ignored\n}",
        ] {
            assert!(parse_key_file(input).is_err(), "{input:?}");
        }
    }

    #[test]
    fn key_file_accepts_coredns_line_oriented_quirks() {
        let keys = parse_key_file(
            "\nkey NAME\\. {\n algorithm anything\n secret first;\n secret second;\n",
        )
        .unwrap();
        assert_eq!(keys.get("name\\.."), Some(&"second".to_owned()));
        assert!(parse_key_file("").unwrap().is_empty());
    }

    #[test]
    fn key_file_reads_multiple_keys() {
        let keys =
            parse_key_file("key one {\n secret YQ==;\n};\nkey TWO. {\n secret Yg==;\n}\n").unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys.get("one.").map(String::as_str), Some("YQ=="));
        assert_eq!(keys.get("two.").map(String::as_str), Some("Yg=="));
    }
}
