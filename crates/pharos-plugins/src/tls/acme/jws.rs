//! JSON Web Signatures (RFC 7515) with ES256 as ACME requests them (RFC 8555 §6.2).

use aws_lc_rs::{
    digest::{SHA256, digest},
    error::Unspecified,
    rand::SystemRandom,
    signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::{Value, json};

/// RFC 7515 §2: base64url without padding.
pub(crate) fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// An ACME account key: P-256 with ECDSA over SHA-256.
pub(crate) struct AccountKey(EcdsaKeyPair);

impl AccountKey {
    pub(crate) fn generate() -> Result<(Self, Vec<u8>), Unspecified> {
        let pkcs8 =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())?;
        let key = Self::from_pkcs8(pkcs8.as_ref()).map_err(|_| Unspecified)?;
        Ok((key, pkcs8.as_ref().to_vec()))
    }

    pub(crate) fn from_pkcs8(pkcs8: &[u8]) -> Result<Self, aws_lc_rs::error::KeyRejected> {
        EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8).map(Self)
    }

    // RFC 7518 §6.2.1: an EC public key is "crv", "x" and "y"; RFC 5480 §2.2: the point is 0x04 || X || Y.
    fn coordinates(&self) -> (String, String) {
        let point = self.0.public_key().as_ref();
        (b64(&point[1..33]), b64(&point[33..65]))
    }

    /// The JWK carried by the header of a newAccount request (RFC 8555 §6.2).
    pub(crate) fn jwk(&self) -> Value {
        let (x, y) = self.coordinates();
        json!({"crv": "P-256", "kty": "EC", "x": x, "y": y})
    }

    /// The base64url SHA-256 thumbprint of the key (RFC 7638 §3).
    pub(crate) fn thumbprint(&self) -> String {
        let (x, y) = self.coordinates();
        // RFC 7638 §3.2: required members in lexicographic order without whitespace.
        let json = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        b64(digest(&SHA256, json.as_bytes()))
    }

    /// RFC 8555 §8.1: the token joined to the account key's thumbprint.
    pub(crate) fn key_authorization(&self, token: &str) -> String {
        format!("{token}.{}", self.thumbprint())
    }

    /// The flattened JWS (RFC 7515 §7.2.2) of `payload`; an empty `payload` is a POST-as-GET (RFC 8555 §6.3).
    pub(crate) fn sign(
        &self,
        identity: Identity<'_>,
        nonce: &str,
        url: &str,
        payload: Option<&Value>,
    ) -> Result<String, Unspecified> {
        // RFC 8555 §6.2: "alg", "nonce" and "url" are required, and exactly one of "jwk" and "kid".
        let mut protected = json!({"alg": "ES256", "nonce": nonce, "url": url});
        match identity {
            Identity::Jwk => protected["jwk"] = self.jwk(),
            Identity::Kid(kid) => protected["kid"] = Value::from(kid),
        }
        let protected = b64(protected.to_string());
        let payload = payload.map_or_else(String::new, |payload| b64(payload.to_string()));
        // RFC 7515 §5.1: the signing input is ASCII(protected "." payload).
        let signature = self.0.sign(
            &SystemRandom::new(),
            format!("{protected}.{payload}").as_bytes(),
        )?;
        Ok(
            json!({"protected": protected, "payload": payload, "signature": b64(signature)})
                .to_string(),
        )
    }
}

/// How a request names its signer (RFC 8555 §6.2).
#[derive(Clone, Copy)]
pub(crate) enum Identity<'a> {
    Jwk,
    Kid(&'a str),
}

#[cfg(test)]
mod tests {
    use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED, UnparsedPublicKey};
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use serde_json::{Value, json};

    use super::{AccountKey, Identity, b64};

    fn decode(text: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(text).unwrap()
    }

    // RFC 7515 Appendix C: base64url drops padding and uses '-' and '_'.
    #[test]
    fn base64url_is_unpadded_and_url_safe() {
        assert_eq!(b64([0xfb, 0xff, 0xfe]), "-__-");
        assert_eq!(b64(b"ab"), "YWI");
        assert_eq!(b64(b""), "");
    }

    // RFC 7515 §A.3: an ES256 JWS carries a 64-octet R || S signature over "protected.payload".
    #[test]
    fn signature_verifies_against_the_jwk() {
        let (key, pkcs8) = AccountKey::generate().unwrap();
        let reloaded = AccountKey::from_pkcs8(&pkcs8).unwrap();
        assert_eq!(key.jwk(), reloaded.jwk());
        let payload = json!({"termsOfServiceAgreed": true});
        let body: Value = serde_json::from_str(
            &key.sign(
                Identity::Jwk,
                "nonce-1",
                "https://ca/new-acct",
                Some(&payload),
            )
            .unwrap(),
        )
        .unwrap();
        let protected = body["protected"].as_str().unwrap();
        let header: Value = serde_json::from_slice(&decode(protected)).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["nonce"], "nonce-1");
        assert_eq!(header["url"], "https://ca/new-acct");
        assert_eq!(header["jwk"], key.jwk());
        assert!(header.get("kid").is_none());
        assert_eq!(
            decode(body["payload"].as_str().unwrap()),
            payload.to_string().as_bytes()
        );

        let signature = decode(body["signature"].as_str().unwrap());
        assert_eq!(signature.len(), 64);
        let mut point = vec![4];
        point.extend(decode(header["jwk"]["x"].as_str().unwrap()));
        point.extend(decode(header["jwk"]["y"].as_str().unwrap()));
        let input = format!("{protected}.{}", body["payload"].as_str().unwrap());
        UnparsedPublicKey::new(&ECDSA_P256_SHA256_FIXED, point)
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    // RFC 8555 §6.3: POST-as-GET has an empty payload; §6.2: an account request names its key by "kid".
    #[test]
    fn post_as_get_has_an_empty_payload_and_a_kid() {
        let (key, _) = AccountKey::generate().unwrap();
        let body: Value = serde_json::from_str(
            &key.sign(
                Identity::Kid("https://ca/acct/1"),
                "n",
                "https://ca/authz/1",
                None,
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(body["payload"], "");
        let header: Value =
            serde_json::from_slice(&decode(body["protected"].as_str().unwrap())).unwrap();
        assert_eq!(header["kid"], "https://ca/acct/1");
        assert!(header.get("jwk").is_none());
    }

    // RFC 7638 §3: the thumbprint hashes the lexicographically ordered members; RFC 8555 §8.1 joins it to the token.
    #[test]
    fn key_authorization_joins_token_and_thumbprint() {
        let (key, _) = AccountKey::generate().unwrap();
        let jwk = key.jwk();
        let json = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk["x"].as_str().unwrap(),
            jwk["y"].as_str().unwrap()
        );
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, json.as_bytes());
        assert_eq!(key.thumbprint(), b64(digest));
        assert_eq!(
            key.key_authorization("tok"),
            format!("tok.{}", key.thumbprint())
        );
    }
}
