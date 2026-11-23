//! Fixtures shared by the credential source tests.

use std::sync::OnceLock;

use aws_lc_rs::{
    encoding::AsDer,
    rsa::KeySize,
    signature::{KeyPair, RSA_PKCS1_2048_8192_SHA256, RsaKeyPair, UnparsedPublicKey},
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};

pub(super) struct TestKey {
    /// A PKCS#8 "PRIVATE KEY" PEM, as Google key files carry it.
    pub pem: String,
    /// The PKCS#1 RSAPublicKey DER the verifier takes.
    pub public: Vec<u8>,
}

/// One RSA key per test process: generation is slow.
pub(super) fn rsa_key() -> &'static TestKey {
    static KEY: OnceLock<TestKey> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = RsaKeyPair::generate(KeySize::Rsa2048).unwrap();
        let der = key.as_der().unwrap();
        let body = STANDARD.encode(der.as_ref());
        let lines: Vec<&str> = body
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect();
        TestKey {
            pem: format!(
                "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                lines.join("\n")
            ),
            public: key.public_key().as_ref().to_vec(),
        }
    })
}

/// A `service_account` key file pointing at `token_uri`.
pub(super) fn service_account_file(token_uri: &str) -> Value {
    json!({
        "type": "service_account",
        "project_id": "p",
        "private_key_id": "key-id-1",
        "private_key": rsa_key().pem,
        "client_email": "robot@p.iam.gserviceaccount.com",
        "token_uri": token_uri,
    })
}

/// Check an RS256 JWT's signature against `public` and return its header and claims.
pub(super) fn verify_jwt(jwt: &str, public: &[u8]) -> (Value, Value) {
    let (input, signature) = jwt.rsplit_once('.').unwrap();
    let signature = URL_SAFE_NO_PAD.decode(signature).unwrap();
    UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, public)
        .verify(input.as_bytes(), &signature)
        .expect("signature verifies");
    let (header, claims) = input.split_once('.').unwrap();
    let decode = |part: &str| -> Value {
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(part).unwrap()).unwrap()
    };
    (decode(header), decode(claims))
}

/// A token endpoint success body.
pub(crate) fn token_response(token: &str, expires_in: u64) -> Value {
    json!({"access_token": token, "expires_in": expires_in, "token_type": "Bearer"})
}
