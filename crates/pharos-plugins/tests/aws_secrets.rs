#![cfg(feature = "dnssec-aws")]

#[path = "../src/dnssec/aws.rs"]
#[allow(dead_code)]
mod aws;

const PUBLIC: &str = include_str!("dnssec-fixtures/Kmiek.nl.+013+59725.key");
const PRIVATE: &str = include_str!("dnssec-fixtures/Kmiek.nl.+013+59725.private");

#[test]
fn parses_coredns_secret_json_without_network() {
    let secret = serde_json::json!({ "key": PUBLIC, "private": PRIVATE }).to_string();
    let pair = aws::parse_secret(&secret).unwrap();
    assert_eq!(pair.public.owner.to_string(), "miek.nl.");
    assert_eq!(pair.public.algorithm, 13);
}

#[test]
fn rejects_invalid_secret_without_exposing_it() {
    for secret in [
        "not json",
        "{}",
        r#"{"key":"secret-marker","private":"bad"}"#,
    ] {
        let error = aws::parse_secret(secret).unwrap_err();
        assert!(!error.contains("secret-marker"));
    }
}
