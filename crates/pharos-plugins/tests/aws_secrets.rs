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
fn accepts_case_insensitive_and_repeated_secret_fields() {
    let public = serde_json::to_string(PUBLIC).unwrap();
    let private = serde_json::to_string(PRIVATE).unwrap();
    let secret = format!(r#"{{"KEY":"bad","Key":{public},"key":null,"PRIVATE":{private}}}"#);
    assert_eq!(aws::parse_secret(&secret).unwrap().public.algorithm, 13);
}

#[test]
fn rejects_sha1_keys_in_secrets() {
    for algorithm in [5, 7] {
        let public = PUBLIC.replace("257 3 13", &format!("257 3 {algorithm}"));
        let secret = serde_json::json!({ "key": public, "private": PRIVATE }).to_string();
        let error = aws::parse_secret(&secret).unwrap_err();
        assert!(error.contains("SHA-1"));
    }
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
    let missing_private = serde_json::json!({ "key": PUBLIC }).to_string();
    assert!(aws::parse_secret(&missing_private).is_err());
    assert!(aws::parse_secret(r#"{"key":5,"private":""}"#).is_err());
}
