use pharos_dnssec::keys::{KeyPair, parse_key_pair};
use serde::{Deserialize, Deserializer, de::MapAccess};

#[derive(Default)]
struct Secret {
    key: String,
    private: String,
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Secret;

            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a Secrets Manager key object")
            }

            fn visit_map<M: MapAccess<'de>>(self, mut map: M) -> Result<Secret, M::Error> {
                let mut secret = Secret::default();
                while let Some(field) = map.next_key::<String>()? {
                    // Go JSON accepts Unicode case folds, including the Kelvin sign.
                    let target =
                        if field.eq_ignore_ascii_case("key") || field.to_lowercase() == "key" {
                            Some(&mut secret.key)
                        } else if field.eq_ignore_ascii_case("private") {
                            Some(&mut secret.private)
                        } else {
                            None
                        };
                    if let Some(target) = target {
                        if let Some(value) = map.next_value::<Option<String>>()? {
                            *target = value;
                        }
                    } else {
                        map.next_value::<serde::de::IgnoredAny>()?;
                    }
                }
                Ok(secret)
            }
        }

        deserializer.deserialize_map(Visitor)
    }
}

fn parse_secret(secret: &str) -> Result<KeyPair, String> {
    let secret: Secret =
        serde_json::from_str(secret).map_err(|_| "invalid Secrets Manager key JSON".to_owned())?;
    parse_key_pair(&secret.key, &secret.private).map_err(|e| format!("invalid DNSSEC key: {e}"))
}

pub(super) fn load(secret_id: &str) -> Result<KeyPair, String> {
    // Setup is synchronous and may already run inside a Tokio runtime.
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .spawn_scoped(scope, || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("cannot create AWS runtime: {e}"))?;
                runtime.block_on(async {
                    let config =
                        aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                    let output = aws_sdk_secretsmanager::Client::new(&config)
                        .get_secret_value()
                        .secret_id(secret_id)
                        .send()
                        .await
                        .map_err(|e| format!("cannot retrieve AWS secret: {e}"))?;
                    let secret = output
                        .secret_string()
                        .ok_or("AWS secret must be a string")?;
                    parse_secret(secret)
                })
            })
            .map_err(|e| format!("cannot start AWS secret loader: {e}"))?
            .join()
            .map_err(|_| "AWS secret loader panicked".to_owned())?
    })
}

#[cfg(test)]
mod tests {
    use super::parse_secret;

    const PUBLIC: &str = include_str!("../../tests/fixtures/dnssec/Kmiek.nl.+013+59725.key");
    const PRIVATE: &str = include_str!("../../tests/fixtures/dnssec/Kmiek.nl.+013+59725.private");

    #[test]
    fn parses_coredns_secret_json_without_network() {
        let secret = serde_json::json!({ "key": PUBLIC, "private": PRIVATE }).to_string();
        let pair = parse_secret(&secret).unwrap();
        assert_eq!(pair.public.owner.to_string(), "miek.nl.");
        assert_eq!(pair.public.algorithm, 13);
    }

    #[test]
    fn accepts_case_insensitive_and_repeated_secret_fields() {
        let public = serde_json::to_string(PUBLIC).unwrap();
        let private = serde_json::to_string(PRIVATE).unwrap();
        let secret = format!(r#"{{"KEY":"bad","Key":{public},"key":null,"PRIVATE":{private}}}"#);
        assert_eq!(parse_secret(&secret).unwrap().public.algorithm, 13);
        let secret = format!(r#"{{"Key":{public},"private":{private}}}"#);
        assert_eq!(parse_secret(&secret).unwrap().public.algorithm, 13);
    }

    #[test]
    fn rejects_sha1_keys_in_secrets() {
        for algorithm in [5, 7] {
            let public = PUBLIC.replace("257 3 13", &format!("257 3 {algorithm}"));
            let secret = serde_json::json!({ "key": public, "private": PRIVATE }).to_string();
            let error = parse_secret(&secret).unwrap_err();
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
            let error = parse_secret(secret).unwrap_err();
            assert!(!error.contains("secret-marker"));
        }
        let missing_private = serde_json::json!({ "key": PUBLIC }).to_string();
        assert!(parse_secret(&missing_private).is_err());
        assert!(parse_secret(r#"{"key":5,"private":""}"#).is_err());
    }

    #[test]
    fn ignores_lone_surrogates_in_unknown_secret_fields() {
        let public = serde_json::to_string(PUBLIC).unwrap();
        let private = serde_json::to_string(PRIVATE).unwrap();
        let secret = format!(r#"{{"key":{public},"private":{private},"unused":"\ud800"}}"#);
        assert!(parse_secret(&secret).is_ok());
    }

    #[test]
    fn rejects_lone_surrogates_in_key_strings() {
        let public = serde_json::to_string(PUBLIC).unwrap();
        let private = serde_json::to_string(PRIVATE).unwrap();
        let private = format!(r#"{}\n;\ud800""#, &private[..private.len() - 1]);
        let secret = format!(r#"{{"key":{public},"private":{private}}}"#);
        assert!(parse_secret(&secret).is_err());
    }
}
