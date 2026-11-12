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

pub(super) fn parse_secret(secret: &str) -> Result<KeyPair, String> {
    let secret: Secret =
        serde_json::from_str(secret).map_err(|_| "invalid Secrets Manager key JSON".to_owned())?;
    parse_key_pair(&secret.key, &secret.private).map_err(|e| format!("invalid DNSSEC key: {e}"))
}

pub(super) fn load(secret_id: &str) -> Result<KeyPair, String> {
    // Setup is synchronous and may already run inside a Tokio runtime.
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
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
            .join()
            .map_err(|_| "AWS secret loader panicked".to_owned())?
    })
}
