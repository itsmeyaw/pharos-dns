use pharos_dnssec::keys::{KeyPair, parse_key_pair};
use serde::Deserialize;

#[derive(Deserialize)]
struct Secret {
    key: String,
    private: String,
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
