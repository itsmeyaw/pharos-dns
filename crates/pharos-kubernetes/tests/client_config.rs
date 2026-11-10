use pharos_kubernetes::{ClientConfig, TlsConfig};
use std::fs;

#[tokio::test]
async fn kubeconfig_context_takes_precedence_over_endpoint() {
    let dir = tempfile::tempdir().unwrap();
    let config = dir.path().join("config");
    fs::write(
        &config,
        r#"
apiVersion: v1
kind: Config
clusters:
- name: one
  cluster: { server: "https://one.example" }
- name: two
  cluster: { server: "https://two.example" }
contexts:
- name: a
  context: { cluster: one, user: user }
- name: b
  context: { cluster: two, user: user }
current-context: a
users:
- name: user
  user: { token: token }
"#,
    )
    .unwrap();
    let config = ClientConfig {
        endpoint: Some("https://ignored.example".into()),
        kubeconfig: Some((config, Some("b".into()))),
        ..Default::default()
    }
    .resolve()
    .await
    .unwrap();
    assert_eq!(config.cluster_url.to_string(), "https://two.example/");
}

#[tokio::test]
async fn endpoint_uses_configured_certificate_paths() {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert");
    let key = dir.path().join("key");
    let ca = dir.path().join("ca");
    let config = ClientConfig {
        endpoint: Some("https://cluster.example:6443".into()),
        tls: Some(TlsConfig {
            cert: cert.clone(),
            key: key.clone(),
            ca: ca.clone(),
        }),
        ..Default::default()
    }
    .resolve()
    .await
    .unwrap();
    assert_eq!(
        config.cluster_url.to_string(),
        "https://cluster.example:6443/"
    );
    assert_eq!(config.root_cert_file.as_deref(), Some(ca.as_path()));
    assert_eq!(
        config.auth_info.client_certificate.as_deref(),
        cert.to_str()
    );
    assert_eq!(config.auth_info.client_key.as_deref(), key.to_str());
}
