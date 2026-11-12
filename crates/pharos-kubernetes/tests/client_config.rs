use pharos_kubernetes::{ClientConfig, TlsConfig};
use std::fs;

#[tokio::test]
async fn client_config_errors_are_typed_and_keep_their_messages() {
    use pharos_kubernetes::ClientConfigError;
    let registry = pharos_server::metrics::Registry::default();
    let config = ClientConfig {
        api_qps: f32::NAN,
        ..Default::default()
    };
    let error = config.client(&registry).await.err().unwrap();
    assert!(matches!(error, ClientConfigError::InvalidQps));
    assert_eq!(error.to_string(), "API QPS must be finite and nonnegative");
    let config = ClientConfig {
        api_max_inflight: usize::MAX,
        ..Default::default()
    };
    let error = config.client(&registry).await.err().unwrap();
    assert!(matches!(error, ClientConfigError::InvalidInflight));
    assert_eq!(
        error.to_string(),
        "API maximum inflight exceeds semaphore limit"
    );
    let config = ClientConfig {
        endpoint: Some("https://bad host".into()),
        ..Default::default()
    };
    assert!(matches!(
        config.resolve().await.unwrap_err(),
        ClientConfigError::InvalidEndpoint(_)
    ));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("missing-kubeconfig");
    let expected = kube::config::Kubeconfig::read_from(&path)
        .unwrap_err()
        .to_string();
    let config = ClientConfig {
        kubeconfig: Some((path, None)),
        ..Default::default()
    };
    let error = config.resolve().await.unwrap_err();
    assert!(matches!(error, ClientConfigError::Kubeconfig(_)));
    assert_eq!(error.to_string(), expected);
}

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

#[tokio::test]
async fn endpoint_does_not_load_ambient_kubeconfig() {
    if std::env::var_os("PHAROS_TEST_KUBECONFIG_CHILD").is_some() {
        let config = ClientConfig {
            endpoint: Some("https://api.example".into()),
            ..Default::default()
        }
        .resolve()
        .await
        .unwrap();
        assert!(config.auth_info.token.is_none());
        assert_eq!(config.cluster_url.to_string(), "https://api.example/");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("config");
    fs::write(
        &file,
        r#"
apiVersion: v1
kind: Config
clusters:
- name: cluster
  cluster: { server: "https://ambient.example" }
contexts:
- name: ctx
  context: { cluster: cluster, user: user }
current-context: ctx
users:
- name: user
  user: { token: unexpected }
"#,
    )
    .unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "endpoint_does_not_load_ambient_kubeconfig"])
        .env("KUBECONFIG", file)
        .env("PHAROS_TEST_KUBECONFIG_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[tokio::test]
async fn in_cluster_reads_service_environment() {
    if std::env::var_os("PHAROS_TEST_CLUSTER_CHILD").is_some() {
        let error = ClientConfig::default().resolve().await.unwrap_err();
        assert!(matches!(
            error,
            pharos_kubernetes::ClientConfigError::EmptyHost
        ));
        assert_eq!(error.to_string(), "KUBERNETES_SERVICE_HOST is empty");
        return;
    }
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "in_cluster_reads_service_environment"])
        .env("KUBERNETES_SERVICE_HOST", "")
        .env("KUBERNETES_SERVICE_PORT", "6443")
        .env("PHAROS_TEST_CLUSTER_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
