use std::{
    fmt,
    path::{Path, PathBuf},
};

use kube::{
    Config,
    config::{KubeConfigOptions, Kubeconfig},
};

/// Errors while resolving Kubernetes configuration or constructing a client.
#[derive(Debug)]
pub enum ClientConfigError {
    InvalidQps,
    InvalidInflight,
    EmptyHost,
    InvalidEndpoint(http::uri::InvalidUri),
    InvalidPort(std::num::ParseIntError),
    Environment(std::env::VarError),
    Io(std::io::Error),
    Kubeconfig(kube::config::KubeconfigError),
    Client(kube::Error),
}

impl fmt::Display for ClientConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidQps => formatter.write_str("API QPS must be finite and nonnegative"),
            Self::InvalidInflight => {
                formatter.write_str("API maximum inflight exceeds semaphore limit")
            }
            Self::EmptyHost => formatter.write_str("KUBERNETES_SERVICE_HOST is empty"),
            Self::InvalidEndpoint(error) => error.fmt(formatter),
            Self::InvalidPort(error) => error.fmt(formatter),
            Self::Environment(error) => error.fmt(formatter),
            Self::Io(error) => error.fmt(formatter),
            Self::Kubeconfig(error) => error.fmt(formatter),
            Self::Client(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for ClientConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidQps | Self::InvalidInflight | Self::EmptyHost => None,
            Self::InvalidEndpoint(error) => Some(error),
            Self::InvalidPort(error) => Some(error),
            Self::Environment(error) => Some(error),
            Self::Io(error) => Some(error),
            Self::Kubeconfig(error) => Some(error),
            Self::Client(error) => Some(error),
        }
    }
}

#[derive(Clone, Debug)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    pub ca: PathBuf,
}

/// Client connection options. An explicit kubeconfig takes precedence.
#[derive(Clone, Debug, Default)]
pub struct ClientConfig {
    pub endpoint: Option<String>,
    pub tls: Option<TlsConfig>,
    pub kubeconfig: Option<(PathBuf, Option<String>)>,
    pub api_qps: f32,
    pub api_burst: usize,
    pub api_max_inflight: usize,
}

impl ClientConfig {
    pub async fn client(
        &self,
        registry: &pharos_server::metrics::Registry,
    ) -> Result<kube::Client, ClientConfigError> {
        if !self.api_qps.is_finite() || self.api_qps < 0.0 {
            return Err(ClientConfigError::InvalidQps);
        }
        if self.api_max_inflight > tokio::sync::Semaphore::MAX_PERMITS {
            return Err(ClientConfigError::InvalidInflight);
        }
        let config = self.resolve().await?;
        let host = config
            .cluster_url
            .authority()
            .map_or("", |authority| authority.as_str())
            .to_owned();
        let layer = crate::metrics::Layer::new(
            registry.kubernetes(),
            host,
            self.api_qps,
            self.api_burst,
            self.api_max_inflight,
        );
        Ok(kube::client::ClientBuilder::try_from(config)
            .map_err(ClientConfigError::Client)?
            .with_layer(&layer)
            .build())
    }

    pub async fn resolve(&self) -> Result<Config, ClientConfigError> {
        if let Some((path, context)) = &self.kubeconfig {
            let file = Kubeconfig::read_from(path).map_err(ClientConfigError::Kubeconfig)?;
            return Config::from_custom_kubeconfig(
                file,
                &KubeConfigOptions {
                    context: context.clone(),
                    ..Default::default()
                },
            )
            .await
            .map_err(ClientConfigError::Kubeconfig);
        }
        if let Some(endpoint) = &self.endpoint {
            let mut config = Config::new(
                endpoint
                    .parse()
                    .map_err(ClientConfigError::InvalidEndpoint)?,
            );
            if let Some(tls) = &self.tls {
                config.root_cert_file = Some(tls.ca.clone());
                config.auth_info.client_certificate = Some(tls.cert.to_string_lossy().into_owned());
                config.auth_info.client_key = Some(tls.key.to_string_lossy().into_owned());
            }
            return Ok(config);
        }
        let host =
            std::env::var("KUBERNETES_SERVICE_HOST").map_err(ClientConfigError::Environment)?;
        let port =
            std::env::var("KUBERNETES_SERVICE_PORT").map_err(ClientConfigError::Environment)?;
        Self::in_cluster(
            &host,
            &port,
            Path::new("/var/run/secrets/kubernetes.io/serviceaccount"),
        )
    }

    fn in_cluster(host: &str, port: &str, directory: &Path) -> Result<Config, ClientConfigError> {
        if host.is_empty() {
            return Err(ClientConfigError::EmptyHost);
        }
        let port: u16 = port.parse().map_err(ClientConfigError::InvalidPort)?;
        // RFC 5952 §6: Bracket IPv6 address literals in URI authorities.
        let host = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
            _ => host.to_owned(),
        };
        let token = directory.join("token");
        std::fs::read(&token).map_err(ClientConfigError::Io)?;
        let mut config = Config::new(
            format!("https://{host}:{port}")
                .parse()
                .map_err(ClientConfigError::InvalidEndpoint)?,
        );
        config.auth_info.token_file = Some(token.to_string_lossy().into_owned());
        let ca = directory.join("ca.crt");
        if ca.exists() {
            config.root_cert_file = Some(ca);
        }
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::{ClientConfig, ClientConfigError};

    #[test]
    fn in_cluster_uses_token_and_ca_files() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("token"), "token").unwrap();
        std::fs::write(dir.path().join("ca.crt"), "cert").unwrap();
        let config = ClientConfig::in_cluster("fd00::1", "443", dir.path()).unwrap();
        assert_eq!(config.cluster_url.to_string(), "https://[fd00::1]:443/");
        assert_eq!(config.root_cert_file.unwrap(), dir.path().join("ca.crt"));
        assert_eq!(
            config.auth_info.token_file.unwrap(),
            dir.path().join("token").to_str().unwrap()
        );
        assert!(matches!(
            ClientConfig::in_cluster("", "443", dir.path()),
            Err(ClientConfigError::EmptyHost)
        ));
        let port_error = ClientConfig::in_cluster("127.0.0.1", "bad", dir.path()).unwrap_err();
        assert!(matches!(port_error, ClientConfigError::InvalidPort(_)));
        assert_eq!(port_error.to_string(), "invalid digit found in string");
        let missing = dir.path().join("missing");
        assert!(matches!(
            ClientConfig::in_cluster("127.0.0.1", "443", &missing),
            Err(ClientConfigError::Io(_))
        ));
    }
}
