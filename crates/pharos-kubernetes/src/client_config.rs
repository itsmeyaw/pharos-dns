use std::{
    error::Error,
    path::{Path, PathBuf},
};

use kube::{
    Config,
    config::{KubeConfigOptions, Kubeconfig},
};

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
}

impl ClientConfig {
    pub async fn client(
        &self,
        registry: &pharos_server::metrics::Registry,
    ) -> Result<kube::Client, Box<dyn Error + Send + Sync>> {
        let config = self.resolve().await?;
        let host = config
            .cluster_url
            .authority()
            .map_or("", |authority| authority.as_str())
            .to_owned();
        let layer = crate::metrics::Layer::new(registry.kubernetes(), host);
        Ok(kube::client::ClientBuilder::try_from(config)?
            .with_layer(&layer)
            .build())
    }

    pub async fn resolve(&self) -> Result<Config, Box<dyn Error + Send + Sync>> {
        if let Some((path, context)) = &self.kubeconfig {
            let file = Kubeconfig::read_from(path)?;
            return Ok(Config::from_custom_kubeconfig(
                file,
                &KubeConfigOptions {
                    context: context.clone(),
                    ..Default::default()
                },
            )
            .await?);
        }
        if let Some(endpoint) = &self.endpoint {
            let mut config = Config::new(endpoint.parse()?);
            if let Some(tls) = &self.tls {
                config.root_cert_file = Some(tls.ca.clone());
                config.auth_info.client_certificate = Some(tls.cert.to_string_lossy().into_owned());
                config.auth_info.client_key = Some(tls.key.to_string_lossy().into_owned());
            }
            return Ok(config);
        }
        let host = std::env::var("KUBERNETES_SERVICE_HOST")?;
        let port = std::env::var("KUBERNETES_SERVICE_PORT")?;
        Self::in_cluster(
            &host,
            &port,
            Path::new("/var/run/secrets/kubernetes.io/serviceaccount"),
        )
    }

    fn in_cluster(
        host: &str,
        port: &str,
        directory: &Path,
    ) -> Result<Config, Box<dyn Error + Send + Sync>> {
        if host.is_empty() {
            return Err("KUBERNETES_SERVICE_HOST is empty".into());
        }
        let port: u16 = port.parse()?;
        let host = match host.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(ip)) => format!("[{ip}]"),
            _ => host.to_owned(),
        };
        let token = directory.join("token");
        std::fs::read(&token)?;
        let mut config = Config::new(format!("https://{host}:{port}").parse()?);
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
    use super::ClientConfig;

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
        assert!(ClientConfig::in_cluster("", "443", dir.path()).is_err());
    }
}
