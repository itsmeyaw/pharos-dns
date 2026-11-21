//! The parsed `azure` Directive, before any Zone is loaded.

use std::{fmt, time::Duration};

use pharos_corefile::Fallthrough;

/// CoreDNS v1.15.0 plugin/azure/setup.go parse: Zones refresh every minute unless configured.
pub const DEFAULT_REFRESH: Duration = Duration::from_secs(60);

/// An Azure cloud and its Resource Manager and Active Directory endpoints.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Environment {
    #[default]
    PublicCloud,
    UsGovernmentCloud,
    ChinaCloud,
    GermanCloud,
}

impl Environment {
    /// go-autorest v0.11.30 autorest/azure/environments.go `EnvironmentFromName`: names compare in upper case.
    pub fn from_name(name: &str) -> Option<Self> {
        const NAMES: [(&str, Environment); 6] = [
            ("AZURECHINACLOUD", Environment::ChinaCloud),
            ("AZUREGERMANCLOUD", Environment::GermanCloud),
            ("AZURECLOUD", Environment::PublicCloud),
            ("AZUREPUBLICCLOUD", Environment::PublicCloud),
            ("AZUREUSGOVERNMENT", Environment::UsGovernmentCloud),
            ("AZUREUSGOVERNMENTCLOUD", Environment::UsGovernmentCloud),
        ];
        NAMES
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|&(_, environment)| environment)
    }

    /// go-autorest v0.11.30 autorest/azure/environments.go: `ResourceManagerEndpoint`.
    pub const fn resource_manager_endpoint(self) -> &'static str {
        match self {
            Self::PublicCloud => "https://management.azure.com/",
            Self::UsGovernmentCloud => "https://management.usgovcloudapi.net/",
            Self::ChinaCloud => "https://management.chinacloudapi.cn/",
            Self::GermanCloud => "https://management.microsoftazure.de/",
        }
    }

    /// go-autorest v0.11.30 autorest/azure/environments.go: `ActiveDirectoryEndpoint`.
    pub const fn active_directory_endpoint(self) -> &'static str {
        match self {
            Self::PublicCloud => "https://login.microsoftonline.com/",
            Self::UsGovernmentCloud => "https://login.microsoftonline.us/",
            Self::ChinaCloud => "https://login.chinacloudapi.cn/",
            Self::GermanCloud => "https://login.microsoftonline.de/",
        }
    }
}

/// A client secret that never appears in `Debug` output.
#[derive(Clone, Default, Eq, PartialEq)]
pub struct Secret(String);

impl Secret {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// One `RESOURCE_GROUP:ZONE` argument: a hosted zone in Azure DNS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ZoneSpec {
    pub resource_group: String,
    /// The zone name as configured; the Azure REST path uses it verbatim.
    pub zone: String,
    /// A Private DNS zone rather than a public DNS zone.
    pub private: bool,
}

/// Everything the Corefile says about one Server Block's `azure` Directive.
#[derive(Clone, Debug)]
pub struct Config {
    /// Hosted zones in Corefile order.
    pub zones: Vec<ZoneSpec>,
    pub tenant: String,
    pub client: String,
    pub secret: Secret,
    pub subscription: String,
    pub environment: Environment,
    pub fallthrough: Fallthrough,
    pub refresh: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            zones: Vec::new(),
            tenant: String::new(),
            client: String::new(),
            secret: Secret::default(),
            subscription: String::new(),
            environment: Environment::default(),
            fallthrough: Fallthrough::default(),
            refresh: DEFAULT_REFRESH,
        }
    }
}
