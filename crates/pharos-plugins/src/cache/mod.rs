//! Cache configuration and DNS Response storage.

mod setup;

/// Configuration for the cache Plugin.
#[derive(Debug)]
pub struct Cache {
    config: setup::Config,
}

impl Cache {
    pub(crate) fn parse(
        cursor: &mut pharos_corefile::Cursor<'_>,
        zones: &[String],
    ) -> Result<Self, pharos_corefile::Error> {
        let zones: Vec<&str> = zones.iter().map(String::as_str).collect();
        Ok(Self {
            config: setup::parse(cursor, &zones)?,
        })
    }
}

impl pharos_server::Plugin for Cache {
    async fn serve<N: pharos_server::Next + Send>(
        &self,
        _cx: &mut pharos_server::Context<'_>,
        _next: N,
    ) -> pharos_server::Outcome {
        let _ = &self.config;
        pharos_server::Outcome::Error(pharos_server::Error::NotImplemented)
    }
}
