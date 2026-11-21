use super::{Api, Config, Page, RecordSet, StartRecord};
use aws_config::BehaviorVersion;
#[allow(deprecated)]
use aws_config::profile::profile_file::{ProfileFileKind, ProfileFiles};
use aws_sdk_route53::{
    config::{Builder, Credentials},
    error::ProvideErrorMetadata,
    types::RrType,
};

/// The AWS SDK Route 53 client.
pub(super) struct Sdk(aws_sdk_route53::Client);

// CoreDNS v1.15.0 plugin/route53/setup.go f: load the default AWS config, apply the Corefile options, and require a region.
// Build this inside the runtime that keeps the client: its connections belong to that runtime.
pub(super) async fn connect(config: &Config) -> Result<Sdk, String> {
    let mut loader = aws_config::defaults(BehaviorVersion::latest());
    // CoreDNS v1.15.0 plugin/route53/setup.go setup: aws_access_key is a static credentials provider with no session token.
    if let Some((id, secret)) = &config.access_key {
        loader = loader.credentials_provider(Credentials::new(
            id,
            &secret.0,
            None,
            None,
            "pharos-route53-corefile",
        ));
    }
    if let Some(profile) = &config.profile {
        loader = loader.profile_name(profile);
    }
    // CoreDNS v1.15.0 plugin/route53/setup.go setup: WithSharedConfigFiles replaces the config files only; the credentials file stays the default.
    if let Some(files) = &config.shared_config_files {
        #[allow(deprecated)]
        let mut profile_files = ProfileFiles::builder().include_default_credentials_file(true);
        for file in files {
            #[allow(deprecated)]
            {
                profile_files = profile_files.with_file(ProfileFileKind::Config, file);
            }
        }
        loader = loader.profile_files(profile_files.build());
    }
    if let Some(endpoint) = &config.endpoint {
        loader = loader.endpoint_url(endpoint);
    }
    let sdk = loader.load().await;
    // CoreDNS v1.15.0 plugin/route53/setup.go f: the default chain already ended at IMDS, so no region is an error.
    if sdk.region().is_none() {
        return Err(
            "failed to get region from IMDS: no region in the environment, shared config, or IMDS"
                .to_owned(),
        );
    }
    Ok(Sdk(aws_sdk_route53::Client::from_conf(
        Builder::from(&sdk).build(),
    )))
}

/// The service's code and message when it sent them; the SDK's own Display of a failure is long and nested.
fn describe(error: &(impl ProvideErrorMetadata + std::fmt::Display)) -> String {
    match (error.code(), error.message()) {
        (Some(code), Some(message)) => format!("{code}: {message}"),
        _ => error.to_string(),
    }
}

impl Api for Sdk {
    async fn check_hosted_zone(&self, dns: &str, hosted_zone_id: &str) -> Result<(), String> {
        self.0
            .list_hosted_zones_by_name()
            .dns_name(dns)
            .hosted_zone_id(hosted_zone_id)
            .send()
            .await
            .map(|_| ())
            .map_err(|error| describe(&error))
    }

    async fn list_record_sets(
        &self,
        hosted_zone_id: &str,
        start: Option<&StartRecord>,
    ) -> Result<Page, String> {
        // CoreDNS v1.15.0 plugin/route53/route53.go updateZones: MaxItems is 1000, the API maximum.
        let mut request = self
            .0
            .list_resource_record_sets()
            .hosted_zone_id(hosted_zone_id)
            .max_items(1000);
        if let Some(start) = start {
            request = request
                .start_record_name(&start.name)
                .start_record_type(RrType::from(start.rtype.as_str()))
                .set_start_record_identifier(start.identifier.clone());
        }
        let output = request.send().await.map_err(|error| describe(&error))?;
        let sets = output
            .resource_record_sets()
            .iter()
            .map(|set| RecordSet {
                name: set.name().to_owned(),
                rtype: set.r#type().as_str().to_owned(),
                // CoreDNS v1.15.0 plugin/route53/route53.go updateZoneFromRRS: aws.ToInt64 reads a missing TTL as 0.
                ttl: set.ttl().unwrap_or(0),
                values: set
                    .resource_records()
                    .iter()
                    .map(|record| record.value().to_owned())
                    .collect(),
            })
            .collect();
        let next = if output.is_truncated() {
            // A truncated page without NextRecordName would repeat the first page forever.
            let name = output
                .next_record_name()
                .ok_or("truncated page without NextRecordName")?;
            let rtype = output
                .next_record_type()
                .ok_or("truncated page without NextRecordType")?;
            Some(StartRecord {
                name: name.to_owned(),
                rtype: rtype.as_str().to_owned(),
                identifier: output.next_record_identifier().map(str::to_owned),
            })
        } else {
            None
        };
        Ok(Page { sets, next })
    }
}
