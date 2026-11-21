//! Sampled Query tracing exported to a Zipkin collector.

pub(crate) mod setup;
#[cfg(test)]
mod tests;

use std::{sync::Arc, time::Duration};

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};

// CoreDNS v1.15.0 plugin/trace/setup.go supportedProviders: the default endpoint of each type.
const ZIPKIN_ENDPOINT: &str = "localhost:9411";
const DATADOG_ENDPOINT: &str = "localhost:8126";
// CoreDNS v1.15.0 plugin/trace/setup.go defServiceName.
const DEFAULT_SERVICE: &str = "coredns";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointType {
    Zipkin,
    Datadog,
}

/// Parsed `trace` Directive; zero sizes and interval mean the exporter default.
#[derive(Debug)]
pub(crate) struct Config {
    pub endpoint_type: EndpointType,
    pub endpoint: String,
    pub service_endpoint: String,
    pub service_name: String,
    pub client_server: bool,
    pub every: u64,
    pub datadog_analytics_rate: f64,
    pub zipkin_max_backlog_size: i64,
    pub zipkin_max_batch_size: i64,
    pub zipkin_max_batch_interval: Duration,
}

#[derive(Debug)]
pub struct Trace {
    config: Arc<Config>,
}

impl Trace {
    pub(crate) fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    #[cfg(test)]
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }
}

impl Plugin for Trace {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        next.run(cx).await
    }
}

// CoreDNS v1.15.0 plugin/trace/setup.go normalizeEndpoint: only known types, and a bare Zipkin host becomes a collector URL.
fn normalize_endpoint(
    endpoint_type: &str,
    endpoint: &str,
) -> Result<(EndpointType, String), String> {
    let (kind, default) = match endpoint_type {
        "zipkin" => (EndpointType::Zipkin, ZIPKIN_ENDPOINT),
        "datadog" => (EndpointType::Datadog, DATADOG_ENDPOINT),
        _ => {
            return Err(format!(
                "tracing endpoint type '{endpoint_type}' is not supported"
            ));
        }
    };
    let endpoint = if endpoint.is_empty() {
        default
    } else {
        endpoint
    };
    let lower = endpoint.to_ascii_lowercase();
    if kind == EndpointType::Zipkin
        && !lower.starts_with("http://")
        && !lower.starts_with("https://")
    {
        return Ok((kind, format!("http://{endpoint}/api/v2/spans")));
    }
    Ok((kind, endpoint.to_owned()))
}

// Go strconv.ParseBool: exactly these spellings.
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "t" | "T" | "TRUE" | "true" | "True" => Some(true),
        "0" | "f" | "F" | "FALSE" | "false" | "False" => Some(false),
        _ => None,
    }
}

// Go net.JoinHostPort brackets a host that contains a colon.
fn join_host_port(host: &str, port: &str) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

pub(crate) fn parse(
    cursor: &mut Cursor<'_>,
    listen_hosts: &[String],
    port: &str,
) -> Result<Config, Error> {
    let mut config = Config {
        endpoint_type: EndpointType::Zipkin,
        endpoint: String::new(),
        service_endpoint: String::new(),
        service_name: DEFAULT_SERVICE.to_owned(),
        client_server: false,
        every: 1,
        datadog_analytics_rate: 0.0,
        zipkin_max_backlog_size: 0,
        zipkin_max_batch_size: 0,
        zipkin_max_batch_interval: Duration::ZERO,
    };
    if let Some(host) = listen_hosts.first().filter(|host| !host.is_empty()) {
        config.service_endpoint = join_host_port(host, port);
    }
    while cursor.next() {
        let args = cursor.remaining_args();
        let lowered;
        let (endpoint_type, endpoint) = match args.as_slice() {
            [] => ("zipkin", ""),
            [endpoint] => ("zipkin", endpoint.as_str()),
            [endpoint_type, endpoint] => {
                lowered = endpoint_type.to_lowercase();
                (lowered.as_str(), endpoint.as_str())
            }
            _ => return Err(cursor.arg_err()),
        };
        (config.endpoint_type, config.endpoint) =
            normalize_endpoint(endpoint_type, endpoint).map_err(|message| cursor.error(message))?;
        while cursor.next_block() {
            let property = cursor.val().to_owned();
            let args = cursor.remaining_args();
            match property.as_str() {
                "every" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    // Go strconv.ParseUint rejects a sign, which Rust's parser accepts.
                    config.every = value
                        .parse::<u64>()
                        .ok()
                        .filter(|_| !value.starts_with('+'))
                        .ok_or_else(|| cursor.error(format!("invalid syntax: '{value}'")))?;
                }
                "service" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    config.service_name.clone_from(value);
                }
                "client_server" => {
                    config.client_server = match args.as_slice() {
                        [] => true,
                        [value] => parse_bool(value)
                            .ok_or_else(|| cursor.error(format!("invalid syntax: '{value}'")))?,
                        _ => return Err(cursor.arg_err()),
                    };
                }
                "datadog_analytics_rate" => {
                    config.datadog_analytics_rate = match args.as_slice() {
                        [] => 0.0,
                        [value] => value
                            .parse::<f64>()
                            .map_err(|_| cursor.error(format!("invalid syntax: '{value}'")))?,
                        _ => return Err(cursor.arg_err()),
                    };
                    let rate = config.datadog_analytics_rate;
                    if !(0.0..=1.0).contains(&rate) && !rate.is_nan() {
                        return Err(cursor.error(format!(
                            "datadog analytics rate must be between 0 and 1, '{rate:.6}' is not supported"
                        )));
                    }
                }
                "zipkin_max_backlog_size" | "zipkin_max_batch_size" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    let size = value
                        .parse::<i64>()
                        .map_err(|_| cursor.error(format!("invalid syntax: '{value}'")))?;
                    if property == "zipkin_max_backlog_size" {
                        config.zipkin_max_backlog_size = size;
                    } else {
                        config.zipkin_max_batch_size = size;
                    }
                }
                "zipkin_max_batch_interval" => {
                    let [value] = args.as_slice() else {
                        return Err(cursor.arg_err());
                    };
                    config.zipkin_max_batch_interval = crate::health::parse_duration(value)
                        .ok_or_else(|| cursor.error(format!("invalid duration: '{value}'")))?;
                }
                _ => return Err(cursor.error(format!("unknown property '{property}'"))),
            }
        }
    }
    Ok(config)
}
