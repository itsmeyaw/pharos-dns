use super::{Config, Secret};
use pharos_corefile::{BlockContext, Cursor, Error, Fallthrough};
use std::{path::PathBuf, time::Duration};

pub(crate) fn setup(
    cursor: &mut Cursor<'_>,
    _block: &mut BlockContext<crate::Chain>,
) -> Result<(), Error> {
    parse(cursor, load_config_from_env())?;
    Err(cursor.error("route53: serving Route 53 data is not implemented yet"))
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: strconv.ParseBool(os.Getenv("AWS_SDK_LOAD_CONFIG")), an error counting as false.
fn load_config_from_env() -> bool {
    std::env::var("AWS_SDK_LOAD_CONFIG")
        .is_ok_and(|value| matches!(value.as_str(), "1" | "t" | "T" | "TRUE" | "true" | "True"))
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: `config.DefaultSharedConfigFilename()` is `$HOME/.aws/config`.
fn default_shared_config_file() -> PathBuf {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join(".aws")
        .join("config")
}

// CoreDNS v1.15.0 plugin/route53/setup.go setup: a plain integer (strconv.Atoi) gets an `s` suffix before time.ParseDuration.
fn parse_refresh(cursor: &Cursor<'_>, value: &str) -> Result<Duration, Error> {
    let digits = value.strip_prefix(['+', '-']).unwrap_or(value);
    let text = if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        format!("{value}s")
    } else {
        value.to_owned()
    };
    let refresh = crate::health::parse_duration(&text).ok_or_else(|| {
        cursor.error(format!(
            "Unable to parse duration: time: invalid duration {text:?}"
        ))
    })?;
    // `parse_duration` clamps a negative duration to zero, so this rejects both.
    if refresh.is_zero() {
        return Err(cursor.error(format!("refresh interval must be greater than 0: {text:?}")));
    }
    Ok(refresh)
}

/// Parses every `route53` stanza of a Server Block; `load_config` is the truthiness of `AWS_SDK_LOAD_CONFIG`.
pub(super) fn parse(cursor: &mut Cursor<'_>, load_config: bool) -> Result<Vec<Config>, Error> {
    let mut stanzas = Vec::new();
    // CoreDNS v1.15.0 plugin/route53/setup.go setup: `for c.Next()` parses each `route53` line as its own stanza.
    while cursor.next() {
        let mut zones: Vec<(String, Vec<String>)> = Vec::new();
        let mut seen = Vec::new();
        let mut config = Config {
            zones: Vec::new(),
            access_key: None,
            endpoint: None,
            profile: None,
            shared_config_files: None,
            fallthrough: Fallthrough::default(),
            // CoreDNS v1.15.0 plugin/route53/setup.go setup: the default update frequency is one minute.
            refresh: Duration::from_secs(60),
        };

        for arg in cursor.remaining_args() {
            // CoreDNS v1.15.0 plugin/route53/setup.go setup: ZONE:HOSTED_ZONE_ID splits at the first colon, both halves non-empty.
            let (dns, hosted_zone_id) = match arg.split_once(':') {
                Some((dns, id)) if !dns.is_empty() && !id.is_empty() => (dns, id),
                _ => return Err(cursor.error(format!("invalid zone {arg:?}"))),
            };
            if seen.contains(&arg) {
                return Err(cursor.error(format!("conflict zone {arg:?}")));
            }
            match zones.iter_mut().find(|(name, _)| name == dns) {
                Some((_, ids)) => ids.push(hosted_zone_id.to_owned()),
                None => zones.push((dns.to_owned(), vec![hosted_zone_id.to_owned()])),
            }
            seen.push(arg);
        }
        config.zones = zones;

        while cursor.next_block() {
            let property = cursor.val().to_owned();
            match property.as_str() {
                "aws_access_key" => {
                    let args = cursor.remaining_args();
                    let [id, secret, ..] = args.as_slice() else {
                        return Err(
                            cursor.error(format!("invalid access key: '[{}]'", args.join(" ")))
                        );
                    };
                    config.access_key = Some((id.clone(), Secret(secret.clone())));
                    pharos_server::logging::log(
                        "WARN",
                        "route53",
                        "Save aws_access_key in Corefile has been deprecated, please use other authentication methods instead",
                    );
                }
                "aws_endpoint" => {
                    if !cursor.next_arg() {
                        return Err(cursor.arg_err());
                    }
                    config.endpoint = Some(cursor.val().to_owned());
                }
                // CoreDNS v1.15.0 plugin/route53/setup.go setup: `upstream` eats its arguments and is ignored.
                "upstream" => {
                    cursor.remaining_args();
                }
                "credentials" => {
                    if !cursor.next_arg() {
                        return Err(cursor.arg_err());
                    }
                    config.profile = Some(cursor.val().to_owned());
                    if cursor.next_arg() {
                        let mut files = vec![PathBuf::from(cursor.val())];
                        // CoreDNS v1.15.0 plugin/route53/setup.go setup: AWS_SDK_LOAD_CONFIG also loads ~/.aws/config, as the SDK does.
                        if load_config {
                            files.push(default_shared_config_file());
                        }
                        config.shared_config_files = Some(files);
                    }
                }
                "fallthrough" => {
                    let args = cursor.remaining_args();
                    let args = args.iter().map(String::as_str).collect::<Vec<_>>();
                    config.fallthrough.set_domains_from_args(&args);
                }
                "refresh" => {
                    if !cursor.next_arg() {
                        return Err(cursor.arg_err());
                    }
                    let value = cursor.val().to_owned();
                    config.refresh = parse_refresh(cursor, &value)?;
                }
                other => return Err(cursor.error(format!("unknown property {other:?}"))),
            }
        }
        stanzas.push(config);
    }
    Ok(stanzas)
}
