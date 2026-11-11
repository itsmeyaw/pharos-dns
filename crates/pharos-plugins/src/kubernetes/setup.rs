use pharos_corefile::{Cursor, Error, Fallthrough, origins_from_args_or_server_block};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    time::Duration,
};

#[derive(Debug)]
pub struct Config {
    pub zones: Vec<String>,
    pub multicluster_zones: Vec<String>,
    pub primary_zone_index: usize,
    pub ttl: u32,
    pub pod_mode: String,
    pub endpoints: bool,
    pub endpoints_list: Vec<String>,
    pub tls: Option<[String; 3]>,
    pub kubeconfig: Option<(String, Option<String>)>,
    pub namespaces: HashSet<String>,
    pub label_selector: Option<String>,
    pub namespace_label_selector: Option<String>,
    pub endpoint_pod_names: bool,
    pub ignore_empty_service: bool,
    pub zonal: bool,
    pub api_qps: f32,
    pub api_burst: usize,
    pub api_max_inflight: usize,
    pub startup_timeout: Duration,
    pub fallthrough: Fallthrough,
}

impl Config {
    pub fn client_config(&self) -> pharos_kubernetes::ClientConfig {
        pharos_kubernetes::ClientConfig {
            endpoint: self.endpoints_list.first().cloned(),
            tls: self
                .tls
                .as_ref()
                .map(|[cert, key, ca]| pharos_kubernetes::TlsConfig {
                    cert: cert.into(),
                    key: key.into(),
                    ca: ca.into(),
                }),
            kubeconfig: self
                .kubeconfig
                .as_ref()
                .map(|(file, context)| (file.into(), context.clone())),
            api_qps: self.api_qps,
            api_burst: self.api_burst,
            api_max_inflight: self.api_max_inflight,
        }
    }

    pub fn watch_config(&self) -> pharos_kubernetes::WatchConfig {
        let mut namespaces = self.namespaces.iter().cloned().collect::<Vec<_>>();
        namespaces.sort();
        pharos_kubernetes::WatchConfig {
            namespaces,
            label_selector: self.label_selector.clone(),
            namespace_label_selector: self.namespace_label_selector.clone(),
            pods_verified: self.pod_mode == "verified",
            endpoints: self.endpoints,
            zonal: self.zonal,
            multicluster: !self.multicluster_zones.is_empty(),
        }
    }
}

pub fn parse(cursor: &mut Cursor<'_>, server_domains: &[&str]) -> Result<Config, Error> {
    cursor.next();
    let args = cursor.remaining_args();
    let zones = origins_from_args_or_server_block(
        &args.iter().map(String::as_str).collect::<Vec<_>>(),
        server_domains,
    );
    let primary_zone_index = zones
        .iter()
        .position(|z| !is_reverse(z))
        .ok_or_else(|| cursor.error("non-reverse zone name must be used"))?;
    let mut config = Config {
        zones,
        multicluster_zones: Vec::new(),
        primary_zone_index,
        ttl: 5,
        pod_mode: "disabled".into(),
        endpoints: true,
        endpoints_list: vec![],
        tls: None,
        kubeconfig: None,
        namespaces: HashSet::new(),
        label_selector: None,
        namespace_label_selector: None,
        endpoint_pod_names: false,
        ignore_empty_service: false,
        zonal: false,
        api_qps: 0.0,
        api_burst: 0,
        api_max_inflight: 0,
        startup_timeout: Duration::from_secs(5),
        fallthrough: Fallthrough::default(),
    };
    while cursor.next_block() {
        let option = cursor.val().to_owned();
        let args = cursor.remaining_args();
        match option.as_str() {
            "endpoint_pod_names" | "noendpoints" | "zonal" => {
                if !args.is_empty() {
                    return Err(cursor.arg_err());
                }
                match option.as_str() {
                    "endpoint_pod_names" => config.endpoint_pod_names = true,
                    "noendpoints" => config.endpoints = false,
                    _ => config.zonal = true,
                }
            }
            "pods" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                if !matches!(args[0].as_str(), "disabled" | "verified" | "insecure") {
                    return Err(cursor.error(format!("wrong value for pods: {}", args[0])));
                }
                config.pod_mode = args[0].clone();
            }
            "namespaces" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                config.namespaces.extend(args);
            }
            "endpoint" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                config.endpoints_list = args;
            }
            "tls" => {
                if args.len() != 3 {
                    return Err(cursor.arg_err());
                }
                config.tls = Some([args[0].clone(), args[1].clone(), args[2].clone()]);
            }
            "labels" | "namespace_labels" => {
                if args.is_empty() {
                    return Err(cursor.arg_err());
                }
                let selector = args.join(" ");
                let selector = parse_selector(&selector).ok_or_else(|| {
                    cursor.error(format!(
                        "unable to parse {option} selector value: '{selector}'"
                    ))
                })?;
                if option == "labels" {
                    config.label_selector = Some(selector);
                } else {
                    config.namespace_label_selector = Some(selector);
                }
            }
            "fallthrough" => config
                .fallthrough
                .set_domains_from_args(&args.iter().map(String::as_str).collect::<Vec<_>>()),
            "ttl" => {
                let value = args.first().ok_or_else(|| cursor.arg_err())?;
                let ttl: i64 = value.parse().map_err(|_| cursor.error("invalid ttl"))?;
                if !(0..=3600).contains(&ttl) {
                    return Err(cursor.error("ttl must be in range [0, 3600]"));
                }
                config.ttl = ttl as u32;
            }
            "ignore" => {
                if let Some(value) = args.first() {
                    if value != "empty_service" {
                        return Err(
                            cursor.error(format!("unable to parse ignore value: '{value}'"))
                        );
                    }
                    config.ignore_empty_service = true;
                }
            }
            "kubeconfig" => {
                if !(1..=2).contains(&args.len()) {
                    return Err(cursor.arg_err());
                }
                config.kubeconfig = Some((args[0].clone(), args.get(1).cloned()));
            }
            "multicluster" => {
                config.multicluster_zones = origins_from_args_or_server_block(
                    &args.iter().map(String::as_str).collect::<Vec<_>>(),
                    &[],
                )
            }
            "startup_timeout" => {
                let value = args.first().ok_or_else(|| cursor.arg_err())?;
                // shortcut: negative timeouts clamp to zero; preserve signed durations when wiring startup.
                config.startup_timeout = crate::health::parse_duration(value).ok_or_else(|| {
                    cursor.error(format!("failed to parse startup_timeout: {value}"))
                })?;
            }
            "apiserver_qps" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                // ClientConfig rejects non-finite QPS even though CoreDNS accepts it here.
                let value =
                    parse_float32(&args[0]).ok_or_else(|| cursor.error("invalid apiserver_qps"))?;
                if value < 0.0 {
                    return Err(cursor.error("apiserver_qps must be >= 0"));
                }
                config.api_qps = value;
            }
            "apiserver_burst" | "apiserver_max_inflight" => {
                if args.len() != 1 {
                    return Err(cursor.arg_err());
                }
                let value: i64 = args[0]
                    .parse()
                    .map_err(|_| cursor.error(format!("invalid {option}")))?;
                if value < 0 {
                    return Err(cursor.error(format!("{option} must be >= 0")));
                }
                let value = usize::try_from(value)
                    .map_err(|_| cursor.error(format!("invalid {option}")))?;
                if option == "apiserver_burst" {
                    config.api_burst = value;
                } else {
                    config.api_max_inflight = value;
                }
            }
            _ => return Err(cursor.error(format!("unknown property '{option}'"))),
        }
    }
    if cursor.has_next() {
        return Err(cursor.error("kubernetes: this plugin can only be used once per Server Block"));
    }
    if !config.namespaces.is_empty() && config.namespace_label_selector.is_some() {
        return Err(cursor.error("namespaces and namespace_labels cannot both be set"));
    }
    for zone in &config.multicluster_zones {
        if !config.zones.contains(zone) {
            return Err(cursor.error(format!(
                "is not authoritative for the multicluster zone {zone} (authoritative zones: {:?})",
                config.zones
            )));
        }
    }
    if config.zonal && !config.endpoints {
        return Err(cursor.error("zonal requires the endpoint cache; remove noendpoints"));
    }
    Ok(config)
}

fn parse_float32(input: &str) -> Option<f32> {
    let (negative, body) = if let Some(body) = input.strip_prefix('-') {
        (true, body)
    } else {
        (false, input.strip_prefix('+').unwrap_or(input))
    };
    if body.starts_with(['+', '-']) {
        return None;
    }
    if body.eq_ignore_ascii_case("nan") {
        return (body.len() == input.len()).then_some(f32::NAN);
    }
    if body.eq_ignore_ascii_case("inf") || body.eq_ignore_ascii_case("infinity") {
        return Some(if negative {
            f32::NEG_INFINITY
        } else {
            f32::INFINITY
        });
    }
    let hex = body.starts_with("0x") || body.starts_with("0X");
    let exponent = body.bytes().position(|b| matches!(b, b'p' | b'P'));
    let bytes = body.as_bytes();
    for (i, &byte) in bytes.iter().enumerate() {
        if byte != b'_' {
            continue;
        }
        let is_digit = |b: u8| {
            if hex && exponent.is_none_or(|e| i < e) {
                b.is_ascii_hexdigit()
            } else {
                b.is_ascii_digit()
            }
        };
        if !(hex && i == 2 || i > 0 && is_digit(bytes[i - 1]))
            || !bytes.get(i + 1).is_some_and(|&b| is_digit(b))
        {
            return None;
        }
    }
    let cleaned = body.replace('_', "");
    if hex {
        return parse_hex_float32(&cleaned[2..], negative);
    }
    let value = cleaned.parse::<f32>().ok()?;
    if !value.is_finite() {
        return None;
    }
    Some(if negative { -value } else { value })
}

fn parse_hex_float32(input: &str, negative: bool) -> Option<f32> {
    let (mantissa, exponent) = input.split_once(['p', 'P'])?;
    let (exp_negative, exponent) = if let Some(rest) = exponent.strip_prefix('-') {
        (true, rest)
    } else {
        (false, exponent.strip_prefix('+').unwrap_or(exponent))
    };
    if exponent.is_empty() || !exponent.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let exponent = exponent.bytes().fold(0i64, |n, b| {
        n.saturating_mul(10).saturating_add(i64::from(b - b'0'))
    });
    let exponent = if exp_negative { -exponent } else { exponent };
    let mut digits = Vec::new();
    let mut point = None;
    for byte in mantissa.bytes() {
        if byte == b'.' && point.is_none() {
            point = Some(digits.len());
        } else {
            digits.push((byte as char).to_digit(16)? as u8);
        }
    }
    if digits.is_empty() {
        return None;
    }
    let sign = if negative { 1 << 31 } else { 0 };
    let Some(first) = digits.iter().position(|&digit| digit != 0) else {
        return Some(f32::from_bits(sign));
    };
    let integer_digits = point.unwrap_or(digits.len());
    let offset = (integer_digits as i64)
        .saturating_sub(first as i64)
        .saturating_sub(1)
        .saturating_mul(4);
    let mut exponent = exponent
        .saturating_add(offset)
        .saturating_add(i64::from(digits[first].ilog2()));
    if exponent > 127 {
        return None;
    }
    if exponent < -150 {
        return Some(f32::from_bits(sign));
    }
    // Round directly to float32 to avoid double-rounding hexadecimal halfway values.
    let precision = if exponent >= -126 {
        24
    } else {
        (exponent + 150) as usize
    };
    let mut value = 0u32;
    let mut count = 0usize;
    let mut round = false;
    let mut sticky = false;
    for (i, &digit) in digits[first..].iter().enumerate() {
        let high = if i == 0 { digit.ilog2() } else { 3 };
        for bit in (0..=high).rev() {
            let set = digit & (1 << bit) != 0;
            if count < precision {
                value = (value << 1) | u32::from(set);
            } else if count == precision {
                round = set;
            } else {
                sticky |= set;
            }
            count += 1;
        }
    }
    if count < precision {
        value <<= precision - count;
    }
    if round && (sticky || value & 1 != 0) {
        value += 1;
    }
    if exponent >= -126 {
        if value == 1 << 24 {
            value >>= 1;
            exponent += 1;
        }
        if exponent > 127 {
            return None;
        }
        value = (((exponent + 127) as u32) << 23) | (value & 0x7f_ffff);
    }
    Some(f32::from_bits(sign | value))
}

fn is_reverse(zone: &str) -> bool {
    let zone = zone.to_ascii_lowercase();
    [".in-addr.arpa.", ".ip6.arpa."]
        .iter()
        .any(|suffix| zone.ends_with(suffix))
}

fn parse_selector(input: &str) -> Option<String> {
    let mut tokens = Vec::new();
    let mut chars = input.char_indices().peekable();
    while let Some((start, ch)) = chars.next() {
        if ch.is_whitespace() {
            continue;
        }
        if "(),!=<>".contains(ch) {
            let mut end = start + ch.len_utf8();
            if matches!(ch, '!' | '=') && chars.peek().is_some_and(|(_, next)| *next == '=') {
                let (index, next) = chars.next().unwrap();
                end = index + next.len_utf8();
            }
            tokens.push(&input[start..end]);
        } else {
            let mut end = start + ch.len_utf8();
            while let Some(&(index, next)) = chars.peek() {
                if next.is_whitespace() || "(),!=<>".contains(next) {
                    break;
                }
                chars.next();
                end = index + next.len_utf8();
            }
            tokens.push(&input[start..end]);
        }
    }
    let mut pos = 0;
    let mut equal = BTreeMap::new();
    let mut expressions: Vec<(&str, String)> = Vec::new();
    while pos < tokens.len() {
        let negated = tokens[pos] == "!";
        if negated {
            pos += 1;
        }
        let key = *tokens.get(pos)?;
        if !valid_key(key) {
            return None;
        }
        pos += 1;
        if negated && !matches!(tokens.get(pos), None | Some(&",")) {
            return None;
        }
        match tokens.get(pos).copied() {
            Some("=" | "==") => {
                pos += 1;
                let mut value = "";
                if let Some(&next) = tokens.get(pos).filter(|value| **value != ",") {
                    if !valid_value(next) {
                        return None;
                    }
                    value = next;
                    pos += 1;
                }
                equal.insert(key, value);
            }
            Some(op @ ("in" | "notin")) => {
                pos += 1;
                if tokens.get(pos) != Some(&"(") {
                    return None;
                }
                pos += 1;
                let mut expect_value = true;
                let mut values = BTreeSet::new();
                while let Some(&token) = tokens.get(pos) {
                    if token == ")" {
                        break;
                    }
                    if token == "," {
                        if expect_value {
                            values.insert("");
                        }
                        expect_value = true;
                    } else if expect_value && valid_value(token) {
                        values.insert(token);
                        expect_value = false;
                    } else {
                        return None;
                    }
                    pos += 1;
                }
                if tokens.get(pos) != Some(&")") {
                    return None;
                }
                if expect_value {
                    values.insert("");
                }
                expressions.push((
                    key,
                    format!(
                        "{key} {op} ({})",
                        values.into_iter().collect::<Vec<_>>().join(",")
                    ),
                ));
                pos += 1;
            }
            Some(",") | None => {
                expressions.push((key, format!("{}{key}", if negated { "!" } else { "" })))
            }
            _ => return None,
        }
        if pos == tokens.len() {
            break;
        }
        if tokens[pos] != "," || pos + 1 == tokens.len() {
            return None;
        }
        pos += 1;
    }
    expressions.extend(
        equal
            .into_iter()
            .map(|(key, value)| (key, format!("{key}={value}"))),
    );
    expressions.sort_by_key(|(key, _)| *key);
    Some(
        expressions
            .into_iter()
            .map(|(_, expression)| expression)
            .collect::<Vec<_>>()
            .join(","),
    )
}

fn valid_key(key: &str) -> bool {
    let (prefix, name) = key
        .split_once('/')
        .map_or((None, key), |(prefix, name)| (Some(prefix), name));
    if let Some(prefix) = prefix
        && (prefix.len() > 253
            || prefix.is_empty()
            || !prefix.split('.').all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .next()
                        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && part
                        .bytes()
                        .last()
                        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
                    && part
                        .bytes()
                        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'-')
            }))
    {
        return false;
    }
    !name.is_empty() && valid_value(name)
}

fn valid_value(value: &str) -> bool {
    value.len() <= 63
        && (value.is_empty()
            || (value
                .bytes()
                .next()
                .is_some_and(|c| c.is_ascii_alphanumeric())
                && value
                    .bytes()
                    .last()
                    .is_some_and(|c| c.is_ascii_alphanumeric())
                && value
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))))
}
