#![forbid(unsafe_code)]
#![recursion_limit = "512"]
//! Plugins are enabled by `plugin-<directive>` Cargo features (underscores in
//! Directive names become hyphens). Enabled but unimplemented Directives reject
//! configuration rather than silently accepting it.

use pharos_corefile::{BlockContext, Cursor, Directive, Error};
#[cfg(any(
    feature = "plugin-cache",
    feature = "plugin-forward",
    feature = "plugin-grpc",
    feature = "plugin-local"
))]
use pharos_proto::Name;
#[cfg(pharos_special_use)]
use pharos_proto::NameRef;
use pharos_server::{Lifecycle, ListenerKey, Router, Server, Transport};
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr, SocketAddrV6},
    sync::Arc,
};

#[cfg(feature = "plugin-acl")]
pub mod acl;
#[cfg(feature = "plugin-any")]
pub mod any;
#[cfg(feature = "plugin-auto")]
pub mod auto;
#[cfg(feature = "plugin-autopath")]
pub mod autopath;
#[cfg(feature = "plugin-bind")]
pub mod bind;
#[cfg(feature = "plugin-bufsize")]
pub mod bufsize;
#[cfg(feature = "plugin-cache")]
pub mod cache;
#[cfg(feature = "plugin-cancel")]
pub mod cancel;
#[cfg(feature = "plugin-chaos")]
pub mod chaos;
#[cfg(feature = "plugin-debug")]
pub mod debug;
#[cfg(any(feature = "plugin-kubernetes", feature = "plugin-k8s-external"))]
mod dns;
#[cfg(feature = "plugin-dns64")]
pub mod dns64;
#[cfg(feature = "plugin-dnssec")]
pub mod dnssec;
#[cfg(any(test, feature = "plugin-dynupdate"))]
pub mod dynupdate;
#[cfg(feature = "plugin-erratic")]
pub mod erratic;
#[cfg(feature = "plugin-errors")]
pub mod errors;
pub mod expression;
#[cfg(feature = "plugin-file")]
pub mod file;
pub mod gotemplate;
#[cfg(feature = "plugin-grpc")]
pub mod grpc;
#[cfg(feature = "plugin-grpc-server")]
pub mod grpc_server;
#[cfg(feature = "plugin-header")]
pub mod header;
#[cfg(any(
    feature = "plugin-health",
    feature = "plugin-errors",
    feature = "plugin-reload",
    feature = "plugin-hosts",
    feature = "plugin-file",
    feature = "plugin-auto",
    feature = "plugin-loadbalance",
    feature = "plugin-kubernetes",
    feature = "plugin-cancel",
    feature = "plugin-timeouts",
    feature = "plugin-erratic",
    feature = "plugin-trace"
))]
pub mod health;
#[cfg(feature = "plugin-hosts")]
pub mod hosts;
#[cfg(feature = "plugin-https")]
pub mod https;
#[cfg(feature = "plugin-https3")]
pub mod https3;
mod ipnet;
#[cfg(feature = "plugin-k8s-external")]
pub mod k8s_external;
#[cfg(feature = "plugin-kubernetes")]
pub mod kubernetes;
#[cfg(feature = "plugin-loadbalance")]
pub mod loadbalance;
#[cfg(feature = "plugin-local")]
pub mod local;
mod message_len;
#[cfg(feature = "plugin-minimal")]
pub mod minimal;
#[cfg(feature = "plugin-multisocket")]
pub mod multisocket;
#[cfg(feature = "plugin-nsid")]
pub mod nsid;
pub mod proxy;
mod regex_match;
#[cfg(feature = "plugin-rewrite")]
pub mod rewrite;
#[cfg(any(feature = "plugin-dns64", feature = "plugin-siit"))]
mod rfc6052;
#[cfg(feature = "plugin-secondary")]
pub mod secondary;
mod serial;
#[cfg(feature = "plugin-sign")]
pub mod sign;
#[cfg(feature = "plugin-siit")]
pub mod siit;
#[cfg(any(
    feature = "plugin-file",
    feature = "plugin-secondary",
    feature = "plugin-auto",
    feature = "plugin-sign",
    feature = "plugin-dynupdate"
))]
pub mod zone;

#[cfg(all(test, feature = "plugin-cache", feature = "plugin-hosts"))]
mod self_lookup_test;

#[cfg(feature = "plugin-dnstap")]
pub mod dnstap;
#[cfg(feature = "plugin-forward")]
pub mod forward;
#[cfg(feature = "plugin-geoip")]
pub mod geoip;

#[cfg(feature = "plugin-log")]
pub mod log;
#[cfg(feature = "plugin-log")]
pub use log::format as log_format;
#[cfg(feature = "plugin-loop")]
pub mod r#loop;
#[cfg(feature = "plugin-metadata")]
pub mod metadata;
#[cfg(feature = "plugin-pprof")]
pub mod pprof;
#[cfg(feature = "plugin-prometheus")]
pub mod prometheus;
#[cfg(feature = "plugin-proxyproto")]
pub mod proxyproto;
#[cfg(feature = "plugin-quic")]
pub mod quic;
#[cfg(feature = "plugin-ready")]
pub mod ready;
#[cfg(feature = "plugin-reload")]
pub mod reload;
#[cfg(feature = "plugin-root")]
pub mod root;
#[cfg(feature = "plugin-shed")]
pub mod shed;
#[cfg(feature = "plugin-template")]
pub mod template;
#[cfg(feature = "plugin-timeouts")]
pub mod timeouts;
#[cfg(feature = "plugin-tls")]
pub mod tls;
#[cfg(feature = "plugin-trace")]
pub mod trace;
#[cfg(feature = "plugin-transfer")]
pub mod transfer;
#[cfg(feature = "plugin-tsig")]
pub mod tsig;
#[cfg(feature = "plugin-view")]
pub mod view;
#[cfg(feature = "plugin-whoami")]
pub mod whoami;

include!(concat!(env!("OUT_DIR"), "/plugins.rs"));

#[cfg(pharos_special_use)]
// RFC 2181 §7.3 and RFC 6303 §3: empty-zone SOA MNAME is resolvable localhost.
pub(crate) const LOCALHOST_NAME: &[u8] = b"\x09localhost\0";

// RFC 6303 §3 and RFC 1035 §3.3.13: shared SOA RNAME and timers for empty Zones.
#[cfg(pharos_special_use)]
pub(crate) const EMPTY_ZONE_SOA_TAIL: &[u8] =
    b"\x06nobody\x07invalid\0\0\0\0\x01\0\0\0\0\0\0\0\0\0\0\0\0\0\x09\x3a\x80";

#[cfg(pharos_special_use)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SpecialUse {
    Test,
    Invalid,
    Reverse { zone_labels: usize },
}

#[cfg(pharos_special_use)]
impl SpecialUse {
    // RFC 6761 §§6.1–6.2 permit opt-in forwarding only for private reverse and test names.
    #[cfg(feature = "plugin-forward")]
    pub(crate) const fn permits_upstream(self) -> bool {
        matches!(self, Self::Test | Self::Reverse { .. })
    }

    pub(crate) const fn zone_labels(self) -> usize {
        match self {
            Self::Test | Self::Invalid => 1,
            Self::Reverse { zone_labels } => zone_labels,
        }
    }
}

// RFC 6761 §§6.1–6.4 and RFC 6303 §4: classify reserved suffixes by wire labels without allocating.
#[cfg(pharos_special_use)]
pub(crate) fn special_use(name: NameRef<'_>) -> Option<SpecialUse> {
    // RFC 6303 §4: avoid reverse-zone storage for names outside `.arpa`.
    let mut last = None;
    for label in name.labels() {
        last = Some(label);
    }
    let last = last?;
    if last.eq_ignore_ascii_case(b"test") {
        return Some(SpecialUse::Test);
    }
    if last.eq_ignore_ascii_case(b"invalid") {
        return Some(SpecialUse::Invalid);
    }
    if !last.eq_ignore_ascii_case(b"arpa") {
        return None;
    }

    // RFC 6303 §4: retain the catalogue suffix in bounded stack storage.
    let mut labels = [&[][..]; 34];
    let mut count = 0;
    for label in name.labels() {
        labels[count % labels.len()] = label;
        count += 1;
    }
    let in_addr = has_suffix(&labels, count, &[b"in-addr", b"arpa"]);
    let ip6 = has_suffix(&labels, count, &[b"ip6", b"arpa"]);
    if !in_addr && !ip6 {
        return None;
    }

    if in_addr {
        for zone in [
            &[b"10".as_slice(), b"in-addr", b"arpa"][..],
            &[b"168", b"192", b"in-addr", b"arpa"],
            &[b"0", b"in-addr", b"arpa"],
            &[b"127", b"in-addr", b"arpa"],
            &[b"254", b"169", b"in-addr", b"arpa"],
            &[b"2", b"0", b"192", b"in-addr", b"arpa"],
            &[b"100", b"51", b"198", b"in-addr", b"arpa"],
            &[b"113", b"0", b"203", b"in-addr", b"arpa"],
            &[b"255", b"255", b"255", b"255", b"in-addr", b"arpa"],
            &[b"255", b"in-addr", b"arpa"],
        ] {
            if has_suffix(&labels, count, zone) {
                return Some(SpecialUse::Reverse {
                    zone_labels: zone.len(),
                });
            }
        }
        for first in [
            b"16".as_slice(),
            b"17",
            b"18",
            b"19",
            b"20",
            b"21",
            b"22",
            b"23",
            b"24",
            b"25",
            b"26",
            b"27",
            b"28",
            b"29",
            b"30",
            b"31",
        ] {
            if has_suffix(&labels, count, &[first, b"172", b"in-addr", b"arpa"]) {
                return Some(SpecialUse::Reverse { zone_labels: 4 });
            }
        }
    }

    if ip6 {
        if has_ipv6_zone_suffix(&labels, count, b"0") {
            return Some(SpecialUse::Reverse { zone_labels: 34 });
        }
        if has_ipv6_zone_suffix(&labels, count, b"1") {
            return Some(SpecialUse::Reverse { zone_labels: 34 });
        }
        for zone in [
            &[b"d".as_slice(), b"f", b"ip6", b"arpa"][..],
            &[b"8", b"e", b"f", b"ip6", b"arpa"],
            &[b"9", b"e", b"f", b"ip6", b"arpa"],
            &[b"a", b"e", b"f", b"ip6", b"arpa"],
            &[b"b", b"e", b"f", b"ip6", b"arpa"],
            &[
                b"8", b"b", b"d", b"0", b"1", b"0", b"0", b"2", b"ip6", b"arpa",
            ],
        ] {
            if has_suffix(&labels, count, zone) {
                return Some(SpecialUse::Reverse {
                    zone_labels: zone.len(),
                });
            }
        }
    }
    None
}

#[cfg(pharos_special_use)]
fn has_ipv6_zone_suffix(labels: &[&[u8]; 34], count: usize, first: &[u8]) -> bool {
    count >= 34
        && (0..34).all(|index| {
            let label = labels[(count - 1 - index) % labels.len()];
            match 33 - index {
                0 => label.eq_ignore_ascii_case(first),
                1..=31 => label == b"0",
                32 => label.eq_ignore_ascii_case(b"ip6"),
                _ => label.eq_ignore_ascii_case(b"arpa"),
            }
        })
}

#[cfg(pharos_special_use)]
fn has_suffix(labels: &[&[u8]; 34], count: usize, suffix: &[&[u8]]) -> bool {
    count >= suffix.len()
        && suffix.iter().rev().enumerate().all(|(index, suffix)| {
            labels[(count - 1 - index) % labels.len()].eq_ignore_ascii_case(suffix)
        })
}

#[cfg(any(
    feature = "plugin-cache",
    feature = "plugin-forward",
    feature = "plugin-grpc",
    feature = "plugin-local"
))]
pub(crate) fn name_within(name: NameRef<'_>, zone: &Name) -> bool {
    #[cfg(any(
        feature = "plugin-file",
        feature = "plugin-secondary",
        feature = "plugin-auto",
        feature = "plugin-sign",
        feature = "plugin-dynupdate"
    ))]
    {
        // RFC 1035 §4.1.4: expand compressed NameRef to stack wire for Zone::contains.
        let mut wire = [0u8; 255];
        let mut len = 0;
        for label in name.labels() {
            wire[len] = label.len() as u8;
            len += 1;
            wire[len..len + label.len()].copy_from_slice(label);
            len += label.len();
        }
        wire[len] = 0;
        crate::zone::contains(&wire[..=len], zone)
    }
    #[cfg(not(any(
        feature = "plugin-file",
        feature = "plugin-secondary",
        feature = "plugin-auto",
        feature = "plugin-sign",
        feature = "plugin-dynupdate"
    )))]
    {
        // RFC 1034 §3.1: a Domain contains itself and every name with its label suffix.
        let zone = NameRef::parse(zone.as_wire(), 0).expect("configured Domain");
        let count = name.labels().count();
        let suffix = zone.labels().count();
        count >= suffix
            && name
                .labels()
                .skip(count - suffix)
                .zip(zone.labels())
                .all(|(label, suffix)| label.eq_ignore_ascii_case(suffix))
    }
}

// RFC 1035 §4.1.1: share Response buffer validation and MessageBuilder setup across Plugins.
#[cfg(pharos_special_use)]
pub(crate) fn response_builder<'a>(
    response: &'a mut Vec<u8>,
    query: pharos_proto::Message<'_>,
    protocol: pharos_server::Protocol,
    max_response_size: usize,
    flags: u16,
) -> Result<pharos_proto::MessageBuilder<'a>, pharos_server::Error> {
    let max = max_response_size.max(512);
    if response.capacity() < max {
        if protocol == pharos_server::Protocol::Tcp {
            response.reserve(max.saturating_sub(response.len()));
        } else {
            return Err(pharos_server::Error::ResponseBufferTooSmall);
        }
    }
    pharos_proto::MessageBuilder::new(response, max, query.id(), flags)
        .map_err(pharos_server::Error::Build)
}

#[cfg(pharos_special_use)]
pub(crate) fn special_nxdomain(
    response: &mut Vec<u8>,
    query: pharos_proto::Message<'_>,
    protocol: pharos_server::Protocol,
    max_response_size: usize,
    special: SpecialUse,
    recursion_available: bool,
) -> pharos_server::Outcome {
    let Some(question) = query.questions().next() else {
        return pharos_server::Outcome::Drop;
    };
    // RFC 6761 §§6.1, 6.2 and 6.4: answer reserved names locally; RFC 2308 §3: attach an SOA.
    let mut flags = 0x8003 | (query.flags() & 0x7800);
    // RFC 6303 §3 and RFC 1034 §4.3.2: reverse empty-zone negatives are authoritative.
    if matches!(special, SpecialUse::Reverse { .. }) {
        flags |= 0x0400;
    }
    if recursion_available {
        flags |= 0x0080;
    }
    if query.opcode() == pharos_proto::Opcode::QUERY {
        flags |= query.flags() & 0x0110;
    }
    let mut builder = match response_builder(response, query, protocol, max_response_size, flags) {
        Ok(builder) => builder,
        Err(error) => return pharos_server::Outcome::Error(error),
    };
    if let Err(error) = builder.question(question.name, question.qtype, question.qclass) {
        return pharos_server::Outcome::Error(pharos_server::Error::Build(error));
    }
    let count = question.name.labels().count();
    let start = count - special.zone_labels();
    let mut owner_wire = [0u8; 255];
    let mut owner_len = 0;
    for label in question.name.labels().skip(start) {
        owner_wire[owner_len] = label.len() as u8;
        owner_len += 1;
        owner_wire[owner_len..owner_len + label.len()].copy_from_slice(label);
        owner_len += label.len();
    }
    owner_wire[owner_len] = 0;
    owner_len += 1;
    let owner = NameRef::parse(&owner_wire[..owner_len], 0).expect("special-use Zone suffix");
    let mut soa = [0u8; LOCALHOST_NAME.len() + EMPTY_ZONE_SOA_TAIL.len()];
    soa[..LOCALHOST_NAME.len()].copy_from_slice(LOCALHOST_NAME);
    soa[LOCALHOST_NAME.len()..LOCALHOST_NAME.len() + EMPTY_ZONE_SOA_TAIL.len()]
        .copy_from_slice(EMPTY_ZONE_SOA_TAIL);
    // RFC 1035 §3.2.5: QCLASS ANY is a wildcard, not a resource-record class.
    let class = if question.qclass == pharos_proto::Class::ANY {
        pharos_proto::Class::IN
    } else {
        question.qclass
    };
    if let Err(error) = builder.record(
        pharos_proto::Section::Authority,
        owner,
        pharos_proto::Type::SOA,
        class,
        604_800,
        &soa[..LOCALHOST_NAME.len() + EMPTY_ZONE_SOA_TAIL.len()],
    ) {
        return pharos_server::Outcome::Error(pharos_server::Error::Build(error));
    }
    let _ = builder.finish();
    pharos_server::Outcome::Response
}

#[cfg(all(test, pharos_special_use))]
mod special_use_tests {
    use super::{SpecialUse, special_use};
    use pharos_proto::Name;

    fn classify(name: &str) -> Option<SpecialUse> {
        let name: Name = name.parse().unwrap();
        special_use(name.as_name_ref())
    }

    #[test]
    fn recognizes_reserved_apices_and_mixed_case() {
        assert_eq!(classify("test."), Some(SpecialUse::Test));
        assert_eq!(classify("invalid."), Some(SpecialUse::Invalid));
        assert_eq!(classify("Api.TeSt."), Some(SpecialUse::Test));
        assert_eq!(classify("InVaLiD."), Some(SpecialUse::Invalid));
    }

    #[test]
    fn reverse_catalogue_requires_a_zone_suffix() {
        assert_eq!(classify("in-addr.arpa."), None);
        assert_eq!(
            classify("255.in-addr.arpa."),
            Some(SpecialUse::Reverse { zone_labels: 3 })
        );
    }

    #[test]
    fn ipv6_reverse_zero_zones_require_34_labels_and_allow_prefixes() {
        let short = format!("1.{}.ip6.arpa.", vec!["0"; 30].join("."));
        let zone = format!("1.{}.ip6.arpa.", vec!["0"; 31].join("."));
        assert_eq!(classify(&short), None);
        assert_eq!(
            classify(&zone),
            Some(SpecialUse::Reverse { zone_labels: 34 })
        );
        assert_eq!(
            classify(&format!("host.{zone}")),
            Some(SpecialUse::Reverse { zone_labels: 34 })
        );
    }
}

/// Plugin-specific CoreDNS compatibility notes in their documented order.
pub const COMPATIBILITY: &[(&str, &str)] = &[
    ("acl", include_str!("acl/README.md")),
    ("any", include_str!("any/README.md")),
    ("autopath", include_str!("autopath/README.md")),
    ("bind", include_str!("bind/README.md")),
    ("bufsize", include_str!("bufsize/README.md")),
    ("cache", include_str!("cache/README.md")),
    ("cancel", include_str!("cancel/README.md")),
    ("chaos", include_str!("chaos/README.md")),
    ("debug", include_str!("debug/README.md")),
    ("dns64", include_str!("dns64/README.md")),
    ("dnssec", include_str!("dnssec/README.md")),
    ("dnstap", include_str!("dnstap/README.md")),
    ("dynupdate", include_str!("dynupdate/README.md")),
    ("errors", include_str!("errors/README.md")),
    ("erratic", include_str!("erratic/README.md")),
    ("file", include_str!("file/README.md")),
    ("auto", include_str!("auto/README.md")),
    ("secondary", include_str!("secondary/README.md")),
    ("forward", include_str!("forward/README.md")),
    ("geoip", include_str!("geoip/README.md")),
    ("grpc", include_str!("grpc/README.md")),
    ("grpc_server", include_str!("grpc_server/README.md")),
    ("header", include_str!("header/README.md")),
    ("health", include_str!("health/README.md")),
    ("hosts", include_str!("hosts/README.md")),
    ("https", include_str!("https/README.md")),
    ("https3", include_str!("https3/README.md")),
    ("k8s_external", include_str!("k8s_external/README.md")),
    ("kubernetes", include_str!("kubernetes/README.md")),
    ("loadbalance", include_str!("loadbalance/README.md")),
    ("local", include_str!("local/README.md")),
    ("log", include_str!("log/README.md")),
    ("metadata", include_str!("metadata/README.md")),
    ("loop", include_str!("loop/README.md")),
    ("minimal", include_str!("minimal/README.md")),
    ("multisocket", include_str!("multisocket/README.md")),
    ("nsid", include_str!("nsid/README.md")),
    ("pprof", include_str!("pprof/README.md")),
    ("prometheus", include_str!("prometheus/README.md")),
    ("proxyproto", include_str!("proxyproto/README.md")),
    ("quic", include_str!("quic/README.md")),
    ("ready", include_str!("ready/README.md")),
    ("reload", include_str!("reload/README.md")),
    ("rewrite", include_str!("rewrite/README.md")),
    ("siit", include_str!("siit/README.md")),
    ("sign", include_str!("sign/README.md")),
    ("root", include_str!("root/README.md")),
    ("shed", include_str!("shed/README.md")),
    ("template", include_str!("template/README.md")),
    ("timeouts", include_str!("timeouts/README.md")),
    ("tls", include_str!("tls/README.md")),
    ("tsig", include_str!("tsig/README.md")),
    ("transfer", include_str!("transfer/README.md")),
    ("trace", include_str!("trace/README.md")),
    ("view", include_str!("view/README.md")),
    ("whoami", include_str!("whoami/README.md")),
];

#[cfg(any(
    feature = "plugin-health",
    feature = "plugin-pprof",
    feature = "plugin-prometheus",
    feature = "plugin-ready"
))]
fn valid_http_address(address: &str) -> bool {
    let Some((host, port)) = address.rsplit_once(':') else {
        return false;
    };
    if port.contains(['[', ']']) {
        return false;
    }
    if host.starts_with('[') {
        host.ends_with(']') && !host[1..host.len() - 1].contains(['[', ']'])
    } else {
        !host.contains([':', '[', ']'])
    }
}

/// Directive registry in Plugin Order.
#[must_use]
pub fn directives() -> &'static [Directive<'static, Chain>] {
    DIRECTIVES
}

/// CoreDNS-style alphabetically sorted plugin listing, including final blank line.
#[must_use]
pub const fn plugins_listing() -> &'static str {
    PLUGINS_LISTING
}

/// Configured DNS Servers keyed by Listener.
pub type Servers = HashMap<ListenerKey, Server<Arc<Chain>>>;

#[cfg(feature = "plugin-k8s-external")]
fn k8s_external_error(chain: &Chain) -> Option<&'static str> {
    (chain.k8s_external.is_some() && chain.kubernetes.is_none())
        .then_some("plugin/k8s_external: kubernetes plugin not loaded")
}

/// Validate configured blocks without running Startup hooks.
pub fn validate_configuration(blocks: &[BlockContext<Chain>]) -> io::Result<()> {
    #[cfg(feature = "plugin-k8s-external")]
    for block in blocks {
        if let Some(error) = k8s_external_error(&block.config) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, error));
        }
    }
    #[cfg(not(feature = "plugin-k8s-external"))]
    let _ = blocks;
    Ok(())
}

/// Group Server Blocks by Listener and collect their hooks in block order.
/// The caller runs Startup before serving and Shutdown before Listeners drain.
pub fn servers(blocks: Vec<BlockContext<Chain>>) -> io::Result<(Servers, Lifecycle)> {
    servers_with_registry(blocks, pharos_server::metrics::Registry::default())
}

/// Build servers using a process-wide metrics registry.
pub fn servers_with_registry(
    blocks: Vec<BlockContext<Chain>>,
    metrics: pharos_server::metrics::Registry,
) -> io::Result<(Servers, Lifecycle)> {
    type ListenerGroup = (
        Router<Arc<Chain>>,
        Option<usize>,
        pharos_server::TcpOptions,
        bool,
        // The first Server Block's TLS identity and Domain, for the shared-Listener check.
        Option<(pharos_server::tls::ServerTls, String)>,
        pharos_server::QuicOptions,
    );
    let mut groups: HashMap<ListenerKey, ListenerGroup> = HashMap::new();
    // Limits of each `https://` Listener: the first Server Block's connection limit and the one explicit stream limit.
    let mut https_limits: HashMap<ListenerKey, (Option<usize>, Option<u32>)> = HashMap::new();
    // Limits of each `grpc://` Listener: the first Server Block's.
    let mut grpc_limits: HashMap<ListenerKey, pharos_server::GrpcOptions> = HashMap::new();
    // Limits of each `https3://` Listener: the first Server Block's `https3` Directive decides both.
    let mut https3_limits: HashMap<ListenerKey, (Option<usize>, Option<usize>)> = HashMap::new();
    #[cfg(feature = "plugin-proxyproto")]
    let mut proxies: HashMap<ListenerKey, Arc<pharos_server::proxyproto::Config>> = HashMap::new();
    let mut lifecycle = Lifecycle::default();
    #[cfg(feature = "plugin-debug")]
    let debug = blocks.iter().any(|block| block.config.debug.is_some());
    #[cfg(not(feature = "plugin-debug"))]
    let debug = false;
    lifecycle.register_sync(pharos_server::Phase::Started, move || {
        pharos_server::logging::set_debug_enabled(debug);
        Ok(())
    });
    #[cfg(feature = "plugin-forward")]
    let _ = metrics.forward();
    #[cfg(feature = "plugin-local")]
    let _ = metrics.local();
    #[cfg(feature = "plugin-health")]
    metrics.enable_health_metrics();
    #[cfg(feature = "plugin-prometheus")]
    let mut exporters = std::collections::BTreeMap::new();
    #[cfg(feature = "plugin-pprof")]
    let mut pprof_addresses: Vec<(String, Option<i64>)> = Vec::new();
    #[cfg(feature = "plugin-ready")]
    let ready_state = Arc::new(ready::State::default());
    #[cfg(feature = "plugin-ready")]
    let mut ready_addresses = std::collections::BTreeSet::new();
    #[cfg(feature = "plugin-tls")]
    let mut blocks = blocks;
    #[cfg(feature = "plugin-tls")]
    {
        if let Some(acme) = tls::acme::link(&mut blocks)? {
            acme.register(&mut lifecycle);
        }
    }
    #[cfg(feature = "plugin-health")]
    let mut health_addresses: Vec<(String, std::time::Duration)> = Vec::new();
    #[cfg(feature = "plugin-ready")]
    {
        let state = Arc::clone(&ready_state);
        // This hook precedes all block shutdown hooks, including a future lameduck delay.
        lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
            state.begin_shutdown();
            Ok(())
        });
    }
    #[cfg(feature = "plugin-tsig")]
    let mut tsig_keyrings = tsig::KeyRings::default();
    #[cfg(any(feature = "plugin-acl", feature = "plugin-template"))]
    let view_names = {
        let mut names = blocks
            .iter()
            .map(|block| pharos_server::Chain::view_name(&block.config))
            .filter(|name| !name.is_empty())
            .map(str::to_owned)
            .collect::<Vec<_>>();
        names.sort_unstable();
        names.dedup();
        names
    };
    for block in blocks {
        #[cfg(any(
            feature = "plugin-forward",
            feature = "plugin-grpc",
            feature = "plugin-cache",
            feature = "plugin-local",
            feature = "plugin-acl",
            feature = "plugin-dns64",
            feature = "plugin-dnssec",
            feature = "plugin-k8s-external",
            feature = "plugin-siit",
            feature = "plugin-autopath",
            feature = "plugin-template",
            feature = "plugin-tsig"
        ))]
        let mut block = block;
        #[cfg(feature = "plugin-forward")]
        if let Some(forward) = &mut block.config.forward {
            forward.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-grpc")]
        if let Some(grpc) = &mut block.config.grpc {
            grpc.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-local")]
        if let Some(local) = &mut block.config.local {
            local.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-hosts")]
        if let Some(hosts) = &block.config.hosts {
            hosts.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-trace")]
        if let Some(trace) = &block.config.trace {
            trace.set_metrics(&metrics);
        }

        #[cfg(feature = "plugin-dnstap")]
        if let Some(dnstap) = &block.config.dnstap {
            dnstap.set_metrics(&metrics);
        }
        #[cfg(all(feature = "plugin-forward", feature = "plugin-dnstap"))]
        if let (Some(forward), Some(dnstap)) = (&mut block.config.forward, &block.config.dnstap) {
            forward.set_taps(dnstap.taps());
        }
        #[cfg(feature = "plugin-kubernetes")]
        if let Some(kubernetes) = &block.config.kubernetes {
            kubernetes.set_metrics(&metrics);
        }
        #[cfg(feature = "plugin-k8s-external")]
        if let Some(error) = k8s_external_error(&block.config) {
            lifecycle.register_sync(pharos_server::Phase::Startup, move || {
                Err(io::Error::new(io::ErrorKind::InvalidInput, error))
            });
        }
        #[cfg(feature = "plugin-k8s-external")]
        if let Some(external) = &mut block.config.k8s_external
            && let Some(kubernetes) = &block.config.kubernetes
        {
            external.bind_kubernetes(kubernetes);
        }
        #[cfg(feature = "plugin-transfer")]
        block.config.bind_transferers();
        #[cfg(feature = "plugin-health")]
        if let Some(health) = &block.config.health
            && !health_addresses
                .iter()
                .any(|(address, _)| *address == health.address)
        {
            health_addresses.push((health.address.clone(), health.lameduck));
        }
        #[cfg(feature = "plugin-pprof")]
        if let Some(pprof) = &block.config.pprof {
            // CoreDNS v1.15.0 plugin/pprof/pprof.go: one pprof listener serves an address; Server Blocks naming it share it.
            match pprof_addresses
                .iter_mut()
                .find(|(address, _)| *address == pprof.address)
            {
                // CoreDNS v1.15.0 plugin/pprof/setup.go: any block that sets `block` counts, the first value wins.
                Some((_, rate)) => *rate = rate.or(pprof.block_rate),
                None => pprof_addresses.push((pprof.address.clone(), pprof.block_rate)),
            }
        }
        #[cfg(feature = "plugin-ready")]
        if let Some(ready) = &block.config.ready {
            ready_addresses.insert(ready.address.clone());
            ready_state.set_continuous(ready.continuous);
        }
        #[cfg(feature = "plugin-prometheus")]
        if let Some(prometheus) = &block.config.prometheus {
            if exporters
                .get(&prometheus.address)
                .is_some_and(|config| config != &prometheus.tls_config)
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "conflicting prometheus TLS configuration",
                ));
            }
            exporters
                .entry(prometheus.address.clone())
                .or_insert_with(|| prometheus.tls_config.clone());
        }
        let keys = block.keys().to_vec();
        let addresses = block.listen_addresses.clone();
        let empty = pharos_server::Chain::is_empty(&block.config);
        lifecycle.extend(&block.config.lifecycle);
        #[cfg(feature = "plugin-tls")]
        let tls = block.config.tls.as_ref().and_then(|tls| tls.server());
        #[cfg(not(feature = "plugin-tls"))]
        let tls: Option<pharos_server::tls::ServerTls> = None;
        let mut routes = Vec::new();
        for key in keys {
            // RFC 7858 §3.2: DoT is TLS; CoreDNS's other encrypted Transports need a certificate too.
            let requires_tls = || {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "{}:// Server Block Key requires the tls Directive",
                        key.transport
                    ),
                )
            };
            let transport = match key.transport.as_str() {
                "dns" => Transport::Dns,
                "tls" if tls.is_some() => Transport::Tls,
                "tls" => return Err(requires_tls()),
                "quic" if tls.is_some() => Transport::Quic,
                "grpc" if tls.is_some() => Transport::Grpc,
                "https3" if tls.is_some() => Transport::Https3,
                "https" | "grpc" | "quic" | "https3" if tls.is_none() => return Err(requires_tls()),
                "https" => Transport::Https,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "unsupported Listener transport",
                    ));
                }
            };
            let port: u16 = key.port.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener port")
            })?;
            let domain: pharos_proto::Name = key.domain.parse().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener Domain")
            })?;
            for address in &addresses {
                let socket = if address.is_empty() {
                    SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), port)
                // RFC 4007 §11.2: Map a textual zone identifier to a local socket scope ID.
                } else if let Some((ip, interface)) = address.split_once('%') {
                    let ip: Ipv6Addr = ip.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener address")
                    })?;
                    // POSIX.1-2024 if_nametoindex: map an interface name to its index.
                    let scope = nix::net::if_::if_nametoindex(interface)
                        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
                    SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope))
                } else {
                    let ip: IpAddr = address.parse().map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidInput, "invalid Listener address")
                    })?;
                    let ip = match ip {
                        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or(IpAddr::V6(ip), IpAddr::V4),
                        ip => ip,
                    };
                    SocketAddr::new(ip, port)
                };
                routes.push((
                    ListenerKey {
                        transport,
                        address: socket,
                    },
                    domain.clone(),
                ));
            }
        }
        #[cfg(feature = "plugin-loop")]
        if let Some(plugin) = &block.config.r#loop
            && let Some((listener, _)) = routes.first()
        {
            plugin.register(&mut lifecycle, listener.address);
        }
        #[cfg(feature = "plugin-tsig")]
        if let Some(tsig) = &mut block.config.tsig {
            tsig.register(routes.iter().map(|(key, _)| *key), &mut tsig_keyrings);
        }
        #[cfg(feature = "plugin-cache")]
        if block.config.cache.is_some() {
            let view_name = pharos_server::Chain::view_name(&block.config).to_owned();
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            if let Some(cache) = &mut block.config.cache {
                cache.set_metrics(&metrics, &listeners, &view_name);
            }
        }
        #[cfg(feature = "plugin-acl")]
        if let Some(acl) = &mut block.config.acl {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            acl.set_metrics(&metrics, &listeners, &view_names);
        }
        #[cfg(feature = "plugin-dns64")]
        if let Some(dns64) = &mut block.config.dns64 {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            dns64.set_metrics(&metrics, &listeners);
        }
        #[cfg(feature = "plugin-template")]
        if let Some(template) = &mut block.config.template {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            template.set_metrics(&metrics, &listeners, &view_names);
        }
        #[cfg(feature = "plugin-dnssec")]
        if let Some(dnssec) = &mut block.config.dnssec {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            dnssec.set_metrics(&metrics, &listeners);
        }
        #[cfg(feature = "plugin-siit")]
        if let Some(siit) = &mut block.config.siit {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            siit.set_metrics(&metrics, &listeners);
        }
        #[cfg(feature = "plugin-autopath")]
        if let Some(provider) = block
            .config
            .autopath
            .as_ref()
            .and_then(|plugin| plugin.provider.as_deref())
            && provider != "kubernetes"
            && !(cfg!(feature = "plugin-erratic") && provider == "erratic")
        {
            let mut found = false;
            pharos_server::Chain::visit_enabled(&block.config, &mut |name| {
                found |= name == provider
            });
            if found {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("autopath: {provider} does not implement AutoPather"),
                ));
            }
        }
        #[cfg(feature = "plugin-autopath")]
        if let Some(autopath) = &mut block.config.autopath {
            let listeners = routes.iter().map(|(key, _)| *key).collect::<Vec<_>>();
            autopath.set_metrics(&metrics, &listeners);
            #[cfg(feature = "plugin-kubernetes")]
            autopath.bind_kubernetes(block.config.kubernetes.as_ref());
            #[cfg(feature = "plugin-erratic")]
            autopath.bind_erratic(block.config.erratic.as_ref());
        }
        #[cfg(feature = "plugin-multisocket")]
        let workers = block.config.multisocket.flatten();
        #[cfg(not(feature = "plugin-multisocket"))]
        let workers = None;
        let chain = Arc::new(block.config);
        #[cfg(feature = "plugin-chaos")]
        let allow_non_in = chain.chaos.is_some();
        #[cfg(not(feature = "plugin-chaos"))]
        let allow_non_in = false;
        #[cfg(feature = "plugin-forward")]
        let allow_non_in = allow_non_in || chain.forward.is_some();
        #[cfg(feature = "plugin-cache")]
        if let Some(cache) = &chain.cache {
            cache.bind(&chain);
        }
        #[cfg(feature = "plugin-forward")]
        if chain.forward.is_some() {
            let chain = Arc::clone(&chain);
            lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
                if let Some(forward) = &chain.forward {
                    forward.stop();
                }
                Ok(())
            });
        }
        #[cfg(feature = "plugin-grpc")]
        if chain.grpc.is_some() {
            let chain = Arc::clone(&chain);
            lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
                if let Some(grpc) = &chain.grpc {
                    grpc.stop();
                }
                Ok(())
            });
        }
        #[cfg(feature = "plugin-ready")]
        if chain.ready.is_some() {
            chain.collect_readiness(&ready_state);
        }
        // CoreDNS v1.15.0 core/dnsserver/server_quic.go NewServerQUIC: the first Server Block's limits apply.
        #[cfg(feature = "plugin-quic")]
        let quic = chain
            .quic
            .as_ref()
            .map_or_else(Default::default, quic::Quic::options);
        #[cfg(not(feature = "plugin-quic"))]
        let quic = pharos_server::QuicOptions::default();
        for (listener, domain) in routes {
            let group = groups.entry(listener).or_insert_with(|| {
                (
                    Router::default(),
                    workers,
                    pharos_server::TcpOptions::default(),
                    false,
                    None,
                    quic,
                )
            });
            if matches!(
                listener.transport,
                Transport::Tls
                    | Transport::Https
                    | Transport::Grpc
                    | Transport::Https3
                    | Transport::Quic
            ) && let Some(tls) = &tls
            {
                match &group.4 {
                    // CoreDNS v1.15.0 core/dnsserver/tlsconfig.go sharedTLSConfig: blocks on one Listener agree.
                    Some((first, zone)) => {
                        if let Some(reason) = first.conflict(tls) {
                            return Err(io::Error::new(
                                io::ErrorKind::InvalidInput,
                                format!(
                                    "conflicting TLS configuration for shared listener {}://{} between zones {zone:?} and {:?}: {reason}",
                                    match listener.transport {
                                        Transport::Tls => "tls",
                                        Transport::Grpc => "grpc",
                                        Transport::Quic => "quic",
                                        Transport::Https3 => "https3",
                                        _ => "https",
                                    },
                                    listener.address,
                                    domain.to_string(),
                                ),
                            ));
                        }
                    }
                    None => group.4 = Some((tls.clone(), domain.to_string())),
                }
            }
            // CoreDNS v1.15.0 core/dnsserver/server_grpc.go NewServergRPC: the first Server Block's limits apply.
            #[cfg(feature = "plugin-grpc-server")]
            if listener.transport == Transport::Grpc {
                grpc_limits.entry(listener).or_insert_with(|| {
                    chain
                        .grpc_server
                        .as_ref()
                        .map_or_else(Default::default, grpc_server::GrpcServer::options)
                });
            }
            #[cfg(feature = "plugin-https")]
            if listener.transport == Transport::Https {
                let first = !https_limits.contains_key(&listener);
                let limits = https_limits.entry(listener).or_default();
                let configured = chain.https.as_ref();
                // CoreDNS v1.15.0 core/dnsserver/server_https.go: only the first block's max_connections applies.
                if first {
                    limits.0 = configured.and_then(|https| https.max_connections);
                }
                // CoreDNS v1.15.0 core/dnsserver/server_https.go: blocks sharing a Listener share one max_streams.
                if let Some(streams) = configured.and_then(|https| https.max_streams) {
                    if let Some(first) = limits.1.filter(|first| *first != streams) {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "conflicting max_streams values for shared HTTPS listener {}: {first} and {streams}",
                                listener.address
                            ),
                        ));
                    }
                    limits.1 = Some(streams);
                }
            }
            // CoreDNS v1.15.0 core/dnsserver/server_https3.go NewServerHTTPS3: the first Server Block's limits apply.
            #[cfg(feature = "plugin-https3")]
            if listener.transport == Transport::Https3 {
                https3_limits.entry(listener).or_insert_with(|| {
                    chain.https3.as_ref().map_or((None, None), |https3| {
                        (https3.max_streams, https3.max_connections)
                    })
                });
            }
            #[cfg(feature = "plugin-timeouts")]
            if let Some(options) = &chain.timeouts {
                if let Some(value) = options.read {
                    group.2.read = value;
                }
                if let Some(value) = options.write {
                    group.2.write = value;
                }
                if let Some(value) = options.idle {
                    group.2.idle = value;
                }
                if let Some(value) = options.max_tcp_queries {
                    group.2.max_queries = usize::try_from(value).ok();
                }
            }
            group.3 |= allow_non_in;
            // CoreDNS v1.15.0 core/dnsserver/server.go NewServer: a later Server Block's proxyproto replaces an earlier one.
            #[cfg(feature = "plugin-proxyproto")]
            if let Some(proxy) = &chain.proxyproto {
                proxies.insert(listener, Arc::clone(&proxy.config));
            }
            group.0.add(
                listener,
                domain,
                (!empty).then(|| Arc::clone(&chain)),
                vec![],
            );
        }
    }
    #[cfg(feature = "plugin-tsig")]
    tsig_keyrings.finish();
    let servers = groups
        .into_iter()
        .map(
            |(key, (router, workers, tcp_options, allow_non_in, tls, quic))| {
                let mut server = Server::with_registry(router, key, metrics.clone());
                server.tcp_options = tcp_options;
                // RFC 7301 §3.1: an HTTPS Listener offers h2 and http/1.1 through ALPN, a gRPC Listener only h2.
                server.tls = tls.map(|(tls, _)| match key.transport {
                    Transport::Https => tls.with_alpn(pharos_server::doh::ALPN),
                    Transport::Grpc => tls.with_alpn(pharos_server::grpc::ALPN),
                    // RFC 9114 §3.1: HTTP/3 over QUIC is selected by ALPN "h3".
                    Transport::Https3 => tls
                        .with_quic_alpn(pharos_server::doh::H3_ALPN)
                        .unwrap_or(tls),
                    _ => tls,
                });
                server.quic = quic;
                if let Some(options) = grpc_limits.get(&key) {
                    server.grpc = *options;
                }
                if let Some((connections, streams)) = https_limits.get(&key) {
                    server.https.max_connections =
                        connections.unwrap_or(server.https.max_connections);
                    server.https.max_streams = streams.unwrap_or(server.https.max_streams);
                }
                if let Some((streams, connections)) = https3_limits.get(&key) {
                    // CoreDNS v1.15.0 core/dnsserver/server_https3.go: 0 keeps the QUIC default or lifts the limit.
                    server.https.max_streams = streams.map_or(server.https.max_streams, |value| {
                        u32::try_from(value).unwrap_or(u32::MAX)
                    });
                    server.https.max_connections =
                        connections.unwrap_or(server.https.max_connections);
                }
                #[cfg(feature = "plugin-proxyproto")]
                {
                    server.proxyproto = proxies.get(&key).cloned();
                }
                server.debug = debug;
                server.allow_non_in = allow_non_in;
                if let Some(workers) = workers {
                    server.udp_workers = workers;
                }
                (key, server)
            },
        )
        .collect();
    #[cfg(feature = "plugin-health")]
    for (address, lameduck) in health_addresses {
        let listener = Arc::new(std::sync::Mutex::new(
            None::<(
                pharos_server::http::Listener,
                pharos_server::http::HealthProbe,
            )>,
        ));
        let startup_listener = Arc::clone(&listener);
        let registry = metrics.clone();
        let start = move || {
            let address = address.clone();
            let listener = Arc::clone(&startup_listener);
            let registry = registry.clone();
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                let server =
                    pharos_server::http::Listener::bind_with_methods(&address, |method, path| {
                        if method != "GET" {
                            return (path == "/health").then(|| {
                                (
                                    405,
                                    "text/plain; charset=utf-8",
                                    "Method Not Allowed\n".into(),
                                )
                            });
                        }
                        // RFC 9110 §9.3.1: GET /health returns the health representation.
                        Some(if path == "/health" {
                            // RFC 9110 §5.6.3: Media-type parameter OWS uses one SP.
                            (200, "text/plain; charset=utf-8", "OK".into())
                        } else {
                            // RFC 9110 §15.5.5: Unknown health paths have no representation.
                            (
                                404,
                                "text/plain; charset=utf-8",
                                "404 page not found\n".into(),
                            )
                        })
                    })
                    .await?;
                let probe = pharos_server::http::HealthProbe::start(&address, registry);
                *listener.lock().unwrap() = Some((server, probe));
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let restart_listener = Arc::clone(&listener);
        lifecycle.register(pharos_server::Phase::Restart, move || {
            let server = restart_listener.lock().unwrap().take();
            async move {
                if let Some((server, probe)) = server {
                    drop(probe);
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
        lifecycle.register(pharos_server::Phase::Shutdown, move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some((server, probe)) = server {
                    tokio::time::sleep(lameduck).await;
                    drop(probe);
                    server.shutdown().await?;
                }
                Ok(())
            }
        });
    }
    #[cfg(feature = "plugin-pprof")]
    for (address, block_rate) in pprof_addresses {
        // CoreDNS v1.15.0 plugin/pprof/pprof.go: the listener starts on startup, stops on restart and shutdown, and a failed restart brings it back.
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let start = move || {
            let address = address.clone();
            let listener = Arc::clone(&startup_listener);
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                let server = pharos_server::http::Listener::bind_async(
                    &address,
                    pprof::http::route,
                    // Go net/http/pprof Profile: a profile response outlasts the default five-second connection cap.
                    pprof::http::LIFETIME,
                )
                .await?;
                if let Some(rate) = block_rate {
                    // CoreDNS v1.15.0 plugin/pprof/pprof.go: runtime.SetBlockProfileRate has no Rust equivalent.
                    pharos_server::logging::log(
                        "INFO",
                        "pprof",
                        &format!(
                            "block profiling rate {rate} accepted but ignored: Pharos has no block profiler"
                        ),
                    );
                }
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stop = move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
    #[cfg(feature = "plugin-ready")]
    for address in ready_addresses {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let state = Arc::clone(&ready_state);
        let start = move || {
            let address = address.clone();
            let state = Arc::clone(&state);
            let listener = Arc::clone(&startup_listener);
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                let server = pharos_server::http::Listener::bind_with_methods(
                    &address,
                    move |method, path| {
                        if path != "/ready" {
                            return None;
                        }
                        if method != "GET" {
                            return Some((
                                405,
                                "text/plain; charset=utf-8",
                                "Method Not Allowed\n".into(),
                            ));
                        }
                        // RFC 9110 §9.3.1: GET /ready returns the readiness representation.
                        let (status, body) = state.response();
                        Some((status, "text/plain; charset=utf-8", body))
                    },
                )
                .await?;
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stop = move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
    #[cfg(feature = "plugin-prometheus")]
    for (address, tls_config) in exporters {
        let listener = Arc::new(std::sync::Mutex::new(None::<pharos_server::http::Listener>));
        let startup_listener = Arc::clone(&listener);
        let registry = metrics.clone();
        let start = move || {
            let address = address.clone();
            let tls_config = tls_config.clone();
            let registry = registry.clone();
            let listener = Arc::clone(&startup_listener);
            async move {
                if listener.lock().unwrap().is_some() {
                    return Ok(());
                }
                // exporter-toolkit v0.20.0 web.Validate: an invalid file fails before the address is bound.
                let security = match &tls_config {
                    Some(path) => prometheus::web_config::load(std::path::Path::new(path))?,
                    None => pharos_server::http::Security::default(),
                };
                let server = pharos_server::http::Listener::bind_secured(
                    &address,
                    move |method, path| {
                        if path != "/metrics" {
                            return None;
                        }
                        if method != "GET" {
                            return Some((
                                405,
                                "text/plain; charset=utf-8",
                                "Method Not Allowed\n".into(),
                            ));
                        }
                        let mut body = String::new();
                        // RFC 9110 §9.3.1: GET /metrics returns the current metrics representation.
                        registry.encode(&mut body);
                        // RFC 9110 §5.6.3: Media-type parameter OWS uses one SP for readability.
                        Some((200, "text/plain; version=0.0.4; charset=utf-8", body))
                    },
                    security,
                )
                .await?;
                *listener.lock().unwrap() = Some(server);
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Startup, start.clone());
        lifecycle.register(pharos_server::Phase::RestartFailed, start);
        let stop = move || {
            let server = listener.lock().unwrap().take();
            async move {
                if let Some(server) = server {
                    server.shutdown().await?;
                }
                Ok(())
            }
        };
        lifecycle.register(pharos_server::Phase::Restart, stop.clone());
        lifecycle.register(pharos_server::Phase::Shutdown, stop);
    }
    Ok((servers, lifecycle))
}

/// Placeholder for enabled but unimplemented Plugins, whose setup always fails.
#[derive(Debug)]
pub struct Unimplemented;

impl pharos_server::Plugin for Unimplemented {
    async fn serve<N: pharos_server::Next + Send>(
        &self,
        _cx: &mut pharos_server::Context<'_, '_>,
        _next: N,
    ) -> pharos_server::Outcome {
        pharos_server::Outcome::Error(pharos_server::Error::NotImplemented)
    }
}

#[cfg(any(
    feature = "plugin-dynupdate",
    feature = "plugin-hosts",
    feature = "plugin-file",
    feature = "plugin-auto",
    feature = "plugin-loadbalance",
    feature = "plugin-dnssec",
    feature = "plugin-sign",
    feature = "plugin-forward",
    feature = "plugin-grpc",
    feature = "plugin-tls"
))]
fn root_path(chain: &Chain) -> Option<&std::path::Path> {
    #[cfg(feature = "plugin-root")]
    {
        chain.root.as_deref()
    }
    #[cfg(not(feature = "plugin-root"))]
    {
        let _ = chain;
        None
    }
}

#[cfg(any(
    test,
    feature = "plugin-dynupdate",
    feature = "plugin-hosts",
    feature = "plugin-file",
    feature = "plugin-auto",
    feature = "plugin-loadbalance",
    feature = "plugin-dnssec",
    feature = "plugin-sign",
    feature = "plugin-forward",
    feature = "plugin-grpc",
    feature = "plugin-tls"
))]
fn resolve_path(path: std::path::PathBuf, root: Option<&std::path::Path>) -> std::path::PathBuf {
    use std::path::{Component, PathBuf};
    let Some(root) = root.filter(|_| path.is_relative()) else {
        return path;
    };
    let joined = root.join(path);
    let mut clean = PathBuf::new();
    for component in joined.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir
                if matches!(clean.components().next_back(), Some(Component::Normal(_))) =>
            {
                clean.pop();
            }
            Component::ParentDir if !clean.has_root() => clean.push(component),
            Component::ParentDir => {}
            _ => clean.push(component),
        }
    }
    if clean.as_os_str().is_empty() {
        clean.push(".");
    }
    clean
}

// CoreDNS v1.15.0 plugin/pkg/tls/tls.go NewTLSConfigFromArgs: `CA`, `CERT KEY` or `CERT KEY CA`, and no arguments for the system roots.
#[cfg(any(feature = "plugin-forward", feature = "plugin-grpc"))]
fn tls_client_from_args(
    args: &[String],
    root: Option<&std::path::Path>,
) -> io::Result<Option<Arc<pharos_server::tls::ClientConfig>>> {
    use pharos_server::tls::{ClientOptions, client_config};
    // CoreDNS v1.15.0 plugin/forward/setup.go and plugin/grpc/setup.go parseBlock: a relative path is joined to `root`.
    let path = |index: usize| resolve_path(args[index].clone().into(), root);
    let options = match args.len() {
        0 => return Ok(None),
        1 => ClientOptions {
            ca: Some(path(0)),
            identity: None,
        },
        2 | 3 => ClientOptions {
            ca: (args.len() == 3).then(|| path(2)),
            identity: Some((path(0), path(1))),
        },
        _ => return Err(io::ErrorKind::InvalidInput.into()),
    };
    client_config(&options).map(Some)
}

#[allow(dead_code)]
fn setup_unimplemented(cursor: &mut Cursor<'_>, _: &mut BlockContext<Chain>) -> Result<(), Error> {
    cursor.next();
    Err(cursor.error(format!("{}: plugin is not implemented", cursor.val())))
}
