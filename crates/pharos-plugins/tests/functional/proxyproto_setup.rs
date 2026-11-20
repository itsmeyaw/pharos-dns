#![forbid(unsafe_code)]
#![cfg(feature = "plugin-proxyproto")]

use std::{net::IpAddr, time::Duration};

use pharos_corefile::{BlockContext, configure, parse};
use pharos_plugins::{Chain, directives};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{
    Context, Metadata, Protocol, Transport,
    proxyproto::{Policy, TLV_LABEL},
};

fn configure_block(body: &str) -> Result<Vec<BlockContext<Chain>>, String> {
    let text = format!(".:53 {{\n{body}\n}}");
    configure(
        &parse("Corefile", &text).map_err(|e| e.to_string())?,
        directives(),
    )
    .map_err(|e| e.to_string())
}

fn config(body: &str) -> std::sync::Arc<pharos_server::proxyproto::Config> {
    let blocks = configure_block(body).unwrap_or_else(|error| panic!("{body}: {error}"));
    std::sync::Arc::clone(&blocks[0].config.proxyproto.as_ref().unwrap().config)
}

fn ip(text: &str) -> IpAddr {
    text.parse().unwrap()
}

// CoreDNS v1.15.0 plugin/proxyproto/setup_test.go TestSetup.
#[test]
fn coredns_setup_cases() {
    for (input, ttl, max) in [
        ("proxyproto", None, 0),
        ("proxyproto {\nallow 127.0.0.1/8 ::1/128\n}", None, 0),
        (
            "proxyproto {\nallow 127.0.0.1/8 ::1/128\ndefault ignore\n}",
            None,
            0,
        ),
        ("proxyproto {\nallow\n}", None, 0),
        (
            "proxyproto {\nudp_session_tracking 28s\n}",
            Some(28),
            10_240,
        ),
        (
            "proxyproto {\nallow 10.0.0.0/8\nudp_session_tracking 1m\n}",
            Some(60),
            10_240,
        ),
        (
            "proxyproto {\nudp_session_tracking 28s 20000\n}",
            Some(28),
            20_000,
        ),
        (
            "proxyproto {\nallow 10.0.0.0/8\nudp_session_tracking 1m 500\n}",
            Some(60),
            500,
        ),
    ] {
        let tracking = config(input).udp_tracking;
        assert_eq!(
            tracking.map(|tracking| (tracking.ttl, tracking.max_sessions)),
            ttl.map(|seconds| (Duration::from_secs(seconds), max)),
            "{input}"
        );
    }
    for (input, expected) in [
        ("proxyproto {\nunknown\n}", "unknown option"),
        ("proxyproto extra_arg", "Wrong argument"),
        ("proxyproto {\nallow invalid_ip\n}", "invalid CIDR address"),
        (
            "proxyproto {\nallow 127.0.0.1/8\ndefault invalid_policy\n}",
            "Wrong argument",
        ),
        ("proxyproto {\nudp_session_tracking\n}", "Wrong argument"),
        (
            "proxyproto {\nudp_session_tracking 28s 100 extra\n}",
            "Wrong argument",
        ),
        (
            "proxyproto {\nudp_session_tracking notaduration\n}",
            "invalid duration",
        ),
        (
            "proxyproto {\nudp_session_tracking 28s notanumber\n}",
            "invalid max sessions",
        ),
        (
            "proxyproto {\nudp_session_tracking 28s 0\n}",
            "invalid max sessions",
        ),
        (
            "proxyproto {\nudp_session_tracking 28s -1\n}",
            "invalid max sessions",
        ),
        ("proxyproto {\ndefault\n}", "Wrong argument"),
        ("proxyproto {\nallow 10.0.0.0\n}", "invalid CIDR address"),
        ("proxyproto {\nallow 10.0.0.0/33\n}", "invalid CIDR address"),
        ("proxyproto {\nallow ::1/129\n}", "invalid CIDR address"),
    ] {
        let error = configure_block(input)
            .err()
            .unwrap_or_else(|| panic!("{input}"));
        assert!(error.contains(expected), "{input}: {error}");
    }
}

// CoreDNS v1.15.0 plugin/proxyproto/setup_test.go TestTLVMetadataFlag.
#[test]
fn tlv_metadata_takes_no_arguments() {
    for (input, expected) in [
        ("proxyproto {\ntlv_metadata\n}", true),
        ("proxyproto {\nallow 10.0.0.0/8\ntlv_metadata\n}", true),
        ("proxyproto {\nallow 10.0.0.0/8\n}", false),
    ] {
        assert_eq!(config(input).tlv_metadata, expected, "{input}");
    }
    assert!(configure_block("proxyproto {\ntlv_metadata on\n}").is_err());
}

// CoreDNS v1.15.0 plugin/proxyproto/setup_test.go TestDefaultPolicyWithoutAllow.
#[test]
fn default_policy_applies_to_every_peer_without_allow() {
    let config = config("proxyproto {\ndefault reject\n}");
    assert_eq!(config.policy(ip("192.0.2.1")), Policy::Reject);
}

// CoreDNS v1.15.0 plugin/proxyproto/setup.go: no `allow` and no `default` uses every peer's header.
#[test]
fn policy_follows_allow_and_default() {
    let cases = [
        ("proxyproto", "192.0.2.1", Policy::Use),
        (
            "proxyproto {\ndefault ignore\n}",
            "192.0.2.1",
            Policy::Ignore,
        ),
        ("proxyproto {\ndefault skip\n}", "192.0.2.1", Policy::Skip),
        ("proxyproto {\ndefault USE\n}", "192.0.2.1", Policy::Use),
        ("proxyproto {\nallow 10.0.0.0/8\n}", "10.1.2.3", Policy::Use),
        (
            "proxyproto {\nallow 10.0.0.0/8\n}",
            "11.1.2.3",
            Policy::Ignore,
        ),
        (
            "proxyproto {\nallow 10.0.0.0/8\ndefault reject\n}",
            "11.1.2.3",
            Policy::Reject,
        ),
        (
            "proxyproto {\nallow 10.0.0.0/8\ndefault reject\n}",
            "10.255.255.255",
            Policy::Use,
        ),
        (
            "proxyproto {\nallow 10.0.0.0/8\nallow 2001:db8::/32\ndefault skip\n}",
            "2001:db8:1::1",
            Policy::Use,
        ),
        (
            "proxyproto {\nallow 2001:db8::/32\ndefault skip\n}",
            "2001:db9::1",
            Policy::Skip,
        ),
        // RFC 4291 §2.5.5.2: an IPv4-mapped peer matches an IPv4 range.
        (
            "proxyproto {\nallow 10.0.0.0/8\ndefault reject\n}",
            "::ffff:10.0.0.1",
            Policy::Use,
        ),
    ];
    for (input, peer, expected) in cases {
        assert_eq!(config(input).policy(ip(peer)), expected, "{input} {peer}");
    }
}

#[test]
fn negative_session_ttl_disables_tracking() {
    assert!(
        config("proxyproto {\nudp_session_tracking -5s\n}")
            .udp_tracking
            .is_none()
    );
    assert!(
        config("proxyproto {\nudp_session_tracking 0\n}")
            .udp_tracking
            .is_none()
    );
}

#[test]
fn proxyproto_is_configured_once_per_server_block() {
    assert!(configure_block("proxyproto\nproxyproto").is_err());
}

#[test]
fn listener_uses_the_last_server_block_that_configures_proxyproto() {
    let text = "one.example:53 {\n proxyproto {\n default reject\n }\n}\ntwo.example:53 {\n}\nthree.example:53 {\n proxyproto {\n default skip\n }\n}";
    let blocks = configure::<Chain>(&parse("Corefile", text).unwrap(), directives()).unwrap();
    let (servers, _) = pharos_plugins::servers(blocks).unwrap();
    let server = servers.values().next().unwrap();
    let proxy = server.proxyproto.as_ref().unwrap();
    assert_eq!(proxy.policy(ip("192.0.2.1")), Policy::Skip);
}

// Every Transport's Listener takes the proxyproto settings of its Server Block.
#[cfg(feature = "plugin-tls")]
#[test]
fn every_encrypted_transport_listener_gets_the_proxy_settings() {
    let fixtures = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/fixtures/tls");
    for (scheme, transport) in [
        ("tls", Transport::Tls),
        ("https", Transport::Https),
        ("grpc", Transport::Grpc),
        ("quic", Transport::Quic),
        ("https3", Transport::Https3),
    ] {
        let text = format!(
            "{scheme}://.:8443 {{\n tls {fixtures}/server.pem {fixtures}/server.key.pem\n proxyproto {{\n default reject\n }}\n whoami\n}}"
        );
        let blocks = configure::<Chain>(&parse("Corefile", &text).unwrap(), directives()).unwrap();
        let (servers, _) = pharos_plugins::servers(blocks).unwrap();
        let (key, server) = servers.iter().next().unwrap();
        assert_eq!(key.transport, transport, "{scheme}");
        let proxy = server.proxyproto.as_ref().unwrap();
        assert_eq!(proxy.policy(ip("192.0.2.1")), Policy::Reject, "{scheme}");
    }
}

#[test]
fn listener_without_proxyproto_has_no_proxy_settings() {
    let blocks = configure_block("whoami").unwrap();
    let (servers, _) = pharos_plugins::servers(blocks).unwrap();
    assert!(servers.values().next().unwrap().proxyproto.is_none());
}

// CoreDNS v1.15.0 plugin/proxyproto/metadata_test.go TestMetadataThroughChain.
#[cfg(feature = "plugin-metadata")]
#[tokio::test]
async fn tlv_label_reaches_the_chain_only_through_the_metadata_plugin() {
    for (directives, name, expected) in [
        (
            "metadata\nproxyproto {\ntlv_metadata\n}\nwhoami",
            "example.org.",
            Some("ea000107"),
        ),
        (
            "metadata example.org\nproxyproto\nwhoami",
            "example.org.",
            Some("ea000107"),
        ),
        (
            "metadata example.net\nproxyproto\nwhoami",
            "example.org.",
            None,
        ),
        ("proxyproto\nwhoami", "example.org.", None),
    ] {
        let chain = configure_block(directives).unwrap();
        let qname: Name = name.parse().unwrap();
        let domain: Name = ".".parse().unwrap();
        let mut wire = Vec::with_capacity(512);
        let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
        builder
            .question(
                NameRef::parse(qname.as_wire(), 0).unwrap(),
                Type::A,
                Class::IN,
            )
            .unwrap();
        let _ = builder.finish();
        let mut response = Vec::with_capacity(512);
        let mut slots = [None; 18];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 512,
        };
        cx.metadata.set_proxy_tlv("ea000107");
        chain[0].config.serve(&mut cx).await;
        assert_eq!(cx.metadata.get(TLV_LABEL), expected, "{directives}");
    }
}

#[cfg(feature = "plugin-metadata")]
#[tokio::test]
async fn no_tlv_means_no_label() {
    let chain = configure_block("metadata\nproxyproto {\ntlv_metadata\n}\nwhoami").unwrap();
    let domain: Name = ".".parse().unwrap();
    let qname: Name = "example.org.".parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 1, 0).unwrap();
    builder
        .question(
            NameRef::parse(qname.as_wire(), 0).unwrap(),
            Type::A,
            Class::IN,
        )
        .unwrap();
    let _ = builder.finish();
    let mut response = Vec::with_capacity(512);
    let mut slots = [None; 18];
    let mut cx = Context {
        query: Message::parse(&wire).unwrap(),
        client: "127.0.0.1:1234".parse().unwrap(),
        local: "127.0.0.1:53".parse().unwrap(),
        transport: Transport::Dns,
        protocol: Protocol::Udp,
        domain: &domain,
        metadata: Metadata::new(&mut slots),
        response: &mut response,
        max_response_size: 512,
    };
    chain[0].config.serve(&mut cx).await;
    assert_eq!(cx.metadata.get(TLV_LABEL), None);
}

// A view expression reads the label while the Listener routes the Query (the collector path).
#[cfg(all(
    feature = "plugin-metadata",
    feature = "plugin-view",
    feature = "plugin-hosts"
))]
#[tokio::test]
async fn view_expression_reads_the_tlv_label_of_a_proxied_query() {
    use pharos_server::Handler;

    const QUERY: &[u8] =
        b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
    let text = ".:53 {\n metadata\n proxyproto {\n  tlv_metadata\n }\n view tagged {\n  expr metadata('proxyproto/tlv') == 'ea000107'\n }\n hosts {\n  192.0.2.1 example.com\n }\n}\n.:53 {\n hosts {\n  192.0.2.2 example.com\n }\n}";
    let blocks = parse("Corefile", text).unwrap();
    let (servers, _) =
        pharos_plugins::servers(configure::<Chain>(&blocks, directives()).unwrap()).unwrap();
    let server = std::sync::Arc::new(servers.into_values().next().unwrap());
    let peer = "127.0.0.1:1234".parse().unwrap();
    let mut response = Vec::with_capacity(512);
    server
        .handle_proxied(QUERY, peer, Protocol::Tcp, "ea000107", &mut response)
        .await;
    let answer = |wire: &[u8]| {
        Message::parse(wire)
            .unwrap()
            .answers()
            .next()
            .unwrap()
            .rdata
            .to_vec()
    };
    assert_eq!(answer(&response), [192, 0, 2, 1]);
    for tlv in ["", "ea000108"] {
        response.clear();
        server
            .handle_proxied(QUERY, peer, Protocol::Tcp, tlv, &mut response)
            .await;
        assert_eq!(answer(&response), [192, 0, 2, 2], "{tlv:?}");
    }
}
