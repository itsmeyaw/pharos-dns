use super::*;

fn service(host: &str, group: &str, key: &str) -> Service {
    Service {
        host: host.into(),
        group: group.into(),
        key: key.into(),
        ..Service::default()
    }
}

fn hosts(services: &[Service]) -> Vec<&str> {
    services.iter().map(|s| s.host.as_str()).collect()
}

// CoreDNS v1.15.0 plugin/etcd/msg/path_test.go TestPath.
#[test]
fn path_reverses_labels_under_prefix() {
    for prefix in ["mydns", "skydns"] {
        assert_eq!(
            path("service.staging.skydns.local.", prefix),
            format!("/{prefix}/local/skydns/staging/service")
        );
    }
}

// CoreDNS v1.15.0 plugin/etcd/msg/path.go Path: `path.Join` cleans the key; the root name has no labels.
#[test]
fn path_is_cleaned_like_go_path_join() {
    assert_eq!(path(".", "skydns"), "/skydns");
    assert_eq!(path("", "skydns"), "/skydns");
    assert_eq!(path("a.b", "skydns"), "/skydns/b/a");
    assert_eq!(path("a..b.", "skydns"), "/skydns/b/a");
    assert_eq!(path("a.b.", "/a/../x/"), "/x/b/a");
    assert_eq!(path("a", ""), "/a");
    assert_eq!(path("a\\.b.c.", "skydns"), "/skydns/c/a\\.b");
    assert_eq!(path("a\\\\.c", "skydns"), "/skydns/c/a\\\\");
}

// CoreDNS v1.15.0 plugin/etcd/msg/path.go PathWithWildcard.
#[test]
fn path_with_wildcard_cuts_before_first_wildcard_from_the_root() {
    assert_eq!(
        path_with_wildcard("service.staging.skydns.local.", "skydns"),
        ("/skydns/local/skydns/staging/service".to_owned(), false)
    );
    assert_eq!(
        path_with_wildcard("service.*.skydns.local.", "skydns"),
        ("/skydns/local/skydns".to_owned(), true)
    );
    assert_eq!(
        path_with_wildcard("any.a.*.local.", "skydns"),
        ("/skydns/local".to_owned(), true)
    );
    assert_eq!(
        path_with_wildcard("*.local.", "skydns"),
        ("/skydns/local".to_owned(), true)
    );
    assert_eq!(
        path_with_wildcard("*.", "skydns"),
        ("/skydns".to_owned(), true)
    );
    assert_eq!(
        path_with_wildcard("anyone.a.local.", "skydns"),
        ("/skydns/local/a/anyone".to_owned(), false)
    );
}

// CoreDNS v1.15.0 plugin/etcd/msg/path_test.go TestDomain.
#[test]
fn domain_reverses_key_with_and_without_trailing_slash() {
    assert_eq!(
        domain("/skydns/local/cluster/staging/service/"),
        "service.staging.cluster.local."
    );
    assert_eq!(
        domain("/skydns/local/cluster/staging/service"),
        "service.staging.cluster.local."
    );
}

// CoreDNS v1.15.0 plugin/etcd/msg/path.go Domain and plugin/pkg/dnsutil/join.go Join.
#[test]
fn domain_of_short_keys_is_the_root() {
    for key in ["", "/", "/skydns", "/skydns/", "//", "/skydns//"] {
        assert_eq!(domain(key), ".", "{key:?}");
    }
    assert_eq!(domain("/skydns/local"), "local.");
    assert_eq!(domain("/skydns/./a"), "a.");
    assert_eq!(domain("/skydns/."), ".");
}

// CoreDNS v1.15.0 plugin/etcd/msg/service_test.go TestSplit255.
#[test]
fn split255_cuts_at_255_bytes() {
    assert_eq!(split255(b"abc"), [&b"abc"[..]]);
    let mut text = vec![b'a'; 254];
    assert_eq!(split255(&text).len(), 1);
    text.push(b'a');
    // CoreDNS v1.15.0 plugin/etcd/msg/service.go split255: exactly 255 bytes ends with an empty chunk.
    assert_eq!(split255(&text), [&text[..], &b""[..]]);
    text.push(b'b');
    assert_eq!(split255(&text), [&text[..255], &b"b"[..]]);
    text.extend([b'a'; 255]);
    let chunks = split255(&text);
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[2], b"a");
    assert_eq!(split255(&[b'x'; 510]).len(), 3);
    assert_eq!(split255(b""), [&b""[..]]);
}

// CoreDNS v1.15.0 plugin/etcd/msg/service_test.go TestTargetStripLargeValueReturns.
#[test]
fn target_strip_past_the_end_returns_the_name() {
    assert_eq!(target_strip("b.z1.test.", i64::MAX), "b.z1.test.");
}

// CoreDNS v1.15.0 plugin/etcd/msg/service.go targetStrip.
#[test]
fn target_strip_removes_leftmost_labels() {
    assert_eq!(target_strip("b.z1.test.", 1), "z1.test.");
    assert_eq!(target_strip("b.z1.test.", 2), "test.");
    assert_eq!(target_strip("b.z1.test.", 3), "b.z1.test.");
    assert_eq!(target_strip("b.z1.test.", 0), "b.z1.test.");
    assert_eq!(target_strip("b.z1.test.", -1), "b.z1.test.");
    assert_eq!(target_strip("a\\.b.c.", 1), "c.");
    assert_eq!(target_strip("a.b", 1), "b");
    assert_eq!(target_strip("a.b", 2), "a.b");
}

// CoreDNS v1.15.0 plugin/etcd/msg/service_test.go TestGroup.
#[test]
fn group_keeps_the_group_of_the_shortest_key() {
    // Keys are in the wrong order, but for this test it does not matter.
    let services = group(vec![
        service("127.0.0.1", "g1", "b/sub/dom1/skydns/test"),
        service("127.0.0.2", "g2", "a/dom1/skydns/test"),
    ]);
    assert_eq!(services.len(), 1, "zeroth set: {services:?}");
    assert_eq!(services[0].key, "a/dom1/skydns/test");

    // Groups disagree on the same level, so nothing is filtered.
    let services = group(vec![
        service("server1", "g1", "region1/skydns/test"),
        service("server2", "g2", "region1/skydns/test"),
    ]);
    assert_eq!(hosts(&services), ["server1", "server2"]);

    // Group is g1, include only the top-level one.
    let services = group(vec![
        service("server1", "g1", "a/dom/region1/skydns/test"),
        service("server2", "g2", "a/subdom/dom/region1/skydns/test"),
    ]);
    assert_eq!(hosts(&services), ["server1"]);

    // Groupless services must be included.
    let services = group(vec![
        service("server1", "g1", "a/dom/region1/skydns/test"),
        service("server2", "g2", "a/subdom/dom/region1/skydns/test"),
        service("server3", "", "b/subdom/dom/region1/skydns/test"),
    ]);
    assert_eq!(hosts(&services), ["server1", "server3"]);

    // Empty group on the highest level: include that one also.
    let services = group(vec![
        service("server1", "g1", "a/dom/region1/skydns/test"),
        service("server2", "", "b/dom/region1/skydns/test"),
        service("server3", "g2", "a/subdom/dom/region1/skydns/test"),
    ]);
    assert_eq!(hosts(&services), ["server1", "server2"]);

    // Empty group on the highest level: include that one also, and the rest.
    let services = group(vec![
        service("server1", "g5", "a/dom/region1/skydns/test"),
        service("server2", "", "b/dom/region1/skydns/test"),
        service("server3", "g5", "a/subdom/dom/region1/skydns/test"),
    ]);
    assert_eq!(hosts(&services), ["server1", "server2", "server3"]);

    // One group.
    let services = group(vec![service("server1", "g6", "a/dom/region1/skydns/test")]);
    assert_eq!(services.len(), 1);

    // No group, one service.
    let services = group(vec![service("server1", "", "a/dom/region1/skydns/test")]);
    assert_eq!(services.len(), 1);

    assert!(group(Vec::new()).is_empty());
}

// CoreDNS v1.15.0 plugin/etcd/msg/service.go Group: `length` is only filled up to the `break`, so
// a service after a shorter groupless key is never taken for a same-level disagreement.
#[test]
fn group_compares_levels_only_up_to_a_shorter_groupless_key() {
    let services = group(vec![
        service("server1", "g1", "a/b/c"),
        service("server2", "", "a/b"),
        service("server3", "g2", "a/b/c"),
    ]);
    assert_eq!(hosts(&services), ["server1", "server2"]);
}

// CoreDNS v1.15.0 plugin/etcd/msg/type_test.go TestType.
#[test]
fn host_type_tells_names_from_addresses() {
    let host = |host: &str, mail: bool, text: &str| {
        Service {
            host: host.into(),
            mail,
            text: text.into(),
            ..Service::default()
        }
        .host_type()
    };
    assert_eq!(host("example.org", false, ""), HostType::Cname);
    assert_eq!(
        host("127.0.0.1", false, ""),
        HostType::A("127.0.0.1".parse().unwrap())
    );
    assert_eq!(
        host("2000::3", false, ""),
        HostType::Aaaa("2000::3".parse().unwrap())
    );
    assert_eq!(host("2000..3", false, ""), HostType::Cname);
    assert_eq!(host("127.0.0.257", false, ""), HostType::Cname);
    assert!(matches!(host("127.0.0.252", true, ""), HostType::A(_)));
    assert!(matches!(host("127.0.0.252", true, "a"), HostType::A(_)));
    assert!(matches!(host("127.0.0.254", false, "a"), HostType::A(_)));
}

// CoreDNS v1.15.0 plugin/etcd/msg/type.go HostType: a name with text is a TXT record, and an IPv4-mapped IPv6 address is IPv4.
#[test]
fn host_type_handles_text_and_mapped_addresses() {
    let of = |host: &str, text: &str| {
        Service {
            host: host.into(),
            text: text.into(),
            ..Service::default()
        }
        .host_type()
    };
    assert_eq!(of("example.org", "x"), HostType::Txt);
    assert_eq!(of("", "x"), HostType::Txt);
    assert_eq!(of("", ""), HostType::Cname);
    assert_eq!(
        of("::ffff:10.1.2.3", ""),
        HostType::A("10.1.2.3".parse().unwrap())
    );
    assert!(matches!(of("::10.1.2.3", ""), HostType::Aaaa(_)));
    assert_eq!(of("fe80::1%eth0", ""), HostType::Cname);
}

fn decode(json: &str) -> Result<Service, DecodeError> {
    Service::from_json("/skydns/local/skydns/x", json.as_bytes())
}

// CoreDNS v1.15.0 plugin/etcd/msg/service.go Service: the JSON field names.
#[test]
fn from_json_reads_every_field() {
    let service = decode(
        r#"{"host":"10.0.0.1","port":8080,"priority":5,"weight":7,"text":"t","mail":true,"ttl":60,"targetstrip":2,"group":"g"}"#,
    )
    .unwrap();
    assert_eq!(
        service,
        Service {
            host: "10.0.0.1".into(),
            port: 8080,
            priority: 5,
            weight: 7,
            text: "t".into(),
            mail: true,
            ttl: 60,
            target_strip: 2,
            group: "g".into(),
            key: "/skydns/local/skydns/x".into(),
        }
    );
}

// Go encoding/json: field names match ignoring case, unknown fields are ignored, `Key` is never read.
#[test]
fn from_json_matches_names_like_go() {
    let service = decode(
        r#"{"HOST":"h","Port":1,"TargetStrip":3,"unknown":[1,{"a":null}],"Key":"ignored","key":"ignored","-":"x"}"#,
    )
    .unwrap();
    assert_eq!(service.host, "h");
    assert_eq!(service.port, 1);
    assert_eq!(service.target_strip, 3);
    assert_eq!(service.key, "/skydns/local/skydns/x");
    // `K` (Kelvin sign) folds to `k` and `ſ` to `s`.
    let service = decode("{\"hoſt\":\"folded\",\"\u{212a}\":1}").unwrap();
    assert_eq!(service.host, "folded");
    // The last spelling of a field wins.
    assert_eq!(decode(r#"{"host":"a","Host":"b"}"#).unwrap().host, "b");
}

// Go encoding/json: `null` and a missing field leave the zero value, and `null` does not reset a field already set.
#[test]
fn from_json_treats_null_as_absent() {
    assert_eq!(decode("null").unwrap().host, "");
    assert_eq!(decode("{}").unwrap().port, 0);
    let service = decode(r#"{"host":"a","port":1,"ttl":3,"mail":true,"host":null,"port":null,"ttl":null,"mail":null,"text":null}"#)
        .unwrap();
    assert_eq!(
        (
            service.host.as_str(),
            service.port,
            service.ttl,
            service.mail
        ),
        ("a", 1, 3, true)
    );
}

// CoreDNS v1.15.0 plugin/etcd/etcd.go loopNodes: a value that does not decode is an error `KEY: REASON`.
#[test]
fn from_json_rejects_what_go_rejects() {
    for json in [
        r#"{"host":1}"#,
        r#"{"host":true}"#,
        r#"{"host":["a"]}"#,
        r#"{"port":"80"}"#,
        r#"{"port":1.5}"#,
        r#"{"port":1e2}"#,
        r#"{"port":9223372036854775808}"#,
        r#"{"priority":{}}"#,
        r#"{"ttl":-1}"#,
        r#"{"ttl":4294967296}"#,
        r#"{"ttl":1.0}"#,
        r#"{"mail":"true"}"#,
        r#"{"mail":1}"#,
        r#"{"text":null,"group":false}"#,
        r#"[]"#,
        r#"[{"host":"a"}]"#,
        r#""host""#,
        "1",
        "true",
        "",
        "{",
        r#"{"host":"a"} x"#,
        "not json",
    ] {
        let error = decode(json).unwrap_err().to_string();
        assert!(
            error.starts_with("/skydns/local/skydns/x: "),
            "{json}: {error}"
        );
    }
    assert!(
        decode(r#"{"port":"80"}"#)
            .unwrap_err()
            .to_string()
            .contains("cannot unmarshal string into Go struct field Service.port of type int")
    );
    assert!(
        decode(r#"{"ttl":-1}"#)
            .unwrap_err()
            .to_string()
            .contains("cannot unmarshal number -1 into Go struct field Service.ttl of type uint32")
    );
}

// Go encoding/json: a duplicate or reordered key still yields one value per field and `ttl` fits u32 exactly.
#[test]
fn from_json_accepts_limits() {
    let service = decode(r#"{"ttl":4294967295,"port":-9223372036854775808}"#).unwrap();
    assert_eq!(service.ttl, u32::MAX);
    assert_eq!(service.port, i64::MIN);
}
