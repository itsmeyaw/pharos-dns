//! Parse the labels beneath a Kubernetes Plugin Domain.

#[derive(Debug, Default)]
pub(super) struct Request<'a> {
    pub kind: &'a [u8],
    pub namespace: &'a [u8],
    pub service: &'a [u8],
    pub endpoint: &'a [u8],
    pub port: &'a [u8],
    pub protocol: &'a [u8],
    pub zone: &'a [&'a [u8]],
    pub prefer: bool,
}

pub(super) fn parse<'a>(labels: &'a [&'a [u8]], zonal: bool) -> Option<Request<'a>> {
    let mut request = Request::default();
    let Some((&kind, remaining)) = labels.split_last() else {
        return Some(request);
    };
    if !kind.eq_ignore_ascii_case(b"pod") && !kind.eq_ignore_ascii_case(b"svc") {
        return None;
    }
    let Some((&namespace, remaining)) = remaining.split_last() else {
        return Some(request);
    };
    request.kind = kind;
    request.namespace = namespace;
    let Some((&service, remaining)) = remaining.split_last() else {
        return Some(request);
    };
    request.service = service;
    match remaining {
        [] => {}
        [endpoint] => request.endpoint = endpoint,
        [port, protocol] => {
            request.port = port.strip_prefix(b"_").unwrap_or(port);
            request.protocol = protocol.strip_prefix(b"_").unwrap_or(protocol);
        }
        _ => {
            if !zonal || !kind.eq_ignore_ascii_case(b"svc") {
                return None;
            }
            let (&anchor, rest) = remaining.split_last()?;
            let (&directive, zone) = rest.split_last()?;
            if !anchor.eq_ignore_ascii_case(b"_zone") || zone.is_empty() {
                return None;
            }
            if directive.eq_ignore_ascii_case(b"prefer") {
                request.prefer = true;
            } else if !directive.eq_ignore_ascii_case(b"pin") {
                return None;
            }
            request.zone = zone;
        }
    }
    Some(request)
}

#[cfg(test)]
mod tests {
    use super::{Request, parse};

    fn coredns_string(request: &Request<'_>) -> String {
        [
            request.port,
            request.protocol,
            request.endpoint,
            &[][..],
            request.service,
            request.namespace,
            request.kind,
        ]
        .map(|value| std::str::from_utf8(value).unwrap())
        .join(".")
    }

    // CoreDNS parse_test.go TestParseRequest; row 6 is multicluster (#41).
    #[test]
    fn coredns_request_table() {
        let cases: &[(&[&[u8]], bool, &str, &str)] = &[
            (
                &[b"_http", b"_tcp", b"webs", b"mynamespace", b"svc"],
                false,
                "http.tcp...webs.mynamespace.svc",
                "",
            ),
            (
                &[b"1-2-3-4", b"webs", b"mynamespace", b"svc"],
                false,
                "..1-2-3-4..webs.mynamespace.svc",
                "",
            ),
            (&[], false, "......", ""),
            (&[b"svc"], false, "......", ""),
            (&[b"pod"], false, "......", ""),
            (
                &[b"", b"", b"webs", b"mynamespace", b"svc"],
                false,
                "....webs.mynamespace.svc",
                "",
            ),
            (
                &[
                    b"us-west-2a",
                    b"pin",
                    b"_zone",
                    b"webs",
                    b"mynamespace",
                    b"svc",
                ],
                true,
                "....webs.mynamespace.svc",
                "us-west-2a",
            ),
            (
                &[
                    b"us-west-2a",
                    b"prefer",
                    b"_zone",
                    b"webs",
                    b"mynamespace",
                    b"svc",
                ],
                true,
                "....webs.mynamespace.svc",
                "us-west-2a",
            ),
            (
                &[
                    b"corp",
                    b"example",
                    b"com",
                    b"pin",
                    b"_zone",
                    b"webs",
                    b"mynamespace",
                    b"svc",
                ],
                true,
                "....webs.mynamespace.svc",
                "corp.example.com",
            ),
            (
                &[b"us-west-2a", b"_zone", b"webs", b"mynamespace", b"svc"],
                true,
                "us-west-2a.zone...webs.mynamespace.svc",
                "",
            ),
        ];
        for (index, (labels, zonal, expected, expected_zone)) in cases.iter().enumerate() {
            let request = parse(labels, *zonal).unwrap_or_else(|| panic!("row {index}"));
            let zone = request
                .zone
                .iter()
                .map(|label| std::str::from_utf8(label).unwrap())
                .collect::<Vec<_>>()
                .join(".");
            assert_eq!(coredns_string(&request), *expected, "row {index}");
            assert_eq!(zone, *expected_zone, "row {index}");
        }
    }

    // Adapted from CoreDNS v1.15.0 plugin/kubernetes/parse_test.go.
    #[test]
    fn parses_service_endpoint_and_srv_names() {
        let request = parse(&[b"_http", b"_tcp", b"web", b"prod", b"svc"], false).unwrap();
        assert_eq!(request.port, b"http");
        assert_eq!(request.protocol, b"tcp");
        assert_eq!(request.service, b"web");
        assert_eq!(request.namespace, b"prod");
        assert_eq!(request.kind, b"svc");
        let request = parse(&[b"one", b"web", b"prod", b"svc"], false).unwrap();
        assert_eq!(request.endpoint, b"one");
        assert!(parse(&[], false).unwrap().kind.is_empty());
        assert!(parse(&[b"svc"], false).unwrap().kind.is_empty());
        assert!(parse(&[b"pod"], false).unwrap().kind.is_empty());
    }

    #[test]
    fn parses_partial_names_and_plain_port_labels() {
        let request = parse(&[b"prod", b"svc"], false).unwrap();
        assert_eq!(request.namespace, b"prod");
        assert!(request.service.is_empty());
        let request = parse(&[b"http", b"_tcp", b"web", b"prod", b"svc"], false).unwrap();
        assert_eq!(request.port, b"http");
        assert_eq!(request.protocol, b"tcp");
    }

    #[test]
    fn parses_and_validates_zonal_names() {
        let labels: &[&[u8]] = &[
            b"corp", b"example", b"pin", b"_zone", b"web", b"prod", b"svc",
        ];
        let request = parse(labels, true).unwrap();
        assert_eq!(request.zone, &[&b"corp"[..], &b"example"[..]]);
        assert!(!request.prefer);
        let preferred = parse(&[b"a", b"prefer", b"_zone", b"web", b"prod", b"svc"], true).unwrap();
        assert!(preferred.prefer);
        assert!(parse(labels, false).is_none());
        assert!(parse(&[b"a", b"unknown", b"_zone", b"web", b"prod", b"svc"], true).is_none());
        assert!(parse(&[b"a", b"pin", b"_zone", b"web", b"prod", b"pod"], true).is_none());
        assert!(parse(&[b"web", b"prod", b"wrong"], true).is_none());
    }
}
