#![forbid(unsafe_code)]

use pharos_server::startup_domains;

#[test]
fn domain_lines_match_coredns_startup_format() {
    assert_eq!(
        startup_domains("", ":53", &["example.org.", "."]),
        ".:53\nexample.org.:53\n"
    );
    assert_eq!(
        startup_domains("", "127.0.0.1:1053", &["example.org."]),
        "example.org.:1053 on 127.0.0.1\n"
    );
    assert_eq!(
        startup_domains("tls://", "[::1]:853", &["_tcp.example."]),
        "Warning: Domain \"_tcp.example.\" does not follow RFC1035 preferred syntax\ntls://_tcp.example.:853 on ::1\n"
    );
    assert_eq!(
        startup_domains("", ":53", &["1.0.168.192.in-addr.arpa."]),
        "1.0.168.192.in-addr.arpa.:53\n"
    );
}
