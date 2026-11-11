#![forbid(unsafe_code)]

use std::{fs, io::Cursor, path::Path};

use pharos_proto::{Name, zone::ZoneParser};

fn check(name: &str, origin: &str) {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/corpus/zone-coredns");
    let zone = fs::read(dir.join(format!("{name}.zone"))).unwrap();
    let expected = fs::read_to_string(dir.join(format!("{name}.expected"))).unwrap();
    let origin: Name = origin.parse().unwrap();
    let records = ZoneParser::new(Cursor::new(zone), origin, name).collect::<Result<Vec<_>, _>>();
    let mut lines = expected.lines();
    match lines.next() {
        Some("reject") => assert!(
            records.is_err(),
            "{name}: expected rejection, got {records:?}"
        ),
        Some("accept") => {
            let records =
                records.unwrap_or_else(|err| panic!("{name}: expected acceptance: {err}"));
            // RFC 1035 §4.1.3: compare owner and RDATA in uncompressed wire form.
            let actual: Vec<_> = records
                .iter()
                .map(|r| {
                    let hex = |bytes: &[u8]| {
                        bytes
                            .iter()
                            .map(|byte| format!("{byte:02x}"))
                            .collect::<String>()
                    };
                    format!(
                        "{}\t{}\t{}\t{}\t{}",
                        hex(r.owner.as_wire()),
                        r.ttl,
                        r.class.0,
                        r.rtype.0,
                        hex(&r.rdata)
                    )
                })
                .collect();
            let expected: Vec<_> = lines.collect();
            assert_eq!(actual.len(), expected.len(), "{name}: record count");
            for (index, (actual, expected)) in actual.iter().zip(expected).enumerate() {
                assert_eq!(actual, expected, "{name}: record {index}");
            }
        }
        other => panic!("{name}: invalid oracle result {other:?}"),
    }
}

macro_rules! fixtures {
    ($($name:ident => $origin:literal),* $(,)?) => {
        $(#[test] #[allow(non_snake_case)] fn $name() { check(stringify!($name), $origin); })*
    };
}

include!("corpus/zone-coredns/manifest.rs");
