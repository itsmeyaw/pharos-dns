#![forbid(unsafe_code)]
#![no_main]

use std::{
    io::{BufReader, Cursor, Read, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::{Mutex, OnceLock},
};

use libfuzzer_sys::fuzz_target;
use pharos_proto::{Name, zone::ZoneParser};

const ORIGIN: &str = "example.";

struct Oracle {
    _child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

impl Oracle {
    fn start() -> Self {
        let path = std::env::var_os("PHAROS_ZONE_ORACLE")
            .expect("set PHAROS_ZONE_ORACLE to the zone-oracle binary (cargo xtask fuzz does this)");
        let mut child = Command::new(path)
            .arg("--batch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start zone oracle");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self { _child: child, stdin, stdout }
    }

    fn parse(&mut self, zone: &[u8]) -> String {
        for frame in [ORIGIN.as_bytes(), zone] {
            self.stdin
                .write_all(&u32::try_from(frame.len()).unwrap().to_be_bytes())
                .unwrap();
            self.stdin.write_all(frame).unwrap();
        }
        self.stdin.flush().unwrap();
        let mut length = [0; 4];
        self.stdout.read_exact(&mut length).expect("oracle response");
        let mut response = vec![0; u32::from_be_bytes(length) as usize];
        self.stdout.read_exact(&mut response).unwrap();
        String::from_utf8(response).expect("oracle response is ASCII")
    }
}

fn has_generate(zone: &[u8]) -> bool {
    zone.split(|&b| b == b'\n')
        .any(|line| line.to_ascii_uppercase().starts_with(b"$GENERATE"))
}

fn without_comments(zone: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(zone.len());
    let (mut quoted, mut escaped, mut comment) = (false, false, false);
    // RFC 1035 §5.1: unquoted, unescaped semicolons start comments through the line end.
    for &b in zone {
        if comment {
            if b == b'\n' {
                comment = false;
                result.push(b);
            }
        } else if escaped {
            result.push(b);
            escaped = false;
        } else if b == b'\\' {
            result.push(b);
            escaped = true;
        } else if b == b'"' {
            result.push(b);
            quoted = !quoted;
        } else if b == b';' && !quoted {
            comment = true;
        } else {
            result.push(b);
        }
    }
    result
}

// miekg/dns re-parses a $GENERATE template without a final newline and accepts an
// unterminated quote there (documented deviations).
fn generate_line_error(zone: &[u8], error: &str) -> bool {
    has_generate(zone) && (error.contains("unterminated record") || error.contains("invalid $GENERATE"))
}

fn pharos(zone: &[u8]) -> String {
    let origin: Name = ORIGIN.parse().unwrap();
    match ZoneParser::new(Cursor::new(zone), origin, "fuzz.zone").collect::<Result<Vec<_>, _>>() {
        // Documented deviations: Pharos rejects missing RDATA fields, unmatched ')' and
        // unterminated quotes.
        Err(error)
            if ["missing ", "fields, got", "unbalanced parentheses", "unterminated record"]
                .iter()
                .any(|message| error.to_string().contains(message))
                || generate_line_error(zone, &error.to_string()) =>
        {
            "documented_reject\n".to_owned()
        }
        Err(_) => "reject\n".to_owned(),
        Ok(records) => {
            let mut result = String::from("accept\n");
            for r in records {
                for b in r.owner.as_wire() {
                    result.push_str(&format!("{b:02x}"));
                }
                result.push_str(&format!("\t{}\t{}\t{}\t", r.ttl, r.class.0, r.rtype.0));
                for b in &r.rdata {
                    result.push_str(&format!("{b:02x}"));
                }
                result.push('\n');
            }
            result
        }
    }
}

fuzz_target!(|zone: &[u8]| {
    static ORACLE: OnceLock<Mutex<Oracle>> = OnceLock::new();
    let mut oracle = ORACLE
        .get_or_init(|| Mutex::new(Oracle::start()))
        .lock()
        .unwrap();
    let expected = oracle.parse(zone);
    let actual = pharos(zone);
    // Documented deviation: miekg/dns drops escaped characters in $GENERATE templates, which
    // may span lines inside quotes; escapes stay covered by zones without $GENERATE.
    if has_generate(zone) && zone.contains(&b'\\') {
        return;
    }
    if actual == "documented_reject\n" {
        return;
    }
    // Documented deviations (docs/compatibility.md): Pharos rejects zones that miekg/dns
    // accepts but cannot pack, and records with an empty owner.
    if expected.starts_with("pack_error\n") || expected.contains("\n\t") {
        assert_eq!(actual, "reject\n", "miekg/dns: {expected}");
        return;
    }
    // Documented deviations: comments can interfere with mnemonic recognition.
    if actual.starts_with("accept\n") && expected == "reject\n" && zone.contains(&b';') {
        let spaced: Vec<u8> = zone
            .iter()
            .flat_map(|&b| if b == b';' { vec![b' ', b';'] } else { vec![b] })
            .collect();
        let mut spaced_expected = oracle.parse(&spaced);
        if spaced_expected != actual && !spaced.ends_with(b"\n") {
            spaced_expected = oracle.parse(&[&spaced[..], b"\n"].concat());
        }
        if spaced_expected == actual {
            return;
        }
        let uncommented = without_comments(zone);
        let mut uncommented_expected = oracle.parse(&uncommented);
        if uncommented_expected != actual && !uncommented.ends_with(b"\n") {
            uncommented_expected = oracle.parse(&[&uncommented[..], b"\n"].concat());
        }
        if uncommented_expected == actual {
            return;
        }
    }
    // Documented deviation: Pharos parses a missing final newline as if it were present.
    if actual != expected && !zone.ends_with(b"\n") {
        let expected = oracle.parse(&[zone, b"\n"].concat());
        assert_eq!(actual, expected, "Pharos and miekg/dns (with final newline) disagree");
        return;
    }
    assert_eq!(actual, expected, "Pharos and miekg/dns disagree");
});
