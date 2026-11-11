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
        let path = std::env::var_os("PHAROS_ZONE_ORACLE").expect(
            "set PHAROS_ZONE_ORACLE to the zone-oracle binary (cargo xtask fuzz does this)",
        );
        let mut child = Command::new(path)
            .arg("--batch")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("start zone oracle");
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        Self {
            _child: child,
            stdin,
            stdout,
        }
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
        self.stdout
            .read_exact(&mut length)
            .expect("oracle response");
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

fn space_numeric_apl_at_line_end(zone: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(zone.len());
    // RFC 3597 §5 and RFC 3123 §4: numeric TYPE42 also permits an empty APL.
    for line in zone.split_inclusive(|&b| b == b'\n') {
        let end = line
            .iter()
            .rposition(|&b| b != b'\n' && b != b'\r')
            .map_or(0, |i| i + 1);
        let start = line[..end]
            .iter()
            .rposition(|&b| b == b' ' || b == b'\t')
            .map_or(0, |i| i + 1);
        let token = &line[start..end];
        let numeric_apl = token
            .get(..4)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"TYPE"))
            && token[4..].iter().all(u8::is_ascii_digit)
            && token[4..]
                .iter()
                .copied()
                .skip_while(|&b| b == b'0')
                .eq(b"42".iter().copied());
        result.extend_from_slice(&line[..end]);
        if numeric_apl {
            result.push(b' ');
        }
        result.extend_from_slice(&line[end..]);
    }
    result
}

// miekg/dns re-parses a $GENERATE template without a final newline and accepts an
// unterminated quote there (documented deviations).
fn generate_line_error(zone: &[u8], error: &str) -> bool {
    has_generate(zone)
        && (error.contains("unterminated record") || error.contains("invalid $GENERATE"))
}

fn dangling_escape_offset(zone: &[u8]) -> Option<usize> {
    let origin: Name = ORIGIN.parse().unwrap();
    let error = ZoneParser::new(Cursor::new(zone), origin, "fuzz.zone")
        .collect::<Result<Vec<_>, _>>()
        .err()?;
    if error.message != "incomplete escape" {
        return None;
    }
    let line_start = zone
        .split_inclusive(|&b| b == b'\n')
        .take(error.line - 1)
        .map(<[u8]>::len)
        .sum::<usize>();
    let offset = line_start + error.column;
    if zone.get(offset - 1) != Some(&b'\\')
        || !matches!(zone.get(offset), None | Some(b'\n'))
    {
        return None;
    }
    Some(offset)
}

fn repair_dangling_name_escape(zone: &[u8]) -> Option<Vec<u8>> {
    let offset = dangling_escape_offset(zone)?;
    // RFC 1035 §5.1: a relative name's origin is appended to make an absolute name.
    let mut repaired = zone.to_vec();
    repaired.splice(offset..offset, b".example.".iter().copied());
    Some(repaired)
}

fn repair_miekg_type_prefix(zone: &[u8]) -> Option<Vec<u8>> {
    let mut repaired = Vec::with_capacity(zone.len());
    let (mut quoted, mut escaped, mut comment) = (false, false, false);
    let mut changed = false;
    let mut i = 0;
    while i < zone.len() {
        let b = zone[i];
        if comment {
            repaired.push(b);
            comment = b != b'\n';
            i += 1;
        } else if escaped {
            repaired.push(b);
            escaped = false;
            i += 1;
        } else if b == b'\\' {
            repaired.push(b);
            escaped = true;
            i += 1;
        } else if b == b'"' {
            repaired.push(b);
            quoted = !quoted;
            i += 1;
        } else if b == b';' && !quoted {
            repaired.push(b);
            comment = true;
            i += 1;
        } else if quoted || matches!(b, b' ' | b'\t' | b'\n') {
            repaired.push(b);
            i += 1;
        } else {
            let end = zone[i..]
                .iter()
                .position(|b| matches!(b, b' ' | b'\t' | b'\n' | b';' | b'"' | b'\\'))
                .map_or(zone.len(), |offset| i + offset);
            let token = &zone[i..end];
            // RFC 3597 §5: numeric type mnemonics have the TYPE prefix.
            if token.len() >= 5
                && !token[..4].eq_ignore_ascii_case(b"TYPE")
                && token[4..].iter().all(u8::is_ascii_digit)
            {
                repaired.extend_from_slice(b"TYPE");
                repaired.extend_from_slice(&token[4..]);
                changed = true;
            } else {
                repaired.extend_from_slice(token);
            }
            i = end;
        }
    }
    changed.then_some(repaired)
}

fn has_dangling_escape(zone: &[u8]) -> bool {
    // RFC 1035 §5.1: a backslash escape requires the following character.
    dangling_escape_offset(zone).is_some()
}

fn pharos(zone: &[u8]) -> String {
    let origin: Name = ORIGIN.parse().unwrap();
    match ZoneParser::new(Cursor::new(zone), origin, "fuzz.zone").collect::<Result<Vec<_>, _>>() {
        // Documented deviations: Pharos rejects missing RDATA fields, unmatched ')' and
        // unterminated quotes.
        Err(error)
            if [
                "missing ",
                "fields, got",
                "unbalanced parentheses",
                "unterminated record",
            ]
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
    // miekg/dns consumes the origin after a dangling name escape. Only skip when
    // spelling out that name reproduces exactly the original accepted result.
    if actual == "reject\n" && expected.starts_with("accept\n") {
        if let Some(repaired) = repair_dangling_name_escape(zone) {
            if pharos(&repaired) == expected && oracle.parse(&repaired) == expected {
                return;
            }
        }
        // miekg/dns reads the fifth byte onward as a numeric type in bitmaps without checking
        // that the first four bytes spell TYPE; only skip when the corrected spelling agrees.
        if let Some(repaired) = repair_miekg_type_prefix(zone) {
            if pharos(&repaired) == expected && oracle.parse(&repaired) == expected {
                return;
            }
        }
        // miekg/dns treats a dangling X25 escape as an empty address, unlike its TXT parser.
        if expected.contains("\t19\t") && has_dangling_escape(zone) {
            return;
        }
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
    // Documented deviation: numeric APL types need a blank before a line end in miekg/dns.
    if actual.starts_with("accept\n") && expected == "reject\n" {
        let spaced = space_numeric_apl_at_line_end(zone);
        if spaced != zone {
            let mut spaced_expected = oracle.parse(&spaced);
            if spaced_expected != actual && !spaced.ends_with(b"\n") {
                spaced_expected = oracle.parse(&[&spaced[..], b"\n"].concat());
            }
            if spaced_expected == actual {
                return;
            }
        }
    }
    // Documented deviation: Pharos parses a missing final newline as if it were present.
    if actual != expected && !zone.ends_with(b"\n") {
        let expected = oracle.parse(&[zone, b"\n"].concat());
        assert_eq!(
            actual, expected,
            "Pharos and miekg/dns (with final newline) disagree"
        );
        return;
    }
    assert_eq!(actual, expected, "Pharos and miekg/dns disagree");
});
