use pharos_proto::{Message, Rdata, Record, Type};

pub(crate) fn compare(
    pharos: &Message<'_>,
    coredns: &Message<'_>,
    tolerance: u32,
    mask_srv_port: bool,
) -> Result<(), String> {
    compare_with_soa_serial(pharos, coredns, tolerance, mask_srv_port, false)
}

pub(crate) fn compare_with_soa_serial(
    pharos: &Message<'_>,
    coredns: &Message<'_>,
    tolerance: u32,
    mask_srv_port: bool,
    mask_soa_serial: bool,
) -> Result<(), String> {
    let questions = |message: &Message<'_>| {
        message
            .questions()
            .map(|q| format!(";{}\t{}\t{}", q.name, q.qclass, q.qtype))
            .collect::<Vec<_>>()
    };
    let mut differences = Vec::new();
    if pharos.flags() != coredns.flags() {
        differences.push(format!(
            ";; HEADER flags:\n- 0x{:04x}\n+ 0x{:04x}",
            pharos.flags(),
            coredns.flags()
        ));
    }
    let (left, right) = (questions(pharos), questions(coredns));
    if left != right {
        differences.push(format!(
            ";; QUESTION SECTION:\n{}",
            diff_lines(&left, &right)
        ));
    }
    for (section, left, right, additional) in [
        (
            "ANSWER",
            pharos.answers().collect::<Vec<_>>(),
            coredns.answers().collect::<Vec<_>>(),
            false,
        ),
        (
            "AUTHORITY",
            pharos.authorities().collect(),
            coredns.authorities().collect(),
            false,
        ),
        (
            "ADDITIONAL",
            pharos.additionals().collect(),
            coredns.additionals().collect(),
            true,
        ),
    ] {
        let mut left_sorted = left.clone();
        let mut right_sorted = right.clone();
        left_sorted.sort_by_key(|r| r.ttl);
        right_sorted.sort_by_key(|r| r.ttl);
        let mut unmatched = right_sorted;
        let matches = left_sorted.iter().all(|a| {
            if let Some(index) = unmatched.iter().position(|b| {
                record_equal(
                    a,
                    b,
                    pharos,
                    coredns,
                    tolerance,
                    additional && mask_srv_port,
                    mask_soa_serial,
                )
            }) {
                unmatched.remove(index);
                true
            } else {
                false
            }
        }) && unmatched.is_empty();
        if !matches {
            let mut left_lines = left.iter().map(record_line).collect::<Vec<_>>();
            let mut right_lines = right.iter().map(record_line).collect::<Vec<_>>();
            if left_lines.iter().any(|line| right_lines.contains(line)) {
                for (line, record) in left_lines
                    .iter_mut()
                    .zip(&left)
                    .chain(right_lines.iter_mut().zip(&right))
                {
                    let raw: String = record
                        .rdata
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect();
                    line.push_str(&format!(" ; RDATA {raw}"));
                }
            }
            differences.push(format!(
                ";; {section} SECTION:\n{}",
                diff_lines(&left_lines, &right_lines)
            ));
        }
    }
    if differences.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "--- pharos\n{}\n+++ coredns\n{}\n;; differences\n{}",
            display_message(pharos),
            display_message(coredns),
            differences.join("\n"),
        ))
    }
}

fn display_message(message: &Message<'_>) -> String {
    let mut result = format!(
        ";; opcode: {}, status: {}, flags: 0x{:04x}\n;; QUESTION SECTION:\n",
        message.opcode(),
        message.rcode(),
        message.flags()
    );
    for q in message.questions() {
        result.push_str(&format!(";{}\t{}\t{}\n", q.name, q.qclass, q.qtype));
    }
    for (section, records) in [
        ("ANSWER", message.answers().collect::<Vec<_>>()),
        ("AUTHORITY", message.authorities().collect()),
        ("ADDITIONAL", message.additionals().collect()),
    ] {
        result.push_str(&format!(";; {section} SECTION:\n"));
        for record in records {
            result.push_str(&format!("{}\n", record_line(&record)));
        }
    }
    result
}

fn diff_lines(left: &[String], right: &[String]) -> String {
    left.iter()
        .map(|line| format!("- {line}\n"))
        .chain(right.iter().map(|line| format!("+ {line}\n")))
        .collect()
}

fn record_line(record: &Record<'_>) -> String {
    let data = record
        .data()
        .unwrap_or(Rdata::Unknown(record.rtype, record.rdata));
    format!(
        "{}\t{}\t{}\t{}\t{}",
        record.name, record.ttl, record.class, record.rtype, data
    )
}

fn whoami_srv(record: &Record<'_>, message: &Message<'_>) -> bool {
    let mut labels = record.name.labels();
    if !matches!(labels.next(), Some(b"_udp" | b"_tcp")) {
        return false;
    }
    let question = message.questions().next();
    let name_matches = match question {
        Some(q) => record.class == q.qclass && labels.eq(q.name.labels()),
        None => record.class.0 == 0 && labels.next().is_none(),
    };
    name_matches
        && matches!(record.data(), Ok(Rdata::Srv { priority: 0, weight: 0, target, .. }) if target.labels().next().is_none())
}

fn record_equal(
    a: &Record<'_>,
    b: &Record<'_>,
    left: &Message<'_>,
    right: &Message<'_>,
    tolerance: u32,
    mask: bool,
    mask_soa_serial: bool,
) -> bool {
    if a.name.to_string() != b.name.to_string()
        || a.rtype != b.rtype
        || a.class != b.class
        || if a.rtype == Type::OPT {
            a.ttl != b.ttl
        } else {
            a.ttl.abs_diff(b.ttl) > tolerance
        }
    {
        return false;
    }
    let mut a_data = a.data().unwrap_or(Rdata::Unknown(a.rtype, a.rdata));
    let mut b_data = b.data().unwrap_or(Rdata::Unknown(b.rtype, b.rdata));
    if mask && whoami_srv(a, left) && whoami_srv(b, right) {
        if let Rdata::Srv { ref mut port, .. } = a_data {
            *port = 0;
        }
        if let Rdata::Srv { ref mut port, .. } = b_data {
            *port = 0;
        }
    }
    if mask_soa_serial
        && let (Rdata::Soa { serial: a, .. }, Rdata::Soa { serial: b, .. }) =
            (&mut a_data, &mut b_data)
    {
        *a = 0;
        *b = 0;
    }
    a_data == b_data && a_data.to_string() == b_data.to_string()
}

#[cfg(test)]
mod tests {
    use super::{compare, compare_with_soa_serial};
    use pharos_proto::Message;

    #[test]
    fn soa_serial_mask_is_opt_in_and_preserves_every_other_field() {
        let left = [
            0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 6, 0, 1, 0, 0, 0, 60, 0, 26, 1, b'a', 0,
            1, b'b', 0, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 4, 0, 0, 0, 5,
        ];
        let mut right = left;
        right[32] = 9; // serial
        let l = Message::parse(&left).unwrap();
        assert!(
            compare_with_soa_serial(&l, &Message::parse(&right).unwrap(), 0, false, false).is_err()
        );
        assert!(
            compare_with_soa_serial(&l, &Message::parse(&right).unwrap(), 0, false, true).is_ok()
        );
        for offset in [16, 20, 24, 27, 36, 40, 44, 48] {
            let mut changed = right;
            changed[offset] ^= 1;
            assert!(
                compare_with_soa_serial(&l, &Message::parse(&changed).unwrap(), 0, false, true)
                    .is_err(),
                "offset {offset}"
            );
        }
        let a = [
            0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1,
            0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
        ];
        let mut other_a = a;
        *other_a.last_mut().unwrap() = 2;
        assert!(
            compare_with_soa_serial(
                &Message::parse(&a).unwrap(),
                &Message::parse(&other_a).unwrap(),
                0,
                false,
                true,
            )
            .is_err()
        );
    }

    #[test]
    fn reports_wrong_answer_in_dig_style() {
        let left = [
            0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 0x0c, 0, 1, 0,
            1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
        ];
        let mut right = left;
        right[1] = 2;
        *right.last_mut().unwrap() = 2;
        let diff = compare(
            &Message::parse(&left).unwrap(),
            &Message::parse(&right).unwrap(),
            0,
            false,
        )
        .unwrap_err();
        assert!(diff.contains("ANSWER"), "{diff}");
        assert!(diff.contains("192.0.2.1"), "{diff}");
        assert!(diff.contains("192.0.2.2"), "{diff}");
        assert!(diff.contains(";; QUESTION SECTION:"), "{diff}");
        assert!(diff.contains(";; opcode:"), "{diff}");
    }

    #[test]
    fn ttl_tolerance_matches_reordered_duplicates_without_rounding() {
        let left = [
            0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1,
            0, 0, 0, 100, 0, 4, 192, 0, 2, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 102, 0, 4, 192, 0, 2,
            1,
        ];
        let mut right = left;
        right[1] = 8;
        right[28] = 101;
        right[44] = 99;
        assert!(
            compare(
                &Message::parse(&left).unwrap(),
                &Message::parse(&right).unwrap(),
                1,
                false
            )
            .is_ok()
        );
        assert!(
            compare(
                &Message::parse(&left).unwrap(),
                &Message::parse(&right).unwrap(),
                0,
                false
            )
            .is_err()
        );
        right[44] = 98;
        assert!(
            compare(
                &Message::parse(&left).unwrap(),
                &Message::parse(&right).unwrap(),
                1,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn preserves_flags_questions_and_all_opt_fields() {
        let left = [
            0, 1, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1, 0, 0, 41, 4, 208, 0,
            0, 0, 0, 0, 5, 0, 3, 0, 1, 42,
        ];
        for (offset, value) in [(3, 0x81), (13, b'b'), (23, 209), (27, 1), (34, 43)] {
            let mut right = left;
            right[offset] = value;
            assert!(
                compare(
                    &Message::parse(&left).unwrap(),
                    &Message::parse(&right).unwrap(),
                    u32::MAX,
                    true
                )
                .is_err(),
                "offset {offset}"
            );
        }
    }

    #[test]
    fn masks_only_whoami_additional_srv_port() {
        let left = [
            0, 1, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1, 4, b'_', b'u', b'd',
            b'p', 0xc0, 12, 0, 33, 0, 1, 0, 0, 0, 0, 0, 7, 0, 0, 0, 0, 0x12, 0x34, 0,
        ];
        let mut right = left;
        right[41] = 0x35;
        let l = Message::parse(&left).unwrap();
        let r = Message::parse(&right).unwrap();
        assert!(compare(&l, &r, 0, true).is_ok());
        assert!(compare(&l, &r, 0, false).is_err());
        right[39] = 1;
        assert!(compare(&l, &Message::parse(&right).unwrap(), 0, true).is_err());

        let mut answer_left = left;
        let mut answer_right = right;
        answer_right[39] = 0;
        answer_left[7] = 1;
        answer_left[11] = 0;
        answer_right[7] = 1;
        answer_right[11] = 0;
        assert!(
            compare(
                &Message::parse(&answer_left).unwrap(),
                &Message::parse(&answer_right).unwrap(),
                0,
                true
            )
            .is_err()
        );

        let mut unrelated_left = left;
        let mut unrelated_right = right;
        unrelated_right[39] = 0;
        unrelated_left[21] = b'x';
        unrelated_right[21] = b'x';
        assert!(
            compare(
                &Message::parse(&unrelated_left).unwrap(),
                &Message::parse(&unrelated_right).unwrap(),
                0,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn reveals_different_rdata_with_same_presentation() {
        let left = [
            0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 8, 0, 0, 0, 0,
            b'\\', b'0', b'6', b'5',
        ];
        let right = [
            0, 1, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 5, 0, 0, 0, 0,
            b'A',
        ];
        let diff = compare(
            &Message::parse(&left).unwrap(),
            &Message::parse(&right).unwrap(),
            0,
            false,
        )
        .unwrap_err();
        assert!(
            diff.contains("5c303635") && diff.contains("0000000041"),
            "{diff}"
        );
    }

    #[test]
    fn reorders_distinct_records_but_not_across_sections() {
        let left = [
            0, 1, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1,
            0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 2,
        ];
        let mut right = left;
        right[34] = 2;
        right[50] = 1;
        assert!(
            compare(
                &Message::parse(&left).unwrap(),
                &Message::parse(&right).unwrap(),
                0,
                false
            )
            .is_ok()
        );
        right[7] = 1;
        right[9] = 1;
        assert!(
            compare(
                &Message::parse(&left).unwrap(),
                &Message::parse(&right).unwrap(),
                0,
                false
            )
            .is_err()
        );
    }

    #[test]
    fn compares_compressed_typed_names_without_ignoring_case() {
        let compressed = [
            0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 2, 0, 1, 0xc0, 12, 0, 2, 0, 1,
            0, 0, 0, 60, 0, 2, 0xc0, 12,
        ];
        let mut plain = vec![
            0, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 2, 0, 1, 1, b'a', 0, 0, 2, 0,
            1, 0, 0, 0, 60, 0, 3, 1, b'a', 0,
        ];
        assert!(
            compare(
                &Message::parse(&compressed).unwrap(),
                &Message::parse(&plain).unwrap(),
                0,
                false
            )
            .is_ok()
        );
        plain[33] = b'A';
        assert!(
            compare(
                &Message::parse(&compressed).unwrap(),
                &Message::parse(&plain).unwrap(),
                0,
                false
            )
            .is_err()
        );
    }
}
