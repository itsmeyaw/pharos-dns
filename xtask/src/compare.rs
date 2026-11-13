use pharos_proto::{Message, Rdata, Record, Type};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) enum RrsigMask {
    #[default]
    None,
    FixedValidity,
    RandomValidity,
}

impl From<bool> for RrsigMask {
    fn from(value: bool) -> Self {
        if value {
            Self::FixedValidity
        } else {
            Self::None
        }
    }
}

#[cfg(test)]
fn compare(
    pharos: &Message<'_>,
    coredns: &Message<'_>,
    tolerance: u32,
    mask_srv_port: bool,
) -> Result<(), String> {
    compare_with_soa_serial(
        pharos,
        coredns,
        tolerance,
        mask_srv_port,
        false,
        false,
        false,
    )
}

pub(crate) fn compare_with_soa_serial(
    pharos: &Message<'_>,
    coredns: &Message<'_>,
    tolerance: u32,
    mask_srv_port: bool,
    mask_soa_serial: bool,
    dedupe_additional: bool,
    mask_rrsig: impl Into<RrsigMask>,
) -> Result<(), String> {
    let mask_rrsig = mask_rrsig.into();
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
        if additional && dedupe_additional {
            // RFC 2181 §5: duplicate RRs carry no meaning; CoreDNS may repeat glue.
            let mut seen = std::collections::HashSet::new();
            right_sorted.retain(|r| seen.insert((record_line(r), r.rdata.to_vec())));
        }
        left_sorted.sort_by_key(|r| r.ttl);
        right_sorted.sort_by_key(|r| r.ttl);
        let mut unmatched = right_sorted;
        let matches = left_sorted.iter().all(|a| {
            if let Some(index) = unmatched.iter().position(|b| {
                record_equal(
                    a,
                    b,
                    (pharos, coredns),
                    tolerance,
                    additional && mask_srv_port,
                    mask_soa_serial,
                    mask_rrsig,
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
    messages: (&Message<'_>, &Message<'_>),
    tolerance: u32,
    mask: bool,
    mask_soa_serial: bool,
    mask_rrsig: RrsigMask,
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
    if mask && whoami_srv(a, messages.0) && whoami_srv(b, messages.1) {
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
    // RFC 4034 §3.1: retain RRSIG metadata and signature length while masking dynamic values.
    if mask_rrsig != RrsigMask::None
        && let (
            Rdata::Rrsig {
                original_ttl: at,
                expiration: ae,
                inception: ai,
                signature: asig,
                ..
            },
            Rdata::Rrsig {
                original_ttl: bt,
                expiration: be,
                inception: bi,
                signature: bsig,
                ..
            },
        ) = (&mut a_data, &mut b_data)
    {
        // RFC 4034 §3.1.5: signature times use 32-bit serial arithmetic.
        let validity = ae.wrapping_sub(*ai);
        let other_validity = be.wrapping_sub(*bi);
        if asig.len() != bsig.len()
            || validity >= 0x8000_0000
            || other_validity >= 0x8000_0000
            || (mask_rrsig == RrsigMask::FixedValidity && validity != other_validity)
        {
            return false;
        }
        // RFC 4034 §3.1.4: Original TTL is the signed RRset's TTL; CoreDNS hardcodes 3600.
        *at = 0;
        *bt = 0;
        *ae = 0;
        *be = 0;
        *ai = 0;
        *bi = 0;
        *asig = &[];
        *bsig = &[];
    }
    a_data == b_data && a_data.to_string() == b_data.to_string()
}

#[cfg(test)]
mod tests {
    use super::compare;
    use pharos_proto::Message;

    fn compare_with_soa_serial(
        left: &Message<'_>,
        right: &Message<'_>,
        ttl: u32,
        srv: bool,
        soa: bool,
        dedupe: bool,
    ) -> Result<(), String> {
        super::compare_with_soa_serial(left, right, ttl, srv, soa, dedupe, false)
    }

    #[test]
    fn random_rrsig_validity_is_masked_only_when_opted_in() {
        let left = [
            0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 46, 0, 1, 0, 0, 0, 60, 0, 24, 0,
            1, 15, 1, 0, 0, 0, 60, 0, 0, 0, 10, 0, 0, 0, 2, 0x12, 0x34, 1, b'a', 0, 10, 11, 12,
        ];
        let mut right = left;
        right[36] = 12;
        let left = Message::parse(&left).unwrap();
        let right = Message::parse(&right).unwrap();
        assert!(
            super::compare_with_soa_serial(
                &left,
                &right,
                0,
                false,
                false,
                false,
                super::RrsigMask::FixedValidity
            )
            .is_err()
        );
        assert!(
            super::compare_with_soa_serial(
                &left,
                &right,
                0,
                false,
                false,
                false,
                super::RrsigMask::RandomValidity
            )
            .is_ok()
        );
    }

    #[test]
    fn rrsig_original_ttl_mask_is_opt_in() {
        let left = [
            0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 46, 0, 1, 0, 0, 0, 60, 0, 24, 0,
            1, 15, 1, 0, 0, 0, 60, 0, 0, 0, 10, 0, 0, 0, 2, 0x12, 0x34, 1, b'a', 0, 10, 11, 12,
        ];
        for offset in 29..33 {
            let mut right = left;
            right[offset] ^= 1;
            let (a, b) = (
                Message::parse(&left).unwrap(),
                Message::parse(&right).unwrap(),
            );
            assert!(super::compare_with_soa_serial(&a, &b, 0, false, false, false, false).is_err());
            assert!(super::compare_with_soa_serial(&a, &b, 0, false, false, false, true).is_ok());
        }
    }

    #[test]
    fn rrsig_mask_is_opt_in_and_preserves_other_fields_and_counts() {
        let left = [
            0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, b'x', 0, 0, 46, 0, 1, 0, 0, 0, 60, 0, 24, 0,
            1, 15, 1, 0, 0, 0, 60, 0, 0, 0, 10, 0, 0, 0, 2, 0x12, 0x34, 1, b'a', 0, 10, 11, 12,
        ];
        let mut right = left;
        right[29..33].copy_from_slice(&7200_u32.to_be_bytes()); // Original TTL
        right[36] = 12; // expiration
        right[40] = 4; // inception
        right[46] = 13; // signature
        let masked = |a: &[u8], b: &[u8], mask| {
            super::compare_with_soa_serial(
                &Message::parse(a).unwrap(),
                &Message::parse(b).unwrap(),
                0,
                false,
                false,
                false,
                mask,
            )
        };
        assert!(masked(&left, &right, false).is_err());
        assert!(masked(&left, &right, true).is_ok());
        let mut wrong_window = right;
        wrong_window[36] += 1;
        assert!(masked(&left, &wrong_window, true).is_err());
        let mut expired_before_inception = right;
        expired_before_inception[36] = 1;
        assert!(masked(&left, &expired_before_inception, true).is_err());
        let mut invalid_window = right;
        invalid_window[36] = 1;
        let mut same_invalid_window = invalid_window;
        same_invalid_window[46] ^= 1;
        assert!(masked(&invalid_window, &same_invalid_window, true).is_err());
        let mut wrapping = left;
        wrapping[33..37].copy_from_slice(&3_u32.to_be_bytes());
        wrapping[37..41].copy_from_slice(&(u32::MAX - 4).to_be_bytes());
        let mut shifted = wrapping;
        shifted[33..37].copy_from_slice(&5_u32.to_be_bytes());
        shifted[37..41].copy_from_slice(&(u32::MAX - 2).to_be_bytes());
        assert!(masked(&wrapping, &shifted, true).is_ok());
        for offset in [3, 13, 16, 18, 22, 25, 26, 27, 28, 41, 42, 44] {
            let mut changed = right;
            changed[offset] ^= 1;
            assert!(masked(&left, &changed, true).is_err(), "offset {offset}");
        }
        let mut longer = right.to_vec();
        longer[24] += 1;
        longer.push(14);
        assert!(masked(&left, &longer, true).is_err());
        let mut duplicate = right.to_vec();
        duplicate[7] = 2;
        duplicate.extend_from_slice(&right[12..]);
        assert!(masked(&left, &duplicate, true).is_err());
        for count in [9, 11] {
            let mut a = left;
            let mut b = right;
            a[7] = 0;
            b[7] = 0;
            a[count] = 1;
            b[count] = 1;
            assert!(masked(&a, &b, true).is_ok());
            assert!(masked(&left, &b, true).is_err());
        }
        let a = [
            0, 1, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1,
        ];
        let mut b = a;
        *b.last_mut().unwrap() = 2;
        assert!(masked(&a, &b, true).is_err());
    }

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
            compare_with_soa_serial(&l, &Message::parse(&right).unwrap(), 0, false, false, false)
                .is_err()
        );
        assert!(
            compare_with_soa_serial(&l, &Message::parse(&right).unwrap(), 0, false, true, false)
                .is_ok()
        );
        for offset in [16, 20, 24, 27, 36, 40, 44, 48] {
            let mut changed = right;
            changed[offset] ^= 1;
            assert!(
                compare_with_soa_serial(
                    &l,
                    &Message::parse(&changed).unwrap(),
                    0,
                    false,
                    true,
                    false
                )
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
                false,
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
    fn masks_only_duplicate_coredns_additionals() {
        let glue = [0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1];
        let one = [
            &[
                0, 1, 0x84, 0, 0, 1, 0, 0, 0, 0, 0, 1, 1, b'a', 0, 0, 1, 0, 1,
            ][..],
            &glue,
        ]
        .concat();
        let mut two = [&one[..], &glue].concat();
        two[11] = 2;
        let (l, r) = (Message::parse(&one).unwrap(), Message::parse(&two).unwrap());
        assert!(compare_with_soa_serial(&l, &r, 0, false, false, true).is_ok());
        assert!(compare_with_soa_serial(&l, &r, 0, false, false, false).is_err());
        assert!(compare_with_soa_serial(&r, &l, 0, false, false, true).is_err());
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
