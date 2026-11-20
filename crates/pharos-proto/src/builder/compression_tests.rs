use super::*;
use proptest::prelude::*;

// RFC 1035 §4.1.4: Keep the original candidate validation as a wire-output oracle.
fn write_name_original(
    builder: &mut MessageBuilder<'_>,
    name: NameRef<'_>,
    compress: bool,
) -> Result<(), BuildError> {
    for (index, label) in name.labels().enumerate() {
        let pointer = builder.offsets[..builder.offset_count]
            .iter()
            .copied()
            .find(|offset| {
                let offset = usize::from(*offset);
                offset < builder.wire.len()
                    && NameRef::parse(builder.wire, offset)
                        .is_ok_and(|stored| stored.labels().eq(name.labels().skip(index)))
            });
        if compress && let Some(offset) = pointer {
            return builder.write_bytes(&(0xc000 | offset).to_be_bytes());
        }
        if pointer.is_none()
            && builder.wire.len() < 0x4000
            && builder.offset_count < COMPRESSION_SLOTS
        {
            builder.offsets[builder.offset_count] = builder.wire.len() as u16;
            builder.offset_count += 1;
        }
        builder.write_bytes(&[label.len() as u8])?;
        builder.write_bytes(label)?;
    }
    builder.write_bytes(&[0])
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn compression_matches_original_wire(
        entries in proptest::collection::vec((any::<u8>(), 0_u8..8, 0_u8..4, any::<bool>(), any::<bool>()), 1..150),
        padding in prop_oneof![Just(0_usize), Just(16_360), Just(16_384)],
    ) {
        let mut actual_wire = Vec::new();
        let mut expected_wire = Vec::new();
        let mut actual = MessageBuilder::new(&mut actual_wire, 65_535, 0, 0).unwrap();
        let mut expected = MessageBuilder::new(&mut expected_wire, 65_535, 0, 0).unwrap();
        actual.write_bytes(&vec![0; padding]).unwrap();
        expected.write_bytes(&vec![0; padding]).unwrap();

        for (first, second, third, compress, compressed_input) in entries {
            // RFC 1035 §4.1.4: exercise repeated suffixes, partial names, and compressed inputs.
            let input = [1, first, 1, b'A' + second, 1, b'a' + third, 0, 1, first, 0xc0, 2];
            let name = NameRef::parse(&input, if compressed_input { 7 } else { 0 }).unwrap();
            let actual_result = actual.write_name_with_compression(name, compress);
            let expected_result = write_name_original(&mut expected, name, compress);
            prop_assert_eq!(actual_result, expected_result);
            prop_assert_eq!(&*actual.wire, &*expected.wire);
            prop_assert_eq!(actual.offset_count, expected.offset_count);
            prop_assert_eq!(&actual.offsets[..actual.offset_count], &expected.offsets[..expected.offset_count]);
        }
    }
}
