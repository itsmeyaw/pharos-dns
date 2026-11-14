#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_proto::{Name, NameRef};

fuzz_target!(|data: &[u8]| {
    let offset = data.first().copied().map_or(0, usize::from);
    for offset in [0, 12, offset] {
        // RFC 4343 §2.1: Presentation escapes represent unusual DNS label octets without loss.
        if let Ok(name) = NameRef::parse(data, offset) {
            let owned = name.to_name();
            let parsed: Name = name.to_string().parse().unwrap();
            assert_eq!(owned.as_wire(), parsed.as_wire());
        }
    }
    if let Ok(text) = std::str::from_utf8(data) {
        if let Ok(name) = text.parse::<Name>() {
            let parsed: Name = name.to_string().parse().unwrap();
            assert_eq!(name.as_wire(), parsed.as_wire());
        }
        let root: Name = ".".parse().unwrap();
        if let Ok(name) = Name::parse(text, &root) {
            let parsed: Name = name.to_string().parse().unwrap();
            assert_eq!(name.as_wire(), parsed.as_wire());
        }
    }
});
