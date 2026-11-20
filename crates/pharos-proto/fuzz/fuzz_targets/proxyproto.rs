#![forbid(unsafe_code)]
#![no_main]

use libfuzzer_sys::fuzz_target;
use pharos_server::proxyproto::header::{self, Parse};

fuzz_target!(|data: &[u8]| {
    // PROXY protocol §2: any input parses to a header, a verdict or an error, and never past its end.
    if let Ok(Parse::Header(parsed)) = header::parse(data) {
        assert!(parsed.length <= data.len());
        let mut hex = String::new();
        header::tlv_hex(parsed.tlvs, &mut hex);
    }
});
