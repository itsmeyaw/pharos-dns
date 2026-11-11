//! Debug Message hexdumps.

use std::fmt::Write;

/// Format a Message for Wireshark's text2pcap.
#[must_use]
pub fn hexdump(data: &[u8]) -> String {
    let mut result = String::new();
    for (i, byte) in data.iter().enumerate() {
        if i % 16 == 0 {
            if i != 0 {
                result.push('\n');
            }
            let _ = write!(result, "debug: {i:06x}");
        }
        let _ = write!(result, " {byte:02x}");
    }
    let _ = write!(result, "\ndebug: {:06x}", data.len());
    result
}

/// Log a Message dump only when debug logging is enabled.
pub fn log_message(message: &str, data: &[u8]) {
    if pharos_server::logging::debug_enabled() && !data.is_empty() {
        pharos_server::logging::log("DEBUG", "debug", &format!("{message}\n{}", hexdump(data)));
    }
}
