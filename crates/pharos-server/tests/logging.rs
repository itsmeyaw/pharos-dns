use std::time::{Duration, UNIX_EPOCH};

use pharos_server::logging::{LogFormat, format_line};

#[test]
fn text_log_uses_utc_rfc3339_and_plugin_name() {
    let timestamp = UNIX_EPOCH + Duration::from_secs(1_704_164_645);
    assert_eq!(
        format_line(LogFormat::Text, timestamp, "ERROR", "whoami", "bad query"),
        "2024-01-02T03:04:05Z ERROR whoami: bad query\n"
    );
}

#[test]
fn json_log_is_one_line_and_escapes_control_characters() {
    assert_eq!(
        format_line(LogFormat::Json, UNIX_EPOCH, "INFO", "x\"y", "a\n\t\\b"),
        "{\"timestamp\":\"1970-01-01T00:00:00Z\",\"level\":\"INFO\",\"plugin\":\"x\\\"y\",\"message\":\"a\\n\\t\\\\b\"}\n"
    );
}
