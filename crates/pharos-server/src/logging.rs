//! Process-wide stdout logging, configured by the binary at startup.

use std::{
    fmt::Write as _,
    io::{self, Write as _},
    sync::atomic::{AtomicBool, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LogFormat {
    Text,
    Json,
}

static JSON: AtomicBool = AtomicBool::new(false);
static DEBUG: AtomicBool = AtomicBool::new(false);
pub const PLUGIN_METADATA: &str = "logging/plugin";
/// Marks an Error already logged by the errors Plugin.
pub const ERROR_LOGGED_METADATA: &str = "logging/errors-logged";

/// Select the format used by subsequent log entries.
pub fn init(format: LogFormat) {
    JSON.store(format == LogFormat::Json, Ordering::Relaxed);
}

/// Enable process-wide debug entries.
pub fn set_debug(enabled: bool) {
    DEBUG.store(enabled, Ordering::Relaxed);
}

/// Whether debug entries are enabled.
pub fn debug_enabled() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

/// Write one entry to stdout.
pub fn log(level: &str, plugin: &str, message: &str) {
    if level == "DEBUG" && !debug_enabled() {
        return;
    }
    let format = if JSON.load(Ordering::Relaxed) {
        LogFormat::Json
    } else {
        LogFormat::Text
    };
    let line = format_line(format, SystemTime::now(), level, plugin, message);
    let _ = io::stdout().lock().write_all(line.as_bytes());
}

/// Format one entry with a supplied timestamp.
pub fn format_line(
    format: LogFormat,
    time: SystemTime,
    level: &str,
    plugin: &str,
    message: &str,
) -> String {
    let mut line = String::with_capacity(128 + 6 * (level.len() + plugin.len() + message.len()));
    match format {
        LogFormat::Text => {
            write_timestamp(&mut line, time);
            let _ = write!(line, " {level} ");
            if !plugin.is_empty() {
                let _ = write!(line, "{plugin}: ");
            }
            let _ = writeln!(line, "{message}");
        }
        LogFormat::Json => {
            line.push_str("{\"timestamp\":\"");
            write_timestamp(&mut line, time);
            line.push('"');
            line.push_str(",\"level\":");
            json_string(&mut line, level);
            line.push_str(",\"plugin\":");
            json_string(&mut line, plugin);
            line.push_str(",\"message\":");
            json_string(&mut line, message);
            line.push_str("}\n");
        }
    }
    line
}

fn json_string(out: &mut String, value: &str) {
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write_timestamp(out: &mut String, time: SystemTime) {
    let seconds = match time.duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_secs() as i64,
        Err(error) => {
            -(error.duration().as_secs() as i64) - i64::from(error.duration().subsec_nanos() != 0)
        }
    };
    let days = seconds.div_euclid(86_400);
    let day_seconds = seconds.rem_euclid(86_400);
    // Gregorian civil date from days since 1970-01-01.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    year += i64::from(month <= 2);
    let _ = write!(
        out,
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        day_seconds / 3600,
        day_seconds % 3600 / 60,
        day_seconds % 60
    );
}
