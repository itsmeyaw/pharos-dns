//! Process-wide stdout logging, configured by the binary at startup.

use std::{
    fmt::{self, Write as _},
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

/// Enable or disable process-wide debug logging.
pub fn set_debug_enabled(enabled: bool) {
    DEBUG.store(enabled, Ordering::Relaxed);
}

/// Return whether debug entries should be emitted.
#[must_use]
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

/// Write a bounded debug entry without allocating on the Query path.
pub fn log_debug(plugin: &str, message: fmt::Arguments<'_>) {
    let mut text = StackText::<2048>::new();
    if text.write_fmt(message).is_err() {
        return;
    }
    let mut line = StackText::<16384>::new();
    let format = if JSON.load(Ordering::Relaxed) {
        LogFormat::Json
    } else {
        LogFormat::Text
    };
    write_line(
        &mut line,
        format,
        SystemTime::now(),
        "DEBUG",
        plugin,
        text.as_str(),
    );
    let _ = io::stdout().lock().write_all(line.as_str().as_bytes());
}

struct StackText<const N: usize> {
    bytes: [u8; N],
    len: usize,
}

impl<const N: usize> StackText<N> {
    fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
        }
    }
    fn as_str(&self) -> &str {
        std::str::from_utf8(&self.bytes[..self.len]).expect("formatted UTF-8")
    }
}

impl<const N: usize> fmt::Write for StackText<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        let end = self
            .len
            .checked_add(value.len())
            .filter(|end| *end <= N)
            .ok_or(fmt::Error)?;
        self.bytes[self.len..end].copy_from_slice(value.as_bytes());
        self.len = end;
        Ok(())
    }
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
    write_line(&mut line, format, time, level, plugin, message);
    line
}

fn write_line(
    line: &mut impl fmt::Write,
    format: LogFormat,
    time: SystemTime,
    level: &str,
    plugin: &str,
    message: &str,
) {
    match format {
        LogFormat::Text => {
            write_timestamp(line, time);
            let _ = write!(line, " {level} ");
            if !plugin.is_empty() {
                let _ = write!(line, "{plugin}: ");
            }
            let _ = writeln!(line, "{message}");
        }
        LogFormat::Json => {
            let _ = line.write_str("{\"timestamp\":\"");
            write_timestamp(line, time);
            let _ = line.write_str("\",\"level\":");
            json_string(line, level);
            let _ = line.write_str(",\"plugin\":");
            json_string(line, plugin);
            let _ = line.write_str(",\"message\":");
            json_string(line, message);
            let _ = line.write_str("}\n");
        }
    }
}

fn json_string(out: &mut impl fmt::Write, value: &str) {
    let _ = out.write_char('"');
    for c in value.chars() {
        match c {
            '"' => {
                let _ = out.write_str("\\\"");
            }
            '\\' => {
                let _ = out.write_str("\\\\");
            }
            '\n' => {
                let _ = out.write_str("\\n");
            }
            '\r' => {
                let _ = out.write_str("\\r");
            }
            '\t' => {
                let _ = out.write_str("\\t");
            }
            c if c <= '\u{1f}' => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => {
                let _ = out.write_char(c);
            }
        }
    }
    let _ = out.write_char('"');
}

fn write_timestamp(out: &mut impl fmt::Write, time: SystemTime) {
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
