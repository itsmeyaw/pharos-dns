//! CoreDNS error logging configuration.

use pharos_corefile::{Cursor, Error};
use pharos_server::{Context, Next, Outcome, Plugin};
use regex::Regex;
use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

#[derive(Debug)]
struct Pattern {
    period: Duration,
    period_text: String,
    regex: Regex,
    level: &'static str,
    show_first: bool,
    count: AtomicU64,
    stop: tokio::sync::watch::Sender<bool>,
}

#[derive(Debug)]
pub struct Errors {
    patterns: Vec<Arc<Pattern>>,
    pub stacktrace: bool,
}

pub(crate) fn parse(cursor: &mut Cursor<'_>) -> Result<Errors, Error> {
    let mut patterns = Vec::new();
    let mut stacktrace = false;
    while cursor.next() {
        let args = cursor.remaining_args();
        if args.len() > 1 || args.first().is_some_and(|arg| arg != "stdout") {
            return Err(cursor.arg_err());
        }
        while cursor.next_block() {
            match cursor.val() {
                "stacktrace" => stacktrace = true,
                "consolidate" => {
                    let args = cursor.remaining_args();
                    if !(2..=4).contains(&args.len()) || args[1].len() > 10_000 {
                        return Err(cursor.arg_err());
                    }
                    let period = crate::health::parse_duration(&args[0])
                        .ok_or_else(|| cursor.error("invalid duration"))?;
                    let period_text = if let Some(value) = args[0].strip_prefix('-') {
                        let magnitude = crate::health::parse_duration(value)
                            .unwrap_or(Duration::from_nanos(1_u64 << 63));
                        if magnitude.is_zero() {
                            "0s".to_owned()
                        } else {
                            format!("-{}", display_duration(magnitude))
                        }
                    } else {
                        display_duration(period)
                    };
                    let regex =
                        Regex::new(&args[1]).map_err(|err| cursor.error(err.to_string()))?;
                    let mut level = None;
                    let mut show_first = false;
                    for arg in &args[2..] {
                        if arg == "show_first" {
                            show_first = true;
                        } else {
                            let value = match arg.as_str() {
                                "warning" => "WARNING",
                                "error" => "ERROR",
                                "info" => "INFO",
                                "debug" => "DEBUG",
                                _ => return Err(cursor.error("invalid consolidate option")),
                            };
                            if level.is_some() || show_first {
                                return Err(cursor.error("invalid consolidate option order"));
                            }
                            level = Some(value);
                        }
                    }
                    patterns.push(Arc::new(Pattern {
                        period,
                        period_text,
                        regex,
                        level: level.unwrap_or("ERROR"),
                        show_first,
                        count: AtomicU64::new(0),
                        stop: tokio::sync::watch::channel(false).0,
                    }));
                }
                _ => return Err(cursor.error("unknown errors option")),
            }
        }
    }
    Ok(Errors {
        patterns,
        stacktrace,
    })
}

impl Plugin for Errors {
    async fn serve<N: Next + Send>(&self, cx: &mut Context<'_, '_>, next: N) -> Outcome {
        let outcome = next.run(cx).await;
        if let Outcome::Error(error) = outcome {
            cx.metadata
                .insert(pharos_server::logging::ERROR_LOGGED_METADATA, "true");
            let message = error.to_string();
            let mut level = "ERROR";
            for pattern in &self.patterns {
                if pattern.regex.is_match(&message) {
                    let Ok(previous) =
                        pattern
                            .count
                            .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                                (count != STOPPED).then(|| count.saturating_add(1).min(STOPPED - 1))
                            })
                    else {
                        level = pattern.level;
                        break;
                    };
                    if previous == 0 {
                        let deadline = tokio::time::Instant::now() + pattern.period;
                        let timer_pattern = Arc::clone(pattern);
                        let mut stop = pattern.stop.subscribe();
                        tokio::spawn(async move {
                            if !*stop.borrow() {
                                tokio::select! {
                                    () = tokio::time::sleep_until(deadline) => timer_pattern.flush(false),
                                    _ = stop.changed() => {},
                                }
                            }
                        });
                        if pattern.show_first {
                            level = pattern.level;
                            break;
                        }
                    }
                    return outcome;
                }
            }
            if let Some(question) = cx.query.questions().next() {
                let name = question.name.to_string().to_lowercase();
                pharos_server::logging::log(
                    level,
                    "errors",
                    &format!("2 {name} {}: {message}", question.qtype),
                );
            } else {
                pharos_server::logging::log(level, "errors", &format!("2 . : {message}"));
            }
        }
        outcome
    }
}

const STOPPED: u64 = u64::MAX;

impl Pattern {
    fn flush(&self, stop: bool) {
        let count = if stop {
            self.count.swap(STOPPED, Ordering::Relaxed)
        } else {
            self.count
                .try_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                    (count != STOPPED).then_some(0)
                })
                .unwrap_or(STOPPED)
        };
        if count != STOPPED && count != 0 && (count > 1 || !self.show_first) {
            pharos_server::logging::log(
                self.level,
                "errors",
                &format!(
                    "{count} errors like '{}' occurred in last {}",
                    self.regex.as_str(),
                    self.period_text
                ),
            );
        }
    }
}

impl Errors {
    pub(crate) fn register_shutdown(&self, lifecycle: &mut pharos_server::Lifecycle) {
        let patterns = self.patterns.clone();
        lifecycle.register_sync(pharos_server::Phase::Shutdown, move || {
            for pattern in &patterns {
                pattern.flush(true);
                pattern.stop.send_replace(true);
            }
            Ok(())
        });
    }
}

fn display_duration(duration: Duration) -> String {
    let nanos = duration.as_nanos();
    if nanos == 0 {
        return "0s".to_owned();
    }
    if nanos < 1_000_000_000 {
        let (unit, scale) = if nanos < 1_000 {
            ("ns", 1)
        } else if nanos < 1_000_000 {
            ("µs", 1_000)
        } else {
            ("ms", 1_000_000)
        };
        return decimal(nanos, scale, unit);
    }
    let seconds = nanos / 1_000_000_000;
    let mut out = String::new();
    if seconds >= 3600 {
        out.push_str(&format!("{}h", seconds / 3600));
    }
    if seconds >= 60 {
        out.push_str(&format!("{}m", seconds % 3600 / 60));
    }
    out.push_str(&decimal(nanos % 60_000_000_000, 1_000_000_000, "s"));
    out
}

fn decimal(value: u128, scale: u128, unit: &str) -> String {
    let whole = value / scale;
    let fraction = value % scale;
    if fraction == 0 {
        return format!("{whole}{unit}");
    }
    let width = scale.ilog10() as usize;
    let fraction = format!("{fraction:0width$}");
    format!("{whole}.{}{unit}", fraction.trim_end_matches('0'))
}
