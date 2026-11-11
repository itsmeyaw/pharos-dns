#[cfg(target_os = "linux")]
pub(crate) fn encode_process(out: &mut String) {
    use std::fs;

    let stat = fs::read_to_string("/proc/self/stat").ok();
    let status = fs::read_to_string("/proc/self/status").ok();
    let limits = fs::read_to_string("/proc/self/limits").ok();
    let boot = fs::read_to_string("/proc/stat").ok();
    let fds = fs::read_dir("/proc/self/fd").ok().and_then(|entries| {
        entries
            .into_iter()
            .try_fold(0usize, |count, entry| entry.map(|_| count + 1))
            .ok()
    });
    encode_from(
        out,
        stat.as_deref(),
        status.as_deref(),
        limits.as_deref(),
        boot.as_deref(),
        fds,
    );
}

// shortcut: other macOS process metrics need OS APIs, add a safe collector when available.
#[cfg(target_os = "macos")]
pub(crate) fn encode_process(out: &mut String) {
    use std::fmt::Write;

    if let Ok(entries) = std::fs::read_dir("/dev/fd") {
        let count = entries.count().saturating_sub(1);
        let _ = write!(
            out,
            "# HELP process_open_fds Number of open file descriptors.\n# TYPE process_open_fds gauge\nprocess_open_fds {count}\n"
        );
    }
}

// shortcut: process metrics are omitted on other platforms until a safe collector exists.
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn encode_process(_out: &mut String) {}

#[cfg(any(target_os = "linux", test))]
fn encode_from(
    out: &mut String,
    stat: Option<&str>,
    status: Option<&str>,
    limits: Option<&str>,
    boot: Option<&str>,
    fds: Option<usize>,
) {
    use std::fmt::Write;

    fn metric<'a>(
        samples: &mut Vec<(&'a str, &'a str, &'a str, f64)>,
        name: &'a str,
        help: &'a str,
        kind: &'a str,
        value: f64,
    ) {
        samples.push((name, help, kind, value));
    }
    let mut samples = Vec::new();

    // shortcut: USER_HZ=100 matches Go procfs; discover it if supporting exotic Linux targets.
    let fields: Vec<_> = stat
        .and_then(|s| {
            s.find('(')
                .zip(s.rfind(')'))
                .filter(|(l, r)| l < r)
                .map(|(_, r)| &s[r + 1..])
        })
        .unwrap_or("")
        .split_whitespace()
        .collect();
    let field = |index: usize| fields.get(index).and_then(|v| v.parse::<u64>().ok());
    if let Some((user, system)) = field(11).zip(field(12)) {
        metric(
            &mut samples,
            "process_cpu_seconds_total",
            "Total user and system CPU time spent in seconds.",
            "counter",
            (user as f64 + system as f64) / 100.0,
        );
    }
    if let Some(value) = fds {
        metric(
            &mut samples,
            "process_open_fds",
            "Number of open file descriptors.",
            "gauge",
            value as f64,
        );
    }
    let max_fds = limits.and_then(|s| {
        s.lines().find_map(|line| {
            let value = line
                .strip_prefix("Max open files")?
                .split_whitespace()
                .next()?;
            if value == "unlimited" {
                Some(u64::MAX)
            } else {
                value.parse::<u64>().ok()
            }
        })
    });
    if let Some(value) = max_fds {
        metric(
            &mut samples,
            "process_max_fds",
            "Maximum number of open file descriptors.",
            "gauge",
            value as f64,
        );
    }
    let rss = status.and_then(|s| {
        s.lines().find_map(|line| {
            let mut parts = line.strip_prefix("VmRSS:")?.split_whitespace();
            let kb = parts.next()?.parse::<u64>().ok()?;
            (parts.next()? == "kB")
                .then(|| kb.checked_mul(1024))
                .flatten()
        })
    });
    if let Some(value) = rss {
        metric(
            &mut samples,
            "process_resident_memory_bytes",
            "Resident memory size in bytes.",
            "gauge",
            value as f64,
        );
    }
    if let Some(value) = field(20) {
        metric(
            &mut samples,
            "process_virtual_memory_bytes",
            "Virtual memory size in bytes.",
            "gauge",
            value as f64,
        );
    }
    let boot_time = boot.and_then(|s| {
        s.lines()
            .find_map(|line| line.strip_prefix("btime ")?.trim().parse::<u64>().ok())
    });
    if let Some((ticks, boot_time)) = field(19).zip(boot_time) {
        metric(
            &mut samples,
            "process_start_time_seconds",
            "Start time of the process since unix epoch in seconds.",
            "gauge",
            boot_time as f64 + ticks as f64 / 100.0,
        );
    }
    samples.sort_unstable_by_key(|(name, _, _, _)| *name);
    for (name, help, kind, value) in samples {
        let value = crate::metrics::float(value);
        let _ = write!(
            out,
            "# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAT: &str =
        "42 (name with ) and spaces) S 1 2 3 4 5 6 7 8 9 10 150 250 0 0 0 0 1 0 1234 5678 9";

    #[test]
    fn encodes_go_compatible_metadata_and_values() {
        let mut out = String::from("prefix\n");
        encode_from(
            &mut out,
            Some(STAT),
            Some("Name:\ttest\nVmRSS:\t 42 kB\n"),
            Some("Max open files            1024  4096  files\n"),
            Some("cpu 0 0 0\nbtime 1000\n"),
            Some(5),
        );
        let actual: std::collections::BTreeSet<_> = out
            .lines()
            .filter_map(|line| line.strip_prefix("# TYPE "))
            .filter_map(|line| line.split_whitespace().next())
            .collect();
        let documented: std::collections::BTreeSet<_> = include_str!("../../../MIGRATION.md")
            .lines()
            .filter_map(|line| line.strip_prefix("| `process_"))
            .filter_map(|line| line.split_once('`').map(|(name, _)| name))
            .map(|name| format!("process_{name}"))
            .collect();
        assert_eq!(actual, documented.iter().map(String::as_str).collect());
        assert_eq!(
            out,
            concat!(
                "prefix\n",
                "# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.\n# TYPE process_cpu_seconds_total counter\nprocess_cpu_seconds_total 4\n",
                "# HELP process_max_fds Maximum number of open file descriptors.\n# TYPE process_max_fds gauge\nprocess_max_fds 1024\n",
                "# HELP process_open_fds Number of open file descriptors.\n# TYPE process_open_fds gauge\nprocess_open_fds 5\n",
                "# HELP process_resident_memory_bytes Resident memory size in bytes.\n# TYPE process_resident_memory_bytes gauge\nprocess_resident_memory_bytes 43008\n",
                "# HELP process_start_time_seconds Start time of the process since unix epoch in seconds.\n# TYPE process_start_time_seconds gauge\nprocess_start_time_seconds 1012.34\n",
                "# HELP process_virtual_memory_bytes Virtual memory size in bytes.\n# TYPE process_virtual_memory_bytes gauge\nprocess_virtual_memory_bytes 5678\n",
            )
        );
    }

    #[test]
    fn omits_unavailable_and_invalid_values_independently() {
        let mut out = String::new();
        encode_from(
            &mut out,
            Some("bad stat"),
            Some("VmRSS: invalid kB"),
            Some("Max open files unlimited unlimited files"),
            None,
            Some(3),
        );
        assert_eq!(
            out,
            concat!(
                "# HELP process_max_fds Maximum number of open file descriptors.\n# TYPE process_max_fds gauge\nprocess_max_fds 1.8446744073709552e+19\n",
                "# HELP process_open_fds Number of open file descriptors.\n# TYPE process_open_fds gauge\nprocess_open_fds 3\n",
            )
        );
    }

    #[test]
    fn missing_boot_time_does_not_hide_other_stat_values() {
        let mut out = String::new();
        encode_from(&mut out, Some(STAT), None, None, None, None);
        assert!(out.contains("process_cpu_seconds_total 4\n"));
        assert!(out.contains("process_virtual_memory_bytes 5678\n"));
        assert!(!out.contains("process_start_time_seconds"));
    }

    #[test]
    fn malformed_fields_do_not_hide_other_metrics() {
        let stat = STAT.replace("150 250", "bad 250");
        let mut out = String::new();
        encode_from(
            &mut out,
            Some(&stat),
            Some("VmRSS: 18446744073709551615 kB"),
            Some("Max open files 7 9 files"),
            Some("btime 1000"),
            None,
        );
        assert!(!out.contains("process_cpu_seconds_total"));
        assert!(!out.contains("process_resident_memory_bytes"));
        assert!(out.contains("process_max_fds 7\n"));
        assert!(out.contains("process_virtual_memory_bytes 5678\n"));
        assert!(out.contains("process_start_time_seconds 1012.34\n"));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn reads_live_proc_metrics() {
        let mut out = String::new();
        encode_process(&mut out);
        for name in [
            "process_cpu_seconds_total",
            "process_open_fds",
            "process_max_fds",
            "process_resident_memory_bytes",
            "process_virtual_memory_bytes",
            "process_start_time_seconds",
        ] {
            assert!(out.contains(&format!("\n{name} ")), "missing {name}: {out}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn reads_live_open_files() {
        let mut out = String::new();
        encode_process(&mut out);
        assert!(out.contains("process_open_fds "));
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_platform_appends_nothing() {
        let mut out = String::from("prefix");
        encode_process(&mut out);
        assert_eq!(out, "prefix");
    }
}
