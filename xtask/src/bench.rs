use std::{
    fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use crate::differential;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

pub(crate) fn run(root: &Path, args: &[String]) -> Result<(), String> {
    let options = Options::parse(args)?;
    let common = Command::new("git")
        .args(["rev-parse", "--git-common-dir"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !common.status.success() {
        return Err(format!(
            "git rev-parse: {}",
            String::from_utf8_lossy(&common.stderr)
        ));
    }
    let common = root.join(
        String::from_utf8(common.stdout)
            .map_err(|e| e.to_string())?
            .trim(),
    );
    let mut micro = Command::new("cargo");
    micro
        .current_dir(root)
        .args(["bench", "--workspace", "--bench", "*", "--"])
        .env("CRITERION_HOME", common.join("pharos-criterion"));
    if let Some(name) = &options.baseline {
        micro.args(["--baseline", name]);
    }
    if let Some(name) = &options.save_baseline {
        micro.args(["--save-baseline", name]);
    }
    let status = micro
        .status()
        .map_err(|e| format!("starting cargo bench: {e}"))?;
    if !status.success() {
        return Err(format!("cargo bench failed: {status}"));
    }
    match Command::new("dnsperf")
        .arg("-h")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Err(e) if e.kind() == ErrorKind::NotFound => {
            println!(
                "dnsperf not found: brew install dnsperf (macOS) or apt install dnsperf (Debian/Ubuntu)"
            );
            return Ok(());
        }
        Err(e) => return Err(format!("starting dnsperf: {e}")),
        Ok(_) => {}
    }
    let status = Command::new("cargo")
        .args(["build", "--release", "-p", "pharos-dns"])
        .current_dir(root)
        .status()
        .map_err(|e| format!("building Pharos: {e}"))?;
    if !status.success() {
        return Err(format!("building Pharos failed: {status}"));
    }
    let directory = root.join("target/bench");
    fs::create_dir_all(&directory).map_err(|e| e.to_string())?;
    let queries = directory.join("queries.txt");
    fs::write(
        &queries,
        "example.org. A\nexample.net. AAAA\nwww.example.com. TXT\n",
    )
    .map_err(|e| e.to_string())?;
    let (corefile, cwd) = if let Some(path) = &options.corefile {
        let path = path
            .canonicalize()
            .map_err(|e| format!("{}: {e}", path.display()))?;
        (
            fs::read_to_string(&path).map_err(|e| e.to_string())?,
            path.parent().unwrap().to_path_buf(),
        )
    } else {
        (".:{port} {\n    whoami\n}\n".to_owned(), root.to_path_buf())
    };
    let pharos = measure(
        "pharos",
        &root.join("target/release/pharos"),
        true,
        &cwd,
        &corefile,
        &directory,
        &queries,
    )?;
    let coredns = root.join("target/coredns/v1.15.0/coredns");
    let mut rows = vec![("Pharos", pharos)];
    if coredns.is_file() {
        let result = measure(
            "coredns", &coredns, false, &cwd, &corefile, &directory, &queries,
        )?;
        rows.push(("CoreDNS", result));
    } else {
        println!("CoreDNS not cached; skipping informational comparison");
    }
    print!("{}", table(&rows));
    let baselines = common.join("pharos-bench");
    if let Some(name) = options.save_baseline {
        fs::create_dir_all(&baselines).map_err(|e| e.to_string())?;
        fs::write(baselines.join(&name), encode_baseline(&pharos))
            .map_err(|e| format!("saving baseline {name}: {e}"))?;
        println!("saved baseline {name}");
    }
    if let Some(name) = options.baseline {
        let baseline = fs::read_to_string(baselines.join(&name))
            .map_err(|e| format!("reading baseline {name}: {e}"))?;
        let changes = regressions(&decode_baseline(&baseline)?, &pharos);
        if !changes.is_empty() {
            return Err(format!(
                "REGRESSION against {name}: {} exceeds 5%",
                changes.join(", ")
            ));
        }
        println!("no regression against {name}");
    }
    Ok(())
}

fn measure(
    name: &str,
    binary: &Path,
    pharos: bool,
    cwd: &Path,
    corefile: &str,
    directory: &Path,
    queries: &Path,
) -> Result<Metrics, String> {
    let port = differential::free_port()?;
    let conf = TemporaryCorefile::new(cwd, corefile, port)?;
    let log = directory.join(format!("{name}.server.log"));
    let mut server =
        differential::start_with_config(binary, cwd, port, Some(&conf.0), &log, pharos)?;
    differential::ready(&mut server, &log, port)?;
    let out = directory.join(format!("{name}.dnsperf.out"));
    let err = directory.join(format!("{name}.dnsperf.err"));
    let mut child = Command::new("dnsperf")
        .args(["-s", "127.0.0.1", "-p", &port.to_string(), "-d"])
        .arg(queries)
        .args(["-l", "10", "-O", "latency-histogram"])
        // dnsperf defaults to one socket and 100 Queries in flight; 16 source ports
        // let Linux SO_REUSEPORT spread Queries across Pharos UDP sockets.
        .args(["-c", "16", "-T", "4", "-q", "256"])
        .stdout(fs::File::create(&out).map_err(|e| e.to_string())?)
        .stderr(fs::File::create(&err).map_err(|e| e.to_string())?)
        .spawn()
        .map_err(|e| format!("starting dnsperf: {e}"))?;
    let mut peak = 0;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                if !status.success() {
                    return Err(format!(
                        "dnsperf failed: {status}\n{}",
                        fs::read_to_string(err).unwrap_or_default()
                    ));
                }
                break;
            }
            Ok(None) => {}
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("waiting for dnsperf: {e}"));
            }
        }
        let sample = Command::new("ps")
            .args(["-o", "rss=", "-p", &server.id().to_string()])
            .output();
        let rss = sample
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u64>().ok())
            .filter(|n| *n > 0);
        match rss {
            Some(rss) => peak = peak.max(rss),
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("could not sample RSS for {name}"));
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if peak == 0 {
        return Err(format!("dnsperf ended before RSS was sampled for {name}"));
    }
    parse_dnsperf(&fs::read_to_string(out).map_err(|e| e.to_string())?, peak)
}

static NEXT_COREFILE: AtomicUsize = AtomicUsize::new(0);

struct TemporaryCorefile(PathBuf);

impl TemporaryCorefile {
    fn new(directory: &Path, corefile: &str, port: u16) -> Result<Self, String> {
        loop {
            let path = directory.join(format!(
                ".pharos-bench-{}-{}",
                std::process::id(),
                NEXT_COREFILE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            options.mode(0o600);
            match options.open(&path) {
                Ok(mut file) => {
                    let temporary = Self(path);
                    file.write_all(corefile.replace("{port}", &port.to_string()).as_bytes())
                        .map_err(|e| e.to_string())?;
                    return Ok(temporary);
                }
                Err(e) if e.kind() == ErrorKind::AlreadyExists => continue,
                Err(e) => {
                    return Err(format!(
                        "creating temporary Corefile in {}: {e}",
                        directory.display()
                    ));
                }
            }
        }
    }
}

impl Drop for TemporaryCorefile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

#[derive(Default)]
struct Options {
    baseline: Option<String>,
    save_baseline: Option<String>,
    corefile: Option<PathBuf>,
}

impl Options {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut options = Self::default();
        let mut args = args.iter();
        while let Some(flag) = args.next() {
            let value = args
                .next()
                .ok_or_else(|| format!("missing value for {flag}"))?;
            match flag.as_str() {
                "--baseline" if options.baseline.is_none() => {
                    baseline_name(value)?;
                    options.baseline = Some(value.clone());
                }
                "--save-baseline" if options.save_baseline.is_none() => {
                    baseline_name(value)?;
                    options.save_baseline = Some(value.clone());
                }
                "--corefile" if options.corefile.is_none() => options.corefile = Some(value.into()),
                _ => return Err(format!("unknown or repeated option: {flag}")),
            }
        }
        if options.baseline.is_some() && options.save_baseline.is_some() {
            return Err("choose --baseline or --save-baseline".into());
        }
        Ok(options)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
struct Metrics {
    qps: f64,
    p50: f64,
    p99: f64,
    rss: u64,
}

fn table(rows: &[(&str, Metrics)]) -> String {
    let mut text = format!(
        "{:<12} {:>9} {:>11} {:>11} {:>15}\n",
        "server", "QPS", "p50 (ms)", "p99 (ms)", "peak RSS (KiB)"
    );
    for (name, m) in rows {
        text.push_str(&format!(
            "{:<12} {:>9.2} {:>11.3} {:>11.3} {:>15}\n",
            name,
            m.qps,
            m.p50 * 1000.0,
            m.p99 * 1000.0,
            m.rss
        ));
    }
    text
}

fn regressions(baseline: &Metrics, current: &Metrics) -> Vec<&'static str> {
    let mut result = Vec::new();
    // One ULP avoids classifying an exactly 5% decimal change as a regression.
    if current.qps < (baseline.qps * 0.95).next_down() {
        result.push("QPS");
    }
    if current.p99 > (baseline.p99 * 1.05).next_up() {
        result.push("p99");
    }
    if u128::from(current.rss) * 100 > u128::from(baseline.rss) * 105 {
        result.push("RSS");
    }
    result
}

fn baseline_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_'))
    {
        return Err("baseline name must contain only letters, digits, '-' or '_'".into());
    }
    Ok(())
}

fn encode_baseline(m: &Metrics) -> String {
    format!("{} {} {} {}\n", m.qps, m.p50, m.p99, m.rss)
}

fn decode_baseline(input: &str) -> Result<Metrics, String> {
    let fields: Vec<_> = input.split_whitespace().collect();
    if fields.len() != 4 {
        return Err("invalid baseline".into());
    }
    let number = |field: &str| {
        field
            .parse::<f64>()
            .ok()
            .filter(|n| n.is_finite() && *n >= 0.0)
            .ok_or("invalid baseline")
    };
    let metrics = Metrics {
        qps: number(fields[0])?,
        p50: number(fields[1])?,
        p99: number(fields[2])?,
        rss: fields[3].parse().map_err(|_| "invalid baseline")?,
    };
    if metrics.qps == 0.0 || metrics.rss == 0 {
        return Err("invalid baseline".into());
    }
    Ok(metrics)
}

// dnsperf 2.16 prints inclusive histogram bounds in seconds; use the upper
// bound of the nearest-rank bucket: https://codeberg.org/DNS-OARC/dnsperf/src/tag/v2.16.0/src/dnsperf.c
fn parse_dnsperf(output: &str, rss: u64) -> Result<Metrics, String> {
    let mut qps = None;
    let mut completed = None;
    let mut minimum = None;
    let mut in_histogram = false;
    let mut buckets = Vec::new();
    for line in output.lines().map(str::trim) {
        if let Some(value) = line.strip_prefix("Queries per second:") {
            qps = value.trim().parse::<f64>().ok();
        } else if let Some(value) = line.strip_prefix("Queries completed:") {
            completed = value
                .split_whitespace()
                .next()
                .and_then(|v| v.parse::<u64>().ok());
        } else if let Some(value) = line.strip_prefix("Average Latency (s):") {
            minimum = value
                .split_once("(min ")
                .and_then(|(_, value)| value.split_once(','))
                .and_then(|(v, _)| v.parse::<f64>().ok());
        } else if line == "Latency bucket (s):   answer count" {
            in_histogram = true;
        } else if in_histogram {
            let Some((range, count)) = line.split_once(':') else {
                in_histogram = false;
                continue;
            };
            let Some((lower, upper)) = range.split_once(" - ") else {
                return Err("invalid dnsperf histogram".into());
            };
            let (lower, upper, count) = (
                lower.parse::<f64>(),
                upper.parse::<f64>(),
                count.trim().parse::<u64>(),
            );
            match (lower, upper, count) {
                (Ok(lower), Ok(upper), Ok(count))
                    if lower.is_finite()
                        && upper.is_finite()
                        && lower >= 0.0
                        && upper >= lower
                        && count > 0 =>
                {
                    buckets.push((upper, count))
                }
                _ => return Err("invalid dnsperf histogram".into()),
            }
        }
    }
    let completed = completed
        .filter(|n| *n > 0)
        .ok_or("dnsperf returned no completed Queries")?;
    let qps = qps
        .filter(|n| n.is_finite() && *n > 0.0)
        .ok_or("dnsperf did not report QPS")?;
    let (p50, p99) = if completed == 1 {
        let value = minimum
            .filter(|v| v.is_finite() && *v >= 0.0)
            .ok_or("dnsperf did not report minimum latency")?;
        (value, value)
    } else {
        if buckets.iter().map(|(_, n)| u128::from(*n)).sum::<u128>() != u128::from(completed)
            || buckets.windows(2).any(|w| w[0].0 > w[1].0)
        {
            return Err("dnsperf histogram missing or incomplete".into());
        }
        let percentile = |p: u128| {
            let rank = (u128::from(completed) * p).div_ceil(100);
            let mut sum = 0;
            buckets
                .iter()
                .find_map(|(upper, n)| {
                    sum += u128::from(*n);
                    (sum >= rank).then_some(*upper)
                })
                .unwrap()
        };
        (percentile(50), percentile(99))
    };
    Ok(Metrics { qps, p50, p99, rss })
}

#[cfg(test)]
mod tests {
    use super::{
        Metrics, Options, TemporaryCorefile, baseline_name, decode_baseline, encode_baseline,
        parse_dnsperf, regressions, table,
    };

    fn reference() -> Metrics {
        Metrics {
            qps: 1000.0,
            p50: 0.001,
            p99: 0.010,
            rss: 10000,
        }
    }

    #[test]
    fn table_displays_metrics_and_units() {
        assert_eq!(
            table(&[("Pharos", reference())]),
            "server             QPS    p50 (ms)    p99 (ms)  peak RSS (KiB)\nPharos         1000.00       1.000      10.000           10000\n"
        );
    }

    #[test]
    fn regression_requires_more_than_five_percent() {
        let baseline = reference();
        assert!(
            regressions(
                &baseline,
                &Metrics {
                    qps: 950.0,
                    p99: 0.0105,
                    rss: 10500,
                    ..baseline
                }
            )
            .is_empty()
        );
        assert_eq!(
            regressions(
                &baseline,
                &Metrics {
                    qps: 949.0,
                    p99: 0.0106,
                    rss: 10501,
                    ..baseline
                }
            ),
            vec!["QPS", "p99", "RSS"]
        );
        assert!(
            regressions(
                &baseline,
                &Metrics {
                    qps: 1100.0,
                    p99: 0.009,
                    rss: 9000,
                    ..baseline
                }
            )
            .is_empty()
        );
        let micros = Metrics {
            p99: 0.000260,
            ..baseline
        };
        assert!(
            regressions(
                &micros,
                &Metrics {
                    p99: 0.000273,
                    ..micros
                }
            )
            .is_empty()
        );
    }

    #[test]
    fn baseline_round_trip_and_validation() {
        let metrics = reference();
        assert_eq!(
            decode_baseline(&encode_baseline(&metrics)).unwrap(),
            metrics
        );
        for input in [
            "",
            "0 1 2 3",
            "NaN 1 2 3",
            "1000 -1 2 3",
            "1000 1 2 3 extra",
        ] {
            assert!(decode_baseline(input).is_err(), "{input}");
        }
        assert!(baseline_name("main-1").is_ok());
        for name in ["", "..", "../main", "/tmp/main", "."] {
            assert!(baseline_name(name).is_err(), "{name}");
        }
    }

    #[test]
    fn parses_dnsperf_216_histogram_and_single_response() {
        // Format from https://codeberg.org/DNS-OARC/dnsperf/src/tag/v2.16.0/src/dnsperf.c (print_statistics/print_histogram).
        let output = "Statistics:\n\n  Queries sent:         102\n  Queries completed:    100 (98.04%)\n  Queries lost:         2 (1.96%)\n\n  Queries per second:   1234.500000\n\n  Average Latency (s):  0.001000 (min 0.000100, max 0.004000)\n  Latency StdDev (s):   0.001000\n  Latency bucket (s):   answer count\n  0.000100 - 0.000199:  50\n  0.001000 - 0.001099:  48\n  0.004000 - 0.004099:  2\n";
        assert_eq!(
            parse_dnsperf(output, 123).unwrap(),
            Metrics {
                qps: 1234.5,
                p50: 0.000199,
                p99: 0.004099,
                rss: 123
            }
        );
        let single = "  Queries completed:    1 (100.00%)\n  Queries per second:   1.000000\n  Average Latency (s):  0.001000 (min 0.001000, max 0.001000)\n";
        assert_eq!(parse_dnsperf(single, 123).unwrap().p99, 0.001);
        assert!(parse_dnsperf(&output.replace("  0.004000 - 0.004099:  2\n", ""), 123).is_err());
        assert!(
            parse_dnsperf(
                "  Queries completed: 0 (0.00%)\n  Queries per second: 0.000000\n",
                123
            )
            .is_err()
        );
    }

    #[test]
    fn command_line_validates_baselines_and_corefile() {
        let args = ["--baseline", "main", "--corefile", "Corefile"].map(str::to_owned);
        let options = Options::parse(&args).unwrap();
        assert_eq!(options.baseline.as_deref(), Some("main"));
        assert_eq!(
            options.corefile.as_deref(),
            Some(std::path::Path::new("Corefile"))
        );
        for args in [
            vec!["--baseline"],
            vec!["--baseline", "../main"],
            vec!["--save-baseline", "a", "--baseline", "b"],
            vec!["--unknown"],
        ] {
            assert!(
                Options::parse(&args.into_iter().map(str::to_owned).collect::<Vec<_>>()).is_err()
            );
        }
    }

    #[test]
    fn corefile_copy_preserves_relative_imports_without_overwriting() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
            "../target/bench-corefile-test-{}",
            std::process::id()
        ));
        std::fs::create_dir(&dir).unwrap();
        let original = dir.join("Corefile");
        std::fs::write(&original, "original").unwrap();
        let path;
        {
            let conf =
                TemporaryCorefile::new(&dir, ".:{port} {\n import sibling\n}\n", 1234).unwrap();
            path = conf.0.clone();
            assert_eq!(path.parent().unwrap(), dir);
            assert!(std::fs::read_to_string(&path).unwrap().contains(":1234"));
            assert_eq!(std::fs::read_to_string(&original).unwrap(), "original");
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                assert_eq!(
                    std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
                    0
                );
            }
        }
        assert!(!path.exists());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
