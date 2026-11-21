//! Handlers for the `/debug/pprof` endpoints.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pharos_server::http::{Reply, RouteRequest};

const PREFIX: &str = "/debug/pprof";
const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";
const NOSNIFF: (&str, &str) = ("x-content-type-options", "nosniff");
/// Go net/http/pprof Profile: the duration used when `seconds` is absent.
const DEFAULT_SECONDS: i64 = 30;
/// Pharos cap on `seconds`; Go has none, but a connection must not stay open without bound.
const MAX_SECONDS: i64 = 300;
/// Connection lifetime of the pprof Listener: the longest profile plus time to build and send it.
pub(crate) const LIFETIME: Duration = Duration::from_secs(330);
/// Go runtime/pprof StartCPUProfile samples at 100 Hz.
const FREQUENCY: std::os::raw::c_int = 100;

/// Go runtime/pprof: one CPU profile may run at a time in the whole process.
static CPU_PROFILING: AtomicBool = AtomicBool::new(false);

/// Holds the process-wide CPU profiling slot until dropped.
struct Slot;

/// A running profiler and the slot it occupies.
struct Running {
    // Fields drop in declaration order: the profiler stops before the slot opens for the next request.
    guard: ::pprof::ProfilerGuard<'static>,
    _slot: Slot,
}

impl Slot {
    fn acquire() -> Option<Self> {
        CPU_PROFILING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| Self)
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        CPU_PROFILING.store(false, Ordering::Release);
    }
}

pub(crate) async fn route(request: RouteRequest) -> Reply {
    let Some(name) = request.path.strip_prefix(PREFIX) else {
        return text(404, "404 page not found\n");
    };
    // Go net/http ServeMux: "/debug/pprof" and the "/debug/pprof/" subtree are the registered patterns.
    if !name.is_empty() && !name.starts_with('/') {
        return text(404, "404 page not found\n");
    }
    if request.method != "GET" {
        // RFC 9110 §9.1: A known resource rejects other recognized methods with 405.
        return Reply {
            status: 405,
            content_type: TEXT,
            headers: vec![("allow", "GET, HEAD")],
            body: Bytes::from_static(b"Method Not Allowed\n"),
        };
    }
    match name {
        // CoreDNS v1.15.0 plugin/pprof/pprof.go: /debug/pprof redirects to /debug/pprof/ with 302.
        "" => Reply {
            status: 302,
            content_type: HTML,
            headers: vec![("location", "/debug/pprof/")],
            body: Bytes::from_static(b"<a href=\"/debug/pprof/\">Found</a>.\n\n"),
        },
        "/" => index(),
        "/cmdline" => cmdline(),
        // Pharos has no symbol table to serve; GET reports zero symbols, as Go does for a binary without any.
        "/symbol" => text(200, "num_symbols: 0\n"),
        "/profile" => profile(request.query.as_deref()).await,
        "/trace" => text(404, "Execution traces are not supported by Pharos\n"),
        // Go net/http/pprof Index: any other profile name is unknown.
        _ => text(404, "Unknown profile\n"),
    }
}

fn text(status: u16, body: &'static str) -> Reply {
    Reply {
        status,
        content_type: TEXT,
        // Go net/http/pprof serveError: error responses carry nosniff.
        headers: vec![NOSNIFF],
        body: Bytes::from_static(body.as_bytes()),
    }
}

fn index() -> Reply {
    // Go net/http/pprof Index: an HTML page listing the profiles the process serves.
    Reply {
        status: 200,
        content_type: HTML,
        headers: vec![NOSNIFF],
        body: Bytes::from_static(INDEX.as_bytes()),
    }
}

const INDEX: &str = "<html>
<head>
<title>/debug/pprof/</title>
</head>
<body>
/debug/pprof/<br>
<br>
Profiles available:
<table>
<thead><td>Profile</td><td>Description</td></thead>
<tr><td><a href=\"profile?seconds=30\">profile</a></td><td>CPU profile; <code>seconds</code> defaults to 30 and may be 1 to 300</td></tr>
<tr><td><a href=\"cmdline\">cmdline</a></td><td>The command line invocation of the current program</td></tr>
<tr><td><a href=\"symbol\">symbol</a></td><td>Symbol lookup; Pharos reports zero symbols because its profiles carry them</td></tr>
</table>
</body>
</html>
";

fn cmdline() -> Reply {
    use std::os::unix::ffi::OsStrExt;
    // Go net/http/pprof Cmdline: the process arguments joined by NUL bytes.
    let mut body = Vec::new();
    for (index, argument) in std::env::args_os().enumerate() {
        if index > 0 {
            body.push(0);
        }
        body.extend_from_slice(argument.as_bytes());
    }
    Reply {
        status: 200,
        content_type: TEXT,
        headers: vec![NOSNIFF],
        body: body.into(),
    }
}

/// Go net/http/pprof Profile: a missing `seconds` means 30; Pharos rejects an unparsable or non-positive value and one above the cap.
fn seconds(query: Option<&str>) -> Result<u64, &'static str> {
    let value = query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .filter_map(|pair| pair.split_once('=').or(Some((pair, ""))))
        // Go net/url ParseQuery: keys and values are percent-decoded; a pair that does not decode is skipped.
        .find_map(|(key, value)| (percent_decode(key)? == "seconds").then(|| percent_decode(value)))
        .map(|value| value.and_then(|value| value.parse::<i64>().ok()));
    match value {
        None => Ok(DEFAULT_SECONDS.unsigned_abs()),
        Some(Some(seconds @ 1..=MAX_SECONDS)) => Ok(seconds.unsigned_abs()),
        Some(Some(seconds)) if seconds > MAX_SECONDS => Err("profile duration too long\n"),
        Some(_) => Err("invalid seconds\n"),
    }
}

/// Go net/url QueryUnescape: `+` is a space and `%XX` is a byte; anything else malformed is rejected.
fn percent_decode(input: &str) -> Option<String> {
    let mut bytes = input.bytes();
    let mut decoded = Vec::with_capacity(input.len());
    while let Some(byte) = bytes.next() {
        decoded.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = char::from(bytes.next()?).to_digit(16)?;
                let low = char::from(bytes.next()?).to_digit(16)?;
                u8::try_from(high * 16 + low).ok()?
            }
            byte => byte,
        });
    }
    String::from_utf8(decoded).ok()
}

async fn profile(query: Option<&str>) -> Reply {
    let seconds = match seconds(query) {
        Ok(seconds) => seconds,
        Err(message) => return text(400, message),
    };
    // Starting the profiler resolves symbols once, which can take long enough to stall a runtime worker.
    // The slot is taken in the same blocking task, so a cancelled request cannot free it while the profiler still runs.
    let started = tokio::task::spawn_blocking(|| {
        // Go runtime/pprof StartCPUProfile: a second concurrent profile fails with this error.
        let slot = Slot::acquire().ok_or_else(|| "cpu profiling already in use".to_owned())?;
        let guard = ::pprof::ProfilerGuardBuilder::default()
            .frequency(FREQUENCY)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|error| error.to_string())?;
        Ok::<_, String>(Running { guard, _slot: slot })
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|started| started);
    let running = match started {
        Ok(running) => running,
        Err(error) => return cpu_error(&error),
    };
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    // Report building symbolises every frame and encodes the profile, so it stays off the runtime workers.
    let encoded = tokio::task::spawn_blocking(move || {
        use ::pprof::protos::Message;
        let profile = running
            .guard
            .report()
            .build()
            .and_then(|report| report.pprof());
        drop(running);
        profile
            .map_err(|error| error.to_string())
            .and_then(|profile| profile.write_to_bytes().map_err(|error| error.to_string()))
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|encoded| encoded);
    match encoded {
        Ok(body) => Reply {
            status: 200,
            // Go net/http/pprof Profile: an opaque attachment named `profile`.
            content_type: "application/octet-stream",
            headers: vec![
                NOSNIFF,
                ("content-disposition", "attachment; filename=\"profile\""),
            ],
            body: body.into(),
        },
        Err(error) => cpu_error(&error),
    }
}

fn cpu_error(error: &str) -> Reply {
    // Go net/http/pprof Profile: StartCPUProfile failures are 500 with this prefix.
    Reply {
        status: 500,
        content_type: TEXT,
        headers: vec![NOSNIFF],
        body: format!("Could not enable CPU profiling: {error}\n").into(),
    }
}

#[cfg(test)]
mod tests {
    use super::{percent_decode, seconds};

    #[test]
    fn missing_seconds_means_the_go_default_of_30() {
        // Go net/http/pprof Profile: `go tool pprof` sends no `seconds`, which profiles for 30 s.
        assert_eq!(seconds(None), Ok(30));
        assert_eq!(seconds(Some("")), Ok(30));
        assert_eq!(seconds(Some("debug=1&x=seconds")), Ok(30));
    }

    #[test]
    fn seconds_is_percent_decoded_and_bounded() {
        assert_eq!(seconds(Some("seconds=1")), Ok(1));
        assert_eq!(seconds(Some("a=b&seconds=%31%30")), Ok(10));
        assert_eq!(seconds(Some("%73econds=2")), Ok(2));
        assert_eq!(seconds(Some("seconds=300")), Ok(300));
        assert_eq!(
            seconds(Some("seconds=301")),
            Err("profile duration too long\n")
        );
        assert_eq!(
            seconds(Some("seconds=99999999999999999999")),
            Err("invalid seconds\n")
        );
        for query in [
            "seconds=",
            "seconds",
            "seconds=abc",
            "seconds=0",
            "seconds=-3",
            "seconds=%zz",
            "seconds=1.5",
        ] {
            assert_eq!(seconds(Some(query)), Err("invalid seconds\n"), "{query}");
        }
    }

    #[test]
    fn percent_decode_follows_query_unescape() {
        assert_eq!(percent_decode("a+b%20c").as_deref(), Some("a b c"));
        assert_eq!(percent_decode("%4"), None);
        assert_eq!(percent_decode("%g0"), None);
        assert_eq!(percent_decode("%ff"), None);
    }
}
