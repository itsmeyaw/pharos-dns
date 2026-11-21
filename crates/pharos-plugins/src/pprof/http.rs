//! Handlers for the `/debug/pprof` endpoints.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use pharos_server::http::{Reply, RouteRequest};

const PREFIX: &str = "/debug/pprof";
const TEXT: &str = "text/plain; charset=utf-8";
const HTML: &str = "text/html; charset=utf-8";
const NOSNIFF: (&str, &str) = ("x-content-type-options", "nosniff");
/// Go net/http/pprof: a profile of this many seconds or more exceeds the 5 s server WriteTimeout.
const WRITE_TIMEOUT_SECONDS: i64 = 5;
/// Go net/http/pprof Profile: the duration used for a missing, unparsable or non-positive `seconds`.
const DEFAULT_SECONDS: i64 = 30;
/// Go runtime/pprof StartCPUProfile samples at 100 Hz.
const FREQUENCY: std::os::raw::c_int = 100;

/// Go runtime/pprof: one CPU profile may run at a time in the whole process.
static CPU_PROFILING: AtomicBool = AtomicBool::new(false);

/// Holds the process-wide CPU profiling slot until dropped.
struct Slot;

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
<tr><td><a href=\"profile?seconds=4\">profile</a></td><td>CPU profile; the <code>seconds</code> parameter must be below 5 (Go's default of 30 exceeds the 5 s write timeout)</td></tr>
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

/// Go net/http/pprof Profile: `seconds` is an i64 where a parse error or a value of at most zero means 30.
fn seconds(query: Option<&str>) -> i64 {
    // shortcut: no percent-decoding of the value, so an escaped number counts as unparsable; upgrade if a client needs it.
    let value = query
        .into_iter()
        .flat_map(|query| query.split('&'))
        .find_map(|pair| pair.strip_prefix("seconds="));
    value
        .and_then(|value| value.parse::<i64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_SECONDS)
}

async fn profile(query: Option<&str>) -> Reply {
    let seconds = seconds(query);
    if seconds >= WRITE_TIMEOUT_SECONDS {
        return text(400, "profile duration exceeds server's WriteTimeout\n");
    }
    // Go runtime/pprof StartCPUProfile: a second concurrent profile fails with this error.
    let Some(slot) = Slot::acquire() else {
        return cpu_error("cpu profiling already in use");
    };
    // Starting the profiler resolves symbols once, which can take long enough to stall a runtime worker.
    let started = tokio::task::spawn_blocking(|| {
        ::pprof::ProfilerGuardBuilder::default()
            .frequency(FREQUENCY)
            .blocklist(&["libc", "libgcc", "pthread", "vdso"])
            .build()
            .map_err(|error| error.to_string())
    })
    .await
    .map_err(|error| error.to_string())
    .and_then(|started| started);
    let guard = match started {
        Ok(guard) => guard,
        Err(error) => return cpu_error(&error),
    };
    tokio::time::sleep(Duration::from_secs(seconds.unsigned_abs())).await;
    // Report building symbolises every frame and encodes the profile, so it stays off the runtime workers.
    let encoded = tokio::task::spawn_blocking(move || {
        use ::pprof::protos::Message;
        let profile = guard.report().build().and_then(|report| report.pprof());
        drop(guard);
        drop(slot);
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
