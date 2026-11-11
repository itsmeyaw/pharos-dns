use std::{
    collections::hash_map::DefaultHasher,
    fs,
    hash::{Hash, Hasher},
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    time::{Duration, Instant, SystemTime},
};

use pharos_proto::{Message, Rdata};

use crate::{
    compare,
    query::{self, Transport},
};

#[derive(Default)]
struct Expect {
    ttl: u32,
    mask_srv_port: bool,
    mask_soa_serial: bool,
    dedupe_additional: bool,
    deviations: Vec<(String, u16, u16)>,
}

fn parse_expect(input: &str, docs: &str) -> Result<Expect, String> {
    let mut expect = Expect::default();
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let (key, value) = line
            .split_once(' ')
            .ok_or_else(|| format!("invalid expectation: {line}"))?;
        let value = value.trim();
        match key {
            "ttl" => expect.ttl = value.parse().map_err(|_| format!("invalid TTL: {value}"))?,
            "mask" if value == "additional.srv.port" => expect.mask_srv_port = true,
            "mask" if value == "soa.serial" => expect.mask_soa_serial = true,
            "mask" if value == "additional.duplicates" => expect.dedupe_additional = true,
            "deviation" => {
                let parts: Vec<_> = value.split('|').map(str::trim).collect();
                let heading = parts[0];
                if !docs.lines().any(|line| {
                    line.strip_prefix("## ")
                        .is_some_and(|text| text.trim() == heading)
                }) {
                    return Err(format!("undocumented deviation heading: {heading}"));
                }
                // shortcut: only header flags can differ, add fields when a documented scenario needs them.
                if parts.len() == 3 {
                    let flags = parts[2]
                        .strip_prefix("flags=")
                        .and_then(|s| s.split_once(':'))
                        .ok_or_else(|| format!("invalid deviation: {value}"))?;
                    let parse = |s: &str| {
                        u16::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)
                            .map_err(|_| format!("invalid flags: {s}"))
                    };
                    if parts[1].is_empty() {
                        return Err(format!("invalid deviation: {value}"));
                    }
                    expect
                        .deviations
                        .push((parts[1].to_owned(), parse(flags.0)?, parse(flags.1)?));
                } else if parts.len() != 1 {
                    return Err(format!("invalid deviation: {value}"));
                }
            }
            _ => return Err(format!("unknown expectation: {line}")),
        }
    }
    Ok(expect)
}

fn apply_deviation(
    expect: &Expect,
    query: &str,
    pharos: &mut [u8],
    coredns: &[u8],
) -> Result<(), String> {
    if pharos.len() < 4 || coredns.len() < 4 {
        return Err("truncated Response header".into());
    }
    let flags = |wire: &[u8]| u16::from_be_bytes([wire[2], wire[3]]);
    if expect.deviations.iter().any(|(name, left, right)| {
        name == query && *left == flags(pharos) && *right == flags(coredns)
    }) {
        pharos[2..4].copy_from_slice(&coredns[2..4]);
    }
    Ok(())
}

static NEXT_TEMP: AtomicUsize = AtomicUsize::new(0);
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Result<Self, String> {
        let path = std::env::temp_dir().join(format!(
            "pharos-diff-{}-{}",
            std::process::id(),
            NEXT_TEMP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        Ok(Self(path))
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

pub(crate) struct Server(Child);
impl Server {
    pub(crate) fn id(&self) -> u32 {
        self.0.id()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = Command::new("kill")
                .args(["-TERM", &self.0.id().to_string()])
                .status();
            let deadline = Instant::now() + Duration::from_secs(3);
            while Instant::now() < deadline {
                if !matches!(self.0.try_wait(), Ok(None)) {
                    return;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            let _ = self.0.kill();
        }
        let _ = self.0.wait();
    }
}

// shortcut: another process can bind the port before startup; pass bound sockets to servers when supported.
pub(crate) fn free_port() -> Result<u16, String> {
    reserve_port()?.port()
}

struct ReservedPort {
    tcp: TcpListener,
    _udp: UdpSocket,
}

impl ReservedPort {
    fn port(&self) -> Result<u16, String> {
        self.tcp
            .local_addr()
            .map(|addr| addr.port())
            .map_err(|e| e.to_string())
    }
}

fn reserve_port() -> Result<ReservedPort, String> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let ipv6_tcp = TcpListener::bind("[::]:0").is_ok();
    let ipv6_udp = UdpSocket::bind("[::]:0").is_ok();
    for _ in 0..1000 {
        let mut hash = DefaultHasher::new();
        std::process::id().hash(&mut hash);
        NEXT.fetch_add(1, Ordering::Relaxed).hash(&mut hash);
        SystemTime::now().hash(&mut hash);
        // Stay below the default ephemeral ranges on macOS and Linux.
        let port = 10_000 + (hash.finish() % 22_768) as u16;
        if (ipv6_tcp && TcpListener::bind(("::", port)).is_err())
            || (ipv6_udp && UdpSocket::bind(("::", port)).is_err())
        {
            continue;
        }
        if let Ok(tcp) = TcpListener::bind(("0.0.0.0", port))
            && let Ok(udp) = UdpSocket::bind(("0.0.0.0", port))
        {
            return Ok(ReservedPort { tcp, _udp: udp });
        }
    }
    Err("could not find a free server port after 1000 attempts".into())
}

fn copy_fixtures(source: &Path, target: &Path) -> Result<(), String> {
    copy_fixture_dir(source, target, true)
}

fn copy_fixture_dir(source: &Path, target: &Path, scenario_root: bool) -> Result<(), String> {
    fs::create_dir_all(target).map_err(|e| e.to_string())?;
    for entry in fs::read_dir(source).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        if scenario_root && matches!(name.to_str(), Some("Corefile" | "queries" | "expect")) {
            continue;
        }
        let kind = entry.file_type().map_err(|e| e.to_string())?;
        if kind.is_dir() {
            copy_fixture_dir(&entry.path(), &target.join(name), false)?;
        } else if kind.is_file() {
            fs::copy(entry.path(), target.join(name)).map_err(|e| e.to_string())?;
        } else {
            return Err(format!("unsupported fixture: {}", entry.path().display()));
        }
    }
    Ok(())
}

fn start(
    binary: &Path,
    cwd: &Path,
    port: u16,
    port2: u16,
    metrics_port: u16,
    corefile: Option<&str>,
    pharos: bool,
) -> Result<Server, String> {
    let conf = if let Some(corefile) = corefile {
        let conf = cwd.join("Corefile");
        fs::write(
            &conf,
            corefile
                .replace("{port}", &port.to_string())
                .replace("{port2}", &port2.to_string())
                .replace("{metrics_port}", &metrics_port.to_string())
                .replace(
                    "{loopback}",
                    if cfg!(target_os = "macos") {
                        "lo0"
                    } else {
                        "lo"
                    },
                ),
        )
        .map_err(|e| e.to_string())?;
        Some(conf)
    } else {
        None
    };
    start_with_config(
        binary,
        cwd,
        port,
        conf.as_deref(),
        &cwd.with_extension("server.log"),
        pharos,
    )
}

pub(crate) fn start_with_config(
    binary: &Path,
    cwd: &Path,
    port: u16,
    conf: Option<&Path>,
    log_path: &Path,
    pharos: bool,
) -> Result<Server, String> {
    let log = fs::File::create(log_path).map_err(|e| e.to_string())?;
    let mut command = Command::new(binary);
    command
        .current_dir(cwd)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log));
    if let Some(conf) = conf {
        command
            .arg(if pharos { "--conf" } else { "-conf" })
            .arg(conf);
    }
    command
        .arg(if pharos { "-p" } else { "-dns.port" })
        .arg(port.to_string());
    command
        .spawn()
        .map(Server)
        .map_err(|e| format!("starting {}: {e}", binary.display()))
}

fn exchange(port: u16, transport: Transport, wire: &[u8]) -> Result<Vec<u8>, String> {
    let timeout = Some(Duration::from_secs(2));
    match transport {
        Transport::Udp => {
            let socket = UdpSocket::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
            socket
                .set_read_timeout(timeout)
                .map_err(|e| e.to_string())?;
            socket
                .connect(("127.0.0.1", port))
                .map_err(|e| e.to_string())?;
            socket.send(wire).map_err(|e| e.to_string())?;
            let mut data = vec![0; 65535];
            let n = socket.recv(&mut data).map_err(|e| e.to_string())?;
            data.truncate(n);
            Ok(data)
        }
        Transport::Tcp => {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).map_err(|e| e.to_string())?;
            stream
                .set_read_timeout(timeout)
                .map_err(|e| e.to_string())?;
            stream
                .set_write_timeout(timeout)
                .map_err(|e| e.to_string())?;
            let len = u16::try_from(wire.len()).map_err(|e| e.to_string())?;
            stream
                .write_all(&len.to_be_bytes())
                .and_then(|()| stream.write_all(wire))
                .map_err(|e| e.to_string())?;
            let mut len = [0; 2];
            stream.read_exact(&mut len).map_err(|e| e.to_string())?;
            let mut data = vec![0; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut data).map_err(|e| e.to_string())?;
            Ok(data)
        }
    }
}

pub(crate) fn ready(server: &mut Server, log_path: &Path, port: u16) -> Result<(), String> {
    let wire = query::parse("ready. A IN udp")?.wire()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let answered = exchange(port, Transport::Udp, &wire).is_ok();
        if server.0.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "server on {port} did not start:\n{}",
                fs::read_to_string(log_path).unwrap_or_default()
            ));
        }
        if answered {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn kubernetes_ready(wire: &[u8]) -> bool {
    Message::parse(wire).is_ok_and(|message| {
        message.answers().any(
            |record| matches!(record.data(), Ok(Rdata::A(ip)) if ip.octets() == [10, 96, 0, 10]),
        )
    })
}

fn kubernetes_http_ready(response: &[u8]) -> bool {
    response.starts_with(b"HTTP/1.1 200 ")
}

fn readiness_probe(port: u16) -> bool {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(500)) else {
        return false;
    };
    if stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .is_err()
        || stream
            .write_all(b"GET /ready HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .is_err()
    {
        return false;
    }
    let mut response = Vec::new();
    stream.read_to_end(&mut response).is_ok() && kubernetes_http_ready(&response)
}

fn wait_for_kubernetes(
    server: &mut Server,
    log_path: &Path,
    port: u16,
    ready_port: u16,
) -> Result<(), String> {
    let wire = query::parse("web.default.svc.cluster.local. A IN udp")?.wire()?;
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if readiness_probe(ready_port)
            && exchange(port, Transport::Udp, &wire).is_ok_and(|reply| kubernetes_ready(&reply))
        {
            return Ok(());
        }
        if server.0.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "Kubernetes fixture not ready on {port}:\n{}",
                fs::read_to_string(log_path).unwrap_or_default()
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn start_kubernetes_api(root: &Path, temp: &Path) -> Result<Server, String> {
    let config = temp.join("kubeconfig");
    let log = fs::File::create(temp.join("kubernetes-api.log")).map_err(|e| e.to_string())?;
    let port = reserve_port()?;
    let number = port.port()?;
    drop(port);
    let mut server = Server(
        Command::new(root.join("target/debug/examples/differential"))
            .arg(&config)
            .arg(number.to_string())
            .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
            .stderr(Stdio::from(log))
            .spawn()
            .map_err(|e| format!("starting fake Kubernetes API: {e}"))?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !config.is_file() {
        if server.0.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "fake Kubernetes API did not start:\n{}",
                fs::read_to_string(temp.join("kubernetes-api.log")).unwrap_or_default()
            ));
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Ok(server)
}

fn kubernetes_corefile(corefile: &str, config: &Path) -> String {
    corefile.replace("{kubeconfig}", &config.to_string_lossy())
}

fn scenario(
    path: &Path,
    pharos: &Path,
    coredns: &Path,
    docs: &str,
    self_test: bool,
) -> Result<usize, String> {
    let input = fs::read_to_string(path.join("queries")).map_err(|e| e.to_string())?;
    let expect = match fs::read_to_string(path.join("expect")) {
        Ok(input) => parse_expect(&input, docs)?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Expect::default(),
        Err(e) => return Err(e.to_string()),
    };
    let mut corefile = match fs::read_to_string(path.join("Corefile")) {
        Ok(input) => Some(input),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let temp = TempDir::new()?;
    let uses_kubernetes = corefile
        .as_deref()
        .is_some_and(|s| s.contains("{kubeconfig}"));
    let _api = if uses_kubernetes {
        let server = start_kubernetes_api(crate::root(), &temp.0)?;
        let config = fs::canonicalize(temp.0.join("kubeconfig")).map_err(|e| e.to_string())?;
        corefile = corefile.map(|s| kubernetes_corefile(&s, &config));
        Some(server)
    } else {
        None
    };
    let (pcwd, ccwd) = (temp.0.join("pharos"), temp.0.join("coredns"));
    copy_fixtures(path, &pcwd)?;
    copy_fixtures(path, &ccwd)?;
    let (pp, cp) = (reserve_port()?, reserve_port()?);
    let has_port2 = corefile.as_deref().is_some_and(|s| s.contains("{port2}"));
    let has_metrics = corefile
        .as_deref()
        .is_some_and(|s| s.contains("{metrics_port}"));
    if uses_kubernetes && !has_metrics {
        return Err("Kubernetes scenarios require a {metrics_port} readiness listener".into());
    }
    let (pp2, cp2) = (
        has_port2.then(reserve_port).transpose()?,
        has_port2.then(reserve_port).transpose()?,
    );
    let (pm, cm) = (
        has_metrics.then(reserve_port).transpose()?,
        has_metrics.then(reserve_port).transpose()?,
    );
    let (pp_num, cp_num) = (pp.port()?, cp.port()?);
    let optional_port =
        |port: &Option<ReservedPort>| port.as_ref().map_or(Ok(0), ReservedPort::port);
    let (pp2_num, cp2_num) = (optional_port(&pp2)?, optional_port(&cp2)?);
    let (pm_num, cm_num) = (optional_port(&pm)?, optional_port(&cm)?);
    // shortcut: another process can bind the port before startup; pass bound sockets to servers when supported.
    drop((pp, pp2, pm));
    let mut p = start(
        pharos,
        &pcwd,
        pp_num,
        pp2_num,
        pm_num,
        corefile.as_deref(),
        true,
    )?;
    ready(&mut p, &pcwd.with_extension("server.log"), pp_num)?;
    if uses_kubernetes {
        wait_for_kubernetes(&mut p, &pcwd.with_extension("server.log"), pp_num, pm_num)?;
    }
    if has_port2 {
        ready(&mut p, &pcwd.with_extension("server.log"), pp2_num)?;
    }
    drop((cp, cp2, cm));
    let mut c = start(
        coredns,
        &ccwd,
        cp_num,
        cp2_num,
        cm_num,
        corefile.as_deref(),
        false,
    )?;
    ready(&mut c, &ccwd.with_extension("server.log"), cp_num)?;
    if uses_kubernetes {
        wait_for_kubernetes(&mut c, &ccwd.with_extension("server.log"), cp_num, cm_num)?;
    }
    if has_port2 {
        ready(&mut c, &ccwd.with_extension("server.log"), cp2_num)?;
    }
    let mut count = 0;
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let query = query::parse(line).map_err(|e| format!("{line}: {e}"))?;
        let wire = query.wire()?;
        let mut pwire =
            exchange(pp_num, query.transport, &wire).map_err(|e| format!("Pharos {line}: {e}"))?;
        let cwire =
            exchange(cp_num, query.transport, &wire).map_err(|e| format!("CoreDNS {line}: {e}"))?;
        if pwire.len() < 4 || cwire.len() < 4 {
            return Err(format!("{line}: truncated Response header"));
        }
        if self_test {
            pwire[2] ^= 4;
        }
        apply_deviation(&expect, line, &mut pwire, &cwire)?;
        let pm = Message::parse(&pwire).map_err(|e| format!("Pharos {line}: {e}"))?;
        let cm = Message::parse(&cwire).map_err(|e| format!("CoreDNS {line}: {e}"))?;
        let result = compare::compare_with_soa_serial(
            &pm,
            &cm,
            expect.ttl,
            expect.mask_srv_port,
            expect.mask_soa_serial,
            expect.dedupe_additional,
        );
        result.map_err(|e| format!("{line}:\n{e}"))?;
        count += 1;
    }
    if count == 0 {
        return Err("scenario has no Queries".into());
    }
    Ok(count)
}

pub(crate) fn run(root: &Path, coredns: &Path, self_test: bool) -> Result<(), String> {
    let status = Command::new("cargo")
        .args(["build", "-p", "pharos"])
        .current_dir(root)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("building Pharos failed: {status}"));
    }
    let status = Command::new("cargo")
        .args([
            "build",
            "-p",
            "pharos-kubernetes",
            "--example",
            "differential",
        ])
        .current_dir(root)
        .status()
        .map_err(|e| e.to_string())?;
    if !status.success() {
        return Err(format!("building Kubernetes fixture failed: {status}"));
    }
    let pharos = root.join("target/debug/pharos");
    let docs = fs::read_to_string(root.join("docs/compatibility.md")).map_err(|e| e.to_string())?;
    let mut paths = fs::read_dir(root.join("tests/differential"))
        .map_err(|e| e.to_string())?
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect::<Vec<_>>();
    paths.sort();
    if paths.is_empty() {
        return Err("no differential scenarios".into());
    }
    println!("{:<24} {:>7}  result", "scenario", "queries");
    let mut failures = Vec::new();
    for path in paths {
        let name = path.file_name().unwrap().to_string_lossy();
        // Ports are released before servers start, so another process can take one; retry once with fresh ports.
        let result = match scenario(&path, &pharos, coredns, &docs, self_test) {
            Err(error)
                if error
                    .to_ascii_lowercase()
                    .contains("address already in use") =>
            {
                scenario(&path, &pharos, coredns, &docs, self_test)
            }
            result => result,
        };
        match result {
            Ok(count) => println!("{name:<24} {count:>7}  PASS"),
            Err(error) => {
                println!("{name:<24} {:>7}  FAIL", "-");
                failures.push(format!("{name}: {error}"));
            }
        }
        if self_test {
            break;
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::{
        TempDir, apply_deviation, copy_fixtures, kubernetes_corefile, kubernetes_ready,
        parse_expect, reserve_port, start,
    };

    #[test]
    fn kubernetes_http_readiness_requires_ok() {
        assert!(super::kubernetes_http_ready(b"HTTP/1.1 200 OK\r\n\r\nOK"));
        assert!(!super::kubernetes_http_ready(
            b"HTTP/1.1 503 Service Unavailable\r\n\r\nkubernetes"
        ));
        assert!(!super::kubernetes_http_ready(b"not an HTTP response"));
    }

    #[test]
    fn readiness_probe_queries_the_ready_endpoint() {
        use std::io::{Read, Write};
        let listener = super::reserve_port().unwrap().tcp;
        let port = listener.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = [0; 256];
            let n = socket.read(&mut request).unwrap();
            assert!(request[..n].starts_with(b"GET /ready HTTP/1.1\r\n"));
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                .unwrap();
        });
        assert!(super::readiness_probe(port));
        server.join().unwrap();
    }

    #[test]
    fn kubernetes_scenarios_expose_readiness() {
        let root = crate::root().join("tests/differential");
        let scenarios: Vec<_> = std::fs::read_dir(root)
            .unwrap()
            .map(Result::unwrap)
            .filter(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("kubernetes-")
            })
            .collect();
        assert!(!scenarios.is_empty());
        for scenario in scenarios {
            let corefile = std::fs::read_to_string(scenario.path().join("Corefile")).unwrap();
            assert!(
                corefile.contains("ready 127.0.0.1:{metrics_port}"),
                "{}",
                scenario.path().display()
            );
        }
    }

    #[test]
    fn both_processes_receive_the_same_absolute_kubeconfig() {
        let temp = TempDir::new().unwrap();
        let config = std::fs::canonicalize(&temp.0).unwrap().join("kubeconfig");
        assert!(config.is_absolute());
        let corefile = kubernetes_corefile(
            ".:{port} {\n kubernetes cluster.local {\n kubeconfig {kubeconfig}\n }\n}\n",
            &config,
        );
        for (name, pharos) in [("pharos", true), ("coredns", false)] {
            let cwd = temp.0.join(name);
            std::fs::create_dir(&cwd).unwrap();
            let _server = start(
                std::path::Path::new("/usr/bin/true"),
                &cwd,
                1001,
                0,
                0,
                Some(&corefile),
                pharos,
            )
            .unwrap();
            let written = std::fs::read_to_string(cwd.join("Corefile")).unwrap();
            assert!(written.contains(&format!("kubeconfig {}", config.display())));
            assert!(!written.contains("{kubeconfig}"));
        }
    }

    #[test]
    fn soa_serial_mask_must_be_explicit() {
        assert!(!parse_expect("", "").unwrap().mask_soa_serial);
        assert!(parse_expect("mask soa.serial", "").unwrap().mask_soa_serial);
        assert!(parse_expect("mask soa", "").is_err());
    }

    #[test]
    fn kubernetes_readiness_requires_fixture_service_answer() {
        let mut response = [
            0, 1, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0, 1, b'a', 0, 0, 1, 0, 1, 0xc0, 12, 0, 1, 0, 1,
            0, 0, 0, 5, 0, 4, 10, 96, 0, 10,
        ];
        assert!(kubernetes_ready(&response));
        response[33] = 11;
        assert!(!kubernetes_ready(&response));
        assert!(!kubernetes_ready(&response[..3]));
    }

    #[test]
    fn substitutes_dns_upstream_and_metrics_ports_for_each_server() {
        let temp = TempDir::new().unwrap();
        let config = ".:{port} {\n    forward . 127.0.0.1:{port2}\n    prometheus localhost:{metrics_port}\n}\n# {loopback}\n";
        let loopback = if cfg!(target_os = "macos") {
            "lo0"
        } else {
            "lo"
        };
        let pharos = temp.0.join("pharos");
        let coredns = temp.0.join("coredns");
        std::fs::create_dir(&pharos).unwrap();
        std::fs::create_dir(&coredns).unwrap();
        let _p = start(
            std::path::Path::new("/usr/bin/true"),
            &pharos,
            1001,
            1003,
            1002,
            Some(config),
            true,
        )
        .unwrap();
        let _c = start(
            std::path::Path::new("/usr/bin/true"),
            &coredns,
            2001,
            2003,
            2002,
            Some(config),
            false,
        )
        .unwrap();
        assert_eq!(
            std::fs::read_to_string(pharos.join("Corefile")).unwrap(),
            format!(
                ".:1001 {{\n    forward . 127.0.0.1:1003\n    prometheus localhost:1002\n}}\n# {loopback}\n"
            )
        );
        assert_eq!(
            std::fs::read_to_string(coredns.join("Corefile")).unwrap(),
            format!(
                ".:2001 {{\n    forward . 127.0.0.1:2003\n    prometheus localhost:2002\n}}\n# {loopback}\n"
            )
        );
    }

    #[test]
    fn reserved_ports_are_distinct_and_block_both_transports() {
        let first = reserve_port().unwrap();
        let second = reserve_port().unwrap();
        let port = first.port().unwrap();
        assert_ne!(port, second.port().unwrap());
        assert!((10_000..=32_767).contains(&port));
        assert!((10_000..=32_767).contains(&second.port().unwrap()));
        assert!(std::net::TcpListener::bind(("0.0.0.0", port)).is_err());
        assert!(std::net::UdpSocket::bind(("0.0.0.0", port)).is_err());
    }

    #[test]
    fn rejects_deviation_without_documented_heading() {
        let docs = "# Compatibility\n\n## EDNS\n";
        assert!(parse_expect("deviation EDNS\n", docs).is_ok());
        assert!(parse_expect("deviation Missing\n", docs).is_err());
    }

    #[test]
    fn rejects_unknown_masks_and_options() {
        assert!(parse_expect("mask everything\n", "").is_err());
        assert!(parse_expect("ttl nope\n", "").is_err());
        assert!(parse_expect("surprise true\n", "").is_err());
    }

    #[test]
    fn deviation_matches_only_the_documented_query_and_exact_flags() {
        let expect = parse_expect(
            "deviation EDNS | example. A IN udp | flags=0x8505:0x8105",
            "## EDNS\n",
        )
        .unwrap();
        let mut pharos = [0, 1, 0x85, 5];
        let coredns = [0, 1, 0x81, 5];
        apply_deviation(&expect, "other. A IN udp", &mut pharos, &coredns).unwrap();
        assert_eq!(pharos[2], 0x85);
        apply_deviation(&expect, "example. A IN udp", &mut pharos, &coredns).unwrap();
        assert_eq!(pharos, coredns);
        assert!(
            parse_expect(
                "deviation Missing | example. A IN udp | flags=0x8505:0x8105",
                "## EDNS\n"
            )
            .is_err()
        );
    }

    #[test]
    fn copies_nested_fixtures_even_when_names_match_scenario_files() {
        let temp = TempDir::new().unwrap();
        let source = temp.0.join("source");
        std::fs::create_dir_all(source.join("fixtures")).unwrap();
        std::fs::write(source.join("queries"), "scenario").unwrap();
        std::fs::write(source.join("fixtures/queries"), "fixture").unwrap();
        let target = temp.0.join("target");
        copy_fixtures(&source, &target).unwrap();
        assert!(!target.join("queries").exists());
        assert_eq!(
            std::fs::read_to_string(target.join("fixtures/queries")).unwrap(),
            "fixture"
        );
    }
}
