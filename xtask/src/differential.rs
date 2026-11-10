use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use pharos_proto::Message;

use crate::{
    compare,
    query::{self, Transport},
};

#[derive(Default)]
struct Expect {
    ttl: u32,
    mask_srv_port: bool,
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

struct Server(Child);
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

fn free_port() -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| e.to_string())?;
    let port = listener.local_addr().map_err(|e| e.to_string())?.port();
    // Check both Transports; sockets are released before the Listener starts.
    UdpSocket::bind(("127.0.0.1", port)).map_err(|e| e.to_string())?;
    Ok(port)
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
    corefile: Option<&str>,
    pharos: bool,
) -> Result<Server, String> {
    let log = fs::File::create(cwd.with_extension("server.log")).map_err(|e| e.to_string())?;
    let mut command = Command::new(binary);
    command
        .current_dir(cwd)
        .stdout(Stdio::from(log.try_clone().map_err(|e| e.to_string())?))
        .stderr(Stdio::from(log));
    if let Some(corefile) = corefile {
        let conf = cwd.join("Corefile");
        fs::write(&conf, corefile.replace("{port}", &port.to_string()))
            .map_err(|e| e.to_string())?;
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

fn ready(server: &mut Server, cwd: &Path, port: u16) -> Result<(), String> {
    let wire = query::parse("ready. A IN udp")?.wire()?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let answered = exchange(port, Transport::Udp, &wire).is_ok();
        if server.0.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline {
            return Err(format!(
                "server on {port} did not start:\n{}",
                fs::read_to_string(cwd.with_extension("server.log")).unwrap_or_default()
            ));
        }
        if answered {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
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
    let corefile = match fs::read_to_string(path.join("Corefile")) {
        Ok(input) => Some(input),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e.to_string()),
    };
    let temp = TempDir::new()?;
    let (pcwd, ccwd) = (temp.0.join("pharos"), temp.0.join("coredns"));
    copy_fixtures(path, &pcwd)?;
    copy_fixtures(path, &ccwd)?;
    let (pp, cp) = (free_port()?, free_port()?);
    if pp == cp {
        return Err("port collision; retry differential run".into());
    }
    let mut p = start(pharos, &pcwd, pp, corefile.as_deref(), true)?;
    let mut c = start(coredns, &ccwd, cp, corefile.as_deref(), false)?;
    ready(&mut p, &pcwd, pp)?;
    ready(&mut c, &ccwd, cp)?;
    let mut count = 0;
    for line in input
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let query = query::parse(line).map_err(|e| format!("{line}: {e}"))?;
        let wire = query.wire()?;
        let mut pwire =
            exchange(pp, query.transport, &wire).map_err(|e| format!("Pharos {line}: {e}"))?;
        let cwire =
            exchange(cp, query.transport, &wire).map_err(|e| format!("CoreDNS {line}: {e}"))?;
        if pwire.len() < 4 || cwire.len() < 4 {
            return Err(format!("{line}: truncated Response header"));
        }
        if self_test {
            pwire[2] ^= 4;
        }
        apply_deviation(&expect, line, &mut pwire, &cwire)?;
        let pm = Message::parse(&pwire).map_err(|e| format!("Pharos {line}: {e}"))?;
        let cm = Message::parse(&cwire).map_err(|e| format!("CoreDNS {line}: {e}"))?;
        compare::compare(&pm, &cm, expect.ttl, expect.mask_srv_port)
            .map_err(|e| format!("{line}:\n{e}"))?;
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
        match scenario(&path, &pharos, coredns, &docs, self_test) {
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
    use super::{TempDir, apply_deviation, copy_fixtures, parse_expect};

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
