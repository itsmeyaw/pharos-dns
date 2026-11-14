use std::{
    fs,
    io::{Read, Write},
    net::{Ipv4Addr, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CLUSTER: &str = "pharos-e2e";
const IMAGE: &str = "pharos-e2e:local";

fn command(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("{program}: {error}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    if !output.status.success() {
        return Err(format!(
            "{program} {} failed ({}):\n{}{}",
            args.join(" "),
            output.status,
            stdout,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(stdout)
}

struct Cluster {
    directory: PathBuf,
    keep: bool,
    active: bool,
}

impl Cluster {
    fn kubeconfig(&self) -> PathBuf {
        self.directory.join("kubeconfig")
    }

    fn kubectl(&self, args: &[&str]) -> Result<String, String> {
        let kubeconfig = self.kubeconfig();
        let path = kubeconfig.to_str().ok_or("non-UTF-8 kubeconfig path")?;
        let mut all = vec!["--kubeconfig", path];
        all.extend_from_slice(args);
        command("kubectl", &all)
    }

    fn cleanup(&mut self) -> Result<(), String> {
        if self.keep {
            eprintln!(
                "kind cluster retained; kubeconfig: {}",
                self.kubeconfig().display()
            );
        } else {
            let kubeconfig = self.kubeconfig();
            let path = kubeconfig.to_str().ok_or("non-UTF-8 kubeconfig path")?;
            command(
                "kind",
                &["delete", "cluster", "--name", CLUSTER, "--kubeconfig", path],
            )?;
            fs::remove_dir_all(&self.directory)
                .map_err(|error| format!("removing {}: {error}", self.directory.display()))?;
        }
        self.active = false;
        Ok(())
    }
}

impl Drop for Cluster {
    fn drop(&mut self) {
        if self.active
            && let Err(error) = self.cleanup()
        {
            eprintln!("e2e cleanup failed: {error}");
        }
    }
}

struct Forward(Child);
impl Drop for Forward {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn http(cluster: &Cluster, pod: &str, remote_port: u16, path: &str) -> Result<String, String> {
    let port = crate::differential::free_port()?;
    let kubeconfig = cluster.kubeconfig();
    let mut child = Forward(
        Command::new("kubectl")
            .arg("--kubeconfig")
            .arg(kubeconfig)
            .args([
                "-n",
                "kube-system",
                "port-forward",
                &format!("pod/{pod}"),
                &format!("{port}:{remote_port}"),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|error| format!("kubectl port-forward: {error}"))?,
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)) {
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .map_err(|e| e.to_string())?;
            write!(
                stream,
                "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
            )
            .map_err(|e| e.to_string())?;
            let mut response = String::new();
            stream
                .read_to_string(&mut response)
                .map_err(|e| e.to_string())?;
            if !response.starts_with("HTTP/1.1 200 ") {
                return Err(format!("{pod} {path}: {response}"));
            }
            return Ok(response);
        }
        if child.0.try_wait().map_err(|e| e.to_string())?.is_some() || Instant::now() >= deadline {
            return Err(format!("port-forward {pod}:{remote_port} did not start"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

struct Case {
    name: &'static str,
    arguments: Vec<String>,
    required: Vec<String>,
}

fn dig(cluster: &Cluster, arguments: &[String]) -> Result<String, String> {
    let mut args = vec![
        "-n",
        "pharos-e2e",
        "exec",
        "deployment/dns-fixture",
        "--",
        "dig",
        "+tries=2",
        "+time=3",
        "+noall",
        "+comments",
        "+answer",
        "+additional",
    ];
    args.extend(arguments.iter().map(String::as_str));
    cluster.kubectl(&args)
}

fn response(cluster: &Cluster, case: &Case) -> Result<String, String> {
    let output = dig(cluster, &case.arguments)?;
    let answer = normalize(&output)?;
    for required in &case.required {
        if !matches_required(&answer, required) {
            return Err(format!("{}: missing {required:?}:\n{output}", case.name));
        }
    }
    Ok(answer)
}

fn matches_required(answer: &str, required: &str) -> bool {
    let required = required.to_ascii_lowercase();
    let expected: Vec<_> = required.split_whitespace().collect();
    !expected.is_empty()
        && answer.lines().any(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            fields
                .windows(expected.len())
                .any(|window| window == expected)
        })
}

fn baseline_matches(case: &Case, expected: &str, actual: &str) -> bool {
    if case.name == "forwarded public A" {
        case.required
            .iter()
            .all(|required| matches_required(actual, required))
    } else {
        actual == expected
    }
}

fn wait_response(cluster: &Cluster, case: &Case, timeout: Duration) -> Result<String, String> {
    let deadline = Instant::now() + timeout;
    loop {
        match response(cluster, case) {
            Ok(answer) => return Ok(answer),
            Err(error) if Instant::now() >= deadline => return Err(error),
            Err(_) => thread::sleep(Duration::from_secs(2)),
        }
    }
}

fn cases(service_ip: &str, kube_ip: &str, pod_ip: &str) -> Result<Vec<Case>, String> {
    let ip: Ipv4Addr = pod_ip
        .parse()
        .map_err(|e| format!("invalid pod IPv4 address: {e}"))?;
    let pod_name = format!(
        "{}.pharos-e2e.pod.cluster.local.",
        ip.to_string().replace('.', "-")
    );
    let kube_record = format!("answer kubernetes.default.svc.cluster.local. in a {kube_ip}");
    let web_record = format!("answer web.pharos-e2e.svc.cluster.local. in a {service_ip}");
    let headless_record = format!("answer headless.pharos-e2e.svc.cluster.local. in a {pod_ip}");
    let endpoint_record =
        format!("answer endpoint.headless.pharos-e2e.svc.cluster.local. in a {pod_ip}");
    let web_extra = format!("additional web.pharos-e2e.svc.cluster.local. in a {service_ip}");
    let headless_extra =
        format!("additional endpoint.headless.pharos-e2e.svc.cluster.local. in a {pod_ip}");
    let pod_record = format!("answer {pod_name} in a {pod_ip}");
    let make = |name, args: &[&str], records: &[&str]| Case {
        name,
        arguments: args.iter().map(|s| (*s).to_owned()).collect(),
        required: records.iter().map(|s| (*s).to_owned()).collect(),
    };
    // Kubernetes DNS spec 1.1.0 §2.3.1: A Service ClusterIP has its matching A record.
    // RFC 7766 §5: Full DNS implementations support both UDP and TCP transport.
    // Kubernetes DNS spec 1.1.0 §2.4.1: Headless Services publish ready IPv4 endpoint A records.
    // RFC 1035 §4.1.1: RCODE 3 means the queried domain does not exist.
    Ok(vec![
        make(
            "kubernetes Service A UDP",
            &["kubernetes.default.svc.cluster.local.", "A"],
            &["NOERROR", &kube_record],
        ),
        make(
            "test Service A UDP",
            &["web.pharos-e2e.svc.cluster.local.", "A"],
            &["NOERROR", &web_record],
        ),
        make(
            "test Service A TCP",
            &["+tcp", "web.pharos-e2e.svc.cluster.local.", "A"],
            &["NOERROR", &web_record],
        ),
        make(
            "headless Service A",
            &["headless.pharos-e2e.svc.cluster.local.", "A"],
            &["NOERROR", &headless_record],
        ),
        make(
            "headless endpoint A",
            &["endpoint.headless.pharos-e2e.svc.cluster.local.", "A"],
            &["NOERROR", &endpoint_record],
        ),
        make(
            "Service SRV and additional",
            &["_http._tcp.web.pharos-e2e.svc.cluster.local.", "SRV"],
            &[
                "NOERROR",
                "0 100 8080 web.pharos-e2e.svc.cluster.local.",
                &web_extra,
            ],
        ),
        make(
            "headless SRV and additional",
            &["_http._tcp.headless.pharos-e2e.svc.cluster.local.", "SRV"],
            &[
                "NOERROR",
                "0 100 8080 endpoint.headless.pharos-e2e.svc.cluster.local.",
                &headless_extra,
            ],
        ),
        make(
            "Service PTR",
            &["-x", service_ip],
            &["NOERROR", "web.pharos-e2e.svc.cluster.local."],
        ),
        make(
            "Pod PTR",
            &["-x", pod_ip],
            &["NOERROR", "endpoint.headless.pharos-e2e.svc.cluster.local."],
        ),
        make(
            "ExternalName CNAME and target",
            &["external.pharos-e2e.svc.cluster.local.", "A"],
            &[
                "NOERROR",
                "cname kubernetes.default.svc.cluster.local.",
                &kube_record,
            ],
        ),
        make(
            "insecure Pod A",
            &[&pod_name, "A"],
            &["NOERROR", &pod_record],
        ),
        make(
            "search path",
            &["+search", "kubernetes.default", "A"],
            &["NOERROR", &kube_record],
        ),
        make(
            "missing Service NXDOMAIN",
            &["missing.pharos-e2e.svc.cluster.local.", "A"],
            &["NXDOMAIN"],
        ),
        make(
            "forwarded public A",
            &["example.com.", "A"],
            &["NOERROR", " in a "],
        ),
    ])
}

fn json_string(text: &str) -> String {
    let mut result = String::from("\"");
    for c in text.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if c.is_control() => result.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

fn reload(cluster: &Cluster, pods: &[String]) -> Result<(), String> {
    let corefile = cluster.kubectl(&[
        "-n",
        "kube-system",
        "get",
        "configmap",
        "coredns",
        "-o",
        "jsonpath={.data.Corefile}",
    ])?;
    let updated = reload_corefile(&corefile)?;
    let patch = format!("{{\"data\":{{\"Corefile\":{}}}}}", json_string(&updated));
    cluster.kubectl(&[
        "-n",
        "kube-system",
        "patch",
        "configmap",
        "coredns",
        "--type=merge",
        "-p",
        &patch,
    ])?;
    for pod in pods {
        let ip = cluster.kubectl(&[
            "-n",
            "kube-system",
            "get",
            "pod",
            pod,
            "-o",
            "jsonpath={.status.podIP}",
        ])?;
        let case = Case {
            name: "Reload",
            arguments: vec![
                format!("@{ip}"),
                "pharos-reload.e2e.test.".into(),
                "A".into(),
            ],
            required: vec!["NOERROR".into(), "192.0.2.55".into()],
        };
        wait_response(cluster, &case, Duration::from_secs(180))?;
        let metrics = http(cluster, pod, 9153, "/metrics")?;
        if !metrics
            .lines()
            .any(|line| line.trim() == "pharos_reload_failed_total 0")
        {
            return Err(format!("{pod}: Reload failure counter missing or nonzero"));
        }
        println!("PASS Reload and metrics: {pod}");
    }
    Ok(())
}

fn reload_corefile(corefile: &str) -> Result<String, String> {
    let needle = "    forward . /etc/resolv.conf {";
    if corefile.matches(needle).count() != 1 {
        return Err("unexpected kubeadm Corefile: cannot add Reload fixture".into());
    }
    let replacement = format!(
        "    hosts {{\n        192.0.2.55 pharos-reload.e2e.test\n        fallthrough\n    }}\n{needle}"
    );
    Ok(corefile.replacen(needle, &replacement, 1))
}

pub(crate) fn run(root: &Path, keep: bool) -> Result<(), String> {
    let revision = std::env::var("PHAROS_IMAGE_REVISION").unwrap_or_else(|_| {
        command(
            "git",
            &["-C", root.to_str().unwrap_or("."), "rev-parse", "HEAD"],
        )
        .unwrap_or_else(|_| "unknown".into())
    });
    println!("Building host image");
    command(
        "docker",
        &[
            "buildx",
            "build",
            "--load",
            "-t",
            IMAGE,
            "--build-arg",
            &format!("VERSION={}", env!("CARGO_PKG_VERSION")),
            "--build-arg",
            &format!("REVISION={}", revision.trim()),
            root.to_str().ok_or("non-UTF-8 root")?,
        ],
    )?;
    let clusters = command("kind", &["get", "clusters"])?;
    if clusters.lines().any(|name| name == CLUSTER) {
        return Err(format!(
            "kind cluster {CLUSTER} already exists; refusing to replace it (remove it with: kind delete cluster --name {CLUSTER})"
        ));
    }
    let directory = std::env::temp_dir().join(format!("pharos-e2e-{}", std::process::id()));
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(&directory)
        .map_err(|e| format!("{}: {e}", directory.display()))?;
    let mut cluster = Cluster {
        directory,
        keep,
        active: true,
    };
    let kubeconfig = cluster.kubeconfig();
    let config = kubeconfig.to_str().ok_or("non-UTF-8 kubeconfig")?;
    command(
        "kind",
        &[
            "create",
            "cluster",
            "--name",
            CLUSTER,
            "--kubeconfig",
            config,
            "--wait",
            "180s",
        ],
    )?;
    cluster.kubectl(&[
        "-n",
        "kube-system",
        "rollout",
        "status",
        "deployment/coredns",
        "--timeout=180s",
    ])?;
    let reference = cluster.kubectl(&[
        "-n",
        "kube-system",
        "get",
        "deployment",
        "coredns",
        "-o",
        "jsonpath={.spec.template.spec.containers[0].image}",
    ])?;
    println!("Stock CoreDNS image: {reference}");
    cluster.kubectl(&[
        "apply",
        "-f",
        root.join("xtask/e2e/fixtures.yaml")
            .to_str()
            .ok_or("non-UTF-8 fixture path")?,
    ])?;
    cluster.kubectl(&[
        "-n",
        "pharos-e2e",
        "rollout",
        "status",
        "deployment/dns-fixture",
        "--timeout=180s",
    ])?;
    let service_ip = cluster.kubectl(&[
        "-n",
        "pharos-e2e",
        "get",
        "service",
        "web",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ])?;
    let kube_ip = cluster.kubectl(&[
        "-n",
        "default",
        "get",
        "service",
        "kubernetes",
        "-o",
        "jsonpath={.spec.clusterIP}",
    ])?;
    let pod_ip = cluster.kubectl(&[
        "-n",
        "pharos-e2e",
        "get",
        "pods",
        "-l",
        "app=dns-fixture",
        "-o",
        "jsonpath={.items[0].status.podIP}",
    ])?;
    let checks = cases(&service_ip, &kube_ip, &pod_ip)?;
    let mut baseline = Vec::new();
    for case in &checks {
        let answer = wait_response(&cluster, case, Duration::from_secs(90))?;
        println!("PASS CoreDNS {}", case.name);
        baseline.push(answer);
    }
    let results = root.join("target/e2e");
    fs::create_dir_all(&results).map_err(|e| e.to_string())?;
    let recorded = checks
        .iter()
        .zip(&baseline)
        .map(|(case, answer)| format!("{}\n{}\n\n", case.name, answer))
        .collect::<String>();
    fs::write(results.join("coredns.txt"), recorded).map_err(|e| e.to_string())?;
    command("kind", &["load", "docker-image", IMAGE, "--name", CLUSTER])?;
    let name = cluster.kubectl(&[
        "-n",
        "kube-system",
        "get",
        "deployment",
        "coredns",
        "-o",
        "jsonpath={.spec.template.spec.containers[0].name}",
    ])?;
    let flag = cluster.kubectl(&[
        "-n",
        "kube-system",
        "get",
        "deployment",
        "coredns",
        "-o",
        "jsonpath={.spec.template.spec.containers[0].args[0]}",
    ])?;
    if name != "coredns" || flag != "-conf" {
        return Err(format!(
            "unexpected CoreDNS container or arguments: {name:?} {flag:?}"
        ));
    }
    cluster.kubectl(&[
        "-n",
        "kube-system",
        "patch",
        "deployment",
        "coredns",
        "--type=json",
        "-p",
        deployment_patch(),
    ])?;
    cluster.kubectl(&[
        "-n",
        "kube-system",
        "rollout",
        "status",
        "deployment/coredns",
        "--timeout=180s",
    ])?;
    let rollout = Instant::now();
    for (case, expected) in checks.iter().zip(&baseline) {
        let actual = wait_response(&cluster, case, Duration::from_secs(90))?;
        if !baseline_matches(case, expected, &actual) {
            return Err(format!(
                "{} differs from CoreDNS:\nCoreDNS:\n{expected}\nPharos:\n{actual}",
                case.name
            ));
        }
        println!("PASS Pharos {}", case.name);
    }
    let pods = cluster.kubectl(&[
        "-n",
        "kube-system",
        "get",
        "pods",
        "-l",
        "k8s-app=kube-dns",
        "-o",
        "jsonpath={range .items[*]}{.metadata.name}{\" \"}{.spec.containers[0].image}{\" \"}{.metadata.deletionTimestamp}{\"\\n\"}{end}",
    ])?;
    let pods = pharos_pods(&pods)?;
    if pods.is_empty() {
        return Err("no DNS Pods after rollout".into());
    }
    for pod in &pods {
        cluster.kubectl(&[
            "-n",
            "kube-system",
            "wait",
            "--for=condition=Ready",
            &format!("pod/{pod}"),
            "--timeout=120s",
        ])?;
        http(&cluster, pod, 8080, "/health")?;
        http(&cluster, pod, 8181, "/ready")?;
        println!("PASS Health and Readiness: {pod}");
    }
    reload(&cluster, &pods)?;
    for (case, expected) in checks.iter().zip(&baseline) {
        let actual = wait_response(&cluster, case, Duration::from_secs(90))?;
        if !baseline_matches(case, expected, &actual) {
            return Err(format!(
                "{} differs after Reload:\nCoreDNS:\n{expected}\nPharos:\n{actual}",
                case.name
            ));
        }
    }
    println!("PASS DNS parity after Reload");
    if let Some(remaining) = Duration::from_secs(120).checked_sub(rollout.elapsed()) {
        thread::sleep(remaining);
    }
    for pod in &pods {
        let restarts = cluster.kubectl(&[
            "-n",
            "kube-system",
            "get",
            "pod",
            pod,
            "-o",
            "jsonpath={.status.containerStatuses[0].restartCount}",
        ])?;
        if restarts != "0" {
            return Err(format!("{pod}: restart count is {restarts}"));
        }
        cluster.kubectl(&[
            "-n",
            "kube-system",
            "wait",
            "--for=condition=Ready",
            &format!("pod/{pod}"),
            "--timeout=60s",
        ])?;
    }
    println!("PASS probes and zero restarts");
    cluster.cleanup()?;
    println!(
        "e2e PASS: {} DNS checks, Health, Readiness, Reload and metrics",
        checks.len()
    );
    Ok(())
}

fn pharos_pods(input: &str) -> Result<Vec<String>, String> {
    let mut pods = Vec::new();
    for line in input.lines().filter(|line| !line.trim().is_empty()) {
        let fields: Vec<_> = line.split_whitespace().collect();
        match fields.as_slice() {
            [name, image] if *image == IMAGE => pods.push((*name).to_owned()),
            [_, _] | [_, _, _] => {}
            _ => return Err(format!("invalid DNS Pod listing: {line}")),
        }
    }
    Ok(pods)
}

fn deployment_patch() -> &'static str {
    r#"[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"pharos-e2e:local"},{"op":"replace","path":"/spec/template/spec/containers/0/args/0","value":"--conf"}]"#
}

fn normalize(input: &str) -> Result<String, String> {
    let mut status = None;
    let mut section = "";
    let mut records = Vec::new();
    for line in input.lines() {
        if let Some((_, tail)) = line.split_once("status: ") {
            status = tail.split(',').next().map(str::to_owned);
        } else if line.starts_with(";; ANSWER SECTION:") {
            section = "answer";
        } else if line.starts_with(";; ADDITIONAL SECTION:") {
            section = "additional";
        } else if !line.is_empty() && !line.starts_with(';') {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 5 || fields[1].parse::<u32>().is_err() || section.is_empty() {
                return Err(format!("invalid dig record: {line}"));
            }
            // TTLs age and loadbalance can reorder RRsets.
            // Kubernetes DNS spec 1.1.0 §2.1: Compare query and Kubernetes data without case.
            records.push(
                format!("{section} {} {}", fields[0], fields[2..].join(" ")).to_ascii_lowercase(),
            );
        }
    }
    records.sort();
    Ok(format!(
        "{}\n{}",
        status.ok_or("missing DNS status")?.to_ascii_lowercase(),
        records.join("\n")
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        deployment_patch, json_string, matches_required, normalize, pharos_pods, reload_corefile,
    };

    #[test]
    fn public_forwarding_allows_rotating_addresses_but_checks_response_shape() {
        let cases = super::cases("10.96.0.10", "10.96.0.1", "10.244.0.5").unwrap();
        let public = cases
            .iter()
            .find(|case| case.name == "forwarded public A")
            .unwrap();
        let baseline = "noerror\nanswer example.com. in a 192.0.2.1";
        assert!(super::baseline_matches(
            public,
            baseline,
            "noerror\nanswer example.com. in a 192.0.2.2"
        ));
        assert!(!super::baseline_matches(public, baseline, "nxdomain"));
        let fixed = cases
            .iter()
            .find(|case| case.name != "forwarded public A")
            .unwrap();
        assert!(!super::baseline_matches(
            fixed,
            baseline,
            "noerror\nanswer example.com. in a 192.0.2.2"
        ));
    }

    #[test]
    fn normalizes_ttl_and_record_order_but_keeps_status_and_sections() {
        let first = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1\n;; ANSWER SECTION:\nexample. 30 IN A 192.0.2.2\nexample. 29 IN A 192.0.2.1\n;; ADDITIONAL SECTION:\nother. 5 IN A 192.0.2.3\n";
        let reordered = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 2\n;; ANSWER SECTION:\nexample. 2 IN A 192.0.2.1\nexample. 3 IN A 192.0.2.2\n;; ADDITIONAL SECTION:\nother. 1 IN A 192.0.2.3\n";
        assert_eq!(normalize(first).unwrap(), normalize(reordered).unwrap());
        assert_ne!(
            normalize(first).unwrap(),
            normalize(&reordered.replace("NOERROR", "NXDOMAIN")).unwrap()
        );
        assert_ne!(
            normalize(first).unwrap(),
            normalize(&reordered.replace("ADDITIONAL SECTION", "ANSWER SECTION")).unwrap()
        );
        assert!(normalize("not a DNS response").is_err());
    }

    #[test]
    fn patch_changes_only_image_and_conf_flag() {
        assert_eq!(
            deployment_patch(),
            r#"[{"op":"replace","path":"/spec/template/spec/containers/0/image","value":"pharos-e2e:local"},{"op":"replace","path":"/spec/template/spec/containers/0/args/0","value":"--conf"}]"#
        );
    }

    #[test]
    fn reload_fixture_preserves_forward_and_escapes_configmap_patch() {
        let original = ".:53 {\n    forward . /etc/resolv.conf {\n    }\n}\n";
        let changed = reload_corefile(original).unwrap();
        assert!(changed.contains("192.0.2.55 pharos-reload.e2e.test\n        fallthrough"));
        assert!(changed.contains("    forward . /etc/resolv.conf {\n    }\n"));
        assert!(reload_corefile(".:53 {}\n").is_err());
        assert_eq!(json_string("a\"\\\n\u{1}"), "\"a\\\"\\\\\\n\\u0001\"");
    }

    #[test]
    fn expected_address_must_match_a_whole_field() {
        let answer = "noerror\nanswer name. in a 10.96.0.10";
        assert!(matches_required(answer, "10.96.0.10"));
        assert!(!matches_required(answer, "10.96.0.1"));
        assert!(matches_required(answer, "in a 10.96.0.10"));
        assert!(!matches_required(answer, "answer name. in a 10.96.0.1"));
    }

    #[test]
    fn selects_only_nonterminating_pharos_pods() {
        let pods = "new pharos-e2e:local \nold coredns:v1.12 2026-01-01T00:00:00Z\nretiring pharos-e2e:local 2026-01-01T00:00:00Z\n";
        assert_eq!(pharos_pods(pods).unwrap(), vec!["new"]);
        assert!(pharos_pods("invalid\n").is_err());
    }
}
