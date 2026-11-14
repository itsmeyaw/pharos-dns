use std::{
    io::Write,
    net::UdpSocket,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use pharos_corefile::{configure, parse};
use pharos_dnssec::{
    canonical::{CanonicalRecord, canonical_rdata, signed_data},
    keys::KeyPair,
};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Rdata, Section, Type};
use pharos_server::{Context, Metadata, Outcome, Protocol, Transport};

struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(binary: &Path, corefile: &Path) -> Process {
    Process(
        Command::new(binary)
            .args(["-conf", corefile.to_str().unwrap()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}

fn free_port() -> u16 {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn query(name: &str, kind: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::new();
    // RFC 1035 §4.1.1: Encode a DNS message with valid header fields and section counts.
    let mut builder = MessageBuilder::new(&mut wire, 4096, 42, 0).unwrap();
    builder
        // RFC 1035 §4.1.2: Encode QNAME, QTYPE, and QCLASS in the question section.
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), kind, Class::IN)
        .unwrap();
    builder
        // RFC 6891 §6.1.1: Add one OPT pseudo-RR to the additional section of a request.
        .record(
            Section::Additional,
            NameRef::parse(&[0], 0).unwrap(),
            Type::OPT,
            // RFC 6891 §6.2.5: Advertise a 4096-octet UDP payload size.
            Class(4096),
            // RFC 3225 §3: Set DO to signal support for DNSSEC security records.
            0x8000,
            &[],
        )
        .unwrap();
    let _ = builder.finish();
    wire
}

fn records(wire: &[u8], authority: bool) -> Vec<(Name, u16, u16, u32, Vec<u8>)> {
    let message = Message::parse(wire).unwrap();
    let mut records: Vec<_> = (if authority {
        message.authorities()
    } else {
        message.answers()
    })
    .map(|rr| {
        (
            rr.name.to_name(),
            rr.rtype.0,
            rr.class.0,
            rr.ttl,
            // RFC 4034 §6.2: Canonicalize RDATA before comparing response records.
            canonical_rdata(&rr.data().unwrap()).unwrap(),
        )
    })
    .collect();
    records.sort();
    records
}

fn verify_answers(wire: &[u8], key: &KeyPair) {
    let message = Message::parse(wire).unwrap();
    let records: Vec<_> = message.answers().chain(message.authorities()).collect();
    let mut checked = 0;
    for rr in &records {
        let Rdata::Rrsig {
            type_covered,
            signature,
            ..
        } = rr.data().unwrap()
        else {
            continue;
        };
        let sig = rr.data().unwrap();
        let rrset: Vec<_> = records
            .iter()
            .filter(|other| other.name == rr.name && other.rtype == type_covered)
            .map(|other| CanonicalRecord {
                owner: other.name,
                class: other.class,
                data: other.data().unwrap(),
            })
            .collect();
        // RFC 4035 §5.3.3: Verify each response signature over reconstructed signed data.
        let data = signed_data(&sig, &rrset).unwrap();
        // RFC 8080 §4: Verify each Ed25519 RRSIG with the DNSKEY public key.
        UnparsedPublicKey::new(&ED25519, &key.public.public_key)
            .verify(&data, signature)
            .unwrap();
        checked += 1;
    }
    assert!(checked > 0, "response has no signatures");
}

async fn compare_file(binary: &Path, directory: &Path, zone: &Path, key: &KeyPair) {
    let port = free_port();
    let corefile = directory.join(format!("file-{port}.conf"));
    std::fs::write(
        &corefile,
        format!("miek.nl:{port} {{\n file {}\n}}\n", zone.display()),
    )
    .unwrap();
    let _server = start(binary, &corefile);
    let blocks = parse(
        "Corefile",
        &format!("miek.nl {{\n file {}\n}}", zone.display()),
    )
    .unwrap();
    let chain = configure::<crate::Chain>(&blocks, crate::directives()).unwrap();
    let domain: Name = "miek.nl.".parse().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    for (name, kind) in [
        ("www.miek.nl.", Type::AAAA),
        ("child.miek.nl.", Type::DS),
        ("miek.nl.", Type::DNSKEY),
        ("caa.miek.nl.", Type::CAA),
        ("uri.miek.nl.", Type::URI),
        ("missing.miek.nl.", Type::A),
    ] {
        let wire = query(name, kind);
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut received = vec![0; 4096];
        let len = loop {
            socket.send_to(&wire, ("127.0.0.1", port)).unwrap();
            if let Ok((len, _)) = socket.recv_from(&mut received) {
                break len;
            }
            assert!(Instant::now() < deadline, "CoreDNS file did not answer");
        };
        received.truncate(len);
        let mut response = Vec::with_capacity(4096);
        let mut slots = [None; 8];
        let mut cx = Context {
            query: Message::parse(&wire).unwrap(),
            client: "127.0.0.1:1234".parse().unwrap(),
            local: "127.0.0.1:53".parse().unwrap(),
            transport: Transport::Dns,
            protocol: Protocol::Udp,
            domain: &domain,
            metadata: Metadata::new(&mut slots),
            response: &mut response,
            max_response_size: 4096,
        };
        assert_eq!(chain[0].config.serve(&mut cx).await, Outcome::Response);
        for authority in [false, true] {
            assert_eq!(
                records(&response, authority),
                records(&received, authority),
                "{name} {kind}"
            );
        }
        verify_answers(&received, key);
    }
}

#[tokio::test]
async fn coredns_and_pharos_file_serve_each_others_signed_zones() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let binary = root.join("../../target/coredns/v1.15.0/coredns");
    if !binary.is_file() {
        eprintln!("CoreDNS binary not cached; interoperability test skipped");
        return;
    }
    let directory =
        std::env::temp_dir().join(format!("pharos-sign-interop-{}", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("unsigned.zone");
    std::fs::copy(root.join("tests/fixtures/sign/db.miek.nl_ns"), &source).unwrap();
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&source)
        .unwrap();
    file.write_all(
        b"\ncaa 1800 IN CAA 0 issue \"a\\092123z\"\nuri 1800 IN URI 1 2 \"a\\092123z\"\n",
    )
    .unwrap();
    let base = root.join("tests/fixtures/dnssec/miek-ed25519-ksk");
    let key =
        KeyPair::from_files(base.with_extension("key"), base.with_extension("private")).unwrap();
    let apex: Name = "miek.nl.".parse().unwrap();
    let pharos_file = directory.join("pharos.signed");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as u32;
    let records =
        super::signer::sign(&apex, &source, std::slice::from_ref(&key), now, 0, 0).unwrap();
    super::output::write(&directory, &pharos_file, &records).unwrap();
    compare_file(&binary, &directory, &pharos_file, &key).await;

    let port = free_port();
    let config = directory.join("sign.conf");
    std::fs::write(
        &config,
        format!(
            "miek.nl:{port} {{\n sign {} {{\n key file {}\n directory {}\n }}\n}}\n",
            source.display(),
            base.display(),
            directory.display()
        ),
    )
    .unwrap();
    let server = start(&binary, &config);
    let coredns_file = directory.join("db.miek.nl.signed");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !coredns_file.is_file() {
        assert!(Instant::now() < deadline, "CoreDNS did not sign Zone");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    drop(server);
    compare_file(&binary, &directory, &coredns_file, &key).await;
    std::fs::remove_dir_all(directory).unwrap();
}
