#![forbid(unsafe_code)]
#![cfg(feature = "plugin-nomad")]

use std::{
    alloc::System,
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{
    Request,
    client::conn::http1,
    header::{HOST, HeaderValue, USER_AGENT},
};
use hyper_util::rt::TokioIo;
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, servers};
use pharos_proto::{Class, Message, MessageBuilder, Name, NameRef, Type};
use pharos_server::{Action, Handler, Protocol};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const WARM: usize = 10;
const MEASURED: usize = 40;
const TARGET: &str = "/v1/service/example?namespace=default";
// Three registrations, one with an escaped tag: Go's encoding/json writes `&` as `\u0026`.
const BODY: &str = r#"[{"Address":"1.2.3.4","Namespace":"default","Port":23202,"ServiceName":"example","Tags":["a\u0026b","c"]},{"Address":"1.2.3.5","Port":1},{"Address":"1:2:3::4","Port":2}]"#;

// RFC 9112 §3: a blocking HTTP/1.1 server that allocates nothing once it is warm, so the
// process-wide counter sees the client alone. It answers each request head with `wire`.
fn serve(listener: TcpListener, wire: Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut buffer = [0_u8; 4096];
    let mut filled = 0;
    loop {
        let read = match stream.read(&mut buffer[filled..]) {
            Ok(0) | Err(_) => return,
            Ok(read) => read,
        };
        filled += read;
        if buffer[..filled].ends_with(b"\r\n\r\n") {
            filled = 0;
            if stream.write_all(&wire).is_err() {
                return;
            }
        }
    }
}

fn upstream() -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let wire = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{BODY}",
        BODY.len()
    )
    .into_bytes();
    (address, std::thread::spawn(move || serve(listener, wire)))
}

struct Counts {
    allocations: usize,
    reallocations: usize,
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// What one lookup costs in hyper, http and tokio alone: the same request and reply without Pharos.
fn bare_hyper(address: SocketAddr) -> Counts {
    runtime().block_on(async {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let (mut sender, connection) = http1::handshake(TokioIo::new(tcp)).await.unwrap();
        tokio::spawn(connection);
        let host = HeaderValue::from_str(&address.to_string()).unwrap();
        let mut out = Vec::with_capacity(512);
        let mut run = async |count: usize| {
            let before = GLOBAL.stats();
            for _ in 0..count {
                sender.ready().await.unwrap();
                let request = Request::get(TARGET)
                    .header(HOST, host.clone())
                    .header(USER_AGENT, HeaderValue::from_static("pharos"))
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let (_, mut body) = sender.send_request(request).await.unwrap().into_parts();
                out.clear();
                while let Some(frame) = body.frame().await {
                    if let Ok(data) = frame.unwrap().into_data() {
                        out.extend_from_slice(&data);
                    }
                }
            }
            let after = GLOBAL.stats();
            Counts {
                allocations: after.allocations - before.allocations,
                reallocations: after.reallocations - before.reallocations,
            }
        };
        run(WARM).await;
        run(MEASURED).await
    })
}

fn question(name: &str, qtype: Type) -> Vec<u8> {
    let name: Name = name.parse().unwrap();
    let mut wire = Vec::with_capacity(512);
    let mut builder = MessageBuilder::new(&mut wire, 512, 0x1234, 0x0100).unwrap();
    builder
        .question(NameRef::parse(name.as_wire(), 0).unwrap(), qtype, Class::IN)
        .unwrap();
    let _ = builder.finish();
    wire
}

fn plugin(address: SocketAddr, qtype: Type, answers: usize) -> Counts {
    // Setup reads NOMAD_* from the environment; none may change what is measured.
    assert!(std::env::vars().all(|(name, _)| !name.starts_with("NOMAD_")));
    let text = format!(".:0 {{\n nomad {{\n address http://{address}\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) =
        servers(configure::<Chain>(&blocks, pharos_plugins::directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let peer = "127.0.0.1:1000".parse().unwrap();
    let wire = question("example.default.service.nomad.", qtype);
    runtime().block_on(async {
        let mut response = Vec::with_capacity(65535);
        let mut query = async || {
            assert_eq!(
                server
                    .handle(&wire, peer, Protocol::Tcp, &mut response)
                    .await,
                Action::Respond
            );
            let message = Message::parse(&response).unwrap();
            assert_eq!(message.rcode().0, 0);
            assert_eq!(message.answers().count(), answers);
        };
        for _ in 0..WARM {
            query().await;
        }
        let before = GLOBAL.stats();
        for _ in 0..MEASURED {
            query().await;
        }
        let after = GLOBAL.stats();
        Counts {
            allocations: after.allocations - before.allocations,
            reallocations: after.reallocations - before.reallocations,
        }
    })
}

fn check(name: &str, qtype: Type, answers: usize) {
    if crate::run_isolated(name) {
        return;
    }
    let (address, thread) = upstream();
    let baseline = bare_hyper(address);
    thread.join().unwrap();
    let (address, thread) = upstream();
    let measured = plugin(address, qtype, answers);
    drop(thread);
    println!(
        "bare hyper: {} allocations, {} reallocations; nomad: {}, {}",
        baseline.allocations, baseline.reallocations, measured.allocations, measured.reallocations
    );
    // Whatever hyper, http and tokio allocate per request is theirs; Pharos adds none on top.
    assert!(measured.allocations <= baseline.allocations);
    assert!(measured.reallocations <= baseline.reallocations);
}

#[test]
fn warmed_a_queries_allocate_only_inside_hyper() {
    check(
        "nomad::nomad_allocations::warmed_a_queries_allocate_only_inside_hyper",
        Type::A,
        2,
    );
}

#[test]
fn warmed_srv_queries_allocate_only_inside_hyper() {
    check(
        "nomad::nomad_allocations::warmed_srv_queries_allocate_only_inside_hyper",
        Type::SRV,
        3,
    );
}
