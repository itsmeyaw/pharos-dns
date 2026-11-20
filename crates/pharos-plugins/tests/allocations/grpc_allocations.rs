#![forbid(unsafe_code)]
#![cfg(feature = "plugin-grpc")]

use std::{
    alloc::System,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{
    Request, Uri,
    client::conn::http2,
    header::{CONTENT_TYPE, HeaderName, HeaderValue},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use pharos_corefile::{configure, parse};
use pharos_plugins::{Chain, servers};
use pharos_proto::Message;
use pharos_server::{Action, Handler, Protocol, grpc::FramePrefix};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const WARM: usize = 10;
const MEASURED: usize = 40;
const QUERY: [u8; 17] = [0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

fn framed(message: &[u8]) -> Vec<u8> {
    use bytes::Buf;
    let mut wire = FramePrefix::new(message.len()).chunk().to_vec();
    wire.extend_from_slice(message);
    wire
}

fn frame_header(out: &mut Vec<u8>, length: usize, kind: u8, flags: u8, stream: u32) {
    out.extend_from_slice(&(length as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
}

// RFC 9113 §4.1, §6: a blocking HTTP/2 server that allocates nothing once it is warm, so the
// process-wide counter sees the client alone. It answers each call with `body` and `grpc-status: 0`.
fn serve(listener: TcpListener, body: Vec<u8>) {
    let (mut stream, _) = listener.accept().unwrap();
    let mut preface = [0; 24];
    stream.read_exact(&mut preface).unwrap();
    let mut out = Vec::with_capacity(1024);
    frame_header(&mut out, 0, 4, 0, 0);
    stream.write_all(&out).unwrap();
    let mut payload = vec![0; 16384];
    loop {
        let mut header = [0; 9];
        if stream.read_exact(&mut header).is_err() {
            return;
        }
        let length =
            usize::from(header[0]) << 16 | usize::from(header[1]) << 8 | usize::from(header[2]);
        let (kind, flags) = (header[3], header[4]);
        let id = u32::from_be_bytes([header[5] & 0x7f, header[6], header[7], header[8]]);
        stream.read_exact(&mut payload[..length]).unwrap();
        out.clear();
        match kind {
            // SETTINGS without ACK
            4 if flags & 1 == 0 => frame_header(&mut out, 0, 4, 1, 0),
            // DATA with END_STREAM: the request is complete
            0 if flags & 1 != 0 => {
                // HEADERS `:status: 200` and `content-type: application/grpc`, as HPACK literals.
                let mut head = [0; 21];
                head[0] = 0x88;
                head[1..3].copy_from_slice(&[0x0f, 0x10]);
                head[3] = 16;
                head[4..20].copy_from_slice(b"application/grpc");
                frame_header(&mut out, 20, 1, 4, id);
                out.extend_from_slice(&head[..20]);
                frame_header(&mut out, body.len(), 0, 0, id);
                out.extend_from_slice(&body);
                // HEADERS END_STREAM trailers: `grpc-status: 0`.
                frame_header(&mut out, 15, 1, 5, id);
                out.extend_from_slice(&[0x00, 11]);
                out.extend_from_slice(b"grpc-status");
                out.extend_from_slice(&[1, b'0']);
            }
            _ => {}
        }
        if !out.is_empty() {
            stream.write_all(&out).unwrap();
        }
    }
}

fn upstream(rcode: u8) -> (SocketAddr, std::thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let mut response = QUERY;
    response[2] |= 0x80;
    response[3] = rcode;
    let body = framed(&response);
    (address, std::thread::spawn(move || serve(listener, body)))
}

struct Counts {
    allocations: usize,
    reallocations: usize,
}

fn measure(calls: usize, mut call: impl FnMut()) -> Counts {
    let before = GLOBAL.stats();
    for _ in 0..calls {
        call();
    }
    let after = GLOBAL.stats();
    Counts {
        allocations: after.allocations - before.allocations,
        reallocations: after.reallocations - before.reallocations,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

// What one gRPC call costs in hyper, http and h2 alone: the same request and reply without Pharos.
fn bare_hyper(address: SocketAddr) -> Counts {
    runtime().block_on(async {
        let tcp = tokio::net::TcpStream::connect(address).await.unwrap();
        tcp.set_nodelay(true).unwrap();
        let (mut sender, connection) = http2::handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(connection);
        let uri: Uri = format!("http://{address}/coredns.dns.DnsService/Query")
            .parse()
            .unwrap();
        let message = Bytes::from(framed(&QUERY));
        let mut out = Vec::with_capacity(512);
        let mut run = async |count: usize| {
            let before = GLOBAL.stats();
            for _ in 0..count {
                sender.ready().await.unwrap();
                let request = Request::post(uri.clone())
                    .header(CONTENT_TYPE, HeaderValue::from_static("application/grpc"))
                    .header("te", HeaderValue::from_static("trailers"))
                    .header(
                        HeaderName::from_static("grpc-timeout"),
                        HeaderValue::from_bytes(b"4999m").unwrap(),
                    )
                    .body(Full::new(message.clone()))
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

fn plugin(address: SocketAddr, options: &str, rcode: u8) -> Counts {
    let text = format!(".:0 {{\n grpc . {address} {{\n{options}\n }}\n}}");
    let blocks = parse("Corefile", &text).unwrap();
    let (mut servers, _) =
        servers(configure::<Chain>(&blocks, pharos_plugins::directives()).unwrap()).unwrap();
    let (_, server) = servers.drain().next().unwrap();
    let peer = "127.0.0.1:1000".parse().unwrap();
    runtime().block_on(async {
        let mut response = Vec::with_capacity(65535);
        let mut query = async || {
            assert_eq!(
                server
                    .handle(&QUERY, peer, Protocol::Tcp, &mut response)
                    .await,
                Action::Respond
            );
            assert_eq!(
                Message::parse(&response).unwrap().rcode().0,
                u16::from(rcode)
            );
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

fn check(name: &str, rcode: u8, options: &str) {
    if crate::run_isolated(name) {
        return;
    }
    let (address, thread) = upstream(rcode);
    let baseline = bare_hyper(address);
    thread.join().unwrap();
    let (address, thread) = upstream(rcode);
    let measured = plugin(address, options, rcode);
    drop(thread);
    println!(
        "bare hyper: {} allocations, {} reallocations; grpc: {}, {}",
        baseline.allocations, baseline.reallocations, measured.allocations, measured.reallocations
    );
    // Whatever hyper, http and h2 allocate per call is theirs; Pharos adds none on top.
    assert!(measured.allocations <= baseline.allocations);
    assert!(measured.reallocations <= baseline.reallocations);
}

#[test]
fn warmed_grpc_queries_allocate_only_inside_hyper() {
    check(
        "grpc::grpc_allocations::warmed_grpc_queries_allocate_only_inside_hyper",
        0,
        "",
    );
}

#[test]
fn warmed_nxdomain_fallthrough_allocates_only_inside_hyper() {
    check(
        "grpc::grpc_allocations::warmed_nxdomain_fallthrough_allocates_only_inside_hyper",
        3,
        "fallthrough",
    );
}
