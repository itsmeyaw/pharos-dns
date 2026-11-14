#![forbid(unsafe_code)]
use pharos_plugins::proxy::{Options, Proxy, Transport};
use pharos_proto::{EdnsOption, Message, Rcode};
use stats_alloc::{INSTRUMENTED_SYSTEM, StatsAlloc};
use std::{alloc::System, net::UdpSocket, time::Duration};

static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;
const QUERY: &[u8] = &[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1];

#[test]
fn warmed_udp_exchange_does_not_allocate() {
    if crate::run_isolated("proxy::proxy_allocations::warmed_udp_exchange_does_not_allocate") {
        return;
    }
    // RFC 5452 §9.2: Keep UDP allocation sampling within one source-port use budget.
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    let registry = pharos_server::metrics::Registry::new("v", "r", "rust");
    proxy.set_metrics(&registry, "forward");
    let thread = std::thread::spawn(move || {
        let mut wire = [0; 512];
        for _ in 0..7 {
            let (len, peer) = server.recv_from(&mut wire).unwrap();
            wire[2] |= 0x80;
            server.send_to(&wire[..len], peer).unwrap();
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mut response = [0; 512];
        for _ in 0..3 {
            proxy
                .exchange(QUERY, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
        }
        let before = GLOBAL.stats();
        for _ in 0..4 {
            proxy
                .exchange(QUERY, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    thread.join().unwrap();
}

#[test]
fn warmed_ecs_multi_rr_udp_exchange_does_not_allocate() {
    if crate::run_isolated(
        "proxy::proxy_allocations::warmed_ecs_multi_rr_udp_exchange_does_not_allocate",
    ) {
        return;
    }
    // RFC 5452 §9.2: Keep UDP allocation sampling within one source-port use budget.
    let server = UdpSocket::bind("127.0.0.1:0").unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut proxy = Proxy::new(server.local_addr().unwrap());
    let registry = pharos_server::metrics::Registry::new("v", "r", "rust");
    proxy.set_metrics(&registry, "forward");
    let thread = std::thread::spawn(move || {
        let mut query = [0; 512];
        let mut response = [0; 512];
        for _ in 0..7 {
            let (len, peer) = server.recv_from(&mut query).unwrap();
            let message = Message::parse(&query[..len]).unwrap();
            let options = message.opt().unwrap().options();
            let mut options = options.iter();
            assert!(matches!(
                options.next(),
                Some(EdnsOption::ClientSubnet(subnet)) if subnet.scope_prefix() == 0
            ));
            assert!(options.next().is_none());
            let response_len = two_a_response(&query[..len], &mut response);
            server.send_to(&response[..response_len], peer).unwrap();
        }
    });
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let query = ecs_query();
    runtime.block_on(async {
        let mut response = [0; 512];
        for _ in 0..3 {
            proxy
                .exchange(&query, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
        }
        let before = GLOBAL.stats();
        for _ in 0..4 {
            proxy
                .exchange(&query, &mut response, Transport::Udp, Options::default())
                .await
                .unwrap();
        }
        let after = GLOBAL.stats();
        assert_eq!(after.allocations - before.allocations, 0);
        assert_eq!(after.reallocations - before.reallocations, 0);
    });
    thread.join().unwrap();
}

// RFC 7871 §6 and RFC 7828 §3.2.1: Exercise ECS SCOPE and UDP Keepalive sanitization.
fn ecs_query() -> Vec<u8> {
    let options = [
        0, 11, 0, 2, 0, 100, // TCP Keepalive
        0, 8, 0, 7, 0, 1, 24, 8, 192, 0, 2, // ECS
    ];
    let mut query = QUERY.to_vec();
    query[10..12].copy_from_slice(&1_u16.to_be_bytes());
    let opt_start = query.len();
    query.extend_from_slice(&[0, 0, 41, 4, 208, 0, 0, 0, 0, 0, 0]);
    query[opt_start + 9..opt_start + 11]
        .copy_from_slice(&u16::try_from(options.len()).unwrap().to_be_bytes());
    query.extend_from_slice(&options);
    query
}

// RFC 1035 §§4.1.1, 4.1.3: Build two A records without allocating in the fake server.
fn two_a_response(query: &[u8], response: &mut [u8]) -> usize {
    let message = Message::parse(query).unwrap();
    let question_len = 12 + message.questions().next().unwrap().name.wire_len() + 4;
    response[..question_len].copy_from_slice(&query[..question_len]);
    response[2] |= 0x80;
    response[3] = Rcode::NOERROR.0 as u8;
    response[6..8].copy_from_slice(&2_u16.to_be_bytes());
    response[10..12].fill(0);
    let records = [
        0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0,
        60, 0, 4, 192, 0, 2, 2,
    ];
    response[question_len..question_len + records.len()].copy_from_slice(&records);
    question_len + records.len()
}
