use super::*;
use crate::proxyproto::Policy;

// PROXY protocol §2.2: a PROXY command, IPv4, DGRAM, from `source` to 192.0.2.53:53.
fn datagram(source: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let mut wire = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    wire.extend([0x21, 0x12, 0, 12]);
    wire.extend(source);
    wire.extend([192, 0, 2, 53]);
    wire.extend(12345u16.to_be_bytes());
    wire.extend(53u16.to_be_bytes());
    wire.extend(payload);
    wire
}

fn meta(length: usize, stride: usize) -> RecvMeta {
    RecvMeta {
        addr: "10.0.0.1:5000".parse().unwrap(),
        len: length,
        stride,
        ..RecvMeta::default()
    }
}

const TTL: Duration = Duration::from_secs(10);

#[derive(Default)]
struct Fixture {
    recv: Recv,
    routes: Routes,
}

impl Fixture {
    fn accept(&mut self, config: &Config, wire: &mut [u8], meta: &mut RecvMeta) {
        self.recv
            .accept((config, &mut self.routes, TTL), wire, meta, Instant::now());
    }
}

fn use_all() -> Config {
    Config::new(|_| Policy::Use)
}

fn proxy(port: u16) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, 1], port))
}

#[test]
fn a_single_datagram_is_stripped_in_place_and_attributed_to_its_client() {
    let mut wire = datagram([192, 0, 2, 1], b"quic");
    let mut meta = meta(wire.len(), wire.len());
    Fixture::default().accept(&use_all(), &mut wire, &mut meta);
    assert_eq!(&wire[..meta.len], b"quic");
    assert_eq!((meta.len, meta.stride), (4, 4));
    assert_eq!(meta.addr, "192.0.2.1:12345".parse().unwrap());
}

#[test]
fn a_malformed_header_drops_the_datagram() {
    let mut wire = datagram([192, 0, 2, 1], b"quic");
    wire[12] = 0x23;
    let mut meta = meta(wire.len(), wire.len());
    Fixture::default().accept(&use_all(), &mut wire, &mut meta);
    assert_eq!(meta.len, 0);
}

// UDP GRO: segments of one buffer may name different clients, so each is delivered on its own.
#[test]
fn coalesced_datagrams_are_split_and_each_keeps_its_client() {
    let mut wire = datagram([192, 0, 2, 1], b"aa");
    let stride = wire.len();
    wire.extend(datagram([192, 0, 2, 2], b"bb"));
    wire.extend(b"cc");
    let mut meta = meta(wire.len(), stride);
    let mut fixture = Fixture::default();
    fixture.accept(&use_all(), &mut wire, &mut meta);
    assert_eq!(meta.len, 0);
    let got = delivered(&mut fixture.recv);
    assert_eq!(got.len(), 3);
    assert_eq!(got[0], ("192.0.2.1:12345".parse().unwrap(), b"aa".to_vec()));
    assert_eq!(got[1], ("192.0.2.2:12345".parse().unwrap(), b"bb".to_vec()));
    // The last segment is a headerless datagram of the proxy itself.
    assert_eq!(got[2], (proxy(5000), b"cc".to_vec()));
}

fn delivered(recv: &mut Recv) -> Vec<(SocketAddr, Vec<u8>)> {
    let mut buffers = [vec![0; 2048], vec![0; 2048], vec![0; 2048], vec![0; 2048]];
    let mut slices: Vec<_> = buffers.iter_mut().map(|b| IoSliceMut::new(b)).collect();
    let mut metas = [RecvMeta::default(); 4];
    let count = recv.deliver(&mut slices, &mut metas);
    metas[..count]
        .iter()
        .zip(&slices)
        .map(|(meta, slice)| (meta.addr, slice[..meta.len].to_vec()))
        .collect()
}

// A datagram that follows a split batch in the same read waits behind it.
#[test]
fn a_datagram_after_a_split_batch_keeps_its_place_in_line() {
    let mut batch = datagram([192, 0, 2, 1], b"aa");
    let stride = batch.len();
    batch.extend(datagram([192, 0, 2, 1], b"bb"));
    let mut first = meta(batch.len(), stride);
    let mut next = datagram([192, 0, 2, 1], b"cc");
    let mut second = meta(next.len(), next.len());
    let mut fixture = Fixture::default();
    fixture.accept(&use_all(), &mut batch, &mut first);
    fixture.accept(&use_all(), &mut next, &mut second);
    assert_eq!((first.len, second.len), (0, 0));
    let payloads: Vec<_> = delivered(&mut fixture.recv)
        .into_iter()
        .map(|(_, payload)| payload)
        .collect();
    assert_eq!(payloads, [b"aa".to_vec(), b"bb".to_vec(), b"cc".to_vec()]);
}

#[test]
fn a_client_is_remembered_with_its_proxy_and_tlvs() {
    let mut config = use_all();
    config.tlv_metadata = true;
    let mut wire = datagram([192, 0, 2, 1], b"quic");
    // PROXY protocol §2.2.7: one TLV of type 0xEA after the address block.
    wire.splice(wire.len() - 4..wire.len() - 4, [0xEA, 0, 1, 7]);
    wire[15] = 16;
    let mut meta = meta(wire.len(), wire.len());
    let mut fixture = Fixture::default();
    fixture.accept(&config, &mut wire, &mut meta);
    let client = "192.0.2.1:12345".parse().unwrap();
    let mut tlv = String::new();
    let route =
        fixture
            .routes
            .sessions
            .as_mut()
            .unwrap()
            .lookup(client, Instant::now(), TTL, &mut tlv);
    assert_eq!(route, Some(proxy(5000)));
    assert_eq!(tlv, "ea000107");
}

// A live route belongs to the proxy that opened it, so a second proxy cannot take over the client.
#[test]
fn another_proxy_cannot_claim_a_client_with_a_live_route() {
    let mut fixture = Fixture::default();
    let mut wire = datagram([192, 0, 2, 1], b"one");
    let mut owner = meta(wire.len(), wire.len());
    fixture.accept(&use_all(), &mut wire, &mut owner);
    assert_eq!(&wire[..owner.len], b"one");
    let mut wire = datagram([192, 0, 2, 1], b"two");
    let mut thief = RecvMeta {
        addr: proxy(6000),
        ..meta(wire.len(), wire.len())
    };
    fixture.accept(&use_all(), &mut wire, &mut thief);
    assert_eq!(thief.len, 0);
    let mut wire = datagram([192, 0, 2, 1], b"three");
    let mut again = meta(wire.len(), wire.len());
    fixture.accept(&use_all(), &mut wire, &mut again);
    assert_eq!(&wire[..again.len], b"three");
}
