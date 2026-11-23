//! Frame Streams (https://farsightsec.github.io/fstrm/) wire format and the bidirectional handshake.
use super::*;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream, duplex};

const CT: &[u8] = b"protobuf:dnstap.Dnstap";
const TIMEOUT: Duration = Duration::from_secs(4);

fn control(kind: ControlType, content_types: &[&[u8]]) -> Vec<u8> {
    let mut buf = Vec::new();
    put_control(&mut buf, kind, content_types);
    buf
}

async fn send(peer: &mut DuplexStream, kind: ControlType, content_types: &[&[u8]]) {
    peer.write_all(&control(kind, content_types)).await.unwrap();
}

async fn expect(peer: &mut DuplexStream, kind: ControlType, content_types: &[&[u8]]) {
    let got = read_control(peer).await.unwrap();
    assert_eq!(got.kind, kind as u32);
    assert_eq!(got.content_types, content_types);
}

// Test receiver: the other end of a bidirectional stream, as golang-dnstap's decoder behaves.
async fn read_data(peer: &mut DuplexStream) -> Vec<u8> {
    let len = peer.read_u32().await.unwrap();
    assert_ne!(len, 0, "control frame where data was expected");
    let mut payload = vec![0; len as usize];
    peer.read_exact(&mut payload).await.unwrap();
    payload
}

// Frame Streams: data frame = 32-bit big-endian length, then payload.
#[tokio::test]
async fn data_frame_golden_bytes() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        let mut frame = [0; 7];
        peer.read_exact(&mut frame).await.unwrap();
        frame
    });
    let mut encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    encoder.write_frame(&[0xaa, 0xbb, 0xcc]).await.unwrap();
    encoder.flush().await.unwrap();
    assert_eq!(receiver.await.unwrap(), [0, 0, 0, 3, 0xaa, 0xbb, 0xcc]);
}

// Frame Streams: control frame = 00 00 00 00 escape, control length, control type, then CONTENT_TYPE fields (type 1, length, bytes).
#[test]
fn control_frame_golden_bytes() {
    let mut expected = vec![
        0, 0, 0, 0, 0, 0, 0, 0x22, 0, 0, 0, 4, 0, 0, 0, 1, 0, 0, 0, 22,
    ];
    expected.extend_from_slice(CT);
    assert_eq!(control(ControlType::Ready, &[CT]), expected);
    assert_eq!(
        control(ControlType::Stop, &[]),
        [0, 0, 0, 0, 0, 0, 0, 4, 0, 0, 0, 3]
    );
    assert_eq!(
        control(ControlType::Start, &[b"a", b"bc"]),
        [
            0, 0, 0, 0, 0, 0, 0, 0x17, 0, 0, 0, 2, // START
            0, 0, 0, 1, 0, 0, 0, 1, b'a', // CONTENT_TYPE "a"
            0, 0, 0, 1, 0, 0, 0, 2, b'b', b'c', // CONTENT_TYPE "bc"
        ]
    );
}

#[test]
fn control_type_numbers() {
    assert_eq!(
        [
            ControlType::Accept as u32,
            ControlType::Start as u32,
            ControlType::Stop as u32,
            ControlType::Ready as u32,
            ControlType::Finish as u32
        ],
        [1, 2, 3, 4, 5]
    );
}

#[tokio::test]
async fn read_control_roundtrips_and_leaves_following_bytes() {
    let mut bytes = control(ControlType::Accept, &[b"a", b"bc"]);
    bytes.extend_from_slice(&[9, 9]);
    let mut rest = &bytes[..];
    let got = read_control(&mut rest).await.unwrap();
    assert_eq!(got.kind, 1);
    assert_eq!(got.content_types, [b"a".to_vec(), b"bc".to_vec()]);
    assert_eq!(rest, [9, 9]);
}

// golang-framestream Control.go Decode: escape must be zero; length 4..=512.
#[tokio::test]
async fn read_control_rejects_malformed_frames() {
    let mut huge = vec![0, 0, 0, 0, 0, 0, 2, 1];
    huge.resize(8 + 513, 0);
    for bytes in [
        &[0, 0, 0, 1, 0, 0, 0, 4, 0, 0, 0, 1][..], // data frame, not the escape
        &[0, 0, 0, 0, 0, 0, 0, 3, 0, 0, 0][..],    // shorter than the control type
        &huge[..],                                 // longer than 512 bytes
        &[0, 0, 0, 0, 0, 0, 0, 8, 0, 0, 0, 1, 0, 0, 0, 9][..], // unknown field type
        &[
            0, 0, 0, 0, 0, 0, 0, 13, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 9, 1,
        ][..], // field longer than frame
        &[0, 0, 0, 0, 0, 0, 0, 5, 0, 0, 0, 1, 7][..], // trailing garbage
    ] {
        let mut input = bytes;
        let error = read_control(&mut input).await.unwrap_err();
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::InvalidData | io::ErrorKind::UnexpectedEof
            ),
            "{bytes:?}: {error}"
        );
    }
}

#[tokio::test]
async fn handshake_data_and_close() {
    let (local, mut peer) = duplex(64 * 1024);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        assert_eq!(read_data(&mut peer).await, b"one");
        assert_eq!(read_data(&mut peer).await, b"two");
        expect(&mut peer, ControlType::Stop, &[]).await;
        send(&mut peer, ControlType::Finish, &[]).await;
        peer
    });
    let mut encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    encoder.write_frame(b"one").await.unwrap();
    encoder.write_frame(b"two").await.unwrap();
    encoder.close().await.unwrap();
    receiver.await.unwrap();
}

// golang-framestream Writer.go NewWriter: an ACCEPT without content types leaves START without one.
#[tokio::test]
async fn accept_without_content_type_starts_without_one() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[]).await;
        expect(&mut peer, ControlType::Start, &[]).await;
    });
    Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    receiver.await.unwrap();
}

#[tokio::test]
async fn accept_choosing_among_several_types_starts_with_ours() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[b"other", CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
    });
    Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    receiver.await.unwrap();
}

// golang-framestream Writer.go NewWriter: ErrContentTypeMismatch when ACCEPT names only other types.
#[tokio::test]
async fn accept_of_other_content_type_fails() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[b"other"]).await;
        peer
    });
    let error = Encoder::connect(local, CT, TIMEOUT).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    receiver.await.unwrap();
}

// golang-framestream Writer.go NewWriter: DecodeTypeEscape(ACCEPT) fails on any other control type.
#[tokio::test]
async fn reply_other_than_accept_fails() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Finish, &[]).await;
        peer
    });
    let error = Encoder::connect(local, CT, TIMEOUT).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    receiver.await.unwrap();
}

// CoreDNS v1.15.0 plugin/dnstap/io.go tcpTimeout: golang-framestream gives the ACCEPT read 4 seconds.
#[tokio::test(start_paused = true)]
async fn silent_peer_times_out_the_handshake() {
    let (local, _peer) = duplex(4096);
    let error = Encoder::connect(local, CT, TIMEOUT).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

// golang-framestream Writer.go Close: a bidirectional Close waits for FINISH, within the timeout.
#[tokio::test(start_paused = true)]
async fn close_times_out_without_finish() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        peer
    });
    let encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    let _peer = receiver.await.unwrap();
    let error = encoder.close().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
}

#[tokio::test]
async fn close_rejects_a_reply_other_than_finish() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        expect(&mut peer, ControlType::Stop, &[]).await;
        send(&mut peer, ControlType::Accept, &[]).await;
        peer
    });
    let encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    let error = encoder.close().await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    receiver.await.unwrap();
}

// golang-framestream Writer.go WriteFrame buffers; only Flush (CoreDNS: every second) puts frames on the wire.
#[tokio::test(start_paused = true)]
async fn frames_stay_buffered_until_flush() {
    let (local, mut peer) = duplex(64 * 1024);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        peer
    });
    let mut encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    let mut peer = receiver.await.unwrap();
    encoder.write_frame(b"x").await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(10), peer.read_u32()).await;
    assert!(early.is_err(), "frame sent before flush");
    encoder.flush().await.unwrap();
    assert_eq!(read_data(&mut peer).await, b"x");
}

// Frame Streams: a zero length is the control escape, so an empty payload cannot be a data frame.
#[tokio::test]
async fn empty_frame_is_rejected() {
    let (local, mut peer) = duplex(4096);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        peer
    });
    let mut encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    let _peer = receiver.await.unwrap();
    let error = encoder.write_frame(&[]).await.unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
}

#[tokio::test]
async fn frames_larger_than_the_buffer_pass_through() {
    let (local, mut peer) = duplex(1024 * 1024);
    let receiver = tokio::spawn(async move {
        expect(&mut peer, ControlType::Ready, &[CT]).await;
        send(&mut peer, ControlType::Accept, &[CT]).await;
        expect(&mut peer, ControlType::Start, &[CT]).await;
        read_data(&mut peer).await
    });
    let mut encoder = Encoder::connect(local, CT, TIMEOUT).await.unwrap();
    let big = vec![7; WRITE_BUFFER * 3];
    encoder.write_frame(&big).await.unwrap();
    encoder.flush().await.unwrap();
    assert_eq!(receiver.await.unwrap(), big);
}

#[test]
fn timeout_matches_coredns() {
    // CoreDNS v1.15.0 plugin/dnstap/io.go: tcpTimeout = 4 * time.Second.
    assert_eq!(TCP_TIMEOUT, Duration::from_secs(4));
}
