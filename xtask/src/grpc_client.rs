use std::{sync::Arc, time::Duration};

use bytes::Bytes;
use tokio::io::AsyncWriteExt;

// CoreDNS pb/dns.proto: `DnsPacket { bytes msg = 1; }` served as coredns.dns.DnsService/Query.
const PATH: &str = "https://localhost/coredns.dns.DnsService/Query";

// gRPC over HTTP/2 §Length-Prefixed-Message: compressed flag, then a four-octet big-endian length.
// Protocol Buffers encoding: field 1, wire type 2 (tag 0x0a), varint length, then the Message.
fn frame(wire: &[u8]) -> Result<Vec<u8>, String> {
    let mut packet = vec![0x0a];
    let mut length = wire.len();
    loop {
        let low = (length & 0x7f) as u8;
        length >>= 7;
        if length == 0 {
            packet.push(low);
            break;
        }
        packet.push(low | 0x80);
    }
    packet.extend_from_slice(wire);
    let mut framed = vec![0];
    framed.extend_from_slice(
        &u32::try_from(packet.len())
            .map_err(|e| e.to_string())?
            .to_be_bytes(),
    );
    framed.extend_from_slice(&packet);
    Ok(framed)
}

fn varint(bytes: &[u8]) -> Result<(usize, &[u8]), String> {
    let mut value = 0usize;
    for (index, byte) in bytes.iter().enumerate().take(3) {
        value |= usize::from(byte & 0x7f) << (7 * index);
        if byte & 0x80 == 0 {
            return Ok((value, &bytes[index + 1..]));
        }
    }
    Err("bad varint".into())
}

fn unframe(body: &[u8]) -> Result<Vec<u8>, String> {
    let [0, a, b, c, d, packet @ ..] = body else {
        return Err("bad gRPC message prefix".into());
    };
    if packet.len() != u32::from_be_bytes([*a, *b, *c, *d]) as usize {
        return Err("gRPC message length mismatch".into());
    }
    let (&0x0a, rest) = packet.split_first().ok_or("empty DnsPacket")? else {
        return Err("DnsPacket field 1 missing".into());
    };
    let (length, message) = varint(rest)?;
    if message.len() != length {
        return Err("DnsPacket length mismatch".into());
    }
    Ok(message.to_vec())
}

// One unary call on a fresh HTTP/2 connection; `preface` is written to the TCP stream first (PROXY header).
pub(crate) fn exchange(
    port: u16,
    wire: &[u8],
    preface: &[u8],
    tls: Arc<rustls::ClientConfig>,
    timeout: Duration,
) -> Result<Vec<u8>, String> {
    let framed = frame(wire)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;
    let call = async {
        let mut tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .map_err(|e| e.to_string())?;
        tcp.write_all(preface).await.map_err(|e| e.to_string())?;
        let name =
            rustls::pki_types::ServerName::try_from("localhost").map_err(|e| e.to_string())?;
        let stream = tokio_rustls::TlsConnector::from(tls)
            .connect(name, tcp)
            .await
            .map_err(|e| e.to_string())?;
        let (mut sender, connection) = h2::client::handshake(stream)
            .await
            .map_err(|e| e.to_string())?;
        tokio::spawn(connection);
        let request = http::Request::post(PATH)
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .map_err(|e| e.to_string())?;
        let (response, mut request_stream) = sender
            .send_request(request, false)
            .map_err(|e| e.to_string())?;
        request_stream
            .send_data(Bytes::from(framed), true)
            .map_err(|e| e.to_string())?;
        let response = response.await.map_err(|e| e.to_string())?;
        if response.status() != http::StatusCode::OK {
            return Err(format!("HTTP status: {}", response.status()));
        }
        let (head, mut body) = response.into_parts();
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.map_err(|e| e.to_string())?;
            body.flow_control()
                .release_capacity(chunk.len())
                .map_err(|e| e.to_string())?;
            data.extend_from_slice(&chunk);
        }
        // gRPC over HTTP/2 §Responses: the status is in the trailers, or in the headers for Trailers-Only.
        let trailers = body.trailers().await.map_err(|e| e.to_string())?;
        let status = trailers
            .as_ref()
            .and_then(|trailers| trailers.get("grpc-status"))
            .or_else(|| head.headers.get("grpc-status"))
            .ok_or("missing grpc-status")?;
        if status.as_bytes() != b"0" {
            let message = trailers
                .as_ref()
                .and_then(|trailers| trailers.get("grpc-message"))
                .or_else(|| head.headers.get("grpc-message"));
            return Err(format!("grpc-status {status:?}: {message:?}"));
        }
        unframe(&data)
    };
    runtime
        .block_on(async { tokio::time::timeout(timeout, call).await })
        .map_err(|e| e.to_string())?
}

#[cfg(test)]
mod tests {
    use super::{frame, unframe};

    #[test]
    fn frames_a_message_as_a_length_prefixed_dns_packet() {
        // Worked example: 3-octet message -> field tag 0x0a, length 3, message; prefix length 5.
        assert_eq!(
            frame(&[1, 2, 3]).unwrap(),
            [0, 0, 0, 0, 5, 0x0a, 3, 1, 2, 3]
        );
    }

    #[test]
    fn long_messages_use_a_two_octet_varint() {
        let framed = frame(&[7; 300]).unwrap();
        // 300 = 0b1_0010_1100 -> 0xac 0x02.
        assert_eq!(&framed[..8], [0, 0, 0, 1, 47, 0x0a, 0xac, 0x02]);
        assert_eq!(unframe(&framed).unwrap(), vec![7; 300]);
    }

    #[test]
    fn rejects_compressed_or_mismatched_messages() {
        assert!(unframe(&[1, 0, 0, 0, 0]).is_err());
        assert!(unframe(&[0, 0, 0, 0, 3, 0x0a, 5, 1]).is_err());
        assert!(unframe(&[0, 0, 0, 0, 4, 0x0a, 1, 1]).is_err());
    }
}
