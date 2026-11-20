use std::net::{IpAddr, SocketAddr};

// PROXY protocol §2.2: every v2 header starts with this 12-octet signature.
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

// A PROXY header a Query line asks the client to send: `+proxy=v1|v2,SOURCE[,tlv=HEX][,first]`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Proxy {
    version: u8,
    source: SocketAddr,
    tlv: Vec<u8>,
    first: bool,
}

impl Proxy {
    pub(crate) fn parse(value: &str) -> Result<Self, String> {
        let mut parts = value.split(',');
        let version = match parts.next() {
            Some("v1") => 1,
            Some("v2") => 2,
            _ => return Err(format!("invalid PROXY version: {value}")),
        };
        let source = parts
            .next()
            .and_then(|source| source.parse().ok())
            .ok_or_else(|| format!("invalid PROXY source: {value}"))?;
        let (mut tlv, mut first) = (Vec::new(), false);
        for part in parts {
            if let Some(hex) = part.strip_prefix("tlv=") {
                let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
                if !remainder.is_empty() || version == 1 {
                    return Err(format!("invalid PROXY TLV: {value}"));
                }
                tlv = pairs
                    .iter()
                    .map(|pair| {
                        std::str::from_utf8(pair)
                            .ok()
                            .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                            .ok_or_else(|| format!("invalid PROXY TLV: {value}"))
                    })
                    .collect::<Result<_, _>>()?;
            } else if part == "first" && version == 2 {
                first = true;
            } else {
                return Err(format!("invalid PROXY option: {part}"));
            }
        }
        Ok(Self {
            version,
            source,
            tlv,
            first,
        })
    }

    // PROXY protocol §2.2 (Spectrum style): the header is a datagram of its own before the Query.
    pub(crate) fn header_first(&self) -> bool {
        self.first
    }

    // PROXY protocol §2.1 (v1) and §2.2 (v2): encode a header for a stream or datagram flow to `destination`.
    pub(crate) fn header(
        &self,
        datagram: bool,
        destination: SocketAddr,
    ) -> Result<Vec<u8>, String> {
        let same_family = self.source.is_ipv4() == destination.is_ipv4();
        if !same_family {
            return Err("PROXY source and destination families differ".into());
        }
        if self.version == 1 {
            if datagram {
                return Err("PROXY v1 has no datagram form".into());
            }
            let family = if self.source.is_ipv4() {
                "TCP4"
            } else {
                "TCP6"
            };
            return Ok(format!(
                "PROXY {family} {} {} {} {}\r\n",
                self.source.ip(),
                destination.ip(),
                self.source.port(),
                destination.port()
            )
            .into_bytes());
        }
        let mut addresses = Vec::new();
        for address in [self.source, destination] {
            match address.ip() {
                IpAddr::V4(ip) => addresses.extend_from_slice(&ip.octets()),
                IpAddr::V6(ip) => addresses.extend_from_slice(&ip.octets()),
            }
        }
        addresses.extend_from_slice(&self.source.port().to_be_bytes());
        addresses.extend_from_slice(&destination.port().to_be_bytes());
        addresses.extend_from_slice(&self.tlv);
        let mut header = V2_SIGNATURE.to_vec();
        // PROXY protocol §2.2: version 2 in the high nibble, command PROXY (1) in the low nibble.
        header.push(0x21);
        // PROXY protocol §2.2: address family (INET 1, INET6 2) high nibble, STREAM 1 or DGRAM 2 low nibble.
        let family = if self.source.is_ipv4() { 0x10 } else { 0x20 };
        header.push(family | if datagram { 2 } else { 1 });
        header.extend_from_slice(
            &u16::try_from(addresses.len())
                .map_err(|e| e.to_string())?
                .to_be_bytes(),
        );
        header.extend_from_slice(&addresses);
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::Proxy;

    #[test]
    fn v1_tcp4_header_matches_the_specification_example() {
        // PROXY protocol §2.1 example: "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n".
        let proxy = Proxy::parse("v1,255.255.255.255:65535").unwrap();
        assert_eq!(
            proxy
                .header(false, "255.255.255.255:65535".parse().unwrap())
                .unwrap(),
            b"PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n"
        );
        assert!(proxy.header(true, "127.0.0.1:53".parse().unwrap()).is_err());
    }

    #[test]
    fn v2_datagram_header_carries_addresses_and_tlvs() {
        let proxy = Proxy::parse("v2,192.0.2.7:4242,tlv=0a020102").unwrap();
        let header = proxy.header(true, "127.0.0.1:53".parse().unwrap()).unwrap();
        assert_eq!(&header[..12], b"\r\n\r\n\0\r\nQUIT\n");
        // 0x21 PROXY v2; 0x12 INET + DGRAM; length 12 + 4 TLV octets.
        assert_eq!(&header[12..16], [0x21, 0x12, 0, 16]);
        assert_eq!(&header[16..24], [192, 0, 2, 7, 127, 0, 0, 1]);
        assert_eq!(&header[24..28], [0x10, 0x92, 0, 53]);
        assert_eq!(&header[28..], [0x0a, 2, 1, 2]);
    }

    #[test]
    fn v6_stream_header_uses_the_inet6_family() {
        let proxy = Proxy::parse("v2,[2001:db8::1]:1").unwrap();
        let header = proxy.header(false, "[::1]:853".parse().unwrap()).unwrap();
        assert_eq!(&header[12..16], [0x21, 0x21, 0, 36]);
        assert!(
            proxy
                .header(false, "127.0.0.1:853".parse().unwrap())
                .is_err()
        );
    }

    #[test]
    fn rejects_malformed_flags() {
        for value in [
            "v3,192.0.2.7:1",
            "v2",
            "v2,192.0.2.7",
            "v2,192.0.2.7:1,tlv=0",
            "v2,192.0.2.7:1,tlv=zz",
            "v1,192.0.2.7:1,tlv=00",
            "v1,192.0.2.7:1,first",
            "v2,192.0.2.7:1,other",
        ] {
            assert!(Proxy::parse(value).is_err(), "accepted {value}");
        }
        assert!(Proxy::parse("v2,192.0.2.7:1,first").unwrap().header_first());
    }
}
