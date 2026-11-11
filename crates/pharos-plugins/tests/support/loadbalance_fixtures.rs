#![forbid(unsafe_code)]

pub fn cdn_response() -> Vec<u8> {
    let mut wire = vec![0, 1, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0];
    wire.extend_from_slice(b"\x03www\x07example\x03com\0\0\x01\0\x01");
    wire.extend_from_slice(b"\xc0\x0c\0\x05\0\x01\0\0\0\x1e\0\x11");
    let target = wire.len();
    wire.extend_from_slice(b"\x03cdn\x07example\x03net\0");
    for last in 1..=4 {
        wire.extend_from_slice(&[
            0xc0,
            target as u8,
            0,
            1,
            0,
            1,
            0,
            0,
            0,
            30,
            0,
            4,
            192,
            0,
            2,
            last,
        ]);
    }
    wire
}

#[allow(dead_code)]
pub fn cdn_query() -> Vec<u8> {
    let mut wire = cdn_response();
    wire.truncate(33);
    wire[2..4].copy_from_slice(&[1, 0]);
    wire[6..8].copy_from_slice(&[0, 0]);
    wire
}
