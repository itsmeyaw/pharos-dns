// RFC 1982 §3.2: Compare serials in modulo-2^32 half-space order.
#[cfg(any(feature = "plugin-transfer", feature = "plugin-secondary"))]
pub(crate) fn serial_at_least(candidate: u32, current: u32) -> bool {
    candidate.wrapping_sub(current) < (1 << 31)
}
