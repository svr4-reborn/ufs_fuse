//! Little-endian field accessors.
//!
//! Direct counterparts of the `u16`/`u32`/`i32` helpers in
//! `host_tools/fs/common.py`, plus their write-side equivalents. The whole
//! on-disk format is little-endian (AT386/x86), so these never need a byte-order
//! parameter.
//!
//! All readers panic on out-of-range offsets, matching the Python behaviour of
//! raising on a bad slice — callers operate on validated structures and a bad
//! offset is a bug, not recoverable input.

/// Read an unsigned 16-bit little-endian value at `offset`.
#[inline]
pub fn u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([buf[offset], buf[offset + 1]])
}

/// Read an unsigned 32-bit little-endian value at `offset`.
#[inline]
pub fn u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read a signed 32-bit little-endian value at `offset`.
#[inline]
pub fn i32(buf: &[u8], offset: usize) -> i32 {
    i32::from_le_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read an unsigned 64-bit little-endian value at `offset`.
#[inline]
pub fn u64(buf: &[u8], offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&buf[offset..offset + 8]);
    u64::from_le_bytes(bytes)
}

/// Write an unsigned 16-bit little-endian value at `offset`.
#[inline]
pub fn put_u16(buf: &mut [u8], offset: usize, value: u16) {
    buf[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

/// Write an unsigned 32-bit little-endian value at `offset`.
#[inline]
pub fn put_u32(buf: &mut [u8], offset: usize, value: u32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write a signed 32-bit little-endian value at `offset`.
#[inline]
pub fn put_i32(buf: &mut [u8], offset: usize, value: i32) {
    buf[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

/// Write an unsigned 64-bit little-endian value at `offset`.
#[inline]
pub fn put_u64(buf: &mut [u8], offset: usize, value: u64) {
    buf[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let mut buf = [0u8; 24];
        put_u16(&mut buf, 0, 0xBEEF);
        put_u32(&mut buf, 2, 0xDEAD_C0DE);
        put_i32(&mut buf, 6, -2);
        put_u64(&mut buf, 10, 0x0102_0304_0506_0708);
        assert_eq!(u16(&buf, 0), 0xBEEF);
        assert_eq!(u32(&buf, 2), 0xDEAD_C0DE);
        assert_eq!(i32(&buf, 6), -2);
        assert_eq!(u64(&buf, 10), 0x0102_0304_0506_0708);
    }

    #[test]
    fn little_endian_byte_order() {
        let buf = [0x34, 0x12, 0x00, 0x00];
        assert_eq!(u16(&buf, 0), 0x1234);
        assert_eq!(u32(&buf, 0), 0x0000_1234);
    }
}
