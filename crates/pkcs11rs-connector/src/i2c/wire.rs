//! Versioned target-driver control framing; never exposed as an HSM command.

pub(super) const OVERHEAD: usize = 16;
pub(super) const MAX_REQUEST: usize = 8192 - OVERHEAD;
const MAGIC: &[u8; 4] = b"BSC\x04";

pub(super) fn encode(payload: &[u8], recovery: bool, token: u32) -> Vec<u8> {
    assert!(payload.len() <= MAX_REQUEST);
    assert!(!recovery || payload.is_empty());
    let mut frame = Vec::with_capacity(payload.len() + OVERHEAD);
    frame.extend_from_slice(MAGIC);
    frame.extend_from_slice(&[if recovery { 2 } else { 1 }, 0]);
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(&token.to_be_bytes());
    frame.extend_from_slice(payload);
    frame.extend_from_slice(&crc32(&frame).to_be_bytes());
    frame
}

pub(super) fn recovery_reply(token: u32) -> [u8; 11] {
    let mut reply = [0x80, 0, 8, b'B', b'S', b'C', 4, 0, 0, 0, 0];
    reply[7..].copy_from_slice(&token.to_be_bytes());
    reply
}

fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_standard_crc_and_driver_wire_layout() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        let frame = encode(&[1, 0, 1, 0xa5], false, 0x1234_5678);
        assert_eq!(&frame[..12], b"BSC\x04\x01\x00\x00\x04\x12\x34\x56\x78");
        assert_eq!(&frame[12..16], &[1, 0, 1, 0xa5]);
        assert_eq!(
            u32::from_be_bytes(frame[16..].try_into().unwrap()),
            crc32(&frame[..16])
        );
        assert_eq!(encode(&vec![0; MAX_REQUEST], false, 0).len(), 8192);
    }

    #[test]
    fn recovery_is_distinct_and_reply_binds_the_token() {
        let frame = encode(&[], true, 0x1234_5678);
        assert_eq!(frame.len(), OVERHEAD);
        assert_eq!(frame[4], 2);
        assert_eq!(&frame[6..8], &[0, 0]);
        assert_eq!(
            &recovery_reply(0x1234_5678),
            b"\x80\x00\x08BSC\x04\x12\x34\x56\x78"
        );
        assert_ne!(recovery_reply(1), recovery_reply(2));
    }
}
