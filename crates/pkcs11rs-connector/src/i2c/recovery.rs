//! Reserved HSM-frontend recovery operation; ordinary requests stay unchanged.
pub(super) fn request(token: u32) -> [u8; 16] {
    let mut frame = *b"\x00\x00\x0dBSCRECOV\x01\x00\x00\x00\x00";
    frame[12..].copy_from_slice(&token.to_be_bytes());
    frame
}

pub(super) fn reply(token: u32) -> [u8; 16] {
    let mut frame = request(token);
    frame[0] = 0x80;
    frame
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn control_uses_existing_hsm_framing_and_binds_the_token() {
        let frame = request(0x12345678);
        assert_eq!(frame, *b"\x00\x00\x0dBSCRECOV\x01\x12\x34\x56\x78");
        assert_eq!(
            u16::from_be_bytes([frame[1], frame[2]]) as usize,
            frame.len() - 3
        );
        assert_eq!(&reply(0x12345678)[1..], &frame[1..]);
        assert_eq!(reply(0)[0], 0x80);
        assert_ne!(reply(1), reply(2));
    }
}
