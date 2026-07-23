use crate::{
    error::Error, CKR_ARGUMENTS_BAD, CKR_DATA_LEN_RANGE, CKR_DEVICE_ERROR,
    CKR_ENCRYPTED_DATA_INVALID,
};
use aes::{
    cipher::{consts::U16, Block, BlockDecrypt, BlockEncrypt, BlockSizeUser, KeyInit},
    Aes128, Aes192, Aes256,
};
use cmac::{Cmac, Mac};

pub(crate) const AES_BLOCK_SIZE: usize = 16;

#[derive(Clone, Copy)]
pub(crate) enum Direction {
    Encrypt,
    Decrypt,
}

pub(crate) fn aes_cmac(key: &[u8], data: &[u8]) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    macro_rules! calculate {
        ($cipher:ty) => {{
            let mut mac = <Cmac<$cipher> as Mac>::new_from_slice(key)
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
            mac.update(data);
            let bytes = mac.finalize().into_bytes();
            let mut output = [0; AES_BLOCK_SIZE];
            output.copy_from_slice(&bytes);
            Ok(output)
        }};
    }

    match key.len() {
        16 => calculate!(Aes128),
        24 => calculate!(Aes192),
        32 => calculate!(Aes256),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

pub(crate) fn aes_encrypt_block(
    key: &[u8],
    block: &[u8; AES_BLOCK_SIZE],
) -> Result<[u8; AES_BLOCK_SIZE], Error> {
    aes_ecb(key, block, Direction::Encrypt)?
        .try_into()
        .map_err(|_| CKR_DEVICE_ERROR.into())
}

pub(crate) fn aes_ecb(key: &[u8], data: &[u8], direction: Direction) -> Result<Vec<u8>, Error> {
    crypt(key, None, data, direction)
}

pub(crate) fn aes_cbc(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    if iv.len() != AES_BLOCK_SIZE {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    crypt(key, Some(iv), data, direction)
}

fn crypt(
    key: &[u8],
    iv: Option<&[u8]>,
    data: &[u8],
    direction: Direction,
) -> Result<Vec<u8>, Error> {
    if !crate::is_multiple_of(data.len(), AES_BLOCK_SIZE) {
        return Err(CKR_DATA_LEN_RANGE.into());
    }

    fn apply<C>(
        key: &[u8],
        iv: Option<&[u8]>,
        data: &[u8],
        direction: Direction,
    ) -> Result<Vec<u8>, Error>
    where
        C: BlockEncrypt + BlockDecrypt + BlockSizeUser<BlockSize = U16> + KeyInit,
    {
        let cipher = C::new_from_slice(key).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let mut output = Vec::with_capacity(data.len());
        let mut chaining = iv.map(|value| {
            let mut block = [0; AES_BLOCK_SIZE];
            block.copy_from_slice(value);
            block
        });

        for input in data.chunks_exact(AES_BLOCK_SIZE) {
            let mut block = Block::<C>::default();
            block.copy_from_slice(input);
            match direction {
                Direction::Encrypt => {
                    if let Some(previous) = chaining {
                        for (byte, previous) in block.iter_mut().zip(previous) {
                            *byte ^= previous;
                        }
                    }
                    cipher.encrypt_block(&mut block);
                    if chaining.is_some() {
                        let mut ciphertext = [0; AES_BLOCK_SIZE];
                        ciphertext.copy_from_slice(&block);
                        chaining = Some(ciphertext);
                    }
                    output.extend_from_slice(&block);
                }
                Direction::Decrypt => {
                    let mut ciphertext = [0; AES_BLOCK_SIZE];
                    ciphertext.copy_from_slice(&block);
                    cipher.decrypt_block(&mut block);
                    if let Some(previous) = chaining {
                        for (byte, previous) in block.iter_mut().zip(previous) {
                            *byte ^= previous;
                        }
                        chaining = Some(ciphertext);
                    }
                    output.extend_from_slice(&block);
                }
            }
        }
        Ok(output)
    }

    match key.len() {
        16 => apply::<Aes128>(key, iv, data, direction),
        24 => apply::<Aes192>(key, iv, data, direction),
        32 => apply::<Aes256>(key, iv, data, direction),
        _ => Err(CKR_ARGUMENTS_BAD.into()),
    }
}

pub(crate) fn pad_iso7816(data: &[u8]) -> Vec<u8> {
    let padded_len = (data.len() + 1).div_ceil(AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    let mut padded = Vec::with_capacity(padded_len);
    padded.extend_from_slice(data);
    padded.push(0x80);
    padded.resize(padded_len, 0);
    padded
}

pub(crate) fn unpad_iso7816(mut data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let Some(marker) = data.iter().rposition(|byte| *byte != 0) else {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    };
    if data[marker] != 0x80 {
        return Err(CKR_ENCRYPTED_DATA_INVALID.into());
    }
    data.truncate(marker);
    Ok(data)
}

pub(crate) fn scp03_kdf(
    key: &[u8],
    constant: u8,
    context: &[u8],
    output_bits: u16,
) -> Result<Vec<u8>, Error> {
    if output_bits == 0 || !crate::is_multiple_of(output_bits, 8) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let output_len = output_bits as usize / 8;
    let iterations = output_len.div_ceil(AES_BLOCK_SIZE);
    if iterations > u8::MAX as usize {
        return Err(CKR_DATA_LEN_RANGE.into());
    }

    let mut output = Vec::with_capacity(iterations * AES_BLOCK_SIZE);
    for counter in 1..=iterations {
        let mut input = Vec::with_capacity(16 + context.len());
        input.extend_from_slice(&[0; 11]);
        input.push(constant);
        input.push(0);
        input.extend_from_slice(&output_bits.to_be_bytes());
        input.push(counter as u8);
        input.extend_from_slice(context);
        output.extend_from_slice(&aes_cmac(key, &input)?);
    }
    output.truncate(output_len);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(value: &str) -> Vec<u8> {
        value
            .split_whitespace()
            .flat_map(|word| {
                (0..word.len())
                    .step_by(2)
                    .map(|offset| u8::from_str_radix(&word[offset..offset + 2], 16).unwrap())
            })
            .collect()
    }

    #[test]
    fn shared_aes_primitives_match_nist_vectors() {
        let key = hex("2b7e151628aed2a6abf7158809cf4f3c");
        let plaintext = hex("6bc1bee22e409f96e93d7e117393172a");
        assert_eq!(
            aes_cmac(&key, &plaintext).unwrap().as_slice(),
            hex("070a16b46b4d4144f79bdd9dd04a287c")
        );
        assert_eq!(
            aes_encrypt_block(&key, plaintext.as_slice().try_into().unwrap()).unwrap(),
            hex("3ad77bb40d7a3660a89ecaf32466ef97").as_slice()
        );
        assert_eq!(
            aes_cbc(
                &key,
                &hex("000102030405060708090a0b0c0d0e0f"),
                &plaintext,
                Direction::Encrypt,
            )
            .unwrap(),
            hex("7649abac8119b246cee98e9b12e9197d")
        );
    }

    #[test]
    fn shared_padding_and_kdf_match_secure_channel_layouts() {
        let plaintext = b"secure channel";
        assert_eq!(unpad_iso7816(pad_iso7816(plaintext)).unwrap(), plaintext);
        assert!(unpad_iso7816(vec![0; AES_BLOCK_SIZE]).is_err());

        assert_eq!(
            scp03_kdf(
                &hex("404142434445464748494a4b4c4d4e4f"),
                0x04,
                &hex("0102030405060708 1112131415161718"),
                128,
            )
            .unwrap(),
            hex("d99675d4a95c58de629225730cddb758")
        );
    }
}
