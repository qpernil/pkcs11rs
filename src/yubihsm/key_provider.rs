//! YubiHSM derivation through scoped objects, followed by local message crypto.
use crate::{
    key_scope::{BoundKey, KeyHandle, Pkcs11KeyScope, SymmetricCredential, generic_template},
    *,
};
use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat, LengthMethod};

/// Only channel-specific working keys leave the derivation provider. This
/// object owns their zeroizing storage and never retains provider handles.
pub(super) struct SessionKeys {
    material: Option<LocalKeys>,
}

struct LocalKeys {
    enc: Zeroizing<[u8; 16]>,
    mac: Zeroizing<[u8; 16]>,
    rmac: Zeroizing<[u8; 16]>,
}

/// Readability is chosen at derivation, never by changing an existing object.
fn readable(mut template: TokenObjectTemplate) -> TokenObjectTemplate {
    template.sensitive = Some(false);
    template.extractable = Some(true);
    template
}

fn template(
    encrypt: bool,
    decrypt: bool,
    sign: bool,
    verify: bool,
    mechanisms: &[CK_MECHANISM_TYPE],
) -> TokenObjectTemplate {
    TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as _),
        key_type: Some(CKK_AES as _),
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        encrypt,
        decrypt,
        sign,
        verify,
        allowed_mechanisms: Some(mechanisms.to_vec()),
        ..Default::default()
    }
}

fn enc_template() -> TokenObjectTemplate {
    template(
        true,
        true,
        false,
        false,
        &[CKM_AES_ECB as _, CKM_AES_CBC as _],
    )
}
fn mac_template() -> TokenObjectTemplate {
    template(false, false, true, false, &[CKM_AES_CMAC as _])
}
fn rmac_template() -> TokenObjectTemplate {
    template(false, false, false, true, &[CKM_AES_CMAC_GENERAL as _])
}

impl SessionKeys {
    pub(super) fn import(enc: &[u8], mac: &[u8], rmac: &[u8]) -> Result<Self, Error> {
        fn copy(value: &[u8]) -> Result<Zeroizing<[u8; 16]>, Error> {
            if value.len() != 16 {
                return Err(CKR_KEY_SIZE_RANGE.into());
            }
            let mut key = Zeroizing::new([0; 16]);
            key.copy_from_slice(value);
            Ok(key)
        }
        Ok(Self {
            material: Some(LocalKeys {
                enc: copy(enc)?,
                mac: copy(mac)?,
                rmac: copy(rmac)?,
            }),
        })
    }

    fn read_working_keys(
        scope: Pkcs11KeyScope,
        enc: KeyHandle,
        mac: KeyHandle,
        rmac: KeyHandle,
    ) -> Result<Self, Error> {
        // Scope ownership guarantees destruction of every intermediate and
        // output object on both success and any partial read failure.
        Ok(Self {
            material: Some(LocalKeys {
                enc: scope.read_aes128(&enc)?,
                mac: scope.read_aes128(&mac)?,
                rmac: scope.read_aes128(&rmac)?,
            }),
        })
    }

    fn material(&self) -> Result<&LocalKeys, Error> {
        self.material
            .as_ref()
            .ok_or_else(|| CKR_KEY_HANDLE_INVALID.into())
    }

    pub(super) fn iv(&self, counter: &[u8; 16]) -> Result<[u8; 16], Error> {
        crate::secure_channel_crypto::aes_encrypt_block(&self.material()?.enc[..], counter)
    }

    pub(super) fn cbc(&self, iv: &[u8; 16], input: &[u8], encrypt: bool) -> Result<Vec<u8>, Error> {
        use crate::secure_channel_crypto::{Direction, aes_cbc};
        aes_cbc(
            &self.material()?.enc[..],
            iv,
            input,
            if encrypt {
                Direction::Encrypt
            } else {
                Direction::Decrypt
            },
        )
    }

    pub(super) fn command_mac(&self, input: &[u8]) -> Result<[u8; 16], Error> {
        crate::secure_channel_crypto::aes_cmac(&self.material()?.mac[..], input)
    }

    pub(super) fn verify_response_mac(&self, input: &[u8], signature: &[u8]) -> Result<(), Error> {
        use subtle::ConstantTimeEq;
        if signature.len() != 8 {
            return Err(CKR_SIGNATURE_LEN_RANGE.into());
        }
        let expected = crate::secure_channel_crypto::aes_cmac(&self.material()?.rmac[..], input)?;
        if !bool::from(expected[..8].ct_eq(signature)) {
            return Err(CKR_SIGNATURE_INVALID.into());
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn peer_response_mac(&self, input: &[u8]) -> Result<[u8; 16], Error> {
        crate::secure_channel_crypto::aes_cmac(&self.material()?.rmac[..], input)
    }

    pub(super) fn clear(&mut self) {
        self.material = None;
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.material.is_none()
    }

    pub(super) fn derive(credential: &SymmetricCredential, context: &[u8]) -> Result<Self, Error> {
        let mut scope = Pkcs11KeyScope::for_key(&credential.enc)?;
        let static_enc = scope.bind(&credential.enc)?;
        let static_mac = scope.bind(&credential.mac)?;
        scope.require_aes128(&static_enc)?;
        scope.require_aes128(&static_mac)?;
        let mut derive = |base: &KeyHandle, constant: u8, output| {
            let mut prefix = [0; 13];
            prefix[11] = constant;
            scope.derive_counter(
                base,
                &[
                    CounterKdfField::Bytes(&prefix),
                    CounterKdfField::Length(
                        IntegerFormat {
                            width_bits: 16,
                            little_endian: false,
                        },
                        LengthMethod::Key,
                    ),
                    CounterKdfField::Counter(IntegerFormat {
                        width_bits: 8,
                        little_endian: false,
                    }),
                    CounterKdfField::Bytes(context),
                ],
                output,
                16,
            )
        };
        let enc = derive(&static_enc, 0x04, readable(enc_template()))?;
        let mac = derive(&static_mac, 0x06, readable(mac_template()))?;
        let rmac = derive(&static_mac, 0x07, readable(rmac_template()))?;
        Self::read_working_keys(scope, enc, mac, rmac)
    }

    pub(super) fn cryptogram(&self, constant: u8, context: &[u8]) -> Result<[u8; 8], Error> {
        // A 64-bit SCP03 cryptogram is a public protocol MAC, not a derived key
        // to be exported. The single CMAC block encodes the requested 64 bits.
        let mut input = vec![0; 16];
        input[11] = constant;
        input[14] = 64;
        input[15] = 1;
        input.extend_from_slice(context);
        let mac = self.command_mac(&input)?;
        mac[..8].try_into().map_err(|_| CKR_FUNCTION_FAILED.into())
    }
}

/// Handshake-owned key arena. Long-term keys and ECDH agreements remain
/// protected; successful receipt verification releases only working AES keys.
pub(super) struct AsymmetricKeys {
    scope: Pkcs11KeyScope,
    ephemeral: KeyHandle,
}

fn agreement_template() -> TokenObjectTemplate {
    generic_template(&[CKM_CONCATENATE_BASE_AND_KEY as _])
}

impl AsymmetricKeys {
    pub(super) fn for_key(key: &BoundKey) -> Result<Self, Error> {
        let mut scope = Pkcs11KeyScope::for_key(key)?;
        let ephemeral = scope.generate_p256()?;
        Ok(Self { scope, ephemeral })
    }

    pub(super) fn public_key(&self) -> Result<Vec<u8>, Error> {
        self.scope.p256_public(&self.ephemeral)
    }

    pub(super) fn static_agreement(
        &mut self,
        credential: &BoundKey,
        peer: &[u8],
    ) -> Result<BoundKey, Error> {
        let base = self.scope.bind(credential)?;
        let shared = self.scope.ecdh(&base, peer, agreement_template())?;
        self.scope.destroy(&base)?;
        self.scope.take_key(&shared)
    }

    pub(super) fn finish(
        mut self,
        static_shared: &BoundKey,
        context: &[u8; 130],
        receipt: &[u8; 16],
    ) -> Result<SessionKeys, Error> {
        if self.public_key()?.as_slice() != &context[..65] {
            return Err(CKR_DATA_INVALID.into());
        }
        let ephemeral_shared =
            self.scope
                .ecdh(&self.ephemeral, &context[65..], agreement_template())?;
        let static_shared = self.scope.bind(static_shared)?;
        self.scope.require_generic_length(&static_shared, 32)?;
        let z = self.scope.append_key(
            &ephemeral_shared,
            &static_shared,
            generic_template(&[CKM_CONCATENATE_BASE_AND_DATA as _]),
            64,
        )?;
        let mut blocks = Vec::new();
        for i in 1u32..=2 {
            let mut suffix = i.to_be_bytes().to_vec();
            suffix.extend_from_slice(&super::SCP11_SHARED_INFO);
            let input = self.scope.append_data(
                &z,
                &suffix,
                generic_template(&[CKM_SHA256_KEY_DERIVATION as _]),
                71,
            )?;
            blocks.push(self.scope.sha256(
                &input,
                readable(generic_template(&[CKM_CONCATENATE_BASE_AND_KEY as _])),
            )?);
            self.scope.destroy(&input)?;
        }
        let material = self.scope.append_key(
            &blocks[0],
            &blocks[1],
            readable(generic_template(&[CKM_EXTRACT_KEY_FROM_KEY as _])),
            64,
        )?;
        finish_asymmetric(self.scope, material, context, receipt)
    }
}

fn finish_asymmetric(
    mut scope: Pkcs11KeyScope,
    material: KeyHandle,
    context: &[u8; 130],
    receipt: &[u8; 16],
) -> Result<SessionKeys, Error> {
    let receipt_key = scope.extract(
        &material,
        0,
        template(false, false, false, true, &[CKM_AES_CMAC as _]),
        16,
    )?;
    let mut transcript = context[65..].to_vec();
    transcript.extend_from_slice(&context[..65]);
    scope.verify_cmac(&receipt_key, &transcript, receipt)?;
    scope.destroy(&receipt_key)?;
    let enc = scope.extract(&material, 128, readable(enc_template()), 16)?;
    let mac = scope.extract(&material, 256, readable(mac_template()), 16)?;
    let rmac = scope.extract(&material, 384, readable(rmac_template()), 16)?;
    SessionKeys::read_working_keys(scope, enc, mac, rmac)
}

#[cfg(test)]
mod tests;
