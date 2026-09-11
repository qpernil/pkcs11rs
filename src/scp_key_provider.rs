//! Card SCP derivation and administration through protected provider objects.
use crate::{
    key_scope::{BoundKey, KeyHandle, Pkcs11KeyScope, generic_template, readable_template},
    *,
};
use software_key_core::counter_kdf::{CounterKdfField, IntegerFormat, LengthMethod};

pub(crate) fn aes_credential_template() -> TokenObjectTemplate {
    TokenObjectTemplate {
        key_type: Some(CKK_AES as _),
        ..generic_template(&[CKM_SP800_108_COUNTER_KDF as _])
    }
}

fn dek_template() -> TokenObjectTemplate {
    TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as _),
        key_type: Some(CKK_AES as _),
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        encrypt: true,
        allowed_mechanisms: Some(vec![CKM_AES_CBC as _]),
        ..Default::default()
    }
}

/// SCP03 has a long-term DEK; SCP11 supplies a disposable derived DEK.
/// The long-term key is used through its session, never read for administration.
pub(crate) enum CardDek {
    Protected(BoundKey),
    Session(Zeroizing<Vec<u8>>),
}
impl CardDek {
    pub(crate) fn len(&self) -> Result<usize, Error> {
        match self {
            Self::Session(value) => Ok(value.len()),
            Self::Protected(key) => {
                let mut scope = Pkcs11KeyScope::for_key(key)?;
                let handle = scope.bind(key)?;
                scope.aes_length(&handle)
            }
        }
    }
    pub(crate) fn encrypt(&self, input: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            Self::Session(key) => crate::secure_channel_crypto::aes_cbc(
                key,
                &[0; 16],
                input,
                crate::secure_channel_crypto::Direction::Encrypt,
            ),
            Self::Protected(key) => {
                let mut scope = Pkcs11KeyScope::for_key(key)?;
                let handle = scope.bind(key)?;
                Ok(scope.encrypt_cbc(&handle, input)?.to_vec())
            }
        }
    }
}

pub(crate) struct Scp03Keys {
    pub(crate) scope: Pkcs11KeyScope,
    pub(crate) enc: KeyHandle,
    pub(crate) mac: KeyHandle,
    pub(crate) dek: Option<KeyHandle>,
}
impl Scp03Keys {
    pub(crate) fn import(enc: &[u8], mac: &[u8], dek: Option<&[u8]>) -> Result<Self, Error> {
        let mut scope = Pkcs11KeyScope::new()?;
        let enc = scope.import_secret(enc, aes_credential_template())?;
        let mac = scope.import_secret(mac, aes_credential_template())?;
        let dek = dek
            .map(|value| scope.import_secret(value, dek_template()))
            .transpose()?;
        Ok(Self {
            scope,
            enc,
            mac,
            dek,
        })
    }
    pub(crate) fn diversify(bmk: &[u8], context: &[u8; 10]) -> Result<Self, Error> {
        if bmk.len() != 32 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let mut scope = Pkcs11KeyScope::new()?;
        let master = scope.import_secret(bmk, aes_credential_template())?;
        let mut derive = |label: u32, template| {
            scope.derive_counter(
                &master,
                &[
                    CounterKdfField::Counter(IntegerFormat {
                        width_bits: 8,
                        little_endian: false,
                    }),
                    CounterKdfField::Bytes(&label.to_be_bytes()),
                    CounterKdfField::Bytes(&[0]),
                    CounterKdfField::Bytes(context),
                    CounterKdfField::Length(
                        IntegerFormat {
                            width_bits: 16,
                            little_endian: false,
                        },
                        LengthMethod::Key,
                    ),
                ],
                template,
                16,
            )
        };
        let enc = derive(1, aes_credential_template())?;
        let mac = derive(2, aes_credential_template())?;
        let dek = Some(derive(3, dek_template())?);
        scope.destroy(&master)?;
        Ok(Self {
            scope,
            enc,
            mac,
            dek,
        })
    }
    pub(crate) fn derive(
        &mut self,
        enc: bool,
        constant: u8,
        context: &[u8],
        length: usize,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        let base = if enc { &self.enc } else { &self.mac };
        let path = self.scope.counter_kdf_path(base)?;
        let mut label = [0; 12];
        label[11] = constant;
        self.scope.counter_kdf_bytes(
            base,
            path,
            &[
                CounterKdfField::Bytes(&label),
                CounterKdfField::Bytes(&[0]),
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
            readable_template(generic_template(&[])),
            length,
        )
    }
    pub(crate) fn take_dek(&mut self) -> Result<Option<CardDek>, Error> {
        self.dek
            .take()
            .map(|key| self.scope.retain_key(&key).map(CardDek::Protected))
            .transpose()
    }
}

pub(crate) fn protect_p256(key: SoftwareSigningKey) -> Result<BoundKey, Error> {
    let mut scope = Pkcs11KeyScope::new()?;
    let key = scope.import_p256(key)?;
    scope.take_key(&key)
}

#[cfg(test)]
mod tests;
