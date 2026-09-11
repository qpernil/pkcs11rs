//! PKCS #11 client-side ownership of sessions and temporary object handles.
//! Cryptography, key policy, and object storage belong to the selected slot.
use crate::{
    pkcs11_auth::{Derivation, P256_PARAMS, Pkcs11Auth, ec_template},
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    *,
};

#[derive(Clone, Debug)]
pub(crate) struct KeyHandle {
    owner: Arc<()>,
    index: usize,
}

struct ObjectHandle {
    session: Rc<ProviderSession>,
    handle: CK_OBJECT_HANDLE,
}
pub(crate) struct Pkcs11KeyScope {
    identity: Arc<()>,
    pub(crate) session: Rc<ProviderSession>,
    objects: Vec<Option<Rc<ObjectHandle>>>,
}

/// Keeps the owning session alive without exporting its key.
#[derive(Clone)]
pub(crate) struct BoundKey(Rc<ObjectHandle>);
impl BoundKey {
    pub(crate) fn authorize_source(&self, pin: &[u8]) -> Result<(), Error> {
        self.0.session.authorize(pin)
    }
    pub(crate) fn hsmauth_authenticate(
        &self,
        target: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        trust_prefix: Option<&std::ffi::OsStr>,
    ) -> Result<YubiHsmSecureSession, Error> {
        self.0.session.hsmauth_authenticate(
            self.0.handle,
            target,
            authkey_id,
            password,
            trust_prefix,
        )
    }

    /// Borrow a credential through its authorized session. Token objects stay
    /// token-owned; dropping this reference never deletes the source key.
    pub(crate) fn from_session(
        session: Rc<ProviderSession>,
        handle: CK_OBJECT_HANDLE,
    ) -> Result<Self, Error> {
        let class = session.attribute(handle, CKA_CLASS)?;
        let class =
            CK_ULONG::from_ne_bytes(class.as_slice().try_into().map_err(|_| CKR_DEVICE_ERROR)?);
        if class != CKO_SECRET_KEY as CK_ULONG && class != CKO_PRIVATE_KEY as CK_ULONG {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        Ok(Self(Rc::new(ObjectHandle { session, handle })))
    }
}

/// Two independently protected AES-128 keys on one provider. The ENC key
/// derives S-ENC; the MAC key derives S-MAC and S-RMAC. Binding never reads or
/// copies either source value, so native token keys remain usable in place.
pub(crate) struct SymmetricCredential {
    pub(crate) enc: BoundKey,
    pub(crate) mac: BoundKey,
}
impl SymmetricCredential {
    pub(crate) fn find(
        session: Rc<ProviderSession>,
        label: &str,
        token: bool,
    ) -> Result<Self, Error> {
        let find = |suffix: &str| {
            let label = format!("{label}.{suffix}");
            let class = (CKO_SECRET_KEY as CK_ULONG).to_ne_bytes();
            let key_type = (CKK_AES as CK_ULONG).to_ne_bytes();
            let keys = session.find(&[
                (CKA_TOKEN, &[u8::from(token)]),
                (CKA_CLASS, &class),
                (CKA_KEY_TYPE, &key_type),
                (CKA_LABEL, label.as_bytes()),
            ])?;
            match keys.as_slice() {
                [handle] => BoundKey::from_session(session.clone(), *handle),
                [] => Err(CKR_KEY_HANDLE_INVALID.into()),
                _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
            }
        };
        Self::new(find("enc")?, find("mac")?)
    }

    pub(crate) fn new(enc: BoundKey, mac: BoundKey) -> Result<Self, Error> {
        let mut scope = Pkcs11KeyScope::for_key(&enc)?;
        for key in [&enc, &mac] {
            let key = scope.bind(key)?;
            scope.require_aes128(&key)?;
        }
        Ok(Self { enc, mac })
    }
}

pub(crate) fn authentication_aes_template() -> TokenObjectTemplate {
    TokenObjectTemplate {
        key_type: Some(CKK_AES as _),
        ..generic_template(&[CKM_SP800_108_COUNTER_KDF as _])
    }
}

/// Both direct-authentication credential types share one temporary slot and
/// owning session. No password survives preparation. Only the selected
/// reauthentication material is transferred to a separate owning session.
pub(crate) struct PasswordCredentials {
    scope: Pkcs11KeyScope,
    enc: KeyHandle,
    mac: KeyHandle,
    asymmetric: KeyHandle,
}
impl PasswordCredentials {
    pub(crate) fn new(password: &[u8]) -> Result<Self, Error> {
        let mut scope = Pkcs11KeyScope::new()?;
        let value = crate::yubico_password_kdf(password)?;
        let enc = scope.import_secret(
            &value[..16],
            TokenObjectTemplate {
                label: "direct.enc".to_owned(),
                ..authentication_aes_template()
            },
        )?;
        let mac = scope.import_secret(
            &value[16..],
            TokenObjectTemplate {
                label: "direct.mac".to_owned(),
                ..authentication_aes_template()
            },
        )?;
        let key = crate::yubico_kdf::yubico_password_p256_key(password)?;
        let asymmetric = scope.import_p256(key)?;
        Ok(Self {
            scope,
            enc,
            mac,
            asymmetric,
        })
    }
    pub(crate) fn symmetric(&self) -> Result<SymmetricCredential, Error> {
        SymmetricCredential::new(
            BoundKey::from_session(
                self.scope.session.clone(),
                self.scope.object(&self.enc)?.handle,
            )?,
            BoundKey::from_session(
                self.scope.session.clone(),
                self.scope.object(&self.mac)?.handle,
            )?,
        )
    }
    pub(crate) fn asymmetric(&self) -> Result<BoundKey, Error> {
        BoundKey::from_session(
            self.scope.session.clone(),
            self.scope.object(&self.asymmetric)?.handle,
        )
    }
    pub(crate) fn retain_symmetric(&mut self) -> Result<SymmetricCredential, Error> {
        let mut keys = self.scope.take_keys(&[&self.enc, &self.mac])?.into_iter();
        let enc = keys.next().ok_or(CKR_FUNCTION_FAILED)?;
        let mac = keys.next().ok_or(CKR_FUNCTION_FAILED)?;
        SymmetricCredential::new(enc, mac)
    }
}

pub(crate) fn generic_template(mechanisms: &[CK_MECHANISM_TYPE]) -> TokenObjectTemplate {
    TokenObjectTemplate {
        class: Some(CKO_SECRET_KEY as _),
        key_type: Some(CKK_GENERIC_SECRET as _),
        private: true,
        sensitive: Some(true),
        extractable: Some(false),
        derive: true,
        allowed_mechanisms: Some(mechanisms.to_vec()),
        ..Default::default()
    }
}

impl Pkcs11KeyScope {
    pub(crate) fn new() -> Result<Self, Error> {
        Self::open(Pkcs11Provider::private_software()?)
    }
    fn open(provider: Rc<Pkcs11Provider>) -> Result<Self, Error> {
        Ok(Self::from_session(ProviderSession::open(provider)?))
    }
    pub(crate) fn from_session(session: Rc<ProviderSession>) -> Self {
        Self {
            identity: Arc::new(()),
            session,
            objects: Vec::new(),
        }
    }
    pub(crate) fn for_key(key: &BoundKey) -> Result<Self, Error> {
        Self::open(key.0.session.provider.clone())
    }
    fn insert(&mut self, object: Rc<ObjectHandle>) -> KeyHandle {
        let index = self.objects.len();
        self.objects.push(Some(object));
        KeyHandle {
            owner: self.identity.clone(),
            index,
        }
    }
    fn created(&mut self, handle: CK_OBJECT_HANDLE) -> KeyHandle {
        self.insert(Rc::new(ObjectHandle {
            session: self.session.clone(),
            handle,
        }))
    }
    fn object(&self, key: &KeyHandle) -> Result<&ObjectHandle, Error> {
        if !Arc::ptr_eq(&key.owner, &self.identity) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        self.objects
            .get(key.index)
            .and_then(Option::as_deref)
            .ok_or_else(|| CKR_KEY_HANDLE_INVALID.into())
    }
    pub(crate) fn bind(&mut self, key: &BoundKey) -> Result<KeyHandle, Error> {
        if !Rc::ptr_eq(&self.session.provider, &key.0.session.provider) {
            return Err(CKR_KEY_HANDLE_INVALID.into());
        }
        Ok(self.insert(key.0.clone()))
    }
    pub(crate) fn take_key(&mut self, key: &KeyHandle) -> Result<BoundKey, Error> {
        self.take_keys(&[key])?
            .pop()
            .ok_or_else(|| CKR_FUNCTION_FAILED.into())
    }
    fn take_keys(&mut self, keys: &[&KeyHandle]) -> Result<Vec<BoundKey>, Error> {
        let mut sources = Vec::with_capacity(keys.len());
        for key in keys {
            let object = self.object(key)?;
            if !Rc::ptr_eq(&object.session, &self.session)
                || self.read(key, CKA_TOKEN)?.as_slice() != [CK_FALSE as u8]
            {
                return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
            }
            sources.push(object.handle);
        }
        // Transfer temporary credentials together to a dedicated owning
        // session. Token bindings are never copied. Partial copies disappear
        // with the new session if preparation fails.
        let session = ProviderSession::open(self.session.provider.clone())?;
        let mut retained = Vec::with_capacity(keys.len());
        for source in sources {
            let handle = session.copy(source)?;
            retained.push(BoundKey::from_session(session.clone(), handle)?);
        }
        for key in keys {
            self.destroy(key)?;
        }
        Ok(retained)
    }
    pub(crate) fn destroy(&mut self, key: &KeyHandle) -> Result<(), Error> {
        let object = self.object(key)?;
        if Rc::ptr_eq(&object.session, &self.session) {
            self.session.destroy(object.handle)?;
        }
        self.objects[key.index] = None;
        Ok(())
    }
    pub(crate) fn import_secret(
        &mut self,
        value: &[u8],
        template: TokenObjectTemplate,
    ) -> Result<KeyHandle, Error> {
        let handle = self.session.create(template, &[(CKA_VALUE, value)])?;
        Ok(self.created(handle))
    }
    pub(crate) fn import_p256(&mut self, key: SoftwareSigningKey) -> Result<KeyHandle, Error> {
        if !matches!(
            key.public_key(),
            SoftwarePublicKey::Ec {
                curve: EcCurve::P256,
                ..
            }
        ) {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let value = key
            .serialized()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let handle = self.session.create(
            ec_template(),
            &[(CKA_EC_PARAMS, P256_PARAMS), (CKA_VALUE, &value)],
        )?;
        Ok(self.created(handle))
    }
    pub(crate) fn generate_p256(&mut self) -> Result<KeyHandle, Error> {
        let (pubkey, privkey) = self.session.generate_p256()?;
        let public = self.created(pubkey);
        let private = self.created(privkey);
        self.destroy(&public)?;
        Ok(private)
    }
    fn read(&self, key: &KeyHandle, kind: u32) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.session.attribute(self.object(key)?.handle, kind)
    }
    fn ulong(&self, key: &KeyHandle, kind: u32) -> Result<CK_ULONG, Error> {
        let value = self.read(key, kind)?;
        Ok(CK_ULONG::from_ne_bytes(
            value.as_slice().try_into().map_err(|_| CKR_DEVICE_ERROR)?,
        ))
    }
    pub(crate) fn p256_public(&self, key: &KeyHandle) -> Result<Vec<u8>, Error> {
        use der::Decode;
        if self.read(key, CKA_EC_PARAMS)?.as_slice() != P256_PARAMS {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let encoded = self.read(key, CKA_PUBLIC_KEY_INFO)?;
        let info = spki::SubjectPublicKeyInfoRef::from_der(&encoded)
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        let point = info.subject_public_key.as_bytes().ok_or(CKR_DEVICE_ERROR)?;
        if point.len() != 65 || point[0] != 4 {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        Ok(point.to_vec())
    }
    fn derive(
        &mut self,
        base: &KeyHandle,
        operation: Derivation<'_>,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        let handle = self
            .session
            .derive(self.object(base)?.handle, operation, template, length)?;
        Ok(self.created(handle))
    }
    pub(crate) fn ecdh(
        &mut self,
        base: &KeyHandle,
        peer: &[u8],
        template: TokenObjectTemplate,
    ) -> Result<KeyHandle, Error> {
        self.derive(base, Derivation::Ecdh(peer), template, 32)
    }
    pub(crate) fn can_derive(
        &self,
        base: &KeyHandle,
        mechanism: CK_MECHANISM_TYPE,
    ) -> Result<bool, Error> {
        self.session
            .can_derive(self.object(base)?.handle, mechanism)
    }
    pub(crate) fn prefixed_ecdh(
        &mut self,
        base: &KeyHandle,
        peer: &[u8],
        prefix: &[u8],
        shared_info: &[u8],
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        self.derive(
            base,
            Derivation::PrefixedEcdh {
                peer,
                prefix,
                shared_info,
            },
            template,
            length,
        )
    }
    /// Export only an explicitly readable ephemeral agreement, never a static key.
    pub(crate) fn read_ephemeral_agreement(
        &self,
        key: &KeyHandle,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.require_generic_length(key, 32)?;
        let value = self.read(key, CKA_VALUE)?;
        if value.len() != 32 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        Ok(value)
    }
    pub(crate) fn append_key(
        &mut self,
        base: &KeyHandle,
        other: &KeyHandle,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        self.derive(
            base,
            Derivation::AppendKey(self.object(other)?.handle),
            template,
            length,
        )
    }
    pub(crate) fn append_data(
        &mut self,
        base: &KeyHandle,
        data: &[u8],
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        self.derive(base, Derivation::AppendData(data), template, length)
    }
    pub(crate) fn extract(
        &mut self,
        base: &KeyHandle,
        offset_bits: usize,
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        self.derive(base, Derivation::Extract { offset_bits }, template, length)
    }
    pub(crate) fn sha256(
        &mut self,
        base: &KeyHandle,
        template: TokenObjectTemplate,
    ) -> Result<KeyHandle, Error> {
        self.derive(base, Derivation::Sha256, template, 32)
    }
    pub(crate) fn derive_counter(
        &mut self,
        base: &KeyHandle,
        fields: &[software_key_core::counter_kdf::CounterKdfField<'_>],
        template: TokenObjectTemplate,
        length: usize,
    ) -> Result<KeyHandle, Error> {
        self.derive(base, Derivation::Counter(fields), template, length)
    }
    pub(crate) fn read_aes128(&self, key: &KeyHandle) -> Result<Zeroizing<[u8; 16]>, Error> {
        if self.ulong(key, CKA_CLASS)? != CKO_SECRET_KEY as CK_ULONG
            || self.ulong(key, CKA_KEY_TYPE)? != CKK_AES as CK_ULONG
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        let value = self.read(key, CKA_VALUE)?;
        let mut output = Zeroizing::new([0; 16]);
        if value.len() != output.len() {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        output.copy_from_slice(&value);
        Ok(output)
    }
    pub(crate) fn require_aes128(&self, key: &KeyHandle) -> Result<(), Error> {
        if self.ulong(key, CKA_CLASS)? != CKO_SECRET_KEY as CK_ULONG
            || self.ulong(key, CKA_KEY_TYPE)? != CKK_AES as CK_ULONG
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if self.ulong(key, CKA_VALUE_LEN)? != 16 {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        Ok(())
    }
    pub(crate) fn require_generic_length(
        &self,
        key: &KeyHandle,
        length: usize,
    ) -> Result<(), Error> {
        if self.ulong(key, CKA_CLASS)? != CKO_SECRET_KEY as CK_ULONG
            || self.ulong(key, CKA_KEY_TYPE)? != CKK_GENERIC_SECRET as CK_ULONG
        {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        }
        if self.ulong(key, CKA_VALUE_LEN)? != length as CK_ULONG {
            return Err(CKR_KEY_SIZE_RANGE.into());
        }
        Ok(())
    }
    pub(crate) fn verify_cmac(
        &self,
        key: &KeyHandle,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), Error> {
        self.session
            .verify_cmac(self.object(key)?.handle, input, signature)
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
impl Pkcs11KeyScope {
    fn snapshot(&self, handle: &KeyHandle) -> TokenObject {
        let handle = self.object(handle).unwrap().handle;
        let mut object = None;
        self.session.call(|| {
            with_session_context(self.session.handle, |ctx| {
                object = ctx.resolve_object(handle)?;
                Ok(())
            })
            .unwrap()
        });
        object.unwrap()
    }
    pub(crate) fn count_provider_objects(&self) -> usize {
        self.session.call(|| {
            with_session_context(self.session.handle, |ctx| Ok(ctx.memory_objects.len())).unwrap()
        })
    }
}
