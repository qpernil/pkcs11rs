//! Authentication selects objects from existing PKCS #11 slots. This index
//! holds weak slot references and discovery capabilities, never a second credential inventory.
use crate::{
    pkcs11_auth::Pkcs11Auth,
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    *,
};
use std::sync::RwLock;

#[derive(Debug, Clone)]
struct RegisteredSlot {
    #[cfg(test)]
    kind: SlotKind,
    serial: String,
    profiles: Vec<CK_PROFILE_ID>,
    slot: std::sync::Weak<Mutex<SlotContext>>,
}
#[derive(Debug, Default)]
pub(crate) struct AuthSlots {
    slots: RwLock<Vec<RegisteredSlot>>,
    #[cfg(test)]
    fixture_owners: Vec<Arc<Mutex<SlotContext>>>,
}
impl AuthSlots {
    pub(crate) fn register(&self, slot: &Arc<Mutex<SlotContext>>) -> Result<(), Error> {
        let entry = {
            let mut ctx = slot.lock().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
            ctx.slot.set_context_reference(Arc::downgrade(slot));
            RegisteredSlot {
                #[cfg(test)]
                kind: ctx.slot.kind(),
                serial: ctx.slot.serial().to_owned(),
                profiles: ctx.slot.additional_profile_ids().to_vec(),
                slot: Arc::downgrade(slot),
            }
        };
        let mut slots = self.slots.write().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        slots.retain(|entry| entry.slot.strong_count() != 0);
        if let Some(existing) = slots
            .iter_mut()
            .find(|existing| existing.slot.ptr_eq(&entry.slot))
        {
            *existing = entry;
        } else {
            slots.push(entry);
        }
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn matching(&self, kind: SlotKind) -> Result<Vec<Arc<Mutex<SlotContext>>>, Error> {
        Ok(self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter(|entry| entry.kind == kind)
            .filter_map(|entry| entry.slot.upgrade())
            .collect())
    }
    #[cfg(target_os = "ios")]
    pub(crate) fn remove(&self, slot: &Arc<Mutex<SlotContext>>) {
        if let Ok(mut slots) = self.slots.write() {
            slots.retain(|entry| !entry.slot.ptr_eq(&Arc::downgrade(slot)));
        }
    }
    #[cfg(test)]
    pub(crate) fn from_native_fixtures(providers: Vec<NativeHsmAuth>) -> Self {
        let mut sources = Self::default();
        for provider in providers {
            let slot = Self::fixture_slot(provider);
            sources.register(&slot).unwrap();
            sources.fixture_owners.push(slot);
        }
        sources
    }
    #[cfg(test)]
    pub(crate) fn fixture_slot(provider: NativeHsmAuth) -> Arc<Mutex<SlotContext>> {
        let slot = crate::HsmAuthSlot::from_native_fixture(provider);
        let context = ModuleContext::private_slot(Box::new(slot)).unwrap();
        context
            .slot_contexts
            .read()
            .unwrap()
            .get(&1)
            .unwrap()
            .clone()
    }
    /// Public-only enumeration. Skip the target itself: it cannot authorize
    /// access to its own authentication source. A busy other source is an error,
    /// since silently omitting it could turn ambiguity into a false unique match.
    pub(crate) fn ordinary_credentials(
        &self,
        label: Option<&str>,
        source: Option<&str>,
        target: &std::sync::Weak<Mutex<SlotContext>>,
        explicit: bool,
    ) -> Result<Vec<OrdinaryCredential>, Error> {
        let entries = self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter_map(|entry| entry.slot.upgrade().map(|slot| (entry.clone(), slot)))
            .collect::<Vec<_>>();
        let mut result = Vec::new();
        for (entry, slot) in entries {
            let serial = entry.serial;
            if entry.slot.ptr_eq(target) || source.is_some_and(|source| source != serial) {
                continue;
            }
            if entry.profiles.contains(&CKP_YUBICO_HSMAUTH) {
                continue;
            }
            let (serial, title, pin_required) = {
                let ctx = slot
                    .try_lock()
                    .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
                if !ctx.slot.is_present() {
                    continue;
                }
                let serial = ctx.slot.serial().to_owned();
                if source.is_some_and(|source| source != serial) {
                    continue;
                }
                (serial, ctx.slot.label(), ctx.slot.user_login_requires_pin())
            };
            let session = ProviderSession::open(Pkcs11Provider::from_slot(slot)?)?;
            let mut template = vec![(CKA_TOKEN, &[CK_TRUE as u8][..])];
            let class = (CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes();
            let key_type = (CKK_EC as CK_ULONG).to_ne_bytes();
            template.extend([
                (CKA_CLASS, &class[..]),
                (CKA_KEY_TYPE, &key_type[..]),
                (CKA_EC_PARAMS, crate::pkcs11_auth::P256_PARAMS),
            ]);
            if let Some(label) = label {
                template.push((CKA_LABEL, label.as_bytes()));
            }
            let mut found = false;
            for handle in session.find(&template)? {
                let point = session.attribute(handle, CKA_EC_POINT)?;
                if point.len() != 67 || point[..3] != [4, 65, 4] {
                    return Err(CKR_PUBLIC_KEY_INVALID.into());
                }
                result.push(OrdinaryCredential {
                    pin_required,
                    explicit,
                    session: session.clone(),
                    source: serial.clone(),
                    title: title.clone(),
                    label: String::from_utf8(session.attribute(handle, CKA_LABEL)?.to_vec())
                        .map_err(|_| CKR_DEVICE_ERROR)?,
                    id: Some(session.attribute(handle, CKA_ID)?.to_vec()),
                    public_key: Some(point[2..].to_vec()),
                });
                found = true;
            }
            // Hidden keys and symmetric pairs require an explicitly selected
            // source and label. Resolve their type only after that source login.
            if !found
                && explicit
                && source.is_some()
                && let Some(label) = label
            {
                result.push(OrdinaryCredential {
                    pin_required,
                    explicit,
                    session,
                    source: serial,
                    title,
                    label: label.to_owned(),
                    id: None,
                    public_key: None,
                });
            }
        }
        Ok(result)
    }
    pub(crate) fn hsmauth_credentials(
        &self,
        label: Option<&str>,
        source: Option<&str>,
        asymmetric_only: bool,
    ) -> Result<Vec<HsmAuthCredentialBinding>, Error> {
        let mut result = Vec::new();
        let entries = self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter(|entry| {
                entry.profiles.contains(&CKP_YUBICO_HSMAUTH)
                    && source.is_none_or(|source| source == entry.serial)
            })
            .filter_map(|entry| {
                entry
                    .slot
                    .upgrade()
                    .map(|slot| (entry.serial.clone(), slot))
            })
            .collect::<Vec<_>>();
        for (serial, slot) in entries {
            if !slot
                .try_lock()
                .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?
                .slot
                .is_present()
            {
                continue;
            }
            let session = ProviderSession::open(Pkcs11Provider::from_slot(slot)?)?;
            let profiles = session.find(&[
                (CKA_CLASS, &(CKO_PROFILE as CK_ULONG).to_ne_bytes()),
                (CKA_PROFILE_ID, &CKP_YUBICO_HSMAUTH.to_ne_bytes()),
            ])?;
            if profiles.is_empty() {
                continue;
            }
            for (key_type, algorithm) in [
                (
                    CKK_YUBICO_HSMAUTH_SYMMETRIC,
                    HsmAuthAlgorithm::Aes128YubicoAuthentication,
                ),
                (
                    CKK_YUBICO_HSMAUTH_ASYMMETRIC,
                    HsmAuthAlgorithm::EcP256YubicoAuthentication,
                ),
            ] {
                if asymmetric_only && key_type == CKK_YUBICO_HSMAUTH_SYMMETRIC {
                    continue;
                }
                let key_type = key_type.to_ne_bytes();
                let class = (CKO_SECRET_KEY as CK_ULONG).to_ne_bytes();
                let mut template = vec![
                    (CKA_TOKEN, &[CK_TRUE as u8][..]),
                    (CKA_CLASS, &class[..]),
                    (CKA_KEY_TYPE, &key_type[..]),
                ];
                if let Some(label) = label {
                    template.push((CKA_LABEL, label.as_bytes()));
                }
                for handle in session.find(&template)? {
                    let label = session.attribute(handle, CKA_LABEL)?;
                    let label = String::from_utf8(label.to_vec()).map_err(|_| CKR_DEVICE_ERROR)?;
                    let id = session.attribute(handle, CKA_ID)?;
                    let public_key = if algorithm == HsmAuthAlgorithm::EcP256YubicoAuthentication {
                        let public = session.find(&[
                            (CKA_TOKEN, &[CK_TRUE as u8]),
                            (CKA_CLASS, &(CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes()),
                            (CKA_KEY_TYPE, &(CKK_EC as CK_ULONG).to_ne_bytes()),
                            (CKA_EC_PARAMS, crate::pkcs11_auth::P256_PARAMS),
                            (CKA_LABEL, label.as_bytes()),
                            (CKA_ID, &id),
                        ])?;
                        let [public] = public.as_slice() else {
                            return Err(CKR_KEY_HANDLE_INVALID.into());
                        };
                        let point = session.attribute(*public, CKA_EC_POINT)?;
                        // CKA_EC_POINT is a DER OCTET STRING containing a P-256 point.
                        if point.len() != 67 || point[..3] != [4, 65, 4] {
                            return Err(CKR_PUBLIC_KEY_INVALID.into());
                        }
                        Some(point[2..].to_vec())
                    } else {
                        None
                    };
                    let retries = session.attribute(handle, CKA_YUBICO_HSMAUTH_RETRIES as u32)?;
                    let retries = CK_ULONG::from_ne_bytes(
                        retries
                            .as_slice()
                            .try_into()
                            .map_err(|_| CKR_DEVICE_ERROR)?,
                    );
                    let touch =
                        session.attribute(handle, CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED as u32)?;
                    result.push(HsmAuthCredentialBinding {
                        key: crate::key_scope::BoundKey::from_session(session.clone(), handle)?,
                        credential: HsmAuthCredential {
                            label,
                            algorithm,
                            retries: u8::try_from(retries).map_err(|_| CKR_DEVICE_ERROR)?,
                            touch_required: touch.as_slice() == [CK_TRUE as u8],
                            public_key,
                        },
                        source: serial.clone(),
                    });
                }
            }
        }
        Ok(result)
    }
    pub(crate) fn asymmetric_hsmauth_credentials(
        &self,
        selector: &HsmAuthWildcardLogin<'_>,
    ) -> Result<Vec<HsmAuthCredentialBinding>, Error> {
        self.hsmauth_credentials(selector.label, selector.source, true)
    }
}
#[derive(Clone)]
pub(crate) struct HsmAuthCredentialBinding {
    pub(crate) key: crate::key_scope::BoundKey,
    pub(crate) credential: HsmAuthCredential,
    source: String,
}
impl HsmAuthCredentialBinding {
    pub(crate) fn source_identifier(&self) -> &str {
        &self.source
    }
    pub(crate) fn slot_label(&self) -> String {
        format!("HSM Auth #{}", self.source)
    }
    pub(crate) fn authenticate(
        &self,
        target: &dyn Connector,
        authkey_id: u16,
        password: &[u8],
        trust_prefix: Option<&std::ffi::OsStr>,
    ) -> Result<YubiHsmSecureSession, Error> {
        self.key
            .hsmauth_authenticate(target, authkey_id, password, trust_prefix)
    }
}

/// A public selection owns only a session and identifying metadata. It does not
/// bind a private key or authorize the source until it has been selected uniquely.
pub(crate) struct OrdinaryCredential {
    pub(crate) pin_required: bool,
    explicit: bool,
    pub(crate) session: Arc<ProviderSession>,
    pub(crate) source: String,
    pub(crate) title: String,
    pub(crate) label: String,
    id: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
}
impl OrdinaryCredential {
    pub(crate) fn authorize(
        self,
        password: &[u8],
        trust_prefix: Option<std::ffi::OsString>,
    ) -> Result<YubiHsmPkcs11AuthenticationMaterial, Error> {
        self.session.authorize(password)?;
        let class = (CKO_PRIVATE_KEY as CK_ULONG).to_ne_bytes();
        let key_type = (CKK_EC as CK_ULONG).to_ne_bytes();
        let mut template = vec![
            (CKA_TOKEN, &[CK_TRUE as u8][..]),
            (CKA_CLASS, &class[..]),
            (CKA_KEY_TYPE, &key_type[..]),
            (CKA_EC_PARAMS, crate::pkcs11_auth::P256_PARAMS),
        ];
        template.push((CKA_LABEL, self.label.as_bytes()));
        if let Some(id) = &self.id {
            template.push((CKA_ID, id));
        }
        let private = self.session.find(&template)?;
        if self.explicit {
            // Decide by object inventory, never by trying one protocol and then
            // another. An asymmetric key and symmetric pair under one name are
            // ambiguous even after a uniquely selected source was authorized.
            let enc = format!("{}.enc", self.label);
            let mac = format!("{}.mac", self.label);
            let has_symmetric = [enc, mac].iter().try_fold(false, |found, label| {
                self.session
                    .find(&[
                        (CKA_TOKEN, &[CK_TRUE as u8]),
                        (CKA_CLASS, &(CKO_SECRET_KEY as CK_ULONG).to_ne_bytes()),
                        (CKA_KEY_TYPE, &(CKK_AES as CK_ULONG).to_ne_bytes()),
                        (CKA_LABEL, label.as_bytes()),
                    ])
                    .map(|keys| found || !keys.is_empty())
            })?;
            if has_symmetric {
                if self.public_key.is_some() || !private.is_empty() {
                    return Err(CKR_TEMPLATE_INCONSISTENT.into());
                }
                return Ok(YubiHsmPkcs11AuthenticationMaterial::Symmetric(
                    crate::key_scope::SymmetricCredential::find(self.session, &self.label, true)?,
                ));
            }
        }
        let handle = match private.as_slice() {
            [handle] => *handle,
            [] => return Err(CKR_KEY_HANDLE_INVALID.into()),
            _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        };
        if self.session.attribute(handle, CKA_DERIVE)?.as_slice() != [CK_TRUE as u8] {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let credential = crate::key_scope::BoundKey::from_session(self.session, handle)?;
        if let Some(public_key) = self.public_key {
            let mut scope = crate::key_scope::Pkcs11KeyScope::for_key(&credential)?;
            let key = scope.bind(&credential)?;
            if scope.p256_public(&key)? != public_key {
                return Err(CKR_PUBLIC_KEY_INVALID.into());
            }
        }
        Ok(YubiHsmPkcs11AuthenticationMaterial::AsymmetricCredential {
            credential,
            trust_prefix,
        })
    }
}
