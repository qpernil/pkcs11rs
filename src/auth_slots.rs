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
    token: String,
    manufacturer: String,
    model: String,
    uri_prefix: String,
    profiles: Vec<CK_PROFILE_ID>,
    client_auth_search_tier: ClientAuthSearchTier,
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
                token: ctx.slot.label(),
                manufacturer: ctx.slot.manufacturer().to_owned(),
                model: ctx.slot.model().to_owned(),
                uri_prefix: crate::pkcs11_uri::slot_uri_prefix(
                    &ctx.slot.label(),
                    ctx.slot.serial(),
                ),
                profiles: ctx.slot.additional_profile_ids().to_vec(),
                client_auth_search_tier: ctx.slot.client_auth_search_tier(),
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
    /// access to its own authentication source. A busy source reached before a
    /// match is an error; sources after the first match remain untouched.
    pub(crate) fn find_ordinary_credential<R>(
        &self,
        selector: &crate::pkcs11_uri::ClientAuthUri,
        target: &std::sync::Weak<Mutex<SlotContext>>,
        mut select: impl FnMut(OrdinaryCredential) -> Result<Option<R>, Error>,
    ) -> Result<Option<R>, Error> {
        let label = selector.object_label()?;
        let explicit = selector.authkey_id.is_some();
        let mut entries = self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter_map(|entry| entry.slot.upgrade().map(|slot| (entry.clone(), slot)))
            .collect::<Vec<_>>();
        // Stable sorting preserves module slot order within one protection tier.
        entries.sort_by_key(|(entry, _)| entry.client_auth_search_tier);
        let mut fallback = None;
        for (entry, slot) in entries {
            if entry.slot.ptr_eq(target)
                || !selector.matches_slot_fields(
                    &entry.token,
                    &entry.manufacturer,
                    &entry.serial,
                    &entry.model,
                )
            {
                continue;
            }
            if entry.profiles.contains(&CKP_YUBICO_HSMAUTH) {
                continue;
            }
            {
                let ctx = slot
                    .try_lock()
                    .map_err(|_| Error::from(CKR_FUNCTION_FAILED))?;
                if !ctx.slot.is_present() {
                    continue;
                }
            }
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
            if let Some(id) = selector.id.as_deref() {
                template.push((CKA_ID, id));
            }
            let mut found = false;
            let public_allowed = selector.class.is_none_or(|class| {
                class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS
                    || class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS
            });
            for handle in if public_allowed {
                session.find(&template)?
            } else {
                Vec::new()
            } {
                let point = session.attribute(handle, CKA_EC_POINT)?;
                if point.len() != 67 || point[..3] != [4, 65, 4] {
                    return Err(CKR_PUBLIC_KEY_INVALID.into());
                }
                let object_label =
                    String::from_utf8(session.attribute(handle, CKA_LABEL)?.to_vec())
                        .map_err(|_| CKR_DEVICE_ERROR)?;
                let credential = OrdinaryCredential {
                    symmetric: false,
                    session: session.clone(),
                    label: object_label.clone(),
                    id: Some(session.attribute(handle, CKA_ID)?.to_vec()),
                    public_key: Some(point[2..].to_vec()),
                    uri_prefix: entry.uri_prefix.clone(),
                };
                found = true;
                if let Some(selected) = select(credential)? {
                    return Ok(Some(selected));
                }
            }
            // Hidden keys and symmetric pairs require an explicitly selected
            // source and label. Resolve their type only after that source login.
            if !found
                && explicit
                && let Some(label) = label
            {
                let selected = match selector.class {
                    Some(class) if class == CKO_SECRET_KEY as CK_OBJECT_CLASS => label
                        .ends_with(".enc")
                        .then_some((label, CKO_SECRET_KEY as CK_OBJECT_CLASS)),
                    Some(class) if class == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => {
                        Some((label, CKO_PRIVATE_KEY as CK_OBJECT_CLASS))
                    }
                    None if label.ends_with(".enc") => {
                        Some((label, CKO_SECRET_KEY as CK_OBJECT_CLASS))
                    }
                    None => Some((label, CKO_PRIVATE_KEY as CK_OBJECT_CLASS)),
                    _ => None,
                };
                let Some((label, requested_class)) = selected else {
                    continue;
                };
                let credential = OrdinaryCredential {
                    symmetric: requested_class == CKO_SECRET_KEY as CK_OBJECT_CLASS,
                    session,
                    label: label.to_owned(),
                    id: selector.id.clone(),
                    public_key: None,
                    uri_prefix: entry.uri_prefix,
                };
                if !public_allowed {
                    return select(credential);
                }
                fallback.get_or_insert(credential);
            }
        }
        fallback.map(&mut select).transpose().map(Option::flatten)
    }
    pub(crate) fn find_hsmauth_credential<R>(
        &self,
        selector: &crate::pkcs11_uri::ClientAuthUri,
        asymmetric_only: bool,
        mut select: impl FnMut(HsmAuthCredentialBinding) -> Result<Option<R>, Error>,
    ) -> Result<Option<R>, Error> {
        let label = selector.object_label()?;
        let entries = self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter(|entry| {
                entry.profiles.contains(&CKP_YUBICO_HSMAUTH)
                    && selector.matches_slot_fields(
                        &entry.token,
                        &entry.manufacturer,
                        &entry.serial,
                        &entry.model,
                    )
            })
            .filter_map(|entry| {
                entry
                    .slot
                    .upgrade()
                    .map(|slot| (entry.serial.clone(), entry.uri_prefix.clone(), slot))
            })
            .collect::<Vec<_>>();
        for (serial, uri_prefix, slot) in entries {
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
            for (key_type, class, algorithm) in [
                (
                    CKK_YUBICO_HSMAUTH_SYMMETRIC,
                    CKO_SECRET_KEY as CK_OBJECT_CLASS,
                    HsmAuthAlgorithm::Aes128YubicoAuthentication,
                ),
                (
                    CKK_YUBICO_HSMAUTH_ASYMMETRIC,
                    CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                    HsmAuthAlgorithm::EcP256YubicoAuthentication,
                ),
            ] {
                if asymmetric_only && key_type == CKK_YUBICO_HSMAUTH_SYMMETRIC {
                    continue;
                }
                if selector.class.is_some_and(|selected_class| {
                    selected_class != class
                        && !(algorithm == HsmAuthAlgorithm::EcP256YubicoAuthentication
                            && selected_class == CKO_PUBLIC_KEY as CK_OBJECT_CLASS)
                }) {
                    continue;
                }
                let key_type = key_type.to_ne_bytes();
                let class_bytes = class.to_ne_bytes();
                let mut template = vec![
                    (CKA_TOKEN, &[CK_TRUE as u8][..]),
                    (CKA_CLASS, &class_bytes[..]),
                    (CKA_KEY_TYPE, &key_type[..]),
                ];
                if let Some(label) = label {
                    template.push((CKA_LABEL, label.as_bytes()));
                }
                if let Some(id) = selector.id.as_deref() {
                    template.push((CKA_ID, id));
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
                    let uri = crate::pkcs11_uri::object_uri_from_prefix(
                        &uri_prefix,
                        class,
                        label.as_bytes(),
                        &id,
                    );
                    let binding = HsmAuthCredentialBinding {
                        key: crate::key_scope::BoundKey::from_session(session.clone(), handle)?,
                        credential: HsmAuthCredential {
                            label,
                            algorithm,
                            retries: u8::try_from(retries).map_err(|_| CKR_DEVICE_ERROR)?,
                            touch_required: touch.as_slice() == [CK_TRUE as u8],
                            public_key,
                        },
                        source: serial.clone(),
                        uri,
                    };
                    if let Some(selected) = select(binding)? {
                        return Ok(Some(selected));
                    }
                }
            }
        }
        Ok(None)
    }

    #[cfg(test)]
    pub(crate) fn ordinary_credentials(
        &self,
        selector: &crate::pkcs11_uri::ClientAuthUri,
        target: &std::sync::Weak<Mutex<SlotContext>>,
    ) -> Result<Vec<OrdinaryCredential>, Error> {
        let mut credentials = Vec::new();
        self.find_ordinary_credential(selector, target, |credential| {
            credentials.push(credential);
            Ok(None::<()>)
        })?;
        Ok(credentials)
    }

    #[cfg(test)]
    pub(crate) fn hsmauth_credentials(
        &self,
        selector: &crate::pkcs11_uri::ClientAuthUri,
        asymmetric_only: bool,
    ) -> Result<Vec<HsmAuthCredentialBinding>, Error> {
        let mut credentials = Vec::new();
        self.find_hsmauth_credential(selector, asymmetric_only, |credential| {
            credentials.push(credential);
            Ok(None::<()>)
        })?;
        Ok(credentials)
    }
}
#[derive(Clone)]
pub(crate) struct HsmAuthCredentialBinding {
    pub(crate) key: crate::key_scope::BoundKey,
    pub(crate) credential: HsmAuthCredential,
    source: String,
    uri: String,
}
impl HsmAuthCredentialBinding {
    pub(crate) fn source_identifier(&self) -> &str {
        &self.source
    }
    pub(crate) fn slot_label(&self) -> String {
        format!("HSM Auth #{}", self.source)
    }
    pub(crate) fn uri(&self) -> &str {
        &self.uri
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
/// bind a private key or authorize the source until exact or ordered wildcard
/// selection has chosen it.
pub(crate) struct OrdinaryCredential {
    symmetric: bool,
    pub(crate) session: Arc<ProviderSession>,
    pub(crate) label: String,
    id: Option<Vec<u8>>,
    pub(crate) public_key: Option<Vec<u8>>,
    uri_prefix: String,
}
impl OrdinaryCredential {
    pub(crate) fn description(&self) -> String {
        let (class, label, id) = if self.symmetric {
            (
                CKO_SECRET_KEY as CK_OBJECT_CLASS,
                self.label.clone(),
                &[][..],
            )
        } else {
            (
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                self.label.clone(),
                self.id.as_deref().unwrap_or_default(),
            )
        };
        crate::pkcs11_uri::object_uri_from_prefix(&self.uri_prefix, class, label.as_bytes(), id)
    }

    pub(crate) fn authorize(
        &self,
        password: Option<&[u8]>,
        trust_prefix: Option<std::ffi::OsString>,
    ) -> Result<YubiHsmPkcs11AuthenticationMaterial, Error> {
        self.session.authorize_optional(password)?;
        if self.symmetric {
            return Ok(YubiHsmPkcs11AuthenticationMaterial::Symmetric(
                crate::key_scope::SymmetricCredential::find(
                    self.session.clone(),
                    &self.label,
                    true,
                )?,
            ));
        }
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
        let handle = match private.as_slice() {
            [handle] => *handle,
            [] => return Err(CKR_KEY_HANDLE_INVALID.into()),
            _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        };
        if self.session.attribute(handle, CKA_DERIVE)?.as_slice() != [CK_TRUE as u8] {
            return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
        }
        let credential = crate::key_scope::BoundKey::from_session(self.session.clone(), handle)?;
        if let Some(public_key) = &self.public_key {
            let mut scope = crate::key_scope::Pkcs11KeyScope::for_key(&credential)?;
            let key = scope.bind(&credential)?;
            if scope.p256_public(&key)? != *public_key {
                return Err(CKR_PUBLIC_KEY_INVALID.into());
            }
        }
        Ok(YubiHsmPkcs11AuthenticationMaterial::AsymmetricCredential {
            credential,
            trust_prefix,
        })
    }
}
