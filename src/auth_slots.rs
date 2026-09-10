//! Authentication selects objects from existing PKCS #11 slots. This index
//! contains only weak slot references, never a second credential inventory.
use crate::{
    pkcs11_auth::Pkcs11Auth,
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    *,
};
use std::sync::RwLock;

#[derive(Debug, Default)]
pub(crate) struct AuthSlots {
    slots: RwLock<Vec<(SlotKind, std::sync::Weak<Mutex<SlotContext>>)>>,
    #[cfg(test)]
    fixture_owners: Vec<Arc<Mutex<SlotContext>>>,
}
impl AuthSlots {
    pub(crate) fn register(&self, slot: &Arc<Mutex<SlotContext>>) -> Result<(), Error> {
        let kind = slot
            .lock()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .slot
            .kind();
        let mut slots = self.slots.write().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
        slots.retain(|(_, entry)| entry.strong_count() != 0);
        if !slots
            .iter()
            .any(|(_, entry)| entry.ptr_eq(&Arc::downgrade(slot)))
        {
            slots.push((kind, Arc::downgrade(slot)));
        }
        Ok(())
    }
    pub(crate) fn matching(&self, kind: SlotKind) -> Result<Vec<Arc<Mutex<SlotContext>>>, Error> {
        Ok(self
            .slots
            .read()
            .map_err(|_| Error::from(CKR_MUTEX_BAD))?
            .iter()
            .filter(|(candidate, _)| *candidate == kind)
            .filter_map(|(_, slot)| slot.upgrade())
            .collect())
    }
    #[cfg(target_os = "ios")]
    pub(crate) fn remove(&self, slot: &Arc<Mutex<SlotContext>>) {
        if let Ok(mut slots) = self.slots.write() {
            slots.retain(|(_, entry)| !entry.ptr_eq(&Arc::downgrade(slot)));
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
    fn hsmauth_credentials(
        &self,
        label: Option<&str>,
        source: Option<&str>,
        asymmetric_only: bool,
    ) -> Result<Vec<HsmAuthCredentialBinding>, Error> {
        let mut result = Vec::new();
        for slot in self.matching(SlotKind::Ccid(CcidApplication::HsmAuth))? {
            let serial = {
                let context = slot.lock().map_err(|_| Error::from(CKR_MUTEX_BAD))?;
                if !context.slot.is_present() {
                    continue;
                }
                context.slot.serial().to_owned()
            };
            if source.is_some_and(|source| source != serial) {
                continue;
            }
            let session = ProviderSession::open(Pkcs11Provider::from_slot(slot)?)?;
            let class = (CKO_SECRET_KEY as CK_ULONG).to_ne_bytes();
            let mut template = vec![(CKA_TOKEN, &[CK_TRUE as u8][..]), (CKA_CLASS, &class[..])];
            if let Some(label) = label {
                template.push((CKA_LABEL, label.as_bytes()));
            }
            for handle in session.find(&template)? {
                let algorithm = session.attribute(handle, CKA_YUBICO_HSMAUTH_ALGORITHM as u32)?;
                let algorithm = CK_ULONG::from_ne_bytes(
                    algorithm
                        .as_slice()
                        .try_into()
                        .map_err(|_| CKR_DEVICE_ERROR)?,
                );
                let algorithm = if algorithm
                    == HsmAuthAlgorithm::Aes128YubicoAuthentication as CK_ULONG
                {
                    HsmAuthAlgorithm::Aes128YubicoAuthentication
                } else if algorithm == HsmAuthAlgorithm::EcP256YubicoAuthentication as CK_ULONG {
                    HsmAuthAlgorithm::EcP256YubicoAuthentication
                } else {
                    return Err(CKR_KEY_TYPE_INCONSISTENT.into());
                };
                if asymmetric_only && algorithm != HsmAuthAlgorithm::EcP256YubicoAuthentication {
                    continue;
                }
                let label = session.attribute(handle, CKA_LABEL)?;
                let label = String::from_utf8(label.to_vec()).map_err(|_| CKR_DEVICE_ERROR)?;
                let id = session.attribute(handle, CKA_ID)?;
                let public_key = if algorithm == HsmAuthAlgorithm::EcP256YubicoAuthentication {
                    let public = session.find(&[
                        (CKA_TOKEN, &[CK_TRUE as u8]),
                        (CKA_CLASS, &(CKO_PUBLIC_KEY as CK_ULONG).to_ne_bytes()),
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
                let touch = session.attribute(handle, CKA_YUBICO_HSMAUTH_TOUCH_REQUIRED as u32)?;
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
        Ok(result)
    }
    pub(crate) fn with_hsmauth_credential<T>(
        &self,
        login: &HsmAuthLogin<'_>,
        operation: impl FnOnce(&HsmAuthCredentialBinding) -> Result<T, Error>,
    ) -> Result<T, Error> {
        let candidates = self.hsmauth_credentials(Some(login.label), login.source, false)?;
        let [credential] = candidates.as_slice() else {
            return Err(CKR_PIN_INCORRECT.into());
        };
        operation(credential)
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
