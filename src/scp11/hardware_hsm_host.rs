//! Temporary native HSM credential owned by the card qualification test.
use super::*;
use crate::{
    pkcs11_auth::Pkcs11Auth,
    pkcs11_provider::{Pkcs11Provider, ProviderSession},
    *,
};
use std::sync::Arc;

pub(super) struct HsmHost {
    owner: Arc<ProviderSession>,
    before: Vec<(u16, u8, u8)>,
    public: CK_OBJECT_HANDLE,
    private: CK_OBJECT_HANDLE,
}

fn inventory(owner: &ProviderSession) -> Result<Vec<(u16, u8, u8)>, Error> {
    let response = owner.call(|| {
        crate::with_session_context(owner.handle, |ctx| {
            ctx._get_session(owner.handle)?
                .1
                .yubihsm_command(&YubiHsmCommand::list_objects(&[])?)
        })
    })?;
    let mut result: Vec<_> = parse_yubihsm_object_list(&response)?
        .into_iter()
        .map(|o| (o.id, o.object_type, o.sequence))
        .collect();
    result.sort_unstable();
    Ok(result)
}

impl HsmHost {
    pub(super) fn generate(context: &ModuleContext, serial: &str) -> Result<Self, Error> {
        let child = {
            let slots = context.slot_contexts.read().map_err(|_| CKR_MUTEX_BAD)?;
            let matches: Vec<_> = slots
                .values()
                .filter(|child| {
                    let slot = child.lock().unwrap();
                    slot.slot.serial() == serial
                        && slot.slot.is_present()
                        && slot.slot.supports_yubihsm_management()
                })
                .cloned()
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "expected one selected physical source HSM"
            );
            matches[0].clone()
        };
        let owner = ProviderSession::open(Pkcs11Provider::from_slot(child)?)?;
        let pin = Zeroizing::new(
            std::env::var("PKCS11RS_TEST_SCP_HOST_HSM_PIN")
                .expect("source HSM bootstrap PIN required"),
        );
        owner.authorize(pin.as_bytes())?;
        drop(pin);
        let mut result = Self {
            before: inventory(&owner)?,
            owner,
            public: 0,
            private: 0,
        };
        let label = format!(
            "scp11-oce-{:x}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        );
        let yes = [CK_TRUE as u8];
        let no = [CK_FALSE as u8];
        let params = crate::pkcs11_auth::P256_PARAMS;
        let attribute = |kind, value: &[u8]| CK_ATTRIBUTE {
            type_: kind as _,
            pValue: value.as_ptr().cast_mut().cast(),
            ulValueLen: value.len() as _,
        };
        let mut public = [
            attribute(CKA_TOKEN, &yes),
            attribute(CKA_EC_PARAMS, params),
            attribute(CKA_LABEL, label.as_bytes()),
        ];
        let mut private = [
            attribute(CKA_TOKEN, &yes),
            attribute(CKA_PRIVATE, &yes),
            attribute(CKA_SENSITIVE, &yes),
            attribute(CKA_EXTRACTABLE, &no),
            attribute(CKA_DERIVE, &yes),
            attribute(CKA_SIGN, &no),
            attribute(CKA_LABEL, label.as_bytes()),
        ];
        let mut mechanism = CK_MECHANISM {
            mechanism: CKM_EC_KEY_PAIR_GEN as _,
            pParameter: std::ptr::null_mut(),
            ulParameterLen: 0,
        };
        result.owner.call(|| {
            api::rust::generate_key_pair(
                result.owner.handle,
                &mut mechanism,
                public.as_mut_ptr(),
                public.len() as _,
                private.as_mut_ptr(),
                private.len() as _,
                &mut result.public,
                &mut result.private,
            )
        })?;
        assert!(
            matches!(result.owner.attribute(result.private,CKA_VALUE),Err(Error::Generic(rv)) if rv==CKR_ATTRIBUTE_SENSITIVE as CK_RV)
        );
        assert_eq!(
            result
                .owner
                .attribute(result.private, CKA_TOKEN)?
                .as_slice(),
            &yes
        );
        assert!(
            result
                .owner
                .can_derive(result.private, CKM_PKCS11RS_PREFIXED_ECDH_DERIVE)?
        );
        let after = inventory(&result.owner)?;
        assert!(
            after.len() > result.before.len(),
            "key must exist as a native HSM object"
        );
        eprintln!(
            "HSM {serial}: generated nonextractable native P-256 OCE key; prefixed ECDH permitted"
        );
        Ok(result)
    }
    pub(super) fn public_key(&self) -> Result<p256::ecdsa::VerifyingKey, Error> {
        use der::Decode;
        let encoded = self.owner.attribute(self.public, CKA_EC_POINT)?;
        let point =
            <&der::asn1::OctetStringRef>::from_der(&encoded).map_err(|_| CKR_DEVICE_ERROR)?;
        p256::ecdsa::VerifyingKey::from_sec1_bytes(point.as_bytes())
            .map_err(|_| CKR_DEVICE_ERROR.into())
    }
    pub(super) fn credential(&self) -> Result<BoundKey, Error> {
        BoundKey::from_session(self.owner.clone(), self.private)
    }
    pub(super) fn cleanup(&mut self) -> Result<(), Error> {
        if self.public != 0 {
            self.owner.destroy(self.public)?;
            self.public = 0;
        }
        if self.private != 0 {
            self.owner.destroy(self.private)?;
            self.private = 0;
        }
        assert_eq!(
            inventory(&self.owner)?,
            self.before,
            "source HSM inventory must be restored"
        );
        eprintln!("Native HSM host credential removed; original HSM inventory restored");
        Ok(())
    }
}
impl Drop for HsmHost {
    fn drop(&mut self) {
        if (self.public != 0 || self.private != 0)
            && let Err(error) = self.cleanup()
        {
            eprintln!("HSM host credential cleanup requires attention: {error:?}");
        }
    }
}
