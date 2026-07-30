use crate::*;

const SOFTWARE_SLOT_DESCRIPTION_PREFIX: &str = "pkcs11rs software slot: ";
const SOFTWARE_MANUFACTURER: &str = "pkcs11rs";
const SOFTWARE_MODEL: &str = "Software";

#[derive(Debug)]
pub(crate) struct SoftwareSlot {
    name: String,
    serial: String,
}

#[derive(Debug)]
struct SoftwareSession {
    slot_id: CK_SLOT_ID,
    flags: CK_FLAGS,
}

impl SoftwareSlot {
    pub(crate) fn new(name: String, ordinal: usize) -> Self {
        Self {
            name,
            serial: format!("SOFTWARE{ordinal:08}"),
        }
    }

    fn description(&self) -> String {
        format!("{SOFTWARE_SLOT_DESCRIPTION_PREFIX}{}", self.name)
    }
}

impl Slot for SoftwareSlot {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn kind(&self) -> SlotKind {
        SlotKind::Software
    }

    fn physical_device_key(&self) -> Option<crate::device::PhysicalDeviceKey> {
        None
    }

    fn software_token_name(&self) -> Option<&str> {
        Some(&self.name)
    }

    fn name(&self) -> String {
        self.description()
    }

    fn manufacturer(&self) -> &str {
        SOFTWARE_MANUFACTURER
    }

    fn product(&self) -> &str {
        SOFTWARE_MODEL
    }

    fn serial(&self) -> &str {
        &self.serial
    }

    fn major(&self) -> u8 {
        1
    }

    fn minor(&self) -> u8 {
        0
    }

    fn hardware_major(&self) -> u8 {
        0
    }

    fn hardware_minor(&self) -> u8 {
        0
    }

    fn is_present(&self) -> bool {
        true
    }

    fn open_session(&mut self, slot_id: CK_SLOT_ID, flags: CK_FLAGS) -> Box<dyn BackendSession> {
        Box::new(SoftwareSession { slot_id, flags })
    }

    fn login(&mut self, _pin: &[u8]) -> Result<(), Error> {
        Err(CKR_USER_TYPE_INVALID.into())
    }

    fn logout(&mut self) -> Result<(), Error> {
        Err(CKR_USER_NOT_LOGGED_IN.into())
    }

    fn init_slot(&mut self) -> Result<(), Error> {
        Ok(())
    }

    fn get_slot_info(&self, info: &mut CK_SLOT_INFO) -> Result<(), Error> {
        str_pad(&self.description(), &mut info.slotDescription);
        str_pad(SOFTWARE_MANUFACTURER, &mut info.manufacturerID);
        info.flags = CKF_TOKEN_PRESENT as CK_FLAGS;
        info.hardwareVersion.major = 0;
        info.hardwareVersion.minor = 0;
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        Ok(())
    }

    fn get_token_info(&self, info: &mut CK_TOKEN_INFO) -> Result<(), Error> {
        str_pad(&self.name, &mut info.label);
        str_pad(SOFTWARE_MANUFACTURER, &mut info.manufacturerID);
        str_pad(SOFTWARE_MODEL, &mut info.model);
        str_pad(&self.serial, &mut info.serialNumber);
        info.flags = (CKF_RNG | CKF_TOKEN_INITIALIZED) as CK_FLAGS;
        info.ulMaxSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulSessionCount = 0;
        info.ulMaxRwSessionCount = CK_EFFECTIVELY_INFINITE as CK_ULONG;
        info.ulRwSessionCount = 0;
        info.ulMaxPinLen = 0;
        info.ulMinPinLen = 0;
        info.ulTotalPublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePublicMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulTotalPrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.ulFreePrivateMemory = CK_UNAVAILABLE_INFORMATION as CK_ULONG;
        info.hardwareVersion.major = 0;
        info.hardwareVersion.minor = 0;
        info.firmwareVersion.major = self.major();
        info.firmwareVersion.minor = self.minor();
        info.utcTime.fill(0);
        Ok(())
    }

    fn backend_mechanisms(&self) -> Vec<MechanismDetails> {
        Vec::new()
    }

    fn supports_software_private_operations(&self) -> bool {
        true
    }

    fn private_objects_require_login(&self) -> bool {
        false
    }

    fn flags(&self) -> CK_FLAGS {
        CKF_TOKEN_PRESENT as CK_FLAGS
    }

    fn label(&self) -> String {
        self.name.clone()
    }

    fn model(&self) -> &str {
        SOFTWARE_MODEL
    }
}

impl BackendSession for SoftwareSession {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn slotID(&self) -> CK_SLOT_ID {
        self.slot_id
    }

    fn flags(&self) -> CK_FLAGS {
        self.flags
    }

    fn get_session_info(&self) -> Result<(), Error> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_identifies_a_non_hardware_slot() {
        let slot = SoftwareSlot::new(String::from("signing"), 3);
        let mut slot_info = unsafe { std::mem::zeroed::<CK_SLOT_INFO>() };
        slot.get_slot_info(&mut slot_info).unwrap();
        assert_eq!(slot_info.flags, CKF_TOKEN_PRESENT as CK_FLAGS);
        assert_eq!(slot_info.flags & CKF_HW_SLOT as CK_FLAGS, 0);
        assert_eq!(
            &slot_info.slotDescription[..b"pkcs11rs software slot: signing".len()],
            b"pkcs11rs software slot: signing"
        );

        let mut token_info = unsafe { std::mem::zeroed::<CK_TOKEN_INFO>() };
        slot.get_token_info(&mut token_info).unwrap();
        assert_eq!(
            token_info.flags,
            (CKF_RNG | CKF_TOKEN_INITIALIZED) as CK_FLAGS
        );
        assert_eq!(&token_info.label[..b"signing".len()], b"signing");
        assert_eq!(&token_info.serialNumber, b"SOFTWARE00000003");
        assert_eq!(token_info.ulMinPinLen, 0);
        assert_eq!(token_info.ulMaxPinLen, 0);
    }

    #[test]
    fn mechanisms_are_the_exact_software_union_without_hardware_flags() {
        let mechanisms = Slot::mechanisms(&SoftwareSlot::new(String::from("mechanism-test"), 0));
        assert_eq!(mechanisms.len(), 49);
        assert_eq!(
            mechanisms
                .iter()
                .map(|mechanism| mechanism.type_)
                .collect::<std::collections::HashSet<_>>()
                .len(),
            mechanisms.len()
        );
        assert!(mechanisms
            .iter()
            .all(|mechanism| mechanism.flags & CKF_HW as CK_FLAGS == 0));
        assert!(!mechanisms
            .iter()
            .any(|mechanism| mechanism.type_ == CKM_GENERIC_SECRET_KEY_GEN as CK_MECHANISM_TYPE));

        for mechanism in mechanisms {
            let (min, max, flags) = match mechanism.type_ {
                x if x == CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE => {
                    (1024, 4096, CKF_GENERATE_KEY_PAIR)
                }
                x if [CKM_RSA_X_509, CKM_RSA_PKCS]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (
                        1024,
                        4096,
                        CKF_ENCRYPT | CKF_DECRYPT | CKF_SIGN | CKF_VERIFY,
                    )
                }
                x if x == CKM_RSA_PKCS_OAEP as CK_MECHANISM_TYPE => {
                    (1024, 4096, CKF_ENCRYPT | CKF_DECRYPT)
                }
                x if x == CKM_RSA_PKCS_PSS as CK_MECHANISM_TYPE
                    || [
                        CKM_SHA1_RSA_PKCS,
                        CKM_SHA224_RSA_PKCS,
                        CKM_SHA256_RSA_PKCS,
                        CKM_SHA384_RSA_PKCS,
                        CKM_SHA512_RSA_PKCS,
                        CKM_SHA3_224_RSA_PKCS,
                        CKM_SHA3_256_RSA_PKCS,
                        CKM_SHA3_384_RSA_PKCS,
                        CKM_SHA3_512_RSA_PKCS,
                        CKM_SHA1_RSA_PKCS_PSS,
                        CKM_SHA224_RSA_PKCS_PSS,
                        CKM_SHA256_RSA_PKCS_PSS,
                        CKM_SHA384_RSA_PKCS_PSS,
                        CKM_SHA512_RSA_PKCS_PSS,
                        CKM_SHA3_224_RSA_PKCS_PSS,
                        CKM_SHA3_256_RSA_PKCS_PSS,
                        CKM_SHA3_384_RSA_PKCS_PSS,
                        CKM_SHA3_512_RSA_PKCS_PSS,
                    ]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (1024, 4096, CKF_SIGN | CKF_VERIFY)
                }
                x if x == CKM_EC_KEY_PAIR_GEN as CK_MECHANISM_TYPE => (
                    224,
                    521,
                    CKF_GENERATE_KEY_PAIR | CKF_EC_F_P | CKF_EC_NAMEDCURVE,
                ),
                x if [
                    CKM_ECDSA,
                    CKM_ECDSA_SHA1,
                    CKM_ECDSA_SHA224,
                    CKM_ECDSA_SHA256,
                    CKM_ECDSA_SHA384,
                    CKM_ECDSA_SHA512,
                    CKM_ECDSA_SHA3_224,
                    CKM_ECDSA_SHA3_256,
                    CKM_ECDSA_SHA3_384,
                    CKM_ECDSA_SHA3_512,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    (
                        224,
                        521,
                        CKF_SIGN | CKF_VERIFY | CKF_EC_F_P | CKF_EC_NAMEDCURVE,
                    )
                }
                x if [CKM_ECDH1_DERIVE, CKM_ECDH1_COFACTOR_DERIVE]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (224, 521, CKF_DERIVE)
                }
                x if [CKM_EC_EDWARDS_KEY_PAIR_GEN, CKM_EC_MONTGOMERY_KEY_PAIR_GEN]
                    .map(|type_| type_ as CK_MECHANISM_TYPE)
                    .contains(&x) =>
                {
                    (
                        255,
                        255,
                        CKF_GENERATE_KEY_PAIR | CKF_EC_NAMEDCURVE | CKF_EC_CURVENAME,
                    )
                }
                x if x == CKM_EDDSA as CK_MECHANISM_TYPE => (255, 255, CKF_SIGN | CKF_VERIFY),
                x if x == CKM_PKCS11RS_PROJECT_PUBLIC_KEY => (0, 0, CKF_DERIVE),
                x if [
                    CKM_SHA_1,
                    CKM_SHA224,
                    CKM_SHA256,
                    CKM_SHA384,
                    CKM_SHA512,
                    CKM_SHA3_224,
                    CKM_SHA3_256,
                    CKM_SHA3_384,
                    CKM_SHA3_512,
                ]
                .map(|type_| type_ as CK_MECHANISM_TYPE)
                .contains(&x) =>
                {
                    (0, 0, CKF_DIGEST)
                }
                other => panic!("unexpected software mechanism {other:#x}"),
            };
            assert_eq!(mechanism.min_key_size, min as CK_ULONG);
            assert_eq!(mechanism.max_key_size, max as CK_ULONG);
            assert_eq!(mechanism.flags, flags as CK_FLAGS);
        }
    }
}
