use crate::{
    secure_channel_crypto::{aes_cbc, aes_encrypt_block, AES_BLOCK_SIZE},
    CommandApdu, Connector, Error, ResponseApdu, Scp03Session, CKR_ARGUMENTS_BAD, CKR_DATA_INVALID,
    CKR_DEVICE_ERROR, CKR_DEVICE_MEMORY, CKR_KEY_SIZE_RANGE,
};
use openssl::{
    bn::BigNumContext,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    nid::Nid,
    pkey::PKey,
    symm::Mode,
    x509::X509,
};
use zeroize::Zeroizing;

const INS_GET_DATA: u8 = 0xca;
const INS_PUT_KEY: u8 = 0xd8;
const INS_STORE_DATA: u8 = 0xe2;
const INS_DELETE: u8 = 0xe4;
const INS_GENERATE_KEY: u8 = 0xf1;
const KEY_TYPE_AES: u32 = 0x88;
const KEY_TYPE_ECC_PUBLIC: u32 = 0xb0;
const KEY_TYPE_ECC_PRIVATE: u32 = 0xb1;
const KEY_TYPE_ECC_PARAMS: u32 = 0xf0;
const TAG_DELETE_KEY_ID: u32 = 0xd0;
const TAG_DELETE_KEY_VERSION: u32 = 0xd2;
const TAG_KEY_INFORMATION: u32 = 0xe0;
const TAG_CARD_RECOGNITION_DATA: u32 = 0x66;
const TAG_CA_KLOC_IDENTIFIERS: u32 = 0xff33;
const TAG_CA_KLCC_IDENTIFIERS: u32 = 0xff34;
const TAG_CERTIFICATE_STORE: u32 = 0xbf21;
const TAG_CPLC: u32 = 0x9f7f;
const STATUS_SUCCESS: u16 = 0x9000;
const STATUS_REFERENCE_DATA_NOT_FOUND: u16 = 0x6a88;

pub(crate) const KID_SCP03: u8 = 0x01;
pub(crate) const KID_SCP11A: u8 = 0x11;
pub(crate) const KID_SCP11B: u8 = 0x13;
pub(crate) const KID_SCP11C: u8 = 0x15;

pub(crate) struct Scp03ProvisioningKeys<'a> {
    pub(crate) enc: &'a [u8],
    pub(crate) mac: &'a [u8],
    pub(crate) dek: &'a [u8],
}

pub(crate) enum Scp11Administration {
    GenerateKey {
        key_ref: KeyRef,
        replace_kvn: u8,
        curve: u8,
    },
    PutPrivateKey {
        key_ref: KeyRef,
        replace_kvn: u8,
        encoded: Zeroizing<Vec<u8>>,
    },
    PutPublicKey {
        key_ref: KeyRef,
        replace_kvn: u8,
        encoded: Vec<u8>,
    },
    StoreCertificateChain {
        key_ref: KeyRef,
        certificates: Vec<Vec<u8>>,
    },
    StoreCaIssuer {
        key_ref: KeyRef,
        subject_key_identifier: Vec<u8>,
    },
    SetAllowlist {
        key_ref: KeyRef,
        serials: Vec<Vec<u8>>,
    },
    DeleteKey {
        key_ref: KeyRef,
        delete_last: bool,
    },
}

pub(crate) struct PreparedScp11Administration {
    command: CommandApdu,
    response: Scp11Response,
}

enum Scp11Response {
    Empty,
    Exact(Vec<u8>),
    GeneratedPublicKey(Scp11Curve),
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(crate) struct KeyRef {
    pub(crate) kid: u8,
    pub(crate) kvn: u8,
}

impl KeyRef {
    fn encoded(self) -> [u8; 2] {
        [self.kid, self.kvn]
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct KeyComponent {
    pub(crate) key_type: u8,
    pub(crate) length: u8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct KeyInfo {
    pub(crate) key_ref: KeyRef,
    pub(crate) components: Vec<KeyComponent>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CaIdentifierKind {
    Kloc,
    Klcc,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CaIdentifier {
    pub(crate) kind: CaIdentifierKind,
    pub(crate) key_ref: KeyRef,
    pub(crate) subject_key_identifier: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CertificateBundle {
    pub(crate) key_ref: KeyRef,
    pub(crate) certificates: Vec<Vec<u8>>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct SecurityDomainInfo {
    pub(crate) keys: Vec<KeyInfo>,
    pub(crate) card_recognition_data: Option<Vec<u8>>,
    pub(crate) cplc: Option<Vec<u8>>,
    pub(crate) ca_identifiers: Vec<CaIdentifier>,
    pub(crate) certificate_bundles: Vec<CertificateBundle>,
}

pub(crate) struct Client;

impl Client {
    pub(crate) fn put_scp03_key_set(
        &self,
        connector: &dyn Connector,
        session: &mut Scp03Session,
        new_kvn: u8,
        replace_kvn: u8,
        keys: &Scp03ProvisioningKeys<'_>,
    ) -> Result<(), Error> {
        let (command, expected) =
            scp03_put_key_command(session.static_dek()?, new_kvn, replace_kvn, keys)?;
        let response = session.transmit(connector, &command)?;
        require_success(&response)?;
        if response.data != expected {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(())
    }

    pub(crate) fn delete_scp03_key_set(
        &self,
        connector: &dyn Connector,
        session: &mut Scp03Session,
        kvn: u8,
        delete_last: bool,
    ) -> Result<(), Error> {
        session.require_oce_authentication()?;
        let command = scp03_delete_key_command(kvn, delete_last)?;
        let response = session.transmit(connector, &command)?;
        require_success(&response)?;
        if !response.data.is_empty() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(())
    }

    pub(crate) fn prepare_scp11_administration(
        &self,
        session: &Scp03Session,
        operation: &Scp11Administration,
    ) -> Result<PreparedScp11Administration, Error> {
        session.require_oce_authentication()?;
        let (command, response) = match operation {
            Scp11Administration::GenerateKey {
                key_ref,
                replace_kvn,
                curve,
            } => {
                validate_scp11_key_ref(*key_ref)?;
                let curve = Scp11Curve::from_id(*curve)?;
                let data = [
                    vec![key_ref.kvn],
                    encode_tlv(KEY_TYPE_ECC_PARAMS, &[curve.id()])?,
                ]
                .concat();
                (
                    administration_apdu(INS_GENERATE_KEY, *replace_kvn, key_ref.kid, data),
                    Scp11Response::GeneratedPublicKey(curve),
                )
            }
            Scp11Administration::PutPrivateKey {
                key_ref,
                replace_kvn,
                encoded,
            } => {
                validate_scp11_key_ref(*key_ref)?;
                let (curve, scalar) = parse_private_key(encoded)?;
                let wrapping_dek = session.static_dek()?;
                if wrapping_dek.len() != AES_BLOCK_SIZE || scalar.len() % AES_BLOCK_SIZE != 0 {
                    return Err(CKR_KEY_SIZE_RANGE.into());
                }
                let wrapped = aes_cbc(
                    wrapping_dek,
                    &[0; AES_BLOCK_SIZE],
                    scalar.as_slice(),
                    Mode::Encrypt,
                )?;
                let data = put_ec_key_data(key_ref.kvn, KEY_TYPE_ECC_PRIVATE, &wrapped, curve)?;
                (
                    administration_apdu(INS_PUT_KEY, *replace_kvn, key_ref.kid, data),
                    Scp11Response::Exact(vec![key_ref.kvn]),
                )
            }
            Scp11Administration::PutPublicKey {
                key_ref,
                replace_kvn,
                encoded,
            } => {
                validate_ec_public_key_ref(*key_ref)?;
                let (curve, point) = parse_public_key(encoded)?;
                let data = put_ec_key_data(key_ref.kvn, KEY_TYPE_ECC_PUBLIC, &point, curve)?;
                (
                    administration_apdu(INS_PUT_KEY, *replace_kvn, key_ref.kid, data),
                    Scp11Response::Exact(vec![key_ref.kvn]),
                )
            }
            Scp11Administration::StoreCertificateChain {
                key_ref,
                certificates,
            } => {
                validate_scp11_key_ref(*key_ref)?;
                validate_certificate_chain(certificates)?;
                let selector = encode_tlv(0x83, &key_ref.encoded())?;
                let selector = encode_tlv(0xa6, &selector)?;
                let certificates = certificates.concat();
                let data = [selector, encode_tlv(TAG_CERTIFICATE_STORE, &certificates)?].concat();
                (
                    administration_apdu(INS_STORE_DATA, 0x90, 0, data),
                    Scp11Response::Empty,
                )
            }
            Scp11Administration::StoreCaIssuer {
                key_ref,
                subject_key_identifier,
            } => {
                validate_ec_public_key_ref(*key_ref)?;
                if subject_key_identifier.is_empty() {
                    return Err(CKR_ARGUMENTS_BAD.into());
                }
                let klcc = matches!(key_ref.kid, KID_SCP11A | KID_SCP11B | KID_SCP11C);
                let selector = [
                    encode_tlv(0x80, &[u8::from(klcc)])?,
                    encode_tlv(0x42, subject_key_identifier)?,
                    encode_tlv(0x83, &key_ref.encoded())?,
                ]
                .concat();
                (
                    administration_apdu(INS_STORE_DATA, 0x90, 0, encode_tlv(0xa6, &selector)?),
                    Scp11Response::Empty,
                )
            }
            Scp11Administration::SetAllowlist { key_ref, serials } => {
                if !matches!(key_ref.kid, KID_SCP11A | KID_SCP11C) || key_ref.kvn == 0 {
                    return Err(CKR_ARGUMENTS_BAD.into());
                }
                let selector = encode_tlv(0x83, &key_ref.encoded())?;
                let serials = serials
                    .iter()
                    .map(|serial| {
                        let serial = canonical_positive_integer(serial)?;
                        encode_tlv(0x93, &serial)
                    })
                    .collect::<Result<Vec<_>, _>>()?
                    .concat();
                let data = [encode_tlv(0xa6, &selector)?, encode_tlv(0x70, &serials)?].concat();
                (
                    administration_apdu(INS_STORE_DATA, 0x90, 0, data),
                    Scp11Response::Empty,
                )
            }
            Scp11Administration::DeleteKey {
                key_ref,
                delete_last,
            } => {
                validate_ec_public_key_ref(*key_ref)?;
                let data = [
                    encode_tlv(TAG_DELETE_KEY_ID, &[key_ref.kid])?,
                    encode_tlv(TAG_DELETE_KEY_VERSION, &[key_ref.kvn])?,
                ]
                .concat();
                (
                    administration_apdu(INS_DELETE, 0, u8::from(*delete_last), data),
                    Scp11Response::Empty,
                )
            }
        };
        Ok(PreparedScp11Administration { command, response })
    }

    pub(crate) fn execute_scp11_administration(
        &self,
        connector: &dyn Connector,
        session: &mut Scp03Session,
        prepared: PreparedScp11Administration,
    ) -> Result<Vec<u8>, Error> {
        let response = session.transmit(connector, &prepared.command)?;
        require_success(&response)?;
        match prepared.response {
            Scp11Response::Empty if response.data.is_empty() => Ok(Vec::new()),
            Scp11Response::Exact(expected) if response.data == expected => Ok(Vec::new()),
            Scp11Response::GeneratedPublicKey(curve) => {
                parse_generated_public_key(&response.data, curve)
            }
            _ => Err(CKR_DEVICE_ERROR.into()),
        }
    }

    pub(crate) fn discover(&self, connector: &dyn Connector) -> Result<SecurityDomainInfo, Error> {
        let keys = self.get_key_information(connector)?;
        let card_recognition_data = self.get_card_recognition_data(connector)?;
        let cplc = self.get_cplc(connector)?;
        let ca_identifiers = self.get_supported_ca_identifiers(connector)?;

        let mut certificate_bundles = Vec::new();
        for key in &keys {
            if !matches!(key.key_ref.kid, KID_SCP11A | KID_SCP11B | KID_SCP11C) {
                continue;
            }
            let certificates = self.get_certificate_bundle(connector, key.key_ref)?;
            if !certificates.is_empty() {
                certificate_bundles.push(CertificateBundle {
                    key_ref: key.key_ref,
                    certificates,
                });
            }
        }

        Ok(SecurityDomainInfo {
            keys,
            card_recognition_data,
            cplc,
            ca_identifiers,
            certificate_bundles,
        })
    }

    pub(crate) fn get_key_information(
        &self,
        connector: &dyn Connector,
    ) -> Result<Vec<KeyInfo>, Error> {
        let encoded = self.get_data(connector, TAG_KEY_INFORMATION, Vec::new())?;
        parse_key_information(&encoded)
    }

    pub(crate) fn get_card_recognition_data(
        &self,
        connector: &dyn Connector,
    ) -> Result<Option<Vec<u8>>, Error> {
        self.get_data_optional(connector, TAG_CARD_RECOGNITION_DATA, Vec::new())?
            .map(|encoded| tlv_value(0x73, &encoded))
            .transpose()
    }

    pub(crate) fn get_cplc(&self, connector: &dyn Connector) -> Result<Option<Vec<u8>>, Error> {
        let cplc = self.get_data_optional(connector, TAG_CPLC, Vec::new())?;
        if cplc.as_ref().is_some_and(|value| value.len() != 42) {
            return Err(CKR_DATA_INVALID.into());
        }
        Ok(cplc)
    }

    pub(crate) fn get_supported_ca_identifiers(
        &self,
        connector: &dyn Connector,
    ) -> Result<Vec<CaIdentifier>, Error> {
        let mut identifiers = Vec::new();
        for (tag, kind) in [
            (TAG_CA_KLOC_IDENTIFIERS, CaIdentifierKind::Kloc),
            (TAG_CA_KLCC_IDENTIFIERS, CaIdentifierKind::Klcc),
        ] {
            if let Some(encoded) = self.get_data_optional(connector, tag, Vec::new())? {
                identifiers.extend(parse_ca_identifiers(&encoded, kind)?);
            }
        }
        Ok(identifiers)
    }

    pub(crate) fn get_certificate_bundle(
        &self,
        connector: &dyn Connector,
        key_ref: KeyRef,
    ) -> Result<Vec<Vec<u8>>, Error> {
        let key_ref = encode_tlv(0x83, &key_ref.encoded())?;
        let request = encode_tlv(0xa6, &key_ref)?;
        let Some(encoded) = self.get_data_optional(connector, TAG_CERTIFICATE_STORE, request)?
        else {
            return Ok(Vec::new());
        };
        parse_certificate_bundle(&encoded)
    }

    fn get_data(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<Vec<u8>, Error> {
        let response = self.send_get_data(connector, tag, data)?;
        if response.status != STATUS_SUCCESS {
            return Err(apdu_status_error(response.status));
        }
        Ok(response.data)
    }

    fn get_data_optional(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, Error> {
        let response = self.send_get_data(connector, tag, data)?;
        match response.status {
            STATUS_SUCCESS => Ok(Some(response.data)),
            STATUS_REFERENCE_DATA_NOT_FOUND => Ok(None),
            status => Err(apdu_status_error(status)),
        }
    }

    fn send_get_data(
        &self,
        connector: &dyn Connector,
        tag: u32,
        data: Vec<u8>,
    ) -> Result<ResponseApdu, Error> {
        if tag > u16::MAX as u32 {
            return Err(CKR_DATA_INVALID.into());
        }
        let le = data.is_empty().then_some(256);
        connector.send_apdu(&CommandApdu {
            cla: 0,
            ins: INS_GET_DATA,
            p1: (tag >> 8) as u8,
            p2: tag as u8,
            data,
            le,
            extended: false,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Scp11Curve {
    Secp256r1,
    Secp384r1,
    Secp521r1,
    BrainpoolP256r1,
    BrainpoolP384r1,
    BrainpoolP512r1,
}

impl Scp11Curve {
    fn from_id(id: u8) -> Result<Self, Error> {
        match id {
            0x00 => Ok(Self::Secp256r1),
            0x01 => Ok(Self::Secp384r1),
            0x02 => Ok(Self::Secp521r1),
            0x03 => Ok(Self::BrainpoolP256r1),
            0x05 => Ok(Self::BrainpoolP384r1),
            0x07 => Ok(Self::BrainpoolP512r1),
            _ => Err(CKR_ARGUMENTS_BAD.into()),
        }
    }

    fn from_nid(nid: Nid) -> Result<Self, Error> {
        match nid {
            Nid::X9_62_PRIME256V1 => Ok(Self::Secp256r1),
            Nid::SECP384R1 => Ok(Self::Secp384r1),
            Nid::SECP521R1 => Ok(Self::Secp521r1),
            Nid::BRAINPOOL_P256R1 => Ok(Self::BrainpoolP256r1),
            Nid::BRAINPOOL_P384R1 => Ok(Self::BrainpoolP384r1),
            Nid::BRAINPOOL_P512R1 => Ok(Self::BrainpoolP512r1),
            _ => Err(CKR_ARGUMENTS_BAD.into()),
        }
    }

    fn id(self) -> u8 {
        match self {
            Self::Secp256r1 => 0x00,
            Self::Secp384r1 => 0x01,
            Self::Secp521r1 => 0x02,
            Self::BrainpoolP256r1 => 0x03,
            Self::BrainpoolP384r1 => 0x05,
            Self::BrainpoolP512r1 => 0x07,
        }
    }

    fn nid(self) -> Nid {
        match self {
            Self::Secp256r1 => Nid::X9_62_PRIME256V1,
            Self::Secp384r1 => Nid::SECP384R1,
            Self::Secp521r1 => Nid::SECP521R1,
            Self::BrainpoolP256r1 => Nid::BRAINPOOL_P256R1,
            Self::BrainpoolP384r1 => Nid::BRAINPOOL_P384R1,
            Self::BrainpoolP512r1 => Nid::BRAINPOOL_P512R1,
        }
    }

    fn public_point_length(self) -> Result<usize, Error> {
        let group = EcGroup::from_curve_name(self.nid())?;
        Ok(1 + 2 * group.degree().div_ceil(8) as usize)
    }
}

pub(crate) fn scp11_public_point_length(curve: u8) -> Result<usize, Error> {
    Scp11Curve::from_id(curve)?.public_point_length()
}

fn validate_new_key_ref(key_ref: KeyRef) -> Result<(), Error> {
    if key_ref.kvn == 0 {
        Err(CKR_ARGUMENTS_BAD.into())
    } else {
        Ok(())
    }
}

fn validate_scp11_key_ref(key_ref: KeyRef) -> Result<(), Error> {
    validate_new_key_ref(key_ref)?;
    if matches!(key_ref.kid, KID_SCP11A | KID_SCP11B | KID_SCP11C) {
        Ok(())
    } else {
        Err(CKR_ARGUMENTS_BAD.into())
    }
}

fn validate_ec_public_key_ref(key_ref: KeyRef) -> Result<(), Error> {
    validate_new_key_ref(key_ref)?;
    if matches!(
        key_ref.kid,
        0x10 | KID_SCP11A | KID_SCP11B | KID_SCP11C | 0x20..=0x2f
    ) {
        Ok(())
    } else {
        Err(CKR_ARGUMENTS_BAD.into())
    }
}

fn administration_apdu(ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> CommandApdu {
    CommandApdu {
        cla: if matches!(ins, INS_PUT_KEY | INS_DELETE | INS_GENERATE_KEY) {
            0x80
        } else {
            0
        },
        ins,
        p1,
        p2,
        data,
        le: None,
        extended: false,
    }
}

fn put_ec_key_data(
    kvn: u8,
    key_type: u32,
    key: &[u8],
    curve: Scp11Curve,
) -> Result<Vec<u8>, Error> {
    Ok([
        vec![kvn],
        encode_tlv(key_type, key)?,
        encode_tlv(KEY_TYPE_ECC_PARAMS, &[curve.id()])?,
        vec![0],
    ]
    .concat())
}

fn parse_private_key(encoded: &[u8]) -> Result<(Scp11Curve, Zeroizing<Vec<u8>>), Error> {
    let key = PKey::private_key_from_pkcs8(encoded)
        .or_else(|_| PKey::private_key_from_der(encoded))
        .and_then(|key| key.ec_key())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let curve = Scp11Curve::from_nid(key.group().curve_name().ok_or(CKR_ARGUMENTS_BAD)?)?;
    let length = key.group().degree().div_ceil(8);
    let scalar = key
        .private_key()
        .to_vec_padded(i32::try_from(length).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?)
        .map_err(Error::from)?;
    Ok((curve, Zeroizing::new(scalar)))
}

fn parse_public_key(encoded: &[u8]) -> Result<(Scp11Curve, Vec<u8>), Error> {
    let key = PKey::public_key_from_der(encoded)
        .and_then(|key| key.ec_key())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let curve = Scp11Curve::from_nid(key.group().curve_name().ok_or(CKR_ARGUMENTS_BAD)?)?;
    let mut context = BigNumContext::new()?;
    let point =
        key.public_key()
            .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)?;
    Ok((curve, point))
}

fn parse_generated_public_key(encoded: &[u8], curve: Scp11Curve) -> Result<Vec<u8>, Error> {
    let tlvs = parse_tlvs(encoded)?;
    if tlvs.len() != 1 || tlvs[0].tag != KEY_TYPE_ECC_PUBLIC {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let group = EcGroup::from_curve_name(curve.nid())?;
    let mut context = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, tlvs[0].value, &mut context)
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    key.check_key().map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    Ok(tlvs[0].value.to_vec())
}

fn validate_certificate_chain(certificates: &[Vec<u8>]) -> Result<(), Error> {
    if certificates.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let certificates = certificates
        .iter()
        .map(|encoded| X509::from_der(encoded).map_err(|_| Error::from(CKR_DATA_INVALID)))
        .collect::<Result<Vec<_>, _>>()?;
    for pair in certificates.windows(2) {
        let issuer = pair[0].public_key()?;
        if !pair[1].verify(&issuer)? {
            return Err(CKR_DATA_INVALID.into());
        }
    }
    Ok(())
}

fn canonical_positive_integer(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let stripped = encoded
        .iter()
        .position(|byte| *byte != 0)
        .map(|offset| &encoded[offset..])
        .ok_or(CKR_ARGUMENTS_BAD)?;
    let mut canonical = Vec::with_capacity(stripped.len() + 1);
    if stripped[0] & 0x80 != 0 {
        canonical.push(0);
    }
    canonical.extend_from_slice(stripped);
    Ok(canonical)
}

fn scp03_put_key_command(
    wrapping_dek: &[u8],
    new_kvn: u8,
    replace_kvn: u8,
    keys: &Scp03ProvisioningKeys<'_>,
) -> Result<(CommandApdu, Vec<u8>), Error> {
    if !(1..=254).contains(&new_kvn) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    if wrapping_dek.len() != AES_BLOCK_SIZE
        || [keys.enc, keys.mac, keys.dek]
            .iter()
            .any(|key| key.len() != AES_BLOCK_SIZE)
    {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }

    let mut data = vec![new_kvn];
    let mut expected = vec![new_kvn];
    for key in [keys.enc, keys.mac, keys.dek] {
        let wrapped = aes_cbc(wrapping_dek, &[0; AES_BLOCK_SIZE], key, Mode::Encrypt)?;
        data.extend_from_slice(&encode_tlv(KEY_TYPE_AES, &wrapped)?);
        let encrypted_ones = aes_encrypt_block(key, &[1; AES_BLOCK_SIZE])?;
        let kcv = &encrypted_ones[..3];
        data.push(kcv.len() as u8);
        data.extend_from_slice(kcv);
        expected.extend_from_slice(kcv);
    }

    Ok((
        CommandApdu {
            cla: 0x80,
            ins: INS_PUT_KEY,
            p1: replace_kvn,
            p2: KID_SCP03 | 0x80,
            data,
            le: None,
            extended: false,
        },
        expected,
    ))
}

fn scp03_delete_key_command(kvn: u8, delete_last: bool) -> Result<CommandApdu, Error> {
    if kvn == 0 {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(CommandApdu {
        cla: 0x80,
        ins: INS_DELETE,
        p1: 0,
        p2: u8::from(delete_last),
        data: encode_tlv(TAG_DELETE_KEY_VERSION, &[kvn])?,
        le: None,
        extended: false,
    })
}

fn require_success(response: &ResponseApdu) -> Result<(), Error> {
    if response.status == STATUS_SUCCESS {
        Ok(())
    } else {
        Err(apdu_status_error(response.status))
    }
}

fn apdu_status_error(status: u16) -> Error {
    log!(1, "Security Domain command failed with status {status:04x}");
    match status {
        0x6982 | 0x6985 => crate::CKR_USER_NOT_LOGGED_IN.into(),
        0x6700 => crate::CKR_DATA_LEN_RANGE.into(),
        0x6a84 => CKR_DEVICE_MEMORY.into(),
        0x6a80 | 0x6a88 => CKR_DATA_INVALID.into(),
        0x6a86 | 0x6b00 => crate::CKR_ARGUMENTS_BAD.into(),
        0x6d00 => crate::CKR_FUNCTION_NOT_SUPPORTED.into(),
        _ => CKR_DEVICE_ERROR.into(),
    }
}

fn parse_key_information(encoded: &[u8]) -> Result<Vec<KeyInfo>, Error> {
    parse_tlvs(encoded)?
        .into_iter()
        .map(|tlv| {
            if tlv.tag != 0xc0 || tlv.value.len() < 2 || tlv.value.len() % 2 != 0 {
                return Err(CKR_DATA_INVALID.into());
            }
            let components = tlv.value[2..]
                .chunks_exact(2)
                .map(|component| KeyComponent {
                    key_type: component[0],
                    length: component[1],
                })
                .collect();
            Ok(KeyInfo {
                key_ref: KeyRef {
                    kid: tlv.value[0],
                    kvn: tlv.value[1],
                },
                components,
            })
        })
        .collect()
}

fn parse_ca_identifiers(
    encoded: &[u8],
    kind: CaIdentifierKind,
) -> Result<Vec<CaIdentifier>, Error> {
    let tlvs = parse_tlvs(encoded)?;
    if tlvs.len() % 2 != 0 {
        return Err(CKR_DATA_INVALID.into());
    }
    tlvs.chunks_exact(2)
        .map(|pair| {
            let key_ref = &pair[1];
            if key_ref.tag != 0x83 || key_ref.value.len() != 2 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok(CaIdentifier {
                kind,
                key_ref: KeyRef {
                    kid: key_ref.value[0],
                    kvn: key_ref.value[1],
                },
                subject_key_identifier: pair[0].value.to_vec(),
            })
        })
        .collect()
}

fn parse_certificate_bundle(encoded: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    parse_tlvs(encoded)?
        .into_iter()
        .map(|tlv| {
            if tlv.tag != 0x30 {
                return Err(CKR_DATA_INVALID.into());
            }
            openssl::x509::X509::from_der(tlv.encoded)?;
            Ok(tlv.encoded.to_vec())
        })
        .collect()
}

fn tlv_value(tag: u32, encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let tlvs = parse_tlvs(encoded)?;
    if tlvs.len() != 1 || tlvs[0].tag != tag {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok(tlvs[0].value.to_vec())
}

fn encode_tlv(tag: u32, value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut encoded = Vec::with_capacity(value.len() + 5);
    match tag {
        0..=0xff => encoded.push(tag as u8),
        0x100..=0xffff => encoded.extend_from_slice(&(tag as u16).to_be_bytes()),
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    match value.len() {
        0..=0x7f => encoded.push(value.len() as u8),
        0x80..=0xff => encoded.extend([0x81, value.len() as u8]),
        0x100..=0xffff => {
            encoded.push(0x82);
            encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
        }
        _ => return Err(CKR_DATA_INVALID.into()),
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

#[derive(Clone, Copy)]
struct Tlv<'a> {
    tag: u32,
    value: &'a [u8],
    encoded: &'a [u8],
}

fn parse_tlvs(mut encoded: &[u8]) -> Result<Vec<Tlv<'_>>, Error> {
    let mut tlvs = Vec::new();
    while !encoded.is_empty() {
        let complete = encoded;
        let (tag, tag_length) = parse_tag(encoded)?;
        encoded = &encoded[tag_length..];
        let (length, length_length) = parse_length(encoded)?;
        encoded = &encoded[length_length..];
        let value = encoded.get(..length).ok_or(CKR_DATA_INVALID)?;
        let encoded_length = tag_length
            .checked_add(length_length)
            .and_then(|length| length.checked_add(value.len()))
            .ok_or(CKR_DATA_INVALID)?;
        tlvs.push(Tlv {
            tag,
            value,
            encoded: &complete[..encoded_length],
        });
        encoded = &encoded[length..];
    }
    Ok(tlvs)
}

fn parse_tag(encoded: &[u8]) -> Result<(u32, usize), Error> {
    let first = *encoded.first().ok_or(CKR_DATA_INVALID)?;
    if first & 0x1f != 0x1f {
        return Ok((first as u32, 1));
    }
    let second = *encoded.get(1).ok_or(CKR_DATA_INVALID)?;
    if second & 0x80 != 0 {
        return Err(CKR_DATA_INVALID.into());
    }
    Ok((((first as u32) << 8) | second as u32, 2))
}

fn parse_length(encoded: &[u8]) -> Result<(usize, usize), Error> {
    match *encoded.first().ok_or(CKR_DATA_INVALID)? {
        length @ 0..=0x7f => Ok((length as usize, 1)),
        0x81 => {
            let length = *encoded.get(1).ok_or(CKR_DATA_INVALID)? as usize;
            if length < 0x80 {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 2))
        }
        0x82 => {
            let length = encoded.get(1..3).ok_or(CKR_DATA_INVALID)?;
            let length = u16::from_be_bytes([length[0], length[1]]) as usize;
            if length <= 0xff {
                return Err(CKR_DATA_INVALID.into());
            }
            Ok((length, 3))
        }
        _ => Err(CKR_DATA_INVALID.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ApduCapabilities;
    use std::{cell::RefCell, collections::VecDeque, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        responses: RefCell<VecDeque<ResponseApdu>>,
        commands: RefCell<Vec<CommandApdu>>,
    }

    impl ScriptedConnector {
        fn new(responses: Vec<ResponseApdu>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
                commands: RefCell::new(Vec::new()),
            }
        }
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Yubico"
        }
        fn product(&self) -> &str {
            "YubiKey"
        }
        fn serial(&self) -> &str {
            "1"
        }
        fn major(&self) -> u8 {
            5
        }
        fn minor(&self) -> u8 {
            7
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn apdu_capabilities(&self) -> ApduCapabilities {
            ApduCapabilities::EXTENDED
        }
        fn send_apdu(&self, command: &CommandApdu) -> Result<ResponseApdu, Error> {
            self.commands.borrow_mut().push(command.clone());
            self.responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR.into())
        }
        fn transmit<'a>(
            &self,
            send_buffer: &[u8],
            receive_buffer: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            let command = CommandApdu::decode(send_buffer)?;
            self.commands.borrow_mut().push(command);
            let response = self
                .responses
                .borrow_mut()
                .pop_front()
                .ok_or(CKR_DEVICE_ERROR)?
                .encode();
            if response.len() > receive_buffer.len() {
                return Err(CKR_DEVICE_ERROR.into());
            }
            receive_buffer[..response.len()].copy_from_slice(&response);
            Ok(&receive_buffer[..response.len()])
        }
    }

    fn response(data: Vec<u8>, status: u16) -> ResponseApdu {
        ResponseApdu { data, status }
    }

    fn certificate() -> Vec<u8> {
        let group =
            openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1).unwrap();
        let key = openssl::ec::EcKey::generate(&group).unwrap();
        let key = openssl::pkey::PKey::from_ec_key(key).unwrap();
        let mut name = openssl::x509::X509NameBuilder::new().unwrap();
        name.append_entry_by_text("CN", "Security Domain test")
            .unwrap();
        let name = name.build();
        let mut certificate = openssl::x509::X509::builder().unwrap();
        certificate.set_version(2).unwrap();
        certificate.set_subject_name(&name).unwrap();
        certificate.set_issuer_name(&name).unwrap();
        certificate.set_pubkey(&key).unwrap();
        certificate
            .set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        certificate
            .set_not_after(openssl::asn1::Asn1Time::days_from_now(1).unwrap().as_ref())
            .unwrap();
        certificate
            .sign(&key, openssl::hash::MessageDigest::sha256())
            .unwrap();
        certificate.build().to_der().unwrap()
    }

    #[test]
    fn discovers_security_domain_metadata_and_certificates() {
        let key_info = [
            encode_tlv(0xc0, &[KID_SCP03, 0xff, 0x88, 0x10]).unwrap(),
            encode_tlv(0xc0, &[KID_SCP11B, 0x01, 0xb1, 0x20, 0xf0, 0x00]).unwrap(),
        ]
        .concat();
        let card_recognition = encode_tlv(0x73, &[0x01, 0x02]).unwrap();
        let ca_identifiers = [
            encode_tlv(0x42, &[0xaa, 0xbb]).unwrap(),
            encode_tlv(0x83, &[KID_SCP11B, 0x01]).unwrap(),
        ]
        .concat();
        let certificate = certificate();
        let mut cplc = vec![0; 42];
        cplc[..2].copy_from_slice(&[0x40, 0x90]);
        let connector = ScriptedConnector::new(vec![
            response(key_info, STATUS_SUCCESS),
            response(card_recognition, STATUS_SUCCESS),
            response(cplc.clone(), STATUS_SUCCESS),
            response(Vec::new(), STATUS_REFERENCE_DATA_NOT_FOUND),
            response(ca_identifiers, STATUS_SUCCESS),
            response(certificate.clone(), STATUS_SUCCESS),
        ]);

        let info = Client.discover(&connector).unwrap();
        assert_eq!(info.keys.len(), 2);
        assert_eq!(info.keys[0].key_ref, KeyRef { kid: 1, kvn: 0xff });
        assert_eq!(info.keys[1].components.len(), 2);
        assert_eq!(info.card_recognition_data, Some(vec![1, 2]));
        assert_eq!(info.cplc, Some(cplc));
        assert_eq!(info.ca_identifiers.len(), 1);
        assert_eq!(info.certificate_bundles[0].certificates, vec![certificate]);

        let commands = connector.commands.borrow();
        assert_eq!(commands.len(), 6);
        assert_eq!(
            (commands[0].ins, commands[0].p1, commands[0].p2),
            (0xca, 0, 0xe0)
        );
        assert_eq!((commands[2].p1, commands[2].p2), (0x9f, 0x7f));
        assert_eq!((commands[5].p1, commands[5].p2), (0xbf, 0x21));
        assert_eq!(commands[5].data, vec![0xa6, 4, 0x83, 2, 0x13, 1]);
        assert_eq!(commands[5].le, None);
    }

    #[test]
    fn rejects_malformed_security_domain_tlvs() {
        assert!(parse_key_information(&[0xc0, 3, 1, 2, 0x88]).is_err());
        assert!(parse_ca_identifiers(&[0x42, 1, 1], CaIdentifierKind::Kloc).is_err());
        assert!(parse_certificate_bundle(&[0x31, 0]).is_err());
        assert!(parse_certificate_bundle(&[0x30, 0]).is_err());
        assert!(parse_tlvs(&[0x42, 0x81, 0x01, 0]).is_err());
    }

    #[test]
    fn scp03_put_key_matches_yubico_wire_format() {
        let wrapping_dek = hex("404142434445464748494a4b4c4d4e4f");
        let enc = hex("000102030405060708090a0b0c0d0e0f");
        let mac = hex("101112131415161718191a1b1c1d1e1f");
        let dek = hex("202122232425262728292a2b2c2d2e2f");
        let (command, expected) = scp03_put_key_command(
            &wrapping_dek,
            2,
            0xff,
            &Scp03ProvisioningKeys {
                enc: &enc,
                mac: &mac,
                dek: &dek,
            },
        )
        .unwrap();

        assert_eq!(
            (command.cla, command.ins, command.p1, command.p2),
            (0x80, 0xd8, 0xff, 0x81)
        );
        assert_eq!(
            command.data,
            hex("02
                 88 10 3d0fa4b855d2a5aa4954b8b5df582a3a 03 c35280
                 88 10 790accda858b997029fa9ae50c9cd028 03 013808
                 88 10 8caa7f589aa0ceb6350a45e70a6e435b 03 840de5")
        );
        assert_eq!(expected, hex("02 c35280 013808 840de5"));
        assert_eq!(command.le, None);
        assert!(!command.extended);
    }

    #[test]
    fn scp03_put_key_requires_aes128_components_and_wrapping_dek() {
        let key = [0; AES_BLOCK_SIZE];
        let short = [0; AES_BLOCK_SIZE - 1];
        assert!(scp03_put_key_command(
            &short,
            1,
            0,
            &Scp03ProvisioningKeys {
                enc: &key,
                mac: &key,
                dek: &key,
            },
        )
        .is_err());
        assert!(scp03_put_key_command(
            &key,
            1,
            0,
            &Scp03ProvisioningKeys {
                enc: &short,
                mac: &key,
                dek: &key,
            },
        )
        .is_err());
        for reserved_kvn in [0, 255] {
            assert!(scp03_put_key_command(
                &key,
                reserved_kvn,
                0,
                &Scp03ProvisioningKeys {
                    enc: &key,
                    mac: &key,
                    dek: &key,
                },
            )
            .is_err());
        }
    }

    #[test]
    fn security_domain_statuses_preserve_device_capacity_errors() {
        let rv: crate::CK_RV = apdu_status_error(0x6a84).into();
        assert_eq!(rv, CKR_DEVICE_MEMORY as crate::CK_RV);
    }

    #[test]
    fn scp03_put_key_validates_the_card_kcv_response() {
        let wrapping_dek = hex("404142434445464748494a4b4c4d4e4f");
        let keys = Scp03ProvisioningKeys {
            enc: &hex("000102030405060708090a0b0c0d0e0f"),
            mac: &hex("101112131415161718191a1b1c1d1e1f"),
            dek: &hex("202122232425262728292a2b2c2d2e2f"),
        };
        let expected = hex("02 c35280 013808 840de5");
        let connector = ScriptedConnector::new(vec![response(expected, STATUS_SUCCESS)]);
        let mut session = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            Some(wrapping_dek.clone()),
            true,
            [0; 16],
            0,
        )
        .unwrap();
        Client
            .put_scp03_key_set(&connector, &mut session, 2, 0, &keys)
            .unwrap();

        let connector = ScriptedConnector::new(vec![response(
            hex("02 c35280 013808 840de4"),
            STATUS_SUCCESS,
        )]);
        let mut session = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            Some(wrapping_dek),
            true,
            [0; 16],
            0,
        )
        .unwrap();
        assert!(Client
            .put_scp03_key_set(&connector, &mut session, 2, 0, &keys)
            .is_err());
    }

    #[test]
    fn scp03_delete_key_set_uses_kvn_filter_and_explicit_last_key_flag() {
        let command = scp03_delete_key_command(2, true).unwrap();
        assert_eq!(
            (command.cla, command.ins, command.p1, command.p2),
            (0x80, 0xe4, 0, 1)
        );
        assert_eq!(command.data, hex("d2 01 02"));
        assert!(scp03_delete_key_command(0, false).is_err());
    }

    #[test]
    fn scp11_key_commands_match_yubico_wire_formats() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let ec_key = EcKey::generate(&group).unwrap();
        let key = PKey::from_ec_key(ec_key).unwrap();
        let mut session = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            Some(vec![0; 16]),
            true,
            [0; 16],
            0,
        )
        .unwrap();

        let generated = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::GenerateKey {
                    key_ref: KeyRef {
                        kid: KID_SCP11B,
                        kvn: 2,
                    },
                    replace_kvn: 1,
                    curve: 0,
                },
            )
            .unwrap();
        assert_eq!(
            (
                generated.command.cla,
                generated.command.ins,
                generated.command.p1,
                generated.command.p2,
            ),
            (0x80, 0xf1, 1, KID_SCP11B)
        );
        assert_eq!(generated.command.data, hex("02 f0 01 00"));

        let public = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::PutPublicKey {
                    key_ref: KeyRef {
                        kid: KID_SCP11A,
                        kvn: 3,
                    },
                    replace_kvn: 0,
                    encoded: key.public_key_to_der().unwrap(),
                },
            )
            .unwrap();
        assert_eq!(
            (public.command.ins, public.command.p1, public.command.p2),
            (0xd8, 0, KID_SCP11A)
        );
        assert_eq!(public.command.data[0], 3);
        assert_eq!(*public.command.data.last().unwrap(), 0);
        let public_tlvs =
            parse_tlvs(&public.command.data[1..public.command.data.len() - 1]).unwrap();
        assert_eq!(public_tlvs[0].tag, KEY_TYPE_ECC_PUBLIC);
        assert_eq!(public_tlvs[1].value, &[0]);

        let private = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::PutPrivateKey {
                    key_ref: KeyRef {
                        kid: KID_SCP11C,
                        kvn: 4,
                    },
                    replace_kvn: 2,
                    encoded: Zeroizing::new(key.private_key_to_pkcs8().unwrap()),
                },
            )
            .unwrap();
        assert_eq!(
            (private.command.ins, private.command.p1, private.command.p2),
            (0xd8, 2, KID_SCP11C)
        );
        let private_tlvs =
            parse_tlvs(&private.command.data[1..private.command.data.len() - 1]).unwrap();
        assert_eq!(private_tlvs[0].tag, KEY_TYPE_ECC_PRIVATE);
        assert_eq!(private_tlvs[0].value.len(), 32);
        assert_eq!(private_tlvs[1].value, &[0]);

        let point = public_tlvs[0].value.to_vec();
        let connector = ScriptedConnector::new(vec![response(
            encode_tlv(KEY_TYPE_ECC_PUBLIC, &point).unwrap(),
            STATUS_SUCCESS,
        )]);
        let output = Client
            .execute_scp11_administration(&connector, &mut session, generated)
            .unwrap();
        assert_eq!(output, point);
    }

    #[test]
    fn scp11_administration_requires_oce_authentication_and_dek_for_private_import() {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
        let key = PKey::from_ec_key(EcKey::generate(&group).unwrap()).unwrap();
        let operation = Scp11Administration::GenerateKey {
            key_ref: KeyRef {
                kid: KID_SCP11B,
                kvn: 1,
            },
            replace_kvn: 0,
            curve: 0,
        };
        let card_only = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            None,
            false,
            [0; 16],
            0,
        )
        .unwrap();
        assert!(Client
            .prepare_scp11_administration(&card_only, &operation)
            .is_err());

        let oce = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            None,
            true,
            [0; 16],
            0,
        )
        .unwrap();
        assert!(Client
            .prepare_scp11_administration(
                &oce,
                &Scp11Administration::PutPrivateKey {
                    key_ref: KeyRef {
                        kid: KID_SCP11A,
                        kvn: 1,
                    },
                    replace_kvn: 0,
                    encoded: Zeroizing::new(key.private_key_to_pkcs8().unwrap()),
                },
            )
            .is_err());
        assert!(Client
            .prepare_scp11_administration(&oce, &operation)
            .is_ok());
    }

    #[test]
    fn scp11_trust_and_exact_delete_commands_are_typed() {
        let session = Scp03Session::from_session_keys(
            vec![0; 16],
            vec![0; 16],
            vec![0; 16],
            None,
            true,
            [0; 16],
            0,
        )
        .unwrap();
        let key_ref = KeyRef {
            kid: KID_SCP11A,
            kvn: 2,
        };
        let certificate = certificate();
        let stored = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::StoreCertificateChain {
                    key_ref,
                    certificates: vec![certificate.clone()],
                },
            )
            .unwrap();
        assert_eq!(
            (stored.command.cla, stored.command.ins, stored.command.p1),
            (0, 0xe2, 0x90)
        );
        assert!(stored.command.data.ends_with(&certificate));

        let allowlist = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::SetAllowlist {
                    key_ref,
                    serials: vec![vec![0, 0x80]],
                },
            )
            .unwrap();
        assert!(allowlist.command.data.ends_with(&hex("70 04 93 02 00 80")));
        assert!(Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::SetAllowlist {
                    key_ref,
                    serials: vec![vec![0]],
                },
            )
            .is_err());

        let deleted = Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::DeleteKey {
                    key_ref,
                    delete_last: false,
                },
            )
            .unwrap();
        assert_eq!(deleted.command.data, hex("d0 01 11 d2 01 02"));
        assert!(Client
            .prepare_scp11_administration(
                &session,
                &Scp11Administration::DeleteKey {
                    key_ref: KeyRef {
                        kid: KID_SCP11A,
                        kvn: 0,
                    },
                    delete_last: false,
                },
            )
            .is_err());
    }

    fn hex(value: &str) -> Vec<u8> {
        value
            .bytes()
            .filter(|byte| !byte.is_ascii_whitespace())
            .collect::<Vec<_>>()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect()
    }
}
