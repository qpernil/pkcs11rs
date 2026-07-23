use crate::{
    error::Error,
    scp03::{environment_byte, parse_hex, CommandApdu, Scp03Session},
    secure_channel_crypto::aes_cmac,
    Connector, CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_PIN_INCORRECT,
    CKR_USER_PIN_NOT_INITIALIZED,
};
use openssl::{
    bn::BigNumContext,
    derive::Deriver,
    ec::{EcGroup, EcKey, EcPoint, PointConversionForm},
    hash::{Hasher, MessageDigest},
    memcmp,
    nid::Nid,
    pkey::{PKey, Private, Public},
    x509::X509,
};
use std::{env, fs};
use zeroize::Zeroizing;

const SCP11A_KEY_ID: u8 = 0x11;
const SCP11B_KEY_ID: u8 = 0x13;
const SCP11C_KEY_ID: u8 = 0x15;
const SCP11_SECURITY_LEVEL: u8 = 0x33;
const KEY_USAGE: u8 = 0x3c;
const KEY_TYPE_AES: u8 = 0x88;
const KEY_LENGTH_AES_128: u8 = 16;
const SESSION_KEY_LENGTH: usize = 16;
const DERIVED_KEY_COUNT: usize = 5;
const YUBICO_ATTESTATION_ROOT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/certificates/yubikey/yubico-attestation-root-1.pem"
));

pub(crate) type Scp11CertificateCacheKey = (u8, u8, [u8; 32]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scp11Variant {
    A,
    B,
    C,
}

impl Scp11Variant {
    fn parameter(self) -> u8 {
        match self {
            Self::A => 0x01,
            Self::B => 0x00,
            Self::C => 0x03,
        }
    }

    fn key_id(self) -> u8 {
        match self {
            Self::A => SCP11A_KEY_ID,
            Self::B => SCP11B_KEY_ID,
            Self::C => SCP11C_KEY_ID,
        }
    }

    fn instruction(self) -> u8 {
        match self {
            Self::A => 0x82,
            Self::B => 0x88,
            Self::C => 0x82,
        }
    }
}

struct Scp11aHostCredentials {
    key_version: u8,
    key_id: u8,
    private_key: EcKey<Private>,
    certificates: Vec<Vec<u8>>,
}

pub(crate) struct Scp11KeySet {
    variant: Scp11Variant,
    key_version: u8,
    card_public_key: Option<EcKey<Public>>,
    certificate_trust: Option<crate::certificate_chain::CertificateTrust>,
    host: Option<Scp11aHostCredentials>,
}

impl std::fmt::Debug for Scp11KeySet {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        fmt.debug_struct("Scp11KeySet")
            .field("variant", &self.variant)
            .field("key_version", &self.key_version)
            .field("curve", &"P-256")
            .field("oce_authenticated", &self.host.is_some())
            .finish_non_exhaustive()
    }
}

impl Scp11KeySet {
    pub(crate) fn from_environment(variant: Scp11Variant) -> Result<Self, Error> {
        let point = env::var("PKCS11RS_SCP11_SD_PUBLIC_KEY");
        let ca_certificate = env::var("PKCS11RS_SCP11_SD_CA_CERTIFICATE");
        let (card_public_key, certificate_trust) = match (point, ca_certificate) {
            (Ok(point), Err(env::VarError::NotPresent)) => {
                (Some(parse_public_point(&parse_hex(&point)?)?), None)
            }
            (Err(env::VarError::NotPresent), Ok(path)) => {
                let anchors = load_certificates(&path)?;
                (
                    None,
                    Some(crate::certificate_chain::CertificateTrust::new(
                        &anchors,
                    )?),
                )
            }
            (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => (
                None,
                Some(crate::certificate_chain::CertificateTrust::new(&[
                    X509::from_pem(YUBICO_ATTESTATION_ROOT)?.to_der()?,
                ])?),
            ),
            (Err(env::VarError::NotUnicode(_)), _)
            | (_, Err(env::VarError::NotUnicode(_)))
            | (Ok(_), Ok(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
        };
        let key_version = environment_byte("PKCS11RS_SCP11_KEY_VERSION", 1)?;
        if key_version & 0x80 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let host = match variant {
            Scp11Variant::A | Scp11Variant::C => Some(Scp11aHostCredentials::from_environment()?),
            Scp11Variant::B => None,
        };
        Ok(Self {
            variant,
            key_version,
            card_public_key,
            certificate_trust,
            host,
        })
    }

    #[cfg(test)]
    pub(crate) fn scp11b_from_certificates(
        key_version: u8,
        certificates: &[Vec<u8>],
        trust_anchors: &[Vec<u8>],
    ) -> Result<Self, Error> {
        if key_version == 0 || key_version & 0x80 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Self {
            variant: Scp11Variant::B,
            key_version,
            card_public_key: Some(card_public_key_from_certificates(
                certificates,
                &crate::certificate_chain::CertificateTrust::new(trust_anchors)?,
            )?),
            certificate_trust: None,
            host: None,
        })
    }

    pub(crate) fn authenticate_selected(
        &self,
        connector: &dyn Connector,
    ) -> Result<Scp03Session, Error> {
        let card_public_key = self.card_public_key.as_ref().ok_or(CKR_ARGUMENTS_BAD)?;
        let group = p256_group()?;
        let ephemeral = EcKey::generate(&group)?;
        self.establish_with_ephemeral_and_card_key(connector, ephemeral, card_public_key)
    }

    pub(crate) fn authenticate_application(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
        cached_public_point: Option<&[u8]>,
    ) -> Result<(Scp03Session, Option<Vec<u8>>), Error> {
        if self.card_public_key.is_some() {
            return self
                .authenticate_selected(connector)
                .map(|session| (session, None));
        }
        if let Some(point) = cached_public_point {
            let card_public_key = parse_public_point(point)?;
            let group = p256_group()?;
            let ephemeral = EcKey::generate(&group)?;
            return self
                .establish_with_ephemeral_and_card_key(connector, ephemeral, &card_public_key)
                .map(|session| (session, None));
        }

        let issuer_sd_aid = crate::configured_issuer_security_domain_aid()?;
        let certificates = (|| {
            crate::scp03::select_application(connector, &issuer_sd_aid)?;
            crate::SecurityDomainClient.get_certificate_bundle(
                connector,
                crate::security_domain::KeyRef {
                    kid: self.variant.key_id(),
                    kvn: self.key_version,
                },
            )
        })();
        crate::scp03::select_application(connector, application_aid)?;
        let card_public_key = card_public_key_from_certificates(
            &certificates?,
            self.certificate_trust
                .as_ref()
                .ok_or(CKR_ARGUMENTS_BAD)?,
        )?;
        let group = p256_group()?;
        let ephemeral = EcKey::generate(&group)?;
        let point = encode_public_point(&card_public_key)?;
        self.establish_with_ephemeral_and_card_key(connector, ephemeral, &card_public_key)
            .map(|session| (session, Some(point)))
    }

    pub(crate) fn certificate_cache_key(&self) -> Option<Scp11CertificateCacheKey> {
        self.card_public_key.is_none().then(|| {
            (
                self.variant.key_id(),
                self.key_version,
                self.certificate_trust
                    .as_ref()
                    .expect("certificate trust exists without a static card key")
                    .fingerprint(),
            )
        })
    }

    #[cfg(test)]
    fn establish_with_ephemeral(
        &self,
        connector: &dyn Connector,
        ephemeral: EcKey<Private>,
    ) -> Result<Scp03Session, Error> {
        let card_public_key = self.card_public_key.as_ref().ok_or(CKR_ARGUMENTS_BAD)?;
        self.establish_with_ephemeral_and_card_key(connector, ephemeral, card_public_key)
    }

    fn establish_with_ephemeral_and_card_key(
        &self,
        connector: &dyn Connector,
        ephemeral: EcKey<Private>,
        card_public_key: &EcKey<Public>,
    ) -> Result<Scp03Session, Error> {
        validate_p256_private_key(&ephemeral)?;
        self.upload_host_certificates(connector)?;
        let host_ephemeral_point = encode_public_point(&ephemeral)?;
        let request_data = authentication_data(&host_ephemeral_point, self.variant.parameter())?;
        let authenticate = CommandApdu {
            cla: 0x80,
            ins: self.variant.instruction(),
            p1: self.key_version,
            p2: self.variant.key_id(),
            data: request_data.clone(),
            le: Some(256),
            extended: false,
        };
        let response = connector
            .send_apdu(&authenticate)?
            .require_success(&authenticate)?;
        let authentication = parse_authentication_response(&response.data)?;
        let card_ephemeral_key = parse_public_point(authentication.card_ephemeral_point)?;

        let ka1 = Zeroizing::new(ecdh(&ephemeral, &card_ephemeral_key)?);
        let static_or_ephemeral = self
            .host
            .as_ref()
            .map(|host| &host.private_key)
            .unwrap_or(&ephemeral);
        let ka2 = Zeroizing::new(ecdh(static_or_ephemeral, card_public_key)?);
        if ka1.len() != 32 || ka2.len() != 32 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let mut key_agreement = Zeroizing::new(Vec::with_capacity(ka1.len() + ka2.len()));
        key_agreement.extend_from_slice(&ka1);
        key_agreement.extend_from_slice(&ka2);
        let key_material = derive_key_material(&key_agreement)?;

        let mut receipt_input =
            Vec::with_capacity(request_data.len() + authentication.card_ephemeral_tlv.len());
        receipt_input.extend_from_slice(&request_data);
        receipt_input.extend_from_slice(authentication.card_ephemeral_tlv);
        let expected_receipt = aes_cmac(&key_material[..SESSION_KEY_LENGTH], &receipt_input)?;
        if !memcmp::eq(&expected_receipt, authentication.receipt) {
            return Err(CKR_PIN_INCORRECT.into());
        }

        Scp03Session::from_session_keys(
            key_material[16..32].to_vec(),
            key_material[32..48].to_vec(),
            key_material[48..64].to_vec(),
            None,
            self.host.is_some(),
            expected_receipt,
            SCP11_SECURITY_LEVEL,
        )
    }

    fn upload_host_certificates(&self, connector: &dyn Connector) -> Result<(), Error> {
        let Some(host) = self.host.as_ref() else {
            return Ok(());
        };
        for (index, certificate) in host.certificates.iter().enumerate() {
            let more = index + 1 < host.certificates.len();
            let upload = CommandApdu {
                cla: 0x80,
                ins: 0x2a,
                p1: host.key_version,
                p2: host.key_id | if more { 0x80 } else { 0 },
                data: certificate.clone(),
                le: None,
                extended: certificate.len() > u8::MAX as usize,
            };
            connector.send_apdu(&upload)?.require_success(&upload)?;
        }
        Ok(())
    }
}

impl Scp11aHostCredentials {
    fn from_environment() -> Result<Self, Error> {
        let key_path = env::var("PKCS11RS_SCP11_OCE_PRIVATE_KEY")
            .map_err(|_| Error::from(CKR_USER_PIN_NOT_INITIALIZED))?;
        let encoded_key = fs::read(key_path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let private_key = PKey::private_key_from_pem(&encoded_key)
            .or_else(|_| PKey::private_key_from_der(&encoded_key))
            .and_then(|key| key.ec_key())
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        validate_p256_private_key(&private_key)?;

        let certificate_paths = env::var("PKCS11RS_SCP11_OCE_CERTIFICATES")
            .map_err(|_| Error::from(CKR_USER_PIN_NOT_INITIALIZED))?;
        let certificates = load_certificates(&certificate_paths)?;
        let leaf =
            X509::from_der(certificates.last().ok_or(CKR_ARGUMENTS_BAD)?).map_err(Error::from)?;
        let leaf_key = leaf
            .public_key()
            .and_then(|key| key.ec_key())
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        if encode_public_point(&private_key)? != encode_public_point(&leaf_key)? {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        let key_version = environment_byte("PKCS11RS_SCP11_OCE_KEY_VERSION", 0)?;
        let key_id = environment_byte("PKCS11RS_SCP11_OCE_KEY_ID", 0)?;
        if key_version & 0x80 != 0 || key_id & 0x80 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(Self {
            key_version,
            key_id,
            private_key,
            certificates,
        })
    }
}

fn load_certificates(paths: &str) -> Result<Vec<Vec<u8>>, Error> {
    crate::certificate_chain::load(paths)
}

fn p256_group() -> Result<EcGroup, Error> {
    EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).map_err(Error::from)
}

fn validate_p256_private_key(key: &EcKey<Private>) -> Result<(), Error> {
    if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    Ok(())
}

fn parse_public_point(encoded: &[u8]) -> Result<EcKey<Public>, Error> {
    if encoded.len() != 65 || encoded.first() != Some(&0x04) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let group = p256_group()?;
    let mut context = BigNumContext::new()?;
    let point = EcPoint::from_bytes(&group, encoded, &mut context)
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let key = EcKey::from_public_key(&group, &point).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    Ok(key)
}

fn card_public_key_from_certificates(
    certificates: &[Vec<u8>],
    trust: &crate::certificate_chain::CertificateTrust,
) -> Result<EcKey<Public>, Error> {
    parse_public_point(&trust.validate_p256_public_point(certificates)?)
}

fn encode_public_point<T>(key: &EcKey<T>) -> Result<Vec<u8>, Error>
where
    T: openssl::pkey::HasPublic,
{
    let mut context = BigNumContext::new()?;
    key.public_key()
        .to_bytes(key.group(), PointConversionForm::UNCOMPRESSED, &mut context)
        .map_err(Error::from)
}

fn ecdh(private: &EcKey<Private>, peer: &EcKey<Public>) -> Result<Vec<u8>, Error> {
    let private = PKey::from_ec_key(private.clone())?;
    let peer = PKey::from_ec_key(peer.clone())?;
    let mut deriver = Deriver::new(&private)?;
    deriver.set_peer(&peer)?;
    deriver.derive_to_vec().map_err(Error::from)
}

fn authentication_data(host_ephemeral_point: &[u8], parameter: u8) -> Result<Vec<u8>, Error> {
    if host_ephemeral_point.len() != 65 || host_ephemeral_point.first() != Some(&0x04) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let parameters = encode_tlv(
        &[0xa6],
        &[
            encode_tlv(&[0x90], &[0x11, parameter])?,
            encode_tlv(&[0x95], &[KEY_USAGE])?,
            encode_tlv(&[0x80], &[KEY_TYPE_AES])?,
            encode_tlv(&[0x81], &[KEY_LENGTH_AES_128])?,
        ]
        .concat(),
    )?;
    let public_key = encode_tlv(&[0x5f, 0x49], host_ephemeral_point)?;
    Ok([parameters, public_key].concat())
}

fn derive_key_material(key_agreement: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    if key_agreement.len() != 64 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let shared_info = [KEY_USAGE, KEY_TYPE_AES, KEY_LENGTH_AES_128];
    let required = SESSION_KEY_LENGTH * DERIVED_KEY_COUNT;
    let mut output = Zeroizing::new(Vec::with_capacity(96));
    for counter in 1u32..=3 {
        let mut hasher = Hasher::new(MessageDigest::sha256())?;
        hasher.update(key_agreement)?;
        hasher.update(&counter.to_be_bytes())?;
        hasher.update(&shared_info)?;
        output.extend_from_slice(&hasher.finish()?);
    }
    output.truncate(required);
    Ok(output)
}

struct AuthenticationResponse<'a> {
    card_ephemeral_tlv: &'a [u8],
    card_ephemeral_point: &'a [u8],
    receipt: &'a [u8],
}

fn parse_authentication_response(data: &[u8]) -> Result<AuthenticationResponse<'_>, Error> {
    let mut remaining = data;
    let (card_ephemeral_tlv, card_ephemeral_point) = take_tlv(&mut remaining, &[0x5f, 0x49])?;
    let (_, receipt) = take_tlv(&mut remaining, &[0x86])?;
    if !remaining.is_empty()
        || card_ephemeral_point.len() != 65
        || card_ephemeral_point.first() != Some(&0x04)
        || receipt.len() != SESSION_KEY_LENGTH
    {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(AuthenticationResponse {
        card_ephemeral_tlv,
        card_ephemeral_point,
        receipt,
    })
}

fn encode_tlv(tag: &[u8], value: &[u8]) -> Result<Vec<u8>, Error> {
    if tag.is_empty() || value.len() > u16::MAX as usize {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let mut encoded = Vec::with_capacity(tag.len() + 3 + value.len());
    encoded.extend_from_slice(tag);
    if value.len() < 0x80 {
        encoded.push(value.len() as u8);
    } else if value.len() <= u8::MAX as usize {
        encoded.extend([0x81, value.len() as u8]);
    } else {
        encoded.push(0x82);
        encoded.extend_from_slice(&(value.len() as u16).to_be_bytes());
    }
    encoded.extend_from_slice(value);
    Ok(encoded)
}

fn take_tlv<'a>(input: &mut &'a [u8], expected_tag: &[u8]) -> Result<(&'a [u8], &'a [u8]), Error> {
    let encoded = *input;
    if expected_tag.is_empty() || !encoded.starts_with(expected_tag) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let mut offset = expected_tag.len();
    let first = *encoded.get(offset).ok_or(CKR_DEVICE_ERROR)?;
    offset += 1;
    let length = match first {
        length if length < 0x80 => length as usize,
        0x81 => {
            let length = *encoded.get(offset).ok_or(CKR_DEVICE_ERROR)? as usize;
            offset += 1;
            if length < 0x80 {
                return Err(CKR_DEVICE_ERROR.into());
            }
            length
        }
        0x82 => {
            let bytes: [u8; 2] = encoded
                .get(offset..offset + 2)
                .ok_or(CKR_DEVICE_ERROR)?
                .try_into()
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
            offset += 2;
            let length = u16::from_be_bytes(bytes) as usize;
            if length <= u8::MAX as usize {
                return Err(CKR_DEVICE_ERROR.into());
            }
            length
        }
        _ => return Err(CKR_DEVICE_ERROR.into()),
    };
    let total = offset.checked_add(length).ok_or(CKR_DEVICE_ERROR)?;
    let raw = encoded.get(..total).ok_or(CKR_DEVICE_ERROR)?;
    let value = encoded.get(offset..total).ok_or(CKR_DEVICE_ERROR)?;
    *input = &encoded[total..];
    Ok((raw, value))
}

#[cfg(test)]
mod tests;
