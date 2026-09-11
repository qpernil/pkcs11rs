use crate::{
    CKK_AES, CKM_AES_CMAC, CKR_ARGUMENTS_BAD, CKR_DEVICE_ERROR, CKR_PIN_INCORRECT,
    CKR_SIGNATURE_INVALID, CKR_USER_PIN_NOT_INITIALIZED, Connector, TokenObjectTemplate,
    error::Error,
    key_scope::{BoundKey, KeyHandle, Pkcs11KeyScope, generic_template, readable_template},
    scp_key_provider::protect_p256,
    scp03::{CommandApdu, Scp03Session},
};
use software_key_core::software_signing::{
    EcCurve, KeyKind, SoftwarePublicKey, SoftwareSigningKey,
};
use std::fs;

#[cfg(test)]
use crate::scp03::parse_hex;

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
    "/certificates/yubikey/yubico-attestation-root-1.der"
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
    private_key: BoundKey,
    certificates: Vec<Vec<u8>>,
}

pub(crate) struct Scp11KeySet {
    variant: Scp11Variant,
    key_version: u8,
    card_public_key: Option<Vec<u8>>,
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
    pub(crate) fn from_configuration(
        variant: Scp11Variant,
        configuration: &crate::configuration::Scp11Configuration,
        pinentry: &crate::pinentry::Pinentry,
    ) -> Result<Self, Error> {
        let (card_public_key, certificate_trust) = match &configuration.trust {
            crate::configuration::Scp11TrustConfiguration::PublicKey(point) => {
                (Some(parse_public_point(point)?), None)
            }
            crate::configuration::Scp11TrustConfiguration::CaCertificate(path) => {
                let encoded = fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
                let anchors = vec![crate::certificate_chain::decode(&encoded)?];
                (
                    None,
                    Some(crate::certificate_chain::CertificateTrust::new(&anchors)?),
                )
            }
            crate::configuration::Scp11TrustConfiguration::Yubico => (
                None,
                Some(crate::certificate_chain::CertificateTrust::new(&[
                    crate::certificate_chain::decode(YUBICO_ATTESTATION_ROOT)?,
                ])?),
            ),
        };
        let host = match variant {
            Scp11Variant::A | Scp11Variant::C => Some(Scp11aHostCredentials::from_configuration(
                configuration
                    .oce
                    .as_ref()
                    .ok_or(CKR_USER_PIN_NOT_INITIALIZED)?,
                pinentry,
            )?),
            Scp11Variant::B => None,
        };
        Ok(Self {
            variant,
            key_version: configuration.key_version,
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
        self.establish_with_card_key(connector, card_public_key)
    }

    pub(crate) fn authenticate_application(
        &self,
        connector: &dyn Connector,
        application_aid: &[u8],
        issuer_sd_aid: &[u8],
        cached_public_point: Option<&[u8]>,
    ) -> Result<(Scp03Session, Option<Vec<u8>>), Error> {
        if self.card_public_key.is_some() {
            return self
                .authenticate_selected(connector)
                .map(|session| (session, None));
        }
        if let Some(point) = cached_public_point {
            let card_public_key = parse_public_point(point)?;
            return self
                .establish_with_card_key(connector, &card_public_key)
                .map(|session| (session, None));
        }

        let certificates = (|| {
            crate::scp03::select_application(connector, issuer_sd_aid)?;
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
            self.certificate_trust.as_ref().ok_or(CKR_ARGUMENTS_BAD)?,
        )?;
        let point = card_public_key.clone();
        self.establish_with_card_key(connector, &card_public_key)
            .map(|session| (session, Some(point)))
    }

    pub(crate) fn certificate_cache_key(&self) -> Option<Scp11CertificateCacheKey> {
        if self.card_public_key.is_some() {
            return None;
        }
        Some((
            self.variant.key_id(),
            self.key_version,
            self.certificate_trust.as_ref()?.fingerprint(),
        ))
    }

    #[cfg(test)]
    fn establish_with_ephemeral(
        &self,
        connector: &dyn Connector,
        ephemeral: SoftwareSigningKey,
    ) -> Result<Scp03Session, Error> {
        let card_public_key = self.card_public_key.as_ref().ok_or(CKR_ARGUMENTS_BAD)?;
        let mut scope = self.key_scope()?;
        let ephemeral = scope.import_p256(ephemeral)?;
        self.establish_with_ephemeral_and_card_key(connector, scope, ephemeral, card_public_key)
    }

    fn key_scope(&self) -> Result<Pkcs11KeyScope, Error> {
        match &self.host {
            Some(host) => Pkcs11KeyScope::for_key(&host.private_key),
            None => Pkcs11KeyScope::new(),
        }
    }

    fn establish_with_card_key(
        &self,
        connector: &dyn Connector,
        card_public_key: &[u8],
    ) -> Result<Scp03Session, Error> {
        let mut scope = self.key_scope()?;
        let ephemeral = scope.generate_p256()?;
        self.establish_with_ephemeral_and_card_key(connector, scope, ephemeral, card_public_key)
    }

    fn establish_with_ephemeral_and_card_key(
        &self,
        connector: &dyn Connector,
        mut scope: Pkcs11KeyScope,
        ephemeral: KeyHandle,
        card_public_key: &[u8],
    ) -> Result<Scp03Session, Error> {
        self.upload_host_certificates(connector)?;
        let host_ephemeral_point = scope.p256_public(&ephemeral)?;
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

        let credential = match &self.host {
            Some(host) => scope.bind(&host.private_key)?,
            None => ephemeral.clone(),
        };
        let material = scope.dual_ecdh_x963(
            &ephemeral,
            &card_ephemeral_key,
            &credential,
            card_public_key,
            &[KEY_USAGE, KEY_TYPE_AES, KEY_LENGTH_AES_128],
            SESSION_KEY_LENGTH * DERIVED_KEY_COUNT,
        )?;
        let receipt_key = scope.extract(
            &material,
            0,
            TokenObjectTemplate {
                key_type: Some(CKK_AES as _),
                derive: false,
                verify: true,
                ..generic_template(&[CKM_AES_CMAC as _])
            },
            16,
        )?;
        let mut receipt_input = request_data;
        receipt_input.extend_from_slice(authentication.card_ephemeral_tlv);
        scope
            .verify_cmac(&receipt_key, &receipt_input, authentication.receipt)
            .map_err(|error| match error {
                Error::Generic(rv) if rv == CKR_SIGNATURE_INVALID as crate::CK_RV => {
                    CKR_PIN_INCORRECT.into()
                }
                error => error,
            })?;
        scope.destroy(&receipt_key)?;
        let mut working = Vec::new();
        for index in 1..DERIVED_KEY_COUNT {
            let key = scope.extract(
                &material,
                index * 128,
                readable_template(TokenObjectTemplate {
                    key_type: Some(CKK_AES as _),
                    derive: false,
                    ..generic_template(&[])
                }),
                16,
            )?;
            working.push(scope.read_aes128(&key)?);
            scope.destroy(&key)?;
        }
        let receipt = authentication
            .receipt
            .try_into()
            .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        Scp03Session::from_session_keys(
            working[0].to_vec(),
            working[1].to_vec(),
            working[2].to_vec(),
            Some(working[3].to_vec()),
            self.host.is_some(),
            receipt,
            SCP11_SECURITY_LEVEL,
        )
    }

    fn upload_host_certificates(&self, connector: &dyn Connector) -> Result<(), Error> {
        let Some(host) = self.host.as_ref() else {
            return Ok(());
        };
        for (index, certificate) in host.certificates.iter().rev().enumerate() {
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
    fn from_configuration(
        configuration: &crate::configuration::Scp11OceConfiguration,
        pinentry: &crate::pinentry::Pinentry,
    ) -> Result<Self, Error> {
        let encrypted_key =
            fs::read(&configuration.private_key).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let encoded_key = crate::private_key::decrypt_file(
            &encrypted_key,
            pinentry,
            "Unlock the SCP11 OCE private key",
        )?;
        let private_key =
            SoftwareSigningKey::from_pkcs8_der_for_kind(KeyKind::Ec(EcCurve::P256), &encoded_key)
                .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;

        let certificate_bundle = fs::read(&configuration.certificate_bundle)
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let certificates = crate::certificate_chain::decode_bundle(&certificate_bundle)?;
        let leaf_key = crate::certificate_chain::p256_public_point(
            certificates.first().ok_or(CKR_ARGUMENTS_BAD)?,
        )?;
        if encode_private_public_point(&private_key)? != leaf_key {
            return Err(CKR_ARGUMENTS_BAD.into());
        }

        Ok(Self {
            key_version: configuration.key_version,
            key_id: configuration.key_id,
            private_key: protect_p256(private_key)?,
            certificates,
        })
    }
}

fn parse_public_point(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    if encoded.len() != 65 || encoded.first() != Some(&0x04) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed: encoded.to_vec(),
    }
    .validate()
    .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    Ok(encoded.to_vec())
}

fn card_public_key_from_certificates(
    certificates: &[Vec<u8>],
    trust: &crate::certificate_chain::CertificateTrust,
) -> Result<Vec<u8>, Error> {
    parse_public_point(&trust.validate_p256_public_point(certificates)?)
}

fn encode_private_public_point(key: &SoftwareSigningKey) -> Result<Vec<u8>, Error> {
    let SoftwarePublicKey::Ec {
        curve: EcCurve::P256,
        uncompressed,
    } = key.public_key()
    else {
        return Err(CKR_ARGUMENTS_BAD.into());
    };
    Ok(uncompressed)
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

#[cfg(test)]
fn derive_key_material(key_agreement: &[u8]) -> Result<zeroize::Zeroizing<Vec<u8>>, Error> {
    if key_agreement.len() != 64 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let required = SESSION_KEY_LENGTH * DERIVED_KEY_COUNT;
    software_key_core::digest::x963_kdf(
        software_key_core::digest::HashAlgorithm::Sha256,
        key_agreement,
        &[KEY_USAGE, KEY_TYPE_AES, KEY_LENGTH_AES_128],
        required,
    )
    .map_err(|_| CKR_DEVICE_ERROR.into())
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
