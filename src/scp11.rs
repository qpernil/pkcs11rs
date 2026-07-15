use crate::{
    error::Error,
    scp03::{aes_cmac, environment_byte, parse_hex, transmit, CommandApdu, Scp03Session},
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

pub(crate) const YUBIKEY_SECURITY_DOMAIN_AID: [u8; 5] = [0xa0, 0x00, 0x00, 0x03, 0x08];

const SCP11A_KEY_ID: u8 = 0x11;
const SCP11B_KEY_ID: u8 = 0x13;
const SCP11_SECURITY_LEVEL: u8 = 0x33;
const KEY_USAGE: u8 = 0x3c;
const KEY_TYPE_AES: u8 = 0x88;
const KEY_LENGTH_AES_128: u8 = 16;
const SESSION_KEY_LENGTH: usize = 16;
const DERIVED_KEY_COUNT: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Scp11Variant {
    A,
    B,
}

impl Scp11Variant {
    fn parameter(self) -> u8 {
        match self {
            Self::A => 0x01,
            Self::B => 0x00,
        }
    }

    fn key_id(self) -> u8 {
        match self {
            Self::A => SCP11A_KEY_ID,
            Self::B => SCP11B_KEY_ID,
        }
    }

    fn instruction(self) -> u8 {
        match self {
            Self::A => 0x82,
            Self::B => 0x88,
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
    card_public_key: EcKey<Public>,
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
        let certificate = env::var("PKCS11RS_SCP11_SD_CERTIFICATE");
        let card_public_key = match (point, certificate) {
            (Ok(point), Err(env::VarError::NotPresent)) => parse_public_point(&parse_hex(&point)?)?,
            (Err(env::VarError::NotPresent), Ok(path)) => public_key_from_certificate(&path)?,
            (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => {
                return Err(CKR_USER_PIN_NOT_INITIALIZED.into());
            }
            (Err(env::VarError::NotUnicode(_)), _)
            | (_, Err(env::VarError::NotUnicode(_)))
            | (Ok(_), Ok(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
        };
        let key_version = environment_byte("PKCS11RS_SCP11_KEY_VERSION", 1)?;
        if key_version & 0x80 != 0 {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let host = match variant {
            Scp11Variant::A => Some(Scp11aHostCredentials::from_environment()?),
            Scp11Variant::B => None,
        };
        Ok(Self {
            variant,
            key_version,
            card_public_key,
            host,
        })
    }

    pub(crate) fn authenticate_selected(
        &self,
        connector: &dyn Connector,
    ) -> Result<Scp03Session, Error> {
        let group = p256_group()?;
        let ephemeral = EcKey::generate(&group)?;
        self.establish_with_ephemeral(connector, ephemeral)
    }

    fn establish_with_ephemeral(
        &self,
        connector: &dyn Connector,
        ephemeral: EcKey<Private>,
    ) -> Result<Scp03Session, Error> {
        validate_p256_private_key(&ephemeral)?;
        self.upload_host_certificates(connector)?;
        let host_ephemeral_point = encode_public_point(&ephemeral)?;
        let request_data = authentication_data(&host_ephemeral_point, self.variant.parameter())?;
        let response = transmit(
            connector,
            &CommandApdu {
                cla: 0x80,
                ins: self.variant.instruction(),
                p1: self.key_version,
                p2: self.variant.key_id(),
                data: request_data.clone(),
                le: Some(256),
                extended: false,
            },
        )?
        .require_success()?;
        let authentication = parse_authentication_response(&response.data)?;
        let card_ephemeral_key = parse_public_point(authentication.card_ephemeral_point)?;

        let ka1 = Zeroizing::new(ecdh(&ephemeral, &card_ephemeral_key)?);
        let static_or_ephemeral = self
            .host
            .as_ref()
            .map(|host| &host.private_key)
            .unwrap_or(&ephemeral);
        let ka2 = Zeroizing::new(ecdh(static_or_ephemeral, &self.card_public_key)?);
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
            transmit(
                connector,
                &CommandApdu {
                    cla: 0x80,
                    ins: 0x2a,
                    p1: host.key_version,
                    p2: host.key_id | if more { 0x80 } else { 0 },
                    data: certificate.clone(),
                    le: None,
                    extended: certificate.len() > u8::MAX as usize,
                },
            )?
            .require_success()?;
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
    let mut certificates = Vec::new();
    for path in env::split_paths(paths) {
        let encoded = fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        let parsed = X509::stack_from_pem(&encoded)
            .or_else(|_| X509::from_der(&encoded).map(|certificate| vec![certificate]))
            .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
        for certificate in parsed {
            certificates.push(certificate.to_der().map_err(Error::from)?);
        }
    }
    if certificates.is_empty() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }

    let parsed: Vec<X509> = certificates
        .iter()
        .map(|certificate| X509::from_der(certificate).map_err(Error::from))
        .collect::<Result<_, _>>()?;
    for pair in parsed.windows(2) {
        let issuer = pair[0].public_key().map_err(Error::from)?;
        if !pair[1].verify(&issuer).map_err(Error::from)? {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
    }
    Ok(certificates)
}

pub(crate) fn configured_application_aid() -> Result<Zeroizing<Vec<u8>>, Error> {
    let aid = match env::var("PKCS11RS_SCP11_AID") {
        Ok(value) => Zeroizing::new(parse_hex(&value)?),
        Err(env::VarError::NotPresent) => Zeroizing::new(YUBIKEY_SECURITY_DOMAIN_AID.to_vec()),
        Err(env::VarError::NotUnicode(_)) => return Err(CKR_ARGUMENTS_BAD.into()),
    };
    if !(5..=16).contains(&aid.len()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(aid)
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

fn public_key_from_certificate(path: &str) -> Result<EcKey<Public>, Error> {
    let encoded = fs::read(path).map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let certificate = X509::from_pem(&encoded)
        .or_else(|_| X509::from_der(&encoded))
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let key = certificate
        .public_key()
        .and_then(|key| key.ec_key())
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    if key.group().curve_name() != Some(Nid::X9_62_PRIME256V1) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    key.check_key()
        .map_err(|_| Error::from(CKR_ARGUMENTS_BAD))?;
    let encoded = encode_public_point(&key)?;
    parse_public_point(&encoded)
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
mod tests {
    use super::*;
    use openssl::bn::BigNum;
    use std::{cell::RefCell, time::Duration};

    #[derive(Debug)]
    struct ScriptedConnector {
        response: Vec<u8>,
        commands: RefCell<Vec<Vec<u8>>>,
    }

    impl Connector for ScriptedConnector {
        fn as_debug(&self) -> &dyn std::fmt::Debug {
            self
        }
        fn manufacturer(&self) -> &str {
            "Test"
        }
        fn product(&self) -> &str {
            "SCP11"
        }
        fn serial(&self) -> &str {
            "1"
        }
        fn major(&self) -> u8 {
            5
        }
        fn minor(&self) -> u8 {
            72
        }
        fn is_present(&self) -> bool {
            true
        }
        fn buffer_size(&self) -> usize {
            4096
        }
        fn transmit<'a>(
            &self,
            send_buffer: &[u8],
            receive_buffer: &'a mut [u8],
            _timeout: Duration,
        ) -> Result<&'a [u8], Error> {
            self.commands.borrow_mut().push(send_buffer.to_vec());
            receive_buffer[..self.response.len()].copy_from_slice(&self.response);
            Ok(&receive_buffer[..self.response.len()])
        }
    }

    fn private_key(scalar: u32) -> EcKey<Private> {
        let group = p256_group().unwrap();
        let scalar = BigNum::from_u32(scalar).unwrap();
        let mut context = BigNumContext::new().unwrap();
        let mut public = EcPoint::new(&group).unwrap();
        public
            .mul_generator2(&group, &scalar, &mut context)
            .unwrap();
        EcKey::from_private_components(&group, &scalar, &public).unwrap()
    }

    #[test]
    fn encodes_scp11b_authentication_parameters() {
        let mut point = vec![0x04];
        point.extend(1u8..=64);
        let data = authentication_data(&point, 0).unwrap();
        assert_eq!(
            &data[..15],
            &[
                0xa6, 0x0d, 0x90, 0x02, 0x11, 0x00, 0x95, 0x01, 0x3c, 0x80, 0x01, 0x88, 0x81, 0x01,
                0x10
            ]
        );
        assert_eq!(&data[15..18], &[0x5f, 0x49, 0x41]);
        assert_eq!(&data[18..], point);
    }

    #[test]
    fn key_derivation_uses_x963_sha256_counter_layout() {
        let agreement: Vec<u8> = (0u8..64).collect();
        assert_eq!(
            derive_key_material(&agreement).unwrap().as_slice(),
            parse_hex(
                "78e6afba798e338b0b6104dfc18e5b9e \
                 faabdf39c991de6879d9c7a0c21ff022 \
                 40998ce38b6d3dd3fd3fa9c7d956b673 \
                 23d069af6457586600431b7ec83d38c7 \
                 183f299ddc90b91643d6d2e137eefcff"
            )
            .unwrap()
        );
    }

    #[test]
    fn authenticates_scp11b_against_fixed_p256_vector() {
        // Independent vector generated with Python cryptography's P-256 ECDH and AES-CMAC.
        let static_public = parse_hex(
            "047cf27b188d034f7e8a52380304b51a \
             c3c08969e277f21b35a60b48fc476699 \
             7807775510db8ed040293d9ac69f7430 \
             dbba7dade63ce982299e04b79d227873d1",
        )
        .unwrap();
        let response = parse_hex(
            "5f4941045ecbe4d1a6330a44c8f7ef951d4bf165 \
             e6c6b721efada985fb41661bc6e7fd6c8734640 \
             c4998ff7e374b06ce1a64a2ecd82ab036384fb83 \
             d9a79b127a27d50328610f0ddff3231c0eae541 \
             9bbcd9536d5a829000",
        )
        .unwrap();
        let connector = ScriptedConnector {
            response: response.clone(),
            commands: RefCell::new(Vec::new()),
        };
        let keys = Scp11KeySet {
            variant: Scp11Variant::B,
            key_version: 1,
            card_public_key: parse_public_point(&static_public).unwrap(),
            host: None,
        };
        keys.establish_with_ephemeral(&connector, private_key(1))
            .unwrap();
        assert_eq!(
            connector.commands.borrow().as_slice(),
            &[parse_hex(
                "8088011353a60d9002110095013c8001888101105f \
                 4941046b17d1f2e12c4247f8bce6e563a440f277 \
                 037d812deb33a0f4a13945d898c2964fe342e2fe1 \
                 a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb \
                 6406837bf51f500"
            )
            .unwrap()]
        );

        let receipt_offset = response.len() - 3;
        let mut bad_response = response;
        bad_response[receipt_offset] ^= 1;
        let connector = ScriptedConnector {
            response: bad_response,
            commands: RefCell::new(Vec::new()),
        };
        assert!(matches!(
            keys.establish_with_ephemeral(&connector, private_key(1)),
            Err(Error::Generic(rv)) if rv == CKR_PIN_INCORRECT as _
        ));
    }

    #[test]
    fn authenticates_scp11a_with_oce_certificate_upload_and_static_ecdh() {
        let static_public = parse_hex(
            "047cf27b188d034f7e8a52380304b51a \
             c3c08969e277f21b35a60b48fc476699 \
             7807775510db8ed040293d9ac69f7430 \
             dbba7dade63ce982299e04b79d227873d1",
        )
        .unwrap();
        let response = parse_hex(
            "5f4941045ecbe4d1a6330a44c8f7ef951d4bf165 \
             e6c6b721efada985fb41661bc6e7fd6c8734640 \
             c4998ff7e374b06ce1a64a2ecd82ab036384fb83 \
             d9a79b127a27d503286105d612b371134aeda05d \
             d9e9b933fa4449000",
        )
        .unwrap();
        let connector = ScriptedConnector {
            response,
            commands: RefCell::new(Vec::new()),
        };
        let keys = Scp11KeySet {
            variant: Scp11Variant::A,
            key_version: 1,
            card_public_key: parse_public_point(&static_public).unwrap(),
            host: Some(Scp11aHostCredentials {
                key_version: 0,
                key_id: 0,
                private_key: private_key(4),
                certificates: vec![vec![0x30, 0x01, 0x00]],
            }),
        };
        keys.establish_with_ephemeral(&connector, private_key(1))
            .unwrap();
        assert_eq!(
            connector.commands.borrow().as_slice(),
            &[
                parse_hex("802a000003300100").unwrap(),
                parse_hex(
                    "8082011153a60d9002110195013c8001888101105f \
                     4941046b17d1f2e12c4247f8bce6e563a440f277 \
                     037d812deb33a0f4a13945d898c2964fe342e2fe1 \
                     a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb \
                     6406837bf51f500"
                )
                .unwrap(),
            ]
        );
    }

    #[test]
    fn rejects_noncanonical_or_trailing_response_tlvs() {
        let mut point = vec![0x04; 65];
        point[0] = 0x04;
        let valid = [
            encode_tlv(&[0x5f, 0x49], &point).unwrap(),
            encode_tlv(&[0x86], &[0; 16]).unwrap(),
        ]
        .concat();
        assert!(parse_authentication_response(&valid).is_ok());

        let mut trailing = valid.clone();
        trailing.push(0);
        assert!(parse_authentication_response(&trailing).is_err());

        let mut noncanonical = vec![0x5f, 0x49, 0x81, 65];
        noncanonical.extend_from_slice(&point);
        noncanonical.extend_from_slice(&encode_tlv(&[0x86], &[0; 16]).unwrap());
        assert!(parse_authentication_response(&noncanonical).is_err());
    }
}
