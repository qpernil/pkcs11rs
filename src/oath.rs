//! YKOATH protocol and the PKCS #11 OTP mapping. No reusable authentication
//! material is retained here. Enumeration never executes CALCULATE.
use crate::*;
use subtle::ConstantTimeEq;

pub(crate) const AID: [u8; 7] = [0xa0, 0, 0, 5, 0x27, 0x21, 1];

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Credential {
    pub(crate) name: Vec<u8>,
    pub(crate) totp: bool,
    pub(crate) hash: u8,
    /// A PKCS #11 view, not state stored in the OATH credential. SHA1 HOTP
    /// offers both standard and extended views of the same device credential.
    pub(crate) extended: bool,
    pub(crate) period: u64,
    pub(crate) digits: Option<u8>,
    pub(crate) touch: Option<bool>,
}
impl Credential {
    pub(crate) fn mechanism(&self) -> CK_MECHANISM_TYPE {
        if self.totp {
            CKM_PKCS11RS_TOTP
        } else if self.extended {
            CKM_PKCS11RS_HOTP
        } else {
            CKM_HOTP as CK_ULONG
        }
    }
    pub(crate) fn key_type(&self) -> CK_KEY_TYPE {
        if self.totp {
            CKK_PKCS11RS_TOTP
        } else if self.extended {
            CKK_PKCS11RS_HOTP
        } else {
            CKK_HOTP as CK_KEY_TYPE
        }
    }
    pub(crate) fn hash_mechanism(&self) -> CK_MECHANISM_TYPE {
        match self.hash {
            1 => CKM_SHA_1 as CK_ULONG,
            2 => CKM_SHA256 as CK_ULONG,
            _ => CKM_SHA512 as CK_ULONG,
        }
    }
    pub(crate) fn from_name(name: Vec<u8>, kind: u8) -> Result<Self, Error> {
        if name.is_empty()
            || name.len() > 64
            || !matches!(kind & 0xf0, 0x10 | 0x20)
            || !matches!(kind & 15, 1..=3)
        {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let totp = kind & 0xf0 == 0x20;
        let period = if totp {
            std::str::from_utf8(&name)
                .ok()
                .and_then(|s| s.split_once('/'))
                .and_then(|(s, _)| s.parse::<u64>().ok())
                .unwrap_or(30)
        } else {
            0
        };
        if totp && period == 0 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        Ok(Self {
            name,
            totp,
            hash: kind & 15,
            extended: !totp && kind & 15 != 1,
            period,
            digits: None,
            touch: None,
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) struct Info {
    pub(crate) version: [u8; 3],
    salt: Vec<u8>,
    challenge: Option<Vec<u8>>,
}

pub(crate) fn tlv(tag: u8, value: &[u8], output: &mut Vec<u8>) -> Result<(), Error> {
    if value.len() > 255 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    output.push(tag);
    if value.len() >= 128 {
        output.push(0x81);
    }
    output.push(value.len() as u8);
    output.extend_from_slice(value);
    Ok(())
}
fn parse(mut data: &[u8]) -> Result<Vec<(u8, &[u8])>, Error> {
    let mut result = Vec::new();
    while !data.is_empty() {
        if data.len() < 2 {
            return Err(CKR_DEVICE_ERROR.into());
        }
        let tag = data[0];
        let (length, offset) = match data[1] {
            0..=127 => (data[1] as usize, 2),
            0x81 if data.len() >= 3 => (data[2] as usize, 3),
            _ => return Err(CKR_DEVICE_ERROR.into()),
        };
        let end = offset + length;
        let value = data.get(offset..end).ok_or(CKR_DEVICE_ERROR)?;
        result.push((tag, value));
        data = &data[end..];
    }
    Ok(result)
}
fn field<'a>(values: &[(u8, &'a [u8])], tag: u8) -> Result<Option<&'a [u8]>, Error> {
    let mut values = values.iter().filter(|(t, _)| *t == tag).map(|(_, v)| *v);
    let first = values.next();
    if values.next().is_some() {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(first)
}
/// Never replay a command after an error: it may have consumed a HOTP
/// counter. The connector collects OATH response fragments before unprotecting.
fn command(c: &dyn Connector, ins: u8, p1: u8, p2: u8, data: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut apdu = CommandApdu {
        cla: 0,
        ins,
        p1,
        p2,
        data,
        le: Some(256),
        extended: false,
    };
    let result = c.send_oath_apdu(&apdu);
    zeroize::Zeroize::zeroize(&mut apdu.data);
    let response = result?;
    log!(
        2,
        "OATH instruction {:02x}: status {:04x}, response bytes {}",
        ins,
        response.status,
        response.data.len()
    );
    match response.status {
        0x9000 => Ok(response.data),
        0x6982 => Err(CKR_USER_NOT_LOGGED_IN.into()),
        0x6a80 if ins == 1 || ins == 3 => Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
        0x6a80 | 0x6a88 => Err(CKR_KEY_HANDLE_INVALID.into()),
        0x6985 => Err(CKR_FUNCTION_CANCELED.into()),
        0x6a84 => Err(CKR_DEVICE_MEMORY.into()),
        _ => Err(CKR_DEVICE_ERROR.into()),
    }
}
pub(crate) fn select(c: &dyn Connector, aid: &[u8]) -> Result<Info, Error> {
    let data = command(c, 0xa4, 4, 0, aid.to_vec())?;
    let fields = parse(&data)?;
    let version = field(&fields, 0x79)?
        .ok_or(CKR_DEVICE_ERROR)?
        .try_into()
        .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
    let salt = field(&fields, 0x71)?.ok_or(CKR_DEVICE_ERROR)?.to_vec();
    let challenge = field(&fields, 0x74)?.map(ToOwned::to_owned);
    if salt.is_empty()
        || challenge.as_ref().is_some_and(|v| v.len() != 8)
        || field(&fields, 0x7b)?.is_some_and(|v| v != [1])
    {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(Info {
        version,
        salt,
        challenge,
    })
}
fn access_key(info: &Info, password: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    software_key_core::digest::pbkdf2_hmac(MessageDigest::Sha1, password, &info.salt, 1000, 16)
        .map_err(|_| CKR_FUNCTION_FAILED.into())
}
fn mac(key: &[u8], data: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    software_key_core::digest::hmac(MessageDigest::Sha1, key, data)
        .map(Zeroizing::new)
        .map_err(|_| CKR_FUNCTION_FAILED.into())
}
pub(crate) fn authenticate(c: &dyn Connector, info: &Info, password: &[u8]) -> Result<(), Error> {
    let Some(challenge) = &info.challenge else {
        return if password.is_empty() {
            Ok(())
        } else {
            Err(CKR_PIN_INCORRECT.into())
        };
    };
    let key = access_key(info, password)?;
    let mut host = [0; 8];
    getrandom::fill(&mut host).map_err(|_| CKR_RANDOM_NO_RNG)?;
    let mut data = Vec::new();
    tlv(0x75, &mac(&key, challenge)?, &mut data)?;
    tlv(0x74, &host, &mut data)?;
    // VALIDATE's failure status is deliberately mapped to a PIN error here.
    let response = c.send_oath_apdu(&CommandApdu {
        cla: 0,
        ins: 0xa3,
        p1: 0,
        p2: 0,
        data,
        le: Some(256),
        extended: false,
    })?;
    if response.status == 0x6a80 || response.status == 0x6984 {
        return Err(CKR_PIN_INCORRECT.into());
    }
    if response.status != 0x9000 {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let fields = parse(&response.data)?;
    let response = field(&fields, 0x75)?.ok_or(CKR_DEVICE_ERROR)?;
    if !bool::from(response.ct_eq(&mac(&key, &host)?)) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    Ok(())
}
pub(crate) fn change_password(
    c: &dyn Connector,
    info: &Info,
    password: &[u8],
) -> Result<(), Error> {
    let mut data = Vec::new();
    if password.is_empty() {
        tlv(0x73, &[], &mut data)?;
    } else {
        let key = access_key(info, password)?;
        let mut host = [0; 8];
        getrandom::fill(&mut host).map_err(|_| CKR_RANDOM_NO_RNG)?;
        let mut keydata = Zeroizing::new(vec![0x21]);
        keydata.extend_from_slice(&key);
        tlv(0x73, &keydata, &mut data)?;
        tlv(0x74, &host, &mut data)?;
        tlv(0x75, &mac(&key, &host)?, &mut data)?;
    }
    command(c, 3, 0, 0, data).map(|_| ())
}
pub(crate) fn list(c: &dyn Connector) -> Result<Vec<Credential>, Error> {
    let data = command(c, 0xa1, 0, 0, Vec::new())?;
    let mut names = HashSet::new();
    parse(&data)?
        .into_iter()
        .map(|(tag, v)| {
            if tag != 0x72 || v.len() < 2 || !names.insert(v[1..].to_vec()) {
                return Err(CKR_DEVICE_ERROR.into());
            }
            Credential::from_name(v[1..].to_vec(), v[0])
        })
        .collect()
}
pub(crate) fn calculate(
    c: &dyn Connector,
    credential: &Credential,
    time: Option<u64>,
) -> Result<Vec<u8>, Error> {
    let challenge = if credential.totp {
        let timestamp = match time {
            Some(v) => v,
            None => std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| CKR_FUNCTION_FAILED)?
                .as_secs(),
        };
        (timestamp / credential.period).to_be_bytes().to_vec()
    } else {
        Vec::new()
    };
    let mut data = Vec::new();
    tlv(0x71, &credential.name, &mut data)?;
    tlv(0x74, &challenge, &mut data)?;
    let response = command(c, 0xa2, 0, 1, data)?;
    let fields = parse(&response)?;
    let result = field(&fields, 0x76)?.ok_or(CKR_DEVICE_ERROR)?;
    if result.len() != 5 || !(6..=8).contains(&result[0]) {
        return Err(CKR_DEVICE_ERROR.into());
    }
    let number =
        u32::from_be_bytes(result[1..].try_into().map_err(|_| CKR_DEVICE_ERROR)?) & 0x7fff_ffff;
    Ok(format!(
        "{:0width$}",
        number % 10u32.pow(result[0] as u32),
        width = result[0] as usize
    )
    .into_bytes())
}
pub(crate) fn put(
    c: &dyn Connector,
    credential: &Credential,
    secret: &[u8],
    counter: u32,
) -> Result<(), Error> {
    if secret.is_empty() || secret.len() > 64 {
        return Err(CKR_KEY_SIZE_RANGE.into());
    }
    log!(
        2,
        "OATH import: hash {}, digits {:?}, secret bytes {}",
        credential.hash,
        credential.digits,
        secret.len()
    );
    let mut key = Zeroizing::new(vec![
        (if credential.totp { 0x20 } else { 0x10 }) | credential.hash,
        credential.digits.ok_or(CKR_TEMPLATE_INCOMPLETE)?,
    ]);
    key.extend_from_slice(secret);
    while key.len() < 16 {
        key.push(0);
    }
    let mut data = Zeroizing::new(Vec::new());
    tlv(0x71, &credential.name, &mut data)?;
    tlv(0x73, &key, &mut data)?;
    if credential.touch == Some(true) {
        data.extend_from_slice(&[0x78, 2]);
    }
    if !credential.totp {
        tlv(0x7a, &counter.to_be_bytes(), &mut data)?;
    }
    command(c, 1, 0, 0, data.to_vec()).map(|_| ())
}
pub(crate) fn delete(c: &dyn Connector, name: &[u8]) -> Result<(), Error> {
    let mut data = Vec::new();
    tlv(0x71, name, &mut data)?;
    command(c, 2, 0, 0, data).map(|_| ())
}

pub(crate) fn supports_attribute(t: CK_ATTRIBUTE_TYPE) -> bool {
    matches!(t, x if [CKA_CLASS,CKA_TOKEN,CKA_PRIVATE,CKA_LABEL,CKA_UNIQUE_ID,CKA_MODIFIABLE,CKA_COPYABLE,CKA_DESTROYABLE,CKA_KEY_TYPE,CKA_ID,CKA_SIGN,CKA_VERIFY,CKA_ENCRYPT,CKA_DECRYPT,CKA_DERIVE,CKA_WRAP,CKA_UNWRAP,CKA_SENSITIVE,CKA_EXTRACTABLE,CKA_ALWAYS_SENSITIVE,CKA_NEVER_EXTRACTABLE,CKA_LOCAL,CKA_ALLOWED_MECHANISMS,CKA_VALUE,CKA_OTP_FORMAT,CKA_OTP_LENGTH,CKA_OTP_TIME_INTERVAL,CKA_OTP_USER_FRIENDLY_MODE,CKA_OTP_CHALLENGE_REQUIREMENT,CKA_OTP_TIME_REQUIREMENT,CKA_OTP_COUNTER_REQUIREMENT,CKA_OTP_PIN_REQUIREMENT,CKA_ATTR_TYPES].iter().any(|v|*v as CK_ATTRIBUTE_TYPE==x))
        || t == CKA_PKCS11RS_OATH_HASH
        || t == CKA_PKCS11RS_OATH_TOUCH_REQUIRED
        || t == CKA_PKCS11RS_URI
}
pub(crate) fn attribute(c: &Credential, t: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
    let ulong = |v: CK_ULONG| v.to_ne_bytes().to_vec();
    match t {
        x if x == CKA_DESTROYABLE as CK_ULONG => Some(vec![1]),
        x if x == CKA_OTP_FORMAT as CK_ULONG => Some(ulong(CK_OTP_FORMAT_DECIMAL as CK_ULONG)),
        x if x == CKA_OTP_LENGTH as CK_ULONG => Some(ulong(
            c.digits
                .map_or(CK_UNAVAILABLE_INFORMATION as CK_ULONG, |v| v as CK_ULONG),
        )),
        x if x == CKA_OTP_TIME_INTERVAL as CK_ULONG => Some(ulong(c.period as CK_ULONG)),
        x if x == CKA_OTP_USER_FRIENDLY_MODE as CK_ULONG => Some(vec![1]),
        x if x == CKA_OTP_TIME_REQUIREMENT as CK_ULONG => Some(ulong(if c.totp {
            CK_OTP_PARAM_OPTIONAL as CK_ULONG
        } else {
            CK_OTP_PARAM_IGNORED as CK_ULONG
        })),
        x if x == CKA_OTP_CHALLENGE_REQUIREMENT as CK_ULONG
            || x == CKA_OTP_COUNTER_REQUIREMENT as CK_ULONG
            || x == CKA_OTP_PIN_REQUIREMENT as CK_ULONG =>
        {
            Some(ulong(CK_OTP_PARAM_IGNORED as CK_ULONG))
        }
        CKA_PKCS11RS_OATH_HASH => Some(ulong(c.hash_mechanism())),
        CKA_PKCS11RS_OATH_TOUCH_REQUIRED => c.touch.map(|v| vec![u8::from(v)]),
        _ => None,
    }
}
pub(crate) fn object(slot: CK_SLOT_ID, c: Credential) -> TokenObject {
    let name = String::from_utf8_lossy(&c.name).into_owned();
    TokenObject {
        slot_id: Some(slot),
        unique_id: format!(
            "{}:{}",
            if !c.totp && c.extended {
                "oath-extended"
            } else {
                "oath"
            },
            c.name
                .iter()
                .map(|v| format!("{v:02x}"))
                .collect::<String>()
        ),
        class: CKO_OTP_KEY as CK_ULONG,
        key_type: c.key_type(),
        label: name,
        id: c.name.clone(),
        token: true,
        private: true,
        sign: true,
        verify: false,
        encrypt: false,
        decrypt: false,
        derive: false,
        wrap: false,
        unwrap: false,
        encapsulate: false,
        decapsulate: false,
        sensitive: true,
        extractable: false,
        always_sensitive: false,
        never_extractable: false,
        local: false,
        key_gen_mechanism: None,
        allowed_mechanisms: Some(vec![c.mechanism()]),
        wrap_with_trusted: false,
        policy_templates: KeyPolicyTemplates::default(),
        creator_session: None,
        public_key: None,
        rp_id: None,
        material: KeyMaterial::OathCredential(c),
    }
}
pub(crate) fn is_mechanism(m: CK_MECHANISM_TYPE) -> bool {
    m == CKM_HOTP as CK_ULONG || m == CKM_PKCS11RS_TOTP || m == CKM_PKCS11RS_HOTP
}

// OTP operations produce no input-message signature. All input parameters are
// copied at initialization; application-owned pointers are never retained.
fn parameters(m: &CK_MECHANISM) -> Result<Option<u64>, Error> {
    if m.pParameter.is_null() {
        return if m.ulParameterLen == 0 {
            Ok(None)
        } else {
            Err(CKR_MECHANISM_PARAM_INVALID.into())
        };
    }
    if m.ulParameterLen as usize != std::mem::size_of::<CK_OTP_PARAMS>() {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let p = unsafe { ptr::read_unaligned(m.pParameter.cast::<CK_OTP_PARAMS>()) };
    if p.ulCount > 16 || (p.pParams.is_null() && p.ulCount != 0) {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let mut seen = HashSet::new();
    let mut time = None;
    for index in 0..p.ulCount as usize {
        let p = unsafe { ptr::read_unaligned(p.pParams.add(index)) };
        if !seen.insert(p.type_) {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        // PKCS #11 requires parameters marked IGNORED by the key to be
        // ignored, including a caller's counter on an internally counted key.
        if p.type_ == CK_OTP_COUNTER as CK_ULONG
            || p.type_ == CK_OTP_PIN as CK_ULONG
            || p.type_ == CK_OTP_CHALLENGE as CK_ULONG
            || (p.type_ == CK_OTP_TIME as CK_ULONG && m.mechanism != CKM_PKCS11RS_TOTP)
        {
            continue;
        }
        if p.pValue.is_null() {
            return Err(CKR_MECHANISM_PARAM_INVALID.into());
        }
        let bytes = unsafe { from_raw_parts(p.pValue.cast::<u8>(), p.ulValueLen as usize) }
            .map_err(|_| CKR_MECHANISM_PARAM_INVALID)?;
        match p.type_ {
            x if x == CK_OTP_TIME as CK_ULONG && m.mechanism == CKM_PKCS11RS_TOTP => {
                time = Some(parse_time(bytes)?)
            }
            x if x == CK_OTP_OUTPUT_FORMAT as CK_ULONG
                && bytes == (CK_OTP_FORMAT_DECIMAL as CK_ULONG).to_ne_bytes() => {}
            x if x == CK_OTP_FLAGS as CK_ULONG
                && bytes.len() == std::mem::size_of::<CK_ULONG>() =>
            {
                let flags = CK_ULONG::from_ne_bytes(
                    bytes.try_into().map_err(|_| CKR_MECHANISM_PARAM_INVALID)?,
                );
                // Only CKF_USER_FRIENDLY_OTP is supported; no next-code/time exclusions.
                if flags & !(CKF_USER_FRIENDLY_OTP as CK_ULONG) != 0 {
                    return Err(CKR_MECHANISM_PARAM_INVALID.into());
                }
            }
            _ => return Err(CKR_MECHANISM_PARAM_INVALID.into()),
        }
    }
    Ok(time)
}
fn parse_time(v: &[u8]) -> Result<u64, Error> {
    if v.len() != 14 || !v.iter().all(u8::is_ascii_digit) {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let number = |s: &[u8]| s.iter().fold(0u64, |a, v| a * 10 + (v - b'0') as u64);
    let year = number(&v[..4]);
    let month = number(&v[4..6]);
    let day = number(&v[6..8]);
    let h = number(&v[8..10]);
    let m = number(&v[10..12]);
    let s = number(&v[12..]);
    let leap = |y: u64| y.is_multiple_of(4) && (!y.is_multiple_of(100) || y.is_multiple_of(400));
    let lengths = [
        31,
        if leap(year) { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if year < 1970
        || !(1..=12).contains(&month)
        || day == 0
        || day > lengths[(month - 1) as usize]
        || h > 23
        || m > 59
        || s > 59
    {
        return Err(CKR_MECHANISM_PARAM_INVALID.into());
    }
    let days = (1970..year)
        .map(|y| if leap(y) { 366 } else { 365 })
        .sum::<u64>()
        + lengths[..(month - 1) as usize].iter().sum::<u64>()
        + day
        - 1;
    Ok(days * 86400 + h * 3600 + m * 60 + s)
}
pub(crate) fn sign_init(
    ctx: &mut SlotContext,
    session: CK_SESSION_HANDLE,
    m: &CK_MECHANISM,
    key: CK_OBJECT_HANDLE,
) -> Result<(), Error> {
    let (slot, _, logged) = ctx.session_details(session)?;
    if !ctx
        .slot
        .backend_mechanisms()
        .iter()
        .any(|v| v.type_ == m.mechanism)
    {
        return Err(CKR_MECHANISM_INVALID.into());
    }
    let time = parameters(m)?;
    let object = ctx.resolve_object(key)?.ok_or(CKR_KEY_HANDLE_INVALID)?;
    if object.private && !logged {
        return Err(CKR_USER_NOT_LOGGED_IN.into());
    }
    let KeyMaterial::OathCredential(c) = &object.material else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    if c.mechanism() != m.mechanism || !object.sign || !object.allows_mechanism(m.mechanism) {
        return Err(CKR_KEY_FUNCTION_NOT_PERMITTED.into());
    }
    ctx.get_session_context_mut(session)?.sign_operation = Some(SignatureOperation {
        multipart: false,
        prehash_state: None,
        key: object.material,
        public_key: None,
        slot_id: slot,
        requires_login: object.private,
        context_specific_extended: false,
        context_specific_rp_id: None,
        oath_time: time,
        fido_authorization: None,
        mechanism: m.mechanism,
        mac_length: None,
        gmac: None,
        pss: None,
        ml_dsa: None,
        piv_pin_policy: None,
        buffer: Vec::new(),
        result: None,
    });
    Ok(())
}
fn result_size(digits: usize) -> usize {
    std::mem::size_of::<CK_OTP_SIGNATURE_INFO>() + std::mem::size_of::<CK_OTP_PARAM>() + digits
}
pub(crate) fn sign(
    ctx: &mut SlotContext,
    op: &SignatureOperation,
    input: &[u8],
    output: *mut u8,
    length: &mut CK_ULONG,
) -> Result<(), Error> {
    if !input.is_empty() {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let KeyMaterial::OathCredential(c) = &op.key else {
        return Err(CKR_KEY_TYPE_INCONSISTENT.into());
    };
    // Eight digits is a safe, side-effect-free bound even when LIST does not
    // reveal a pre-existing credential's configured digit count.
    let needed = result_size(op.result.as_ref().map_or(8, Vec::len));
    if output.is_null() {
        *length = needed as CK_ULONG;
        return Ok(());
    }
    if (*length as usize) < needed {
        *length = needed as CK_ULONG;
        return Err(CKR_BUFFER_TOO_SMALL.into());
    }
    let result = ctx.slot.oath_calculate(c, op.oath_time);
    let result = result?;
    unsafe {
        let param = output
            .add(std::mem::size_of::<CK_OTP_SIGNATURE_INFO>())
            .cast::<CK_OTP_PARAM>();
        let value = output.add(
            std::mem::size_of::<CK_OTP_SIGNATURE_INFO>() + std::mem::size_of::<CK_OTP_PARAM>(),
        );
        ptr::copy_nonoverlapping(result.as_ptr(), value, result.len());
        ptr::write_unaligned(
            param,
            CK_OTP_PARAM {
                type_: CK_OTP_VALUE as CK_ULONG,
                pValue: value.cast(),
                ulValueLen: result.len() as CK_ULONG,
            },
        );
        ptr::write_unaligned(
            output.cast::<CK_OTP_SIGNATURE_INFO>(),
            CK_OTP_SIGNATURE_INFO {
                pParams: param,
                ulCount: 1,
            },
        );
    }
    *length = result_size(result.len()) as CK_ULONG;
    Ok(())
}

#[cfg(test)]
mod tests;

/// Only explicitly representable OATH policy is accepted. PUT overwrites an
/// existing name on the device, so the slot separately rejects duplicate names.
pub(crate) fn import_template(
    template: &[CK_ATTRIBUTE],
) -> Result<(Credential, Zeroizing<Vec<u8>>, u32), Error> {
    let mut seen = HashSet::new();
    let mut class = None;
    let mut kind = None;
    let mut label = None;
    let mut id = None;
    let mut secret = None;
    let mut digits = 6;
    let mut hash = 1;
    let mut touch = false;
    let mut period = None;
    let mut counter = 0;
    for a in template {
        if !seen.insert(a.type_) {
            return Err(CKR_TEMPLATE_INCONSISTENT.into());
        }
        let number = || crate::object::read_ulong_template_attribute(a).map_err(Error::from);
        let boolean = || crate::object::read_bool_template_attribute(a).map_err(Error::from);
        let bytes = || crate::object::read_attribute_value(a).map_err(Error::from);
        match a.type_ {
            x if x == CKA_CLASS as CK_ULONG => class = Some(number()?),
            x if x == CKA_KEY_TYPE as CK_ULONG => kind = Some(number()?),
            x if x == CKA_LABEL as CK_ULONG => label = Some(bytes()?),
            x if x == CKA_ID as CK_ULONG => id = Some(bytes()?),
            x if x == CKA_VALUE as CK_ULONG => secret = Some(Zeroizing::new(bytes()?)),
            x if x == CKA_TOKEN as CK_ULONG
                || x == CKA_SENSITIVE as CK_ULONG
                || x == CKA_SIGN as CK_ULONG =>
            {
                if !boolean()? {
                    return Err(CKR_TEMPLATE_INCONSISTENT.into());
                }
            }
            x if x == CKA_PRIVATE as CK_ULONG => {
                let _ = boolean()?;
            }
            x if x == CKA_EXTRACTABLE as CK_ULONG
                || x == CKA_VERIFY as CK_ULONG
                || x == CKA_ENCRYPT as CK_ULONG
                || x == CKA_DECRYPT as CK_ULONG
                || x == CKA_WRAP as CK_ULONG
                || x == CKA_UNWRAP as CK_ULONG
                || x == CKA_DERIVE as CK_ULONG
                || x == CKA_COPYABLE as CK_ULONG
                || x == CKA_MODIFIABLE as CK_ULONG =>
            {
                if boolean()? {
                    return Err(CKR_TEMPLATE_INCONSISTENT.into());
                }
            }
            x if x == CKA_OTP_FORMAT as CK_ULONG => {
                if number()? != CK_OTP_FORMAT_DECIMAL as CK_ULONG {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
            }
            x if x == CKA_OTP_LENGTH as CK_ULONG => {
                let n = number()?;
                if !(6..=8).contains(&n) {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
                digits = n as u8;
            }
            x if x == CKA_OTP_TIME_INTERVAL as CK_ULONG => {
                let n = number()?;
                if n == 0 {
                    return Err(CKR_ATTRIBUTE_VALUE_INVALID.into());
                }
                period = Some(crate::key_metadata::cryptoki_ulong_to_u64(n));
            }
            x if x == CKA_OTP_COUNTER as CK_ULONG => {
                let b = bytes()?;
                let b: [u8; 8] = b.try_into().map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
                counter = u32::try_from(u64::from_be_bytes(b))
                    .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
            }
            CKA_PKCS11RS_OATH_HASH => {
                hash = match number()? {
                    x if x == CKM_SHA_1 as CK_ULONG => 1,
                    x if x == CKM_SHA256 as CK_ULONG => 2,
                    x if x == CKM_SHA512 as CK_ULONG => 3,
                    _ => return Err(CKR_ATTRIBUTE_VALUE_INVALID.into()),
                }
            }
            CKA_PKCS11RS_OATH_TOUCH_REQUIRED => touch = boolean()?,
            _ => return Err(CKR_ATTRIBUTE_TYPE_INVALID.into()),
        }
    }
    if !seen.contains(&(CKA_TOKEN as CK_ATTRIBUTE_TYPE)) {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if class != Some(CKO_OTP_KEY as CK_ULONG) {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let key_type = kind.ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    let totp = match key_type {
        x if x == CKK_HOTP as CK_ULONG => false,
        CKK_PKCS11RS_HOTP => false,
        CKK_PKCS11RS_TOTP => true,
        _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
    };
    if key_type == CKK_PKCS11RS_HOTP && !seen.contains(&CKA_PKCS11RS_OATH_HASH) {
        return Err(CKR_TEMPLATE_INCOMPLETE.into());
    }
    if (key_type == CKK_HOTP as CK_KEY_TYPE && hash != 1)
        || (!totp && period.is_some())
        || (totp && seen.contains(&(CKA_OTP_COUNTER as CK_ULONG)))
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    if let (Some(label), Some(id)) = (&label, &id)
        && label != id
    {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    let mut name = id.or(label).ok_or(CKR_TEMPLATE_INCOMPLETE)?;
    std::str::from_utf8(&name).map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
    if totp && let Some(period) = period {
        let prefix = format!("{period}/");
        if period != 30 && !name.starts_with(prefix.as_bytes()) {
            name = [prefix.as_bytes(), &name].concat();
        }
    }
    let mut credential = Credential::from_name(name, (if totp { 0x20 } else { 0x10 }) | hash)
        .map_err(|_| CKR_ATTRIBUTE_VALUE_INVALID)?;
    credential.extended = key_type == CKK_PKCS11RS_HOTP;
    if period.is_some_and(|p| credential.period != p) {
        return Err(CKR_TEMPLATE_INCONSISTENT.into());
    }
    credential.digits = Some(digits);
    credential.touch = Some(touch);
    Ok((credential, secret.ok_or(CKR_TEMPLATE_INCOMPLETE)?, counter))
}

#[cfg(all(test, feature = "embedded-virtual-yubikey"))]
pub(crate) mod virtual_tests;
