//! RFC 7512 selectors used for YubiHSM client-authentication credentials.
//!
//! The URI identifies an existing source token/object. PKCS11RS query
//! attributes carry the target Authentication Key or request creation of a
//! temporary direct-password credential.
use crate::*;

const AUTHKEY_QUERY: &str = "pkcs11rs-authkey";
const DIRECT_QUERY: &str = "pkcs11rs-direct";

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ClientAuthUri {
    pub(crate) token: Option<Vec<u8>>,
    pub(crate) manufacturer: Option<Vec<u8>>,
    pub(crate) serial: Option<Vec<u8>>,
    pub(crate) model: Option<Vec<u8>>,
    pub(crate) object: Option<Vec<u8>>,
    pub(crate) id: Option<Vec<u8>>,
    pub(crate) class: Option<CK_OBJECT_CLASS>,
    pub(crate) authkey_id: Option<u16>,
    pub(crate) direct: Option<String>,
}

impl ClientAuthUri {
    pub(crate) fn parse(value: &[u8]) -> Result<Self, Error> {
        let value = std::str::from_utf8(value).map_err(|_| CKR_PIN_INCORRECT)?;
        let (scheme, rest) = value.split_at(value.len().min(7));
        if !scheme.eq_ignore_ascii_case("pkcs11:") {
            return Err(CKR_PIN_INCORRECT.into());
        }
        if rest.contains('#') {
            return Err(CKR_PIN_INCORRECT.into());
        }
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        let mut result = Self::default();
        for component in path.split(';').filter(|component| !component.is_empty()) {
            let (name, value) = component.split_once('=').ok_or(CKR_PIN_INCORRECT)?;
            let decoded = percent_decode(value)?;
            let destination = match name {
                "token" => &mut result.token,
                "manufacturer" => &mut result.manufacturer,
                "serial" => &mut result.serial,
                "model" => &mut result.model,
                "object" => &mut result.object,
                "id" => &mut result.id,
                "type" => {
                    if result.class.is_some() {
                        return Err(CKR_PIN_INCORRECT.into());
                    }
                    result.class = Some(parse_object_type(&decoded)?);
                    continue;
                }
                // An unknown path attribute must not accidentally broaden a
                // selector. This login API reports that as an invalid username.
                _ => return Err(CKR_PIN_INCORRECT.into()),
            };
            if destination.replace(decoded).is_some() {
                return Err(CKR_PIN_INCORRECT.into());
            }
        }
        for component in query.split('&').filter(|component| !component.is_empty()) {
            let (name, value) = component.split_once('=').ok_or(CKR_PIN_INCORRECT)?;
            match name {
                AUTHKEY_QUERY => {
                    if result.authkey_id.is_some() {
                        return Err(CKR_PIN_INCORRECT.into());
                    }
                    result.authkey_id = Some(parse_authkey_id(&percent_decode(value)?)?);
                }
                DIRECT_QUERY => {
                    if result.direct.is_some() {
                        return Err(CKR_PIN_INCORRECT.into());
                    }
                    result.direct = Some(
                        String::from_utf8(percent_decode(value)?)
                            .map_err(|_| Error::from(CKR_PIN_INCORRECT))?,
                    );
                }
                // PINs are supplied by C_LoginUser. Accepting a second secret
                // in the username would create conflicting authentication paths.
                "pin-value" | "pin-source" => return Err(CKR_ARGUMENTS_BAD.into()),
                // RFC query attributes select a module rather than an object.
                // PKCS11RS is already the loaded module, so they have no effect.
                "module-name" | "module-path" => {}
                // RFC 7512 permits vendor query attributes to be ignored.
                _ if name.contains('-') => {}
                _ => return Err(CKR_PIN_INCORRECT.into()),
            }
        }
        if result.direct.is_some()
            && (result.authkey_id.is_none()
                || result.token.is_some()
                || result.manufacturer.is_some()
                || result.serial.is_some()
                || result.model.is_some()
                || result.object.is_some()
                || result.id.is_some()
                || result.class.is_some())
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        Ok(result)
    }

    pub(crate) fn matches_slot_fields(
        &self,
        token: &str,
        manufacturer: &str,
        serial: &str,
        model: &str,
    ) -> bool {
        matches_text(self.token.as_deref(), token)
            && matches_text(self.manufacturer.as_deref(), manufacturer)
            && matches_text(self.serial.as_deref(), serial)
            && matches_text(self.model.as_deref(), model)
    }

    pub(crate) fn object_label(&self) -> Result<Option<&str>, Error> {
        self.object
            .as_deref()
            .map(|value| std::str::from_utf8(value).map_err(|_| Error::from(CKR_PIN_INCORRECT)))
            .transpose()
    }

    pub(crate) fn is_wildcard_target(&self) -> bool {
        self.authkey_id.is_none()
    }

    #[cfg(test)]
    pub(crate) fn format(&self) -> String {
        let mut result = String::from("pkcs11:");
        let mut first = true;
        for (name, value) in [
            ("token", self.token.as_deref()),
            ("manufacturer", self.manufacturer.as_deref()),
            ("serial", self.serial.as_deref()),
            ("model", self.model.as_deref()),
            ("object", self.object.as_deref()),
            ("id", self.id.as_deref()),
        ] {
            let Some(value) = value else { continue };
            if !first {
                result.push(';');
            }
            first = false;
            result.push_str(name);
            result.push('=');
            result.push_str(&percent_encode(value));
        }
        if let Some(class) = self.class.and_then(format_object_type) {
            if !first {
                result.push(';');
            }
            result.push_str("type=");
            result.push_str(class);
        }
        let mut first_query = true;
        if let Some(direct) = self.direct.as_ref() {
            result.push('?');
            first_query = false;
            result.push_str(DIRECT_QUERY);
            result.push('=');
            result.push_str(&percent_encode(direct.as_bytes()));
        }
        if let Some(authkey_id) = self.authkey_id {
            result.push(if first_query { '?' } else { '&' });
            result.push_str(AUTHKEY_QUERY);
            result.push('=');
            result.push_str(&format!("{authkey_id:04x}"));
        }
        result
    }
}

pub(crate) fn object_uri(slot: &dyn Slot, object: &TokenObject) -> String {
    object_uri_parts(slot, object.class, object.label.as_bytes(), &object.id)
}

pub(crate) fn object_uri_parts(
    slot: &dyn Slot,
    class: CK_OBJECT_CLASS,
    object: &[u8],
    id: &[u8],
) -> String {
    object_uri_from_prefix(
        &slot_uri_prefix(&slot.label(), slot.serial()),
        class,
        object,
        id,
    )
}

pub(crate) fn slot_uri_prefix(label: &str, serial: &str) -> String {
    let mut uri = format!("pkcs11:token={}", percent_encode(label.as_bytes()));
    if !serial.is_empty() && !label.contains(serial) {
        uri.push_str(";serial=");
        uri.push_str(&percent_encode(serial.as_bytes()));
    }
    uri
}

pub(crate) fn object_uri_from_prefix(
    prefix: &str,
    class: CK_OBJECT_CLASS,
    object: &[u8],
    id: &[u8],
) -> String {
    let mut uri = prefix.to_owned();
    uri.push_str(";object=");
    uri.push_str(&percent_encode(object));
    if !id.is_empty() {
        uri.push_str(";id=");
        uri.push_str(&percent_encode(id));
    }
    if let Some(type_) = format_object_type(class) {
        uri.push_str(";type=");
        uri.push_str(type_);
    }
    uri
}

pub(crate) fn authentication_uri(source: &str, authkey_id: u16) -> String {
    format!("{source}?{AUTHKEY_QUERY}={authkey_id:04x}")
}

pub(crate) fn direct_authentication_uri(label: &str, authkey_id: u16) -> String {
    format!(
        "pkcs11:?{DIRECT_QUERY}={}&{AUTHKEY_QUERY}={authkey_id:04x}",
        percent_encode(label.as_bytes())
    )
}

fn matches_text(expected: Option<&[u8]>, actual: &str) -> bool {
    expected.is_none_or(|expected| expected == actual.as_bytes())
}

fn parse_authkey_id(value: &[u8]) -> Result<u16, Error> {
    if value.len() != 4 {
        return Err(CKR_PIN_INCORRECT.into());
    }
    std::str::from_utf8(value)
        .ok()
        .and_then(|value| u16::from_str_radix(value, 16).ok())
        .ok_or_else(|| CKR_PIN_INCORRECT.into())
}

fn parse_object_type(value: &[u8]) -> Result<CK_OBJECT_CLASS, Error> {
    match value {
        b"data" => Ok(CKO_DATA as CK_OBJECT_CLASS),
        b"cert" => Ok(CKO_CERTIFICATE as CK_OBJECT_CLASS),
        b"public" => Ok(CKO_PUBLIC_KEY as CK_OBJECT_CLASS),
        b"private" => Ok(CKO_PRIVATE_KEY as CK_OBJECT_CLASS),
        b"secret-key" => Ok(CKO_SECRET_KEY as CK_OBJECT_CLASS),
        _ => Err(CKR_PIN_INCORRECT.into()),
    }
}

fn format_object_type(class: CK_OBJECT_CLASS) -> Option<&'static str> {
    match class {
        x if x == CKO_DATA as CK_OBJECT_CLASS => Some("data"),
        x if x == CKO_CERTIFICATE as CK_OBJECT_CLASS => Some("cert"),
        x if x == CKO_PUBLIC_KEY as CK_OBJECT_CLASS => Some("public"),
        x if x == CKO_PRIVATE_KEY as CK_OBJECT_CLASS => Some("private"),
        x if x == CKO_SECRET_KEY as CK_OBJECT_CLASS => Some("secret-key"),
        _ => None,
    }
}

fn percent_decode(value: &str) -> Result<Vec<u8>, Error> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        let encoded = bytes.get(index + 1..index + 3).ok_or(CKR_PIN_INCORRECT)?;
        let high = hex(encoded[0]).ok_or(CKR_PIN_INCORRECT)?;
        let low = hex(encoded[1]).ok_or(CKR_PIN_INCORRECT)?;
        decoded.push((high << 4) | low);
        index += 3;
    }
    Ok(decoded)
}

fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn percent_encode(value: &[u8]) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            encoded.push(char::from(*byte));
        } else {
            encoded.push('%');
            encoded.push_str(&format!("{byte:02X}"));
        }
    }
    encoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_broad_and_exact_authentication_uris() {
        assert_eq!(
            ClientAuthUri::parse(b"pkcs11:").unwrap(),
            ClientAuthUri::default()
        );
        let parsed = ClientAuthUri::parse(
            b"pkcs11:token=PIV%20%2337070618;object=Authentication;id=%9A;type=private?pkcs11rs-authkey=00a5",
        )
        .unwrap();
        assert_eq!(parsed.token.as_deref(), Some(b"PIV #37070618".as_slice()));
        assert_eq!(parsed.object.as_deref(), Some(b"Authentication".as_slice()));
        assert_eq!(parsed.id.as_deref(), Some([0x9a].as_slice()));
        assert_eq!(parsed.class, Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS));
        assert_eq!(parsed.authkey_id, Some(0x00a5));
    }

    #[test]
    fn parses_algorithm_neutral_direct_authentication() {
        let parsed =
            ClientAuthUri::parse(b"pkcs11:?pkcs11rs-direct=phone%20client&pkcs11rs-authkey=0001")
                .unwrap();
        assert_eq!(parsed.direct.as_deref(), Some("phone client"));
        assert_eq!(parsed.authkey_id, Some(1));
    }

    #[test]
    fn rejects_ambiguous_or_secret_bearing_syntax() {
        for value in [
            b"pkcs11:token=a;token=b".as_slice(),
            b"pkcs11:unknown=value",
            b"pkcs11:?pin-value=password",
            b"pkcs11:token=x?pkcs11rs-direct=x&pkcs11rs-authkey=0001",
            b"pkcs11:?pkcs11rs-direct=x",
        ] {
            assert!(ClientAuthUri::parse(value).is_err(), "accepted {value:?}");
        }
    }

    #[test]
    fn formats_rfc_object_and_login_uris() {
        assert_eq!(
            authentication_uri(
                "pkcs11:token=PIV%20%2337070618;object=Authentication;id=%9A;type=private",
                1
            ),
            "pkcs11:token=PIV%20%2337070618;object=Authentication;id=%9A;type=private?pkcs11rs-authkey=0001"
        );
        assert_eq!(
            direct_authentication_uri("phone client", 0xa5),
            "pkcs11:?pkcs11rs-direct=phone%20client&pkcs11rs-authkey=00a5"
        );
        assert_eq!(
            slot_uri_prefix("PIV #37070618", "37070618"),
            "pkcs11:token=PIV%20%2337070618"
        );
        assert_eq!(
            slot_uri_prefix("Secure Enclave", ""),
            "pkcs11:token=Secure%20Enclave"
        );
        assert_eq!(
            object_uri_from_prefix(
                "pkcs11:token=HSM%20Auth",
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                b"asymmetric",
                b"asymmetric",
            ),
            "pkcs11:token=HSM%20Auth;object=asymmetric;id=asymmetric;type=private"
        );
        assert_eq!(
            object_uri_from_prefix(
                "pkcs11:token=PIV",
                CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                b"Authentication",
                b"asymmetric",
            ),
            "pkcs11:token=PIV;object=Authentication;id=asymmetric;type=private"
        );
    }

    #[test]
    fn generated_object_uri_round_trips_through_the_selector() {
        let uri = object_uri_from_prefix(
            &slot_uri_prefix("Software Token", "7"),
            CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
            "räksmörgås".as_bytes(),
            &[0x00, 0x7f, 0x80, 0xff],
        );
        let parsed = ClientAuthUri::parse(uri.as_bytes()).unwrap();
        assert_eq!(parsed.token.as_deref(), Some(b"Software Token".as_slice()));
        assert_eq!(parsed.serial.as_deref(), Some(b"7".as_slice()));
        assert_eq!(parsed.object.as_deref(), Some("räksmörgås".as_bytes()));
        assert_eq!(
            parsed.id.as_deref(),
            Some([0x00, 0x7f, 0x80, 0xff].as_slice())
        );
        assert_eq!(parsed.class, Some(CKO_PRIVATE_KEY as CK_OBJECT_CLASS));
        assert!(parsed.authkey_id.is_none());
        assert!(parsed.direct.is_none());

        let selected = authentication_uri(&uri, 0x00a5);
        let parsed = ClientAuthUri::parse(selected.as_bytes()).unwrap();
        assert_eq!(parsed.authkey_id, Some(0x00a5));
        assert_eq!(parsed.object.as_deref(), Some("räksmörgås".as_bytes()));
        assert_eq!(
            parsed.id.as_deref(),
            Some([0x00, 0x7f, 0x80, 0xff].as_slice())
        );
    }
}
