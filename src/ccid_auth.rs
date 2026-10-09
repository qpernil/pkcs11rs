//! Login-selected card credentials. Source authorization belongs to the source slot.
use crate::{
    key_scope::{BoundKey, Pkcs11KeyScope},
    pkcs11_auth::Pkcs11Auth,
    *,
};

#[derive(Clone)]
pub(crate) enum CardCredential {
    Scp03 {
        description: String,
        enc: BoundKey,
        mac: BoundKey,
        dek: Option<BoundKey>,
    },
    Scp11 {
        description: String,
        key: BoundKey,
        certificates: Vec<Vec<u8>>,
    },
}

#[derive(Default)]
pub(crate) struct CardAuthentication {
    pub(crate) sources: Option<Arc<auth_slots::AuthSlots>>,
    pub(crate) target: std::sync::Weak<Mutex<SlotContext>>,
    pub(crate) protocol: Option<SecureChannelProtocol>,
    pub(crate) credential: Option<CardCredential>,
}
impl std::fmt::Debug for CardAuthentication {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardAuthentication")
            .field("protocol", &self.protocol)
            .field("bound", &self.credential.is_some())
            .finish_non_exhaustive()
    }
}

impl CardCredential {
    pub(crate) fn description(&self) -> &str {
        match self {
            Self::Scp03 { description, .. } | Self::Scp11 { description, .. } => description,
        }
    }
    pub(crate) fn scp03_keys(&self) -> Result<scp_key_provider::Scp03Keys, Error> {
        let Self::Scp03 { enc, mac, dek, .. } = self else {
            return Err(CKR_KEY_TYPE_INCONSISTENT.into());
        };
        enc.require_source_authorization()?;
        mac.require_source_authorization()?;
        let mut scope = Pkcs11KeyScope::for_key(enc)?;
        let enc = scope.bind(enc)?;
        let mac = scope.bind(mac)?;
        let dek = dek.as_ref().map(|key| scope.bind(key)).transpose()?;
        Ok(scp_key_provider::Scp03Keys {
            scope,
            enc,
            mac,
            dek,
        })
    }
}

/// Validate the selector and determine the protocol without provider lookup.
pub(crate) fn selection(
    username: &[u8],
    configured: Option<SecureChannelProtocol>,
) -> Result<(pkcs11_uri::ClientAuthUri, SecureChannelProtocol), Error> {
    let selector = pkcs11_uri::ClientAuthUri::parse(username)?;
    if selector.direct.is_some() || selector.authkey_id.is_some() {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let requested = selector.scp;
    // SCP11c is an explicit configuration policy, not a URI request.
    if requested == Some(SecureChannelProtocol::Scp11c) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    if configured.is_some() && requested.is_some() && configured != requested {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let protocol = configured.or(requested).unwrap_or_else(|| {
        if selector.class == Some(CKO_SECRET_KEY as _) {
            SecureChannelProtocol::Scp03
        } else {
            SecureChannelProtocol::Scp11a
        }
    });
    if protocol == SecureChannelProtocol::Scp11b {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let symmetric = protocol == SecureChannelProtocol::Scp03;
    let class = if symmetric {
        CKO_SECRET_KEY
    } else {
        CKO_PRIVATE_KEY
    } as CK_ULONG;
    if selector
        .class
        .is_some_and(|c| c != class as CK_OBJECT_CLASS)
    {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok((selector, protocol))
}

pub(crate) fn resolve(
    sources: &auth_slots::AuthSlots,
    target: &std::sync::Weak<Mutex<SlotContext>>,
    target_device: &Arc<crate::device::DeviceContext>,
    username: &[u8],
    configured: Option<SecureChannelProtocol>,
    configuration: &SecureChannelConfiguration,
) -> Result<(SecureChannelProtocol, CardCredential), Error> {
    let (selector, protocol) = selection(username, configured)?;
    let symmetric = protocol == SecureChannelProtocol::Scp03;
    let class = if symmetric {
        CKO_SECRET_KEY
    } else {
        CKO_PRIVATE_KEY
    } as CK_ULONG;
    sources
        .find_card_credential(&selector, target, target_device, |session| {
            let mut template = vec![
                (CKA_TOKEN, vec![CK_TRUE as u8]),
                (CKA_CLASS, class.to_ne_bytes().to_vec()),
            ];
            let key_type = if symmetric { CKK_AES } else { CKK_EC } as CK_ULONG;
            template.push((CKA_KEY_TYPE, key_type.to_ne_bytes().to_vec()));
            if !symmetric {
                template.push((CKA_EC_PARAMS, pkcs11_auth::P256_PARAMS.to_vec()));
            }
            if let Some(label) = &selector.object {
                template.push((CKA_LABEL, label.clone()));
            }
            if let Some(id) = &selector.id {
                template.push((CKA_ID, id.clone()));
            }
            let borrowed = template
                .iter()
                .map(|(k, v)| (*k, v.as_slice()))
                .collect::<Vec<_>>();
            let keys = session.find(&borrowed)?;
            let handle = match keys.as_slice() {
                [] => return Ok(None),
                [handle] => *handle,
                _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
            };
            let key = BoundKey::from_session(session.clone(), handle)?;
            let description =
                String::from_utf8(session.attribute(handle, CKA_PKCS11RS_URI as _)?.to_vec())
                    .map_err(|_| CKR_DEVICE_ERROR)?;
            let credential = if symmetric {
                let label = session.attribute(handle, CKA_LABEL)?;
                let label = std::str::from_utf8(&label).map_err(|_| CKR_ARGUMENTS_BAD)?;
                let name = label.strip_suffix(".enc").ok_or(CKR_ARGUMENTS_BAD)?;
                let find = |suffix: &str, required: bool| -> Result<Option<BoundKey>, Error> {
                    let keys = session.find(&[
                        (CKA_TOKEN, &[CK_TRUE as u8]),
                        (CKA_CLASS, &(CKO_SECRET_KEY as CK_ULONG).to_ne_bytes()),
                        (CKA_KEY_TYPE, &(CKK_AES as CK_ULONG).to_ne_bytes()),
                        (CKA_LABEL, format!("{name}.{suffix}").as_bytes()),
                    ])?;
                    match keys.as_slice() {
                        [h] => Ok(Some(BoundKey::from_session(session.clone(), *h)?)),
                        [] if !required => Ok(None),
                        [] => Err(CKR_KEY_HANDLE_INVALID.into()),
                        _ => Err(CKR_TEMPLATE_INCONSISTENT.into()),
                    }
                };
                CardCredential::Scp03 {
                    description,
                    enc: key,
                    mac: find("mac", true)?.ok_or(CKR_KEY_HANDLE_INVALID)?,
                    dek: find("dek", false)?,
                }
            } else {
                let id = session.attribute(handle, CKA_ID)?;
                if id.is_empty() {
                    return Err(CKR_TEMPLATE_INCOMPLETE.into());
                }
                let certificates = session.find(&[
                    (CKA_TOKEN, &[CK_TRUE as u8]),
                    (CKA_CLASS, &(CKO_CERTIFICATE as CK_ULONG).to_ne_bytes()),
                    (CKA_CERTIFICATE_TYPE, &(CKC_X_509 as CK_ULONG).to_ne_bytes()),
                    (CKA_ID, &id),
                ])?;
                let leaf = match certificates.as_slice() {
                    [h] => session.attribute(*h, CKA_VALUE)?.to_vec(),
                    [] => return Err(CKR_TEMPLATE_INCOMPLETE.into()),
                    _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
                };
                let mut scope = Pkcs11KeyScope::for_key(&key)?;
                let handle = scope.bind(&key)?;
                let parsed = software_key_core::certificate_chain::ParsedCertificate::parse(&leaf)?;
                if parsed.p256_key_agreement_point()? != scope.p256_public(&handle)? {
                    return Err(CKR_PUBLIC_KEY_INVALID.into());
                }
                let certificates = oce_chain(leaf, &configuration.scp11.oce_intermediates)?;
                CardCredential::Scp11 {
                    key,
                    certificates,
                    description,
                }
            };
            Ok(Some((protocol, credential)))
        })?
        .ok_or_else(|| CKR_KEY_HANDLE_INVALID.into())
}

/// Leaf first; a missing terminal issuer is verified by the card's fixed CA key.
fn oce_chain(leaf: Vec<u8>, intermediates: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, Error> {
    use software_key_core::certificate_chain::ParsedCertificate;
    use x509_cert::ext::pkix::{
        AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectKeyIdentifier,
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| CKR_FUNCTION_FAILED)?
        .as_secs();
    let mut chain = vec![leaf];
    loop {
        let current = ParsedCertificate::parse(chain.last().ok_or(CKR_ARGUMENTS_BAD)?)?;
        if !current.is_valid_at(now) {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if current.is_self_issued() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        let issuer = certificate_chain::issuer(chain.last().ok_or(CKR_ARGUMENTS_BAD)?)?;
        let aki = current
            .certificate()
            .tbs_certificate()
            .get_extension::<AuthorityKeyIdentifier>()
            .map_err(|_| CKR_ARGUMENTS_BAD)?
            .and_then(|(_, v)| v.key_identifier);
        let mut candidates = Vec::new();
        for der in intermediates {
            if certificate_chain::subject(der)? != issuer {
                continue;
            }
            let candidate = ParsedCertificate::parse(der)?;
            let ski = candidate
                .certificate()
                .tbs_certificate()
                .get_extension::<SubjectKeyIdentifier>()
                .map_err(|_| CKR_ARGUMENTS_BAD)?
                .map(|(_, v)| v.0);
            if aki.as_ref().zip(ski.as_ref()).is_some_and(|(a, s)| a != s) {
                continue;
            }
            if current.verify_signature(&candidate).is_ok() {
                candidates.push((der, candidate));
            }
        }
        let (der, candidate) = match candidates.as_slice() {
            [] => break,
            [candidate] => candidate,
            _ => return Err(CKR_TEMPLATE_INCONSISTENT.into()),
        };
        let tbs = candidate.certificate().tbs_certificate();
        if !candidate.is_valid_at(now)
            || !tbs
                .get_extension::<BasicConstraints>()
                .map_err(|_| CKR_ARGUMENTS_BAD)?
                .is_some_and(|(_, v)| v.ca)
            || tbs
                .get_extension::<KeyUsage>()
                .map_err(|_| CKR_ARGUMENTS_BAD)?
                .is_some_and(|(_, v)| !v.key_cert_sign())
        {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        if candidate.is_self_issued() {
            break;
        } // Do not transmit the root.
        if chain.contains(der) || chain.len() > intermediates.len() {
            return Err(CKR_ARGUMENTS_BAD.into());
        }
        chain.push((*der).clone());
    }
    Ok(chain)
}

#[cfg(all(test, feature = "embedded-virtual-yubikey", not(feature = "abi-tests")))]
mod tests;
