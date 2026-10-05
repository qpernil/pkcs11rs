//! WebAuthn registration export normalization. This does not replace the RP's
//! challenge, origin, or attestation trust validation.
use super::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

pub(super) const EXPORT_SCHEMA: &str = "pkcs11rs.preview-sign.webauthn";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Export {
    schema: String,
    version: u64,
    rp_id: String,
    credential: Credential,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Credential {
    id: String,
    raw_id: String,
    #[serde(rename = "type")]
    type_: String,
    response: Response,
    client_extension_results: ExtensionResults,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Response {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    attestation_object: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExtensionResults {
    preview_sign: SignResult,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct SignResult {
    generated_key: GeneratedKey,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GeneratedKey {
    key_handle: String,
    public_key: String,
    algorithm: i64,
    attestation_object: String,
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    type_: String,
    challenge: String,
    origin: String,
}

fn decode_bytes(encoded: &str) -> Result<Vec<u8>, PreviewSignError> {
    URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| PreviewSignError::Malformed("invalid base64url WebAuthn field"))
}

/// Translate string-keyed WebAuthn attestation into the equivalent CTAP map,
/// preserving authenticator data and attestation statement bytes verbatim.
fn ctap_attestation(encoded: &[u8]) -> Result<Vec<u8>, PreviewSignError> {
    let mut decoder = Decoder::new(encoded);
    let count = definite_map(&mut decoder, "WebAuthn attestation is not a definite map")?;
    let mut format = None;
    let mut auth_data = None;
    let mut statement = None;
    for _ in 0..count {
        match decoder.str()? {
            "fmt" if format.is_none() => format = Some(decoder.str()?.to_owned()),
            "authData" if auth_data.is_none() => auth_data = Some(decoder.bytes()?.to_vec()),
            "attStmt" if statement.is_none() => {
                let start = decoder.position();
                require_map_value(&mut decoder, "WebAuthn attestation statement is not a map")?;
                statement = Some(encoded[start..decoder.position()].to_vec());
            }
            "fmt" | "authData" | "attStmt" => {
                return Err(PreviewSignError::Malformed(
                    "duplicate WebAuthn attestation field",
                ));
            }
            _ => decoder.skip()?,
        }
    }
    if decoder.position() != encoded.len() {
        return Err(PreviewSignError::Malformed(
            "trailing WebAuthn attestation data",
        ));
    }
    let mut output = Vec::new();
    let mut encoder = Encoder::new(&mut output);
    encoder
        .map(3)?
        .u8(1)?
        .str(&format.ok_or(PreviewSignError::Malformed(
            "missing WebAuthn attestation format",
        ))?)?
        .u8(2)?
        .bytes(&auth_data.ok_or(PreviewSignError::Malformed(
            "missing WebAuthn authenticator data",
        ))?)?
        .u8(3)?;
    encoder
        .writer_mut()
        .extend_from_slice(&statement.ok_or(PreviewSignError::Malformed(
            "missing WebAuthn attestation statement",
        ))?);
    Ok(output)
}

pub(super) fn validate_client_data(encoded: &[u8]) -> Result<[u8; 32], PreviewSignError> {
    let client_data: ClientData = serde_json::from_slice(encoded)
        .map_err(|_| PreviewSignError::Malformed("invalid registration client data"))?;
    if client_data.type_ != "webauthn.create"
        || client_data.origin.is_empty()
        || decode_bytes(&client_data.challenge)?.is_empty()
    {
        return Err(PreviewSignError::Malformed(
            "invalid registration ceremony data",
        ));
    }
    copy_array::<32>(
        &software_key_core::digest::HashAlgorithm::Sha256.digest(encoded),
        "invalid client-data hash length",
    )
}

pub(super) fn decode_registration(
    encoded: &[u8],
) -> Result<(String, Vec<u8>, Vec<u8>), PreviewSignError> {
    let export: Export = serde_json::from_slice(encoded)
        .map_err(|_| PreviewSignError::Malformed("invalid WebAuthn registration export"))?;
    if export.schema != EXPORT_SCHEMA {
        return Err(PreviewSignError::Malformed(
            "invalid WebAuthn export schema",
        ));
    }
    if export.version != 1 {
        return Err(PreviewSignError::UnsupportedSchemaVersion(export.version));
    }
    let credential = export.credential;
    if credential.type_ != "public-key" || credential.id != credential.raw_id {
        return Err(PreviewSignError::Malformed(
            "invalid WebAuthn credential identity",
        ));
    }
    let credential_id = decode_bytes(&credential.raw_id)?;
    let client_data_json = decode_bytes(&credential.response.client_data_json)?;
    validate_client_data(&client_data_json)?;
    let parent = ctap_attestation(&decode_bytes(&credential.response.attestation_object)?)?;
    let generated = credential
        .client_extension_results
        .preview_sign
        .generated_key;
    let signing = ctap_attestation(&decode_bytes(&generated.attestation_object)?)?;
    let mut decoder = Decoder::new(&parent);
    decoder.map()?;
    // ctap_attestation emits exactly three fields in this order.
    decoder.u8()?;
    decoder.str()?;
    decoder.u8()?;
    let parent_key = parse_attested_key(decoder.bytes()?, true)?;
    let signing_key = parse_signing_key_attestation_object(&signing)?;
    if credential_id != parent_key.credential_id
        || decode_bytes(&generated.key_handle)? != signing_key.credential_id
        || decode_bytes(&generated.public_key)? != signing_key.public_key_cose
        || generated.algorithm != parse_registration_algorithm(&parent_key.preview_sign_output)?
    {
        return Err(PreviewSignError::Malformed(
            "inconsistent WebAuthn PreviewSign result",
        ));
    }
    let mut response = Vec::new();
    let mut encoder = Encoder::new(&mut response);
    encoder.map(4)?;
    // Copy the three normalized parent map entries, excluding its map header.
    encoder.writer_mut().extend_from_slice(&parent[1..]);
    encoder
        .u8(6)?
        .map(1)?
        .str(PREVIEW_SIGN_EXTENSION)?
        .map(1)?
        .u8(7)?
        .bytes(&signing)?;
    Ok((export.rp_id, client_data_json, response))
}

#[cfg(test)]
pub(crate) fn browser_export(registration: &PreviewSignRegistration) -> Vec<u8> {
    fn attestation(ctap: &[u8]) -> Vec<u8> {
        let mut decoder = Decoder::new(ctap);
        let count = decoder.map().unwrap().unwrap();
        let mut output = Vec::new();
        let mut encoder = Encoder::new(&mut output);
        encoder.map(3).unwrap();
        for _ in 0..count {
            let key = decoder.u8().unwrap();
            let start = decoder.position();
            decoder.skip().unwrap();
            let name = match key {
                1 => "fmt",
                2 => "authData",
                3 => "attStmt",
                _ => continue,
            };
            encoder.str(name).unwrap();
            encoder
                .writer_mut()
                .extend_from_slice(&ctap[start..decoder.position()]);
        }
        output
    }
    let b64 = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    let client_data =
        br#"{"type":"webauthn.create","challenge":"AQID","origin":"https://example.com"}"#;
    serde_json::to_vec(&serde_json::json!({
        "schema": EXPORT_SCHEMA, "version": 1, "rpId": registration.rp_id(),
        "credential": {
            "id": b64(registration.credential_id()), "rawId": b64(registration.credential_id()),
            "type": "public-key",
            "response": {
                "clientDataJSON": b64(client_data),
                "attestationObject": b64(&attestation(registration.make_credential_response())),
            },
            "clientExtensionResults": { "previewSign": { "generatedKey": {
                "keyHandle": b64(registration.signing_key_handle()),
                "publicKey": b64(registration.signing_seed_public_key_cose()),
                "algorithm": registration.algorithm(),
                "attestationObject": b64(&attestation(registration.signing_key_attestation_object())),
            }}},
        },
    })).unwrap()
}
