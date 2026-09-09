use super::*;
use crate::secure_channel_crypto::{aes_cmac, aes_encrypt_block, scp03_kdf};
use software_key_core::{
    secure_channel::x963_kdf_sha256, software_key_agreement::derive_with_signing_key,
};

fn ec(scalar: u8) -> SoftwareSigningKey {
    let mut encoded = [0; 32];
    encoded[31] = scalar;
    SoftwareSigningKey::from_serialized_for_kind(KeyKind::Ec(EcCurve::P256), &encoded).unwrap()
}
fn public(key: &SoftwareSigningKey) -> Vec<u8> {
    let SoftwarePublicKey::Ec { uncompressed, .. } = key.public_key() else {
        panic!("EC fixture")
    };
    uncompressed
}
fn credential(value: &[u8], mechanism: CK_MECHANISM_TYPE) -> BoundKey {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let handle = scope
        .import_secret(value, generic_template(&[mechanism]))
        .unwrap();
    scope.take_key(&handle).unwrap()
}
fn check_keys(keys: &SessionKeys, enc: &[u8], mac: &[u8], rmac: &[u8]) {
    assert!(!keys.is_empty());
    assert_eq!(
        keys.iv(&[0; 16]).unwrap(),
        aes_encrypt_block(enc, &[0; 16]).unwrap()
    );
    assert_eq!(
        keys.command_mac(b"command").unwrap(),
        aes_cmac(mac, b"command").unwrap()
    );
    let response_mac = aes_cmac(rmac, b"response").unwrap();
    keys.verify_response_mac(b"response", &response_mac[..8])
        .unwrap();
    assert!(
        keys.verify_response_mac(b"tampered", &response_mac[..8])
            .is_err()
    );
}

#[test]
fn symmetric_bound_credential_is_one_object_and_survives_session_cleanup() {
    let value: Vec<u8> = (0x40..0x60).collect();
    let credential = credential(&value, CKM_EXTRACT_KEY_FROM_KEY as _);
    let mut keys = SessionKeys::derive(&credential, &[1; 16]).unwrap();
    check_keys(
        &keys,
        &scp03_kdf(&value[..16], 4, &[1; 16], 128).unwrap(),
        &scp03_kdf(&value[16..], 6, &[1; 16], 128).unwrap(),
        &scp03_kdf(&value[16..], 7, &[1; 16], 128).unwrap(),
    );
    keys.clear();
    assert!(keys.is_empty());
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential)
            .unwrap()
            .count_provider_objects(),
        1
    );
    let second = SessionKeys::derive(&credential, &[2; 16]).unwrap();
    assert!(!second.is_empty());
    drop(second);
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential)
            .unwrap()
            .count_provider_objects(),
        1
    );
}

type AsymmetricFixture = (
    AsymmetricKeys,
    BoundKey,
    std::rc::Weak<crate::pkcs11_provider::Pkcs11Provider>,
    [u8; 130],
    Zeroizing<Vec<u8>>,
    [u8; 16],
);

fn asymmetric_fixture() -> AsymmetricFixture {
    let mut scope = Pkcs11KeyScope::new().unwrap();
    let key = scope.import_p256(ec(1)).unwrap();
    let credential = scope.take_key(&key).unwrap();
    let source = Rc::downgrade(&scope.session.provider);
    let ephemeral = scope.import_p256(ec(2)).unwrap();
    let mut exchange = AsymmetricKeys { scope, ephemeral };
    let static_shared = exchange
        .static_agreement(&credential, &public(&ec(3)))
        .unwrap();
    let mut context = [0; 130];
    context[..65].copy_from_slice(&exchange.public_key().unwrap());
    context[65..].copy_from_slice(&public(&ec(4)));
    // Independent raw-key reference exists only in this test fixture.
    let mut z = derive_with_signing_key(&ec(2), &context[65..]).unwrap();
    z.extend_from_slice(&derive_with_signing_key(&ec(1), &public(&ec(3))).unwrap());
    let expected = x963_kdf_sha256(&z, &super::super::SCP11_SHARED_INFO, 64).unwrap();
    let transcript = [&context[65..], &context[..65]].concat();
    let receipt = aes_cmac(&expected[..16], &transcript).unwrap();
    (exchange, static_shared, source, context, expected, receipt)
}

#[test]
fn asymmetric_bound_key_derives_readable_working_keys_for_local_crypto() {
    let (exchange, static_shared, source, context, expected, receipt) = asymmetric_fixture();
    assert!(source.upgrade().is_some());
    let mut keys = exchange.finish(&static_shared, &context, &receipt).unwrap();
    check_keys(
        &keys,
        &expected[16..32],
        &expected[32..48],
        &expected[48..64],
    );
    assert!(source.upgrade().is_some());
    keys.clear();
    assert!(keys.is_empty());
}

#[test]
fn asymmetric_receipt_and_transcript_rejections_publish_no_session_keys() {
    let (exchange, shared, source, context, _, mut receipt) = asymmetric_fixture();
    receipt[0] ^= 1;
    assert!(
        matches!(exchange.finish(&shared, &context, &receipt), Err(Error::Generic(rv)) if rv == CKR_SIGNATURE_INVALID as CK_RV)
    );
    assert!(source.upgrade().is_some());
    let (exchange, shared, _, mut context, _, receipt) = asymmetric_fixture();
    context[1] ^= 1;
    assert!(
        matches!(exchange.finish(&shared, &context, &receipt), Err(Error::Generic(rv)) if rv == CKR_DATA_INVALID as CK_RV)
    );
    let (exchange, shared, _, mut context, _, receipt) = asymmetric_fixture();
    context[65..].fill(0);
    assert!(exchange.finish(&shared, &context, &receipt).is_err());
}

#[test]
fn local_keys_validate_lengths_and_clear_all_operations() {
    for (enc, mac, rmac) in [(15, 16, 16), (16, 17, 16), (16, 16, 32)] {
        assert!(SessionKeys::import(&vec![1; enc], &vec![2; mac], &vec![3; rmac]).is_err());
    }
    let mut keys = SessionKeys::import(&[1; 16], &[2; 16], &[3; 16]).unwrap();
    let iv = keys.iv(&[0; 16]).unwrap();
    let encrypted = keys.cbc(&iv, &[42; 32], true).unwrap();
    assert_eq!(keys.cbc(&iv, &encrypted, false).unwrap(), [42; 32]);
    for signature in [&[][..], &[0; 7], &[0; 9], &[0; 16]] {
        assert!(
            matches!(keys.verify_response_mac(b"response", signature), Err(Error::Generic(rv)) if rv == CKR_SIGNATURE_LEN_RANGE as CK_RV)
        );
    }
    keys.clear();
    assert!(keys.is_empty());
    assert!(keys.iv(&[0; 16]).is_err());
    assert!(keys.cbc(&iv, &encrypted, false).is_err());
    assert!(keys.command_mac(b"command").is_err());
    assert!(keys.verify_response_mac(b"response", &[0; 8]).is_err());
}

#[test]
fn partial_working_key_read_fails_and_releases_the_derivation_scope() {
    let credential = credential(&[0x42; 32], CKM_SHA256_KEY_DERIVATION as _);
    let mut scope = Pkcs11KeyScope::for_key(&credential).unwrap();
    let base = scope.bind(&credential).unwrap();
    let block = scope
        .sha256(
            &base,
            readable(generic_template(&[CKM_EXTRACT_KEY_FROM_KEY as _])),
        )
        .unwrap();
    let enc = scope
        .extract(&block, 0, readable(enc_template()), 16)
        .unwrap();
    // The second read fails after the first has produced a zeroizing value.
    let mac = scope.extract(&block, 0, mac_template(), 16).unwrap();
    let rmac = scope
        .extract(&block, 128, readable(rmac_template()), 16)
        .unwrap();
    assert_eq!(scope.count_provider_objects(), 5);
    assert!(
        matches!(SessionKeys::read_working_keys(scope, enc, mac, rmac),
        Err(Error::Generic(rv)) if rv == CKR_ATTRIBUTE_SENSITIVE as CK_RV)
    );
    assert_eq!(
        Pkcs11KeyScope::for_key(&credential)
            .unwrap()
            .count_provider_objects(),
        1
    );
}
