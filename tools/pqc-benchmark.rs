//! Software-only timings for the shared PQC core and the public PKCS #11 ABI.
//! Build and run with tools/pqc-benchmark.py; never run with inherited provider configuration.

use software_key_core::post_quantum::*;
use std::{hint::black_box, ptr::null_mut, time::Instant};
#[allow(
    dead_code,
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals
)]
#[path = "../src/pkcs11.rs"]
mod p;
use p::*;

const N: usize = 2000;
const WARM: usize = 100;

fn bench<T>(
    layer: &str,
    alg: &str,
    operation: &str,
    mut f: impl FnMut() -> T,
    mut cleanup: impl FnMut(T),
) {
    for _ in 0..WARM {
        cleanup(black_box(f()));
    }
    let mut ns = Vec::with_capacity(N);
    for _ in 0..N {
        let start = Instant::now();
        let value = black_box(f());
        ns.push(start.elapsed().as_nanos() as f64);
        cleanup(value);
    }
    ns.sort_by(f64::total_cmp);
    let mean = ns.iter().sum::<f64>() / N as f64;
    println!(
        "{layer},{alg},{operation},{N},{:.3},{:.3},{:.3},{:.0}",
        ns[N / 2] / 1000.,
        mean / 1000.,
        ns[N * 95 / 100] / 1000.,
        1e9 / mean
    );
}
fn ok(rv: CK_RV) {
    assert_eq!(rv, CKR_OK as CK_RV, "PKCS #11 error: {rv:#x}");
}
fn mech(kind: u32) -> CK_MECHANISM {
    CK_MECHANISM {
        mechanism: kind as _,
        pParameter: null_mut(),
        ulParameterLen: 0,
    }
}
fn attr<T>(kind: u32, value: &mut T) -> CK_ATTRIBUTE {
    CK_ATTRIBUTE {
        type_: kind as _,
        pValue: (value as *mut T).cast(),
        ulValueLen: size_of::<T>() as _,
    }
}
unsafe fn destroy(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) {
    ok(unsafe { C_DestroyObject(session, object) });
}
unsafe fn pair(
    session: CK_SESSION_HANDLE,
    kem: bool,
    parameter_set: u64,
) -> (CK_OBJECT_HANDLE, CK_OBJECT_HANDLE) {
    let mut m = mech(if kem {
        CKM_ML_KEM_KEY_PAIR_GEN
    } else {
        CKM_ML_DSA_KEY_PAIR_GEN
    });
    let mut parameter_set = parameter_set as CK_ULONG;
    let mut yes = 1u8;
    let mut pub_attrs = [
        attr(CKA_PARAMETER_SET, &mut parameter_set),
        attr(if kem { CKA_ENCAPSULATE } else { CKA_VERIFY }, &mut yes),
    ];
    let mut priv_attrs = [attr(if kem { CKA_DECAPSULATE } else { CKA_SIGN }, &mut yes)];
    let (mut public, mut private) = (0, 0);
    ok(unsafe {
        C_GenerateKeyPair(
            session,
            &mut m,
            pub_attrs.as_mut_ptr(),
            pub_attrs.len() as _,
            priv_attrs.as_mut_ptr(),
            priv_attrs.len() as _,
            &mut public,
            &mut private,
        )
    });
    (public, private)
}
unsafe fn sign(session: CK_SESSION_HANDLE, private: CK_OBJECT_HANDLE, msg: &[u8]) -> Vec<u8> {
    let mut m = mech(CKM_ML_DSA);
    ok(unsafe { C_SignInit(session, &mut m, private) });
    let mut len = 0;
    ok(unsafe {
        C_Sign(
            session,
            msg.as_ptr().cast_mut(),
            msg.len() as _,
            null_mut(),
            &mut len,
        )
    });
    let mut sig = vec![0; len as usize];
    ok(unsafe {
        C_Sign(
            session,
            msg.as_ptr().cast_mut(),
            msg.len() as _,
            sig.as_mut_ptr(),
            &mut len,
        )
    });
    sig.truncate(len as usize);
    sig
}
unsafe fn verify(session: CK_SESSION_HANDLE, public: CK_OBJECT_HANDLE, msg: &[u8], sig: &[u8]) {
    let mut m = mech(CKM_ML_DSA);
    ok(unsafe { C_VerifyInit(session, &mut m, public) });
    ok(unsafe {
        C_Verify(
            session,
            msg.as_ptr().cast_mut(),
            msg.len() as _,
            sig.as_ptr().cast_mut(),
            sig.len() as _,
        )
    });
}
unsafe fn encapsulate(
    session: CK_SESSION_HANDLE,
    public: CK_OBJECT_HANDLE,
) -> (Vec<u8>, CK_OBJECT_HANDLE) {
    let mut m = mech(CKM_ML_KEM);
    let mut len = 0;
    let mut handle = 0;
    ok(unsafe {
        C_EncapsulateKey(
            session,
            &mut m,
            public,
            null_mut(),
            0,
            null_mut(),
            &mut len,
            &mut handle,
        )
    });
    let mut ct = vec![0; len as usize];
    ok(unsafe {
        C_EncapsulateKey(
            session,
            &mut m,
            public,
            null_mut(),
            0,
            ct.as_mut_ptr(),
            &mut len,
            &mut handle,
        )
    });
    ct.truncate(len as usize);
    (ct, handle)
}
unsafe fn decapsulate(
    session: CK_SESSION_HANDLE,
    private: CK_OBJECT_HANDLE,
    ct: &[u8],
) -> CK_OBJECT_HANDLE {
    let mut m = mech(CKM_ML_KEM);
    let mut handle = 0;
    ok(unsafe {
        C_DecapsulateKey(
            session,
            &mut m,
            private,
            null_mut(),
            0,
            ct.as_ptr().cast_mut(),
            ct.len() as _,
            &mut handle,
        )
    });
    handle
}
unsafe fn value(session: CK_SESSION_HANDLE, object: CK_OBJECT_HANDLE) -> Vec<u8> {
    let mut bytes = vec![0u8; 32];
    let mut a = CK_ATTRIBUTE {
        type_: CKA_VALUE as _,
        pValue: bytes.as_mut_ptr().cast(),
        ulValueLen: bytes.len() as _,
    };
    ok(unsafe { C_GetAttributeValue(session, object, &mut a, 1) });
    bytes.truncate(a.ulValueLen as usize);
    bytes
}
fn main() {
    println!("layer,algorithm,operation,samples,median_us,mean_us,p95_us,ops_per_second");
    let message = [42u8; 32];
    for (alg, params) in [
        ("ML-DSA-44", MlDsaParameterSet::MlDsa44),
        ("ML-DSA-65", MlDsaParameterSet::MlDsa65),
        ("ML-DSA-87", MlDsaParameterSet::MlDsa87),
    ] {
        bench(
            "core",
            alg,
            "keygen",
            || MlDsaPrivateKey::generate(params).unwrap(),
            drop,
        );
        let key = MlDsaPrivateKey::generate(params).unwrap();
        let public = key.public_key();
        let sig = key.sign_hedged(&message, b"").unwrap();
        verify_ml_dsa(params, &public, &message, b"", &sig).unwrap();
        let mut bad = message;
        bad[0] ^= 1;
        assert!(verify_ml_dsa(params, &public, &bad, b"", &sig).is_err());
        bench(
            "core",
            alg,
            "sign",
            || key.sign_hedged(black_box(&message), b"").unwrap(),
            drop,
        );
        bench(
            "core",
            alg,
            "verify",
            || verify_ml_dsa(params, black_box(&public), &message, b"", &sig).unwrap(),
            drop,
        );
    }
    for (alg, params) in [
        ("ML-KEM-512", MlKemParameterSet::MlKem512),
        ("ML-KEM-768", MlKemParameterSet::MlKem768),
        ("ML-KEM-1024", MlKemParameterSet::MlKem1024),
    ] {
        bench(
            "core",
            alg,
            "keygen",
            || MlKemPrivateKey::generate(params).unwrap(),
            drop,
        );
        let key = MlKemPrivateKey::generate(params).unwrap();
        let public = key.public_key();
        let (ct, expected) = ml_kem_encapsulate(params, &public).unwrap();
        assert_eq!(*key.decapsulate(&ct).unwrap(), *expected);
        bench(
            "core",
            alg,
            "encapsulate",
            || ml_kem_encapsulate(params, black_box(&public)).unwrap(),
            drop,
        );
        bench(
            "core",
            alg,
            "decapsulate",
            || key.decapsulate(black_box(&ct)).unwrap(),
            drop,
        );
    }
    // This executable is run with a clean environment, hardware discovery off,
    // one ephemeral software slot, and no persistent storage or remote URLs.
    assert_eq!(std::env::var("PKCS11RS_HARDWARE_DISCOVERY").unwrap(), "0");
    assert!(std::env::var("PKCS11RS_TOKEN_STORAGE").is_err());
    assert!(std::env::var("PKCS11RS_YUBIHSM_URLS").is_err());
    unsafe {
        ok(C_Initialize(null_mut()));
        let mut count = 0;
        ok(C_GetSlotList(1, null_mut(), &mut count));
        assert_eq!(count, 1);
        let mut slot = 0;
        ok(C_GetSlotList(1, &mut slot, &mut count));
        let mut session = 0;
        ok(C_OpenSession(
            slot,
            (CKF_SERIAL_SESSION | CKF_RW_SESSION) as _,
            null_mut(),
            None,
            &mut session,
        ));
        let mut test_pin = *b"bench-only-test-pin";
        ok(C_Login(
            session,
            CKU_USER as _,
            test_pin.as_mut_ptr(),
            test_pin.len() as _,
        ));
        test_pin.fill(0);
        for (alg, set) in [("ML-DSA-44", 1), ("ML-DSA-65", 2), ("ML-DSA-87", 3)] {
            bench(
                "pkcs11",
                alg,
                "keygen",
                || pair(session, false, set),
                |(public, private)| {
                    destroy(session, public);
                    destroy(session, private);
                },
            );
            let (public, private) = pair(session, false, set);
            let sig = sign(session, private, &message);
            verify(session, public, &message, &sig);
            bench(
                "pkcs11",
                alg,
                "sign",
                || sign(session, private, black_box(&message)),
                drop,
            );
            bench(
                "pkcs11",
                alg,
                "verify",
                || verify(session, public, black_box(&message), &sig),
                drop,
            );
            destroy(session, public);
            destroy(session, private);
        }
        for (alg, set) in [("ML-KEM-512", 1), ("ML-KEM-768", 2), ("ML-KEM-1024", 3)] {
            bench(
                "pkcs11",
                alg,
                "keygen",
                || pair(session, true, set),
                |(public, private)| {
                    destroy(session, public);
                    destroy(session, private);
                },
            );
            let (public, private) = pair(session, true, set);
            let (ct, expected) = encapsulate(session, public);
            let actual = decapsulate(session, private, &ct);
            let mut expected_value = value(session, expected);
            let mut actual_value = value(session, actual);
            assert_eq!(expected_value, actual_value);
            expected_value.fill(0);
            actual_value.fill(0);
            destroy(session, expected);
            destroy(session, actual);
            bench(
                "pkcs11",
                alg,
                "encapsulate",
                || encapsulate(session, public),
                |(_, handle)| destroy(session, handle),
            );
            bench(
                "pkcs11",
                alg,
                "decapsulate",
                || decapsulate(session, private, black_box(&ct)),
                |handle| destroy(session, handle),
            );
            destroy(session, public);
            destroy(session, private);
        }
        ok(C_Logout(session));
        ok(C_CloseSession(session));
        ok(C_Finalize(null_mut()));
    }
}
