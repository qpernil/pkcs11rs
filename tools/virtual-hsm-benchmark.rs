//! Run only through virtual-hsm-benchmark.py. Disposable in-memory devices;
//! no transport, persistent state, hardware discovery, or authentication secrets.
use software_key_core::software_signing::{SignatureScheme as S, ecdsa_signature_from_der};
#[cfg(track_heap)]
use std::alloc::{GlobalAlloc, Layout, System};
use std::{hint::black_box, time::Instant};
use virtual_yubihsm_core::{
    Algorithm as A, Capability as C, CapabilitySet, CommandCode as Cmd, Device, DeviceConfig,
    Frame, ObjectKey, ObjectMaterial, ObjectType, SessionAuthorization,
};

#[cfg(track_heap)]
mod heap {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};
    pub static LIVE: AtomicUsize = AtomicUsize::new(0);
    pub static PEAK: AtomicUsize = AtomicUsize::new(0);
    fn add(n: usize) {
        let live = LIVE.fetch_add(n, Relaxed) + n;
        PEAK.fetch_max(live, Relaxed);
    }
    pub struct Tracked;
    unsafe impl GlobalAlloc for Tracked {
        unsafe fn alloc(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc(l) };
            if !p.is_null() {
                add(l.size());
            }
            p
        }
        unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
            let p = unsafe { System.alloc_zeroed(l) };
            if !p.is_null() {
                add(l.size());
            }
            p
        }
        unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
            unsafe { System.dealloc(p, l) };
            LIVE.fetch_sub(l.size(), Relaxed);
        }
        unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
            let next = unsafe { System.realloc(p, l, n) };
            if !next.is_null() {
                LIVE.fetch_sub(l.size(), Relaxed);
                add(n);
            }
            next
        }
    }
}
#[cfg(track_heap)]
#[global_allocator]
static ALLOCATOR: heap::Tracked = heap::Tracked;
fn live() -> usize {
    #[cfg(track_heap)]
    {
        heap::LIVE.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(track_heap))]
    {
        0
    }
}
fn reset_peak() {
    #[cfg(track_heap)]
    heap::PEAK.store(live(), std::sync::atomic::Ordering::Relaxed);
}
fn peak() -> usize {
    #[cfg(track_heap)]
    {
        heap::PEAK.load(std::sync::atomic::Ordering::Relaxed)
    }
    #[cfg(not(track_heap))]
    {
        0
    }
}
fn call(d: &mut Device, auth: SessionAuthorization, f: &Frame) -> Vec<u8> {
    let response = d.execute_inner(auth, f);
    assert_eq!(
        response.command,
        f.command | 0x80,
        "command {:02x} failed: {:?}",
        f.command,
        response.data
    );
    response.data
}
fn frame(cmd: Cmd, data: Vec<u8>) -> Frame {
    Frame::new(cmd as u8, data).unwrap()
}
fn generate(a: A, id: u16) -> Frame {
    let caps = CapabilitySet::from_capabilities([
        C::SignPkcs,
        C::SignEcdsa,
        C::SignEddsa,
        C::DeriveEcdh,
        C::SignMlDsa,
        C::EncapsulateMlKem,
        C::DecapsulateMlKem,
        C::EncapsulateHybridKem,
        C::DecapsulateHybridKem,
    ]);
    let mut data = id.to_be_bytes().to_vec();
    data.extend_from_slice(b"disposable benchmark");
    data.resize(42, 0);
    data.extend_from_slice(&1u16.to_be_bytes());
    data.extend_from_slice(&caps.to_bytes());
    data.push(a as u8);
    frame(Cmd::GenerateAsymmetricKey, data)
}
fn public(d: &mut Device, auth: SessionAuthorization, id: u16) -> Vec<u8> {
    call(
        d,
        auth,
        &frame(Cmd::GetPublicKey, id.to_be_bytes().to_vec()),
    )[1..]
        .to_vec()
}
fn verify(d: &Device, a: A, data: &[u8], signature: &[u8]) {
    let object = d
        .object(ObjectKey {
            object_type: ObjectType::AsymmetricKey,
            id: 100,
        })
        .unwrap();
    let ObjectMaterial::SigningKey(key) = &object.material else {
        panic!("signing key")
    };
    let pk = key.public_key();
    match a {
        A::Rsa2048 | A::Rsa3072 | A::Rsa4096 => pk
            .verify_prehash(S::RsaPkcs1Sha256, data, signature)
            .unwrap(),
        A::EcP224
        | A::EcP256
        | A::EcP384
        | A::EcP521
        | A::EcK256
        | A::EcBrainpoolP256
        | A::EcBrainpoolP384
        | A::EcBrainpoolP512 => {
            let (scheme, n) = match a {
                A::EcP224 => (S::EcdsaP224Sha224, 28),
                A::EcP256 => (S::EcdsaP256Sha256, 32),
                A::EcP384 => (S::EcdsaP384Sha384, 48),
                A::EcP521 => (S::EcdsaP521Sha512, 66),
                A::EcK256 => (S::EcdsaSecp256k1Sha256, 32),
                A::EcBrainpoolP256 => (S::EcdsaBrainpoolP256Sha256, 32),
                A::EcBrainpoolP384 => (S::EcdsaBrainpoolP384Sha384, 48),
                A::EcBrainpoolP512 => (S::EcdsaBrainpoolP512Sha512, 64),
                _ => unreachable!(),
            };
            pk.verify_prehash(
                scheme,
                data,
                &ecdsa_signature_from_der(signature, n).unwrap(),
            )
            .unwrap();
        }
        A::Ed448 => pk.verify_message(S::Ed448, data, signature).unwrap(),
        A::Ed25519 => pk.verify_message(S::Ed25519, data, signature).unwrap(),
        _ => {
            let params = a.ml_dsa().unwrap();
            software_key_core::post_quantum::verify_ml_dsa(
                params,
                &match pk {
                    software_key_core::software_signing::SoftwarePublicKey::MlDsa {
                        public_key,
                        ..
                    } => public_key,
                    _ => unreachable!(),
                },
                data,
                b"",
                signature,
            )
            .unwrap();
        }
    }
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let a = match args[1].as_str() {
        "ML-KEM-768+P-256" => A::HybridMlKem768P256,
        "ML-KEM-768+X25519" => A::HybridMlKem768X25519,
        "ML-KEM-1024+P-384" => A::HybridMlKem1024P384,
        "RSA-2048" => A::Rsa2048,
        "RSA-3072" => A::Rsa3072,
        "RSA-4096" => A::Rsa4096,
        "P-224" => A::EcP224,
        "P-256" => A::EcP256,
        "P-521" => A::EcP521,
        "secp256k1" => A::EcK256,
        "Brainpool-P256" => A::EcBrainpoolP256,
        "Brainpool-P384" => A::EcBrainpoolP384,
        "Brainpool-P512" => A::EcBrainpoolP512,
        "Ed448" => A::Ed448,
        "X448" => A::X448,
        "P-384" => A::EcP384,
        "Ed25519" => A::Ed25519,
        "X25519" => A::X25519,
        "ML-DSA-44" => A::MlDsa44,
        "ML-DSA-65" => A::MlDsa65,
        "ML-DSA-87" => A::MlDsa87,
        "ML-KEM-512" => A::MlKem512,
        "ML-KEM-768" => A::MlKem768,
        "ML-KEM-1024" => A::MlKem1024,
        _ => panic!("unknown algorithm"),
    };
    assert!(virtual_yubihsm_core::FirmwareProfile::compiled().post_quantum());
    let op = &args[2];
    let n: usize = args[3].parse().unwrap();
    assert!(n > 0);
    let mut d = Device::factory_default(DeviceConfig::default());
    let auth = d.session_authorization(1).unwrap();
    let gen_frame = generate(a, 100);
    let before = live();
    call(&mut d, auth, &gen_frame);
    let retained = live().saturating_sub(before);
    let info = &d
        .object(ObjectKey {
            object_type: ObjectType::AsymmetricKey,
            id: 100,
        })
        .unwrap()
        .info;
    let key_bytes = info.length;
    let public_bytes = public(&mut d, auth, 100).len();
    let mut expected = Vec::new();
    let message = vec![
        42;
        match a {
            A::EcP224 => 28,
            A::EcP384 | A::EcBrainpoolP384 => 48,
            A::EcP521 | A::EcBrainpoolP512 => 64,
            _ => 32,
        }
    ];
    let encap = if a.hybrid_kem().is_some() {
        Cmd::EncapsulateHybridKem
    } else {
        Cmd::EncapsulateMlKem
    };
    let decap = if a.hybrid_kem().is_some() {
        Cmd::DecapsulateHybridKem
    } else {
        Cmd::DecapsulateMlKem
    };
    let request = match op.as_str() {
        "keygen" | "keypair" => gen_frame.clone(),
        "sign" => {
            let cmd = match a {
                A::Rsa2048 | A::Rsa3072 | A::Rsa4096 => Cmd::SignPkcs1,
                A::EcP224
                | A::EcP256
                | A::EcP384
                | A::EcP521
                | A::EcK256
                | A::EcBrainpoolP256
                | A::EcBrainpoolP384
                | A::EcBrainpoolP512 => Cmd::SignEcdsa,
                A::Ed25519 | A::Ed448 => Cmd::SignEddsa,
                _ => Cmd::SignMlDsa,
            };
            let mut data = 100u16.to_be_bytes().to_vec();
            if a.ml_dsa().is_some() {
                data.extend_from_slice(&[2, 0, 0]);
            }
            data.extend_from_slice(&message);
            frame(cmd, data)
        }
        "encapsulate" => frame(encap, 100u16.to_be_bytes().to_vec()),
        "decapsulate" => {
            let mut output = call(&mut d, auth, &frame(encap, 100u16.to_be_bytes().to_vec()));
            expected = output.split_off(output.len() - 32);
            let mut data = 100u16.to_be_bytes().to_vec();
            data.extend_from_slice(&output);
            frame(decap, data)
        }
        "derive" => {
            call(&mut d, auth, &generate(a, 101));
            let mut peer = public(&mut d, auth, 101);
            let mut own = public(&mut d, auth, 100);
            if !matches!(a, A::X25519 | A::X448) {
                peer.insert(0, 4);
                own.insert(0, 4);
            }
            let mut data = 101u16.to_be_bytes().to_vec();
            data.extend_from_slice(&own);
            expected = call(&mut d, auth, &frame(Cmd::DeriveEcdh, data));
            let mut data = 100u16.to_be_bytes().to_vec();
            data.extend_from_slice(&peer);
            frame(Cmd::DeriveEcdh, data)
        }
        _ => panic!("unknown operation"),
    };
    let delete = frame(
        Cmd::DeleteObject,
        vec![0, 100, ObjectType::AsymmetricKey as u8],
    );
    let public_frame = frame(Cmd::GetPublicKey, 100u16.to_be_bytes().to_vec());
    if op != "keygen" && op != "keypair" {
        let result = call(&mut d, auth, &request);
        if op == "encapsulate" {
            let (ct, secret) = result.split_at(result.len() - 32);
            let mut data = 100u16.to_be_bytes().to_vec();
            data.extend_from_slice(ct);
            assert_eq!(call(&mut d, auth, &frame(decap, data)), secret);
        }
        if op == "sign" {
            verify(&d, a, &message, &result);
        }
        if !expected.is_empty() {
            assert_eq!(result, expected);
        }
        for _ in 0..10 {
            black_box(call(&mut d, auth, &request));
        }
    }
    let mut timings = Vec::with_capacity(n);
    let mut max_extra = 0;
    let mut output_bytes = 0;
    for _ in 0..n {
        if op == "keygen" || op == "keypair" {
            call(&mut d, auth, &delete);
        }
        let base = live();
        reset_peak();
        let started = Instant::now();
        let response = call(&mut d, auth, &request);
        let response = black_box(if op == "keypair" {
            drop(response);
            call(&mut d, auth, &public_frame)
        } else {
            response
        });
        let elapsed = started.elapsed().as_nanos() as u64;
        max_extra = max_extra.max(peak().saturating_sub(base));
        output_bytes = response.len();
        drop(response);
        timings.push(elapsed);
    }
    timings.sort_unstable();
    println!(
        "{{\"median_us\":{},\"mean_us\":{},\"p95_us\":{},\"samples\":{},\"peak_extra_rust_heap_bytes\":{},\"retained_key_rust_heap_bytes\":{},\"native_key_bytes\":{},\"native_key_pages\":{},\"public_bytes\":{},\"response_bytes\":{}}}",
        timings[n / 2] as f64 / 1000.,
        timings.iter().map(|x| *x as f64).sum::<f64>() / n as f64 / 1000.,
        timings[(n * 95 / 100).min(n - 1)] as f64 / 1000.,
        n,
        max_extra,
        retained,
        key_bytes,
        usize::from(key_bytes).div_ceil(126),
        public_bytes,
        output_bytes
    );
}
