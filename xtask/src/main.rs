use libloading::{Library, Symbol};
use std::{
    env,
    ffi::{c_ulong, c_void, OsString},
    fs,
    path::{Path, PathBuf},
    process,
};

const WRAPPER: &str = r#"#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
"#;

fn main() {
    let mut args = env::args().skip(1);
    let command = args.next();
    let args = args.collect::<Vec<_>>();
    match command.as_deref() {
        Some("bindings") => bindings(&args),
        Some("load-shared-library") => load_shared_library(&args),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: cargo xtask bindings [--check]\n       cargo xtask load-shared-library [--release]"
    );
    process::exit(2);
}

fn bindings(args: &[String]) {
    let mut args = args.iter().map(String::as_str);
    let check = match args.next() {
        None => false,
        Some("--check") => true,
        Some(_) => usage(),
    };
    if args.next().is_some() {
        usage();
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask directory has a parent")
        .to_path_buf();
    let bindings_path = root.join("src/pkcs11.rs");
    let bindings = bindgen::Builder::default()
        .header_contents("pkcs11_bindgen.h", WRAPPER)
        .clang_arg(format!("-I{}", root.display()))
        .layout_tests(false)
        .generate()
        .expect("generate PKCS #11 bindings")
        .to_string();

    if check {
        let current = fs::read_to_string(&bindings_path).unwrap_or_default();
        if current != bindings {
            eprintln!(
                "{} is stale; run `cargo xtask bindings`",
                bindings_path.display()
            );
            process::exit(1);
        }
    } else {
        fs::write(&bindings_path, bindings).expect("write generated PKCS #11 bindings");
    }
}

type CkRv = c_ulong;
type CkSlotId = c_ulong;
type CkUlong = c_ulong;
type CkBbool = u8;

type CInitialize = unsafe extern "C" fn(*mut c_void) -> CkRv;
type CGetFunctionList = unsafe extern "C" fn(*mut *mut c_void) -> CkRv;
type CGetSlotList = unsafe extern "C" fn(CkBbool, *mut CkSlotId, *mut CkUlong) -> CkRv;
type CFinalize = unsafe extern "C" fn(*mut c_void) -> CkRv;

const CKR_OK: CkRv = 0;

struct EnvironmentGuard(Vec<(OsString, OsString)>);

impl EnvironmentGuard {
    fn isolated_pkcs11rs_configuration() -> Self {
        let configured = env::vars_os()
            .filter(|(name, _)| {
                name.to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("PKCS11RS_")
            })
            .collect::<Vec<_>>();
        for (name, _) in &configured {
            env::remove_var(name);
        }
        env::set_var("PKCS11RS_HARDWARE_DISCOVERY", "0");
        Self(configured)
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        env::remove_var("PKCS11RS_HARDWARE_DISCOVERY");
        for (name, value) in self.0.drain(..) {
            env::set_var(name, value);
        }
    }
}

fn library_filename() -> &'static str {
    if cfg!(target_os = "windows") {
        "pkcs11rs.dll"
    } else if cfg!(target_os = "macos") {
        "libpkcs11rs.dylib"
    } else {
        "libpkcs11rs.so"
    }
}

fn target_directory(root: &Path) -> PathBuf {
    env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"))
}

fn load_shared_library(args: &[String]) {
    let release = match args {
        [] => false,
        [argument] if argument == "--release" => true,
        _ => usage(),
    };
    let manifest_directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_directory
        .parent()
        .expect("xtask directory has a parent");
    let profile = if release { "release" } else { "debug" };
    let path = target_directory(root)
        .join(profile)
        .join(library_filename());
    assert!(
        path.is_file(),
        "{} is missing; run `cargo build --locked{}` first",
        path.display(),
        if release { " --release" } else { "" }
    );

    let _environment = EnvironmentGuard::isolated_pkcs11rs_configuration();
    let library = unsafe { Library::new(&path) }
        .unwrap_or_else(|error| panic!("load {}: {error}", path.display()));
    let initialize: Symbol<CInitialize> =
        unsafe { library.get(b"C_Initialize\0") }.expect("resolve C_Initialize");
    let get_function_list: Symbol<CGetFunctionList> =
        unsafe { library.get(b"C_GetFunctionList\0") }.expect("resolve C_GetFunctionList");
    let get_slot_list: Symbol<CGetSlotList> =
        unsafe { library.get(b"C_GetSlotList\0") }.expect("resolve C_GetSlotList");
    let finalize: Symbol<CFinalize> =
        unsafe { library.get(b"C_Finalize\0") }.expect("resolve C_Finalize");

    let mut function_list = std::ptr::null_mut();
    let function_list_result = unsafe { get_function_list(&mut function_list) };
    let initialize_result = unsafe { initialize(std::ptr::null_mut()) };
    let mut slot_count = 0;
    let slot_list_result = if initialize_result == CKR_OK {
        unsafe { get_slot_list(0, std::ptr::null_mut(), &mut slot_count) }
    } else {
        initialize_result
    };
    let finalize_result = unsafe { finalize(std::ptr::null_mut()) };

    assert_eq!(function_list_result, CKR_OK, "C_GetFunctionList");
    assert!(!function_list.is_null(), "C_GetFunctionList returned null");
    assert_eq!(initialize_result, CKR_OK, "C_Initialize");
    assert_eq!(slot_list_result, CKR_OK, "C_GetSlotList");
    assert_eq!(finalize_result, CKR_OK, "C_Finalize");
}
