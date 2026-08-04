use libloading::{Library, Symbol};
use std::{
    env,
    ffi::{c_ulong, c_void, OsString},
    fs,
    path::{Path, PathBuf},
    process::{self, Command},
};

const IOS_DEVICE_TARGET: &str = "aarch64-apple-ios";
const IOS_SIMULATOR_TARGET: &str = "aarch64-apple-ios-sim";
const IOS_DEFAULT_DEPLOYMENT_TARGET: &str = "18.0";
const IOS_LIBRARY_NAME: &str = "libpkcs11rs.a";
const IOS_HEADERS: [&str; 4] = ["pkcs11.h", "pkcs11f.h", "pkcs11t.h", "pkcs11rs.h"];
const IOS_UMBRELLA_HEADER_NAME: &str = "pkcs11rs_ios.h";
const IOS_UMBRELLA_HEADER: &str = r#"#ifndef PKCS11RS_IOS_H
#define PKCS11RS_IOS_H 1

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11rs.h"

#endif
"#;
const IOS_MODULE_MAP: &str = r#"module PKCS11RS {
    header "pkcs11rs_ios.h"
    export *
}
"#;

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
        Some("ios") => ios(&args),
        Some("load-shared-library") => load_shared_library(&args),
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!(
        "usage: cargo xtask bindings [--check]\n       cargo xtask ios [--release] [--output PATH]\n       cargo xtask load-shared-library [--release]"
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

fn ios(args: &[String]) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask directory has a parent")
        .to_path_buf();
    let mut release = false;
    let mut output = target_directory(&root)
        .join("ios")
        .join("PKCS11RS.xcframework");
    let mut arguments = args.iter();

    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--release" => release = true,
            "--output" => {
                let path = arguments.next().unwrap_or_else(|| usage());
                output = absolute_path(&root, Path::new(path));
            }
            "--help" | "-h" => {
                println!("usage: cargo xtask ios [--release] [--output PATH]");
                return;
            }
            _ => usage(),
        }
    }

    let cargo = env::var_os("CARGO").unwrap_or_else(|| OsString::from("cargo"));
    let deployment_target = env::var_os("IPHONEOS_DEPLOYMENT_TARGET")
        .unwrap_or_else(|| OsString::from(IOS_DEFAULT_DEPLOYMENT_TARGET));
    build_ios_slice(
        &cargo,
        &root,
        IOS_DEVICE_TARGET,
        release,
        &deployment_target,
    );
    build_ios_slice(
        &cargo,
        &root,
        IOS_SIMULATOR_TARGET,
        release,
        &deployment_target,
    );

    let profile = if release { "release" } else { "debug" };
    let target = target_directory(&root);
    let device_library = target
        .join(IOS_DEVICE_TARGET)
        .join(profile)
        .join(IOS_LIBRARY_NAME);
    let simulator_library = target
        .join(IOS_SIMULATOR_TARGET)
        .join(profile)
        .join(IOS_LIBRARY_NAME);
    let headers = stage_ios_headers(&root);

    if output.is_dir() {
        fs::remove_dir_all(&output)
            .unwrap_or_else(|error| panic!("replace {}: {error}", output.display()));
    } else if output.exists() {
        fs::remove_file(&output)
            .unwrap_or_else(|error| panic!("replace {}: {error}", output.display()));
    }
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("create {}: {error}", parent.display()));
    }

    run_command(
        Command::new("xcodebuild")
            .current_dir(&root)
            .arg("-create-xcframework")
            .arg("-library")
            .arg(device_library)
            .arg("-headers")
            .arg(&headers)
            .arg("-library")
            .arg(simulator_library)
            .arg("-headers")
            .arg(&headers)
            .arg("-output")
            .arg(&output),
    );

    println!("created {}", output.display());
}

fn build_ios_slice(
    cargo: &OsString,
    root: &Path,
    target: &str,
    release: bool,
    deployment_target: &OsString,
) {
    let mut command = Command::new(cargo);
    command
        .current_dir(root)
        .env("IPHONEOS_DEPLOYMENT_TARGET", deployment_target)
        .arg("build")
        .arg("--locked")
        .arg("--package")
        .arg("pkcs11rs")
        .arg("--lib")
        .arg("--no-default-features")
        .arg("--target")
        .arg(target);
    if release {
        command.arg("--release");
    }
    run_command(&mut command);
}

fn stage_ios_headers(root: &Path) -> PathBuf {
    let destination = target_directory(root).join("ios").join("include");
    if destination.exists() {
        fs::remove_dir_all(&destination)
            .unwrap_or_else(|error| panic!("replace {}: {error}", destination.display()));
    }
    fs::create_dir_all(&destination)
        .unwrap_or_else(|error| panic!("create {}: {error}", destination.display()));
    for name in IOS_HEADERS {
        fs::copy(root.join(name), destination.join(name))
            .unwrap_or_else(|error| panic!("stage {name}: {error}"));
    }
    fs::write(
        destination.join(IOS_UMBRELLA_HEADER_NAME),
        IOS_UMBRELLA_HEADER,
    )
    .expect("write iOS umbrella header");
    fs::write(destination.join("module.modulemap"), IOS_MODULE_MAP)
        .expect("write iOS Clang module map");
    destination
}

fn run_command(command: &mut Command) {
    eprintln!("running {command:?}");
    let status = command
        .status()
        .unwrap_or_else(|error| panic!("start {command:?}: {error}"));
    assert!(status.success(), "{command:?} exited with {status}");
}

fn absolute_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        root.join(path)
    }
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
