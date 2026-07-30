use libloading::{Library, Symbol};
use pkcs11rs as _;
use std::{
    ffi::{c_ulong, c_void, OsString},
    path::PathBuf,
};

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
        let configured = std::env::vars_os()
            .filter(|(name, _)| {
                name.to_string_lossy()
                    .to_ascii_uppercase()
                    .starts_with("PKCS11RS_")
            })
            .collect::<Vec<_>>();
        for (name, _) in &configured {
            std::env::remove_var(name);
        }
        std::env::set_var("PKCS11RS_HARDWARE_DISCOVERY", "0");
        Self(configured)
    }
}

impl Drop for EnvironmentGuard {
    fn drop(&mut self) {
        std::env::remove_var("PKCS11RS_HARDWARE_DISCOVERY");
        for (name, value) in self.0.drain(..) {
            std::env::set_var(name, value);
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

fn built_library_path() -> PathBuf {
    let test_executable = std::env::current_exe().expect("resolve the integration-test executable");
    let deps = test_executable
        .parent()
        .expect("integration-test executable has a parent directory");
    let profile = deps
        .parent()
        .expect("integration-test dependency directory has a parent");
    let candidates = [
        profile.join(library_filename()),
        deps.join(library_filename()),
    ];
    candidates
        .into_iter()
        .find(|candidate| candidate.is_file())
        .unwrap_or_else(|| {
            panic!(
                "Cargo did not build {} beside the integration test",
                library_filename()
            )
        })
}

#[test]
fn loads_initializes_queries_and_finalizes_the_shared_library() {
    let _environment = EnvironmentGuard::isolated_pkcs11rs_configuration();
    let path = built_library_path();
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
