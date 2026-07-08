use std::{env, fs, path::PathBuf};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let wrapper_path = out_dir.join("pkcs11_bindgen.h");
    let bindings_path = out_dir.join("pkcs11.rs");

    println!("cargo:rerun-if-changed=pkcs11.h");
    println!("cargo:rerun-if-changed=pkcs11f.h");
    println!("cargo:rerun-if-changed=pkcs11t.h");

    fs::write(
        &wrapper_path,
        r#"#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11.h"
"#,
    )
    .unwrap();

    let bindings = bindgen::Builder::default()
        .header(wrapper_path.to_string_lossy())
        .clang_arg(format!("-I{}", manifest_dir.display()))
        .layout_tests(false)
        .generate()
        .expect("generate PKCS#11 bindings");

    bindings
        .write_to_file(bindings_path)
        .expect("write PKCS#11 bindings");
}
