use std::{env, fs, path::PathBuf, process};

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
    if args.next().as_deref() != Some("bindings") {
        eprintln!("usage: cargo xtask bindings [--check]");
        process::exit(2);
    }
    let check = match args.next().as_deref() {
        None => false,
        Some("--check") => true,
        Some(_) => {
            eprintln!("usage: cargo xtask bindings [--check]");
            process::exit(2);
        }
    };
    if args.next().is_some() {
        eprintln!("usage: cargo xtask bindings [--check]");
        process::exit(2);
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
