fn main() {
    println!("cargo::rustc-check-cfg=cfg(embedded_virtual_yubihsm)");
    if [
        "CARGO_FEATURE_FIRMWARE_YUBIHSM2",
        "CARGO_FEATURE_FIRMWARE_SECURE_CHANNEL",
        "CARGO_FEATURE_FIRMWARE_FULL",
        "CARGO_FEATURE_TEST_FIRMWARE_PREFIXED_ECDH",
        "CARGO_FEATURE_TEST_FIRMWARE_SESSION_OBJECTS",
    ]
    .iter()
    .any(|name| std::env::var_os(name).is_some())
    {
        println!("cargo::rustc-cfg=embedded_virtual_yubihsm");
    }
}
