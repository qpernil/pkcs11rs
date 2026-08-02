use zeroize::Zeroizing;

pub(crate) fn request(description: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let program = std::env::var_os("PKCS11RS_PINENTRY")
        .filter(|program| !program.is_empty())
        .ok_or_else(|| "PKCS11RS_PINENTRY is required to unlock the private key".to_owned())?;
    crate::pinentry_client::request(
        &program,
        crate::pinentry_client::Prompt {
            title: "pkcs11rs-tool private key",
            description,
            label: "Password:",
        },
        std::env::var_os("GPG_TTY"),
    )
    .map_err(|error| error.to_string())
}
