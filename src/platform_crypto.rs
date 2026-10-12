pub(crate) use platform_credential::{
    EcdhCredential, PLATFORM_CREDENTIAL_NAME_CAPACITY, PlatformAuthenticationCredential,
    PlatformCredentialAlgorithm, PlatformCryptoError, resolve_platform_credential,
    validate_platform_credential_name,
};

#[cfg(not(test))]
pub(crate) use platform_credential::{
    delete_platform_credential, generate_platform_credential, list_platform_credentials,
    platform_credential_public_key,
};

// Unit tests can exercise the exported lifecycle against an isolated store.
// The override is thread-local, scoped, and absent from module builds.
#[cfg(test)]
thread_local! {
    static TEST_STORE: std::cell::RefCell<Option<std::sync::Arc<dyn platform_credential::AuthenticationCredentialStore>>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) fn with_test_credential_store<T>(
    store: std::sync::Arc<dyn platform_credential::AuthenticationCredentialStore>,
    run: impl FnOnce() -> T,
) -> T {
    struct Restore(Option<std::sync::Arc<dyn platform_credential::AuthenticationCredentialStore>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            TEST_STORE.with(|store| *store.borrow_mut() = self.0.take());
        }
    }
    let _restore = Restore(TEST_STORE.with(|current| current.replace(Some(store))));
    run()
}

#[cfg(test)]
macro_rules! store_operation {
    ($name:ident, $operation:ident, ($($argument:ident: $type:ty),*), $output:ty) => {
        pub(crate) fn $name($($argument: $type),*) -> Result<$output, PlatformCryptoError> {
            TEST_STORE.with(|store| match store.borrow().as_ref() {
                Some(store) => store.$operation($($argument),*),
                None => platform_credential::$name($($argument),*),
            })
        }
    };
}

#[cfg(test)]
store_operation!(generate_platform_credential, generate, (name: &str), crate::SoftwarePublicKey);
#[cfg(test)]
store_operation!(platform_credential_public_key, public_key, (name: &str), crate::SoftwarePublicKey);
#[cfg(test)]
store_operation!(
    list_platform_credentials,
    list,
    (),
    Vec<platform_credential::PlatformCredentialInfo>
);
#[cfg(test)]
store_operation!(delete_platform_credential, delete, (name: &str), ());
