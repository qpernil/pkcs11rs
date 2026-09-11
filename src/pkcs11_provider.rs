//! Instance selection for the Rust handlers behind the PKCS #11 entry points.
//! A prepared provider has its own session routing and either a private slot or
//! a shared existing slot. Preparation never rediscovers or copies credentials. Selection is scoped to a synchronous call, including unwinding.
use crate::*;
use std::cell::RefCell;

thread_local! {
    static SELECTED: RefCell<Option<Arc<Option<ModuleContext>>>> = const { RefCell::new(None) };
}

pub(crate) enum ContextRead {
    Global(std::sync::RwLockReadGuard<'static, Option<ModuleContext>>),
    Private(Arc<Option<ModuleContext>>),
}
impl std::ops::Deref for ContextRead {
    type Target = Option<ModuleContext>;
    fn deref(&self) -> &Self::Target {
        match self {
            Self::Global(value) => value,
            Self::Private(value) => value,
        }
    }
}
pub(crate) fn selected_context() -> Option<Arc<Option<ModuleContext>>> {
    SELECTED.with(|selected| selected.borrow().clone())
}

pub(crate) struct Pkcs11Provider {
    context: Arc<Option<ModuleContext>>,
    quiet: tracing::Dispatch,
    automatic_software_login: bool,
}
impl Pkcs11Provider {
    pub(crate) fn private_software() -> Result<Arc<Self>, Error> {
        let slot =
            SoftwareSlot::new_with_storage("private authentication".to_owned(), 0, None, None)?;
        let mut provider = Self::new(Box::new(slot))?;
        Arc::get_mut(&mut provider)
            .ok_or(CKR_FUNCTION_FAILED)?
            .automatic_software_login = true;
        Ok(provider)
    }

    /// An isolated instance containing the supplied slot. Its native backend
    /// and credentials need not be software; ordinary slot login applies.
    pub(crate) fn new(slot: Box<dyn Slot>) -> Result<Arc<Self>, Error> {
        let quiet = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let context =
            tracing::dispatcher::with_default(&quiet, || ModuleContext::private_slot(slot))?;
        Ok(Arc::new(Self {
            context: Arc::new(Some(context)),
            quiet,
            automatic_software_login: false,
        }))
    }

    /// Prepare an existing slot without cloning its backend or credentials.
    /// The caller selects the slot and supplies login separately if necessary.
    #[allow(dead_code)] // Exercised by integration tests; configured selection is separate.
    pub(crate) fn from_slot(slot: Arc<Mutex<SlotContext>>) -> Result<Arc<Self>, Error> {
        let quiet = tracing::Dispatch::new(tracing::subscriber::NoSubscriber::default());
        let context =
            tracing::dispatcher::with_default(&quiet, || ModuleContext::for_auth_slot(slot))?;
        Ok(Arc::new(Self {
            context: Arc::new(Some(context)),
            quiet,
            automatic_software_login: false,
        }))
    }

    pub(crate) fn call<T>(&self, operation: impl FnOnce() -> T) -> T {
        struct Restore(Option<Arc<Option<ModuleContext>>>);
        impl Drop for Restore {
            fn drop(&mut self) {
                SELECTED.with(|selected| {
                    *selected.borrow_mut() = self.0.take();
                });
            }
        }
        let _restore =
            Restore(SELECTED.with(|selected| selected.replace(Some(self.context.clone()))));
        tracing::dispatcher::with_default(&self.quiet, operation)
    }
}

#[cfg(test)]
pub(crate) fn check(rv: CK_RV) -> Result<(), Error> {
    if rv == CKR_OK as CK_RV {
        Ok(())
    } else {
        Err(Error::from(rv))
    }
}

pub(crate) struct ProviderSession {
    pub(crate) provider: Arc<Pkcs11Provider>,
    pub(crate) handle: CK_SESSION_HANDLE,
}
impl ProviderSession {
    pub(crate) fn open(provider: Arc<Pkcs11Provider>) -> Result<Arc<Self>, Error> {
        let slots = provider.call(|| api::rust::get_slot_list(true))?;
        let [slot] = slots.as_slice() else {
            return Err(CKR_DEVICE_ERROR.into());
        };
        let handle = provider
            .call(|| api::rust::open_session(*slot, (CKF_RW_SESSION | CKF_SERIAL_SESSION) as _))?;
        let session = Arc::new(Self { provider, handle });
        if session.provider.automatic_software_login {
            // This ephemeral, nonpersistent token has no configured credential.
            // Supply a fresh random PIN solely to establish its PKCS #11 login state.
            let mut pin = Zeroizing::new([0u8; 32]);
            getrandom::fill(pin.as_mut()).map_err(|_| Error::from(CKR_RANDOM_NO_RNG))?;
            for byte in pin.iter_mut() {
                *byte = b'a' + (*byte & 15);
            }
            match session.login(&pin[..]) {
                Ok(()) => {}
                Err(Error::Generic(rv)) if rv == CKR_USER_ALREADY_LOGGED_IN as CK_RV => {}
                Err(error) => return Err(error),
            }
        }
        Ok(session)
    }
    /// Authorize only a selected source. Never resubmit a PIN to an already
    /// authorized token, and never cache it for later provider login.
    pub(crate) fn authorization_required(&self) -> Result<bool, Error> {
        let mut session: CK_SESSION_INFO = unsafe { std::mem::zeroed() };
        self.call(|| api::rust::get_session_info(self.handle, &mut session))?;
        if matches!(session.state, x if x == CKS_RO_USER_FUNCTIONS as CK_STATE || x == CKS_RW_USER_FUNCTIONS as CK_STATE)
        {
            return Ok(false);
        }
        let mut token: CK_TOKEN_INFO = unsafe { std::mem::zeroed() };
        self.call(|| api::rust::get_token_info(session.slotID, &mut token))?;
        Ok(token.flags & CKF_LOGIN_REQUIRED as CK_FLAGS != 0)
    }
    pub(crate) fn authorize(&self, pin: &[u8]) -> Result<(), Error> {
        if !self.authorization_required()? {
            return Ok(());
        }
        match self.login(pin) {
            Err(Error::Generic(rv)) if rv == CKR_USER_ALREADY_LOGGED_IN as CK_RV => Ok(()),
            result => result,
        }
    }
    pub(crate) fn login(&self, pin: &[u8]) -> Result<(), Error> {
        self.call(|| api::rust::login(self.handle, CKU_USER as _, pin.as_ptr(), pin.len() as _))
    }
    pub(crate) fn call<T>(&self, operation: impl FnOnce() -> T) -> T {
        self.provider.call(operation)
    }
}
impl Drop for ProviderSession {
    fn drop(&mut self) {
        let _ = self.call(|| api::rust::close_session(self.handle));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_instance_is_reentrant_and_hidden_from_the_public_module() {
        let _serial = crate::test::TEST_LOCK.lock().unwrap();
        // Authentication is also used during discovery/finalization. None of
        // its PKCS #11 calls may depend on acquiring this global module lock.
        let global = crate::lock_context().unwrap();
        let before = global
            .as_ref()
            .map(|module| module.slot_contexts.read().unwrap().len());
        let mut scope = crate::key_scope::Pkcs11KeyScope::new().unwrap();
        let key = scope
            .import_secret(
                &[42; 32],
                crate::key_scope::generic_template(&[CKM_EXTRACT_KEY_FROM_KEY as _]),
            )
            .unwrap();
        scope.require_generic_length(&key, 32).unwrap();
        assert!(selected_context().is_none());
        let mut info = CK_SESSION_INFO {
            slotID: 0,
            state: 0,
            flags: 0,
            ulDeviceError: 0,
        };
        assert_eq!(
            api::C_GetSessionInfo(scope.session.handle, &mut info),
            CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV
        );
        assert_eq!(
            global
                .as_ref()
                .map(|module| module.slot_contexts.read().unwrap().len()),
            before
        );
        let context = Arc::downgrade(&scope.session.provider.context);
        drop(scope);
        assert!(context.upgrade().is_none());
    }

    #[test]
    fn instance_selection_is_thread_local_nested_and_restored_after_unwind() {
        let first = Pkcs11Provider::private_software().unwrap();
        let second = Pkcs11Provider::private_software().unwrap();
        assert!(selected_context().is_none());
        first.call(|| {
            assert!(Arc::ptr_eq(&selected_context().unwrap(), &first.context));
            std::thread::spawn(|| assert!(selected_context().is_none()))
                .join()
                .unwrap();
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                second.call(|| {
                    assert!(Arc::ptr_eq(&selected_context().unwrap(), &second.context));
                    panic!("exercise selection cleanup");
                });
            }));
            assert!(result.is_err());
            assert!(Arc::ptr_eq(&selected_context().unwrap(), &first.context));
        });
        assert!(selected_context().is_none());
    }

    #[test]
    fn closing_a_session_destroys_objects_without_individual_destroy_calls() {
        let provider = Pkcs11Provider::private_software().unwrap();
        let first = ProviderSession::open(provider.clone()).unwrap();
        let observer = ProviderSession::open(provider).unwrap();
        let mut class = CKO_DATA as CK_OBJECT_CLASS;
        let mut attr = CK_ATTRIBUTE {
            type_: CKA_CLASS as _,
            pValue: (&mut class as *mut CK_OBJECT_CLASS).cast(),
            ulValueLen: std::mem::size_of_val(&class) as _,
        };
        let mut object = 0;
        check(first.call(|| api::C_CreateObject(first.handle, &mut attr, 1, &mut object))).unwrap();
        drop(first); // The shared close handler performs creator-session cleanup.
        assert_eq!(
            observer.call(|| api::C_GetAttributeValue(observer.handle, object, &mut attr, 1)),
            CKR_OBJECT_HANDLE_INVALID as CK_RV
        );
    }
}
