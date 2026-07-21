struct Context {
    libusb: Option<rusb::Context>,
    pcsc: Option<Rc<pcsc::Context>>,
    slots: HashMap<CK_SLOT_ID, Box<dyn Slot>>,
    dynamic_slots: HashSet<CK_SLOT_ID>,
    slots_discovered: bool,
    sessions: HashMap<CK_SESSION_HANDLE, Box<dyn Session>>,
    logged_in_slots: HashMap<CK_SLOT_ID, LoginRole>,
    objects: HashMap<CK_OBJECT_HANDLE, TokenObject>,
    next_object_handle: CK_OBJECT_HANDLE,
    find_operations: HashMap<CK_SESSION_HANDLE, FindOperation>,
    encrypt_operations: HashMap<CK_SESSION_HANDLE, CryptOperation>,
    decrypt_operations: HashMap<CK_SESSION_HANDLE, CryptOperation>,
    sign_operations: HashMap<CK_SESSION_HANDLE, SignatureOperation>,
    verify_operations: HashMap<CK_SESSION_HANDLE, SignatureOperation>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LoginRole {
    User,
    So,
}


impl std::fmt::Debug for Context {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        fmt.debug_struct("Context")
            .field("libusb", &self.libusb)
            .field("pcsc", &self.pcsc.as_ref().map(|_| "Context { .. }"))
            .field("slots", &self.slots)
            .field("sessions", &self.sessions)
            .field("objects", &self.objects)
            .field("find_operations", &self.find_operations)
            .field("encrypt_operations", &self.encrypt_operations)
            .field("decrypt_operations", &self.decrypt_operations)
            .field("sign_operations", &self.sign_operations)
            .field("verify_operations", &self.verify_operations)
            .finish()
    }
}

impl Context {
    #[allow(unused_mut)]
    fn new() -> Result<Context, Error> {
        #[cfg(feature = "abi-tests")]
        let slots = HashMap::from([
            (ABI_TEST_SLOT_ID, Box::new(AbiTestSlot) as Box<dyn Slot>),
            (
                ABI_TEST_PIV_SLOT_ID,
                Box::new(abi_test_piv_slot()?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP03_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP03")?) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_YUBIHSM_SLOT_ID,
                Box::new(AbiYubiHsmSlot) as Box<dyn Slot>,
            ),
            (
                ABI_TEST_SCP11_SLOT_ID,
                Box::new(AbiScp03Slot::new("SCP11")?) as Box<dyn Slot>,
            ),
        ]);
        #[cfg(not(feature = "abi-tests"))]
        let slots = HashMap::new();

        let objects = default_objects()?;
        let next_object_handle = objects.keys().max().map(|handle| handle + 1).unwrap_or(1);
        let mut context = Context {
            #[cfg(feature = "abi-tests")]
            libusb: None,
            #[cfg(not(feature = "abi-tests"))]
            libusb: match rusb::Context::new() {
                Ok(context) => Some(context),
                Err(e) => {
                    log!(1, "libusb::Context::new: {}", e);
                    None
                }
            },
            #[cfg(feature = "abi-tests")]
            pcsc: None,
            #[cfg(not(feature = "abi-tests"))]
            pcsc: match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => Some(Rc::new(context)),
                Err(e) => {
                    log!(1, "pcsc::Context::establish: {}", e);
                    None
                }
            },
            slots,
            dynamic_slots: HashSet::new(),
            slots_discovered: false,
            sessions: HashMap::new(),
            logged_in_slots: HashMap::new(),
            objects,
            next_object_handle,
            find_operations: HashMap::new(),
            encrypt_operations: HashMap::new(),
            decrypt_operations: HashMap::new(),
            sign_operations: HashMap::new(),
            verify_operations: HashMap::new(),
        };
        #[cfg(all(feature = "abi-tests", not(test)))]
        add_abi_test_backend_objects(&mut context)?;
        log!(2, "Context.new {:?}", context);
        Ok(context)
    }
    fn get_info(&self, info: &mut CK_INFO) -> Result<(), Error> {
        info.cryptokiVersion.major = 3;
        info.cryptokiVersion.minor = 2;
        info.libraryVersion.major = 1;
        info.libraryVersion.minor = 0;
        info.flags = 0;
        str_pad(
            "YubiHSM & YubiKey PKCS#11 module",
            &mut info.libraryDescription,
        );
        str_pad("Yubico", &mut info.manufacturerID);
        Ok(())
    }
    fn get_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        match self.slots.get(&slot_id) {
            Some(slot) => Ok(slot.as_ref()),
            None => Err(CKR_SLOT_ID_INVALID.into()),
        }
    }
    fn get_present_slot(&self, slot_id: CK_SLOT_ID) -> Result<&(dyn Slot + '_), Error> {
        let slot = self.get_slot(slot_id)?;
        if slot.is_present() {
            Ok(slot)
        } else {
            Err(CKR_TOKEN_NOT_PRESENT.into())
        }
    }
    fn _get_slot_mut(&mut self, slot_id: CK_SLOT_ID) -> Result<&mut (dyn Slot + '_), Error> {
        match self.slots.get_mut(&slot_id) {
            Some(slot) => Ok(slot.as_mut()),
            None => Err(CKR_SLOT_ID_INVALID.into()),
        }
    }
    fn get_session_(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Option<(&(dyn Slot + '_), &(dyn Session + '_))> {
        let session = self.sessions.get(&session_handle)?;
        let slot = self.slots.get(&session.slotID())?;
        Some((slot.as_ref(), session.as_ref()))
    }
    fn _get_session(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(&(dyn Slot + '_), &(dyn Session + '_)), Error> {
        match self.get_session_(session_handle) {
            Some(ctx) => Ok(ctx),
            None => Err(CKR_SESSION_HANDLE_INVALID.into()),
        }
    }
    fn session_details(
        &self,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(CK_SLOT_ID, CK_FLAGS, bool), Error> {
        let session = self._get_session(session_handle)?.1;
        let slot_id = session.slotID();
        Ok((
            slot_id,
            session.flags(),
            self.login_role(slot_id) == Some(LoginRole::User),
        ))
    }

    fn login_role(&self, slot_id: CK_SLOT_ID) -> Option<LoginRole> {
        self.logged_in_slots.get(&slot_id).copied().filter(|_| {
            self.slots
                .get(&slot_id)
                .is_some_and(|slot| slot.login_is_active())
        })
    }

    fn is_slot_logged_in(&self, slot_id: CK_SLOT_ID) -> bool {
        self.login_role(slot_id).is_some()
    }

    fn is_slot_user_logged_in(&self, slot_id: CK_SLOT_ID) -> bool {
        self.login_role(slot_id) == Some(LoginRole::User)
    }

    fn reconcile_login_state(&mut self, slot_id: CK_SLOT_ID) {
        if self.logged_in_slots.contains_key(&slot_id) && !self.is_slot_logged_in(slot_id) {
            self.clear_login_state(slot_id);
        }
    }

    fn insert_object(&mut self, mut object: TokenObject) -> CK_OBJECT_HANDLE {
        let handle = self.next_object_handle;
        self.next_object_handle += 1;
        if object.unique_id.is_empty() {
            object.unique_id = handle.to_string().into_bytes();
        }
        self.objects.insert(handle, object);
        handle
    }

    fn refresh_slot_token_objects(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        let objects = self
            .slots
            .get(&slot_id)
            .ok_or(CKR_SLOT_ID_INVALID)?
            .token_objects(slot_id)?;
        self.objects
            .retain(|_, object| object.slot_id != Some(slot_id) || !object.token);
        for object in objects.into_iter().filter(|object| object.token) {
            self.insert_object(object);
        }
        Ok(())
    }

    fn insert_session_objects(
        &mut self,
        slot_id: CK_SLOT_ID,
        session_handle: CK_SESSION_HANDLE,
    ) -> Result<(), Error> {
        let objects = self
            .slots
            .get(&slot_id)
            .ok_or(CKR_SLOT_ID_INVALID)?
            .session_objects(slot_id)?;
        for mut object in objects.into_iter().filter(|object| !object.token) {
            if self.objects.values().any(|existing| {
                existing.owner_session == Some(session_handle)
                    && existing.slot_id == Some(slot_id)
                    && existing.unique_id == object.unique_id
            }) {
                continue;
            }
            object.set_owner(session_handle, slot_id);
            self.insert_object(object);
        }
        Ok(())
    }

    fn clear_login_state(&mut self, slot_id: CK_SLOT_ID) {
        self.logged_in_slots.remove(&slot_id);
        let slot_sessions: HashSet<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter(|(_handle, session)| session.slotID() == slot_id)
            .map(|(handle, _session)| *handle)
            .collect();
        self.find_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.encrypt_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.decrypt_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.sign_operations
            .retain(|session, _operation| !slot_sessions.contains(session));
        self.verify_operations
            .retain(|session, _operation| !slot_sessions.contains(session));

        self.objects
            .retain(|_, object| object.slot_id != Some(slot_id) || object.token || !object.private);
        let private_token_handles: Vec<CK_OBJECT_HANDLE> = self
            .objects
            .iter()
            .filter(|(_handle, object)| {
                object.slot_id == Some(slot_id) && object.token && object.private
            })
            .map(|(handle, _object)| *handle)
            .collect();
        for handle in private_token_handles {
            if let Some(object) = self.objects.remove(&handle) {
                self.insert_object(object);
            }
        }
    }

    fn logout_slot(&mut self, slot_id: CK_SLOT_ID) -> Result<(), Error> {
        self._get_slot_mut(slot_id)?.logout()?;
        self.clear_login_state(slot_id);
        Ok(())
    }

    fn close_slot_state(&mut self, slot_id: CK_SLOT_ID, remove_token_objects: bool) {
        self.logged_in_slots.remove(&slot_id);
        if let Some(slot) = self.slots.get_mut(&slot_id) {
            slot.clear_session();
        }
        let sessions: HashSet<CK_SESSION_HANDLE> = self
            .sessions
            .iter()
            .filter(|(_, session)| session.slotID() == slot_id)
            .map(|(handle, _)| *handle)
            .collect();
        self.sessions.retain(|handle, _| !sessions.contains(handle));
        self.find_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.encrypt_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.decrypt_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.sign_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.verify_operations
            .retain(|handle, _| !sessions.contains(handle));
        self.objects.retain(|_, object| {
            object.slot_id != Some(slot_id) || (!remove_token_objects && object.token)
        });
    }

    #[allow(unreachable_code)]
    fn init(&mut self) {
        if self.slots_discovered {
            return;
        }
        self.slots_discovered = true;
        #[cfg(feature = "abi-tests")]
        {
            return;
        }
        let mut seen_dynamic_slots = HashSet::new();
        if let Some(context) = self.libusb.as_ref() {
            if let Ok(devices) = context.devices() {
                for device in devices.iter() {
                    if let Ok(desc) = device.device_descriptor() {
                        //eprintln!("USB Bus {} Device {}: ID {}: {}", device.bus_number(), device.address(), desc.vendor_id(), desc.product_id());
                        if desc.vendor_id() == 0x1050 && desc.product_id() == 0x30 {
                            match device.open() {
                                Ok(handle) => {
                                    let version = desc.device_version();
                                    let packet_size = match bulk_out_packet_size(&device) {
                                        Ok(packet_size) => packet_size,
                                        Err(error) => {
                                            log!(1, "libusb bulk OUT endpoint: {:?}", error);
                                            continue;
                                        }
                                    };
                                    let manufacturer = handle
                                        .read_manufacturer_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let product =
                                        handle.read_product_string_ascii(&desc).unwrap_or_default();
                                    let serial = handle
                                        .read_serial_number_string_ascii(&desc)
                                        .unwrap_or_default();
                                    let mut connector = UsbConnector {
                                        handle,
                                        version,
                                        manufacturer,
                                        product,
                                        serial,
                                        packet_size,
                                        claimed: false,
                                    };
                                    //let mut connector = CurlConnector { serial, url: String::from("http://127.0.0.1:12345"), connected: false, curl: RefCell::new(curl::easy::Easy::new()) };
                                    let name = connector.name();
                                    log!(2, "{}", name);
                                    if let Some(slot_id) =
                                        self.slots.iter().find_map(|(slot_id, slot)| {
                                            (slot.name() == name).then_some(*slot_id)
                                        })
                                    {
                                        if self.dynamic_slots.contains(&slot_id) {
                                            seen_dynamic_slots.insert(slot_id);
                                        }
                                        continue;
                                    }
                                    if let Err(error) = connector.connect() {
                                        log!(1, "libusb.claim_interface: {:?}", error);
                                        continue;
                                    }
                                    let slot_id = next_key(&self.slots, 0);
                                    let mut slot = Box::new(YubiHsmSlot {
                                        connector: Rc::new(connector),
                                        session: Rc::new(RefCell::new(None)),
                                        version: (0, 0, 0),
                                        algorithms: Vec::new(),
                                    });
                                    if let Err(error) = slot.init_slot() {
                                        log!(1, "YubiHSM GET DEVICE INFO: {:?}", error);
                                        continue;
                                    }
                                    self.slots.insert(slot_id, slot);
                                    self.dynamic_slots.insert(slot_id);
                                    seen_dynamic_slots.insert(slot_id);
                                }
                                Err(e) => {
                                    log!(1, "libusb.open: {}", e);
                                }
                            }
                        }
                    }
                }
            }
        }
        if let Some(context) = self.pcsc.clone() {
            if let Ok(readers) = context.list_readers_owned() {
                for reader in readers {
                    let connector = PcscConnector {
                        reader,
                        context: context.clone(),
                        card: RefCell::new(None),
                        firmware_version: Cell::new(None),
                        serial_number: OnceLock::new(),
                        apdu_capabilities: Cell::new(ApduCapabilities::SHORT_ONLY),
                    };
                    let name = connector.name();
                    log!(2, "{}", name);
                    if let Some(slot_id) = self
                        .slots
                        .iter()
                        .find_map(|(slot_id, slot)| (slot.name() == name).then_some(*slot_id))
                    {
                        if self.dynamic_slots.contains(&slot_id) {
                            seen_dynamic_slots.insert(slot_id);
                        }
                        let (was_present, is_present) = {
                            let slot = self.slots.get(&slot_id).unwrap();
                            let was_present = slot.is_present();
                            map(slot.refresh());
                            (was_present, slot.is_present())
                        };
                        if was_present && !is_present {
                            self.close_slot_state(slot_id, false);
                        } else if !was_present && is_present {
                            let initialized = self
                                .slots
                                .get_mut(&slot_id)
                                .ok_or_else(|| Error::from(CKR_SLOT_ID_INVALID))
                                .and_then(|slot| slot.init_slot());
                            if let Err(error) = initialized {
                                log!(
                                    1,
                                    "CCID application initialization failed for {}: {:?}",
                                    name,
                                    error
                                );
                                if let Some(slot) = self.slots.get(&slot_id) {
                                    slot.set_discovery_error(&error);
                                }
                            } else {
                                if let Some(slot) = self.slots.get(&slot_id) {
                                    slot.clear_discovery_error();
                                }
                                if let Err(error) = self.refresh_slot_token_objects(slot_id) {
                                    log!(2, "CCID object discovery: {:?}", error);
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.set_discovery_error(&error);
                                    }
                                }
                            }
                        }
                        continue;
                    }
                    if let Err(error) = connector.refresh() {
                        log!(1, "PCSC reader has no usable card: {:?}", error);
                        let reader_prefix = format!("{} ", name);
                        let known_slot_ids: Vec<CK_SLOT_ID> = self
                            .slots
                            .iter()
                            .filter(|(slot_id, slot)| {
                                self.dynamic_slots.contains(slot_id)
                                    && slot.name().starts_with(&reader_prefix)
                            })
                            .map(|(slot_id, _)| *slot_id)
                            .collect();
                        for slot_id in known_slot_ids {
                            seen_dynamic_slots.insert(slot_id);
                            let was_present = self
                                .slots
                                .get(&slot_id)
                                .is_some_and(|slot| slot.is_present());
                            if let Some(slot) = self.slots.get(&slot_id) {
                                map(slot.refresh());
                                if was_present && !slot.is_present() {
                                    self.close_slot_state(slot_id, false);
                                }
                            }
                        }
                        continue;
                    }
                    let configurations = match configured_ccid_configurations() {
                        Ok(configurations) => configurations,
                        Err(error) => {
                            log!(1, "CCID application configuration: {:?}", error);
                            continue;
                        }
                    };
                    let base_connector: Rc<dyn Connector> = Rc::new(connector);
                    let shared_state = Rc::new(RefCell::new(SecureChannelState::default()));
                    for configuration in configurations {
                        let application_label = ccid_application_label(configuration.application);
                        let name = format!("{} {}", base_connector.name(), application_label);
                        if let Some(slot_id) = self
                            .slots
                            .iter()
                            .find_map(|(slot_id, slot)| (slot.name() == name).then_some(*slot_id))
                        {
                            if self.dynamic_slots.contains(&slot_id) {
                                seen_dynamic_slots.insert(slot_id);
                            }
                            let (was_present, is_present) = {
                                let slot = self.slots.get(&slot_id).unwrap();
                                let was_present = slot.is_present();
                                map(slot.refresh());
                                (was_present, slot.is_present())
                            };
                            if was_present && !is_present {
                                self.close_slot_state(slot_id, false);
                            } else if !was_present && is_present {
                                let initialized = self
                                    .slots
                                    .get_mut(&slot_id)
                                    .ok_or_else(|| Error::from(CKR_SLOT_ID_INVALID))
                                    .and_then(|slot| slot.init_slot());
                                if let Err(error) = initialized {
                                    log!(
                                        1,
                                        "CCID application initialization failed for {}: {:?}",
                                        application_label,
                                        error
                                    );
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.set_discovery_error(&error);
                                    }
                                } else {
                                    if let Some(slot) = self.slots.get(&slot_id) {
                                        slot.clear_discovery_error();
                                    }
                                    if let Err(error) = self.refresh_slot_token_objects(slot_id) {
                                        log!(2, "CCID object discovery: {:?}", error);
                                        if let Some(slot) = self.slots.get(&slot_id) {
                                            slot.set_discovery_error(&error);
                                        }
                                    }
                                }
                            }
                            continue;
                        }

                        let slot_id = next_key(&self.slots, 0);
                        let application_aid = match ccid_application_aid(
                            configuration.application,
                            configuration.secure_channel,
                        ) {
                            Ok(aid) => aid,
                            Err(error) => {
                                log!(1, "CCID application AID configuration: {:?}", error);
                                continue;
                            }
                        };
                        if let Err(error) =
                            select_application(base_connector.as_ref(), &application_aid)
                        {
                            log!(
                                1,
                                "CCID application AID selection for {}: {:?}",
                                application_label,
                                error
                            );
                            continue;
                        }
                        if let Ok(mut state) = shared_state.try_borrow_mut() {
                            state.session = None;
                            state.application_aid = application_aid.clone();
                        }
                        let application_connector: Rc<dyn Connector> =
                            Rc::new(PcscAppletConnector::new(
                                base_connector.clone(),
                                &application_aid,
                                configuration.secure_channel,
                                shared_state.clone(),
                            ));
                        let mut slot: Box<dyn Slot> = match configuration.application {
                            CcidApplication::Piv => Box::new(PivSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::OpenPgp => Box::new(OpenPgpSlot::new(
                                application_connector,
                                application_aid.clone(),
                            )),
                            CcidApplication::HsmAuth => Box::new(GenericPcscSlot::new(
                                application_connector,
                                application_aid,
                                "YubiHSM Auth",
                            )),
                            CcidApplication::GlobalPlatform => Box::new(GlobalPlatformSlot::new(
                                application_connector,
                                application_aid,
                            )),
                        };
                        if slot.is_present() {
                            if let Err(error) = slot.init_slot() {
                                log!(
                                    1,
                                    "CCID application initialization failed for reader {}, applet {}: {:?}",
                                    base_connector.name(),
                                    application_label,
                                    error
                                );
                                slot.set_discovery_error(&error);
                            } else {
                                slot.clear_discovery_error();
                            }
                        }
                        let token_objects = if slot.is_present() {
                            match slot.token_objects(slot_id) {
                                Ok(objects) => objects,
                                Err(error) => {
                                    log!(2, "CCID object discovery: {:?}", error);
                                    slot.set_discovery_error(&error);
                                    Vec::new()
                                }
                            }
                        } else {
                            Vec::new()
                        };
                        self.slots.insert(slot_id, slot);
                        for object in token_objects.into_iter().filter(|object| object.token) {
                            self.insert_object(object);
                        }
                        self.dynamic_slots.insert(slot_id);
                        seen_dynamic_slots.insert(slot_id);
                    }
                }
            }
        }
        let removed_slots: Vec<CK_SLOT_ID> = self
            .dynamic_slots
            .difference(&seen_dynamic_slots)
            .copied()
            .collect();
        for slot_id in removed_slots {
            self.close_slot_state(slot_id, true);
            self.slots.remove(&slot_id);
            self.dynamic_slots.remove(&slot_id);
        }
        log!(2, "Context.init {:?}", self);
    }
}

#[cfg(not(any(test, feature = "abi-tests")))]
fn default_objects() -> Result<HashMap<CK_OBJECT_HANDLE, TokenObject>, Error> {
    Ok(HashMap::new())
}

#[cfg(any(test, feature = "abi-tests"))]
fn default_objects() -> Result<HashMap<CK_OBJECT_HANDLE, TokenObject>, Error> {
    let private_key = Rsa::generate(2048)?;
    let public_key =
        Rsa::from_public_components(private_key.n().to_owned()?, private_key.e().to_owned()?)?;
    let objects = HashMap::from([
        (
            1,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: b"1".to_vec(),
                class: CKO_PUBLIC_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: b"Test RSA public key".to_vec(),
                id: vec![1],
                token: true,
                private: false,
                encrypt: true,
                decrypt: false,
                sign: false,
                verify: true,
                derive: false,
                sensitive: false,
                extractable: true,
                always_sensitive: false,
                never_extractable: false,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::RsaPublic(public_key),
            },
        ),
        (
            2,
            TokenObject {
                slot_id: Some(ABI_TEST_SLOT_ID),
                unique_id: b"2".to_vec(),
                class: CKO_PRIVATE_KEY as CK_OBJECT_CLASS,
                key_type: CKK_RSA as CK_KEY_TYPE,
                label: b"Test RSA private key".to_vec(),
                id: vec![1],
                token: true,
                private: true,
                encrypt: false,
                decrypt: true,
                sign: true,
                verify: false,
                derive: false,
                sensitive: true,
                extractable: false,
                always_sensitive: true,
                never_extractable: true,
                local: true,
                key_gen_mechanism: Some(CKM_RSA_PKCS_KEY_PAIR_GEN as CK_MECHANISM_TYPE),
                owner_session: None,
                material: KeyMaterial::RsaPrivate(private_key),
            },
        ),
    ]);

    Ok(objects)
}

#[cfg(feature = "abi-tests")]
#[allow(dead_code)]
fn add_abi_test_backend_objects(context: &mut Context) -> Result<(), Error> {
    for object in abi_test_piv_slot()?.token_objects(ABI_TEST_PIV_SLOT_ID)? {
        context.insert_object(object);
    }
    context.insert_object(abi_test_yubihsm_object(ABI_TEST_YUBIHSM_SLOT_ID));
    context.insert_object(abi_test_yubihsm_aes_object(ABI_TEST_YUBIHSM_SLOT_ID));
    context.insert_object(abi_test_yubihsm_nist_aes_object(ABI_TEST_YUBIHSM_SLOT_ID));
    for object in abi_test_yubihsm_authentication_objects(ABI_TEST_YUBIHSM_SLOT_ID)? {
        context.insert_object(object);
    }
    for object in abi_test_yubihsm_opaque_objects(ABI_TEST_YUBIHSM_SLOT_ID)? {
        context.insert_object(object);
    }
    Ok(())
}


// The PKCS#11 entry points serialize all access through G_CONTEXT. Some connector
// handles are not marked Send by their crates, so Context must not escape the
// mutex guard even though the global mutex itself may be touched by any caller
// thread.
unsafe impl Send for Context {}

static G_CONTEXT: Mutex<Option<Context>> = Mutex::new(None);
