use super::*;
use virtual_yubihsm_core::{
    Device as VirtualYubiHsm, DeviceConfig as VirtualYubiHsmConfig, Frame as VirtualYubiHsmFrame,
};

const COMMAND_ERROR: u8 = 0x7f;

#[derive(Clone, Debug)]
struct NativeObject {
    info: YubiHsmObjectInfo,
    value: Vec<u8>,
    public_key: Option<YubiHsmPublicKey>,
}

#[derive(Debug)]
pub(super) struct AbiYubiHsmConnector {
    device: RefCell<VirtualYubiHsm>,
    objects: RefCell<HashMap<(u8, u16), NativeObject>>,
    concurrency: Option<(Arc<AbiYubiHsmConcurrencyState>, usize)>,
}

impl AbiYubiHsmConnector {
    pub(super) fn new(
        serial: &'static str,
        concurrency: Option<(Arc<AbiYubiHsmConcurrencyState>, usize)>,
    ) -> Result<Self, Error> {
        let serial = serial
            .strip_prefix("HSM")
            .and_then(|serial| serial.parse().ok())
            .ok_or(CKR_ARGUMENTS_BAD)?;
        let config = VirtualYubiHsmConfig {
            version: [2, 4, 0],
            serial,
            log_capacity: 62,
            algorithms: vec![
                YUBIHSM_ALGO_RSA_PKCS1_SHA1,
                YUBIHSM_ALGO_RSA_PKCS1_SHA256,
                YUBIHSM_ALGO_RSA_OAEP_SHA1,
                YUBIHSM_ALGO_RSA_2048,
                YUBIHSM_ALGO_AES128_CCM_WRAP,
                YUBIHSM_ALGO_AES128,
                YUBIHSM_ALGO_AES_ECB,
                YUBIHSM_ALGO_AES_CBC,
                YUBIHSM_ALGO_AES_KWP,
                YUBIHSM_ALGO_HMAC_SHA256,
            ],
            part_number: *b"ABI YubiHSM\0\0",
        };
        let mut device_private = [0; 32];
        device_private[31] = 1;
        let device =
            VirtualYubiHsm::factory_default_with_device_static_private(config, device_private)
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
        Ok(Self {
            device: RefCell::new(device),
            objects: RefCell::new(initial_objects()?),
            concurrency,
        })
    }

    fn reply(&self, request: &[u8]) -> Result<Vec<u8>, Error> {
        let mut device = self
            .device
            .try_borrow_mut()
            .map_err(|_| Error::from(CKR_CANT_LOCK))?;
        Ok(device.handle_encoded_with(request, |_, request| {
            let response = YubiHsmCommandCode::try_from(request.command)
                .and_then(|command| self.handle_command(command, &request.data));
            Some(match response {
                Ok(data) => VirtualYubiHsmFrame::response(request.command, data),
                Err(error) => VirtualYubiHsmFrame {
                    command: COMMAND_ERROR,
                    data: vec![device_error(&error)],
                },
            })
        }))
    }

    fn handle_command(&self, command: YubiHsmCommandCode, data: &[u8]) -> Result<Vec<u8>, Error> {
        match command {
            YubiHsmCommandCode::CloseSession => Ok(Vec::new()),
            YubiHsmCommandCode::GetStorageInfo => Ok(vec![0; 10]),
            YubiHsmCommandCode::GetPseudoRandom => {
                let length = u16::from_be_bytes(
                    data.try_into()
                        .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?,
                ) as usize;
                if let Some((state, slot_index)) = &self.concurrency {
                    state.overlap(*slot_index)?;
                    let slot_id = if *slot_index == 0 {
                        ABI_TEST_YUBIHSM_SLOT_ID
                    } else {
                        ABI_TEST_SECOND_YUBIHSM_SLOT_ID
                    };
                    let marker = u8::try_from(slot_id).map_err(|_| CKR_DEVICE_ERROR)?;
                    return Ok(vec![marker; length]);
                }
                Ok(vec![0x5a; length])
            }
            YubiHsmCommandCode::ListObjects => {
                let mut response = Vec::new();
                for object in self
                    .objects
                    .try_borrow()
                    .map_err(|_| Error::from(CKR_CANT_LOCK))?
                    .values()
                {
                    response.extend_from_slice(&object.info.id.to_be_bytes());
                    response.extend([object.info.object_type, object.info.sequence]);
                }
                Ok(response)
            }
            YubiHsmCommandCode::GetObjectInfo => {
                let (id, object_type) = object_reference(data)?;
                let objects = self
                    .objects
                    .try_borrow()
                    .map_err(|_| Error::from(CKR_CANT_LOCK))?;
                let object = objects
                    .get(&(object_type, id))
                    .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
                encode_object_info(&object.info)
            }
            YubiHsmCommandCode::GetPublicKey => {
                let id = read_id(data)?;
                let requested_type = data.get(2).copied();
                let objects = self
                    .objects
                    .try_borrow()
                    .map_err(|_| Error::from(CKR_CANT_LOCK))?;
                let object = objects
                    .values()
                    .find(|object| {
                        object.info.id == id
                            && requested_type
                                .is_none_or(|object_type| object.info.object_type == object_type)
                            && object.public_key.is_some()
                    })
                    .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
                let public_key = object.public_key.as_ref().ok_or(CKR_DEVICE_ERROR)?;
                Ok([&[public_key.algorithm][..], public_key.key.as_slice()].concat())
            }
            YubiHsmCommandCode::GetOpaque => {
                let id = read_id(data)?;
                if id == 0 {
                    return abi_yubihsm_attestation_signer_certificate();
                }
                let objects = self
                    .objects
                    .try_borrow()
                    .map_err(|_| Error::from(CKR_CANT_LOCK))?;
                objects
                    .get(&(YUBIHSM_OPAQUE, id))
                    .map(|object| object.value.clone())
                    .ok_or_else(|| CKR_OBJECT_HANDLE_INVALID.into())
            }
            YubiHsmCommandCode::PutOpaque => self.put_object(command, data),
            YubiHsmCommandCode::DeleteObject => {
                let (id, object_type) = object_reference(data)?;
                self.objects
                    .try_borrow_mut()?
                    .remove(&(object_type, id))
                    .ok_or(CKR_OBJECT_HANDLE_INVALID)?;
                Ok(Vec::new())
            }
            _ => {
                let command = YubiHsmCommand::raw(command, data)?;
                abi_yubihsm_command(&command)
            }
        }
    }

    fn put_object(&self, command: YubiHsmCommandCode, data: &[u8]) -> Result<Vec<u8>, Error> {
        if data.len() < 53 {
            return Err(CKR_DATA_LEN_RANGE.into());
        }
        let requested_id = read_id(data)?;
        let mut objects = self.objects.try_borrow_mut()?;
        let id = if requested_id == 0 {
            (1..=u16::MAX)
                .find(|id| !objects.contains_key(&(YUBIHSM_OPAQUE, *id)))
                .ok_or(CKR_DEVICE_MEMORY)?
        } else {
            requested_id
        };
        let label = decode_label(&data[2..42])?;
        let value = data[53..].to_vec();
        let info = YubiHsmObjectInfo {
            capabilities: data[44..52]
                .try_into()
                .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?,
            id,
            length: value.len() as u16,
            domains: u16::from_be_bytes(
                data[42..44]
                    .try_into()
                    .map_err(|_| Error::from(CKR_DATA_LEN_RANGE))?,
            ),
            object_type: YUBIHSM_OPAQUE,
            algorithm: data[52],
            sequence: 1,
            origin: 2,
            label,
            delegated_capabilities: [0; 8],
        };
        objects.insert(
            (YUBIHSM_OPAQUE, id),
            NativeObject {
                info,
                value,
                public_key: None,
            },
        );
        let _ = command;
        Ok(id.to_be_bytes().to_vec())
    }
}

impl Connector for AbiYubiHsmConnector {
    fn as_debug(&self) -> &dyn std::fmt::Debug {
        self
    }

    fn manufacturer(&self) -> &str {
        "PKCS11RS"
    }

    fn product(&self) -> &str {
        "YubiHSM"
    }

    fn major(&self) -> u8 {
        2
    }

    fn minor(&self) -> u8 {
        4
    }

    fn is_present(&self) -> bool {
        true
    }

    fn buffer_size(&self) -> usize {
        4096
    }

    fn transmit<'a>(
        &self,
        send_buffer: &[u8],
        receive_buffer: &'a mut [u8],
        _timeout: Duration,
    ) -> Result<&'a [u8], Error> {
        let response = self.reply(send_buffer)?;
        if response.len() > receive_buffer.len() {
            return Err(CKR_DEVICE_ERROR.into());
        }
        receive_buffer[..response.len()].copy_from_slice(&response);
        Ok(&receive_buffer[..response.len()])
    }
}

fn initial_objects() -> Result<HashMap<(u8, u16), NativeObject>, Error> {
    let mut objects = HashMap::new();
    let private = abi_test_yubihsm_object(ABI_TEST_YUBIHSM_SLOT_ID);
    let public = abi_test_yubihsm_public_object(ABI_TEST_YUBIHSM_SLOT_ID);
    let public_key = match &public.material {
        KeyMaterial::YubiHsm {
            algorithm,
            public_key,
            ..
        } => Some(YubiHsmPublicKey {
            algorithm: *algorithm,
            key: public_key.clone(),
        }),
        _ => return Err(CKR_DEVICE_ERROR.into()),
    };
    insert_token_object(&mut objects, private, public_key)?;
    for object in [
        abi_test_yubihsm_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_nist_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_rfc5649_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_rfc3610_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_nist_gmac_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_rfc3394_aes_object(ABI_TEST_YUBIHSM_SLOT_ID),
        abi_test_yubihsm_hmac_object(ABI_TEST_YUBIHSM_SLOT_ID)?,
    ] {
        insert_token_object(&mut objects, object, None)?;
    }
    for object in abi_test_yubihsm_authentication_objects(ABI_TEST_YUBIHSM_SLOT_ID)?
        .into_iter()
        .chain(abi_test_yubihsm_wrap_objects(ABI_TEST_YUBIHSM_SLOT_ID)?)
        .chain(abi_test_yubihsm_opaque_objects(ABI_TEST_YUBIHSM_SLOT_ID)?)
    {
        insert_token_object(&mut objects, object, None)?;
    }
    if let Some(object) = objects.get_mut(&(YUBIHSM_OPAQUE, ABI_YUBIHSM_OPAQUE_DATA_ID)) {
        object.value = ABI_YUBIHSM_OPAQUE_DATA.to_vec();
    }
    if let Some(object) = objects.get_mut(&(YUBIHSM_OPAQUE, ABI_YUBIHSM_OPAQUE_CERTIFICATE_ID)) {
        object.value = abi_yubihsm_opaque_certificate()?;
    }

    insert_projection_metadata(&mut objects, YUBIHSM_ASYMMETRIC_KEY, 1, &public, 0x7000)?;
    insert_projection_metadata(
        &mut objects,
        YUBIHSM_WRAP_KEY,
        9,
        &abi_test_yubihsm_rsa_wrap_public_object(ABI_TEST_YUBIHSM_SLOT_ID),
        0x7001,
    )?;
    Ok(objects)
}

fn insert_projection_metadata(
    objects: &mut HashMap<(u8, u16), NativeObject>,
    target_type: u8,
    target_id: u16,
    projection: &TokenObject,
    metadata_id: u16,
) -> Result<(), Error> {
    let target = objects
        .get(&(target_type, target_id))
        .map(|object| object.info.clone())
        .ok_or(CKR_DEVICE_ERROR)?;
    let (metadata_label, metadata) = yubihsm_abi_public_projection_metadata(&target, projection)?;
    objects.insert(
        (YUBIHSM_OPAQUE, metadata_id),
        NativeObject {
            info: YubiHsmObjectInfo {
                capabilities: [0; 8],
                id: metadata_id,
                length: metadata.len() as u16,
                domains: target.domains,
                object_type: YUBIHSM_OPAQUE,
                algorithm: YUBIHSM_ALGO_OPAQUE_DATA,
                sequence: 1,
                origin: 1,
                label: metadata_label,
                delegated_capabilities: [0; 8],
            },
            value: metadata,
            public_key: None,
        },
    );
    Ok(())
}

fn insert_token_object(
    objects: &mut HashMap<(u8, u16), NativeObject>,
    object: TokenObject,
    public_key: Option<YubiHsmPublicKey>,
) -> Result<(), Error> {
    let KeyMaterial::YubiHsm {
        id,
        object_type,
        algorithm,
        length,
        domains,
        capabilities,
        delegated_capabilities,
        public_key: encoded_public_key,
        ..
    } = object.material
    else {
        return Err(CKR_DEVICE_ERROR.into());
    };
    objects.insert(
        (object_type, id),
        NativeObject {
            info: YubiHsmObjectInfo {
                capabilities,
                id,
                length: length as u16,
                domains,
                object_type,
                algorithm,
                sequence: 1,
                origin: 1,
                label: object.label,
                delegated_capabilities,
            },
            value: Vec::new(),
            public_key: public_key.or_else(|| {
                (!encoded_public_key.is_empty()).then_some(YubiHsmPublicKey {
                    algorithm,
                    key: encoded_public_key,
                })
            }),
        },
    );
    Ok(())
}

fn encode_object_info(info: &YubiHsmObjectInfo) -> Result<Vec<u8>, Error> {
    if info.label.len() > 40 {
        return Err(CKR_DATA_LEN_RANGE.into());
    }
    let mut encoded = vec![0; 66];
    encoded[..8].copy_from_slice(&info.capabilities);
    encoded[8..10].copy_from_slice(&info.id.to_be_bytes());
    encoded[10..12].copy_from_slice(&info.length.to_be_bytes());
    encoded[12..14].copy_from_slice(&info.domains.to_be_bytes());
    encoded[14..18].copy_from_slice(&[
        info.object_type,
        info.algorithm,
        info.sequence,
        info.origin,
    ]);
    encoded[18..18 + info.label.len()].copy_from_slice(info.label.as_bytes());
    encoded[58..].copy_from_slice(&info.delegated_capabilities);
    Ok(encoded)
}

fn read_id(data: &[u8]) -> Result<u16, Error> {
    data.get(..2)
        .and_then(|id| id.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| CKR_DATA_LEN_RANGE.into())
}

fn object_reference(data: &[u8]) -> Result<(u16, u8), Error> {
    Ok((read_id(data)?, *data.get(2).ok_or(CKR_DATA_LEN_RANGE)?))
}

fn decode_label(encoded: &[u8]) -> Result<String, Error> {
    let label = encoded.split(|byte| *byte == 0).next().unwrap_or_default();
    std::str::from_utf8(label)
        .map(str::to_owned)
        .map_err(|_| CKR_DATA_INVALID.into())
}

fn device_error(error: &Error) -> u8 {
    match error {
        Error::Generic(rv) if *rv == CKR_OBJECT_HANDLE_INVALID as CK_RV => 0x0b,
        Error::Generic(rv) if *rv == CKR_DATA_LEN_RANGE as CK_RV => 0x08,
        Error::Generic(rv) if *rv == CKR_DEVICE_MEMORY as CK_RV => 0x07,
        _ => 0xff,
    }
}
