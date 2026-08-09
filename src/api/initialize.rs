use crate::*;

pub(crate) const INITIALIZE_ARGS_MAGIC: CK_ULONG = 0x5031_3150;
pub(crate) const INITIALIZE_ARGS_VERSION: CK_ULONG = 1;

#[repr(C)]
struct InitializeArgsV1 {
    magic: CK_ULONG,
    size: CK_ULONG,
    version: CK_ULONG,
    configuration: *const CK_UTF8CHAR,
    configuration_length: CK_ULONG,
    log_context: *mut std::ffi::c_void,
    log_event: Option<crate::logging::HostLogEvent>,
}

pub(super) struct InitializeReserved {
    pub(super) configuration: Option<JsonConfiguration>,
    pub(super) host_log_provider: Option<crate::logging::HostLogProvider>,
}

pub(super) unsafe fn parse_initialize_reserved(
    reserved: *mut std::ffi::c_void,
) -> Result<InitializeReserved, Error> {
    if reserved.is_null() || unsafe { reserved.cast::<u8>().read() } != b'P' {
        return legacy_reserved(reserved);
    }
    let magic = unsafe { reserved.cast::<CK_ULONG>().read_unaligned() };
    if magic != INITIALIZE_ARGS_MAGIC {
        return legacy_reserved(reserved);
    }
    let arguments = unsafe { _as_ref(reserved.cast::<InitializeArgsV1>()) }?;
    let expected_size = CK_ULONG::try_from(std::mem::size_of::<InitializeArgsV1>())
        .map_err(|_| CKR_ARGUMENTS_BAD)?;
    if arguments.size != expected_size || arguments.version != INITIALIZE_ARGS_VERSION {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    let configuration_length = usize::try_from(arguments.configuration_length)
        .ok()
        .filter(|length| *length <= crate::configuration::MAX_CONFIGURATION_STRING_BYTES)
        .ok_or(CKR_ARGUMENTS_BAD)?;
    let configuration = if configuration_length == 0 {
        None
    } else {
        let encoded = unsafe { from_raw_parts(arguments.configuration, configuration_length) }?;
        JsonConfiguration::from_bytes(encoded)?
    };
    let host_log_provider = arguments
        .log_event
        .map(|event| crate::logging::HostLogProvider::new(arguments.log_context, event));
    Ok(InitializeReserved {
        configuration,
        host_log_provider,
    })
}

unsafe fn legacy_reserved(reserved: *mut std::ffi::c_void) -> Result<InitializeReserved, Error> {
    let configuration = match unsafe { JsonConfiguration::from_reserved(reserved) }? {
        ReservedConfiguration::Empty | ReservedConfiguration::Opaque => None,
        ReservedConfiguration::Json(configuration) => Some(*configuration),
    };
    Ok(InitializeReserved {
        configuration,
        host_log_provider: None,
    })
}
