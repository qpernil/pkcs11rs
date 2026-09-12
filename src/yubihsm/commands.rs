mod audit;
mod crypto;
mod device;
mod object;
mod otp;
mod protocol;
mod response;
mod session_object;
mod wrapping;

#[cfg(test)]
pub(crate) use object::ObjectFilter;
pub(crate) use object::{DelegatedObjectParameters, ObjectParameters};
#[cfg(test)]
pub(crate) use protocol::ALL_COMMAND_CODES;
#[cfg(test)]
use protocol::{
    ALGORITHM_AES128_YUBICO_AUTHENTICATION, ALGORITHM_AES128_YUBICO_OTP,
    ALGORITHM_AES192_YUBICO_OTP, ALGORITHM_AES256_YUBICO_OTP,
    ALGORITHM_EC_P256_YUBICO_AUTHENTICATION, MAX_COMMAND_DATA_LENGTH, MAX_LOG_ENTRY_COUNT,
    MAX_OBJECT_COUNT,
};
pub(crate) use protocol::{Command, CommandCode};
#[cfg(test)]
use response::{
    ImportedObject, LogEntries, ObjectEntry, OtpDecryption, StorageInfo, require_empty,
};
pub(crate) use response::{ObjectInfo, PublicKey, parse_object_id, parse_object_list};
pub(crate) use session_object::{
    FLAG_DERIVE as SESSION_OBJECT_DERIVE, FLAG_READABLE as SESSION_OBJECT_READABLE,
    FLAG_VERIFY as SESSION_OBJECT_VERIFY, SessionObjectKind, SessionObjectSource,
};
pub(crate) use wrapping::RsaWrapParameters;

#[cfg(test)]
mod tests;
