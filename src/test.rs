#[path = "tests/common.rs"]
mod common;

#[cfg(unix)]
pub(crate) use common::TestPinentry;
#[cfg(unix)]
pub(crate) use common::TEST_LOCK;
