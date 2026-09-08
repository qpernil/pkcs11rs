//! One-shot, per-thread snapshots for paired C_GetSlotList buffer calls.

use crate::{CK_SLOT_ID, HandleCounters};
use std::{
    cell::RefCell,
    sync::{Arc, Weak},
};

thread_local! {
    static PENDING: RefCell<Option<Snapshot>> = const { RefCell::new(None) };
}

pub(crate) struct Snapshot {
    // Weak identity avoids retaining a finalized module or its session state.
    lifetime: Weak<HandleCounters>,
    token_present: bool,
    pub(crate) slots: Vec<CK_SLOT_ID>,
}

impl Snapshot {
    pub(crate) fn new(
        handles: &Arc<HandleCounters>,
        token_present: bool,
        slots: Vec<CK_SLOT_ID>,
    ) -> Self {
        Self {
            lifetime: Arc::downgrade(handles),
            token_present,
            slots,
        }
    }

    pub(crate) fn matches(&self, handles: &Arc<HandleCounters>, token_present: bool) -> bool {
        self.token_present == token_present && self.lifetime.ptr_eq(&Arc::downgrade(handles))
    }

    pub(crate) fn save(self) {
        PENDING.with(|pending| *pending.borrow_mut() = Some(self));
    }
}

pub(crate) fn take_snapshot() -> Option<Snapshot> {
    PENDING.with(|pending| pending.borrow_mut().take())
}
