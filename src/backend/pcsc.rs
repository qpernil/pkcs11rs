use crate::*;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex, Weak, atomic::AtomicBool},
};

#[cfg(feature = "native-hardware")]
pub(crate) use crate::PcscConnector as CcidConnector;

pub(crate) struct CcidReader {
    pub(crate) connector: SharedConnector,
    pub(crate) reader_state: Arc<PcscReaderState>,
    pub(crate) inventory_presence: Option<Arc<AtomicBool>>,
}

pub(crate) struct CcidProvider {
    enabled: bool,
    #[cfg(feature = "native-hardware")]
    context: Option<pcsc::Context>,
    #[cfg(feature = "native-hardware")]
    connectors: Mutex<HashMap<String, Weak<CcidConnector>>>,
}

impl CcidProvider {
    pub(crate) fn new(enabled: bool) -> Self {
        #[cfg(all(feature = "native-hardware", not(feature = "abi-tests")))]
        let context = if enabled {
            match pcsc::Context::establish(pcsc::Scope::System) {
                Ok(context) => Some(context),
                Err(error) => {
                    log!(1, "pcsc::Context::establish: {}", error);
                    None
                }
            }
        } else {
            None
        };
        #[cfg(all(feature = "native-hardware", feature = "abi-tests"))]
        let context = None;

        Self {
            enabled,
            #[cfg(feature = "native-hardware")]
            context,
            #[cfg(feature = "native-hardware")]
            connectors: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn name(&self) -> &'static str {
        "pcsc"
    }

    pub(crate) fn enumerate(&self) -> Result<Vec<CcidReader>, Error> {
        if !self.enabled {
            return Ok(Vec::new());
        }

        #[cfg(feature = "native-hardware")]
        if let Some(context) = self.context.clone() {
            let readers = context
                .list_readers_owned()
                .map_err(|_| Error::from(CKR_DEVICE_ERROR))?;
            let mut connectors = self.connectors.lock().map_err(|_| CKR_MUTEX_BAD)?;
            let mut present = std::collections::HashSet::new();
            let readers = readers
                .into_iter()
                .map(|reader| {
                    let name = reader.to_string_lossy().into_owned();
                    present.insert(name.clone());
                    let connector = connectors
                        .get(&name)
                        .and_then(Weak::upgrade)
                        .unwrap_or_else(|| {
                            let connector = Arc::new(CcidConnector::new(reader, context.clone()));
                            connectors.insert(name, Arc::downgrade(&connector));
                            connector
                        });
                    let reader_state = connector.reader_state();
                    CcidReader {
                        connector: connector as SharedConnector,
                        reader_state,
                        inventory_presence: None,
                    }
                })
                .collect();
            connectors
                .retain(|name, connector| present.contains(name) || connector.strong_count() > 0);
            return Ok(readers);
        }

        Ok(Vec::new())
    }
}

impl std::fmt::Debug for CcidProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CcidProvider")
            .field("name", &self.name())
            .field("enabled", &self.enabled)
            .finish_non_exhaustive()
    }
}
