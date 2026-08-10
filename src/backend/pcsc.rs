use crate::*;
use std::sync::{Arc, atomic::AtomicBool};

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
            return Ok(readers
                .into_iter()
                .map(|reader| {
                    let connector = CcidConnector::new(reader, context.clone());
                    let reader_state = connector.reader_state();
                    CcidReader {
                        connector: Arc::new(connector) as SharedConnector,
                        reader_state,
                        inventory_presence: None,
                    }
                })
                .collect());
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
