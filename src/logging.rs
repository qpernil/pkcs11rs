use crate::CK_RV;
use std::{cell::Cell, io, time::Instant};
use tracing::{Dispatch, Level, Span};
use tracing_subscriber::fmt::format::FmtSpan;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LogLevel {
    Off,
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    pub(crate) fn parse(value: &str) -> Option<Self> {
        Some(match value.trim().to_ascii_lowercase().as_str() {
            "off" => Self::Off,
            "error" => Self::Error,
            "warn" | "warning" => Self::Warn,
            "info" => Self::Info,
            "debug" => Self::Debug,
            "trace" => Self::Trace,
            _ => return None,
        })
    }

    const fn filter(self) -> tracing::level_filters::LevelFilter {
        match self {
            Self::Off => tracing::level_filters::LevelFilter::OFF,
            Self::Error => tracing::level_filters::LevelFilter::ERROR,
            Self::Warn => tracing::level_filters::LevelFilter::WARN,
            Self::Info => tracing::level_filters::LevelFilter::INFO,
            Self::Debug => tracing::level_filters::LevelFilter::DEBUG,
            Self::Trace => tracing::level_filters::LevelFilter::TRACE,
        }
    }
}

pub(crate) fn configured_dispatch(level: Option<LogLevel>) -> Option<Dispatch> {
    let level = level?;
    if level == LogLevel::Off {
        return Some(Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    }
    let max_level = level.filter();
    let span_events = FmtSpan::NONE;
    #[cfg(target_os = "ios")]
    {
        Some(Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(max_level)
                .with_ansi(false)
                .with_target(false)
                .with_level(false)
                .without_time()
                .with_span_events(span_events)
                .with_writer(crate::apple::logging::AppleMakeWriter)
                .finish(),
        ))
    }
    #[cfg(not(target_os = "ios"))]
    {
        Some(Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(max_level)
                .with_ansi(false)
                .with_target(true)
                .with_span_events(span_events)
                .with_writer(io::stderr)
                .finish(),
        ))
    }
}

fn module_dispatch() -> Option<Dispatch> {
    crate::MODULE_CONTEXT
        .try_read()
        .ok()
        .and_then(|module| module.as_ref().and_then(|context| context.logging.clone()))
}

pub(crate) fn with_dispatch<T>(dispatch: Option<&Dispatch>, operation: impl FnOnce() -> T) -> T {
    match dispatch {
        Some(dispatch) => tracing::dispatcher::with_default(dispatch, operation),
        None => operation(),
    }
}

thread_local! {
    static CURRENT_FFI_FUNCTION: Cell<Option<&'static str>> = const { Cell::new(None) };
}

pub(crate) const COMMUNICATING_MESSAGE: &str = "Communicating";

pub(crate) fn current_operation_message() -> &'static str {
    CURRENT_FFI_FUNCTION.with(|function| match function.get() {
        Some("C_GetSlotList") => "Discovering tokens…",
        Some("C_GetSlotInfo") | Some("C_GetTokenInfo") => "Reading token information…",
        Some("C_GetMechanismList") | Some("C_GetMechanismInfo") => "Reading token capabilities…",
        Some("C_OpenSession") => "Opening a token session…",
        Some("C_Login") | Some("C_LoginUser") => "Authenticating…",
        Some("C_Logout") => "Logging out…",
        Some("C_FindObjectsInit") | Some("C_FindObjects") | Some("C_FindObjectsFinal") => {
            "Finding objects…"
        }
        Some("C_GetAttributeValue") => "Reading object attributes…",
        Some("C_SetAttributeValue") => "Updating object attributes…",
        Some("C_Sign") | Some("C_SignFinal") | Some("C_SignMessage") => "Signing…",
        Some("C_Verify") | Some("C_VerifyFinal") | Some("C_VerifyMessage") => "Verifying…",
        Some("C_Decrypt") | Some("C_DecryptFinal") => "Decrypting…",
        Some("C_Encrypt") | Some("C_EncryptFinal") => "Encrypting…",
        Some("C_GenerateKey") | Some("C_GenerateKeyPair") => "Generating a key…",
        Some("C_DeriveKey") => "Deriving a key…",
        Some("C_WrapKey") => "Wrapping a key…",
        Some("C_UnwrapKey") => "Unwrapping a key…",
        Some("C_SeedRandom") | Some("C_GenerateRandom") => "Generating random data…",
        Some("C_SetPIN") | Some("C_InitPIN") => "Changing the PIN…",
        Some("C_InitToken") => "Initializing the token…",
        Some("C_CreateObject") | Some("C_CopyObject") => "Writing an object…",
        Some("C_DestroyObject") => "Deleting an object…",
        _ => COMMUNICATING_MESSAGE,
    })
}

pub(crate) fn ffi_call(function: &'static str, operation: impl FnOnce() -> CK_RV) -> CK_RV {
    let dispatch = module_dispatch();
    let started = Instant::now();
    let result = with_dispatch(dispatch.as_ref(), || {
        let previous = CURRENT_FFI_FUNCTION.with(|current| current.replace(Some(function)));
        struct FunctionGuard(Option<&'static str>);
        impl Drop for FunctionGuard {
            fn drop(&mut self) {
                CURRENT_FFI_FUNCTION.with(|current| current.set(self.0));
            }
        }
        let _function = FunctionGuard(previous);
        tracing::debug!(
            target: "pkcs11rs::ffi",
            function,
            "PKCS #11 call entered"
        );
        let result = operation();
        let installed_dispatch = dispatch.is_none() && module_dispatch().is_some();
        if !installed_dispatch {
            tracing::debug!(
                target: "pkcs11rs::ffi",
                function,
                return_value = result,
                elapsed_us = started.elapsed().as_micros() as u64,
                "PKCS #11 call returned"
            );
        }
        result
    });
    if dispatch.is_none() {
        if let Some(initialized_dispatch) = module_dispatch() {
            with_dispatch(Some(&initialized_dispatch), || {
                tracing::debug!(
                    target: "pkcs11rs::ffi",
                    function,
                    return_value = result,
                    elapsed_us = started.elapsed().as_micros() as u64,
                    "PKCS #11 call returned"
                );
            });
        }
    }
    result
}

pub(crate) struct Operation {
    span: Span,
    started: Option<Instant>,
    level: Level,
}

impl Operation {
    pub(crate) fn new(span: Span) -> Self {
        Self::with_level(span, Level::DEBUG)
    }

    pub(crate) fn info(span: Span) -> Self {
        Self::with_level(span, Level::INFO)
    }

    pub(crate) fn trace(span: Span) -> Self {
        Self::with_level(span, Level::TRACE)
    }

    fn with_level(span: Span, level: Level) -> Self {
        let started = (!span.is_disabled()).then(Instant::now);
        if started.is_some() {
            match level {
                Level::INFO => tracing::info!(parent: &span, "started"),
                Level::TRACE => tracing::trace!(parent: &span, "started"),
                _ => tracing::debug!(parent: &span, "started"),
            }
        }
        Self {
            span,
            started,
            level,
        }
    }

    pub(crate) fn enter(&self) -> tracing::span::Entered<'_> {
        self.span.enter()
    }
}

impl Drop for Operation {
    fn drop(&mut self) {
        if let Some(started) = self.started {
            let elapsed_us = started.elapsed().as_micros() as u64;
            match self.level {
                Level::INFO => tracing::info!(
                    parent: &self.span,
                    elapsed_us,
                    "completed"
                ),
                Level::TRACE => tracing::trace!(
                    parent: &self.span,
                    elapsed_us,
                    "completed"
                ),
                _ => tracing::debug!(
                    parent: &self.span,
                    elapsed_us,
                    "completed"
                ),
            }
        }
    }
}
