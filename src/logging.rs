use crate::CK_RV;
use std::{io, time::Instant};
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

pub(crate) fn ffi_call(function: &'static str, operation: impl FnOnce() -> CK_RV) -> CK_RV {
    let dispatch = module_dispatch();
    let started = Instant::now();
    let result = with_dispatch(dispatch.as_ref(), || {
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
