use crate::{CK_RV, CK_ULONG, CK_UTF8CHAR};
use std::{
    ffi::c_void,
    io::{self, Write},
    time::Instant,
};
use tracing::{Dispatch, Level, Span};
use tracing_subscriber::fmt::{format::FmtSpan, MakeWriter};

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

pub(crate) type HostLogEvent = unsafe extern "C" fn(
    context: *mut c_void,
    level: CK_ULONG,
    target: *const CK_UTF8CHAR,
    target_length: CK_ULONG,
    message: *const CK_UTF8CHAR,
    message_length: CK_ULONG,
);

#[derive(Clone, Copy)]
pub(crate) struct HostLogProvider {
    context: usize,
    event: HostLogEvent,
}

impl HostLogProvider {
    pub(crate) fn new(context: *mut c_void, event: HostLogEvent) -> Self {
        Self {
            context: context as usize,
            event,
        }
    }
}

impl std::fmt::Debug for HostLogProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostLogProvider")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct HostMakeWriter {
    provider: HostLogProvider,
}

struct HostWriter {
    provider: HostLogProvider,
    level: CK_ULONG,
    target: String,
    message: Vec<u8>,
}

impl<'writer> MakeWriter<'writer> for HostMakeWriter {
    type Writer = HostWriter;

    fn make_writer(&'writer self) -> Self::Writer {
        HostWriter {
            provider: self.provider,
            level: log_level(Level::TRACE),
            target: "pkcs11rs".to_owned(),
            message: Vec::new(),
        }
    }

    fn make_writer_for(&'writer self, metadata: &tracing::Metadata<'_>) -> Self::Writer {
        HostWriter {
            provider: self.provider,
            level: log_level(*metadata.level()),
            target: metadata.target().to_owned(),
            message: Vec::new(),
        }
    }
}

impl Write for HostWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.message.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Drop for HostWriter {
    fn drop(&mut self) {
        while self
            .message
            .last()
            .is_some_and(|byte| matches!(byte, b'\r' | b'\n'))
        {
            self.message.pop();
        }
        if self.message.is_empty() {
            return;
        }
        let Ok(target_length) = CK_ULONG::try_from(self.target.len()) else {
            return;
        };
        let Ok(message_length) = CK_ULONG::try_from(self.message.len()) else {
            return;
        };
        unsafe {
            (self.provider.event)(
                self.provider.context as *mut c_void,
                self.level,
                self.target.as_ptr(),
                target_length,
                self.message.as_ptr(),
                message_length,
            );
        }
    }
}

const fn log_level(level: Level) -> CK_ULONG {
    match level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

pub(crate) fn configured_dispatch(
    level: Option<LogLevel>,
    host: Option<HostLogProvider>,
) -> Option<Dispatch> {
    let level = match (level, host) {
        (None, None) => return None,
        (None, Some(_)) => LogLevel::Trace,
        (Some(level), _) => level,
    };
    if level == LogLevel::Off {
        return Some(Dispatch::new(tracing::subscriber::NoSubscriber::default()));
    }
    let max_level = level.filter();
    let span_events = FmtSpan::NONE;
    match host {
        Some(provider) => Some(Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(max_level)
                .with_ansi(false)
                .with_target(false)
                .with_span_events(span_events)
                .with_writer(HostMakeWriter { provider })
                .finish(),
        )),
        None => Some(Dispatch::new(
            tracing_subscriber::fmt()
                .with_max_level(max_level)
                .with_ansi(false)
                .with_target(true)
                .with_span_events(span_events)
                .with_writer(io::stderr)
                .finish(),
        )),
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
