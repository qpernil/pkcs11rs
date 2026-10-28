//! Opt-in phase measurements. Logging happens after the exchange's locks drop.
use std::{
    path::Path,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

const TARGET: &str = "pkcs11rs_connector::i2c::timing";
static NEXT_EXCHANGE: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug)]
pub(super) enum Phase {
    RequestLock,
    RequestSetup,
    RequestWrite,
    CleanupAck,
    ResponseReady,
    ResponseLock,
    ResponseSetup,
    HeaderRead,
    BodyRead,
    Complete,
}

impl Phase {
    fn name(self) -> &'static str {
        match self {
            Self::RequestLock => "request_lock",
            Self::RequestSetup => "request_setup",
            Self::RequestWrite => "request_write",
            Self::CleanupAck => "cleanup_ack",
            Self::ResponseReady => "response_ready",
            Self::ResponseLock => "response_lock",
            Self::ResponseSetup => "response_setup",
            Self::HeaderRead => "header_read",
            Self::BodyRead => "body_read",
            Self::Complete => "complete",
        }
    }
}

pub(super) struct ExchangeTiming<'a> {
    bus: &'a Path,
    address: u16,
    request_bytes: usize,
    response_bytes: usize,
    id: u64,
    started: Option<Instant>,
    phase_started: Option<Instant>,
    phase: Phase,
    elapsed: [Duration; 10],
    complete: bool,
}

impl<'a> ExchangeTiming<'a> {
    pub(super) fn new(bus: &'a Path, address: u16, request_bytes: usize) -> Self {
        let started = tracing::enabled!(target: TARGET, tracing::Level::DEBUG).then(Instant::now);
        Self {
            bus,
            address,
            request_bytes,
            response_bytes: 0,
            id: if started.is_some() {
                NEXT_EXCHANGE.fetch_add(1, Ordering::Relaxed)
            } else {
                0
            },
            started,
            phase_started: started,
            phase: Phase::RequestLock,
            elapsed: [Duration::ZERO; 10],
            complete: false,
        }
    }

    pub(super) fn enter(&mut self, phase: Phase) {
        if self.started.is_some() {
            self.enter_at(phase, Instant::now());
        }
    }

    fn enter_at(&mut self, phase: Phase, now: Instant) {
        if let Some(previous) = self.phase_started {
            self.elapsed[self.phase as usize] += now.duration_since(previous);
            self.phase_started = Some(now);
        }
        self.phase = phase;
    }

    pub(super) fn complete(&mut self, response_bytes: usize) {
        self.response_bytes = response_bytes;
        self.enter(Phase::Complete);
        self.complete = true;
    }
}

fn micros(duration: Duration) -> u64 {
    u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
}

impl Drop for ExchangeTiming<'_> {
    fn drop(&mut self) {
        let Some(started) = self.started else {
            return;
        };
        let now = Instant::now();
        self.enter_at(self.phase, now);
        let elapsed = &self.elapsed;
        tracing::debug!(target: TARGET,
            exchange_id = self.id,
            bus = %self.bus.display(), address = self.address,
            request_bytes = self.request_bytes, response_bytes = self.response_bytes,
            outcome = if self.complete { "ok" } else { "error" },
            last_phase = self.phase.name(), total_us = micros(now.duration_since(started)),
            request_lock_us = micros(elapsed[Phase::RequestLock as usize]),
            request_setup_us = micros(elapsed[Phase::RequestSetup as usize]),
            request_write_us = micros(elapsed[Phase::RequestWrite as usize]),
            cleanup_ack_us = micros(elapsed[Phase::CleanupAck as usize]),
            response_ready_us = micros(elapsed[Phase::ResponseReady as usize]),
            response_lock_us = micros(elapsed[Phase::ResponseLock as usize]),
            response_setup_us = micros(elapsed[Phase::ResponseSetup as usize]),
            header_read_us = micros(elapsed[Phase::HeaderRead as usize]),
            body_read_us = micros(elapsed[Phase::BodyRead as usize]),
            "I2C exchange timing");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::Write,
        sync::{Arc, Mutex},
    };
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for Capture {
        type Writer = Self;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn phase_intervals_partition_wait_and_transfer_time() {
        let start = Instant::now();
        let mut timing = ExchangeTiming::new(Path::new("test-bus"), 0x24, 4);
        timing.started = Some(start);
        timing.phase_started = Some(start);
        timing.enter_at(Phase::RequestWrite, start + Duration::from_millis(17));
        timing.enter_at(Phase::ResponseReady, start + Duration::from_millis(22));
        assert_eq!(
            timing.elapsed[Phase::RequestLock as usize],
            Duration::from_millis(17)
        );
        assert_eq!(
            timing.elapsed[Phase::RequestWrite as usize],
            Duration::from_millis(5)
        );
        timing.started = None; // Synthetic clock: no real-time Drop measurement.
    }

    #[test]
    fn early_error_and_success_both_emit_metadata_only() {
        let capture = Capture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::DEBUG)
            .without_time()
            .with_ansi(false)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let fail = || -> Result<(), &'static str> {
                let mut timing = ExchangeTiming::new(Path::new("test-bus"), 0x24, 4);
                timing.enter(Phase::RequestSetup);
                Err("simulated setup failure")?;
                Ok(())
            };
            assert!(fail().is_err());
            let mut timing = ExchangeTiming::new(Path::new("test-bus"), 0x25, 4);
            timing.enter(Phase::BodyRead);
            timing.complete(4);
        });
        let text = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
        assert_eq!(text.matches("I2C exchange timing").count(), 2);
        assert!(text.contains("outcome=\"error\""));
        assert!(text.contains("last_phase=\"request_setup\""));
        assert!(text.contains("outcome=\"ok\""));
        assert!(text.contains("request_lock_us="));
        assert!(text.contains("response_lock_us="));
        assert!(!text.contains("simulated setup failure"));
    }
}
