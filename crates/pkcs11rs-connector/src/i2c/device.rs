use super::{I2cYubiHsmSpec, ReadyGpioSpec};
use crate::registry::TransportError;
use gpiocdev_uapi::v2 as gpio;
use std::{
    fs::{File, OpenOptions},
    io::{self, Read, Write},
    os::fd::AsRawFd,
    thread,
    time::{Duration, Instant},
};

const I2C_SLAVE: libc::c_ulong = 0x0703;
const FRAME_HEADER_LENGTH: usize = 3;
const MAX_FRAME_LENGTH: usize = 3_136;
const MAX_FRAME_DATA_LENGTH: usize = MAX_FRAME_LENGTH - FRAME_HEADER_LENGTH;
const BUS_LOCK_RETRY_DELAY: Duration = Duration::from_millis(2);
const DEVICE_INFO_REQUEST: [u8; 3] = [0x06, 0x00, 0x00];
const DEVICE_INFO_RESPONSE: u8 = 0x86;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct I2cDeviceIdentity {
    pub(super) serial: u32,
    pub(super) version: [u8; 3],
}

fn device_error(operation: &str, error: impl std::fmt::Display) -> TransportError {
    TransportError::device(format!("{operation}: {error}"))
}

pub(super) struct YubiHsmI2cDevice {
    bus: File,
    ready: ReadyLine,
    endpoint: I2cYubiHsmSpec,
    timeout: Duration,
}

impl YubiHsmI2cDevice {
    pub(super) fn open(
        endpoint: I2cYubiHsmSpec,
        timeout: Duration,
    ) -> Result<(Self, I2cDeviceIdentity), TransportError> {
        if timeout.is_zero() {
            return Err(TransportError::device(String::from(
                "I2C response timeout must be greater than zero",
            )));
        }
        let bus = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&endpoint.bus)
            .map_err(|error| device_error("open I2C bus", error))?;
        if unsafe {
            libc::ioctl(
                bus.as_raw_fd(),
                I2C_SLAVE,
                libc::c_ulong::from(endpoint.address),
            )
        } != 0
        {
            return Err(device_error(
                "select I2C target address",
                io::Error::last_os_error(),
            ));
        }
        let ready = ReadyLine::open(&endpoint.ready)?;
        let mut device = Self {
            bus,
            ready,
            endpoint,
            timeout,
        };
        let identity = device.identity()?;
        Ok((device, identity))
    }

    fn identity(&mut self) -> Result<I2cDeviceIdentity, TransportError> {
        let response = self.transmit(&DEVICE_INFO_REQUEST)?;
        if response.len() < 12 || response[0] != DEVICE_INFO_RESPONSE {
            return Err(TransportError::device(String::from(
                "I2C endpoint did not return a valid YubiHSM DeviceInfo response",
            )));
        }
        Ok(I2cDeviceIdentity {
            version: response[3..6].try_into().expect("checked response length"),
            serial: u32::from_be_bytes(
                response[6..10].try_into().expect("checked response length"),
            ),
        })
    }

    pub(super) fn transmit(&mut self, request: &[u8]) -> Result<Vec<u8>, TransportError> {
        let timeout = self.timeout;
        validate_request(request)?;
        let deadline = Instant::now() + timeout;
        let bus_lock = BusLock::acquire(&self.bus, deadline)?;
        self.ready.listen_for(gpio::LineFlags::EDGE_RISING)?;
        self.ready.discard_events()?;
        write_transaction(&mut self.bus, request)
            .map_err(|error| device_error("write I2C request", error))?;
        // Arm a single edge: Linux's both-edge threaded handler infers the
        // direction from a later pin reading and can mislabel a fast pulse.
        if !self.ready.wait_for_ack(deadline)? {
            return Err(TransportError::device(
                "I2C target did not acknowledge request cleanup",
            ));
        }
        self.ready.listen_for(gpio::LineFlags::EDGE_FALLING)?;
        drop(bus_lock);
        if !self.ready.wait_for_level(true, deadline)? {
            return Err(self.response_timeout(timeout));
        }
        let _bus_lock = BusLock::acquire(&self.bus, deadline)?;
        let mut header = [0_u8; FRAME_HEADER_LENGTH];
        read_transaction(&mut self.bus, &mut header)
            .map_err(|error| device_error("read I2C response header", error))?;
        if header[0] != request[0] | 0x80 && header[0] != 0x7f {
            return Err(TransportError::device("unexpected I2C response command"));
        }
        let length = u16::from_be_bytes([header[1], header[2]]) as usize;
        if length > MAX_FRAME_DATA_LENGTH {
            return Err(TransportError::device(format!(
                "I2C response declares invalid {length}-byte payload"
            )));
        }
        let mut response = Vec::with_capacity(FRAME_HEADER_LENGTH + length);
        response.extend_from_slice(&header);
        if length != 0 {
            let start = response.len();
            response.resize(start + length, 0);
            read_transaction(&mut self.bus, &mut response[start..])
                .map_err(|error| device_error("read I2C response payload", error))?;
        }
        // READY remains asserted. The next request clears any unread data;
        // the controller's exact-length read is the successful completion.
        Ok(response)
    }

    fn response_timeout(&self, timeout: Duration) -> TransportError {
        TransportError::device(format!(
            "I2C target 0x{:02x} response timed out after {:?}",
            self.endpoint.address, timeout
        ))
    }
}

struct BusLock(File);

impl BusLock {
    fn acquire(bus: &File, deadline: Instant) -> Result<Self, TransportError> {
        let lock = bus
            .try_clone()
            .map_err(|error| device_error("duplicate I2C bus descriptor", error))?;
        loop {
            if Instant::now() >= deadline {
                return Err(TransportError::device(String::from(
                    "timed out waiting for exclusive I2C bus access",
                )));
            }
            if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0 {
                return Ok(Self(lock));
            }
            let error = io::Error::last_os_error();
            match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock => thread::sleep(BUS_LOCK_RETRY_DELAY),
                _ => return Err(device_error("lock I2C bus", error)),
            }
        }
    }
}

impl Drop for BusLock {
    fn drop(&mut self) {
        // The owned duplicate keeps the open file description alive until unlock.
        unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

fn validate_request(request: &[u8]) -> Result<(), TransportError> {
    if request.len() < FRAME_HEADER_LENGTH {
        return Err(TransportError::invalid_frame(
            "YubiHSM request has no complete header",
        ));
    }
    let expected = FRAME_HEADER_LENGTH + u16::from_be_bytes([request[1], request[2]]) as usize;
    if request.len() != expected {
        return Err(TransportError::invalid_frame(format!(
            "invalid YubiHSM request length: {} bytes, expected {expected}",
            request.len()
        )));
    }
    if request.len() > MAX_FRAME_LENGTH {
        return Err(TransportError::too_large(format!(
            "YubiHSM request exceeds {MAX_FRAME_LENGTH} bytes"
        )));
    }
    Ok(())
}

struct ReadyLine {
    lines: File,
}

impl ReadyLine {
    fn open(spec: &ReadyGpioSpec) -> Result<Self, TransportError> {
        let chip = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&spec.chip)
            .map_err(|error| device_error("open READY GPIO chip", error))?;
        let request = gpio::LineRequest {
            offsets: gpio::Offsets::from_slice(&[spec.offset]),
            consumer: gpio::Name::from_bytes(b"pkcs11rs-i2c"),
            config: gpio::LineConfig {
                flags: gpio::LineFlags::INPUT
                    | gpio::LineFlags::EDGE_RISING
                    | gpio::LineFlags::BIAS_PULL_UP,
                ..Default::default()
            },
            num_lines: 1,
            ..Default::default()
        };
        let lines = gpio::get_line(&chip, request)
            .map_err(|error| device_error("request READY GPIO line", error))?;
        Ok(Self { lines })
    }

    fn listen_for(&self, edge: gpio::LineFlags) -> Result<(), TransportError> {
        gpio::set_line_config(
            &self.lines,
            gpio::LineConfig {
                flags: gpio::LineFlags::INPUT | gpio::LineFlags::BIAS_PULL_UP | edge,
                ..Default::default()
            },
        )
        .map_err(|error| device_error("configure READY edge", error))
    }

    fn read_edge(&self) -> Result<u32, TransportError> {
        let mut words = [0_u64; std::mem::size_of::<gpio::LineEdgeEvent>() / 8];
        let length = gpio::read_event(&self.lines, &mut words)
            .map_err(|error| device_error("read READY GPIO edge", error))?;
        if length != words.len() {
            return Err(TransportError::device("short READY GPIO edge event"));
        }
        gpio::LineEdgeEvent::from_slice(&words)
            .map(|event| event.kind)
            .map_err(|error| device_error("decode READY GPIO edge", error))
    }

    fn discard_events(&self) -> Result<(), TransportError> {
        while gpio::wait_event(&self.lines, Duration::ZERO)
            .map_err(|error| device_error("drain READY events", error))?
        {
            self.read_edge()?;
        }
        Ok(())
    }

    fn wait_for_ack(&self, deadline: Instant) -> Result<bool, TransportError> {
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            match gpio::wait_event(&self.lines, remaining) {
                Ok(false) => return Ok(false),
                Err(gpio::Error::Os(gpio::Errno(libc::EINTR))) => continue,
                Err(error) => return Err(device_error("wait for request acknowledgement", error)),
                Ok(true) => {}
            }
            // READY is active-low: a physical rising edge acknowledges cleanup.
            if self.read_edge()? == gpio::LineEdgeEventKind::RisingEdge as u32 {
                return Ok(true);
            }
        }
    }

    fn is_asserted(&self) -> Result<bool, TransportError> {
        let mut values = gpio::LineValues { bits: 0, mask: 1 };
        gpio::get_line_values(&self.lines, &mut values)
            .map_err(|error| device_error("read READY GPIO level", error))?;
        Ok(values.bits & 1 == 0)
    }

    fn wait_for_level(
        &mut self,
        asserted: bool,
        deadline: Instant,
    ) -> Result<bool, TransportError> {
        loop {
            if self.is_asserted()? == asserted {
                return Ok(true);
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(false);
            }
            match gpio::wait_event(&self.lines, remaining) {
                Ok(false) => return Ok(false),
                Err(gpio::Error::Os(gpio::Errno(libc::EINTR))) => continue,
                Err(error) => return Err(device_error("wait for READY GPIO edge", error)),
                Ok(true) => {}
            }
            self.read_edge()?;
        }
    }
}

fn write_transaction(bus: &mut File, bytes: &[u8]) -> io::Result<()> {
    match bus.write(bytes)? {
        length if length == bytes.len() => Ok(()),
        length => Err(io::Error::new(
            io::ErrorKind::WriteZero,
            format!("short I2C write: {length} of {} bytes", bytes.len()),
        )),
    }
}

fn read_transaction(bus: &mut File, bytes: &mut [u8]) -> io::Result<()> {
    match bus.read(bytes)? {
        length if length == bytes.len() => Ok(()),
        length => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            format!("short I2C read: {length} of {} bytes", bytes.len()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bus_lock_serializes_independent_handles_and_releases_on_drop() {
        use std::{os::unix::fs::OpenOptionsExt, time::SystemTime};

        let path = std::env::temp_dir().join(format!(
            "pkcs11rs-i2c-lock-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let first = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        let second = File::open(&path).unwrap();
        std::fs::remove_file(path).unwrap();
        let held = BusLock::acquire(&first, Instant::now() + Duration::from_secs(1)).unwrap();
        assert!(BusLock::acquire(&second, Instant::now() + Duration::from_millis(5)).is_err());
        drop(held);
        let acquired = BusLock::acquire(&second, Instant::now() + Duration::from_secs(1))
            .expect("dropping the first endpoint's guard must unlock the physical bus");
        drop(acquired);
        assert!(BusLock::acquire(&first, Instant::now() + Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn validates_request_framing() {
        assert!(validate_request(&[0x01, 0, 1, 0xaa]).is_ok());
        assert_eq!(
            validate_request(&[0x01, 0, 1]).unwrap_err().kind(),
            crate::registry::TransportErrorKind::InvalidCommandFrame
        );
    }
}
