//! Read-only USB qualification of the explicitly selected virtual YubiHSM.
#![cfg(feature = "blocking")]

use pkcs11rs_local_hardware::{YubiHsmUsbDevice, yubihsm_candidates_blocking};
use std::time::Duration;

const SERIAL_ENV: &str = "PKCS11RS_YUBIHSM_USB_ECHO_SERIAL";
const TIMEOUT: Duration = Duration::from_secs(2);
const FRAME_LENGTHS: &[usize] = &[
    3, 4, 63, 64, 65, 127, 128, 129, 191, 192, 193, 319, 320, 321, 3135, 3136, 3137, 8191, 8192, 63,
];

fn selected_device() -> YubiHsmUsbDevice {
    let serial = std::env::var(SERIAL_ENV).expect("Set the explicit virtual HSM serial");
    let matching: Vec<_> = yubihsm_candidates_blocking()
        .unwrap()
        .into_iter()
        .filter(|candidate| {
            candidate.manufacturer() == "Virtual USB Gadget"
                && candidate.serial_blocking().unwrap().as_deref() == Some(serial.as_str())
        })
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "Expected exactly one selected virtual HSM"
    );
    matching
        .into_iter()
        .next()
        .unwrap()
        .open_blocking()
        .unwrap()
}

fn echo(length: usize) -> Vec<u8> {
    let mut frame = vec![0x01];
    frame.extend_from_slice(&u16::try_from(length - 3).unwrap().to_be_bytes());
    frame.extend((3..length).map(|index| index as u8));
    frame
}

fn check(mut expected: Vec<u8>, actual: &[u8], mode: &str) {
    expected[0] |= 0x80;
    assert_eq!(actual, expected, "{mode}, frame length {}", expected.len());
    println!("{mode}: {}-byte Echo passed", expected.len());
}

#[test]
#[ignore = "requires an explicitly selected virtual USB gadget; read-only Echo"]
fn blocking_echo_packet_boundaries() {
    let mut device = selected_device();
    device.connect_blocking().unwrap();
    for &length in FRAME_LENGTHS {
        let command = echo(length);
        // Deliberately use an exact-fit caller buffer. It must not determine
        // the USB read size or leave a response ZLP for the next command.
        let mut buffer = vec![0; length];
        let response = device
            .transmit_blocking(&command, &mut buffer, TIMEOUT)
            .unwrap();
        check(command.clone(), response, "blocking borrowed");
        let response = device
            .transmit_owned_blocking(command.clone(), TIMEOUT)
            .unwrap();
        check(command, &response, "blocking owned");
    }
}

#[cfg(feature = "async-tokio")]
#[tokio::test(flavor = "current_thread")]
#[ignore = "requires an explicitly selected virtual USB gadget; read-only Echo"]
async fn asynchronous_echo_packet_boundaries() {
    let mut device = selected_device();
    device.connect().await.unwrap();
    for &length in FRAME_LENGTHS {
        let command = echo(length);
        let mut buffer = vec![0; length];
        let response = device
            .transmit(&command, &mut buffer, TIMEOUT)
            .await
            .unwrap();
        check(command.clone(), response, "async borrowed");
        let response = device
            .transmit_owned(command.clone(), TIMEOUT)
            .await
            .unwrap();
        check(command, &response, "async owned");
    }
}
