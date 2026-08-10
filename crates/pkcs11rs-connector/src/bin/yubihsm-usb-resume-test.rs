use clap::Parser;
use pkcs11rs_local_hardware::{YubiHsmUsbCandidate, YubiHsmUsbDevice, yubihsm_candidates};
use std::{process::ExitCode, time::Duration};

const DEVICE_INFO: &[u8] = &[0x06, 0x00, 0x00];
const DEVICE_INFO_RESPONSE: u8 = 0x86;
const RESUME_CHECK_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Debug, Parser)]
#[command(
    version,
    about = "Test a YubiHSM USB handle across a real Mac sleep/wake cycle"
)]
struct Args {
    /// YubiHSM serial. Required when multiple identifiable devices are attached.
    #[arg(long)]
    serial: Option<String>,

    /// Maximum time waiting for each cleartext DeviceInfo response.
    #[arg(long, default_value_t = 5)]
    response_timeout_seconds: u64,

    /// Extra delayed-tick duration used to identify a real sleep/wake cycle.
    #[arg(long, default_value_t = 10)]
    resume_gap_seconds: u64,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(error) => {
            eprintln!("ERROR {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<bool, String> {
    if args.response_timeout_seconds == 0 {
        return Err("--response-timeout-seconds must be greater than zero".into());
    }
    if args.resume_gap_seconds == 0 {
        return Err("--resume-gap-seconds must be greater than zero".into());
    }

    println!("YubiHSM USB sleep/wake test");
    println!("The test sends only the unauthenticated cleartext DeviceInfo command.");
    println!("It does not create, use, or close a YubiHSM session.");
    println!("Stop the connector and every other YubiHSM USB user before running it.");

    let (serial, candidate) = select_initial(args.serial.as_deref()).await?;
    println!("SELECTED serial={serial} id={:?}", candidate.id());
    let mut original = open_and_claim("baseline", candidate).await?;
    let response_timeout = Duration::from_secs(args.response_timeout_seconds);
    device_info("baseline.original_handle", &original, response_timeout).await?;

    println!(
        "READY action=sleep_the_mac; waiting for a wall-clock gap greater than {} seconds",
        RESUME_CHECK_INTERVAL.as_secs() + args.resume_gap_seconds
    );
    let gap = wait_for_resume(Duration::from_secs(args.resume_gap_seconds)).await;
    println!("RESUME gap_ms={}", gap.as_millis());

    let original_usable =
        observe_device_info("post_wake.original_handle", &original, response_timeout).await;

    // Enumeration itself does not claim the interface. Do it while retaining
    // the original handle to distinguish enumeration recovery from claim
    // recovery, then discard the result so the full refresh starts cleanly.
    let enumeration_while_held = timed_select(&serial, "post_wake.enumerate_while_original_held")
        .await
        .is_ok();

    original.disconnect();
    drop(original);
    println!("RESULT phase=post_wake.release_original outcome=success");
    tokio::time::sleep(Duration::from_millis(100)).await;

    let refreshed = match timed_select(&serial, "refresh.enumerate").await {
        Ok(candidate) => match open_and_claim("refresh", candidate).await {
            Ok(device) => {
                observe_device_info("refresh.fresh_handle", &device, response_timeout).await
            }
            Err(error) => {
                println!("RESULT phase=refresh.open_or_claim outcome=failed error={error:?}");
                false
            }
        },
        Err(error) => {
            println!("RESULT phase=refresh.enumerate outcome=failed error={error:?}");
            false
        }
    };

    println!(
        "SUMMARY original_handle={} enumeration_while_original_held={} fresh_refresh={}",
        outcome(original_usable),
        outcome(enumeration_while_held),
        outcome(refreshed)
    );
    Ok(refreshed)
}

fn outcome(value: bool) -> &'static str {
    if value { "usable" } else { "failed" }
}

async fn select_initial(
    requested_serial: Option<&str>,
) -> Result<(String, YubiHsmUsbCandidate), String> {
    let started = std::time::Instant::now();
    let candidates = yubihsm_candidates()
        .await
        .map_err(|error| format!("initial USB enumeration failed: {error}"))?;
    println!(
        "RESULT phase=baseline.enumerate outcome=success duration_ms={} candidates={}",
        started.elapsed().as_millis(),
        candidates.len()
    );

    let mut identified = Vec::new();
    for candidate in candidates {
        let id = candidate.id();
        match candidate.serial().await {
            Ok(Some(serial)) if !serial.is_empty() => identified.push((serial, candidate)),
            Ok(_) => println!(
                "RESULT phase=baseline.identify outcome=skipped id={id:?} error=missing_serial"
            ),
            Err(error) => {
                println!("RESULT phase=baseline.identify outcome=failed id={id:?} error={error:?}")
            }
        }
    }

    if let Some(requested_serial) = requested_serial {
        return identified
            .into_iter()
            .find(|(serial, _)| serial == requested_serial)
            .ok_or_else(|| format!("no identifiable YubiHSM has serial {requested_serial}"));
    }
    match identified.len() {
        0 => Err("no identifiable YubiHSM is attached".into()),
        1 => Ok(identified.pop().expect("length checked")),
        _ => {
            let serials = identified
                .iter()
                .map(|(serial, _)| serial.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!(
                "multiple YubiHSMs are attached ({serials}); select one with --serial"
            ))
        }
    }
}

async fn timed_select(serial: &str, phase: &str) -> Result<YubiHsmUsbCandidate, String> {
    let started = std::time::Instant::now();
    let candidates = yubihsm_candidates()
        .await
        .map_err(|error| format!("USB enumeration failed: {error}"))?;
    let count = candidates.len();
    for candidate in candidates {
        match candidate.serial().await {
            Ok(Some(candidate_serial)) if candidate_serial == serial => {
                println!(
                    "RESULT phase={phase} outcome=success duration_ms={} candidates={count}",
                    started.elapsed().as_millis()
                );
                return Ok(candidate);
            }
            Ok(_) => {}
            Err(error) => println!(
                "RESULT phase={phase}.identify outcome=failed id={:?} error={error:?}",
                candidate.id()
            ),
        }
    }
    Err(format!(
        "serial {serial} not found among {count} candidates"
    ))
}

async fn open_and_claim(
    phase: &str,
    candidate: YubiHsmUsbCandidate,
) -> Result<YubiHsmUsbDevice, String> {
    let started = std::time::Instant::now();
    let mut device = candidate.open().await.map_err(|error| {
        format!(
            "open failed after {} ms: {error}",
            started.elapsed().as_millis()
        )
    })?;
    println!(
        "RESULT phase={phase}.open outcome=success duration_ms={}",
        started.elapsed().as_millis()
    );

    let started = std::time::Instant::now();
    device.connect().await.map_err(|error| {
        format!(
            "claim failed after {} ms: {error}",
            started.elapsed().as_millis()
        )
    })?;
    println!(
        "RESULT phase={phase}.claim outcome=success duration_ms={}",
        started.elapsed().as_millis()
    );
    Ok(device)
}

async fn device_info(
    phase: &str,
    device: &YubiHsmUsbDevice,
    response_timeout: Duration,
) -> Result<(), String> {
    let started = std::time::Instant::now();
    let mut response = vec![0; device.buffer_size()];
    let received = device
        .transmit(DEVICE_INFO, &mut response, response_timeout)
        .await
        .map_err(|error| {
            format!(
                "DeviceInfo failed after {} ms: {error}",
                started.elapsed().as_millis()
            )
        })?;
    validate_device_info(received)?;
    println!(
        "RESULT phase={phase}.device_info outcome=success duration_ms={} response_bytes={}",
        started.elapsed().as_millis(),
        received.len()
    );
    Ok(())
}

async fn observe_device_info(
    phase: &str,
    device: &YubiHsmUsbDevice,
    response_timeout: Duration,
) -> bool {
    match device_info(phase, device, response_timeout).await {
        Ok(()) => true,
        Err(error) => {
            println!("RESULT phase={phase}.device_info outcome=failed error={error:?}");
            false
        }
    }
}

fn validate_device_info(response: &[u8]) -> Result<(), String> {
    if response.len() < 3 {
        return Err(format!(
            "short DeviceInfo response: {} bytes",
            response.len()
        ));
    }
    if response[0] != DEVICE_INFO_RESPONSE {
        return Err(format!(
            "unexpected DeviceInfo response command 0x{:02x}",
            response[0]
        ));
    }
    let declared = usize::from(u16::from_be_bytes([response[1], response[2]])) + 3;
    if response.len() != declared {
        return Err(format!(
            "invalid DeviceInfo response length: actual {}, declared {declared}",
            response.len()
        ));
    }
    Ok(())
}

async fn wait_for_resume(extra_gap: Duration) -> Duration {
    let mut last_check = std::time::SystemTime::now();
    loop {
        tokio::time::sleep(RESUME_CHECK_INTERVAL).await;
        let now = std::time::SystemTime::now();
        if let Ok(gap) = now.duration_since(last_check) {
            if gap > RESUME_CHECK_INTERVAL + extra_gap {
                return gap;
            }
        }
        last_check = now;
    }
}
