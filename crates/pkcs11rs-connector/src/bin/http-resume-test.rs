#[path = "../http_timeout.rs"]
mod http_timeout;

use axum::{routing::get, Router};
use clap::Parser;
use http_timeout::WriteTimeoutAcceptor;
use hyper_util::rt::TokioTimer;
use std::{
    net::{SocketAddr, TcpListener as StdTcpListener},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Parser)]
#[command(about = "Test HTTP listener and connection behavior across system sleep")]
struct Args {
    /// Address on which the isolated HTTP test server listens.
    #[arg(long, default_value = "0.0.0.0:12346")]
    listen: SocketAddr,

    /// Wall-clock gap treated as evidence that the Mac slept.
    #[arg(long, default_value_t = 12)]
    resume_gap_seconds: u64,

    /// Maximum time for each TCP connect and HTTP request after wake.
    #[arg(long, default_value_t = 5)]
    request_timeout_seconds: u64,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let request_timeout = Duration::from_secs(args.request_timeout_seconds);
    let resume_gap = Duration::from_secs(args.resume_gap_seconds);

    let listener = StdTcpListener::bind(args.listen)?;
    listener.set_nonblocking(true)?;
    let bound = listener.local_addr()?;
    let client_address = SocketAddr::from(([127, 0, 0, 1], bound.port()));
    let requests = Arc::new(AtomicU64::new(0));
    let app_requests = requests.clone();
    let app = Router::new().route(
        "/probe",
        get(move || {
            let requests = app_requests.clone();
            async move {
                let request = requests.fetch_add(1, Ordering::Relaxed) + 1;
                println!("SERVER request={request} outcome=received");
                "ok\n"
            }
        }),
    );

    let handle = axum_server::Handle::new();
    let mut server = axum_server::from_tcp(listener)?
        .map(|acceptor| WriteTimeoutAcceptor::new(acceptor, HTTP_STAGE_TIMEOUT))
        .handle(handle.clone());
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HTTP_STAGE_TIMEOUT));
    let server_task = tokio::spawn(server.serve(app.into_make_service()));

    println!("HTTP listener sleep/wake test");
    println!("This test does not enumerate USB devices or send YubiHSM commands.");
    println!("LISTEN address={bound} probe=http://{client_address}/probe");

    let mut retained = connect(client_address, request_timeout).await?;
    request(
        "baseline.retained_connection",
        &mut retained,
        request_timeout,
    )
    .await?;

    println!(
        "READY action=sleep_the_mac; waiting for a wall-clock gap greater than {} seconds",
        resume_gap.as_secs()
    );
    let observed_gap = wait_for_resume(resume_gap).await;
    println!("RESUME gap_ms={}", observed_gap.as_millis());

    let retained_request = observe_request(
        "post_wake.retained_connection",
        &mut retained,
        request_timeout,
    );
    let fresh_request = observe_fresh_request(client_address, request_timeout);
    let (retained_usable, fresh_usable) = tokio::join!(retained_request, fresh_request);

    println!(
        "SUMMARY retained_connection={} fresh_connect_and_accept={}",
        usability(retained_usable),
        usability(fresh_usable)
    );
    println!(
        "NOTE retained_connection is informational; the server may close an idle HTTP/1.1 connection under its header-read deadline"
    );
    println!("NOTE fresh_connect_and_accept is the listener/accept pass criterion");

    handle.graceful_shutdown(Some(Duration::from_secs(1)));
    match tokio::time::timeout(Duration::from_secs(2), server_task).await {
        Ok(result) => result??,
        Err(_) => return Err("HTTP test server did not stop".into()),
    }
    if !fresh_usable {
        return Err("fresh TCP connect or HTTP accept failed after wake".into());
    }
    Ok(())
}

async fn wait_for_resume(threshold: Duration) -> Duration {
    let mut previous = SystemTime::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = SystemTime::now();
        let elapsed = now.duration_since(previous).unwrap_or_default();
        if elapsed > threshold {
            return elapsed;
        }
        previous = now;
    }
}

async fn connect(address: SocketAddr, timeout: Duration) -> Result<TcpStream, String> {
    let started = Instant::now();
    match tokio::time::timeout(timeout, TcpStream::connect(address)).await {
        Ok(Ok(stream)) => {
            println!(
                "RESULT phase=baseline.connect outcome=success duration_ms={}",
                started.elapsed().as_millis()
            );
            Ok(stream)
        }
        Ok(Err(error)) => Err(format!(
            "TCP connect failed after {} ms: {error}",
            started.elapsed().as_millis()
        )),
        Err(_) => Err(format!(
            "TCP connect timed out after {} ms",
            started.elapsed().as_millis()
        )),
    }
}

async fn observe_fresh_request(address: SocketAddr, timeout: Duration) -> bool {
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, async {
        let mut stream = TcpStream::connect(address)
            .await
            .map_err(|error| format!("TCP connect failed: {error}"))?;
        request_inner(&mut stream).await
    })
    .await;
    match result {
        Ok(Ok(())) => {
            println!(
                "RESULT phase=post_wake.fresh_connect_and_request outcome=success duration_ms={}",
                started.elapsed().as_millis()
            );
            true
        }
        Ok(Err(error)) => {
            println!(
                "RESULT phase=post_wake.fresh_connect_and_request outcome=failed duration_ms={} error={error}",
                started.elapsed().as_millis()
            );
            false
        }
        Err(_) => {
            println!(
                "RESULT phase=post_wake.fresh_connect_and_request outcome=timeout duration_ms={}",
                started.elapsed().as_millis()
            );
            false
        }
    }
}

async fn observe_request(phase: &str, stream: &mut TcpStream, timeout: Duration) -> bool {
    match request(phase, stream, timeout).await {
        Ok(()) => true,
        Err(error) => {
            println!("RESULT phase={phase} outcome=failed error={error}");
            false
        }
    }
}

async fn request(phase: &str, stream: &mut TcpStream, timeout: Duration) -> Result<(), String> {
    let started = Instant::now();
    let result = tokio::time::timeout(timeout, request_inner(stream)).await;
    match result {
        Ok(Ok(())) => {
            println!(
                "RESULT phase={phase} outcome=success duration_ms={}",
                started.elapsed().as_millis()
            );
            Ok(())
        }
        Ok(Err(error)) => Err(format!(
            "HTTP request failed after {} ms: {error}",
            started.elapsed().as_millis()
        )),
        Err(_) => Err(format!(
            "HTTP request timed out after {} ms",
            started.elapsed().as_millis()
        )),
    }
}

async fn request_inner(stream: &mut TcpStream) -> Result<(), String> {
    stream
        .write_all(b"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n")
        .await
        .map_err(|error| format!("write failed: {error}"))?;

    let mut response = Vec::with_capacity(256);
    let mut chunk = [0u8; 256];
    loop {
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("read failed: {error}"))?;
        if read == 0 {
            return Err("server closed the connection before the complete response".into());
        }
        response.extend_from_slice(&chunk[..read]);
        if complete_response_length(&response).is_some_and(|length| response.len() >= length) {
            break;
        }
        if response.len() > 8_192 {
            return Err("response exceeded 8192 bytes".into());
        }
    }

    if !response.starts_with(b"HTTP/1.1 200 ") && !response.starts_with(b"HTTP/1.0 200 ") {
        return Err(format!(
            "unexpected response: {}",
            String::from_utf8_lossy(&response)
        ));
    }
    Ok(())
}

fn complete_response_length(response: &[u8]) -> Option<usize> {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")?
        + 4;
    let headers = std::str::from_utf8(&response[..header_end]).ok()?;
    let content_length = headers.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("content-length")
            .then(|| value.trim().parse::<usize>().ok())
            .flatten()
    })?;
    header_end.checked_add(content_length)
}

fn usability(usable: bool) -> &'static str {
    if usable {
        "usable"
    } else {
        "unusable"
    }
}
