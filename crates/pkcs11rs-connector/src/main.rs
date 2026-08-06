mod api;
mod http_timeout;
mod registry;
mod tls;

use api::{router, AppState};
use clap::Parser;
use http_timeout::WriteTimeoutAcceptor;
use hyper_util::rt::TokioTimer;
use registry::{spawn_discovery, DeviceRegistry};
use std::{
    future::Future,
    io,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::Arc,
    time::{Duration, SystemTime},
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ServerFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

const RESUME_CHECK_INTERVAL: Duration = Duration::from_secs(2);
const RESUME_GAP_THRESHOLD: Duration = Duration::from_secs(10);
const SERVER_RESTART_DELAY: Duration = Duration::from_secs(1);
const SERVER_STOP_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP2_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Address on which the connector listens.
    #[arg(long, default_value = "127.0.0.1:12345")]
    listen: SocketAddr,

    /// Permit unencrypted HTTP on a non-loopback address.
    #[arg(long)]
    allow_insecure_http: bool,

    /// PEM server certificate chain. Supplying this enables HTTPS.
    #[arg(long, requires = "tls_key")]
    tls_certificate: Option<PathBuf>,

    /// PEM server private key. Supplying this enables HTTPS.
    #[arg(long, requires = "tls_certificate")]
    tls_key: Option<PathBuf>,

    /// PEM CA certificates used to require and verify mTLS client certificates.
    #[arg(long, requires = "tls_certificate")]
    tls_client_ca: Option<PathBuf>,

    /// Serial exposed through the single-device legacy connector protocol.
    #[arg(long)]
    legacy_serial: Option<String>,

    /// Maximum time waiting for a YubiHSM USB command response.
    #[arg(long, default_value_t = 60)]
    command_timeout_seconds: u64,

    /// Maximum number of HTTP requests processed concurrently across all connections.
    #[arg(long, default_value_t = 64)]
    http_max_in_flight_requests: usize,
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "pkcs11rs_connector=info".into()),
        )
        .init();

    let args = Args::parse();
    validate_args(&args)?;
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut legacy_serial = args.legacy_serial.clone();

    loop {
        match serve_until_restart(&args, legacy_serial.clone()).await {
            Ok(ServeOutcome::Shutdown) => return Ok(()),
            Ok(ServeOutcome::Resume {
                gap,
                selected_legacy_serial,
            }) => {
                legacy_serial = selected_legacy_serial;
                tracing::warn!(
                    ?gap,
                    "system suspend detected; restarting connector services"
                );
            }
            Err(error) => {
                tracing::error!(%error, "connector service stopped; retrying");
                tokio::select! {
                    _ = tokio::signal::ctrl_c() => return Ok(()),
                    _ = tokio::time::sleep(SERVER_RESTART_DELAY) => {}
                }
            }
        }
    }
}

enum ServeOutcome {
    Shutdown,
    Resume {
        gap: Duration,
        selected_legacy_serial: Option<String>,
    },
}

async fn serve_until_restart(
    args: &Args,
    legacy_serial: Option<String>,
) -> Result<ServeOutcome, BoxError> {
    let registry = DeviceRegistry::new(Duration::from_secs(args.command_timeout_seconds));
    let discovery = spawn_discovery(registry.clone()).await?;
    let app = router(
        AppState {
            registry: registry.clone(),
            legacy_serial: legacy_serial.clone(),
        },
        args.http_max_in_flight_requests,
    );

    let handle = axum_server::Handle::new();
    let mut server = match connector_server(args, app, handle.clone()) {
        Ok(server) => server,
        Err(error) => {
            discovery.abort();
            return Err(error);
        }
    };
    let outcome = tokio::select! {
        result = &mut server => {
            discovery.abort();
            return result.map(|()| ServeOutcome::Shutdown).map_err(Into::into);
        }
        _ = tokio::signal::ctrl_c() => {
            handle.graceful_shutdown(Some(Duration::from_secs(10)));
            let result = server.await;
            discovery.abort();
            result?;
            ServeOutcome::Shutdown
        }
        gap = wait_for_resume() => {
            // Connections which survived suspend can retain unusable network and
            // USB state. Stop them promptly, then let the outer loop rebuild the
            // listener, registry, discovery watcher, and device handles.
            handle.shutdown();
            match tokio::time::timeout(SERVER_STOP_TIMEOUT, &mut server).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    tracing::warn!(%error, "HTTP server failed while stopping after resume");
                }
                Err(_) => {
                    tracing::warn!("HTTP server did not stop promptly after resume; dropping it");
                }
            }
            discovery.abort();
            let selected_legacy_serial = match legacy_serial {
                Some(serial) => Some(serial),
                None => registry.selected_legacy_serial().await,
            };
            ServeOutcome::Resume {
                gap,
                selected_legacy_serial,
            }
        }
    };
    Ok(outcome)
}

fn connector_server(
    args: &Args,
    app: axum::Router,
    handle: axum_server::Handle<SocketAddr>,
) -> Result<ServerFuture, BoxError> {
    let server: ServerFuture = match (&args.tls_certificate, &args.tls_key) {
        (Some(certificate), Some(key)) => {
            let config = tls::server_config(certificate, key, args.tls_client_ca.as_deref())?;
            tracing::info!(address = %args.listen, mtls = args.tls_client_ca.is_some(), "listening with HTTPS");
            let mut server = axum_server::bind_rustls(
                args.listen,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )
            .map(|acceptor| {
                WriteTimeoutAcceptor::new(
                    acceptor.handshake_timeout(HTTP_STAGE_TIMEOUT),
                    HTTP_STAGE_TIMEOUT,
                )
            })
            .handle(handle);
            configure_http(&mut server);
            Box::pin(server.serve(app.into_make_service()))
        }
        (None, None) => {
            tracing::info!(address = %args.listen, "listening with HTTP");
            let mut server = axum_server::bind(args.listen)
                .map(|acceptor| WriteTimeoutAcceptor::new(acceptor, HTTP_STAGE_TIMEOUT))
                .handle(handle);
            configure_http(&mut server);
            Box::pin(server.serve(app.into_make_service()))
        }
        _ => unreachable!("clap requires the TLS certificate and key together"),
    };
    Ok(server)
}

fn configure_http<A>(server: &mut axum_server::Server<SocketAddr, A>) {
    server
        .http_builder()
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Some(HTTP_STAGE_TIMEOUT));
    server
        .http_builder()
        .http2()
        .max_header_list_size(HTTP2_MAX_HEADER_LIST_SIZE);
}

async fn wait_for_resume() -> Duration {
    let mut last_check = SystemTime::now();
    loop {
        tokio::time::sleep(RESUME_CHECK_INTERVAL).await;
        let now = SystemTime::now();
        if let Ok(gap) = now.duration_since(last_check) {
            if is_resume_gap(gap) {
                return gap;
            }
        }
        last_check = now;
    }
}

fn is_resume_gap(gap: Duration) -> bool {
    gap > RESUME_CHECK_INTERVAL + RESUME_GAP_THRESHOLD
}

fn validate_args(args: &Args) -> Result<(), BoxError> {
    if args.command_timeout_seconds == 0 {
        return Err("--command-timeout-seconds must be greater than zero".into());
    }
    if args.http_max_in_flight_requests == 0 {
        return Err("--http-max-in-flight-requests must be greater than zero".into());
    }
    if args.http_max_in_flight_requests > tokio::sync::Semaphore::MAX_PERMITS {
        return Err("--http-max-in-flight-requests is too large".into());
    }
    if args.tls_certificate.is_none()
        && !args.listen.ip().is_loopback()
        && !args.allow_insecure_http
    {
        return Err(
            "refusing non-loopback HTTP; configure TLS or pass --allow-insecure-http".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::{Method, Request, Version};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
    use std::{
        fs,
        net::TcpListener,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };
    use tokio::{
        io::{AsyncRead, AsyncWrite},
        net::TcpStream,
        task::JoinHandle,
    };
    use tokio_rustls::{client::TlsStream, TlsConnector};

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct PemFiles {
        directory: PathBuf,
        certificate: PathBuf,
        key: PathBuf,
    }

    impl PemFiles {
        fn self_signed_localhost() -> (Self, rustls::pki_types::CertificateDer<'static>) {
            let rcgen::CertifiedKey { cert, key_pair } =
                rcgen::generate_simple_self_signed(vec![String::from("localhost")]).unwrap();
            let directory = std::env::temp_dir().join(format!(
                "pkcs11rs-connector-test-{}-{}",
                std::process::id(),
                NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&directory).unwrap();
            let certificate = directory.join("certificate.pem");
            let key = directory.join("key.pem");
            fs::write(&certificate, cert.pem()).unwrap();
            fs::write(&key, key_pair.serialize_pem()).unwrap();
            (
                Self {
                    directory,
                    certificate,
                    key,
                },
                cert.der().clone(),
            )
        }
    }

    impl Drop for PemFiles {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.directory);
        }
    }

    fn listener() -> (TcpListener, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        (listener, address)
    }

    fn spawn_http_server(
        app: axum::Router,
    ) -> (
        SocketAddr,
        axum_server::Handle<SocketAddr>,
        JoinHandle<std::io::Result<()>>,
    ) {
        let (listener, address) = listener();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp(listener)?
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });
        (address, handle, server)
    }

    fn spawn_https_server(
        app: axum::Router,
        config: rustls::ServerConfig,
    ) -> (
        SocketAddr,
        axum_server::Handle<SocketAddr>,
        JoinHandle<std::io::Result<()>>,
    ) {
        let (listener, address) = listener();
        let handle = axum_server::Handle::new();
        let server_handle = handle.clone();
        let server = tokio::spawn(async move {
            axum_server::from_tcp_rustls(
                listener,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )?
            .handle(server_handle)
            .serve(app.into_make_service())
            .await
        });
        (address, handle, server)
    }

    async fn send_http2<IO>(
        io: IO,
        method: Method,
        uri: String,
        body: &'static [u8],
    ) -> (Version, Vec<u8>)
    where
        IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(io),
        )
        .await
        .unwrap();
        let connection = tokio::spawn(connection);
        let response = sender
            .send_request(
                Request::builder()
                    .method(method)
                    .uri(uri)
                    .body(Full::new(Bytes::from_static(body)))
                    .unwrap(),
            )
            .await
            .unwrap();
        let version = response.version();
        let body = response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        drop(sender);
        connection.abort();
        (version, body)
    }

    fn https_client(certificate: rustls::pki_types::CertificateDer<'static>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        roots.add(certificate).unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_root_certificates(roots)
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".to_vec()];
        TlsConnector::from(Arc::new(config))
    }

    async fn connect_https2(address: SocketAddr, connector: &TlsConnector) -> TlsStream<TcpStream> {
        let stream = connector
            .connect(
                ServerName::try_from("localhost").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(b"h2".as_slice()));
        stream
    }

    #[test]
    fn non_loopback_http_requires_an_explicit_override() {
        let args = Args {
            listen: "0.0.0.0:12345".parse().unwrap(),
            allow_insecure_http: false,
            tls_certificate: None,
            tls_key: None,
            tls_client_ca: None,
            legacy_serial: None,
            command_timeout_seconds: 30,
            http_max_in_flight_requests: 64,
        };
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn usb_command_response_timeout_defaults_to_one_minute() {
        let args = Args::try_parse_from(["pkcs11rs-connector"]).unwrap();
        assert_eq!(args.command_timeout_seconds, 60);
        assert_eq!(args.http_max_in_flight_requests, 64);
    }

    #[test]
    fn delayed_timer_tick_detects_a_system_resume() {
        assert!(!is_resume_gap(RESUME_CHECK_INTERVAL));
        assert!(!is_resume_gap(RESUME_CHECK_INTERVAL + RESUME_GAP_THRESHOLD));
        assert!(is_resume_gap(
            RESUME_CHECK_INTERVAL + RESUME_GAP_THRESHOLD + Duration::from_millis(1)
        ));
    }

    #[tokio::test]
    async fn multi_device_api_works_over_http2_when_a_device_appears() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("11111111", b"other device")
            .await;
        let app = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        );
        let (address, handle, server) = spawn_http_server(app);

        registry
            .insert_test_response("22222222", b"second device")
            .await;
        let (version, body) = send_http2(
            TcpStream::connect(address).await.unwrap(),
            Method::GET,
            format!("http://{address}/v1/devices"),
            b"",
        )
        .await;
        assert_eq!(version, Version::HTTP_2);
        let devices: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(devices["devices"][0]["serial"], "11111111");
        assert_eq!(devices["devices"][1]["serial"], "22222222");

        let (version, body) = send_http2(
            TcpStream::connect(address).await.unwrap(),
            Method::POST,
            format!("http://{address}/v1/devices/22222222/commands"),
            b"command",
        )
        .await;
        assert_eq!(version, Version::HTTP_2);
        assert_eq!(body, b"second device");

        handle.shutdown();
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn http_server_can_drop_stale_connections_and_rebind_the_same_address() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        let app = router(
            AppState {
                registry,
                legacy_serial: None,
            },
            64,
        );
        let (address, first_handle, first_server) = spawn_http_server(app.clone());

        let stream = TcpStream::connect(address).await.unwrap();
        let (_, body) = send_http2(
            stream,
            Method::GET,
            format!("http://{address}/v1/devices"),
            b"",
        )
        .await;
        assert!(String::from_utf8(body).unwrap().contains("12345678"));

        first_handle.shutdown();
        first_server.await.unwrap().unwrap();

        let second_handle = axum_server::Handle::new();
        let server_handle = second_handle.clone();
        let second_server = tokio::spawn(async move {
            axum_server::bind(address)
                .handle(server_handle)
                .serve(app.into_make_service())
                .await
        });
        assert_eq!(second_handle.listening().await, Some(address));

        let stream = TcpStream::connect(address).await.unwrap();
        let (_, body) = send_http2(
            stream,
            Method::GET,
            format!("http://{address}/v1/devices"),
            b"",
        )
        .await;
        assert!(String::from_utf8(body).unwrap().contains("12345678"));

        second_handle.shutdown();
        second_server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn multi_device_api_works_over_https2_at_startup() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("11111111", b"other device")
            .await;
        registry
            .insert_test_response("22222222", b"second device")
            .await;
        let app = router(
            AppState {
                registry,
                legacy_serial: None,
            },
            64,
        );
        let (pem, certificate) = PemFiles::self_signed_localhost();
        let config = tls::server_config(&pem.certificate, &pem.key, None).unwrap();
        let connector = https_client(certificate);
        let (address, handle, server) = spawn_https_server(app, config);

        let stream = connect_https2(address, &connector).await;
        let (version, body) = send_http2(
            stream,
            Method::GET,
            format!("https://localhost:{}/v1/devices/22222222", address.port()),
            b"",
        )
        .await;
        assert_eq!(version, Version::HTTP_2);
        let device: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(device["serial"], "22222222");

        let stream = connect_https2(address, &connector).await;
        let (version, body) = send_http2(
            stream,
            Method::POST,
            format!(
                "https://localhost:{}/v1/devices/22222222/commands",
                address.port()
            ),
            b"command",
        )
        .await;
        assert_eq!(version, Version::HTTP_2);
        assert_eq!(body, b"second device");

        handle.shutdown();
        server.await.unwrap().unwrap();
    }
}
