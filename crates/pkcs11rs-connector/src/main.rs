mod api;
mod http_timeout;
mod registry;
mod tls;
#[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
mod virtual_hsm;

use api::{AppState, router};
use clap::{Parser, ValueEnum};
use http_timeout::WriteTimeoutAcceptor;
use hyper_util::rt::TokioTimer;
use registry::{DeviceRegistry, spawn_discovery};
use std::{
    future::Future, io, net::SocketAddr, path::PathBuf, pin::Pin, str::FromStr, sync::Arc,
    time::Duration,
};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ServerFuture = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

const SERVER_RESTART_DELAY: Duration = Duration::from_secs(1);
const HTTP_STAGE_TIMEOUT: Duration = Duration::from_secs(5);
const HTTP2_MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;
const DEFAULT_VIRTUAL_YUBIHSM_BATCH_DELAY_MS: u64 = 500;

#[derive(Clone, Debug, Eq, PartialEq)]
struct VirtualYubiHsmSpec {
    serial: u32,
    state_directory: PathBuf,
}

impl FromStr for VirtualYubiHsmSpec {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (serial, state_directory) = value.split_once('=').ok_or_else(|| {
            String::from("expected SERIAL=STATE_DIRECTORY for an embedded virtual YubiHSM")
        })?;
        let serial = serial
            .parse::<u32>()
            .map_err(|_| format!("invalid embedded virtual YubiHSM serial {serial:?}"))?;
        if state_directory.is_empty() {
            return Err(String::from(
                "embedded virtual YubiHSM state directory must not be empty",
            ));
        }
        Ok(Self {
            serial,
            state_directory: PathBuf::from(state_directory),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum VirtualPersistence {
    Batched,
    Immediate,
}

enum VirtualHsmRuntime {
    #[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
    Enabled(virtual_hsm::VirtualHsmActors),
    #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
    Disabled,
}

impl VirtualHsmRuntime {
    async fn start(args: &Args, registry: &DeviceRegistry) -> Result<Self, BoxError> {
        #[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
        {
            let actors = virtual_hsm::VirtualHsmActors::start(
                registry,
                &args.virtual_yubihsms,
                args.virtual_yubihsm_persistence,
                Duration::from_millis(args.virtual_yubihsm_batch_delay_ms),
            )
            .await?;
            Ok(Self::Enabled(actors))
        }

        #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
        {
            let _ = registry;
            if !args.virtual_yubihsms.is_empty() {
                tracing::warn!(
                    instances = args.virtual_yubihsms.len(),
                    "ignoring embedded virtual YubiHSM configuration because this connector was built without embedded support"
                );
            }
            Ok(Self::Disabled)
        }
    }

    async fn shutdown(self) -> io::Result<()> {
        match self {
            #[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
            Self::Enabled(actors) => actors.shutdown().await,
            #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
            Self::Disabled => Ok(()),
        }
    }
}

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

    /// Discover and serve locally attached physical YubiHSMs. Ignored without embedded support.
    #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
    hardware_discovery: bool,

    /// Embedded virtual YubiHSM expressed as SERIAL=STATE_DIRECTORY. Repeat for more devices.
    #[arg(long = "virtual-yubihsm", value_name = "SERIAL=STATE_DIRECTORY")]
    virtual_yubihsms: Vec<VirtualYubiHsmSpec>,

    /// Durability policy shared by configured embedded virtual YubiHSMs.
    #[arg(long, value_enum, default_value = "batched")]
    virtual_yubihsm_persistence: VirtualPersistence,

    /// Maximum batching delay for embedded virtual YubiHSM persistence.
    #[arg(long, default_value_t = DEFAULT_VIRTUAL_YUBIHSM_BATCH_DELAY_MS)]
    virtual_yubihsm_batch_delay_ms: u64,
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

    loop {
        match serve_until_shutdown(&args).await {
            Ok(()) => return Ok(()),
            Err(error) => {
                tracing::error!(%error, "connector service stopped; retrying");
                tokio::select! {
                    result = shutdown_signal() => {
                        result?;
                        return Ok(());
                    }
                    _ = tokio::time::sleep(SERVER_RESTART_DELAY) => {}
                }
            }
        }
    }
}

async fn serve_until_shutdown(args: &Args) -> Result<(), BoxError> {
    let registry = DeviceRegistry::new(Duration::from_secs(args.command_timeout_seconds));
    let virtual_hsms = VirtualHsmRuntime::start(args, &registry).await?;
    let discovery = if hardware_discovery_enabled(args) {
        match spawn_discovery(registry.clone()).await {
            Ok(discovery) => Some(discovery),
            Err(error) => {
                virtual_hsms.shutdown().await?;
                return Err(error);
            }
        }
    } else {
        tracing::info!("local YubiHSM hardware discovery disabled");
        None
    };
    let app = router(
        AppState {
            registry,
            legacy_serial: args.legacy_serial.clone(),
        },
        args.http_max_in_flight_requests,
    );

    let handle = axum_server::Handle::new();
    let mut server = match connector_server(args, app, handle.clone()) {
        Ok(server) => server,
        Err(error) => {
            if let Some(discovery) = &discovery {
                discovery.abort();
            }
            virtual_hsms.shutdown().await?;
            return Err(error);
        }
    };
    let server_result = tokio::select! {
        result = &mut server => result,
        result = shutdown_signal() => {
            match result {
                Ok(()) => {
                    handle.graceful_shutdown(Some(Duration::from_secs(10)));
                    server.await
                }
                Err(error) => Err(error),
            }
        }
    };
    if let Some(discovery) = discovery {
        discovery.abort();
    }
    let virtual_result = virtual_hsms.shutdown().await;
    server_result?;
    virtual_result?;
    Ok(())
}

fn hardware_discovery_enabled(args: &Args) -> bool {
    #[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
    {
        args.hardware_discovery
    }

    #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
    {
        if !args.hardware_discovery {
            tracing::warn!(
                "ignoring disabled hardware discovery because this connector was built without embedded support"
            );
        }
        true
    }
}

async fn shutdown_signal() -> io::Result<()> {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            result = tokio::signal::ctrl_c() => result,
            _ = terminate.recv() => Ok(()),
        }
    }

    #[cfg(not(unix))]
    tokio::signal::ctrl_c().await
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
    use rustls::{ClientConfig, RootCertStore, pki_types::ServerName};
    #[cfg(unix)]
    use std::{
        env,
        io::{BufRead, BufReader},
        process::{Command, Stdio},
    };
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
    use tokio_rustls::{TlsConnector, client::TlsStream};

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const TEST_COMMAND: &[u8] = b"\x03\x00\x07command";

    #[cfg(unix)]
    #[test]
    fn sigterm_completes_shutdown_signal() {
        const CHILD_ENVIRONMENT: &str = "PKCS11RS_CONNECTOR_SIGTERM_TEST_CHILD";
        const READY_MARKER: &str = "PKCS11RS_CONNECTOR_SIGTERM_READY";

        if env::var_os(CHILD_ENVIRONMENT).is_some() {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let shutdown = tokio::spawn(shutdown_signal());
                    tokio::task::yield_now().await;
                    eprintln!("{READY_MARKER}");
                    shutdown.await.unwrap().unwrap();
                });
            return;
        }

        let mut child = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::sigterm_completes_shutdown_signal",
                "--nocapture",
            ])
            .env(CHILD_ENVIRONMENT, "1")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stderr = BufReader::new(child.stderr.take().unwrap());
        let mut line = String::new();
        loop {
            line.clear();
            assert_ne!(stderr.read_line(&mut line).unwrap(), 0);
            if line.contains(READY_MARKER) {
                break;
            }
        }

        let signal_status = Command::new("kill")
            .args(["-TERM", &child.id().to_string()])
            .status()
            .unwrap();
        assert!(signal_status.success());
        assert!(child.wait().unwrap().success());
    }

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
            hardware_discovery: true,
            virtual_yubihsms: Vec::new(),
            virtual_yubihsm_persistence: VirtualPersistence::Batched,
            virtual_yubihsm_batch_delay_ms: DEFAULT_VIRTUAL_YUBIHSM_BATCH_DELAY_MS,
        };
        assert!(validate_args(&args).is_err());
    }

    #[test]
    fn usb_command_response_timeout_defaults_to_one_minute() {
        let args = Args::try_parse_from(["pkcs11rs-connector"]).unwrap();
        assert_eq!(args.command_timeout_seconds, 60);
        assert_eq!(args.http_max_in_flight_requests, 64);
        assert!(args.hardware_discovery);
        assert_eq!(
            args.virtual_yubihsm_persistence,
            VirtualPersistence::Batched
        );
        assert_eq!(
            args.virtual_yubihsm_batch_delay_ms,
            DEFAULT_VIRTUAL_YUBIHSM_BATCH_DELAY_MS
        );
    }

    #[cfg(all(feature = "embedded-virtual-yubihsm", unix))]
    #[test]
    fn embedded_connector_can_disable_local_hardware_discovery() {
        let args = Args::try_parse_from([
            "pkcs11rs-connector",
            "--hardware-discovery",
            "false",
            "--virtual-yubihsm",
            "12345678=/var/lib/pkcs11rs/virtual",
        ])
        .unwrap();
        assert!(!args.hardware_discovery);
        assert!(!hardware_discovery_enabled(&args));
        assert_eq!(args.virtual_yubihsms.len(), 1);
    }

    #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
    #[test]
    fn physical_only_connector_ignores_disabled_hardware_discovery() {
        let args =
            Args::try_parse_from(["pkcs11rs-connector", "--hardware-discovery", "false"]).unwrap();
        assert!(!args.hardware_discovery);
        assert!(hardware_discovery_enabled(&args));
    }

    #[test]
    fn embedded_configuration_is_accepted_independently_of_compile_time_support() {
        let args = Args::try_parse_from([
            "pkcs11rs-connector",
            "--virtual-yubihsm",
            "12345678=/var/lib/pkcs11rs/first",
            "--virtual-yubihsm",
            "87654321=/var/lib/pkcs11rs/second",
            "--virtual-yubihsm-persistence",
            "immediate",
        ])
        .unwrap();
        assert_eq!(
            args.virtual_yubihsms,
            vec![
                VirtualYubiHsmSpec {
                    serial: 12_345_678,
                    state_directory: PathBuf::from("/var/lib/pkcs11rs/first"),
                },
                VirtualYubiHsmSpec {
                    serial: 87_654_321,
                    state_directory: PathBuf::from("/var/lib/pkcs11rs/second"),
                },
            ]
        );
        assert_eq!(
            args.virtual_yubihsm_persistence,
            VirtualPersistence::Immediate
        );
    }

    #[cfg(not(all(feature = "embedded-virtual-yubihsm", unix)))]
    #[tokio::test]
    async fn connector_without_embedded_support_ignores_virtual_configuration() {
        let args = Args::try_parse_from([
            "pkcs11rs-connector",
            "--virtual-yubihsm",
            "12345678=relative-path-that-is-not-validated",
            "--virtual-yubihsm",
            "12345678=duplicate-that-is-also-ignored",
        ])
        .unwrap();
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        assert!(matches!(
            VirtualHsmRuntime::start(&args, &registry).await.unwrap(),
            VirtualHsmRuntime::Disabled
        ));
        assert!(registry.list().await.is_empty());
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
            TEST_COMMAND,
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
            TEST_COMMAND,
        )
        .await;
        assert_eq!(version, Version::HTTP_2);
        assert_eq!(body, b"second device");

        handle.shutdown();
        server.await.unwrap().unwrap();
    }
}
