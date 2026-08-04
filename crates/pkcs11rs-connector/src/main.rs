mod api;
mod registry;
mod tls;

use api::{router, AppState};
use clap::Parser;
use registry::{spawn_discovery, DeviceRegistry};
use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

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

    /// Maximum time for one USB command exchange.
    #[arg(long, default_value_t = 30)]
    command_timeout_seconds: u64,
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

    let registry = DeviceRegistry::new(Duration::from_secs(args.command_timeout_seconds));
    let discovery = spawn_discovery(registry.clone()).await?;
    let app = router(AppState {
        registry,
        legacy_serial: args.legacy_serial,
    });

    let handle = axum_server::Handle::new();
    let shutdown_handle = handle.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        }
    });

    let result = match (&args.tls_certificate, &args.tls_key) {
        (Some(certificate), Some(key)) => {
            let config = tls::server_config(certificate, key, args.tls_client_ca.as_deref())?;
            tracing::info!(address = %args.listen, mtls = args.tls_client_ca.is_some(), "listening with HTTPS");
            axum_server::bind_rustls(
                args.listen,
                axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(config)),
            )
            .handle(handle)
            .serve(app.into_make_service())
            .await
        }
        (None, None) => {
            tracing::info!(address = %args.listen, "listening with HTTP");
            axum_server::bind(args.listen)
                .handle(handle)
                .serve(app.into_make_service())
                .await
        }
        _ => unreachable!("clap requires the TLS certificate and key together"),
    };
    discovery.abort();
    result.map_err(Into::into)
}

fn validate_args(args: &Args) -> Result<(), BoxError> {
    if args.command_timeout_seconds == 0 {
        return Err("--command-timeout-seconds must be greater than zero".into());
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
        };
        assert!(validate_args(&args).is_err());
    }

    #[tokio::test]
    async fn multi_device_api_works_over_http2_when_a_device_appears() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("11111111", b"other device")
            .await;
        let app = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        });
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
    async fn multi_device_api_works_over_https2_at_startup() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("11111111", b"other device")
            .await;
        registry
            .insert_test_response("22222222", b"second device")
            .await;
        let app = router(AppState {
            registry,
            legacy_serial: None,
        });
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
