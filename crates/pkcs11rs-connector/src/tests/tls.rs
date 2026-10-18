use super::*;
use rcgen::{
    Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use std::sync::atomic::AtomicUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub(super) struct Authority {
    pub(super) certificate: Certificate,
    key: KeyPair,
}

impl Authority {
    pub(super) fn new() -> Self {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let certificate = params.self_signed(&key).unwrap();
        Self { certificate, key }
    }

    pub(super) fn client(&self, expired: bool, wrong_usage: bool) -> (Certificate, KeyPair) {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![if wrong_usage {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        if expired {
            params.not_before = rcgen::date_time_ymd(2020, 1, 1);
            params.not_after = rcgen::date_time_ymd(2021, 1, 1);
        }
        let certificate = params
            .signed_by(&key, &self.certificate, &self.key)
            .unwrap();
        (certificate, key)
    }
}

pub(super) fn client_config(
    server_certificate: CertificateDer<'static>,
    version: &'static rustls::SupportedProtocolVersion,
    identity: Option<&(Certificate, KeyPair)>,
) -> ClientConfig {
    let mut roots = RootCertStore::empty();
    roots.add(server_certificate).unwrap();
    let builder =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[version])
            .unwrap()
            .with_root_certificates(roots);
    let mut config = match identity {
        Some((certificate, key)) => builder
            .with_client_auth_cert(
                vec![certificate.der().clone()],
                PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    config
}

async fn request(
    address: SocketAddr,
    config: ClientConfig,
    hostname: &'static str,
    version: rustls::ProtocolVersion,
) -> io::Result<Vec<u8>> {
    let connector = TlsConnector::from(Arc::new(config));
    let mut stream = connector
        .connect(
            ServerName::try_from(hostname).unwrap(),
            TcpStream::connect(address).await?,
        )
        .await?;
    assert_eq!(stream.get_ref().1.protocol_version(), Some(version));
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"http/1.1".as_slice())
    );
    stream
        .write_all(b"GET /v1/devices HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await?;
    Ok(response)
}

#[derive(Clone, Copy, Debug)]
enum ClientCase {
    Trusted,
    Missing,
    Untrusted,
    Expired,
    WrongUsage,
}

async fn check_mtls(case: ClientCase) {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let authority = Authority::new();
        let (pem, certificate) = PemFiles::self_signed_localhost();
        let ca_path = pem.directory.join("client-ca.pem");
        fs::write(&ca_path, authority.certificate.pem()).unwrap();
        let identity = match case {
            ClientCase::Missing => None,
            ClientCase::Untrusted => Some(Authority::new().client(false, false)),
            ClientCase::Expired => Some(authority.client(true, false)),
            ClientCase::WrongUsage => Some(authority.client(false, true)),
            ClientCase::Trusted => Some(authority.client(false, false)),
        };
        let app = router(
            AppState {
                registry: DeviceRegistry::new(),
                legacy_serial: None,
            },
            64,
        );
        let requests = Arc::new(AtomicUsize::new(0));
        let request_counter = requests.clone();
        let app = app.layer(axum::middleware::from_fn(
            move |request: Request<axum::body::Body>, next: axum::middleware::Next| {
                let requests = request_counter.clone();
                async move {
                    requests.fetch_add(1, Ordering::SeqCst);
                    next.run(request).await
                }
            },
        ));
        let server_config = tls::server_config(&pem.certificate, &pem.key, Some(&ca_path)).unwrap();
        let (address, handle, server) = spawn_https_server(app, server_config);
        let config = client_config(certificate, version, identity.as_ref());
        let result = tokio::time::timeout(
            Duration::from_secs(5),
            request(address, config.clone(), "localhost", version.version),
        )
        .await
        .expect("mTLS request stalled");
        if matches!(case, ClientCase::Trusted) {
            assert!(result.unwrap().starts_with(b"HTTP/1.1 200 OK"));
            let mut http2_config = config;
            http2_config.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(http2_config));
            let stream = connect_https2(address, &connector).await;
            assert_eq!(stream.get_ref().1.protocol_version(), Some(version.version));
            let (http_version, body) = send_http2(
                stream,
                Method::GET,
                format!("https://localhost:{}/v1/devices", address.port()),
                b"",
            )
            .await;
            assert_eq!(http_version, Version::HTTP_2);
            assert_eq!(
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["devices"],
                serde_json::json!([])
            );
        } else {
            assert!(
                result.is_err(),
                "{case:?} client reached HTTP over {:?}",
                version.version
            );
        }
        assert_eq!(
            requests.load(Ordering::SeqCst),
            if matches!(case, ClientCase::Trusted) {
                2
            } else {
                0
            },
            "{case:?} client reached an HTTP handler over {:?}",
            version.version
        );
        handle.shutdown();
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn mtls_trusted_clients_can_use_http1_and_http2() {
    check_mtls(ClientCase::Trusted).await;
}
#[tokio::test]
async fn mtls_rejects_missing_client_certificates() {
    check_mtls(ClientCase::Missing).await;
}
#[tokio::test]
async fn mtls_rejects_untrusted_client_certificates() {
    check_mtls(ClientCase::Untrusted).await;
}
#[tokio::test]
async fn mtls_rejects_expired_client_certificates() {
    check_mtls(ClientCase::Expired).await;
}
#[tokio::test]
async fn mtls_rejects_server_only_client_certificates() {
    check_mtls(ClientCase::WrongUsage).await;
}

#[tokio::test]
async fn tls_authenticates_the_server_under_both_protocol_versions() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let (pem, certificate) = PemFiles::self_signed_localhost();
        let app = router(
            AppState {
                registry: DeviceRegistry::new(),
                legacy_serial: None,
            },
            64,
        );
        let config = tls::server_config(&pem.certificate, &pem.key, None).unwrap();
        let (address, handle, server) = spawn_https_server(app, config);
        for (root, hostname, accepted) in [
            (certificate.clone(), "localhost", true),
            (certificate.clone(), "wrong.example", false),
            (
                Authority::new().certificate.der().clone(),
                "localhost",
                false,
            ),
        ] {
            let config = client_config(root, version, None);
            let result = tokio::time::timeout(
                Duration::from_secs(5),
                request(address, config, hostname, version.version),
            )
            .await
            .expect("TLS request stalled");
            if accepted {
                assert!(result.unwrap().starts_with(b"HTTP/1.1 200 OK"));
            } else {
                assert!(result.is_err(), "untrusted server reached HTTP");
            }
        }
        handle.shutdown();
        server.await.unwrap().unwrap();
    }
}
