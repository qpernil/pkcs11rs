use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

type Http2Sender = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

async fn start(
    args: &Args,
) -> (
    SocketAddr,
    axum_server::Handle<SocketAddr>,
    JoinHandle<io::Result<()>>,
) {
    let app = router(
        AppState {
            registry: DeviceRegistry::new(),
            legacy_serial: None,
        },
        64,
    );
    let handle = axum_server::Handle::new();
    let server = tokio::spawn(connector_server(args, app, handle.clone()).unwrap());
    let address = handle.listening().await.unwrap();
    (address, handle, server)
}

fn args(connections: usize, handshakes: usize) -> Args {
    let mut args = Args::try_parse_from(["pkcs11rs-connector"]).unwrap();
    args.listen = "127.0.0.1:0".parse().unwrap();
    args.http_max_connections = connections;
    args.tls_max_concurrent_handshakes = handshakes;
    args
}

async fn wait_connections(handle: &axum_server::Handle<SocketAddr>, count: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        while handle.connection_count() != count {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("connection count did not settle");
}

async fn assert_closed<IO: AsyncRead + Unpin>(io: &mut IO, timeout: Duration) {
    let mut byte = [0];
    let result = tokio::time::timeout(timeout, io.read(&mut byte))
        .await
        .expect("overloaded connection was queued instead of closed");
    match result {
        Ok(0) => {}
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::ConnectionReset
                    | io::ErrorKind::ConnectionAborted
                    | io::ErrorKind::BrokenPipe
                    | io::ErrorKind::UnexpectedEof
            ) => {}
        other => panic!("expected connection closure, got {other:?}"),
    }
}

async fn http2<IO: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
    io: IO,
) -> (Http2Sender, JoinHandle<()>) {
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(io))
            .await
            .unwrap();
    let connection = tokio::spawn(async move {
        let _ = connection.await;
    });
    (sender, connection)
}

async fn inventory(sender: &mut Http2Sender) {
    let response = tokio::time::timeout(
        Duration::from_secs(3),
        sender.send_request(
            Request::builder()
                .uri("http://localhost/v1/devices")
                .body(Full::new(Bytes::new()))
                .unwrap(),
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["devices"],
        serde_json::json!([])
    );
}

async fn finish(handle: axum_server::Handle<SocketAddr>, server: JoinHandle<io::Result<()>>) {
    handle.shutdown();
    tokio::time::timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_connections(&handle, 0).await;
}

#[tokio::test]
async fn admission_http_limits_idle_connections_before_headers_and_recovers() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let (address, handle, server) = start(&args(1, 1)).await;
    let first = TcpStream::connect(address).await.unwrap();
    wait_connections(&handle, 1).await;
    for _ in 0..8 {
        let mut excess = TcpStream::connect(address).await.unwrap();
        assert_closed(&mut excess, Duration::from_secs(3)).await;
    }
    let (mut sender, connection) = http2(first).await;
    inventory(&mut sender).await;
    wait_connections(&handle, 1).await;
    inventory(&mut sender).await;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    wait_connections(&handle, 0).await;
    let (mut sender, connection) = http2(TcpStream::connect(address).await.unwrap()).await;
    inventory(&mut sender).await;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    finish(handle, server).await;
}

#[tokio::test]
async fn admission_tls_handshake_limit_preserves_established_clients_and_recovers() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let (pem, certificate) = PemFiles::self_signed_localhost();
    let mut args = args(3, 1);
    args.tls_certificate = Some(pem.certificate.clone());
    args.tls_key = Some(pem.key.clone());
    let (address, handle, server) = start(&args).await;
    let connector = https_client(certificate);
    let (mut sender, connection) = http2(connect_https2(address, &connector).await).await;
    inventory(&mut sender).await;
    let stalled = TcpStream::connect(address).await.unwrap();
    wait_connections(&handle, 2).await;
    for _ in 0..8 {
        let mut excess = TcpStream::connect(address).await.unwrap();
        assert_closed(&mut excess, Duration::from_secs(3)).await;
    }
    inventory(&mut sender).await;
    drop(stalled);
    wait_connections(&handle, 1).await;
    let stream = connect_https2(address, &connector).await;
    let (_, body) = send_http2(
        stream,
        Method::GET,
        format!("https://localhost:{}/v1/devices", address.port()),
        b"",
    )
    .await;
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap()["devices"],
        serde_json::json!([])
    );
    drop(sender);
    connection.abort();
    let _ = connection.await;
    finish(handle, server).await;
}

#[tokio::test]
async fn admission_tls_connection_limit_holds_after_handshake_completion() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let (pem, certificate) = PemFiles::self_signed_localhost();
    let mut args = args(1, 2);
    args.tls_certificate = Some(pem.certificate.clone());
    args.tls_key = Some(pem.key.clone());
    let (address, handle, server) = start(&args).await;
    let connector = https_client(certificate);
    let (mut sender, connection) = http2(connect_https2(address, &connector).await).await;
    inventory(&mut sender).await;
    let mut excess = TcpStream::connect(address).await.unwrap();
    assert_closed(&mut excess, Duration::from_secs(3)).await;
    inventory(&mut sender).await;
    drop(sender);
    connection.abort();
    let _ = connection.await;
    wait_connections(&handle, 0).await;
    let stream = connect_https2(address, &connector).await;
    let _ = send_http2(
        stream,
        Method::GET,
        format!("https://localhost:{}/v1/devices", address.port()),
        b"",
    )
    .await;
    finish(handle, server).await;
}

#[tokio::test]
async fn admission_failed_and_timed_out_tls_handshakes_release_capacity() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let (pem, certificate) = PemFiles::self_signed_localhost();
    let mut args = args(1, 1);
    args.tls_certificate = Some(pem.certificate.clone());
    args.tls_key = Some(pem.key.clone());
    let (address, handle, server) = start(&args).await;
    let mut invalid = TcpStream::connect(address).await.unwrap();
    invalid.write_all(b"invalid TLS data").await.unwrap();
    // A failed TLS handshake may send a TLS alert before closing the socket.
    let mut alert = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(3), invalid.read_to_end(&mut alert))
        .await
        .unwrap();
    assert!(
        result.is_ok()
            || result.as_ref().is_err_and(|e| matches!(
                e.kind(),
                io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
            ))
    );
    assert!(alert.is_empty() || alert[0] == 0x15, "expected a TLS alert");
    wait_connections(&handle, 0).await;
    let mut stalled = TcpStream::connect(address).await.unwrap();
    wait_connections(&handle, 1).await;
    assert_closed(&mut stalled, HTTP_STAGE_TIMEOUT + Duration::from_secs(3)).await;
    wait_connections(&handle, 0).await;
    let connector = https_client(certificate);
    let stream = connect_https2(address, &connector).await;
    let _ = send_http2(
        stream,
        Method::GET,
        format!("https://localhost:{}/v1/devices", address.port()),
        b"",
    )
    .await;
    finish(handle, server).await;
}

#[tokio::test]
async fn admission_shutdown_closes_stalled_tls_clients_without_waiting_for_timeout() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let (pem, _certificate) = PemFiles::self_signed_localhost();
    let mut args = args(1, 1);
    args.tls_certificate = Some(pem.certificate.clone());
    args.tls_key = Some(pem.key.clone());
    let (address, handle, server) = start(&args).await;
    let mut stalled = TcpStream::connect(address).await.unwrap();
    wait_connections(&handle, 1).await;
    finish(handle, server).await;
    assert_closed(&mut stalled, Duration::from_secs(3)).await;
}

#[test]
fn admission_limits_are_positive_bounded_and_configurable() {
    let defaults = Args::try_parse_from(["pkcs11rs-connector"]).unwrap();
    assert_eq!(defaults.http_max_connections, DEFAULT_HTTP_MAX_CONNECTIONS);
    assert_eq!(
        defaults.tls_max_concurrent_handshakes,
        DEFAULT_TLS_MAX_CONCURRENT_HANDSHAKES
    );
    assert!(validate_args(&defaults).is_ok());
    for flag in [
        "--http-max-connections",
        "--tls-max-concurrent-handshakes",
        "--http-max-in-flight-requests",
    ] {
        for value in [0, tokio::sync::Semaphore::MAX_PERMITS + 1] {
            let parsed =
                Args::try_parse_from(["pkcs11rs-connector", flag, &value.to_string()]).unwrap();
            assert!(
                validate_args(&parsed).is_err(),
                "{flag}={value} was accepted"
            );
        }
    }
    let configured = Args::try_parse_from([
        "pkcs11rs-connector",
        "--http-max-connections",
        "7",
        "--tls-max-concurrent-handshakes",
        "2",
    ])
    .unwrap();
    assert_eq!(configured.http_max_connections, 7);
    assert_eq!(configured.tls_max_concurrent_handshakes, 2);
    assert!(validate_args(&configured).is_ok());
}

#[tokio::test]
async fn admission_mtls_authentication_failures_release_both_limits() {
    let _network_guard = NETWORK_TEST_LOCK.lock().await;
    let authority = tls_tests::Authority::new();
    let identity = authority.client(false, false);
    let (pem, certificate) = PemFiles::self_signed_localhost();
    let ca_path = pem.directory.join("client-ca.pem");
    fs::write(&ca_path, authority.certificate.pem()).unwrap();
    let mut args = args(1, 1);
    args.tls_certificate = Some(pem.certificate.clone());
    args.tls_key = Some(pem.key.clone());
    args.tls_client_ca = Some(ca_path);
    let (address, handle, server) = start(&args).await;
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let config = tls_tests::client_config(certificate.clone(), version, None);
        let connector = TlsConnector::from(Arc::new(config));
        let tcp = TcpStream::connect(address).await.unwrap();
        wait_connections(&handle, 1).await;
        let rejected = tokio::time::timeout(Duration::from_secs(3), async {
            let mut stream = connector
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await?;
            stream
                .write_all(b"GET /v1/devices HTTP/1.1\r\nHost: localhost\r\n\r\n")
                .await?;
            let mut byte = [0];
            stream.read(&mut byte).await
        })
        .await
        .unwrap();
        assert!(
            matches!(rejected, Err(_) | Ok(0)),
            "unauthenticated client reached HTTP"
        );
        wait_connections(&handle, 0).await;
        let mut config = tls_tests::client_config(certificate.clone(), version, Some(&identity));
        config.alpn_protocols = vec![b"h2".to_vec()];
        let connector = TlsConnector::from(Arc::new(config));
        let stream = connect_https2(address, &connector).await;
        let _ = send_http2(
            stream,
            Method::GET,
            format!("https://localhost:{}/v1/devices", address.port()),
            b"",
        )
        .await;
        wait_connections(&handle, 0).await;
    }
    finish(handle, server).await;
}
