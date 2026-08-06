use crate::registry::{DeviceRegistry, LegacySelectionError, TransportError, TransportErrorKind};
use axum::{
    body::Bytes,
    error_handling::HandleErrorLayer,
    extract::{Path, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;
use std::time::Duration;
use tower::{
    limit::GlobalConcurrencyLimitLayer, load_shed::LoadShedLayer, BoxError, ServiceBuilder,
};
use tower_http::{
    limit::RequestBodyLimitLayer,
    timeout::RequestBodyDeadlineLayer,
    trace::{MakeSpan, OnResponse, TraceLayer},
};
use tracing::Span;

const MAX_COMMAND_BODY: usize = 8192;
const OCTET_STREAM: &str = "application/octet-stream";
const HTTP_REQUEST_BODY_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct HsmCommandMetrics {
    serial: String,
    usb_device_id: Option<String>,
    elapsed: Duration,
    error_code: Option<&'static str>,
    error: Option<String>,
}

#[derive(Clone, Copy)]
struct LogCommandResponse;

#[derive(Clone, Copy)]
struct MakeHttpSpan;

impl<B> MakeSpan<B> for MakeHttpSpan {
    fn make_span(&mut self, request: &axum::http::Request<B>) -> Span {
        tracing::debug_span!(
            "http_request",
            method = %request.method(),
            uri = %request.uri(),
            version = ?request.version(),
        )
    }
}

impl<B> OnResponse<B> for LogCommandResponse {
    fn on_response(self, response: &axum::http::Response<B>, latency: Duration, _span: &Span) {
        let Some(metrics) = response.extensions().get::<HsmCommandMetrics>() else {
            tracing::debug!(
                status = response.status().as_u16(),
                http_request_elapsed_ms = latency.as_millis(),
                "HTTP request completed"
            );
            return;
        };
        match &metrics.error {
            None => tracing::debug!(
                status = response.status().as_u16(),
                http_request_elapsed_ms = latency.as_millis(),
                hsm_serial = %metrics.serial,
                usb_device_id = %metrics.usb_device_id.as_deref().unwrap_or("-"),
                hsm_outcome = "ok",
                hsm_command_elapsed_ms = metrics.elapsed.as_millis(),
                "HTTP request completed"
            ),
            Some(error) => tracing::debug!(
                status = response.status().as_u16(),
                http_request_elapsed_ms = latency.as_millis(),
                hsm_serial = %metrics.serial,
                usb_device_id = %metrics.usb_device_id.as_deref().unwrap_or("-"),
                hsm_outcome = "error",
                hsm_error_code = metrics.error_code.unwrap_or("device_transport_error"),
                hsm_error = %error,
                hsm_command_elapsed_ms = metrics.elapsed.as_millis(),
                "HTTP request completed"
            ),
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    pub registry: DeviceRegistry,
    pub legacy_serial: Option<String>,
}

#[derive(Serialize)]
struct DeviceList {
    devices: Vec<crate::registry::DeviceView>,
}

#[derive(Serialize)]
struct Problem {
    code: &'static str,
    message: String,
}

pub fn router(state: AppState, max_in_flight_requests: usize) -> Router {
    router_with_request_body_deadline(state, HTTP_REQUEST_BODY_TIMEOUT, max_in_flight_requests)
}

fn router_with_request_body_deadline(
    state: AppState,
    request_body_deadline: Duration,
    max_in_flight_requests: usize,
) -> Router {
    let router = Router::new()
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{serial}", get(get_device))
        .route("/v1/devices/{serial}/commands", post(device_command))
        .route("/connector/status", get(legacy_status))
        .route("/connector/api", post(legacy_command))
        .layer(RequestBodyLimitLayer::new(MAX_COMMAND_BODY))
        .layer(RequestBodyDeadlineLayer::new(request_body_deadline))
        .with_state(state);
    with_http_tracing(with_global_request_limit(router, max_in_flight_requests))
}

fn with_http_tracing(router: Router) -> Router {
    router.layer(
        TraceLayer::new_for_http()
            .make_span_with(MakeHttpSpan)
            .on_request(())
            .on_response(LogCommandResponse)
            .on_failure(()),
    )
}

fn with_global_request_limit(router: Router, max_in_flight_requests: usize) -> Router {
    router.layer(
        ServiceBuilder::new()
            .layer(HandleErrorLayer::new(handle_overload))
            .layer(LoadShedLayer::new())
            .layer(GlobalConcurrencyLimitLayer::new(max_in_flight_requests)),
    )
}

async fn handle_overload(_error: BoxError) -> Response {
    problem(
        StatusCode::SERVICE_UNAVAILABLE,
        "server_overloaded",
        String::from("the connector is at its in-flight HTTP request limit"),
    )
}

async fn list_devices(State(state): State<AppState>) -> Json<DeviceList> {
    Json(DeviceList {
        devices: state.registry.list().await,
    })
}

async fn get_device(Path(serial): Path<String>, State(state): State<AppState>) -> Response {
    match state.registry.view(&serial).await {
        Some(view) => Json(view).into_response(),
        None => problem(
            StatusCode::NOT_FOUND,
            "device_not_found",
            format!("no attached YubiHSM has serial {serial}"),
        ),
    }
}

async fn device_command(
    Path(serial): Path<String>,
    State(state): State<AppState>,
    body: Bytes,
) -> Response {
    let Some(entry) = state.registry.get(&serial).await else {
        if state.registry.view(&serial).await.is_some() {
            return problem(
                StatusCode::SERVICE_UNAVAILABLE,
                "device_unclaimed",
                format!("YubiHSM {serial} is not claimed by this connector"),
            );
        }
        return problem(
            StatusCode::NOT_FOUND,
            "device_not_found",
            format!("no attached YubiHSM has serial {serial}"),
        );
    };
    let view = entry.view();
    let usb_device_id = entry.usb_device_id();
    command_response(view.serial, usb_device_id, entry.command(&body).await)
}

async fn legacy_status(State(state): State<AppState>) -> Response {
    let (status, serial) = match state
        .registry
        .select_legacy(state.legacy_serial.as_deref())
        .await
    {
        Ok(entry) => ("OK", entry.view().serial),
        Err(LegacySelectionError::NoDevice) => ("NO_DEVICE", String::from("*")),
    };
    (
        StatusCode::OK,
        [(CONTENT_TYPE, "text/plain; charset=utf-8")],
        format!(
            "status={status}\nserial={serial}\nversion={}\n",
            env!("CARGO_PKG_VERSION")
        ),
    )
        .into_response()
}

async fn legacy_command(State(state): State<AppState>, body: Bytes) -> Response {
    match state
        .registry
        .select_legacy(state.legacy_serial.as_deref())
        .await
    {
        Ok(entry) => {
            let view = entry.view();
            let usb_device_id = entry.usb_device_id();
            command_response(view.serial, usb_device_id, entry.command(&body).await)
        }
        Err(LegacySelectionError::NoDevice) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_device",
            String::from("the legacy YubiHSM is not attached"),
        ),
    }
}

fn command_response(
    serial: String,
    usb_device_id: Option<String>,
    (result, elapsed): (Result<Vec<u8>, TransportError>, Duration),
) -> Response {
    let error_code = result.as_ref().err().map(TransportError::code);
    let error = result.as_ref().err().map(ToString::to_string);
    let mut response = match result {
        Ok(response) => (StatusCode::OK, [(CONTENT_TYPE, OCTET_STREAM)], response).into_response(),
        Err(error) => {
            let status = match error.kind() {
                TransportErrorKind::InvalidCommandFrame => StatusCode::BAD_REQUEST,
                TransportErrorKind::CommandTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
                TransportErrorKind::DeviceTransport => StatusCode::SERVICE_UNAVAILABLE,
            };
            problem(status, error.code(), error.to_string())
        }
    };
    response.extensions_mut().insert(HsmCommandMetrics {
        serial,
        usb_device_id,
        elapsed,
        error_code,
        error,
    });
    response
}

fn problem(status: StatusCode, code: &'static str, message: String) -> Response {
    (status, Json(Problem { code, message })).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::{BodyExt, Full};
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use std::{
        io::Write,
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::net::{TcpListener, TcpStream};
    use tower::ServiceExt;
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone, Default)]
    struct LogCapture(Arc<Mutex<Vec<u8>>>);

    impl LogCapture {
        fn text(&self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl Write for LogCapture {
        fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for LogCapture {
        type Writer = Self;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    async fn body(response: Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    fn command_frame(payload: &[u8]) -> Vec<u8> {
        let payload_length = u16::try_from(payload.len()).unwrap();
        let mut frame = Vec::with_capacity(3 + payload.len());
        frame.push(0x03);
        frame.extend_from_slice(&payload_length.to_be_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[tokio::test(flavor = "current_thread")]
    async fn debug_logs_include_http_and_hsm_command_timings() {
        let capture = LogCapture::default();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "pkcs11rs_connector=debug",
            ))
            .with_ansi(false)
            .without_time()
            .with_target(false)
            .with_writer(capture.clone())
            .finish();
        tracing::subscriber::set_global_default(subscriber).unwrap();

        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("logging-test-serial").await;
        registry
            .insert_test_error(
                "logging-error-serial",
                TransportError::from(pkcs11rs_local_hardware::Error::InvalidMessageLength {
                    actual: 3,
                    expected: Some(4),
                }),
            )
            .await;
        let app = router(registry_state(registry), 64);
        let command_uri =
            "/v1/devices/logging-test-serial/commands?logging-test=command-completion";
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(command_uri)
                    .body(Body::from(command_frame(b"command")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let log = capture.text();
        assert!(log.contains("method=POST"));
        assert!(log.contains(&format!("uri={command_uri}")));
        assert!(log.contains("HTTP request completed"));
        assert!(log.contains("hsm_serial=logging-test-serial"));
        assert!(log.contains("usb_device_id=-"));
        assert!(log.contains("hsm_outcome=\"ok\""));
        assert!(log.contains("hsm_command_elapsed_ms="));
        assert!(log.contains("http_request_elapsed_ms="));
        assert!(log.contains("status=200"));
        assert_eq!(
            log.lines()
                .filter(|line| {
                    line.contains(&format!("uri={command_uri}"))
                        && line.contains("HTTP request completed")
                })
                .count(),
            1
        );

        let error_uri = "/v1/devices/logging-error-serial/commands?logging-test=framing-error";
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(error_uri)
                    .body(Body::from(command_frame(&[])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let log = capture.text();
        let error_log = log
            .lines()
            .find(|line| {
                line.contains(&format!("uri={error_uri}"))
                    && line.contains("HTTP request completed")
            })
            .unwrap();
        assert!(error_log.contains("hsm_outcome=\"error\""));
        assert!(error_log.contains("hsm_error_code=\"invalid_command_frame\""));
        assert!(error_log.contains("hsm_error="));

        let enumeration_uri = "/v1/devices?logging-test=enumeration-completion";
        let response = app
            .oneshot(
                Request::builder()
                    .uri(enumeration_uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let log = capture.text();
        let enumeration_log = log
            .lines()
            .find(|line| {
                line.contains(&format!("uri={enumeration_uri}"))
                    && line.contains("HTTP request completed")
            })
            .unwrap();
        assert!(enumeration_log.contains("http_request_elapsed_ms="));
        assert!(!enumeration_log.contains("hsm_command_elapsed_ms="));
    }

    #[tokio::test]
    async fn modern_routes_enumerate_and_address_devices_by_serial() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        registry.insert_test_unclaimed("87654321").await;
        let app = router(
            AppState {
                registry,
                legacy_serial: None,
            },
            64,
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/devices")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains(
            r#"{"serial":"12345678","manufacturer":"Test","product":"YubiHSM","usb_version":"2.0","status":"available"}"#
        ));
        assert!(response_body.contains(
            r#"{"serial":"87654321","manufacturer":"Test","product":"YubiHSM","usb_version":"2.0","status":"unclaimed"}"#
        ));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/devices/87654321")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert!(String::from_utf8(body(response).await)
            .unwrap()
            .contains(r#""status":"unclaimed""#));

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/87654321/commands")
                    .header(CONTENT_TYPE, OCTET_STREAM)
                    .body(Body::from(command_frame(&[])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(String::from_utf8(body(response).await)
            .unwrap()
            .contains(r#""code":"device_unclaimed""#));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/12345678/commands")
                    .header(CONTENT_TYPE, OCTET_STREAM)
                    .body(Body::from(command_frame(&[])))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], OCTET_STREAM);
        assert_eq!(body(response).await, command_frame(&[]));
    }

    #[tokio::test]
    async fn legacy_routes_latch_a_device_present_at_startup() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("12345678", b"first device")
            .await;
        let app = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        );
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/connector/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=OK\n"));
        assert!(response_body.contains("serial=12345678\n"));

        registry
            .insert_test_response("87654321", b"second device")
            .await;
        let response = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        )
        .oneshot(
            Request::builder()
                .uri("/connector/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=OK\n"));
        assert!(response_body.contains("serial=12345678\n"));

        let legacy_response = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/connector/api")
                .body(Body::from(command_frame(b"command")))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(body(legacy_response).await, b"first device");

        let modern_response = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/12345678/commands")
                .body(Body::from(command_frame(b"command")))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(body(modern_response).await, b"first device");

        let response = router(
            AppState {
                registry,
                legacy_serial: Some(String::from("87654321")),
            },
            64,
        )
        .oneshot(
            Request::builder()
                .uri("/connector/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=OK\n"));
        assert!(response_body.contains("serial=87654321\n"));
    }

    #[tokio::test]
    async fn legacy_routes_latch_the_first_device_discovered_after_startup() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        let app = router(
            AppState {
                registry: registry.clone(),
                legacy_serial: None,
            },
            64,
        );

        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/connector/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=NO_DEVICE\n"));
        assert!(response_body.contains("serial=*\n"));

        registry
            .insert_test_response("12345678", b"first device")
            .await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/connector/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=OK\n"));
        assert!(response_body.contains("serial=12345678\n"));

        registry
            .insert_test_response("87654321", b"second device")
            .await;
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/connector/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let response_body = String::from_utf8(body(response).await).unwrap();
        assert!(response_body.contains("status=OK\n"));
        assert!(response_body.contains("serial=12345678\n"));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/connector/api")
                    .body(Body::from(command_frame(b"command")))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(body(response).await, b"first device");
    }

    #[tokio::test]
    async fn oversized_commands_are_rejected_before_transport() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        let response = router(
            AppState {
                registry,
                legacy_serial: None,
            },
            64,
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/12345678/commands")
                .body(Body::from(vec![0; MAX_COMMAND_BODY + 1]))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn declared_oversized_body_is_rejected_without_being_read() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        let pending_body =
            Body::from_stream(futures_util::stream::pending::<Result<Bytes, std::io::Error>>());
        let response = tokio::time::timeout(
            Duration::from_millis(50),
            router(registry_state(registry), 64).oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/12345678/commands")
                    .header(axum::http::header::CONTENT_LENGTH, MAX_COMMAND_BODY + 1)
                    .body(pending_body)
                    .unwrap(),
            ),
        )
        .await
        .expect("an oversized declared body must be rejected before it is read")
        .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn usb_validation_errors_have_specific_http_codes_and_messages() {
        let cases = [
            (
                pkcs11rs_local_hardware::Error::InvalidMessageLength {
                    actual: 3,
                    expected: Some(7),
                },
                StatusCode::BAD_REQUEST,
                "invalid_command_frame",
                "received 3 bytes, expected 7",
            ),
            (
                pkcs11rs_local_hardware::Error::SendBufferTooLarge {
                    actual: 3137,
                    maximum: 3136,
                    firmware_version: (2, 5),
                },
                StatusCode::PAYLOAD_TOO_LARGE,
                "command_too_large",
                "received 3137 bytes, maximum 3136 bytes for firmware 2.5",
            ),
            (
                pkcs11rs_local_hardware::Error::DeviceRemoved,
                StatusCode::SERVICE_UNAVAILABLE,
                "device_transport_error",
                "USB device is not connected",
            ),
        ];

        for (error, status, code, message) in cases {
            let response = command_response(
                String::from("12345678"),
                Some(String::from("test-device")),
                (Err(TransportError::from(error)), Duration::from_millis(1)),
            );
            assert_eq!(response.status(), status);
            let metrics = response.extensions().get::<HsmCommandMetrics>().unwrap();
            assert_eq!(metrics.error_code, Some(code));
            assert!(metrics.error.as_deref().unwrap().contains(message));
            let response_body = String::from_utf8(body(response).await).unwrap();
            assert!(response_body.contains(&format!("\"code\":\"{code}\"")));
            assert!(response_body.contains(message));
        }
    }

    #[tokio::test]
    async fn request_body_deadline_does_not_reset_when_data_arrives() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        let stream = futures_util::stream::unfold(0, |index| async move {
            if index == 10 {
                return None;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
            Some((Ok::<_, std::io::Error>(Bytes::from_static(b"a")), index + 1))
        });
        let response = router_with_request_body_deadline(
            registry_state(registry),
            Duration::from_millis(25),
            64,
        )
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/12345678/commands")
                .body(Body::from_stream(stream))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[derive(Clone)]
    struct BlockingRequest {
        entered: std::sync::Arc<tokio::sync::Notify>,
        release: std::sync::Arc<tokio::sync::Notify>,
    }

    async fn block_request(State(state): State<BlockingRequest>) {
        state.entered.notify_one();
        state.release.notified().await;
    }

    async fn fast_request() {}

    #[tokio::test]
    async fn global_request_limit_sheds_load_and_keeps_the_http2_connection_usable() {
        let entered = std::sync::Arc::new(tokio::sync::Notify::new());
        let release = std::sync::Arc::new(tokio::sync::Notify::new());
        let app = Router::new()
            .route("/block", get(block_request))
            .route("/fast", get(fast_request))
            .with_state(BlockingRequest {
                entered: entered.clone(),
                release: release.clone(),
            });
        let app = with_global_request_limit(app, 1);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let (mut sender, connection) = hyper::client::conn::http2::handshake::<_, _, Full<Bytes>>(
            TokioExecutor::new(),
            TokioIo::new(TcpStream::connect(address).await.unwrap()),
        )
        .await
        .unwrap();
        let connection = tokio::spawn(connection);

        let mut first_sender = sender.clone();
        let first = tokio::spawn(async move {
            first_sender
                .send_request(
                    Request::builder()
                        .uri(format!("http://{address}/block"))
                        .body(Full::new(Bytes::new()))
                        .unwrap(),
                )
                .await
                .unwrap()
        });
        entered.notified().await;

        let overloaded = tokio::time::timeout(
            Duration::from_millis(50),
            sender.send_request(
                Request::builder()
                    .uri(format!("http://{address}/fast"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            ),
        )
        .await
        .expect("an overloaded request must not wait")
        .unwrap();
        assert_eq!(overloaded.status(), StatusCode::SERVICE_UNAVAILABLE);
        let overloaded_body = overloaded.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8(overloaded_body.to_vec())
            .unwrap()
            .contains("server_overloaded"));

        release.notify_one();
        assert_eq!(first.await.unwrap().status(), StatusCode::OK);

        let recovered = sender
            .send_request(
                Request::builder()
                    .uri(format!("http://{address}/fast"))
                    .body(Full::new(Bytes::new()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(recovered.status(), StatusCode::OK);

        drop(sender);
        connection.abort();
        server.abort();
    }

    fn registry_state(registry: DeviceRegistry) -> AppState {
        AppState {
            registry,
            legacy_serial: None,
        }
    }
}
