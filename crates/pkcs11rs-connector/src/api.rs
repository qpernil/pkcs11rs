use crate::registry::{DeviceRegistry, LegacySelectionError};
use axum::{
    body::Bytes,
    extract::{DefaultBodyLimit, Path, State},
    http::{header::CONTENT_TYPE, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::Serialize;

const MAX_COMMAND_BODY: usize = 3139;
const OCTET_STREAM: &str = "application/octet-stream";

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

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/v1/devices", get(list_devices))
        .route("/v1/devices/{serial}", get(get_device))
        .route("/v1/devices/{serial}/commands", post(device_command))
        .route("/connector/status", get(legacy_status))
        .route("/connector/api", post(legacy_command))
        .layer(DefaultBodyLimit::max(MAX_COMMAND_BODY))
        .with_state(state)
}

async fn list_devices(State(state): State<AppState>) -> Json<DeviceList> {
    Json(DeviceList {
        devices: state.registry.list().await,
    })
}

async fn get_device(Path(serial): Path<String>, State(state): State<AppState>) -> Response {
    match state.registry.get(&serial).await {
        Some(entry) => Json(entry.view()).into_response(),
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
        return problem(
            StatusCode::NOT_FOUND,
            "device_not_found",
            format!("no attached YubiHSM has serial {serial}"),
        );
    };
    command_response(entry.command(&body).await)
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
        Ok(entry) => command_response(entry.command(&body).await),
        Err(LegacySelectionError::NoDevice) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "no_device",
            String::from("the legacy YubiHSM is not attached"),
        ),
    }
}

fn command_response(result: Result<Vec<u8>, crate::registry::TransportError>) -> Response {
    match result {
        Ok(response) => (StatusCode::OK, [(CONTENT_TYPE, OCTET_STREAM)], response).into_response(),
        Err(error) => problem(
            StatusCode::SERVICE_UNAVAILABLE,
            "device_transport_error",
            error.to_string(),
        ),
    }
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
    use http_body_util::BodyExt;
    use std::time::Duration;
    use tower::ServiceExt;

    async fn body(response: Response) -> Vec<u8> {
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec()
    }

    #[tokio::test]
    async fn modern_routes_enumerate_and_address_devices_by_serial() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry.insert_test_echo("12345678").await;
        let app = router(AppState {
            registry,
            legacy_serial: None,
        });

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
        assert!(response_body.contains("12345678"));

        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/devices/12345678/commands")
                    .header(CONTENT_TYPE, OCTET_STREAM)
                    .body(Body::from(vec![0x03, 0x01, 0x00]))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[CONTENT_TYPE], OCTET_STREAM);
        assert_eq!(body(response).await, [0x03, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn legacy_routes_latch_a_device_present_at_startup() {
        let registry = DeviceRegistry::new(Duration::from_secs(1));
        registry
            .insert_test_response("12345678", b"first device")
            .await;
        let app = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        });
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
        let response = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        })
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

        let legacy_response = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        })
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/connector/api")
                .body(Body::from("command"))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(body(legacy_response).await, b"first device");

        let modern_response = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        })
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devices/12345678/commands")
                .body(Body::from("command"))
                .unwrap(),
        )
        .await
        .unwrap();
        assert_eq!(body(modern_response).await, b"first device");

        let response = router(AppState {
            registry,
            legacy_serial: Some(String::from("87654321")),
        })
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
        let app = router(AppState {
            registry: registry.clone(),
            legacy_serial: None,
        });

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
                    .body(Body::from("command"))
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
        let response = router(AppState {
            registry,
            legacy_serial: None,
        })
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
}
