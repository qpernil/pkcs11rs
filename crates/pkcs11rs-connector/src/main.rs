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
}
