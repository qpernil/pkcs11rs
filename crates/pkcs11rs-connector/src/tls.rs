use rustls::{RootCertStore, ServerConfig, server::WebPkiClientVerifier};
use std::{fs::File, io::BufReader, path::Path, sync::Arc};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

pub fn server_config(
    certificate_path: &Path,
    private_key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<ServerConfig, BoxError> {
    let server_certificates = certificates(certificate_path)?;
    if server_certificates.is_empty() {
        return Err(format!("{} contains no certificates", certificate_path.display()).into());
    }
    let private_key =
        rustls_pemfile::private_key(&mut BufReader::new(File::open(private_key_path)?))?
            .ok_or_else(|| format!("{} contains no private key", private_key_path.display()))?;

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])?;
    let mut config = if let Some(client_ca_path) = client_ca_path {
        let mut roots = RootCertStore::empty();
        for certificate in certificates(client_ca_path)? {
            roots.add(certificate)?;
        }
        if roots.is_empty() {
            return Err(format!("{} contains no CA certificates", client_ca_path.display()).into());
        }
        let verifier = WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()?;
        builder
            .with_client_cert_verifier(verifier)
            .with_single_cert(server_certificates, private_key)?
    } else {
        builder
            .with_no_client_auth()
            .with_single_cert(server_certificates, private_key)?
    };
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(config)
}

fn certificates(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>, BoxError> {
    rustls_pemfile::certs(&mut BufReader::new(File::open(path)?))
        .collect::<Result<Vec<_>, _>>()
        .map_err(Into::into)
}
