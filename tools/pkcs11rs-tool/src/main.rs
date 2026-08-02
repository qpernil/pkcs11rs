use base64::{engine::general_purpose::STANDARD, Engine};
use der::Decode;
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process,
};
use x509_cert::Certificate;

#[path = "../../../src/certificate_bundle.rs"]
mod certificate_bundle;
#[path = "../../../src/encrypted_private_key.rs"]
mod encrypted_private_key;
mod pinentry;
#[path = "../../../src/pinentry_client.rs"]
mod pinentry_client;
mod validation;

use validation::Purpose;

const USAGE: &str = "\
usage:
  pkcs11rs-tool certificate-bundle create --purpose PURPOSE --output FILE [--key FILE] [--trust FILE] [--force] CERTIFICATE...
  pkcs11rs-tool certificate-bundle verify --purpose PURPOSE [--key FILE] [--trust FILE] FILE

purposes:
  certificate-collection  canonical certificates with no chain semantics
  yubihsm-tls-client      leaf-first TLS client chain and matching encrypted key
  yubihsm-tls-ca          independent TLS trust anchors
  scp11-oce               leaf-first SCP11 OCE chain and matching encrypted P-256 key

CERTIFICATE inputs may be canonical DER files or PEM files containing one or
more CERTIFICATE blocks. Identity purposes require --key and use
PKCS11RS_PINENTRY to unlock password-encrypted PKCS #8 DER. --trust names a
canonical CBOR certificate bundle containing explicit trust anchors.";

fn main() {
    if let Err(error) = run(env::args_os().skip(1).collect()) {
        eprintln!("pkcs11rs-tool: {error}");
        process::exit(1);
    }
}

enum Operation {
    Create,
    Verify,
}

struct Options {
    operation: Operation,
    purpose: Purpose,
    output: Option<PathBuf>,
    key: Option<PathBuf>,
    trust: Option<PathBuf>,
    force: bool,
    inputs: Vec<PathBuf>,
}

fn run(arguments: Vec<OsString>) -> Result<(), String> {
    let options = parse_arguments(arguments)?;
    match options.operation {
        Operation::Create => create(options),
        Operation::Verify => verify(options),
    }
}

fn parse_arguments(arguments: Vec<OsString>) -> Result<Options, String> {
    let mut arguments = arguments.into_iter();
    if arguments.next().as_deref() != Some(std::ffi::OsStr::new("certificate-bundle")) {
        return Err(USAGE.to_owned());
    }
    let operation = match arguments.next().and_then(|value| value.into_string().ok()) {
        Some(value) if value == "create" => Operation::Create,
        Some(value) if value == "verify" => Operation::Verify,
        _ => return Err(USAGE.to_owned()),
    };

    let mut purpose = None;
    let mut output = None;
    let mut key = None;
    let mut trust = None;
    let mut force = false;
    let mut inputs = Vec::new();
    let mut positional = false;
    while let Some(argument) = arguments.next() {
        if positional {
            inputs.push(PathBuf::from(argument));
            continue;
        }
        match argument.to_str() {
            Some("--") => positional = true,
            Some("--purpose") => {
                let value = option_value(&mut arguments, "--purpose")?;
                let value = value
                    .to_str()
                    .ok_or_else(|| "--purpose must be UTF-8".to_owned())?;
                set_once(&mut purpose, Purpose::parse(value)?, "--purpose")?;
            }
            Some("--output") => {
                let value = PathBuf::from(option_value(&mut arguments, "--output")?);
                set_once(&mut output, value, "--output")?;
            }
            Some("--key") => {
                let value = PathBuf::from(option_value(&mut arguments, "--key")?);
                set_once(&mut key, value, "--key")?;
            }
            Some("--trust") => {
                let value = PathBuf::from(option_value(&mut arguments, "--trust")?);
                set_once(&mut trust, value, "--trust")?;
            }
            Some("--force") => force = true,
            Some(value) if value.starts_with('-') => {
                return Err(format!("unknown option {value:?}\n\n{USAGE}"));
            }
            _ => inputs.push(PathBuf::from(argument)),
        }
    }

    let purpose = purpose.ok_or_else(|| "--purpose is required".to_owned())?;
    if purpose.requires_key() != key.is_some() {
        return Err(if purpose.requires_key() {
            "this purpose requires --key".to_owned()
        } else {
            "--key is not applicable to this purpose".to_owned()
        });
    }
    if trust.is_some() && !purpose.accepts_trust() {
        return Err("--trust is not applicable to this purpose".to_owned());
    }

    match operation {
        Operation::Create => {
            if inputs.is_empty() {
                return Err("create requires at least one certificate input".to_owned());
            }
            let output_path = output
                .as_ref()
                .ok_or_else(|| "create requires --output".to_owned())?;
            if output_path
                .extension()
                .and_then(|extension| extension.to_str())
                != Some("cbor")
            {
                return Err("certificate-bundle output must use the .cbor extension".to_owned());
            }
        }
        Operation::Verify => {
            if output.is_some() {
                return Err("--output is not applicable to verify".to_owned());
            }
            if force {
                return Err("--force is not applicable to verify".to_owned());
            }
            if inputs.len() != 1 {
                return Err("verify requires exactly one certificate bundle".to_owned());
            }
        }
    }

    Ok(Options {
        operation,
        purpose,
        output,
        key,
        trust,
        force,
        inputs,
    })
}

fn option_value(
    arguments: &mut impl Iterator<Item = OsString>,
    option: &str,
) -> Result<OsString, String> {
    arguments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("{option} requires a value"))
}

fn set_once<T>(slot: &mut Option<T>, value: T, option: &str) -> Result<(), String> {
    if slot.replace(value).is_some() {
        Err(format!("{option} may only be specified once"))
    } else {
        Ok(())
    }
}

fn create(options: Options) -> Result<(), String> {
    let certificates = import_certificates(&options.inputs)?;
    let trust = load_optional_bundle(options.trust.as_deref())?;
    validation::validate(
        options.purpose,
        &certificates,
        options.key.as_deref(),
        trust.as_deref(),
    )?;
    let encoded = certificate_bundle::encode(&certificates).map_err(|error| error.to_string())?;
    let decoded = certificate_bundle::decode(&encoded).map_err(|error| error.to_string())?;
    if decoded != certificates {
        return Err("generated bundle failed its canonical round trip".to_owned());
    }
    let output = options.output.expect("validated by argument parser");
    write_output(&output, &encoded, options.force)?;
    println!(
        "created {} with {} certificate{}",
        output.display(),
        certificates.len(),
        if certificates.len() == 1 { "" } else { "s" }
    );
    report_certificates(&certificates)?;
    Ok(())
}

fn verify(options: Options) -> Result<(), String> {
    let path = &options.inputs[0];
    let encoded = fs::read(path)
        .map_err(|error| format!("read certificate bundle {}: {error}", path.display()))?;
    let certificates = certificate_bundle::decode(&encoded)
        .map_err(|error| format!("decode certificate bundle {}: {error}", path.display()))?;
    let trust = load_optional_bundle(options.trust.as_deref())?;
    validation::validate(
        options.purpose,
        &certificates,
        options.key.as_deref(),
        trust.as_deref(),
    )?;
    println!(
        "verified {} with {} certificate{}",
        path.display(),
        certificates.len(),
        if certificates.len() == 1 { "" } else { "s" }
    );
    report_certificates(&certificates)
}

fn load_optional_bundle(path: Option<&Path>) -> Result<Option<Vec<Vec<u8>>>, String> {
    path.map(|path| {
        let encoded = fs::read(path)
            .map_err(|error| format!("read trust bundle {}: {error}", path.display()))?;
        certificate_bundle::decode(&encoded)
            .map_err(|error| format!("decode trust bundle {}: {error}", path.display()))
    })
    .transpose()
}

fn import_certificates(paths: &[PathBuf]) -> Result<Vec<Vec<u8>>, String> {
    let mut certificates = Vec::new();
    let mut fingerprints = HashSet::new();
    for path in paths {
        let encoded = fs::read(path)
            .map_err(|error| format!("read certificate input {}: {error}", path.display()))?;
        let imported = if starts_with_pem_marker(&encoded) {
            decode_pem_certificates(&encoded)
                .map_err(|error| format!("import PEM {}: {error}", path.display()))?
        } else {
            vec![certificate_bundle::decode_certificate(&encoded)
                .map_err(|error| format!("import DER {}: {error}", path.display()))?]
        };
        for certificate in imported {
            let fingerprint: [u8; 32] = Sha256::digest(&certificate).into();
            if !fingerprints.insert(fingerprint) {
                return Err(format!(
                    "certificate input {} contains or repeats a duplicate certificate",
                    path.display()
                ));
            }
            certificates.push(certificate);
        }
    }
    Ok(certificates)
}

fn starts_with_pem_marker(encoded: &[u8]) -> bool {
    let first = encoded
        .iter()
        .position(|byte| !byte.is_ascii_whitespace())
        .unwrap_or(encoded.len());
    encoded[first..].starts_with(b"-----BEGIN ")
}

fn decode_pem_certificates(encoded: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let text = std::str::from_utf8(encoded).map_err(|_| "PEM is not UTF-8".to_owned())?;
    let mut certificates = Vec::new();
    let mut base64 = None::<String>;
    for raw_line in text.lines() {
        let line = raw_line.strip_suffix('\r').unwrap_or(raw_line).trim();
        match (&mut base64, line) {
            (None, "") => {}
            (None, "-----BEGIN CERTIFICATE-----") => base64 = Some(String::new()),
            (None, _) => {
                return Err(
                    "only CERTIFICATE blocks and surrounding whitespace are allowed".to_owned(),
                )
            }
            (Some(value), "-----END CERTIFICATE-----") => {
                let decoded = STANDARD
                    .decode(value.as_bytes())
                    .map_err(|_| "invalid certificate base64".to_owned())?;
                certificates.push(
                    certificate_bundle::decode_certificate(&decoded)
                        .map_err(|error| error.to_string())?,
                );
                base64 = None;
            }
            (Some(_), value) if value.starts_with("-----") || value.is_empty() => {
                return Err("malformed CERTIFICATE block".to_owned())
            }
            (Some(base64), value) => base64.push_str(value),
        }
    }
    if base64.is_some() {
        return Err("unterminated CERTIFICATE block".to_owned());
    }
    if certificates.is_empty() {
        return Err("PEM contains no certificates".to_owned());
    }
    Ok(certificates)
}

fn write_output(path: &Path, encoded: &[u8], force: bool) -> Result<(), String> {
    if force {
        return fs::write(path, encoded)
            .map_err(|error| format!("write certificate bundle {}: {error}", path.display()));
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create certificate bundle {}: {error}", path.display()))?;
    if let Err(error) = output.write_all(encoded) {
        drop(output);
        let _ = fs::remove_file(path);
        return Err(format!(
            "write certificate bundle {}: {error}",
            path.display()
        ));
    }
    Ok(())
}

fn report_certificates(certificates: &[Vec<u8>]) -> Result<(), String> {
    for (index, encoded) in certificates.iter().enumerate() {
        let certificate = Certificate::from_der(encoded)
            .map_err(|error| format!("parse certificate {} for report: {error}", index + 1))?;
        let fingerprint = Sha256::digest(encoded);
        let fingerprint = fingerprint
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        println!(
            "  {}: {}  sha256:{}",
            index + 1,
            certificate.tbs_certificate().subject(),
            fingerprint
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pem(label: &str, encoded: &[u8]) -> String {
        let encoded = STANDARD.encode(encoded);
        let body = encoded
            .as_bytes()
            .chunks(64)
            .map(|line| std::str::from_utf8(line).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        format!("-----BEGIN {label}-----\n{body}\n-----END {label}-----\n")
    }

    #[test]
    fn imports_multiple_pem_certificates_in_order() {
        let first = include_bytes!("../../../certificates/yubikey/yubico-attestation-root-1.der");
        let second = include_bytes!("../../../certificates/yubikey/yubico-fido-ca-1.der");
        let encoded = format!(
            "\n{}\r\n{}",
            pem("CERTIFICATE", first),
            pem("CERTIFICATE", second)
        );
        let decoded = decode_pem_certificates(encoded.as_bytes()).unwrap();
        assert_eq!(decoded, [first.as_slice(), second.as_slice()]);
    }

    #[test]
    fn rejects_noncertificate_pem_blocks_and_text() {
        assert!(decode_pem_certificates(pem("PRIVATE KEY", b"key").as_bytes()).is_err());
        assert!(decode_pem_certificates(b"comment\n").is_err());
    }

    #[test]
    fn parser_requires_purpose_and_key_by_profile() {
        assert!(parse_arguments(vec![
            "certificate-bundle".into(),
            "verify".into(),
            "bundle.cbor".into(),
        ])
        .is_err());
        assert!(parse_arguments(vec![
            "certificate-bundle".into(),
            "verify".into(),
            "--purpose".into(),
            "scp11-oce".into(),
            "bundle.cbor".into(),
        ])
        .is_err());
    }
}
