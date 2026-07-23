use crate::{Error, CKR_ARGUMENTS_BAD, CKR_CANCEL, CKR_CANT_LOCK, CKR_FUNCTION_FAILED};
use std::{
    ffi::{OsStr, OsString},
    io::{BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
    sync::Mutex,
};
use zeroize::Zeroizing;

const CONFIGURATION_ENV: &str = "PKCS11RS_PINENTRY";
const MAX_RESPONSE_LINE: usize = 1024 * 1024;

static PROGRAM: Mutex<Option<OsString>> = Mutex::new(None);
static PROMPT: Mutex<()> = Mutex::new(());

pub(crate) struct Prompt<'a> {
    pub(crate) title: &'a str,
    pub(crate) description: &'a str,
    pub(crate) label: &'a str,
}

pub(crate) fn configure_from_environment() -> Result<(), Error> {
    configure(std::env::var_os(CONFIGURATION_ENV))
}

fn configure(value: Option<OsString>) -> Result<(), Error> {
    let value = parse_configuration(value)?;
    match value.as_deref() {
        Some(program) => log!(2, "Pinentry configured with executable {:?}", program),
        None => log!(2, "Pinentry is not configured"),
    }
    *PROGRAM.lock().map_err(|_| CKR_CANT_LOCK)? = value;
    Ok(())
}

#[cfg(test)]
pub(crate) fn configure_for_test(value: Option<OsString>) -> Result<(), Error> {
    configure(value)
}

fn parse_configuration(value: Option<OsString>) -> Result<Option<OsString>, Error> {
    if value.as_ref().is_some_and(|value| value.is_empty()) {
        return Err(CKR_ARGUMENTS_BAD.into());
    }
    Ok(value)
}

pub(crate) fn is_configured() -> bool {
    PROGRAM
        .lock()
        .map(|program| program.is_some())
        .unwrap_or(false)
}

pub(crate) fn request(prompt: Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let program = PROGRAM
        .lock()
        .map_err(|_| CKR_CANT_LOCK)?
        .clone()
        .ok_or(CKR_ARGUMENTS_BAD)?;
    let _prompt = PROMPT.lock().map_err(|_| CKR_CANT_LOCK)?;
    log!(
        2,
        "Starting pinentry executable {:?} for prompt {:?}",
        program,
        prompt.label
    );
    let result = Client::start(&program).and_then(|client| client.request(prompt));
    match &result {
        Ok(_) => log!(2, "Pinentry returned a password"),
        Err(Error::Generic(rv)) if *rv == CKR_CANCEL as crate::CK_RV => {
            log!(2, "Pinentry prompt was cancelled")
        }
        Err(error) => log!(2, "Pinentry prompt failed: {:?}", error),
    }
    result
}

struct Client {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Client {
    fn start(program: &OsStr) -> Result<Self, Error> {
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().ok_or(CKR_FUNCTION_FAILED)?;
        let output = child.stdout.take().ok_or(CKR_FUNCTION_FAILED)?;
        let mut client = Self {
            child,
            input,
            output: BufReader::new(output),
        };
        client.expect_ok()?;
        log!(2, "Pinentry Assuan connection established");
        Ok(client)
    }

    fn request(mut self, prompt: Prompt<'_>) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.optional_environment("ttyname", tty_name(std::env::var_os("GPG_TTY")))?;
        self.optional_environment("ttytype", std::env::var_os("TERM"))?;
        self.command("SETTITLE", Some(prompt.title))?;
        self.command("SETDESC", Some(prompt.description))?;
        self.command("SETPROMPT", Some(prompt.label))?;
        self.write_command("GETPIN", None)?;
        let secret = match self.response()? {
            Response::Ok(secret) => Zeroizing::new(secret),
            Response::Error => return Err(CKR_CANCEL.into()),
        };
        if std::str::from_utf8(secret.as_slice()).is_err() {
            return Err(crate::CKR_PIN_INVALID.into());
        }
        self.write_command("BYE", None)?;
        let _ = self.response();
        let _ = self.child.wait();
        Ok(secret)
    }

    fn optional_environment(&mut self, name: &str, value: Option<OsString>) -> Result<(), Error> {
        let Some(value) = value.and_then(|value| value.into_string().ok()) else {
            return Ok(());
        };
        self.write_command("OPTION", Some(&format!("{name}={value}")))?;
        if matches!(self.response()?, Response::Error) {
            log!(2, "Pinentry rejected optional Assuan setting {:?}", name);
        }
        Ok(())
    }

    fn command(&mut self, command: &str, argument: Option<&str>) -> Result<(), Error> {
        self.write_command(command, argument)?;
        self.expect_ok()
    }

    fn write_command(&mut self, command: &str, argument: Option<&str>) -> Result<(), Error> {
        self.input.write_all(command.as_bytes())?;
        if let Some(argument) = argument {
            self.input.write_all(b" ")?;
            self.input
                .write_all(escape(argument.as_bytes()).as_bytes())?;
        }
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }

    fn expect_ok(&mut self) -> Result<(), Error> {
        match self.response()? {
            Response::Ok(_) => Ok(()),
            Response::Error => Err(CKR_FUNCTION_FAILED.into()),
        }
    }

    fn response(&mut self) -> Result<Response, Error> {
        let mut data = Vec::new();
        loop {
            let mut line = Vec::new();
            let length = self.output.read_until(b'\n', &mut line)?;
            if length == 0 || line.len() > MAX_RESPONSE_LINE {
                return Err(CKR_FUNCTION_FAILED.into());
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line == b"OK" || line.starts_with(b"OK ") {
                return Ok(Response::Ok(data));
            }
            if line == b"ERR" || line.starts_with(b"ERR ") {
                log!(2, "Pinentry returned an Assuan error");
                return Ok(Response::Error);
            }
            if let Some(value) = line.strip_prefix(b"D ") {
                data.extend_from_slice(&unescape(value)?);
                continue;
            }
            if line.starts_with(b"S ") || line.starts_with(b"#") {
                continue;
            }
            log!(2, "Pinentry returned an unexpected Assuan response");
            return Err(CKR_FUNCTION_FAILED.into());
        }
    }
}

fn tty_name(configured: Option<OsString>) -> Option<OsString> {
    #[cfg(unix)]
    {
        configured
            .filter(|value| !value.is_empty())
            .or_else(|| Some(OsString::from("/dev/tty")))
    }
    #[cfg(not(unix))]
    {
        let _ = configured;
        None
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

enum Response {
    Ok(Vec<u8>),
    Error,
}

fn escape(value: &[u8]) -> String {
    let mut escaped = String::with_capacity(value.len());
    for byte in value {
        if byte.is_ascii_alphanumeric() || matches!(byte, b' ' | b'_' | b'-' | b'.') {
            escaped.push(char::from(*byte));
        } else {
            escaped.push('%');
            escaped.push(hex(byte >> 4));
            escaped.push(hex(byte & 0x0f));
        }
    }
    escaped
}

fn unescape(value: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::with_capacity(value.len());
    let mut index = 0;
    while index < value.len() {
        if value[index] != b'%' {
            decoded.push(value[index]);
            index += 1;
            continue;
        }
        let high = value.get(index + 1).and_then(|value| unhex(*value));
        let low = value.get(index + 2).and_then(|value| unhex(*value));
        decoded.push(
            high.zip(low)
                .map(|(high, low)| high << 4 | low)
                .ok_or(CKR_FUNCTION_FAILED)?,
        );
        index += 3;
    }
    Ok(decoded)
}

fn hex(value: u8) -> char {
    char::from(if value < 10 {
        b'0' + value
    } else {
        b'A' + value - 10
    })
}

fn unhex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assuan_arguments_and_data_are_encoded_without_loss() {
        assert_eq!(escape(b"prompt: 100%"), "prompt%3A 100%25");
        assert_eq!(
            unescape(b"p%C3%A5ss%25word").unwrap(),
            "påss%word".as_bytes()
        );
        assert!(unescape(b"truncated%2").is_err());
        assert!(unescape(b"invalid%XX").is_err());
    }

    #[test]
    fn pinentry_configuration_is_explicit() {
        assert_eq!(parse_configuration(None).unwrap(), None);
        assert_eq!(
            parse_configuration(Some(OsString::from("pinentry-mac"))).unwrap(),
            Some(OsString::from("pinentry-mac"))
        );
        assert!(parse_configuration(Some(OsString::new())).is_err());
    }

    #[test]
    fn configured_tty_overrides_the_platform_default() {
        #[cfg(unix)]
        {
            assert_eq!(
                tty_name(Some(OsString::from("/dev/ttys123"))),
                Some(OsString::from("/dev/ttys123"))
            );
            assert_eq!(tty_name(None), Some(OsString::from("/dev/tty")));
        }
        #[cfg(not(unix))]
        {
            assert_eq!(tty_name(Some(OsString::from("ignored"))), None);
            assert_eq!(tty_name(None), None);
        }
    }

    #[cfg(unix)]
    #[test]
    fn obtains_and_decodes_a_secret_from_a_pinentry_process() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "pkcs11rs-pinentry-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("test")
        ));
        std::fs::write(
            &path,
            br#"#!/bin/sh
printf '%s\n' 'OK ready'
while IFS= read -r command; do
    case "$command" in
        GETPIN)
            printf '%s\n' 'D p%C3%A5ss%25word' 'OK'
            ;;
        BYE)
            printf '%s\n' 'OK'
            exit 0
            ;;
        *)
            printf '%s\n' 'OK'
            ;;
    esac
done
"#,
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&path).unwrap().permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&path, permissions).unwrap();

        let secret = Client::start(path.as_os_str())
            .unwrap()
            .request(Prompt {
                title: "PKCS #11",
                description: "Authenticate",
                label: "Password:",
            })
            .unwrap();
        assert_eq!(secret.as_slice(), "påss%word".as_bytes());
        std::fs::remove_file(path).unwrap();
    }
}
