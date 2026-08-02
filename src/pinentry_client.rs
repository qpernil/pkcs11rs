use std::{
    ffi::{OsStr, OsString},
    fmt,
    io::{self, BufRead, BufReader, Write},
    process::{Child, ChildStdin, ChildStdout, Command, Stdio},
};
use zeroize::Zeroizing;

const MAX_RESPONSE_LINE: usize = 1024 * 1024;

pub(crate) struct Prompt<'a> {
    pub(crate) title: &'a str,
    pub(crate) description: &'a str,
    pub(crate) label: &'a str,
}

#[derive(Debug)]
pub(crate) enum Error {
    Io(io::Error),
    Protocol,
    Cancelled,
    InvalidSecret,
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => error.fmt(formatter),
            Self::Protocol => formatter.write_str("invalid pinentry protocol exchange"),
            Self::Cancelled => formatter.write_str("pinentry prompt was cancelled"),
            Self::InvalidSecret => formatter.write_str("pinentry returned a non-UTF-8 password"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub(crate) fn request(
    program: &OsStr,
    prompt: Prompt<'_>,
    configured_tty: Option<OsString>,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    Client::start(program)?.request(prompt, configured_tty)
}

struct Client {
    child: Child,
    input: ChildStdin,
    output: BufReader<ChildStdout>,
}

impl Client {
    fn start(program: &OsStr) -> Result<Self, Error> {
        Self::start_command(Command::new(program))
    }

    fn start_command(mut command: Command) -> Result<Self, Error> {
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        let input = child.stdin.take().ok_or(Error::Protocol)?;
        let output = child.stdout.take().ok_or(Error::Protocol)?;
        let mut client = Self {
            child,
            input,
            output: BufReader::new(output),
        };
        client.expect_ok()?;
        Ok(client)
    }

    fn request(
        mut self,
        prompt: Prompt<'_>,
        configured_tty: Option<OsString>,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        self.optional_environment("ttyname", tty_name(configured_tty))?;
        self.optional_environment("ttytype", std::env::var_os("TERM"))?;
        self.command("SETTITLE", Some(prompt.title))?;
        self.command("SETDESC", Some(prompt.description))?;
        self.command("SETPROMPT", Some(prompt.label))?;
        self.write_command("GETPIN", None)?;
        let secret = match self.response()? {
            Response::Ok(secret) => Zeroizing::new(secret),
            Response::Error => return Err(Error::Cancelled),
        };
        if std::str::from_utf8(secret.as_slice()).is_err() {
            return Err(Error::InvalidSecret);
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
        let _ = self.response()?;
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
            Response::Error => Err(Error::Protocol),
        }
    }

    fn response(&mut self) -> Result<Response, Error> {
        let mut data = Vec::new();
        loop {
            let mut line = Vec::new();
            let length = self.output.read_until(b'\n', &mut line)?;
            if length == 0 || line.len() > MAX_RESPONSE_LINE {
                return Err(Error::Protocol);
            }
            while matches!(line.last(), Some(b'\n' | b'\r')) {
                line.pop();
            }
            if line == b"OK" || line.starts_with(b"OK ") {
                return Ok(Response::Ok(data));
            }
            if line == b"ERR" || line.starts_with(b"ERR ") {
                return Ok(Response::Error);
            }
            if let Some(value) = line.strip_prefix(b"D ") {
                data.extend_from_slice(&unescape(value)?);
                continue;
            }
            if !line.starts_with(b"S ") && !line.starts_with(b"#") {
                return Err(Error::Protocol);
            }
        }
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
        let decoded_byte = value
            .get(index + 1)
            .and_then(|high| unhex(*high))
            .zip(value.get(index + 2).and_then(|low| unhex(*low)))
            .map(|(high, low)| high << 4 | low)
            .ok_or(Error::Protocol)?;
        decoded.push(decoded_byte);
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
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(
            r#"
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
        );

        let secret = Client::start_command(command)
            .unwrap()
            .request(
                Prompt {
                    title: "PKCS #11",
                    description: "Authenticate",
                    label: "Password:",
                },
                None,
            )
            .unwrap();
        assert_eq!(secret.as_slice(), "påss%word".as_bytes());
    }
}
