use super::{AlgorithmArg, Command};
use crate::{
    credentials::{self, Algorithm, CredentialRecord},
    error::{Error, Result},
    storage::SecretStore,
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEventKind, KeyModifiers},
    terminal,
};
use std::io::{self, IsTerminal, Read, Write};
use zeroize::{Zeroize, Zeroizing};

pub const MAX_INPUT_BYTES: usize = 16 * 1024;

pub trait Input {
    fn secret(&mut self, stdin: bool, prompt: &str) -> Result<Zeroizing<String>>;
    fn confirm(&mut self) -> Result<bool>;
}

pub struct TerminalInput;

fn input_error() -> Error {
    Error::InvalidConfiguration("input must be nonempty UTF-8 and at most 16384 bytes".into())
}
fn io_error(_: io::Error) -> Error {
    Error::General("input/output operation failed".into())
}

/// Read only an explicitly selected stream, retaining at most the bounded input.
pub fn read_bounded(reader: &mut dyn Read) -> Result<Zeroizing<String>> {
    let mut bytes = Zeroizing::new(Vec::new());
    reader
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(input_error());
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| input_error())?;
    let text = text.trim();
    if text.is_empty() {
        return Err(input_error());
    }
    Ok(Zeroizing::new(text.to_owned()))
}

struct RawMode;
impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = terminal::disable_raw_mode();
    }
}

impl TerminalInput {
    fn concealed(&mut self, prompt: &str) -> Result<Zeroizing<String>> {
        if !io::stdin().is_terminal() || !io::stderr().is_terminal() {
            return Err(Error::InteractionRequired("interactive input requires a terminal; select --secret-stdin or import --stdin explicitly".into()));
        }
        eprint!("{prompt}");
        io::stderr().flush().map_err(io_error)?;
        terminal::enable_raw_mode().map_err(io_error)?;
        let guard = RawMode;
        let mut value = Zeroizing::new(String::new());
        loop {
            if let Event::Key(mut key) = event::read().map_err(io_error)? {
                if key.kind == KeyEventKind::Release {
                    continue;
                }
                match key.code {
                    KeyCode::Enter => break,
                    KeyCode::Esc => {
                        return Err(Error::InteractionRequired("input cancelled".into()))
                    }
                    KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                        return Err(Error::InteractionRequired("input cancelled".into()))
                    }
                    KeyCode::Backspace => {
                        value.pop();
                    }
                    KeyCode::Char(mut c) if !c.is_control() => {
                        if value.len() + c.len_utf8() > MAX_INPUT_BYTES {
                            c.zeroize();
                            return Err(input_error());
                        }
                        value.push(c);
                        c.zeroize();
                    }
                    _ => {}
                }
                if let KeyCode::Char(ref mut character) = key.code {
                    character.zeroize();
                }
            }
        }
        drop(guard);
        eprintln!();
        if value.trim().is_empty() {
            return Err(input_error());
        }
        Ok(value)
    }
}

impl Input for TerminalInput {
    fn secret(&mut self, stdin: bool, prompt: &str) -> Result<Zeroizing<String>> {
        if stdin {
            read_bounded(&mut io::stdin().lock())
        } else {
            self.concealed(prompt)
        }
    }
    fn confirm(&mut self) -> Result<bool> {
        Ok(self
            .concealed("Delete credential? Type yes to confirm: ")?
            .as_str()
            == "yes")
    }
}

pub enum Prepared {
    Store {
        name: String,
        record: CredentialRecord,
        replace: bool,
    },
    Get(String),
    List,
    Remove(String),
    Doctor,
    Version,
}

pub fn prepare(command: Command, input: &mut dyn Input) -> Result<Prepared> {
    match command {
        Command::Add {
            name,
            secret_stdin,
            replace,
            algorithm,
            digits,
            period,
            t0,
            issuer,
            account,
        } => {
            credentials::validate_identifier(&name)?;
            let secret = input.secret(secret_stdin, "Base32 seed: ")?;
            let algorithm = match algorithm {
                AlgorithmArg::Sha1 => Algorithm::SHA1,
                AlgorithmArg::Sha256 => Algorithm::SHA256,
                AlgorithmArg::Sha512 => Algorithm::SHA512,
            };
            let record =
                CredentialRecord::new(&secret, algorithm, digits, period, t0, issuer, account)?;
            Ok(Prepared::Store {
                name,
                record,
                replace,
            })
        }
        Command::Import {
            stdin,
            name,
            replace,
        } => {
            if let Some(ref name) = name {
                credentials::validate_identifier(name)?;
            }
            let uri = input.secret(stdin, "OTPAuth URI: ")?;
            let record = credentials::parse_otpauth(&uri)?;
            let name = name.or_else(|| record.account.clone()).ok_or_else(|| {
                Error::InvalidArguments(
                    "import requires --name when the URI has no account label".into(),
                )
            })?;
            credentials::validate_identifier(&name).map_err(|_| {
                Error::InvalidArguments(
                    "import requires --name with a valid portable identifier".into(),
                )
            })?;
            Ok(Prepared::Store {
                name,
                record,
                replace,
            })
        }
        Command::Get { name } => {
            credentials::validate_identifier(&name)?;
            Ok(Prepared::Get(name))
        }
        Command::Remove { name, force } => {
            credentials::validate_identifier(&name)?;
            if !force && !input.confirm()? {
                return Err(Error::InteractionRequired(
                    "deletion was not confirmed".into(),
                ));
            }
            Ok(Prepared::Remove(name))
        }
        Command::List => Ok(Prepared::List),
        Command::Doctor => Ok(Prepared::Doctor),
        Command::Version => Ok(Prepared::Version),
    }
}

pub fn execute(command: Prepared, store: &dyn SecretStore, output: &mut dyn Write) -> Result<()> {
    match command {
        Prepared::Store {
            name,
            record,
            replace,
        } => store.store(&name, &record.to_bytes()?, replace),
        Prepared::Get(name) => {
            let bytes = store.retrieve(&name)?;
            let record = CredentialRecord::from_bytes(&bytes)?;
            let code = crate::totp::generate_current(&record)?;
            writeln!(output, "{}", code.as_str()).map_err(io_error)
        }
        Prepared::List => {
            let mut names = store.list()?;
            names.sort();
            names.dedup();
            for name in &names {
                credentials::validate_identifier(name)?;
            }
            for name in names {
                writeln!(output, "{name}").map_err(io_error)?;
            }
            Ok(())
        }
        Prepared::Remove(name) => store.delete(&name),
        Prepared::Version => {
            writeln!(output, "totp {}", env!("CARGO_PKG_VERSION")).map_err(io_error)
        }
        Prepared::Doctor => crate::diagnostics::report(store, output),
    }
}
