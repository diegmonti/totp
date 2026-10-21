use clap::{error::ErrorKind, Parser};
use totp::{
    cli::{
        commands::{self, Prepared, TerminalInput},
        Cli,
    },
    error::{Error, Result},
};

fn run() -> Result<()> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            error
                .print()
                .map_err(|_| Error::General("could not write help".into()))?;
            return Ok(());
        }
        // clap normally echoes unexpected arguments, which may contain a seed or URI.
        Err(_) => {
            return Err(Error::InvalidArguments(
                "invalid command or arguments; use totp help".into(),
            ))
        }
    };
    let command = commands::prepare(cli.command, &mut TerminalInput)?;
    if matches!(command, Prepared::Version) {
        println!("totp {}", env!("CARGO_PKG_VERSION"));
        return Ok(());
    }
    let store = match totp::storage::native_store() {
        Ok(store) => store,
        Err(error) => {
            if matches!(command, Prepared::Doctor) {
                totp::diagnostics::unavailable(&mut std::io::stdout().lock())?;
            }
            return Err(error);
        }
    };
    commands::execute(command, store.as_ref(), &mut std::io::stdout().lock())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("Error: {error}");
        std::process::exit(error.exit_code());
    }
}
