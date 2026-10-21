pub mod commands;

use clap::{Parser, Subcommand, ValueEnum};

#[derive(Parser)]
#[command(
    name = "totp",
    version,
    about = "TOTP credentials in native secure storage"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, ValueEnum)]
pub enum AlgorithmArg {
    Sha1,
    Sha256,
    Sha512,
}

#[derive(Subcommand)]
pub enum Command {
    /// Register a Base32 seed using concealed input by default.
    Add {
        /// Lowercase identifier: [a-z0-9][a-z0-9._-]{0,63}.
        name: String,
        #[arg(long)]
        secret_stdin: bool,
        #[arg(long)]
        replace: bool,
        #[arg(long, value_enum, default_value = "sha1")]
        algorithm: AlgorithmArg,
        #[arg(long, default_value_t = 6)]
        digits: u32,
        #[arg(long, default_value_t = 30)]
        period: u64,
        #[arg(long, default_value_t = 0)]
        t0: u64,
        #[arg(long)]
        issuer: Option<String>,
        #[arg(long)]
        account: Option<String>,
    },
    /// Print the current code followed by one newline.
    Get { name: String },
    /// List identifiers from native secure storage.
    List,
    /// Delete a credential (confirmation required unless --force).
    Remove {
        name: String,
        #[arg(long)]
        force: bool,
    },
    /// Register an OTPAuth URI using concealed input by default.
    Import {
        #[arg(long)]
        stdin: bool,
        /// Defaults to the URI account label when it is a valid identifier.
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        replace: bool,
    },
    /// Report platform and secure storage capabilities.
    Doctor,
    /// Print the application version.
    Version,
}
