use crate::{
    error::{Error, Result},
    storage::SecretStore,
};
use std::io::Write;

pub fn report(store: &dyn SecretStore, output: &mut dyn Write) -> Result<()> {
    let caps = store.capabilities();
    let write_error = |_| Error::General("could not write diagnostics".into());
    writeln!(output, "totp {}", env!("CARGO_PKG_VERSION")).map_err(write_error)?;
    writeln!(
        output,
        "platform: {} {}",
        std::env::consts::OS,
        std::env::consts::ARCH
    )
    .map_err(write_error)?;
    writeln!(output, "backend: {}", caps.backend).map_err(write_error)?;
    writeln!(output, "read: {}", caps.read).map_err(write_error)?;
    writeln!(output, "write: {}", caps.write).map_err(write_error)?;
    writeln!(output, "native enumeration: {}", caps.enumeration).map_err(write_error)?;
    writeln!(output, "accessibility: {}", caps.accessibility).map_err(write_error)?;
    writeln!(
        output,
        "non-interactive authorization: {}",
        caps.non_interactive
    )
    .map_err(write_error)?;
    // Native metadata enumeration checks availability without fetching protected payloads.
    if let Err(error) = store.list() {
        writeln!(output, "backend availability: unavailable or inaccessible")
            .map_err(write_error)?;
        return Err(error);
    }
    writeln!(output, "backend availability: available").map_err(write_error)
}

pub fn unavailable(output: &mut dyn Write) -> Result<()> {
    writeln!(
        output,
        "totp {}\nplatform: {} {}\nbackend: {}\nbackend availability: unavailable",
        env!("CARGO_PKG_VERSION"),
        std::env::consts::OS,
        std::env::consts::ARCH,
        crate::storage::backend_name()
    )
    .map_err(|_| Error::General("could not write diagnostics".into()))
}
