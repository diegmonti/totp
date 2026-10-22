//! Native stores are the sole inventory; identifiers are public native metadata.
use crate::error::{Error, Result};
use zeroize::Zeroizing;
pub mod platform;
pub const NAMESPACE: &str = "org.frugo.totp";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    Supported,
    Unsupported,
    Unknown,
}
impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Supported => "supported",
            Self::Unsupported => "unsupported",
            Self::Unknown => "unknown",
        })
    }
}
#[derive(Clone, Copy, Debug)]
pub struct Capabilities {
    pub backend: &'static str,
    pub read: Capability,
    pub write: Capability,
    pub enumeration: Capability,
    pub accessibility: Capability,
    pub non_interactive: Capability,
}
pub trait SecretStore {
    fn store(&self, name: &str, record: &[u8], replace: bool) -> Result<()>;
    fn retrieve(&self, name: &str) -> Result<Zeroizing<Vec<u8>>>;
    fn delete(&self, name: &str) -> Result<()>;
    fn list(&self) -> Result<Vec<String>>;
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            backend: backend_name(),
            read: Capability::Supported,
            write: Capability::Supported,
            enumeration: Capability::Supported,
            accessibility: Capability::Unknown,
            non_interactive: Capability::Unknown,
        }
    }
}
pub fn backend_name() -> &'static str {
    if cfg!(target_os = "linux") {
        "Secret Service"
    } else if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "unsupported"
    }
}
pub fn native_store() -> Result<Box<dyn SecretStore>> {
    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(platform::linux::LinuxStore::new()?));
    }
    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(platform::windows::WindowsStore::new()?));
    }
    #[cfg(target_os = "macos")]
    {
        return Ok(Box::new(platform::macos::MacosStore::new()?));
    }
    #[allow(unreachable_code)]
    Err(Error::BackendUnavailable(
        "unsupported operating system".into(),
    ))
}
