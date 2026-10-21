//! Secret Service with DH encrypted transport and an overall operation deadline.
//! No unlock, collection creation, or Prompt request is ever made.
use crate::{
    error::{Error, Result},
    storage::{SecretStore, NAMESPACE},
};
use secret_service::{EncryptionType, SecretService};
use std::os::{
    linux::net::SocketAddrExt,
    unix::{
        fs::MetadataExt,
        net::{SocketAddr, UnixListener},
    },
};
use std::{
    collections::HashMap,
    future::Future,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub struct LinuxStore;
impl LinuxStore {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
    fn run<T>(&self, future: impl Future<Output = Result<T>>) -> Result<T> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| {
                Error::BackendUnavailable("cannot initialize Secret Service runtime".into())
            })?;
        runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(10), future)
                .await
                .map_err(|_| {
                    Error::BackendUnavailable(
                        "Secret Service operation timed out after 10 seconds".into(),
                    )
                })?
        })
    }
}
// Abstract sockets provide a per-user cross-process mutation lock without any
// persistent file, secret payload, or credential inventory. Keep the listener
// alive until mutation finishes; the kernel releases it on crash or process exit.
fn mutation_lock() -> Result<UnixListener> {
    let uid = std::fs::metadata("/proc/self")
        .map_err(|_| Error::BackendUnavailable("cannot identify current Linux user".into()))?
        .uid();
    let address = SocketAddr::from_abstract_name(format!("{NAMESPACE}.mutation.{uid}").as_bytes())
        .map_err(|_| Error::General("cannot construct native mutation lock".into()))?;
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match UnixListener::bind_addr(&address) {
            Ok(listener) => return Ok(listener),
            Err(error)
                if error.kind() == std::io::ErrorKind::AddrInUse && Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(Error::General(
                    "another credential mutation is busy; timed out after 10 seconds".into(),
                ))
            }
            Err(_) => {
                return Err(Error::BackendUnavailable(
                    "cannot acquire native credential mutation lock".into(),
                ))
            }
        }
    }
}
fn attrs(name: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", NAMESPACE), ("credential", name)])
}
fn locked() -> Error {
    Error::InteractionRequired(
        "credential store is locked or requires authorization; unlock it outside totp".into(),
    )
}
fn map_error(error: secret_service::Error) -> Error {
    use secret_service::Error as S;
    match error {
        S::Locked | S::Prompt => locked(),
        S::NoResult | S::Unavailable => Error::BackendUnavailable("no existing Secret Service default collection or session bus; configure an unlocked secure keyring".into()),
        S::Zbus(ref e) if e.to_string().contains("org.freedesktop.Secret.Error.IsLocked") => locked(),
        S::Zbus(ref e) if e.to_string().contains("AccessDenied") || e.to_string().contains("PermissionDenied") => Error::PermissionDenied("Secret Service denied access".into()),
        S::ZbusFdo(ref e) if e.to_string().contains("AccessDenied") => Error::PermissionDenied("Secret Service denied access".into()),
        // Never propagate server-controlled error text: it could contain payloads.
        _ => Error::BackendUnavailable("Secret Service request failed; check the session bus, keyring service and permissions".into()),
    }
}
impl SecretStore for LinuxStore {
    fn store(&self, name: &str, record: &[u8], replace: bool) -> Result<()> {
        let _lock = mutation_lock()?;
        self.run(async {
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(map_error)?;
            let found = service.search_items(attrs(name)).await.map_err(map_error)?;
            let count = found.unlocked.len() + found.locked.len();
            if count > 0 && !replace {
                return Err(Error::AlreadyExists(name.into()));
            }
            if !found.locked.is_empty() {
                return Err(locked());
            }
            if count > 1 {
                return Err(Error::General(
                    "ambiguous duplicate native credentials; repair keyring entries outside totp"
                        .into(),
                ));
            }
            if let Some(item) = found.unlocked.first() {
                // SetSecret updates the payload in place, preserving the existing item.
                return item
                    .set_secret(record, "application/json")
                    .await
                    .map_err(map_error);
            }
            let collection = service.get_default_collection().await.map_err(map_error)?;
            if collection.is_locked().await.map_err(map_error)? {
                return Err(locked());
            }
            collection
                .create_item(
                    &format!("{NAMESPACE}/{name}"),
                    attrs(name),
                    record,
                    false,
                    "application/json",
                )
                .await
                .map_err(map_error)?;
            Ok(())
        })
    }
    fn retrieve(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.run(async {
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(map_error)?;
            let found = service.search_items(attrs(name)).await.map_err(map_error)?;
            if !found.locked.is_empty() {
                return Err(locked());
            }
            if found.unlocked.len() > 1 {
                return Err(Error::General(
                    "ambiguous duplicate native credentials".into(),
                ));
            }
            let item = found
                .unlocked
                .first()
                .ok_or_else(|| Error::NotFound(name.into()))?;
            Ok(Zeroizing::new(item.get_secret().await.map_err(map_error)?))
        })
    }
    fn delete(&self, name: &str) -> Result<()> {
        let _lock = mutation_lock()?;
        self.run(async {
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(map_error)?;
            let found = service.search_items(attrs(name)).await.map_err(map_error)?;
            if !found.locked.is_empty() {
                return Err(locked());
            }
            if found.unlocked.len() > 1 {
                return Err(Error::General(
                    "ambiguous duplicate native credentials".into(),
                ));
            }
            found
                .unlocked
                .first()
                .ok_or_else(|| Error::NotFound(name.into()))?
                .delete()
                .await
                .map_err(map_error)
        })
    }
    fn list(&self) -> Result<Vec<String>> {
        self.run(async {
            let service = SecretService::connect(EncryptionType::Dh)
                .await
                .map_err(map_error)?;
            let found = service
                .search_items(HashMap::from([("application", NAMESPACE)]))
                .await
                .map_err(map_error)?;
            let mut names = Vec::new();
            // Search + GetAttributes only: locked-item metadata can be listed when
            // the service permits it, and no GetSecret request occurs here.
            for item in found.unlocked.iter().chain(found.locked.iter()) {
                let attributes = item.get_attributes().await.map_err(map_error)?;
                if attributes.get("application").map(String::as_str) == Some(NAMESPACE) {
                    if let Some(name) = attributes.get("credential") {
                        if crate::credentials::validate_identifier(name).is_err() {
                            return Err(Error::General(
                                "native credential has invalid identifier metadata".into(),
                            ));
                        }
                        names.push(name.clone());
                    }
                }
            }
            names.sort();
            names.dedup();
            Ok(names)
        })
    }
}
