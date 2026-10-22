//! Generic-password Keychain items scoped by service and account. Queries never
//! allow UI and enumeration requests attributes only, never protected data.
use crate::{
    error::{Error, Result},
    storage::SecretStore,
};
use std::{ffi::c_void, ptr};
use zeroize::Zeroizing;
type CF = *const c_void;
#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFBooleanTrue: CF;
    static kCFTypeDictionaryKeyCallBacks: u8;
    static kCFTypeDictionaryValueCallBacks: u8;
    fn CFRelease(value: CF);
    fn CFStringCreateWithBytes(
        allocator: CF,
        bytes: *const u8,
        len: isize,
        encoding: u32,
        external: u8,
    ) -> CF;
    fn CFStringGetLength(value: CF) -> isize;
    fn CFStringGetMaximumSizeForEncoding(len: isize, encoding: u32) -> isize;
    fn CFStringGetCString(value: CF, buffer: *mut i8, size: isize, encoding: u32) -> u8;
    fn CFDictionaryCreate(
        allocator: CF,
        keys: *const CF,
        values: *const CF,
        count: isize,
        key_callbacks: *const u8,
        value_callbacks: *const u8,
    ) -> CF;
    fn CFDictionaryGetValue(dictionary: CF, key: CF) -> CF;
    fn CFDataCreate(allocator: CF, bytes: *const u8, len: isize) -> CF;
    fn CFDataGetLength(data: CF) -> isize;
    fn CFDataGetBytePtr(data: CF) -> *const u8;
    fn CFArrayGetCount(array: CF) -> isize;
    fn CFArrayGetValueAtIndex(array: CF, index: isize) -> CF;
}
#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecClass: CF;
    static kSecClassGenericPassword: CF;
    static kSecAttrService: CF;
    static kSecAttrAccount: CF;
    static kSecValueData: CF;
    static kSecReturnData: CF;
    static kSecReturnAttributes: CF;
    static kSecMatchLimit: CF;
    static kSecMatchLimitAll: CF;
    static kSecUseAuthenticationUI: CF;
    static kSecUseAuthenticationUIFail: CF;
    fn SecKeychainSetUserInteractionAllowed(allowed: u8) -> i32;
    fn SecItemCopyMatching(query: CF, result: *mut CF) -> i32;
    fn SecItemAdd(attributes: CF, result: *mut CF) -> i32;
    fn SecItemUpdate(query: CF, attributes: CF) -> i32;
    fn SecItemDelete(query: CF) -> i32;
}
const UTF8: u32 = 0x08000100;
struct Owned(CF);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}
fn string(s: &str) -> Owned {
    Owned(unsafe { CFStringCreateWithBytes(ptr::null(), s.as_ptr(), s.len() as isize, UTF8, 0) })
}
fn dictionary(pairs: &[(CF, CF)]) -> Owned {
    let keys: Vec<_> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<_> = pairs.iter().map(|p| p.1).collect();
    Owned(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as isize,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
}
fn failure(status: i32) -> Error {
    match status {
        -25300 => Error::NotFound("credential not found".into()),
        -25299 => Error::AlreadyExists("credential already exists; use --replace".into()),
        -25308 | -25293 | -128 => Error::InteractionRequired("Keychain is locked or requires authorization; authorize this executable through Keychain Access".into()),
        -25291 => Error::BackendUnavailable("Keychain service unavailable".into()),
        -25243 | -34018 => Error::PermissionDenied("Keychain access denied".into()),
        _ => Error::BackendUnavailable(format!("Keychain operation failed with OSStatus {status}")),
    }
}
fn checked(status: i32) -> Result<()> {
    if status == 0 {
        Ok(())
    } else {
        Err(failure(status))
    }
}
pub struct MacosStore;
impl MacosStore {
    pub fn new() -> Result<Self> {
        // This executable is a CLI, and must never open authorization dialogs.
        checked(unsafe { SecKeychainSetUserInteractionAllowed(0) })?;
        Ok(Self)
    }
    fn query(&self, name: Option<&str>, extra: &[(CF, CF)]) -> Owned {
        let service = string("org.frugo.totp");
        let account = name.map(string);
        let mut pairs = unsafe {
            vec![
                (kSecClass, kSecClassGenericPassword),
                (kSecAttrService, service.0),
                (kSecUseAuthenticationUI, kSecUseAuthenticationUIFail),
            ]
        };
        if let Some(account) = &account {
            pairs.push(unsafe { (kSecAttrAccount, account.0) });
        }
        pairs.extend_from_slice(extra);
        dictionary(&pairs)
    }
}
impl SecretStore for MacosStore {
    fn store(&self, name: &str, record: &[u8], replace: bool) -> Result<()> {
        let data =
            Owned(unsafe { CFDataCreate(ptr::null(), record.as_ptr(), record.len() as isize) });
        let attributes = dictionary(&[unsafe { (kSecValueData, data.0) }]);
        let query = self.query(Some(name), &[]);
        if replace {
            let status = unsafe { SecItemUpdate(query.0, attributes.0) };
            if status != -25300 {
                return checked(status);
            }
        }
        let add = self.query(Some(name), &[unsafe { (kSecValueData, data.0) }]);
        // SecItemAdd rejects duplicates atomically; there is no check/write race.
        checked(unsafe { SecItemAdd(add.0, ptr::null_mut()) })
    }
    fn retrieve(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let query = self.query(Some(name), &[unsafe { (kSecReturnData, kCFBooleanTrue) }]);
        let mut result = ptr::null();
        checked(unsafe { SecItemCopyMatching(query.0, &mut result) })?;
        let result = Owned(result);
        let len = unsafe { CFDataGetLength(result.0) } as usize;
        let data = if len == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(CFDataGetBytePtr(result.0), len).to_vec() }
        };
        Ok(Zeroizing::new(data))
    }
    fn delete(&self, name: &str) -> Result<()> {
        let query = self.query(Some(name), &[]);
        checked(unsafe { SecItemDelete(query.0) })
    }
    fn list(&self) -> Result<Vec<String>> {
        let query = self.query(None, &unsafe {
            [
                (kSecReturnAttributes, kCFBooleanTrue),
                (kSecMatchLimit, kSecMatchLimitAll),
            ]
        });
        let mut result = ptr::null();
        let status = unsafe { SecItemCopyMatching(query.0, &mut result) };
        if status == -25300 {
            return Ok(vec![]);
        }
        checked(status)?;
        let result = Owned(result);
        let mut names = Vec::new();
        unsafe {
            for i in 0..CFArrayGetCount(result.0) {
                let attrs = CFArrayGetValueAtIndex(result.0, i);
                let account = CFDictionaryGetValue(attrs, kSecAttrAccount);
                if account.is_null() {
                    continue;
                }
                let capacity =
                    CFStringGetMaximumSizeForEncoding(CFStringGetLength(account), UTF8) + 1;
                let mut bytes = vec![0u8; capacity as usize];
                if CFStringGetCString(account, bytes.as_mut_ptr().cast(), capacity, UTF8) != 0 {
                    let len = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
                    if let Ok(name) = String::from_utf8(bytes[..len].to_vec()) {
                        names.push(name);
                    }
                }
            }
        }
        names.sort();
        names.dedup();
        Ok(names)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn maps_authorization_and_duplicate_errors() {
        assert!(matches!(failure(-25308), Error::InteractionRequired(_)));
        assert!(matches!(failure(-25299), Error::AlreadyExists(_)));
    }
}

#[cfg(test)]
mod native_integration {
    use super::*;
    #[test]
    #[ignore = "requires an unlocked, authorized native credential store"]
    fn native_lifecycle_and_enumeration() {
        let store = MacosStore::new().unwrap();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("integration-{}-{stamp}", std::process::id());
        store.store(&name, b"first", false).unwrap();
        assert!(matches!(
            store.store(&name, b"duplicate", false),
            Err(Error::AlreadyExists(_))
        ));
        assert_eq!(&**store.retrieve(&name).unwrap(), b"first");
        let names = store.list().unwrap();
        assert!(names.contains(&name));
        assert!(names.windows(2).all(|pair| pair[0] < pair[1]));
        store.store(&name, b"replacement", true).unwrap();
        assert_eq!(&**store.retrieve(&name).unwrap(), b"replacement");
        store.delete(&name).unwrap();
        assert!(matches!(store.retrieve(&name), Err(Error::NotFound(_))));
        assert!(!store.list().unwrap().contains(&name));
    }
}
