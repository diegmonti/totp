//! Native Windows Credential Manager storage. Credential enumeration exposes blobs
//! in the OS allocation; they are never copied and are wiped before release.
use crate::error::{Error, Result};
use crate::storage::SecretStore;
use std::{ffi::c_void, ptr};
use zeroize::Zeroizing;
const PREFIX: &str = "org.frugo.totp/";
#[repr(C)]
struct Credential {
    flags: u32,
    kind: u32,
    target: *mut u16,
    comment: *mut u16,
    written: u64,
    size: u32,
    blob: *mut u8,
    persist: u32,
    attributes_count: u32,
    attributes: *mut c_void,
    alias: *mut u16,
    user: *mut u16,
}
#[link(name = "Advapi32")]
extern "system" {
    fn CredReadW(target: *const u16, kind: u32, flags: u32, out: *mut *mut Credential) -> i32;
    fn CredWriteW(credential: *const Credential, flags: u32) -> i32;
    fn CredDeleteW(target: *const u16, kind: u32, flags: u32) -> i32;
    fn CredEnumerateW(
        filter: *const u16,
        flags: u32,
        count: *mut u32,
        out: *mut *mut *mut Credential,
    ) -> i32;
    fn CredFree(buffer: *mut c_void);
    fn OpenProcessToken(process: *mut c_void, access: u32, token: *mut *mut c_void) -> i32;
    fn GetTokenInformation(
        token: *mut c_void,
        class: u32,
        buffer: *mut c_void,
        length: u32,
        required: *mut u32,
    ) -> i32;
    fn ConvertSidToStringSidW(sid: *const c_void, text: *mut *mut u16) -> i32;
}
#[link(name = "Kernel32")]
extern "system" {
    fn GetLastError() -> u32;
    fn GetCurrentProcess() -> *mut c_void;
    fn LocalFree(memory: *mut c_void) -> *mut c_void;
    fn CreateMutexW(attributes: *const c_void, owner: i32, name: *const u16) -> *mut c_void;
    fn WaitForSingleObject(handle: *mut c_void, millis: u32) -> u32;
    fn ReleaseMutex(handle: *mut c_void) -> i32;
    fn CloseHandle(handle: *mut c_void) -> i32;
}
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}
fn target(name: &str) -> Result<Vec<u16>> {
    if name.contains('\0') {
        return Err(Error::InvalidArguments(
            "credential name contains NUL".into(),
        ));
    }
    Ok(wide(&format!("{PREFIX}{name}")))
}
fn failure(code: u32) -> Error {
    match code {
        1168 => Error::NotFound("credential not found".into()),
        5 => Error::PermissionDenied("Windows Credential Manager denied access".into()),
        1312 => Error::BackendUnavailable("Windows logon session has no credential store".into()),
        _ => Error::BackendUnavailable(format!("Windows Credential Manager error {code}")),
    }
}
unsafe fn wipe(c: *mut Credential) {
    if !(*c).blob.is_null() {
        for i in 0..(*c).size as usize {
            ptr::write_volatile((*c).blob.add(i), 0);
        }
    }
}
struct Allocation(*mut Credential);
impl Drop for Allocation {
    fn drop(&mut self) {
        unsafe {
            wipe(self.0);
            CredFree(self.0.cast());
        }
    }
}
// Use the token SID rather than session-local identity: persisted credentials
// can be shared by multiple logon sessions of the same OS user.
fn mutation_lock_name() -> Result<Vec<u16>> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), 8, &mut token) } == 0 {
        return Err(failure(unsafe { GetLastError() }));
    }
    let mut needed = 0;
    let probe = unsafe { GetTokenInformation(token, 1, ptr::null_mut(), 0, &mut needed) };
    let probe_error = unsafe { GetLastError() };
    if probe != 0 || probe_error != 122 || (needed as usize) < 2 * std::mem::size_of::<usize>() {
        unsafe {
            CloseHandle(token);
        }
        return Err(Error::BackendUnavailable(
            "cannot determine Windows token identity".into(),
        ));
    }
    // Allocate pointer-aligned storage for TOKEN_USER and its embedded SID.
    let mut buffer = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
    let ok =
        unsafe { GetTokenInformation(token, 1, buffer.as_mut_ptr().cast(), needed, &mut needed) };
    let error = unsafe { GetLastError() };
    unsafe {
        CloseHandle(token);
    }
    if ok == 0 {
        return Err(failure(error));
    }
    let sid = unsafe { *(buffer.as_ptr() as *const *const c_void) };
    let mut text = ptr::null_mut();
    if unsafe { ConvertSidToStringSidW(sid, &mut text) } == 0 {
        return Err(failure(unsafe { GetLastError() }));
    }
    let mut len = 0;
    unsafe {
        while *text.add(len) != 0 {
            len += 1;
        }
    }
    let sid = unsafe { String::from_utf16_lossy(std::slice::from_raw_parts(text, len)) };
    unsafe {
        LocalFree(text.cast());
    }
    Ok(wide(&format!("Global\\org.frugo.totp.write.{sid}")))
}
// Serialize check/write between application processes. Credential Manager itself
// offers no create-if-absent primitive. The mutex has the user's default ACL.
struct WriteLock(*mut c_void);
impl WriteLock {
    fn acquire() -> Result<Self> {
        let name = mutation_lock_name()?;
        let h = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
        if h.is_null() {
            return Err(failure(unsafe { GetLastError() }));
        }
        match unsafe { WaitForSingleObject(h, 5000) } {
            0 | 0x80 => Ok(Self(h)),
            _ => {
                unsafe {
                    CloseHandle(h);
                }
                Err(Error::BackendUnavailable(
                    "credential write lock unavailable".into(),
                ))
            }
        }
    }
}
impl Drop for WriteLock {
    fn drop(&mut self) {
        unsafe {
            ReleaseMutex(self.0);
            CloseHandle(self.0);
        }
    }
}
pub struct WindowsStore;
impl WindowsStore {
    pub fn new() -> Result<Self> {
        Ok(Self)
    }
}
impl SecretStore for WindowsStore {
    fn store(&self, name: &str, record: &[u8], replace: bool) -> Result<()> {
        if record.len() > 2560 {
            return Err(Error::InvalidConfiguration(
                "record exceeds Windows credential blob limit".into(),
            ));
        }
        let mut name = target(name)?;
        let _lock = WriteLock::acquire()?;
        if !replace {
            let mut old = ptr::null_mut();
            if unsafe { CredReadW(name.as_ptr(), 1, 0, &mut old) } != 0 {
                let _old = Allocation(old);
                return Err(Error::AlreadyExists(
                    "credential already exists; use --replace".into(),
                ));
            }
            let code = unsafe { GetLastError() };
            if code != 1168 {
                return Err(failure(code));
            }
        }
        let c = Credential {
            flags: 0,
            kind: 1,
            target: name.as_mut_ptr(),
            comment: ptr::null_mut(),
            written: 0,
            size: record.len() as u32,
            blob: record.as_ptr() as *mut u8,
            persist: 2,
            attributes_count: 0,
            attributes: ptr::null_mut(),
            alias: ptr::null_mut(),
            user: ptr::null_mut(),
        };
        if unsafe { CredWriteW(&c, 0) } == 0 {
            return Err(failure(unsafe { GetLastError() }));
        }
        Ok(())
    }
    fn retrieve(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        let name = target(name)?;
        let mut raw = ptr::null_mut();
        if unsafe { CredReadW(name.as_ptr(), 1, 0, &mut raw) } == 0 {
            return Err(failure(unsafe { GetLastError() }));
        }
        let c = Allocation(raw);
        let bytes = unsafe {
            if (*c.0).size == 0 {
                Vec::new()
            } else {
                std::slice::from_raw_parts((*c.0).blob, (*c.0).size as usize).to_vec()
            }
        };
        Ok(Zeroizing::new(bytes))
    }
    fn delete(&self, name: &str) -> Result<()> {
        let name = target(name)?;
        let _lock = WriteLock::acquire()?;
        if unsafe { CredDeleteW(name.as_ptr(), 1, 0) } == 0 {
            return Err(failure(unsafe { GetLastError() }));
        }
        Ok(())
    }
    fn list(&self) -> Result<Vec<String>> {
        let filter = wide(&format!("{PREFIX}*"));
        let mut count = 0;
        let mut entries = ptr::null_mut();
        if unsafe { CredEnumerateW(filter.as_ptr(), 0, &mut count, &mut entries) } == 0 {
            let code = unsafe { GetLastError() };
            return if code == 1168 {
                Ok(vec![])
            } else {
                Err(failure(code))
            };
        }
        let mut names = Vec::new();
        unsafe {
            for &c in std::slice::from_raw_parts(entries, count as usize) {
                if (*c).kind == 1 && !(*c).target.is_null() {
                    let mut len = 0;
                    while *(*c).target.add(len) != 0 {
                        len += 1;
                    }
                    if let Ok(s) = String::from_utf16(std::slice::from_raw_parts((*c).target, len))
                    {
                        if let Some(n) = s.strip_prefix(PREFIX) {
                            names.push(n.to_string());
                        }
                    }
                }
                wipe(c);
            }
            CredFree(entries.cast());
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
    fn credential_layout_matches_windows_x64_abi() {
        assert_eq!(std::mem::size_of::<Credential>(), 80);
        assert_eq!(std::mem::offset_of!(Credential, written), 24);
        assert_eq!(std::mem::offset_of!(Credential, blob), 40);
        assert_eq!(std::mem::offset_of!(Credential, user), 72);
    }
    #[test]
    fn mapping_is_exact_and_nul_is_rejected() {
        assert_eq!(target("github").unwrap(), wide("org.frugo.totp/github"));
        assert!(target("a\0b").is_err());
    }
}

#[cfg(test)]
mod native_integration {
    use super::*;
    #[test]
    #[ignore = "requires an unlocked, authorized native credential store"]
    fn native_lifecycle_and_enumeration() {
        let store = WindowsStore::new().unwrap();
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
