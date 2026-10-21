//! Explicitly opt-in: writes temporary entries into the real user's keyring.
use totp::storage::native_store;

#[test]
#[ignore = "requires an authorized native credential store and TOTP_NATIVE_TESTS=1"]
fn native_storage_lifecycle_and_enumeration() {
    assert_eq!(
        std::env::var("TOTP_NATIVE_TESTS").as_deref(),
        Ok("1"),
        "set TOTP_NATIVE_TESTS=1 to authorize real native storage writes"
    );
    let store = native_store().unwrap();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let names: Vec<_> = (0..3)
        .map(|i| format!("integration-{}-{nonce}-{i}", std::process::id()))
        .collect();
    struct Cleanup<'a> {
        store: &'a dyn totp::storage::SecretStore,
        names: &'a [String],
    }
    impl Drop for Cleanup<'_> {
        fn drop(&mut self) {
            for name in self.names {
                let _ = self.store.delete(name);
            }
        }
    }
    let _cleanup = Cleanup {
        store: store.as_ref(),
        names: &names,
    };
    for name in &names {
        store.store(name, b"test-protected-payload", false).unwrap();
    }
    assert!(store.store(&names[0], b"other", false).is_err());
    assert_eq!(
        &**store.retrieve(&names[0]).unwrap(),
        b"test-protected-payload"
    );
    let inventory = store.list().unwrap();
    assert!(inventory.windows(2).all(|pair| pair[0] < pair[1]));
    for name in &names {
        assert!(inventory.contains(name));
    }
    store.store(&names[0], b"replacement", true).unwrap();
    assert_eq!(&**store.retrieve(&names[0]).unwrap(), b"replacement");
    store.delete(&names[1]).unwrap();
    assert!(!store.list().unwrap().contains(&names[1]));
    assert!(store.retrieve(&names[1]).is_err());
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an authorized native credential store and TOTP_NATIVE_TESTS=1"]
fn concurrent_registration_has_one_winner() {
    assert_eq!(std::env::var("TOTP_NATIVE_TESTS").as_deref(), Ok("1"));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("race-{}-{nonce}", std::process::id());
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let name = name.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = native_store().unwrap();
                barrier.wait();
                store.store(&name, b"concurrent-test", false)
            })
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|handle| handle.join().unwrap())
        .collect();
    native_store().unwrap().delete(&name).unwrap();
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(totp::Error::AlreadyExists(_))))
            .count(),
        1
    );
}

#[test]
#[ignore = "requires an authorized native credential store and TOTP_NATIVE_TESTS=1"]
fn native_cli_registration_generation_import_and_removal() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    assert_eq!(std::env::var("TOTP_NATIVE_TESTS").as_deref(), Ok("1"));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let first = format!("cli-{}-{nonce}", std::process::id());
    let second = format!("uri-{}-{nonce}", std::process::id());
    let run = |args: &[&str], input: Option<&[u8]>| {
        let mut child = Command::new(env!("CARGO_BIN_EXE_totp"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child.stdin.take().unwrap().write_all(input).unwrap();
        } else {
            drop(child.stdin.take());
        }
        let output = child.wait_with_output().unwrap();
        for buffer in [&output.stdout, &output.stderr] {
            assert!(
                !buffer.windows(16).any(|part| part == b"JBSWY3DPEHPK3PXP"),
                "secret echoed"
            );
            assert!(
                !buffer.windows(10).any(|part| part == b"otpauth://"),
                "URI echoed"
            );
        }
        output
    };
    struct Cleanup(Vec<String>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for name in &self.0 {
                let _ = Command::new(env!("CARGO_BIN_EXE_totp"))
                    .args(["remove", name, "--force"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
        }
    }
    let _cleanup = Cleanup(vec![first.clone(), second.clone()]);
    let added = run(
        &["add", &first, "--secret-stdin", "--period", "4294967295"],
        Some(b"JBSWY3DPEHPK3PXP\n"),
    );
    assert!(added.status.success());
    assert!(added.stdout.is_empty());
    // A period longer than the current Unix epoch keeps the time counter at
    // zero, so comparing CLI codes cannot race across a normal TOTP boundary.
    let before = run(&["get", &first], None);
    assert!(before.status.success());
    let invalid = run(
        &["add", &first, "--secret-stdin", "--replace"],
        Some(b"INVALID!\n"),
    );
    assert_eq!(invalid.status.code(), Some(6));
    let after = run(&["get", &first], None);
    assert!(after.status.success());
    assert_eq!(before.stdout, after.stdout);
    let duplicate = run(
        &["add", &first, "--secret-stdin"],
        Some(b"JBSWY3DPEHPK3PXP\n"),
    );
    assert_eq!(duplicate.status.code(), Some(7));
    let code = run(&["get", &first], None);
    assert!(code.status.success());
    assert!(code.stderr.is_empty());
    assert_eq!(code.stdout.len(), 7);
    assert_eq!(code.stdout[6], b'\n');
    assert!(code.stdout[..6].iter().all(u8::is_ascii_digit));
    let imported = run(
        &["import", "--stdin", "--name", &second],
        Some(b"otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&algorithm=SHA256&digits=8&period=60\n"),
    );
    assert!(imported.status.success());
    assert!(imported.stdout.is_empty());
    let code = run(&["get", &second], None);
    assert!(code.status.success());
    assert_eq!(code.stdout.len(), 9);
    assert!(code.stdout[..8].iter().all(u8::is_ascii_digit));
    assert_eq!(code.stdout[8], b'\n');
    let listing = run(&["list"], None);
    assert!(listing.status.success());
    let listing = String::from_utf8(listing.stdout).unwrap();
    assert!(listing.lines().any(|name| name == first));
    assert!(listing.lines().any(|name| name == second));
    assert!(run(&["remove", &first, "--force"], None).status.success());
    assert_eq!(run(&["get", &first], None).status.code(), Some(3));
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires an authorized native credential store and TOTP_NATIVE_TESTS=1"]
fn native_enumeration_excludes_other_namespaces() {
    use secret_service::{EncryptionType, SecretService};
    use std::collections::HashMap;
    assert_eq!(std::env::var("TOTP_NATIVE_TESTS").as_deref(), Ok("1"));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("foreign-{}-{nonce}", std::process::id());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let change_foreign = |create: bool| {
        runtime.block_on(async {
            let service = SecretService::connect(EncryptionType::Dh).await.unwrap();
            let attributes = HashMap::from([
                ("application", "com.diegmonti.totp.integration-unrelated"),
                ("credential", name.as_str()),
            ]);
            if create {
                service
                    .get_default_collection()
                    .await
                    .unwrap()
                    .create_item(
                        "unrelated test entry",
                        attributes,
                        b"unrelated-test",
                        false,
                        "application/octet-stream",
                    )
                    .await
                    .unwrap();
            } else {
                for item in service.search_items(attributes).await.unwrap().unlocked {
                    item.delete().await.unwrap();
                }
            }
        })
    };
    change_foreign(true);
    let inventory = native_store().unwrap().list();
    change_foreign(false);
    assert!(!inventory.unwrap().contains(&name));
}

/// Run only in a disposable D-Bus session with a disposable keyring directory.
/// This deliberately leaves that keyring locked and its temporary fixture intact:
/// cleanup must destroy the isolated session/keyring, never prompt to unlock it.
#[cfg(target_os = "linux")]
#[test]
#[ignore = "locks the default keyring; requires isolated TOTP_LOCKED_TESTS=1 session"]
fn locked_native_backend_fails_without_interaction() {
    use secret_service::{EncryptionType, SecretService};
    use std::{
        io::Write,
        process::{Command, Stdio},
        time::{Duration, Instant},
    };
    if std::env::var("TOTP_LOCKED_TESTS").as_deref() != Ok("1") {
        eprintln!("skipped: TOTP_LOCKED_TESTS=1 is required in a disposable keyring session");
        return;
    }
    assert_eq!(std::env::var("TOTP_NATIVE_TESTS").as_deref(), Ok("1"));
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("locked-{}-{nonce}", std::process::id());
    native_store()
        .unwrap()
        .store(&name, b"locked-test-payload", false)
        .unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(10), async {
            let service = SecretService::connect(EncryptionType::Dh).await.unwrap();
            let collection = service.get_default_collection().await.unwrap();
            collection.lock().await.unwrap();
            assert!(collection.is_locked().await.unwrap());
        })
        .await
        .expect("locking the isolated collection timed out");
    });
    for args in [
        vec!["get", name.as_str()],
        vec!["add", "locked-new-fixture", "--secret-stdin"],
    ] {
        let needs_input = args[0] == "add";
        let started = Instant::now();
        let mut child = Command::new(env!("CARGO_BIN_EXE_totp"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if needs_input {
            stdin.write_all(b"JBSWY3DPEHPK3PXP\n").unwrap();
        }
        drop(stdin);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if started.elapsed() > Duration::from_secs(12) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("locked-store command did not finish without interaction");
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(5));
        assert!(output.stdout.is_empty());
        assert!(!output
            .stderr
            .windows(16)
            .any(|part| part == b"JBSWY3DPEHPK3PXP"));
    }
}
