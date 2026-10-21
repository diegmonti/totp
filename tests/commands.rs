use clap::Parser;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
};
use totp::{
    cli::{
        commands::{self, Input, Prepared},
        Cli,
    },
    credentials::{Algorithm, CredentialRecord},
    error::{Error, Result},
    storage::SecretStore,
};
use zeroize::Zeroizing;

#[derive(Default)]
struct MockStore {
    records: RefCell<BTreeMap<String, Vec<u8>>>,
    reads: Cell<usize>,
    fail: Cell<bool>,
}
impl SecretStore for MockStore {
    fn store(&self, name: &str, record: &[u8], replace: bool) -> Result<()> {
        if self.fail.get() {
            return Err(Error::PermissionDenied("test rejection".into()));
        }
        let mut records = self.records.borrow_mut();
        if records.contains_key(name) && !replace {
            return Err(Error::AlreadyExists(name.into()));
        }
        records.insert(name.into(), record.into());
        Ok(())
    }
    fn retrieve(&self, name: &str) -> Result<Zeroizing<Vec<u8>>> {
        self.reads.set(self.reads.get() + 1);
        self.records
            .borrow()
            .get(name)
            .cloned()
            .map(Zeroizing::new)
            .ok_or_else(|| Error::NotFound(name.into()))
    }
    fn delete(&self, name: &str) -> Result<()> {
        self.records
            .borrow_mut()
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| Error::NotFound(name.into()))
    }
    fn list(&self) -> Result<Vec<String>> {
        Ok(self.records.borrow().keys().rev().cloned().collect())
    }
}
struct TestInput {
    value: &'static str,
    confirmed: bool,
    calls: usize,
    explicit: bool,
}
impl TestInput {
    fn new(value: &'static str) -> Self {
        Self {
            value,
            confirmed: false,
            calls: 0,
            explicit: false,
        }
    }
}
impl Input for TestInput {
    fn secret(&mut self, explicit: bool, _: &str) -> Result<Zeroizing<String>> {
        self.calls += 1;
        self.explicit = explicit;
        Ok(Zeroizing::new(self.value.into()))
    }
    fn confirm(&mut self) -> Result<bool> {
        self.calls += 1;
        Ok(self.confirmed)
    }
}
fn prepared(args: &[&str], input: &mut TestInput) -> Result<Prepared> {
    commands::prepare(Cli::try_parse_from(args).unwrap().command, input)
}
fn run(args: &[&str], input: &mut TestInput, store: &MockStore) -> Result<Vec<u8>> {
    let command = prepared(args, input)?;
    let mut out = Vec::new();
    commands::execute(command, store, &mut out)?;
    Ok(out)
}
#[test]
fn registration_replacement_generation_and_deletion() {
    let store = MockStore::default();
    let mut input = TestInput::new("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    assert!(run(
        &["totp", "add", "github", "--secret-stdin"],
        &mut input,
        &store
    )
    .unwrap()
    .is_empty());
    assert!(input.explicit);
    assert_eq!(
        run(
            &["totp", "add", "github", "--secret-stdin"],
            &mut input,
            &store
        )
        .unwrap_err()
        .exit_code(),
        7
    );
    let old = store.records.borrow()["github"].clone();
    input.value = "INVALID!";
    assert_eq!(
        run(
            &["totp", "add", "github", "--replace", "--secret-stdin"],
            &mut input,
            &store
        )
        .unwrap_err()
        .exit_code(),
        6
    );
    assert_eq!(store.records.borrow()["github"], old);
    input.value = "JBSWY3DPEHPK3PXP";
    assert!(run(
        &[
            "totp",
            "add",
            "github",
            "--replace",
            "--secret-stdin",
            "--digits",
            "8"
        ],
        &mut input,
        &store
    )
    .is_ok());
    let calls = input.calls;
    let code = run(&["totp", "get", "github"], &mut input, &store).unwrap();
    assert_eq!(code.len(), 9);
    assert!(code[..8].iter().all(u8::is_ascii_digit));
    assert_eq!(code[8], b'\n');
    assert_eq!(input.calls, calls);
    assert_eq!(
        run(&["totp", "remove", "github"], &mut input, &store)
            .unwrap_err()
            .exit_code(),
        5
    );
    assert!(store.records.borrow().contains_key("github"));
    run(&["totp", "remove", "github", "--force"], &mut input, &store).unwrap();
    assert!(store.records.borrow().is_empty());
}
#[test]
fn list_is_sorted_and_never_reads_payloads() {
    let store = MockStore::default();
    store.records.borrow_mut().insert("z".into(), vec![]);
    store.records.borrow_mut().insert("a".into(), vec![]);
    assert_eq!(
        run(&["totp", "list"], &mut TestInput::new(""), &store).unwrap(),
        b"a\nz\n"
    );
    assert_eq!(store.reads.get(), 0);
    store.records.borrow_mut().clear();
    assert!(run(&["totp", "list"], &mut TestInput::new(""), &store)
        .unwrap()
        .is_empty());
}
#[test]
fn import_preserves_configuration_and_requires_safe_name() {
    let store = MockStore::default();
    let mut input=TestInput::new("otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=45");
    run(&["totp", "import", "--stdin"], &mut input, &store).unwrap();
    assert!(input.explicit);
    let r = CredentialRecord::from_bytes(&store.records.borrow()["alice"]).unwrap();
    assert_eq!(r.algorithm, Algorithm::SHA256);
    assert_eq!(r.digits, 8);
    assert_eq!(r.period, 45);
    assert_eq!(r.issuer.as_deref(), Some("Example"));
    input.value = "otpauth://totp/alice%40example.com?secret=JBSWY3DPEHPK3PXP";
    // Explicit naming works for account labels outside the portable identifier policy.
    run(
        &["totp", "import", "--stdin", "--name", "mail"],
        &mut input,
        &store,
    )
    .unwrap();
}
#[test]
fn bounded_input_and_failed_store() {
    assert!(commands::read_bounded(&mut &b"\n"[..]).is_err());
    assert!(
        commands::read_bounded(&mut vec![b'x'; commands::MAX_INPUT_BYTES + 1].as_slice()).is_err()
    );
    assert!(commands::read_bounded(&mut &b"\xff"[..]).is_err());
    assert_eq!(
        commands::read_bounded(&mut &b" abc\r\n"[..])
            .unwrap()
            .as_str(),
        "abc"
    );
    let store = MockStore::default();
    store.fail.set(true);
    assert_eq!(
        run(
            &["totp", "add", "x", "--secret-stdin"],
            &mut TestInput::new("JBSWY3DPEHPK3PXP"),
            &store
        )
        .unwrap_err()
        .exit_code(),
        8
    );
    assert!(store.records.borrow().is_empty());
}
#[test]
fn diagnostic_output_never_reads_or_displays_record() {
    let store = MockStore::default();
    store
        .records
        .borrow_mut()
        .insert("private-name".into(), b"secret-seed".to_vec());
    let out = String::from_utf8(run(&["totp", "doctor"], &mut TestInput::new(""), &store).unwrap())
        .unwrap();
    assert!(out.contains("backend"));
    assert!(!out.contains("private-name"));
    assert!(!out.contains("secret-seed"));
    assert_eq!(store.reads.get(), 0);
}
#[test]
fn corrupt_and_future_records_produce_no_output() {
    let store = MockStore::default();
    for (payload, expected) in [
        (b"not-json".as_slice(), 6),
        (br#"{"schemaVersion":2}"#.as_slice(), 10),
    ] {
        store
            .records
            .borrow_mut()
            .insert("broken".into(), payload.to_vec());
        let mut output = Vec::new();
        let error =
            commands::execute(Prepared::Get("broken".into()), &store, &mut output).unwrap_err();
        assert_eq!(error.exit_code(), expected);
        assert!(output.is_empty());
        assert_eq!(store.records.borrow()["broken"], payload);
    }
}
