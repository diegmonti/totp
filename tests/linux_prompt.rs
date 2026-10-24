//! Authorization dialogs for mutations; locked retrieval must never prompt.
#![cfg(target_os = "linux")]

use std::{
    collections::HashMap,
    io::{BufRead, BufReader, Write},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use zbus::{
    interface,
    object_server::SignalEmitter,
    zvariant::{OwnedObjectPath, OwnedValue, Value},
};

const COLLECTION: &str = "/org/freedesktop/secrets/collection/test";
const ITEM: &str = "/org/freedesktop/secrets/collection/test/item";
const PROMPT: &str = "/org/freedesktop/secrets/prompt/test";
const PAYLOAD: &str = "server-controlled-payload IsLocked AccessDenied";

type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);
type Shared = Arc<Mutex<State>>;
#[derive(Default)]
struct State {
    mode: String,
    unlocked: bool,
    pending: String,
    calls: Vec<String>,
}
fn path(value: &str) -> OwnedObjectPath {
    value.try_into().unwrap()
}

struct Service(Shared);
#[interface(name = "org.freedesktop.Secret.Service")]
impl Service {
    fn open_session(&self, algorithm: &str, _input: Value<'_>) -> (OwnedValue, OwnedObjectPath) {
        assert_eq!(algorithm, "dh-ietf1024-sha256-aes128-cbc-pkcs7");
        (
            Value::from(vec![2u8]).try_into().unwrap(),
            path("/org/freedesktop/secrets/session/test"),
        )
    }
    fn search_items(
        &self,
        attributes: HashMap<String, String>,
    ) -> (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) {
        let mut state = self.0.lock().unwrap();
        state.mode = attributes["credential"].clone();
        state.unlocked = !state.mode.starts_with("locked-");
        let exists = state.mode.contains("delete")
            || state.mode.contains("get")
            || state.mode.contains("replace");
        if exists {
            if state.unlocked {
                (vec![path(ITEM)], vec![])
            } else {
                (vec![], vec![path(ITEM)])
            }
        } else {
            (vec![], vec![])
        }
    }
    fn read_alias(&self, _name: &str) -> OwnedObjectPath {
        path(COLLECTION)
    }
    fn unlock(&self, _objects: Vec<OwnedObjectPath>) -> (Vec<OwnedObjectPath>, OwnedObjectPath) {
        let mut state = self.0.lock().unwrap();
        state.calls.push("Unlock".into());
        state.pending = "unlock".into();
        (vec![], path(PROMPT))
    }
}

struct Collection(Shared);
#[interface(name = "org.freedesktop.Secret.Collection")]
impl Collection {
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.0.lock().unwrap().unlocked
    }
    fn create_item(
        &self,
        _properties: HashMap<String, OwnedValue>,
        _secret: Secret,
        _replace: bool,
    ) -> zbus::fdo::Result<(OwnedObjectPath, OwnedObjectPath)> {
        let mut state = self.0.lock().unwrap();
        state.calls.push("CreateItem".into());
        match state.mode.as_str() {
            "denied" => Err(zbus::fdo::Error::AccessDenied(PAYLOAD.into())),
            "failed" => Err(zbus::fdo::Error::Failed(PAYLOAD.into())),
            _ => {
                state.pending = "create".into();
                Ok((path("/"), path(PROMPT)))
            }
        }
    }
}

struct Item(Shared);
#[interface(name = "org.freedesktop.Secret.Item")]
impl Item {
    #[zbus(property)]
    fn locked(&self) -> bool {
        !self.0.lock().unwrap().unlocked
    }
    fn delete(&self) -> OwnedObjectPath {
        let mut state = self.0.lock().unwrap();
        state.calls.push("Delete".into());
        state.pending = "delete".into();
        path(PROMPT)
    }
    fn set_secret(&self, _secret: Secret) {
        let mut state = self.0.lock().unwrap();
        assert!(state.unlocked);
        state.calls.push("SetSecret".into());
    }
    fn get_secret(&self, _session: OwnedObjectPath) -> zbus::fdo::Result<Secret> {
        self.0.lock().unwrap().calls.push("GetSecret".into());
        Err(zbus::fdo::Error::Failed(PAYLOAD.into()))
    }
}

struct Prompt(Shared);
#[interface(name = "org.freedesktop.Secret.Prompt")]
impl Prompt {
    async fn prompt(
        &self,
        _window_id: &str,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
    ) -> zbus::fdo::Result<()> {
        let (dismissed, pending) = {
            let mut state = self.0.lock().unwrap();
            state.calls.push("Prompt".into());
            let dismissed = state.mode.contains("cancel");
            if state.pending == "unlock" && !dismissed {
                state.unlocked = true;
            }
            (dismissed, state.pending.clone())
        };
        let result = match pending.as_str() {
            "create" => Value::from(path(ITEM)),
            "unlock" => Value::from(vec![path(ITEM)]),
            _ => Value::from(String::new()),
        };
        Self::completed(&emitter, dismissed, result)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))
    }
    #[zbus(signal)]
    async fn completed(
        emitter: &SignalEmitter<'_>,
        dismissed: bool,
        result: Value<'_>,
    ) -> zbus::Result<()>;
}

struct TestService {
    bus: Child,
    address: String,
    stop: Arc<AtomicBool>,
    state: Shared,
    worker: Option<JoinHandle<()>>,
}
impl TestService {
    fn start() -> Self {
        let mut bus = Command::new("dbus-daemon")
            .args(["--session", "--nofork", "--print-address=1"])
            .stdout(Stdio::piped())
            .spawn()
            .expect("install dbus-daemon to run Linux authorization regression tests");
        let mut address = String::new();
        BufReader::new(bus.stdout.take().unwrap())
            .read_line(&mut address)
            .unwrap();
        let mut service = Self {
            bus,
            address: address.trim().into(),
            stop: Arc::new(AtomicBool::new(false)),
            state: Arc::default(),
            worker: None,
        };
        let address = service.address.clone();
        let state = service.state.clone();
        let stop = service.stop.clone();
        let (ready, receiver) = mpsc::channel();
        service.worker = Some(thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let _connection = zbus::connection::Builder::address(address.as_str())
                        .unwrap()
                        .name("org.freedesktop.secrets")
                        .unwrap()
                        .serve_at("/org/freedesktop/secrets", Service(state.clone()))
                        .unwrap()
                        .serve_at(COLLECTION, Collection(state.clone()))
                        .unwrap()
                        .serve_at(ITEM, Item(state.clone()))
                        .unwrap()
                        .serve_at(PROMPT, Prompt(state))
                        .unwrap()
                        .build()
                        .await
                        .unwrap();
                    ready.send(()).unwrap();
                    while !stop.load(Ordering::Relaxed) {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                });
        }));
        receiver
            .recv_timeout(Duration::from_secs(10))
            .expect("test service did not start");
        service
    }
    fn run(&self, command: &str, name: &str, expected_exit: i32) -> Vec<String> {
        self.state.lock().unwrap().calls.clear();
        let mut args = vec![command, name];
        match command {
            "remove" => args.push("--force"),
            "add" => {
                args.push("--secret-stdin");
                if name.contains("replace") {
                    args.push("--replace");
                }
            }
            _ => {}
        }
        let mut child = Command::new(env!("CARGO_BIN_EXE_totp"))
            .args(args)
            .env("DBUS_SESSION_BUS_ADDRESS", &self.address)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if command == "add" {
            stdin.write_all(b"JBSWY3DPEHPK3PXP\n").unwrap();
        }
        drop(stdin);
        let started = Instant::now();
        while child.try_wait().unwrap().is_none() {
            if started.elapsed() > Duration::from_secs(12) {
                child.kill().unwrap();
                child.wait().unwrap();
                panic!("{name} did not finish");
            }
            thread::sleep(Duration::from_millis(20));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(
            output.status.code(),
            Some(expected_exit),
            "{name}: {output:?}"
        );
        assert!(output.stdout.is_empty());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(!stderr.contains("JBSWY3DPEHPK3PXP"));
        assert!(!stderr.contains("server-controlled-payload"));
        self.state.lock().unwrap().calls.clone()
    }
}
impl Drop for TestService {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = self.bus.kill();
        let _ = self.bus.wait();
    }
}

#[test]
fn mutation_dialogs_complete_or_cancel_and_locked_get_never_prompts() {
    let service = TestService::start();
    for (command, name, exit) in [
        ("add", "prompt-create", 0),
        ("add", "cancel-create", 5),
        ("remove", "prompt-delete", 0),
        ("remove", "cancel-delete", 5),
        ("add", "locked-create", 0),
        ("add", "locked-replace", 0),
        ("remove", "locked-delete", 0),
        ("add", "locked-cancel-create", 5),
        ("add", "locked-cancel-replace", 5),
        ("remove", "locked-cancel-delete", 5),
    ] {
        let calls = service.run(command, name, exit);
        assert!(calls.iter().any(|s| s == "Prompt"), "{name}: {calls:?}");
        assert_eq!(
            calls.iter().any(|s| s == "Unlock"),
            name.starts_with("locked-")
        );
        if name.starts_with("locked-cancel-") {
            assert_eq!(calls, ["Unlock", "Prompt"]);
        }
    }
    assert!(service.run("get", "locked-get", 5).is_empty());
    assert_eq!(service.run("get", "failed-get", 4), ["GetSecret"]);
    service.run("add", "denied", 8);
    service.run("add", "failed", 4);
}
