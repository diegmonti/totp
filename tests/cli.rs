use std::{
    io::Write,
    process::{Command, Stdio},
};
fn invoke(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_totp"))
        .args(args)
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            "unix:path=/nonexistent/totp-test-bus",
        )
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Some failing commands exit before the supplied input can be written.
    let _ = child.stdin.take().unwrap().write_all(input);
    child.wait_with_output().unwrap()
}
#[test]
fn help_and_version_do_not_require_secure_backend() {
    for args in [
        &["help"][..],
        &["--help"][..],
        &["version"][..],
        &["--version"][..],
    ] {
        let out = invoke(args, b"");
        assert!(out.status.success());
        assert!(out.stderr.is_empty());
        assert!(out.stdout.starts_with(b"totp") || out.stdout.starts_with(b"TOTP"));
    }
}
#[test]
fn rejected_arguments_never_echo_secret() {
    let seed = "SECRET_VALUE_MUST_NOT_APPEAR";
    for args in [
        vec!["add", "name", seed],
        vec!["import", seed],
        vec!["get", "name", seed],
        vec!["add", "name", "--digits", seed],
        vec![seed],
    ] {
        let out = invoke(&args, b"");
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains(seed));
    }
}
#[test]
fn stdin_is_explicit_and_validation_precedes_backend() {
    let seed = b"JBSWY3DPEHPK3PXP\n";
    for args in [
        &["add", "name"][..],
        &["import"][..],
        &["remove", "name"][..],
    ] {
        let out = invoke(args, seed);
        assert_eq!(out.status.code(), Some(5));
        assert!(out.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&out.stderr).contains("JBSWY"));
    }
    for input in [&b""[..], &b"invalid!"[..], &b"\xff"[..]] {
        let out = invoke(&["add", "name", "--secret-stdin"], input);
        assert_eq!(out.status.code(), Some(6));
        assert!(out.stdout.is_empty());
    }
    let out = invoke(&["add", "name", "--secret-stdin"], &vec![b'A'; 16385]);
    assert_eq!(out.status.code(), Some(6));
}
#[cfg(target_os = "linux")]
#[test]
fn missing_backend_fails_explicitly_without_stdout() {
    for args in [
        &["get", "name"][..],
        &["list"][..],
        &["remove", "name", "--force"][..],
    ] {
        let out = invoke(args, b"");
        assert_eq!(out.status.code(), Some(4));
        assert!(out.stdout.is_empty());
        assert!(!out.stderr.is_empty());
    }
    let out = invoke(&["doctor"], b"");
    assert_eq!(out.status.code(), Some(4));
    assert!(String::from_utf8_lossy(&out.stdout).contains("unavailable"));
}
