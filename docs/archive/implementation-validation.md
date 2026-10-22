> Historical validation notes from the initial implementation, before publication. See the [v0.1.0 validation record](../validation.md) for subsequent CI and release results.

# Implementation validation

The implementation followed [the plan](implementation-plan.md) using five
Sol 6.1 implementation subagents and a separate Sol 6.1 reviewer.

## Local evidence

Validated on Linux x86-64 with stable Rust 1.99.1:

- `cargo fmt --all -- --check`.
- `cargo clippy --locked --all-targets -- -D warnings` (the vendored upstream
  library emits non-fatal lifetime-style warnings).
- `cargo test --locked`: six core tests and ten CLI/command tests pass. The core
  suite covers all 18 RFC 6238 vectors in both supported digit widths.
- Five opt-in native tests pass against an isolated D-Bus session and GNOME
  Keyring: lifecycle/enumeration, concurrent registration, complete CLI flow,
  unrelated namespace exclusion, and explicit locked-store failures. The last
  test runs separately with `TOTP_LOCKED_TESTS=1` on a disposable keyring.
- `cargo check --locked --offline --tests` passes for Windows x64 GNU and both
  macOS architectures. These compile checks do not execute native OS calls.
- GitHub workflow syntax is checked with actionlint.
- `cargo deny --locked check advisories bans licenses sources` passes with three
  reviewed maintenance-only exceptions for the zbus 5 dependency family. The
  identifiers, rationale and migration review date are recorded in `deny.toml`
  and [releasing.md](../releasing.md); security vulnerability checks remain enabled.

## Review and corrections

Independent review identified and verified fixes for:

- Windows case-insensitive identifier collisions: portable identifiers reject
  uppercase consistently.
- Linux concurrent duplicate registration: bounded per-user mutation locking.
- Windows cross-session mutation races between cooperating CLI processes:
  global user-SID-scoped locking.
- Notarization completion versus acceptance: publication requires an explicit
  `Accepted` JSON result.

The review found no remaining code blockers after those corrections. The
implementation also suppresses implicit Secret Service prompts through a small,
documented vendor patch, and fixes a diagnostic failure-path assertion found by
the CLI suite.

The first native macOS CI run correctly denied the separate test harness access
to a CLI-created credential. The end-to-end test was corrected to retrieve and
clean up through the same CLI executable identity, without relaxing Keychain
permissions. Independent review approved this correction; the Linux regression
run passed before pushing it for native macOS validation.

## Remaining release evidence

Native GitHub CI results are authoritative for Windows MSVC, Linux ARM64, and
both macOS runtime environments. Cross-compilation alone does not establish
native integration success. Production macOS signing, upgrade continuity,
locked-state behavior, and access isolation require the acceptance procedure in
[releasing.md](../releasing.md). No release was published by the implementation
task, and these local results are not a claim of complete v1 release acceptance.
