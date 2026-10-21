# CI and release maintenance

CI executes formatting, locked dependency compilation, Clippy with warnings denied, unit/CLI tests, and the ignored native integration test on Windows x64, Linux x64/ARM64, and macOS Intel/Apple Silicon. Native integration requires `TOTP_NATIVE_TESTS=1` and `cargo test --locked --test native_storage -- --ignored --test-threads=1`. CI supplies an isolated Linux D-Bus session and unlocked GNOME Keyring, a temporary unlocked macOS keychain, or the Windows runner's native user store. Test-only disposable keyring passwords in the workflow are not production secrets. Native tests register three entries, check deterministic enumeration, replace and delete them. An additional Linux test checks exclusion of an unrelated native item; equivalent unrelated-item fixture evidence on macOS and Windows remains a platform acceptance task. Linux also runs an opt-in locked-collection failure test in an isolated temporary XDG data/config directory. Scheduled CI checks RustSec advisories, licenses and dependency sources with cargo-deny; Dependabot proposes weekly updates.

The five-platform workflow has been configured, but this source delivery does not establish that GitHub-hosted runs or production signed upgrade acceptance have passed. Review actual workflow results and retain external acceptance evidence before calling v1 release-ready. CI's temporary stores do not reproduce every production session or locked state.

## Dependency maintenance exceptions

Reviewed 2026-10-21: `deny.toml` narrowly exempts maintenance-only notices RUSTSEC-2026-0370, RUSTSEC-2026-0371 and RUSTSEC-2026-0372. The zvariant, zbus_names and zvariant_derive standalone crates merged into zbus 6; the vendored Secret Service 5 adapter currently requires zbus 5. No security vulnerability is waived by these entries. New vulnerability advisories continue to fail CI.

Maintainers must track upstream Secret Service support for zbus 6, review migrating the adapter, and remove these exceptions when its dependency graph is migrated. Reassess no later than 2027-01-21 and at every release; that date is a review obligation, not an automatically enforced expiration. Do not broaden the exception list to make checks pass.

## Automatic publication

Push a `v<package-version>` tag to trigger release. The workflow reruns all CI gates, verifies the tag against Cargo metadata, builds five native release executables, signs and notarizes both macOS builds, archives binaries with README and license, generates SHA-256 checksums, and publishes a GitHub release automatically after all builds succeed. Configure GitHub tag protection/rulesets so only release maintainers can create version tags. Use a `release` environment with the repository's appropriate deployment restrictions; adding required reviewers intentionally makes publication wait for those reviewers.

Set these environment secrets before creating a release tag:

| Secret | Value |
|---|---|
| `MACOS_CERTIFICATE_BASE64` | Base64-encoded Developer ID Application PKCS#12 certificate including its private key |
| `MACOS_CERTIFICATE_PASSWORD` | PKCS#12 import password |
| `MACOS_SIGNING_IDENTITY` | Stable Developer ID Application identity, including team ID |
| `APPLE_ID` | Notarization Apple ID |
| `APPLE_TEAM_ID` | Matching Developer team ID |
| `APPLE_APP_PASSWORD` | App-specific notarization password |

Keep the same signing team and designated requirement across releases. Protect and rotate signing credentials through the organization's signing process. Missing credentials fail macOS builds and block the complete release; no unsigned fallback is published. Notarization must return JSON status `Accepted`; submission or waiting alone is insufficient. Raw CLI executables do not support stapled tickets; online Gatekeeper assessment may be needed. Do not describe a binary as signed or notarized until the actual workflow succeeds and the downloaded artifact is checked.

Before publishing, review dependency changes and advisories, package licenses, native integration logs, tag/package version, and the manual acceptance evidence below. Releases use glibc from Ubuntu 24.04 on Linux; older distributions may require building from source. A standalone executable still requires native OS credential services. Windows signing is not configured.

Action commits are pinned and were verified against upstream tags: checkout v4.2.2, upload-artifact v4.6.2, download-artifact v4.3.0. Review Dependabot updates before changing pins. Rust uses the stable channel; builds are locked to Cargo.lock but are not claimed bit-for-bit reproducible.

## macOS upgrade acceptance

This procedure is a mandatory manual release acceptance gate. It requires two genuine Developer ID-signed builds and a representative real user login Keychain on both supported macOS architectures. CI's temporary keychain test does not satisfy it. Record OS version, architecture, old/new versions, signing team, designated requirements, and pass/fail evidence without seeds or codes.

1. Download the previous and candidate release artifacts through the release channel. Verify checksums, `codesign --verify --strict --verbose=2 <binary>`, and inspect `codesign -d -r- --verbose=4 <binary>`. Verify the expected stable team and designated requirement. Confirm notarization acceptance from the workflow, and Gatekeeper assessment appropriate to the installation path.
2. Install the previous signed build at the intended stable executable path. Register a disposable test credential through concealed input. Establish the narrowly scoped authorization using the supported native workflow; do not allow all applications.
3. Run `get` repeatedly with stdin disconnected and capture only exit status and output shape. Confirm no dialog, PIN, biometric request or extra input and exactly six/eight digits plus newline. Run `list` and verify expected identifiers only.
4. Replace the installed executable with the candidate signed build, retaining path and Keychain. Repeat unattended retrieval and enumeration without broadening policy. Verify credential metadata/configuration still works and the previous record has not been rewritten by reads.
5. Inspect the Keychain item's access policy. Confirm no unrelated application gained access. Test a differently signed disposable executable and confirm it is not silently granted equivalent authorization; do not log record content.
6. Lock the relevant Keychain, run retrieval with stdin disconnected, and verify bounded explicit failure without an authorization UI. Unlock through the normal authorized workflow and confirm recovery. Test denied access separately.
7. Test invalid replacement, explicit valid replacement, deletion, and disappearance from enumeration. Remove disposable records. Record any authorization changes users must perform in the release notes.

If upgrade continuity or access isolation fails, block the release and investigate the access policy and signing requirement. Never compensate by granting unrestricted access.
