> Historical record of the initial implementation task. Its delivery instructions applied to that task only. Current contributor guidance is in [CONTRIBUTING.md](../../CONTRIBUTING.md); current publication procedures are in [releasing.md](../releasing.md).

# Implementation plan

This plan implements [requirements](../development/requirements.md) version 1.0. The repository began with only
the requirements and MIT license. Work is divided among Sol 6.1 implementation
agents, followed by a separate Sol 6.1 review and corrective validation.

## Design and sequence

1. **Core model and cryptography:** establish stable error codes, portable names
   (`[a-z0-9][a-z0-9._-]{0,63}`), a strict versioned protected JSON record,
   Base32 and OTPAuth validation, and RFC 6238 calculation using maintained
   cryptographic libraries. Cover all official vectors and time/configuration
   boundaries. Zeroize sensitive owned buffers where possible.
2. **Native storage:** isolate Windows Credential Manager, macOS Keychain, and
   Linux Secret Service behind a shared interface. Use native enumeration with
   namespace `com.diegmonti.totp`, no persistent index, no plaintext fallback,
   explicit replacement, and explicit failure when interaction is required.
3. **CLI and diagnostics:** implement all specified commands, concealed bounded
   interactive input, explicit bounded stdin registration, exact code/list output,
   confirmation rules, and stable exit codes. Test with injected stores and
   subprocesses without introducing a production test-storage backend.
4. **Platform validation:** provide native lifecycle/enumeration tests on Windows,
   macOS, and Linux, including unlocked headless Secret Service. Test negative
   paths, namespace isolation, and replacement preservation.
5. **CI and release:** format, lint, test and build all five target combinations;
   monitor dependencies and licenses. Release version tags automatically after
   validation, packaging binaries and checksums. Require configured stable macOS
   signing credentials for optional official macOS archives rather than silently
   shipping unsigned replacements. Without Apple credentials, publish Windows
   and Linux archives and document macOS source installation.
6. **Documentation:** cover installation, CLI and shell examples, security model,
   backend setup, Linux/WSL limitations, macOS authorization, troubleshooting,
   schema compatibility, release configuration, and acceptance evidence.
7. **Independent review:** review requirements coverage, security boundaries,
   native APIs, tests and workflows; address findings and rerun affected checks.

## Integration contracts

`SecretStore` provides store-with-explicit-replace, retrieve, delete and list.
The native store is the only persistent inventory. Protected payloads include
secret, algorithm, digits, period, epoch, issuer and account. Diagnostics must
distinguish detected capabilities from unknown per-credential authorization.

## Acceptance and delivery

Run local formatting, clippy, unit/CLI tests and available native integration
checks. Push a feature branch and open a reviewable pull request. Do not merge
or publish a release as part of implementation. Record platform checks that
cannot be exercised locally; CI must provide the remaining platform evidence.
Signed macOS upgrade authorization is an additional gate only when distributing
the optional signed macOS archives.
