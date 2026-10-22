> Design specification: “version 1.0” below describes the intended product scope, not the current package version. See [releases](https://github.com/diegmonti/totp/releases) for published versions and [traceability](traceability.md) for implementation coverage. Proposed architecture and future enhancements are design intent, not a promise of available features.

# Software Requirements Specification
## Cross-Platform Secure TOTP CLI

**Version:** 1.0  
**Status:** Requirements Specification  
**Date:** October 20, 2026  
**Implementation Language:** Rust  
**Target Platforms:** Windows, Linux, macOS

---

# 1. Introduction

## 1.1 Purpose

This document defines the functional, security, architectural, and non-functional requirements for a cross-platform command-line application that securely stores Time-Based One-Time Password (TOTP) credentials and generates authentication codes.

The application shall integrate with native operating-system credential storage facilities and support fully non-interactive TOTP generation whenever the operating system permits unattended access.

The application is intended primarily for developers, system administrators, and automation workflows that require secure, scriptable access to TOTP codes.

## 1.2 Objectives

The application shall:

- Provide a consistent command-line interface across Windows, Linux, and macOS.
- Generate TOTP codes compliant with RFC 6238.
- Store TOTP secrets using operating-system-native secure credential storage.
- Retrieve credentials without user interaction when backend access is already authorized.
- Enumerate stored credentials directly through native storage mechanisms.
- Support interactive and explicitly selected non-interactive credential registration.
- Store complete, versioned TOTP credential records.
- Avoid storing plaintext secrets in application-managed files.
- Prevent automatic fallback to insecure credential storage.
- Be distributed as a standalone native executable.

## 1.3 Scope

Version 1.0 shall provide:

1. Credential registration and replacement.
2. TOTP code generation.
3. Native credential enumeration.
4. Credential deletion.
5. Registration through OTPAuth URIs.
6. Versioned credential metadata.
7. Explicit stdin-based registration.
8. Native secure storage backend detection.
9. Non-interactive TOTP retrieval and generation.
10. Platform and storage diagnostics.

## 1.4 Exclusions

The following capabilities are outside the scope of version 1.0:

- HOTP authentication.
- Encrypted backup export and import.
- Migration of credentials between installations.
- Automatic cloud synchronization.
- Graphical user interface.
- Browser integration.
- Remote secret management services.
- Dedicated Linux headless storage backends.
- Application-managed plaintext secret databases.

Backup, import/export, and cross-platform credential migration may be introduced in future versions.

## 1.5 Terminology

| Term | Definition |
|---|---|
| TOTP | Time-Based One-Time Password, as specified by RFC 6238 |
| Seed | Shared secret used to generate TOTP codes |
| Credential | A named TOTP configuration containing the seed and associated metadata |
| Credential Store | Operating-system facility used to securely store credential data |
| Backend | Platform-specific implementation of credential storage operations |
| OTPAuth URI | Standard URI format commonly used to provision one-time password applications |
| Non-interactive Operation | Operation that completes without prompting the user |
| Headless Environment | System without an active graphical desktop session |

---

# 2. Technology Stack

## 2.1 Programming Language

The application shall be implemented in **Rust**, using a stable Rust toolchain.

Rust is selected for:

- Native compilation across supported platforms.
- Memory safety without garbage collection.
- Explicit management of sensitive data lifetimes.
- Availability of cryptographic libraries.
- Access to platform-specific operating-system APIs.
- Standalone executable distribution.

## 2.2 Recommended Dependencies

These are original design recommendations, not the installed dependency inventory. The implementation uses native platform bindings and RustCrypto HMAC/SHA crates instead of `keyring` and `totp-rs`; see [Cargo.toml](../../Cargo.toml) for current dependencies.

| Component | Recommended Library | Purpose |
|---|---|---|
| CLI framework | `clap` | Command-line argument parsing |
| Secure storage | `keyring` | Native credential storage integration |
| TOTP generation | `totp-rs` | RFC 6238 implementation |
| Serialization | `serde` | Versioned credential records |
| Sensitive memory handling | `zeroize` | Best-effort clearing of secret material |
| Error handling | `thiserror` | Structured application errors |
| Native API integration | Platform-specific bindings | Credential enumeration and access-control features |

The exact dependencies and versions shall be validated during implementation.

## 2.3 Dependency Requirements

- Dependencies shall be maintained and actively supported.
- The project shall commit `Cargo.lock`.
- Cryptographic primitives shall not be implemented from scratch.
- Dependency vulnerabilities shall be monitored.
- Dependencies shall be reviewed for licensing compatibility.
- Platform-specific libraries may be used when a common abstraction does not expose required operating-system functionality.

---

# 3. Functional Requirements

## FR-001 — Credential Registration

The application shall support registration of TOTP credentials.

Example:

```bash
totp add github
```

Requirements:

- Each credential shall have a unique identifier.
- Interactive registration shall conceal secret input.
- The application shall accept Base32-encoded TOTP seeds.
- Secrets shall be validated before storage.
- Duplicate identifiers shall be rejected unless replacement is explicitly requested.
- The complete credential record shall be stored in native secure storage.
- Successfully registered secrets shall not be displayed.
- Default TOTP parameters shall be applied when alternatives are not provided.

**Priority:** Must Have

## FR-002 — TOTP Generation

The application shall generate a current TOTP code for a registered credential.

Example:

```bash
totp get github
```

Requirements:

- Retrieve the credential from native secure storage.
- Validate the stored credential record.
- Generate the code using the credential's configured algorithm, digit count, period, and epoch.
- Print only the code followed by a newline.
- Preserve leading zeros.
- Return exit code `0` upon success.
- Never expose the underlying secret.

Default parameters:

| Parameter | Value |
|---|---|
| Algorithm | HMAC-SHA1 |
| Digits | 6 |
| Period | 30 seconds |
| T0 | 0 |

The application shall also support:

- HMAC-SHA256.
- HMAC-SHA512.
- Eight-digit TOTP codes.
- Configurable time periods.

**Priority:** Must Have

## FR-003 — Native Credential Enumeration

The application shall list credentials stored in the operating system's native credential store.

Example:

```bash
totp list
```

Requirements:

- Enumeration shall use native credential-store functionality.
- Only credentials belonging to the application's namespace shall be returned.
- No separate application-managed credential index shall be maintained.
- Enumeration shall not retrieve plaintext seeds unnecessarily.
- Results shall be sorted deterministically.
- Each identifier shall be printed on a separate line.
- Unavailable enumeration capabilities shall result in an explicit error.

Expected platform mechanisms:

| Platform | Mechanism |
|---|---|
| Windows | `CredEnumerate` |
| macOS | `SecItemCopyMatching` |
| Linux | Secret Service item search |

The implementation shall account for differences in native credential attributes, filtering, and enumeration permissions.

**Priority:** Must Have

## FR-004 — Credential Removal

The application shall allow deletion of stored credentials.

Example:

```bash
totp remove github
```

Requirements:

- Delete the selected credential from native storage.
- Require confirmation when executing interactively unless `--force` is supplied.
- Fail rather than wait for input when confirmation is required but unavailable.
- Return a nonzero exit code if removal fails.
- Never reveal the removed seed.
- Require no synchronization with an application-managed credential index.

Example of unattended removal:

```bash
totp remove github --force
```

**Priority:** Must Have

## FR-005 — OTPAuth URI Registration

The application shall support registration from standard `otpauth://totp/` URIs.

Example:

```bash
totp import
```

Supported attributes shall include:

- Secret.
- Issuer.
- Account label.
- Algorithm.
- Digit count.
- Period.

Requirements:

- Validate URI structure and parameters.
- Reject unsupported OTP types.
- Preserve supported TOTP configuration.
- Store imported information as a versioned credential record.
- Avoid exposing the URI in logs or command arguments.
- Support both concealed interactive input and explicit stdin input.

The `import` command in version 1.0 refers exclusively to OTPAuth credential registration, not to importing application backups or credential archives.

**Priority:** Must Have

## FR-006 — Non-Interactive TOTP Generation

The application shall support fully non-interactive execution of credential retrieval and TOTP generation.

Example:

```bash
totp get github
```

When the operating-system credential store permits unattended access, the command shall execute without:

- Password prompts.
- PIN prompts.
- Biometric confirmation.
- Graphical dialogs.
- User confirmation.
- Additional input.

If authorization or backend availability prevents non-interactive access, the application shall fail explicitly.

The application shall not bypass operating-system security controls.

**Priority:** Must Have

## FR-007 — Credential Replacement

The application shall support explicitly replacing existing credentials.

Example:

```bash
totp add github --replace
```

Requirements:

- Replacement shall require an explicit option.
- Replacement data shall be validated before modifying the existing credential.
- Native atomic update mechanisms shall be used where supported.
- The existing credential should remain valid if validation fails.
- Storage failures shall not be reported as successful replacements.

**Priority:** Must Have

## FR-008 — Diagnostics

The application shall provide diagnostic commands.

Examples:

```bash
totp version
totp doctor
```

Diagnostics shall report:

- Application version.
- Operating system and architecture.
- Selected secure storage backend.
- Backend availability.
- Native enumeration support.
- Non-interactive access capability where detectable.
- Configuration and permission errors.

Diagnostics shall never disclose secrets or generated TOTP codes.

**Priority:** Must Have

## FR-009 — Non-Interactive Credential Registration

The application shall support credential registration through explicitly selected standard input.

Example:

```bash
totp add github --secret-stdin
```

Requirements:

- Reading a seed from stdin shall require an explicit option.
- Input shall not be echoed to stdout.
- Secrets shall not be accepted as ordinary positional arguments.
- Input length shall be bounded.
- Empty or malformed input shall be rejected.
- Validation and storage behavior shall match interactive registration.
- The application shall not automatically consume piped input without an explicit option.

OTPAuth URIs shall also support stdin registration:

```bash
totp import --stdin
```

The documentation shall explain that passing a seed through stdin does not guarantee its confidentiality if the upstream process exposes or logs the value.

Interactive registration shall remain the default behavior.

**Priority:** Must Have

---

# 4. Credential Data Model

## DM-001 — Versioned Credential Records

Each credential shall be represented by a structured, versioned record.

Conceptual structure:

```json
{
  "schemaVersion": 1,
  "type": "totp",
  "secret": "BASE32_ENCODED_SECRET",
  "algorithm": "SHA1",
  "digits": 6,
  "period": 30,
  "t0": 0,
  "issuer": "GitHub",
  "account": "example@example.com"
}
```

This structure illustrates the serialized credential payload.

The record shall be stored in native secure credential storage, not in an application-managed plaintext JSON file.

## DM-002 — Credential Identification

Every credential shall have an application-level identifier.

Identifiers shall:

- Be unique within the application's namespace.
- Follow a documented portable character policy.
- Have a documented maximum length.
- Map unambiguously to native storage entries.
- Remain stable across application upgrades.

The identifier encoding scheme shall avoid collisions and ambiguity across platforms.

## DM-003 — Schema Versioning

The application shall:

- Include a schema version in each credential record.
- Validate record structure before use.
- Reject unsupported schema versions.
- Avoid silently discarding unknown required fields.
- Preserve metadata required for TOTP generation.
- Provide a foundation for explicit schema migration in future releases.

## DM-004 — Protected Metadata

The following attributes shall be included in the protected credential payload:

- Seed.
- Algorithm.
- Digit count.
- Period.
- Epoch.
- Issuer.
- Account label.

Native credential-store identifiers may expose application-level credential names to authorized system tools.

Credential identifiers shall therefore not be treated as confidential.

## DM-005 — Storage Format Portability

The logical credential record format shall be independent of the operating system.

This shall allow future migration functionality to reuse the same record representation without changing the TOTP generation engine.

Version 1.0 does not require portable credential export or import between installations.

---

# 5. Secure Storage Requirements

## SR-001 — Native Credential Storage

The application shall use the following preferred storage backends:

| Platform | Backend |
|---|---|
| Windows | Windows Credential Manager |
| macOS | macOS Keychain |
| Linux | Secret Service-compatible credential store |

Credentials shall be stored under the security context of the authorized operating-system user.

## SR-002 — Storage Abstraction

Native storage operations shall be isolated behind a common interface.

Conceptual Rust interface:

```rust
trait SecretStore {
    fn store(
        &self,
        name: &str,
        record: &[u8],
    ) -> Result<()>;

    fn retrieve(
        &self,
        name: &str,
    ) -> Result<Vec<u8>>;

    fn delete(
        &self,
        name: &str,
    ) -> Result<()>;

    fn list(
        &self,
    ) -> Result<Vec<String>>;
}
```

The actual implementation may use strongly typed credential records, structured errors, and backend capability descriptors.

Platform-specific enumeration shall be implemented where portable libraries do not expose the required functionality.

## SR-003 — Native Storage as the Authoritative Source

The native credential store shall be the sole authoritative inventory of registered credentials.

The application shall not maintain a separate persistent credential index.

Configuration files may contain non-secret application preferences but shall not duplicate the credential inventory.

## SR-004 — Linux Headless Compatibility

Linux headless environments shall be supported when an existing compatible secure credential backend is accessible without user interaction.

Requirements:

- A graphical desktop shall not be a mandatory application prerequisite.
- The application shall detect whether a compatible Secret Service backend is available.
- Missing session D-Bus services shall be reported explicitly.
- Locked or inaccessible credential stores shall be reported explicitly.
- No unprotected credential store shall be created automatically.
- No plaintext storage fallback shall be provided.

A dedicated headless storage backend is outside the scope of version 1.0.

## SR-005 — Windows Subsystem for Linux

WSL shall be treated as a Linux environment.

The application shall not assume that a Linux process can directly access Windows Credential Manager.

When no compatible Linux credential backend exists, the application shall report that secure storage is unavailable.

## SR-006 — macOS Keychain Authorization

The macOS implementation shall support unattended credential retrieval by the authorized application.

Requirements:

- Official prebuilt macOS release binaries, when provided, shall use a stable code-signing identity and be notarized.
- macOS release archives are optional when signing or notarization credentials are unavailable. Windows and Linux releases shall remain available independently of those credentials.
- macOS shall remain supported through source builds and automated native CI. Source builds do not guarantee Keychain authorization continuity across rebuilds; this limitation shall be documented.
- The selected Keychain access policy shall support unattended access after appropriate authorization.
- The implementation shall not require user presence for every TOTP generation.
- The application shall not deliberately grant unrestricted credential access to unrelated applications.
- Access failures shall be reported explicitly.
- Authorization restrictions shall not be automatically relaxed.
- Behavior following application upgrades shall be tested.

The implementation shall account for differences between traditional file-based Keychain access controls and Data Protection Keychain access controls.

## SR-007 — Backend Capability Detection

The storage abstraction shall expose or determine:

- Backend identity.
- Read capability.
- Write capability.
- Native enumeration support.
- Accessibility.
- Non-interactive authorization status where reliably detectable.

Capabilities that cannot be determined in advance shall be treated as unknown.

## SR-008 — Secure Failure Behavior

If a native credential backend is unavailable, inaccessible, or locked, the application shall not:

- Store secrets in plaintext.
- Create an unprotected fallback database.
- Weaken operating-system access restrictions.
- Retry indefinitely.
- Report success after a failed operation.

---

# 6. Security Requirements

## SEC-001 — Credential Confidentiality

TOTP seeds shall never be written to:

- Normal command output.
- Application logs.
- Diagnostic reports.
- Command-line arguments.
- Application-managed plaintext files.

## SEC-002 — Sensitive Memory Handling

The application shall minimize the lifetime of plaintext secret material in memory.

Sensitive buffers should be cleared using `zeroize` or equivalent mechanisms when no longer needed.

The implementation shall avoid unnecessary copying, formatting, and allocation of secret material.

Memory clearing is a best-effort defense and does not guarantee elimination of all copies held by external libraries or operating-system facilities.

## SEC-003 — TOTP Cryptographic Standards

TOTP generation shall comply with RFC 6238 and the corresponding HOTP calculation defined in RFC 4226.

Supported algorithms shall include:

- HMAC-SHA1.
- HMAC-SHA256.
- HMAC-SHA512.

SHA1 support is required for TOTP interoperability and shall not be reused for unrelated security purposes.

## SEC-004 — Time Source

The application shall use the operating system's current UTC time.

It shall not implement a separate time synchronization service.

Incorrect system time may result in invalid TOTP codes.

## SEC-005 — Error Handling

Errors shall be written to stderr.

Error messages shall be actionable without revealing secrets.

Examples:

```text
Error: credential 'github' not found.
Error: secure storage backend unavailable.
Error: credential store is locked.
Error: native credential enumeration unavailable.
```

## SEC-006 — Threat Model

The application protects credentials at rest through operating-system-native security mechanisms.

It does not guarantee protection against:

- Malware running under the authorized user identity.
- Compromise of the operating system.
- Compromise of a native credential backend.
- Unauthorized access granted through incorrect operating-system configuration.
- Processes that the operating system explicitly authorizes to read the same credentials.

The application shall document these limitations without claiming stronger guarantees than those provided by the selected backend.

## SEC-007 — Secure Input

Interactive registration shall use concealed input wherever supported.

Non-interactive registration shall require explicit stdin input.

Secrets shall not be accepted as positional command-line arguments.

## SEC-008 — Secure Defaults

The application shall:

- Use native secure credential storage.
- Reject insecure fallback mechanisms.
- Avoid automatic permission relaxation.
- Require explicit authorization for destructive operations.
- Never expose secrets in diagnostic output.

## SEC-009 — Logging

Logging shall never include:

- Plaintext TOTP seeds.
- Complete OTPAuth URIs containing secrets.
- Generated TOTP codes.
- Protected credential payloads.

Diagnostic logging may be enabled explicitly.

---

# 7. Command-Line Interface Requirements

## 7.1 Command Structure

The general command format shall be:

```text
totp <command> [arguments] [options]
```

Supported commands:

| Command | Description |
|---|---|
| `totp add <name>` | Interactive credential registration |
| `totp add <name> --secret-stdin` | Non-interactive registration |
| `totp add <name> --replace` | Explicit credential replacement |
| `totp get <name>` | Generate current TOTP |
| `totp list` | Enumerate native credentials |
| `totp remove <name>` | Remove a credential |
| `totp remove <name> --force` | Remove without confirmation |
| `totp import` | Register a credential using an OTPAuth URI |
| `totp import --stdin` | Register an OTPAuth URI through stdin |
| `totp doctor` | Diagnose storage backend |
| `totp version` | Display application version |
| `totp help` | Display command help |

## 7.2 Standard Output Contract

Successful execution of:

```bash
totp get github
```

shall produce exactly the configured number of decimal digits followed by a newline.

Example:

```text
042731
```

Standard output shall not include:

- Application banners.
- Timestamps.
- Informational messages.
- Progress indicators.
- Debug output.

This requirement enables integration with shell scripts, PowerShell pipelines, and automation tools.

## 7.3 Credential Listing Output

The `list` command shall print one credential identifier per line.

Results shall be sorted deterministically.

If no credentials exist, the command shall succeed and produce empty stdout.

## 7.4 Exit Codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | General application error |
| 2 | Invalid command or arguments |
| 3 | Credential not found |
| 4 | Secure storage backend unavailable |
| 5 | Credential store locked or interaction required |
| 6 | Invalid secret or TOTP configuration |
| 7 | Credential already exists |
| 8 | Permission denied |
| 9 | Native credential enumeration unavailable |
| 10 | Unsupported credential schema |

Exit codes shall remain stable across compatible application releases.

## 7.5 Non-Interactive Execution

The `get` command shall not read from stdin or display prompts.

Commands requiring confirmation shall fail when input is unavailable unless an explicit non-interactive option is provided.

## 7.6 Timeout Behavior

Backend operations shall have bounded execution behavior wherever supported.

When native operating-system calls cannot be reliably interrupted, the application shall document the limitation.

---

# 8. Non-Functional Requirements

## NFR-001 — Supported Platforms

The application shall support:

- Windows x86-64.
- Linux x86-64.
- Linux ARM64.
- macOS ARM64.
- macOS x86-64.

Platform support shall be validated through automated builds and integration tests.

## NFR-002 — Deployment

The application shall be distributed as a standalone native executable.

It shall not require:

- A Rust toolchain.
- A language interpreter.
- A separately installed language runtime.
- An application-managed database server.
- An application-specific background daemon.

Native operating-system credential services may still be required.

## NFR-003 — Performance

Under normal operating conditions:

- TOTP calculation should complete within 10 milliseconds after credential retrieval.
- A successful local TOTP CLI invocation should normally complete within 500 milliseconds.

These are performance targets rather than guarantees because native credential-store latency varies across environments.

## NFR-004 — Reliability

Read-only operations shall not modify stored credentials.

Validation failures shall not overwrite valid credentials.

Unexpected termination during credential retrieval shall not corrupt stored credentials.

## NFR-005 — Maintainability

The source code shall separate:

- CLI parsing.
- Command execution.
- Credential serialization.
- TOTP calculation.
- Native secure storage integration.
- Platform-specific enumeration.
- Diagnostics.
- Error handling.

Platform-specific logic shall not be embedded in the TOTP generator.

## NFR-006 — Compatibility

The serialized credential format and identifier mapping shall remain stable across compatible releases.

Future schema changes shall follow an explicit compatibility and migration policy.

## NFR-007 — Documentation

The project shall provide:

- Installation instructions.
- CLI command reference.
- Supported platform matrix.
- Secure storage configuration guidance.
- Linux headless limitations.
- WSL behavior.
- macOS Keychain access-control guidance.
- Troubleshooting documentation.
- Security model and limitations.
- Usage examples for PowerShell, Bash, and Zsh.

---

# 9. Testing and Acceptance Criteria

## AC-001 — TOTP Correctness

The application shall pass the official RFC 6238 test vectors.

Tests shall include:

- SHA1, SHA256, and SHA512.
- Six- and eight-digit codes.
- Different time periods.
- Leading-zero preservation.
- Invalid Base32 secrets.
- Invalid credential configurations.
- Boundary conditions between time steps.

## AC-002 — Native Secure Storage

Credentials shall be stored in the selected native credential backend.

The application shall not create plaintext credential files.

Registration, retrieval, and deletion shall be validated on every supported desktop operating system.

## AC-003 — Native Credential Enumeration

On each supported desktop platform:

1. Register three credentials.
2. Execute `totp list`.
3. Verify that all three identifiers are returned.
4. Verify deterministic ordering.
5. Remove one credential.
6. Verify that it disappears from the listing.
7. Verify that unrelated native credentials are excluded.

The test shall confirm that enumeration operates without an application-managed index.

Where supported by backend instrumentation, tests shall also verify that enumeration does not unnecessarily retrieve seed values.

## AC-004 — Linux Headless Compatibility

In a headless Linux environment with an available, unlocked, compatible credential backend, credential operations shall succeed without a graphical desktop.

If no compatible backend is available:

- Operations shall fail explicitly.
- No insecure fallback shall occur.
- The application shall report the relevant backend limitation.

## AC-005 — Non-Interactive Registration

The application shall successfully register a valid TOTP credential using:

```bash
totp add test --secret-stdin
```

Tests shall verify that:

- The secret is not echoed.
- Malformed input is rejected.
- Empty input is rejected.
- Input size limits are enforced.
- No plaintext secret is persisted outside native secure storage.
- Positional secret arguments are rejected.
- Explicit stdin selection is mandatory.

## AC-006 — macOS Keychain Authorization

Tests shall confirm that:

1. Registration succeeds using the approved Keychain configuration.
2. Authorized unattended retrieval succeeds.
3. Repeated TOTP generation does not require per-use confirmation.
4. Locked or inaccessible Keychain states produce explicit failures.
5. Application upgrades do not unexpectedly broaden credential access.
6. Required authorization changes are documented.

## AC-007 — Versioned Credential Records

Stored records shall preserve:

- Schema version.
- Secret.
- Algorithm.
- Digit count.
- Period.
- Epoch.
- Issuer.
- Account label.

Unsupported schema versions shall be rejected without modifying the stored credential.

## AC-008 — Non-Interactive TOTP Generation

With an accessible and authorized backend:

```bash
totp get test
```

shall:

- Complete without user interaction.
- Output only the TOTP code.
- Preserve leading zeros.
- Append exactly one newline.
- Return exit code `0`.

If backend access requires user interaction, the operation shall fail explicitly.

## AC-009 — Credential Replacement

Tests shall verify:

- Duplicate identifiers are rejected by default.
- Explicit replacement succeeds.
- Invalid replacement data does not overwrite a valid credential.
- Failed storage operations do not report success.

## AC-010 — CLI Output and Exit Codes

Tests shall verify:

- Successful commands use the documented stdout format.
- Errors are written to stderr.
- Exit codes match the documented contract.
- Secrets are not present in error messages.
- Scriptable commands do not include decorative output.

## AC-011 — Security Validation

Security tests shall verify:

- No plaintext credential fallback.
- No seed disclosure in logs.
- No TOTP disclosure in diagnostics.
- No unsupported secret-bearing positional arguments.
- Explicit errors for unavailable or locked credential stores.
- No automatic relaxation of access controls.

## AC-012 — Platform Integration

The following capabilities shall be tested on each supported desktop operating system.

| Capability | Windows | macOS | Linux |
|---|---|---|---|
| Native credential storage | Required | Required | Required |
| Credential registration | Required | Required | Required |
| Credential retrieval | Required | Required | Required |
| Native enumeration | Required | Required | Required |
| Credential deletion | Required | Required | Required |
| Non-interactive TOTP generation | Required when authorized | Required when authorized | Required when authorized |
| Secure failure behavior | Required | Required | Required |

## AC-013 — Release Acceptance

Version 1.0 shall be ready for release when:

1. All Must Have functional requirements are implemented.
2. All RFC 6238 test vectors pass.
3. Native credential storage is validated on Windows, macOS, and Linux desktop.
4. Native credential enumeration is validated.
5. Non-interactive registration and TOTP generation are tested.
6. Conditional Linux headless behavior is validated.
7. macOS application authorization is validated.
8. No insecure storage fallback exists.
9. Stable CLI output and exit codes are verified.
10. Standalone Windows and Linux release binaries and documentation are available. macOS source installation is documented; prebuilt macOS archives are optional and require signing, notarization, and the corresponding upgrade authorization acceptance checks.

---

# 10. Internal Architecture

## 10.1 Project Structure

The proposed project structure is:

```text
src/
├── main.rs
├── cli/
│   ├── mod.rs
│   └── commands.rs
├── credentials/
│   ├── mod.rs
│   ├── record.rs
│   └── validation.rs
├── totp/
│   ├── mod.rs
│   └── generator.rs
├── storage/
│   ├── mod.rs
│   ├── backend.rs
│   └── platform/
│       ├── windows.rs
│       ├── macos.rs
│       └── linux.rs
├── diagnostics/
│   └── mod.rs
└── error.rs
```

## 10.2 Architecture Principles

The implementation shall follow these principles:

- TOTP generation shall be independent of native credential storage.
- Native credential stores shall be the authoritative source of credentials.
- Enumeration shall use platform-specific native functionality.
- No application-managed credential index shall exist.
- Credential records shall use a platform-independent schema.
- Platform-specific access-control mechanisms shall remain isolated.
- CLI behavior shall remain consistent across supported operating systems.

## 10.3 Credential Registration Flow

```text
User Input
    |
    v
CLI Validation
    |
    v
Credential Record Creation
    |
    v
Record Serialization
    |
    v
Native Secure Storage
```

## 10.4 TOTP Generation Flow

```text
CLI Request
    |
    v
Native Credential Retrieval
    |
    v
Record Deserialization
    |
    v
Credential Validation
    |
    v
RFC 6238 TOTP Calculation
    |
    v
Code on stdout
```

## 10.5 Native Enumeration Flow

```text
totp list
    |
    v
Platform Enumeration API
    |
    v
Application Namespace Filtering
    |
    v
Credential Identifier Extraction
    |
    v
Deterministic Sorting
    |
    v
Identifiers on stdout
```

---

# 11. Future Enhancements

The following features may be considered for releases after version 1.0.

| Feature | Description | Suggested Priority |
|---|---|---|
| Encrypted credential backup | Secure export and restore of credential collections | High |
| Cross-platform credential migration | Transfer credentials between Windows, Linux, and macOS installations | High |
| Dedicated Linux headless backend | Support for TPM2 or other explicitly approved mechanisms | Medium |
| WSL integration | Access to Windows-native credential storage from WSL | Medium |
| Remote secret management | Integration with enterprise secret managers | Medium |
| JSON output | Machine-readable credential metadata | Low |
| Clipboard integration | Optional copying of generated TOTP codes | Low |
| Multiple profiles | Logical separation of credential collections | Low |
| HOTP support | Counter-based one-time passwords | Low |
| Cloud synchronization | Optional synchronization across devices | Low |

## 11.1 Future Backup and Migration Requirements

A future release may introduce portable encrypted credential backup and restoration.

The intended functionality includes:

- Exporting selected or all registered credentials.
- Encrypting exported data using a maintained, authenticated encryption format.
- Supporting passphrase-protected backups.
- Importing credentials into a different supported operating system.
- Preserving complete credential records and TOTP configuration.
- Handling duplicate credentials explicitly.
- Never writing intermediate plaintext backup files.
- Supporting schema versioning and compatibility checks.

The `age` encryption format should be evaluated as a preferred implementation option.

No backup export, backup import, or cross-platform credential migration functionality is required for version 1.0.

---

# 12. Definition of Done

Version 1.0 shall be considered complete when the application:

- Runs on Windows, Linux, and macOS.
- Uses native operating-system secure credential storage.
- Stores complete versioned credential records.
- Generates RFC 6238-compliant TOTP codes.
- Supports fully non-interactive generation when native access is authorized.
- Enumerates credentials directly from native storage.
- Supports interactive credential registration.
- Supports explicit stdin-based registration.
- Supports OTPAuth URI registration.
- Supports credential replacement and deletion.
- Provides meaningful backend diagnostics.
- Handles Linux headless environments conditionally.
- Uses an authorized macOS Keychain access configuration.
- Never silently falls back to insecure credential storage.
- Produces predictable CLI output and exit codes.
- Passes all applicable functional, integration, and security acceptance criteria.
- Is distributed as standalone native executables.
- Includes installation, usage, and security documentation.

**End of Software Requirements Specification — Version 1.0**
