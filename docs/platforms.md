# Native storage setup and troubleshooting

Run `totp doctor` as the same OS user and session that will run automation. A successful diagnostic cannot promise future authorization; the store may lock later. Never fix access failures by exporting seeds to files or granting broad access to unrelated applications.

## Linux and WSL

Install and configure a Secret Service-compatible provider such as GNOME Keyring, and ensure its encrypted collection is initialized and unlocked through its normal user workflow. The process needs the correct session D-Bus address (`DBUS_SESSION_BUS_ADDRESS`), not merely a running system bus. A desktop login often handles this. SSH, containers, cron and service units usually do not inherit the desktop user's session or unlocked collection.

Headless operation works only with an existing accessible, unlocked compatible backend. `dbus-run-session` creates a session bus, not a secure credential store. Starting a daemon without correctly unlocking an encrypted collection is insufficient. The application never creates an unprotected fallback. Do not put your keyring password in command arguments or shell history. A dedicated headless backend is outside scope.

The Linux adapter uses `secret-service` with encrypted DH transport. `get`, `list`, and `doctor` never request unlocking or an authorization dialog. A locked credential makes `get` fail with exit code 5; unlock the keyring before unattended generation.

`add`, `import`, replacement, and `remove` may ask the provider to unlock the existing collection/item and may display its authorization dialog. Approving the dialog allows the operation to continue; cancelling it fails with exit code 5. `--secret-stdin` and `--stdin` choose how the seed/URI is read, and `--force` skips the CLI removal confirmation; these options do not suppress native authorization dialogs. The application does not create a collection or relax the provider's access policy.

Read/list operations have a ten-second deadline. Mutations have a two-minute deadline to allow time for authorization, plus up to ten seconds to acquire the mutation lock. A timeout does not prove that a write was rolled back; check the store before retrying.

WSL uses Linux Secret Service. It cannot automatically use Windows Credential Manager. Configure a Linux provider or expect explicit unavailability. Do not copy Windows credentials into plaintext files as a workaround.

If unavailable: verify the session bus and service ownership, provider installation, and collection state. If locked or interaction is required: unlock through the provider's authorized UI/session mechanism before automation, or approve its dialog during registration/removal. If access is denied: inspect the provider's policy as that user. Do not run the application as root to work around a user-session configuration failure.

## macOS

Use the normal login Keychain under your user account, unlocked and authorized for the installed executable. Native operations disable interactive authorization; a locked Keychain or a requirement for UI must result in an explicit error. Initial authorization may need to be established through the system's authorized Keychain workflow before unattended use. The tool does not request user presence on every code generation or grant all applications access.

Official prebuilt archives are optional and require signing/notarization credentials; otherwise use the [source installation instructions](installation.md#build-from-source), which require no paid Apple certificate. Official builds must retain the same Developer ID team and designated code requirement across upgrades. Locally rebuilt, unsigned, ad-hoc signed, relocated, or differently signed executables can be treated as different applications. Do not select “allow all applications” to fix access failures. Review the item's access policy using Keychain Access and authorize only the intended executable. Traditional file-based Keychain ACL behavior differs from Data Protection Keychain access groups; do not assume one model's permissions apply to the other.

CI uses a temporary unlocked keychain for native round trips on both macOS architectures, even when no macOS archives are published. That does not validate production Developer ID trust, login locking, Gatekeeper, or upgrade continuity. Before distributing signed macOS upgrades, complete the [manual upgrade acceptance checklist](releasing.md#macos-upgrade-acceptance) using actual signed builds.

## Windows

Use Windows Credential Manager in the same user security context as registration. A scheduled task, service account, elevated process or different session may have a different credential context or unavailable profile. Register and test credentials under the intended automation account and its supported logon configuration. Investigate policy and profile access when denied; the application does not bypass Windows security controls.

## Incorrect codes and damaged records

Verify UTC clock synchronization, service algorithm/digits/period, and the registered credential. Avoid printing the seed when diagnosing mismatches. Unsupported schema versions fail without rewriting records; use a compatible binary rather than editing native records by hand. A failed replacement validation preserves the existing credential. Native storage failures can require checking whether a write actually completed before retrying.
