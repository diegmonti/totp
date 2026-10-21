# Native storage setup and troubleshooting

Run `totp doctor` as the same OS user and session that will run automation. A successful diagnostic cannot promise future authorization; the store may lock later. Never fix access failures by exporting seeds to files or granting broad access to unrelated applications.

## Linux and WSL

Install and configure a Secret Service-compatible provider such as GNOME Keyring, and ensure its encrypted collection is initialized and unlocked through its normal user workflow. The process needs the correct session D-Bus address (`DBUS_SESSION_BUS_ADDRESS`), not merely a running system bus. A desktop login often handles this. SSH, containers, cron and service units usually do not inherit the desktop user's session or unlocked collection.

Headless operation works only with an existing accessible, unlocked compatible backend. `dbus-run-session` creates a session bus, not a secure credential store. Starting a daemon without correctly unlocking an encrypted collection is insufficient. The application never creates an unprotected fallback. Do not put your keyring password in command arguments or shell history. A dedicated headless backend is outside scope.

WSL uses Linux Secret Service. It cannot automatically use Windows Credential Manager. Configure a Linux provider or expect explicit unavailability. Do not copy Windows credentials into plaintext files as a workaround.

If unavailable: verify the session bus and service ownership, provider installation, and collection state. If locked or interaction is required: unlock through the provider's authorized UI/session mechanism before automation. If access is denied: inspect the provider's policy as that user. Do not run the application as root to work around a user-session configuration failure.

## macOS

Use the normal login Keychain under your user account, unlocked and authorized for the installed executable. Native operations disable interactive authorization; a locked Keychain or a requirement for UI must result in an explicit error. Initial authorization may need to be established through the system's authorized Keychain workflow before unattended use. The tool does not request user presence on every code generation or grant all applications access.

Official builds must retain the same Developer ID team and designated code requirement across upgrades. Locally rebuilt, unsigned, ad-hoc signed, relocated, or differently signed executables can be treated as different applications. Do not select “allow all applications” to fix access failures. Review the item's access policy using Keychain Access and authorize the intended signed executable only. Traditional file-based Keychain ACL behavior differs from Data Protection Keychain access groups; do not assume one model's permissions apply to the other.

CI uses a temporary unlocked keychain for native round trips. That does not validate production Developer ID trust, login locking, Gatekeeper, or upgrade continuity. The [manual upgrade acceptance checklist](releasing.md#macos-upgrade-acceptance) must be completed using actual signed builds.

## Windows

Use Windows Credential Manager in the same user security context as registration. A scheduled task, service account, elevated process or different session may have a different credential context or unavailable profile. Register and test credentials under the intended automation account and its supported logon configuration. Investigate policy and profile access when denied; the application does not bypass Windows security controls.

## Incorrect codes and damaged records

Verify UTC clock synchronization, service algorithm/digits/period, and the registered credential. Avoid printing the seed when diagnosing mismatches. Unsupported schema versions fail without rewriting records; use a compatible binary rather than editing native records by hand. A failed replacement validation preserves the existing credential. Native storage failures can require checking whether a write actually completed before retrying.
