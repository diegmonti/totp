# Security

## Reporting a vulnerability

Report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/diegmonti/totp/security/advisories/new). Include the affected version, platform, impact, and steps to reproduce. Keep vulnerability details out of public issues. Do not put real seeds, credential payloads, or secret-bearing OTPAuth URIs in issues or reports; use disposable reproductions.

## Security model

Seeds and TOTP parameters are serialized as a versioned record inside the current user's native credential store. No application-managed plaintext credential database or inventory exists. Enumeration uses native APIs and filters the application namespace. Credential identifiers are not confidential; protected payloads contain seeds, algorithm, digits, period, epoch, issuer and account.

The tool protects credentials at rest using operating system controls. It cannot protect against malware running as the authorized user, a compromised OS or privileged debugger, memory inspection during generation, or access to an already unlocked account. Native policy and encryption behavior depend on the operating system and configured store. Best-effort zeroization reduces sensitive memory lifetime but cannot eliminate copies inside libraries, allocators, or operating-system services.

Never pass seeds or OTPAuth URIs in arguments. Interactive input is concealed; explicit stdin is useful for automation but the producer may leak its input. Do not enable shell tracing around secret-producing commands. Protect generated codes from CI logs and terminal recording. Diagnostics and errors must not include seeds, complete secret-bearing URIs, protected records, or generated codes.

Unavailable, unauthorized, or unsupported native storage fails explicitly. Retrieval from locked storage fails without requesting interaction. On Linux, registration, replacement, and deletion may use the provider's normal unlock/authorization dialogs; cancellation fails the operation. Access controls are not relaxed automatically. Non-interactive retrieval depends on previously authorized native access. Backend calls use available native bounds; synchronous native APIs may remain blocked by an unresponsive OS service and cannot always be reliably interrupted. Use an external process supervisor timeout where required, and do not interpret a timeout as proof that a write did not occur.

Dependencies are locked, checked by `cargo deny`, and monitored weekly in CI and Dependabot. These checks aid review and do not prove that dependencies or binaries are vulnerability-free. Official macOS releases require a stable Developer ID identity and notarization; source and ad-hoc builds have different authorization behavior. See [release setup](docs/releasing.md).
