# Command reference

[Installation](installation.md) · [Platform setup](platforms.md) · [Security](../SECURITY.md)

```text
totp add <name> [--secret-stdin] [--replace]
    [--algorithm sha1|sha256|sha512] [--digits 6|8] [--period N] [--t0 N]
    [--issuer TEXT] [--account TEXT]
totp import [--stdin] [--name NAME] [--replace]
totp get <name>
totp list
totp remove <name> [--force]
totp doctor
totp version
totp help
```

`add` conceals the Base32 seed prompt. Defaults are SHA1, 6 digits, 30 seconds, and epoch 0. `import` conceals an `otpauth://totp/` URI and preserves supported algorithm, digits, period, issuer and account fields. HOTP is rejected. Use `--name` to choose the identifier; otherwise the account label is used when it is a valid identifier. `import` registers a single OTPAuth credential; it does not restore backups.

Both commands reject duplicates unless `--replace` is explicit, and validate input before updating storage. Periods must be positive; an epoch later than the current time fails generation. Base32 is case-insensitive, accepts valid padded or unpadded input, and rejects embedded whitespace. Unknown or duplicate record fields and unsupported schemas are rejected. Input is limited to 16,384 bytes including whitespace and newline. Secrets and URIs are never ordinary command arguments. Piped input is consumed only with `--secret-stdin` or `--stdin`. An upstream process can still expose stdin data in logs or memory.

`get` prints only the configured decimal digits and one newline. It preserves leading zeros and never reads stdin. `list` prints sorted identifiers, one per line, or nothing when empty. Identifiers must match `[a-z0-9][a-z0-9._-]{0,63}` (1–64 ASCII bytes); uppercase is rejected to avoid Windows aliases. The stable namespace is `org.frugo.totp`. Names are visible to authorized native system tools and are not confidential. `remove` requires the exact interactive confirmation `yes`, or `--force`; missing input fails. `doctor` reports backend availability and capabilities without seeds or codes. Unknown authorization capability is not a guarantee of unattended access.

On Linux, `add`, `import`, replacement, and `remove` may display the native keyring's unlock or authorization dialog. Cancelling the dialog fails the operation. Stdin input flags do not suppress that dialog, and `remove --force` only skips the CLI confirmation. `get` never opens a dialog and requires an already accessible store.

## Shell examples

Bash and Zsh:

```sh
totp add github                 # concealed interactive seed input
totp import --name work         # concealed interactive URI input
secret_provider | totp add work --secret-stdin
uri_provider | totp import --stdin --name work --replace
code=$(totp get github) || exit "$?"
# Supply "$code" directly to the consuming application.
totp remove work --force
```

`secret_provider` and `uri_provider` stand for an existing trusted producer, not built-in commands. Do not type actual seeds into shell commands, history, environment assignments, or command substitutions. Generated codes are authentication material too; avoid printing or logging them in automation.

PowerShell:

```powershell
totp add github
Secret-Provider | totp add work --secret-stdin
Uri-Provider | totp import --stdin --name work
$code = totp get github
if ($LASTEXITCODE -ne 0) { throw 'TOTP retrieval failed' }
# Supply $code directly to the consuming application.
totp remove work --force
```

## Errors and operations

Errors go to stderr; a failed command returns nonzero. Keep your operating system clock synchronized. Native access must already be authorized for unattended use; the tool does not bypass locks or authorization policy. Read [platform setup and troubleshooting](platforms.md) and the [security model](../SECURITY.md).

| Exit | Meaning |
|---|---|
| 0 | Success |
| 1 | General application error |
| 2 | Invalid command or arguments |
| 3 | Credential not found |
| 4 | Secure storage unavailable |
| 5 | Store locked or interaction required |
| 6 | Invalid secret or TOTP configuration |
| 7 | Credential already exists |
| 8 | Permission denied |
| 9 | Native enumeration unavailable |
| 10 | Unsupported credential schema |

Backup, export, cross-platform migration, HOTP, and synchronization are not implemented. Keep the service's recovery codes in a safe place before relying on any authenticator.
