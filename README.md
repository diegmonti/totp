# totp

A command-line TOTP authenticator that stores credentials in Windows Credential Manager, macOS Keychain, or Linux Secret Service. Generate RFC 6238 codes with SHA1, SHA256, or SHA512, using six or eight digits.

Credentials stay in your operating system's native store. There is no application credential file, separate inventory, or plaintext fallback. Unattended use requires an already accessible and authorized store.

On Linux, adding, replacing, and removing credentials may open the native keyring's unlock or authorization dialog. Generating codes never opens an authorization dialog.

## Install

Download binaries and `SHA256SUMS` from [GitHub Releases](https://github.com/diegmonti/totp/releases). See the [installation guide](docs/installation.md) for checksum verification and source builds.

| Platform | Distribution | Credential backend |
|---|---|---|
| Windows x64 | Prebuilt ZIP | Credential Manager |
| Linux x64 / ARM64 | Prebuilt tar.gz | Secret Service over session D-Bus |
| macOS Intel / Apple Silicon | Build from source; signed archives optional | Keychain |

Linux binaries are built on Ubuntu 24.04 and require compatible glibc and a configured Secret Service provider. macOS source builds need no paid Apple certificate. See [platform setup](docs/platforms.md), including headless Linux, WSL, and Keychain authorization.

## Quick start

After installing and configuring native storage:

```sh
totp doctor
totp add github    # enter the Base32 seed at the concealed prompt
totp get github    # prints the current code
totp list
totp remove github # asks for confirmation
```

Use `totp import` to register an `otpauth://totp/` URI through a concealed prompt. Never put seeds or secret-bearing URIs in command arguments. Generated codes are sensitive too; keep them out of logs and terminal recordings.

Backup, export, synchronization, cross-platform migration, and HOTP are not implemented. Keep the service's recovery codes before relying on any authenticator. Read the [security model](SECURITY.md) for the protections and limits of native storage.

## Documentation

Reading this README from a release archive? Open the [online documentation](https://github.com/diegmonti/totp/blob/main/docs/README.md); the full guides are not bundled in binary archives.

- [Installation and upgrades](docs/installation.md)
- [Commands, scripting, and exit codes](docs/usage.md)
- [Platform setup and troubleshooting](docs/platforms.md)
- [Security and vulnerability reporting](SECURITY.md)
- [Contributing and testing](CONTRIBUTING.md)
- [Release maintenance](docs/releasing.md)
- [Documentation index](docs/README.md), including design references

## License

[MIT](LICENSE). Dependencies retain their respective licenses.
