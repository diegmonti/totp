# Installation and upgrades

## Prebuilt downloads

Download the matching archive and `SHA256SUMS` from [GitHub Releases](https://github.com/diegmonti/totp/releases). Windows x64 and Linux x64/ARM64 archives are available. macOS archives are optional: use a source build when a release does not include them.

| OS / CPU | Archive target |
|---|---|
| Windows x64 | `x86_64-pc-windows-msvc.zip` |
| Linux x64 | `x86_64-unknown-linux-gnu.tar.gz` |
| Linux ARM64 | `aarch64-unknown-linux-gnu.tar.gz` |
| macOS Intel (when included) | `x86_64-apple-darwin.tar.gz` |
| macOS Apple Silicon (when included) | `aarch64-apple-darwin.tar.gz` |

Filenames begin with `totp-v<version>-`. Each archive includes the executable, README, and license. Linux builds use glibc from Ubuntu 24.04; older distributions may need a source build. Windows binaries are not code-signed. Native operating-system credential services are still required.

## Verify and install

Compare the archive's SHA-256 with its entry in `SHA256SUMS` before extracting it. For example, for v0.1.0 Linux x64:

```sh
sha256sum totp-v0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

On macOS use `shasum -a 256 <archive>`. In PowerShell:

```powershell
Get-FileHash .\totp-v0.1.0-x86_64-pc-windows-msvc.zip -Algorithm SHA256
```

Checksums detect corruption; obtain both files through the trusted release channel. They are not independent signatures.

Extract the archive. On Linux or macOS, place `totp` in a directory on your `PATH`, for example:

```sh
install -d "$HOME/.local/bin"
install -m 755 totp "$HOME/.local/bin/totp"
```

Add `$HOME/.local/bin` to `PATH` if necessary. On Windows, extract `totp.exe` into a directory included in your user `Path` environment variable, then open a new terminal.

Run `totp version` and `totp doctor`, then follow the [platform setup guide](platforms.md) for your native credential store.

## Build from source

Install stable Rust and your platform's native build tools. Check out a published tag for a release build:

```sh
git clone https://github.com/diegmonti/totp.git
cd totp
git checkout v0.1.0
cargo build --release --locked
```

The executable is `target/release/totp` (`target\release\totp.exe` on Windows). Install it on your `PATH` as above. Contributors working on the latest code should use the [contribution guide](../CONTRIBUTING.md).

A local macOS build requires no paid Apple certificate. Rebuilding, moving, or replacing the executable may require renewed Keychain authorization; read the [macOS guidance](platforms.md#macos).

## Upgrade

Read the target release notes and verify the new archive before replacing the executable. Credentials remain in the native store. Unsupported credential schema versions fail explicitly; compatibility across future versions must be checked in their release notes. The tool has no backup or migration command, and `import` registers OTPAuth credentials rather than restoring backups.

Retain your service recovery codes. On macOS, review Keychain authorization after an upgrade without granting access to all applications.
