# Contributing

Report reproducible bugs and propose changes through [GitHub issues](https://github.com/diegmonti/totp/issues). Include your OS, architecture, `totp version`, command, exit status, and sanitized error output. Use disposable examples; never include real seeds, generated codes, credential payloads, or secret-bearing OTPAuth URIs. For suspected vulnerabilities, follow [SECURITY.md](SECURITY.md).

## Development

Install stable Rust and the native build tools for your OS, then run:

```sh
cargo build --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
```

The normal test suite covers TOTP vectors, input validation, and CLI behavior without requiring native credentials. Native integration tests are ignored by default. To opt in, set `TOTP_NATIVE_TESTS=1` and run:

```sh
cargo test --locked --test native_storage -- --ignored --test-threads=1
```

Use disposable credentials and an isolated test store. Follow the [CI workflow](.github/workflows/ci.yml) for an isolated Linux session or temporary macOS keychain; Windows CI uses the runner's user store. Do not run the locked-store test against your normal keyring: `TOTP_LOCKED_TESTS=1` explicitly enables a test that locks the collection. Platform setup and limits are described in [platforms.md](docs/platforms.md).

CI runs tests and native integration on Windows x64, Linux x64/ARM64, and macOS Intel/Apple Silicon. Cross-compiling is useful but does not replace execution on those platforms. See [release maintenance](docs/releasing.md) for release checks and manual platform acceptance procedures.

## Changes and review

Keep pull requests focused. Explain the behavior changed and how you verified it; update user documentation when commands or setup change. Preserve stable output, exit codes, credential identifiers, and record compatibility. Add tests for meaningful behavior changes and do not weaken storage authorization to make tests pass.

Dependency changes must include `Cargo.lock`. Run `cargo deny --locked check advisories bans licenses sources` with the cargo-deny version used in CI. Review new advisories and licenses rather than adding blanket exceptions.

Linux uses a vendored Secret Service adapter with a small [no-prompt patch](vendor/secret-service/TOTP-PATCH.md). Adapter upgrades must preserve that behavior. See [release maintenance](docs/releasing.md) for dependency exceptions, signing, and publication.

The [requirements](docs/development/requirements.md) and [traceability map](docs/development/traceability.md) describe intended scope and implementation coverage. Historical implementation records are archived separately from current contributor instructions.
