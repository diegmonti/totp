# v0.1.0 validation record

[v0.1.0](https://github.com/diegmonti/totp/releases/tag/v0.1.0) was published on 2026-10-22 from commit `93f1116981ec6ec9e3d07cfd87e8f6e8a1f534f7`.

The [successful release workflow](https://github.com/diegmonti/totp/actions/runs/39820699258) ran all five platform test jobs and the dependency audit, then built and published Windows x64 and Linux x64/ARM64 archives with `SHA256SUMS`. The Tokio patch in [PR #9](https://github.com/diegmonti/totp/pull/9) resolved the advisory that blocked the earlier release attempt; no vulnerability exception was added.

Post-publication verification downloaded all three archives and confirmed their SHA-256 values, expected contents (executable, README, license), and binary architectures. The Windows ZIP also passed its CRC check. The downloaded Linux x64 executable passed `version`, `doctor`, `add`, `list`, `get`, and `remove` checks using a disposable Secret Service keyring and public test seed. Windows and Linux ARM64 downloaded binaries were inspected but not executed during this post-publication check; those platforms were exercised in CI.

macOS Intel and Apple Silicon native CI passed. No macOS archives were published because signing credentials were not configured. CI temporary keychains do not establish production Developer ID trust, Gatekeeper behavior, or signed upgrade authorization continuity. Those require the [manual acceptance procedure](releasing.md#macos-upgrade-acceptance) before distributing signed upgrades. Unrelated-item exclusion on Windows and macOS also remains a manual platform acceptance task.

This record applies to v0.1.0 only. It does not claim completion of all future 1.0 design goals or validate later changes. Earlier development evidence is preserved in the [historical notes](archive/implementation-validation.md).
