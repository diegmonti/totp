# Requirement traceability and evidence

The source specification is [REQUIREMENTS.md](../REQUIREMENTS.md). This map describes implementation/test responsibilities, not a claim that external platform acceptance has already passed. See actual test output and release evidence.

| Requirements | Implementation / validation |
|---|---|
| FR-001, FR-007, FR-009; AC-005, AC-009 | CLI concealed/explicit stdin registration, validation-before-write, duplicate/replacement tests |
| FR-002; SEC-003/004; AC-001 | Core RFC 6238 vectors for SHA1/256/512, digit widths, periods, epochs and time boundaries |
| FR-003/004; SR-001/003; AC-002/003 | Native storage modules and `tests/native_storage.rs`: three-entry sorted namespace enumeration, replacement and deletion |
| FR-005; DM-001–005; AC-007 | OTPAuth parser and strict versioned protected record validation, identifier mapping |
| FR-006/008; SR-007/008; AC-008/010/011 | CLI output/exit tests, no-prompt native calls, doctor and explicit capability errors |
| SR-004/005; AC-004 | Linux Secret Service session CI; documented headless/WSL conditions; absent/locked provider failure |
| SR-006; AC-006 | macOS no-UI native API, required Developer ID/notarization workflow; real signed upgrade and access-policy checks remain manual release evidence |
| SEC-001/002/005–009 | Redacted errors, no secret-bearing arguments/files, bounded input, zeroizing sensitive buffers; security model in SECURITY.md |
| NFR-001/002/005; AC-012 | Five native CI targets, native integration, platform separation and five standalone release archives |
| NFR-003/004/006 | Performance targets depend on OS latency; read/validation behavior tests and stable versioned schema; no universal latency guarantee |
| NFR-007 | README, platforms.md, SECURITY.md, releasing.md; Bash, Zsh and PowerShell examples |
| AC-013; Definition of Done | Passing automated matrix plus documented real-platform authorization/upgrade checks and actual published signed artifacts required |

No backup, export, cross-platform migration, cloud synchronization, GUI, HOTP, or dedicated headless store is implemented by the v1 scope. Actual Windows/macOS behavior and signed upgrade continuity require those platforms; Linux-only local success cannot substitute for them.
