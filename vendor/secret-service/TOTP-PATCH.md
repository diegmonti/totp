Source: secret-service 5.0.0, https://crates.io/crates/secret-service/5.0.0
License: MIT OR Apache-2.0 (included).

The upstream library implicitly runs Secret Service Prompt on item creation and
item deletion. This vendored copy changes precisely those two code paths to
return Error::Prompt instead. No Prompt method is invoked by totp. The encrypted
DH session, encryption/decryption, D-Bus protocol and all other implementation
remain upstream code. Re-evaluate this patch when upgrading the library.

Vendoring includes the library source, manifest and licenses only. Manifest
references to the omitted upstream README and example target are removed.
