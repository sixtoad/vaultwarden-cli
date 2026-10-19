# Companion synthetic slice

Separate Flutter UI and Rust core with a macOS Secure Enclave test-key adapter.
Windows and Linux run the shared shell and report biometrics unavailable.
No provider, vault, password, enrollment or execution access is implemented.

See [migration contract and evidence](../docs/companion-migration.md).
Run `bash ../scripts/test-desktop-companion.sh` on a matching desktop host.
Flutter 3.47.7, flutter_rust_bridge 2.13.0 and Rust 1.88 or newer are required.
Bindings are checked in; regeneration instructions are in the migration document.
