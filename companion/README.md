# Companion development application

Foreground Flutter UI and Rust lifecycle for existing Linux provider approvals.
macOS explicitly imports a dedicated development PKCS#12 and private CA, validates
the exact server leaf pin, and keeps the client identity in native Keychain code.
Windows and Linux report provider transport unavailable. The synthetic Secure
Enclave signing demonstration remains a separate, explicitly opened mode.
This application does not replace or adopt settings from the installed Swift app.

See [migration contract and evidence](../docs/companion-migration.md).
Run `bash ../scripts/test-desktop-companion.sh` on a matching desktop host.
Flutter 3.47.7, flutter_rust_bridge 2.13.0 and Rust 1.88 or newer are required.
Bindings are checked in; regeneration instructions are in the migration document.
