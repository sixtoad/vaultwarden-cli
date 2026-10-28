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


## Quiet Instrument shell (issue #50, first slice)

The app opens Requests. Desktop widths use a sidebar and request master/detail;
compact windows use four bottom destinations and list-to-review navigation.
Back, Cancel review and destination changes retire the Rust review and clear
passwords before navigation. They do not cancel the remote request. Pending
settlement/recovery remains visible on every destination and queries only the
original request ID.

Devices & agents shows the configured provider, leaf pin and local client
certificate fingerprint. Activity shows only the latest validated request status,
not remote history. Reopening explicitly requests fresh review. Settings contains
System/Light/Dark appearance, capability limits, advanced certificate import and
the separate synthetic signer. Disposable pilot setup remains build-gated there.
Appearance is local to the open application session; it is not saved.

The complete Rust-escaped review now appears as typed, labeled fields, including
indexed arguments, credential labels/use types, digests, exact Unix deadline,
closed status and one-time scope. Strings retain Rust's quoting and escaping;
the UI neither decodes wire data nor derives approval authority from these facts.
Originating device identity is explicitly unavailable in protocol v1; requester
text is not a device identity. Approve requires a fresh password; deny carries
none. Approved/running is not completed. Android/iOS native approval integration,
mutual enrollment, remote device management/history, notifications and bundled CLI
repair remain open dependencies; the shell does not claim them implemented.

Golden fixtures use only synthetic requests and test-only licensed Roboto (also
substituted for any monospace text in goldens). Production uses platform
system typography. Update deliberate visual changes
with `flutter test --update-goldens test/access_golden_test.dart`, inspect each
PNG under `test/goldens/`, then run `flutter test` without updating. The matrix
covers desktop/compact light/dark plus compact 200% text scale. Controller
navigation mutations run with `python3 ../scripts/mutate-provider-controller.py
<external-evidence-dir>`; never run that while editing or building companion code.

See [capability and evidence checklist](../docs/implementation/issue-50-capabilities.md)
for the delivery boundary. Rollback is source/build reversion: this slice changes
no credentials, saved protocol state or installed application.

## Structured request review (issue #50, second slice)

The generated bridge exposes an optional display-only review from the same
validated Rust object as the retained `review_text` compatibility projection.
Both disappear on invalidation or expiry. Tickets remain private to Rust, and
the existing `canDecide`, password and original-ID recovery rules are unchanged.
Rust rejects reviews exceeding the provider's existing limits of 32 arguments
or 16 credentials before building either display projection or admitting a
decision. Accepted reviews show every entry in full. Invalid replacements retire
the preceding review; no authority is inferred from incomplete scope.

This slice does not expand the frozen v1 schema. The root provider's optional
`create` and `ssh` review extensions remain unsupported by this companion and
are rejected in full, as are other unknown fields. They are never silently
discarded to permit a partial-scope approval. New history, trust inventory and
authoritative originating-device metadata require separately specified APIs.
