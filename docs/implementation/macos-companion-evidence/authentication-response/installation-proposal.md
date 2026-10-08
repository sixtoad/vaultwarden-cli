# Development installation — authorized and performed

The prepared native bundle fixes explicit password-rejection reporting and includes
the local-network purpose description. Nine native XCTest cases and fifteen signed
bundle cases passed; removing HTTP 422 from the allowlist was killed by a runtime
assertion, and source restoration was verified. Linux regression verification is
complete and recorded in `../password-rejection-fix/`: all three feature suites,
checks, twelve runtime-killed mutations, and agent/browser/systemd regressions
passed. One initial agent failure passed an unchanged isolated rerun; its cause
is unconfirmed and its log retained. Live backend exclusions remain explicit.

Source bundle on the authorized Mac:
`/tmp/vw-companion-native.reIOJJ/auth-error-repro/corrected-final-evidence/bundle/Approval Companion.app`

Proposed destination:
`/Users/sixtocantolla/Applications/Approval Companion.app`

A read-only check found neither this destination nor `/Applications/Approval Companion.app`
present on 2026-10-07. Recheck before copying and refuse to overwrite an existing
app. Verify the copied signature and exact hashes before opening:

- Executable SHA256: `d750c8ff625c2da5ce380727abfd5aad8f4f5ee1f73682d4197f5813419c1273`
- Info.plist SHA256: `93b130095117bd9081e9d54583c4ef9c501119347d1a21bd0663878a79e01a4a`

The proposed action copies this development bundle to the user's Applications
folder, quits the task's previous temporary companion process, and opens the
installed bundle with the existing saved provider setup and Keychain identity.
It is ad-hoc signed and not notarized. Login registration and OS notification/local
network permissions remain explicit operator actions in the app/System Settings.
This enables the remaining logged-in notification and login-startup acceptance;
installation itself is not evidence that those checks pass.

The user's instruction “Do not commit, push, open a PR or deploy without my approval”
requires approval before this persistent installation. No installation, login
registration, logout or OS permission change has been performed by this proposal.

On 2026-10-07 the user answered **“do it”**, then **“resume”** after an interruption.
The exact verified bundle was installed and opened; see [installation result](installation-result.json).
Login registration and OS permissions remain operator actions. Earlier proposal
text above records the scope that was approved.
