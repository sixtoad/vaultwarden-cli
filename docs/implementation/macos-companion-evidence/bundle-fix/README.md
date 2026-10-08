# Packaged private-CA fix verification

The real app exposed an ATS-only failure that command-line tests missed. Its old process logged `AnchorTrusted`, `ATS failed system trust`, `-9802` and `-1200`; [redacted markers](prior-ats-failure.json) are retained. A real `.app` strict-ATS control reproduces private-CA rejection before an API body is delivered.

After explicit user approval, the development bundle enables the app-wide ATS exception. The production transport is unchanged and continues to require HTTPS, TLS 1.2+, CA-only chain/hostname/validity evaluation, exact leaf pin, mutual TLS, no redirects and no decision retries. No system trust setting changed. See [policy rationale and approval history](ATS-policy-proposal.md).

- Nine Swift tests passed, zero failed/skipped.
- Thirteen real-bundle cases passed with the exact production plist: strict control, valid private CA, wrong CA/pin/hostname, expired certificate, foreign/revoked identity, HTTP rejection, TLS1.1 rejection, redirect, response limit and lost-reply single transmission. An independent successful TLS1.1 mutual handshake proves the legacy server was viable.
- Seven scoped mutants were caught by runtime assertions: pin, trust evaluation, hostname, HTTP admission, TLS minimum, decision retry and response bounds. No survivor or skip; exact source bytes restored and all thirteen bundled cases passed again.
- Thirteen final source/fixture/script hashes match the tested Mac snapshot. Release bundle lint and strict signature verification passed; the temporary actual app was reopened with saved preferences preserved.
- Temporary Keychain cleanup was verified for every bundle probe.
- After reopening, the user confirmed **“Connected Provider unlocked”**; the parent observed HTTP 200 from the actual app (PID 18791), with no Keychain prompt reported. This verifies the corrected GUI connection, not the remaining manual acceptance steps.

[Results](results.json), [source hashes](source-hashes.json), [full evidence archive](bundle-fix-evidence.tar.gz), [archive SHA256](bundle-fix-evidence.tar.gz.sha256). The archive includes original logs, mutation runner, test results and a per-file SHA256 manifest; every original byte was verified before compacting the working copies. The earlier native archive remains unchanged for history.

Interactive UI, notification, sleep/reconnect, login-startup and protected-execution results are tracked separately by the parent; they are not inferred from these automated checks.
