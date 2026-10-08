# Wrong-password response diagnosis

The user clarified that the secure field was editable. No focus defect was established and no activation/input changes were made.

The real app (PID 60645) received HTTP 403 at 2026-10-07 09:55:19.949 Dublin for task `7DC092AA-5BE0-4A71-87BB-387C65B80AE0`; at 09:55:19.950 CFNetwork completed that same task with error -1206 (`NSURLErrorClientCertificateRejected`). The native transport already permits HTTP 403 and its JSON decoder recognizes `authentication_failed`, but the network error prevents that decoding path. The UI conservatively fetched pending status and displayed uncertainty without retrying approval. The precise cause is being reproduced with a synthetic app-bundle fixture.

A diagnostic `osascript` System Events read unexpectedly triggered an Automation permission prompt for sshd-keygen-wrapper. The operator was instructed to choose Don't Allow. No AppleEvents/Accessibility authorization was required or intentionally changed. Cancelling the local SSH session left remote PIDs 83971 (osascript) and 83963 (its shell); both exact PIDs were subsequently terminated with SIGTERM and verified absent via `ps`. No further AppleEvents/Accessibility queries are used. This was a development diagnostic, not companion behavior.

## Correction and verification

A disposable signed app using production CompanionCore reproduced the HTTP 403 failure against the synthetic Python TLS server, independently of the Rust server’s connection shutdown. Returning HTTP 422 and explicitly allowing that status delivered `CompanionError.rejected(authentication_failed)`. Provider/protocol changes are owned by the shared-core lane; unauthorized device responses remain HTTP 403. The client continues to fail closed for transport errors and never retries approval.

The final native run passed all 9 XCTest cases and 15 real-bundle transport cases, including separate wrong-approval-password and wrong-unlock-password rejections with exactly one command each. Development release build, plist validation and strict ad-hoc signature verification passed. All 13 input hashes matched. Removing HTTP 422 from the native allowlist compiled but failed the explicit rejection assertion at runtime; the exact original source was restored and the full final run passed. New mutation: 1 killed, 0 survivors, 0 invalid mutants; no final baseline tests skipped. Previous seven transport/security mutation witnesses remain archived for unchanged guards.

The first intentionally failing 403 run also exposed a test cleanup assumption: `lsregister -u` can return 1 for an already absent strict-ATS probe. Cleanup now accepts only exit 0/1 with a successful registry read proving the task’s unique identifier and exact path absent. Unknown errors still fail cleanup. Temporary Keychain restoration/deletion and probe registration absence passed in the final run. Initial failures are retained in the archive.

The prepared bundle includes the local-network usage description for the configured Linux provider; the authorized ATS dictionary is unchanged. It is built in a disposable development directory and has not been opened, installed or registered for login by this lane. Parent coordinates replacement and further operator acceptance. No focus change, approval-rule change, OS permission change, commit, push or deployment was performed.

Evidence: [raw archive](evidence.tar.gz), [archive SHA256](evidence.tar.gz.sha256), [source hashes](source-hashes.json), [bundle hashes](bundle-verification.json), [15 case results](bundle-results.json), [mutation result](mutation-results.json), [actual app network witness](actual-app-response.log). Logged-in approval/denial, correct execution, notifications and login acceptance still require parent completion.
