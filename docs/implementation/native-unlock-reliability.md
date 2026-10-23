# Native unlock waiting bound

Execution date: 2026-10-22. Baseline source is
`5c1a30e78ff2dea54471edb1ab33711f0d0cb126`; the implementation worktree is
`vaultwarden-storage-acceptance`, branch `fix/native-unlock-reliability`.
Acceptance is complete: the controlled delayed unlock succeeds without replay,
40 native cases are verified across the full review run and focused correction
rerun, the release bundle build passed, and owned infrastructure and temporary
Mac credentials were removed.

## Demonstrated failure and scope

The native transport previously applied a five-second request and resource
timeout to every operation. Production authentication first revokes the existing
session, performs two backend metadata GETs, derives keys and loads the bootstrap
credential, then performs the token POST and saves the authenticated session.
Each backend HTTP operation permits ten seconds. The native five-second waiting
bound could therefore expire before successful authentication returned.

The controlled reproduction used the real Rust provider, real
disposable Vaultwarden, production native `CompanionCore`, and the unchanged
`StorageAcceptance.swift` driver. A private diagnostic proxy delayed one actual
successful token response by six seconds; it recorded only status and timings.

| Baseline observation | Measured result |
| --- | --- |
| Normal native unlock | Success in 1.1963 seconds |
| Unlock with delayed token response | Native failure after 5.0067 seconds |
| Backend token response | HTTP 200 after 6.0186 seconds |
| Transmissions and writes | Exactly one token POST; zero cipher POSTs |
| Explicit subsequent session read | Current state was unlocked |

Raw baseline evidence: [normal unlock](native-unlock-reliability-evidence/baseline-normal.json),
[delayed native unlock](native-unlock-reliability-evidence/baseline-delayed.json),
[token delay](native-unlock-reliability-evidence/baseline-delay.json),
[backend counters](native-unlock-reliability-evidence/baseline-proxy.json), and
[explicit session read](native-unlock-reliability-evidence/baseline-explicit-session.json).

With the updated client, the same real-provider chain began locked and returned
unlocked after **7.167297500 seconds**. Native attempted and completed counts were
exactly one session read and one unlock; the driver reported success and verified
temporary-keychain cleanup. The actual token response was HTTP 200 after
6.016395168 seconds, including the six-second delay. The cumulative token POST
counter increased from one to two: exactly one additional POST for the updated
attempt. Cipher POSTs, vault items and agent executions all remained zero.
See [updated native result](native-unlock-reliability-evidence/updated-delayed.json),
[updated token delay](native-unlock-reliability-evidence/updated-delay.json), and
[final inventory and counters](native-unlock-reliability-evidence/updated-final.json).

[Source and binary provenance](native-unlock-reliability-evidence/provenance.json)
records the baseline commit, source hashes, unchanged driver hash, provider
fixture and diagnostic proxy hashes, both native binary hashes, and the Mac
source archive hash.

The diagnostic proxy is retained as
[`tests/fixtures/unlock-delay-proxy.py`](../../tests/fixtures/unlock-delay-proxy.py).
Its only change from the executed `/tmp/vw-unlock-delay-proxy.py` is resolving
`tests/secret-storage-acceptance.py` relative to the retained file, rather than
using the original absolute worktree path. The historical proxy SHA-256 in
provenance remains
`dde93a64375295a87b27578172f372d4086555a02f6e1caed3dc17d548fd967a`;
the retained relative-path source is
`347998ef2b56757fb01bc601b3400545e03de5032819da2116e8d31f3b61105c`.

To reproduce within an already prepared disposable storage-acceptance root,
stop only its identity-checked owned ordinary proxy before substituting this
proxy at the same configured loopback port. From the repository root, invoke:

```bash
unlock_fixture_root=/absolute/path/to/owned/disposable/acceptance-root
umask 077
timeout 3600s python3 tests/fixtures/unlock-delay-proxy.py "$unlock_fixture_root"
```

In a second shell, before sending exactly one explicit native unlock from a
locked provider, arm the next token response with:

```bash
unlock_fixture_root=/absolute/path/to/owned/disposable/acceptance-root
umask 077
python3 - "$unlock_fixture_root" <<'PY'
from pathlib import Path
import sys
with (Path(sys.argv[1]) / 'delay-next-token').open('x') as flag:
    flag.write('6\n')
PY
```

The proxy preserves the fixture-root ownership checks, loopback-only upstream,
private CA verification, body bounds and existing upstream timeout. Its one-shot
flag accepts delays greater than zero and no more than eight seconds, then is
removed before sleeping. It records only response status and elapsed timings in
`unlock-delay-observed.json`; the existing proxy records method/path counts.
Preserve those observations before restarting the proxy because counters reset
on launch. Stop the owned diagnostic process before the fixture's normal
identity-checked cleanup removes its private material. This invocation is only
for the synthetic disposable fixture, never an installed provider or vault.

The controlled delay establishes a client/provider waiting mismatch. A later
session observation alone does not establish which attempt authenticated. The
earlier intermittent failures recorded in
[`secret-storage-acceptance.md`](secret-storage-acceptance.md) remain
inconclusive: their evidence cannot establish that they had this same cause.
That original evidence is preserved. An initial diagnostic wrapper failed with a
Python subclass monkeypatch error before reaching the backend; it is excluded
from the reproduction evidence.

Pre-existing polling/unlock interleaving remains a deferred, unverified medium
risk. Checking concurrent real-provider polling and an explicit user retry needs
a separate test; no automatic replay was observed or introduced, and production
`AppModel` behavior is unchanged.

## Change

The exact canonical v1 unlock command generated by `CompanionClient` receives a
60-second request and resource waiting bound. The policy re-encodes a bounded,
nonempty password into the known unlock schema and requires byte equality.
Duplicate keys, additional fields, wrong command/version/types, malformed JSON,
and other raw encodings retain the five-second default. Native command encoding
now sorts JSON object keys; field names, types, values and the
`CompanionTransport.send(Data)` interface are unchanged. External callers using
noncanonical raw unlock bodies retain the short default.

The finite unlock bound accommodates up to three sequential ten-second backend
operations plus KDF and keyring work. It changes client waiting only. Production
provider authorization, session expiry, request deadlines and approval rules are
unchanged. Reads and decisions keep the existing five-second bound.

Only a Foundation error with domain `NSURLErrorDomain` and code
`NSURLErrorTimedOut` becomes `CompanionError.timeout`. Its fixed message says
that the request may have completed. Other Foundation errors remain transport
failures, and existing trust/HTTP/response-limit failures retain precedence.
No raw error description, `userInfo`, body, credential or token is logged. No
unlock or decision retry, redirect or replay is introduced. Pinned CA, leaf and
hostname validation, mutual TLS, response limits and fresh review requirements
remain unchanged.

## Verification

The executable native regressions cover normal and six-second unlock success,
five-second read timeout, a committed unlock with its reply dropped, explicit
session observation, authentication rejection, and pin/CA/hostname/client
failures. Each real TLS scenario asserts the exact received command sequence.
The delayed/lost fixture stores only command names and synthetic session state.
Every native fixture retains its temporary keychain and child-process cleanup
assertions.

Review added a total-resource-deadline regression: a valid 76-byte JSON response
streams one byte per second for 75 seconds, keeping the idle timeout refreshed.
The native test requires `.timeout` after 58–65 seconds and exactly one unlock.
The TLS-suite watchdog is 180 seconds; the production deadline remains 60.
The read-timeout regression now constructs its client before timing, uses an
eight-second delayed response and requires timeout before seven seconds. Trust
failures require the exact transport category; a revoked client must return a
typed transport failure or the explicit `unauthorized` rejection.

Protocol tests verify the exact 60/5-second policy without waiting 60 seconds,
including invalid raw bodies and password byte limits. They also verify safe
timeout classification and that a timed-out decision performs only a status
read while preserving uncertainty. The app-model regression verifies that an
unlock timeout clears the password, reports an unknown outcome, and sends no
second unlock when a subsequent explicit read observes unlocked.
That app-model test now first polls a locked session, matching the UI's starting
state, and verifies the unchanged unknown-outcome message after the timeout.

Local checks completed: `git diff --check`, Python fixture syntax compilation,
and `python3 macos/Tests/Fixtures/test_tls_fixture.py` (one test passed). The
loopback test initially encountered the sandbox's socket restriction and passed
when rerun with authorized local socket access.

On the authorized Mac, the initial focused suites passed 39 native cases:
18 protocol tests, nine app-model tests and 12 real TLS tests. The bundled TLS matrix passed all 20
checks with zero skipped. The Python fixture regression passed one test and the
watchdog regressions passed eight tests. The first native suite attempt omitted
the shared `tests/fixtures/companion/review.json` from the transferred snapshot,
causing 12 fixture-dependent protocol cases to fail. Supplying that unchanged
fixture and rerunning the full focused suites passed; no implementation change
was needed for this harness packaging failure.
`scripts/test-macos-companion.sh` completed with exit zero, including the release
bundle build. The [native test record](native-unlock-reliability-evidence/native-tests.json)
retains per-case results, platform/toolchain details, log hashes and the bundled
TLS check list. Sanitized full native logs are retained in
[`native-logs/`](native-unlock-reliability-evidence/native-logs/), including the
historical full review failure and successful focused trust-test rerun.

The [disclosure scan](native-unlock-reliability-evidence/disclosure-scan.json)
checked 17 sanitized JSON evidence files against nine known secret values and
found zero matches. This is a bounded check of the recorded evidence, not a
claim to detect every possible secret encoding.
The scan record lists its exact covered files and explains that later cleanup,
native-test and log artifacts were outside that initial credential-value scan.

The review verification run passed the new streaming-deadline test in 61.181
seconds including fixture setup, and all other cases except the tightened
revoked-client error assertion. The real server received exactly one unlock,
but Foundation returned `CompanionError.transport` rather than delivering the
fixture's HTTP 403 as `.rejected("unauthorized")`. Client authentication can
terminate before Foundation delivers that rejection. The regression now
requires a typed `CompanionError` and accepts only those two outcomes for the
revoked client; all other trust failures still require exactly `.transport`.
Nil and unrelated errors remain failures. The corrected trust test passed its
focused rerun with one test, zero failures and exit zero in 1.723 seconds.
Final coverage is 40 unique passing native cases: 18 protocol, nine app-model
and 13 TLS cases across the full review run and focused rerun. This does not
relabel the historical full run, which had 39 passes and one failed assertion,
as an all-passing invocation. The
[post-review test record](native-unlock-reliability-evidence/post-review-tests.json)
retains both results and their log hashes. Production code remains byte-identical
to the real-vault acceptance campaign and successful release build.

## Isolation and cleanup

The run used only synthetic services and temporary Mac keychains. No production
server code, installed app, configuration, trust store or deployment was modified.
Linux cleanup removed all owned services, the disposable container, private TLS
and bootstrap material, and agent material. Independent checks verified that
execution units and runtime state were absent; see the
[cleanup record](native-unlock-reliability-evidence/cleanup.json). Native driver
invocations verified their own temporary-keychain cleanup and original search
list restoration. Final checks found no test-keychain entries in the Mac
security list and no temporary fixture directories. The exact owned Mac
workspace was removed after evidence copying and independently verified absent.
The later owned review workspace was also removed, with no temporary test
keychains or fixture directories remaining, as recorded in the same cleanup
evidence.
