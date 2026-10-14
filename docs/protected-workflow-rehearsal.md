# Disposable protected workflow rehearsal

This opt-in Linux rehearsal uses the production daemon, helper, user manager,
trusted HTTPS UI and signed restricted-agent CLI. It creates a disposable
Vaultwarden container and synthetic Login items. It never uses an existing vault
or imports provider lifecycle, policy or pairing state.

Prerequisites are systemd 255 or newer with cgroup v2, an accessible local default
Docker engine, existing subordinate UID/GID mappings, `unshare`, `setpriv`,
`newuidmap`, `newgidmap`, a native C compiler, OpenSSL, D-Bus, GNOME Keyring,
`secret-tool`, `gdbus`, `xdg-open`, `journalctl`, Firefox, Xvfb, NSS `certutil`, xauth, Node and the locked dependencies
in `tests/ui/package-lock.json`. Install those JS dependencies with
`npm ci --ignore-scripts --prefix tests/ui`. Dependency installation is separate
from the runner; it never installs packages, accounts or host trust.

The production `vaultwarden-accessd.service` and its fixed supervisor runtime
must both be absent. Existing, failed, stopped or installed units are collisions.
The runner never stops or replaces them. The provider's home ancestry must meet
the production executable-verification ownership and permissions requirements.
Preflight also verifies that the actual restricted identity can traverse that
home. An inaccessible home is rejected before provisioning; the runner never
changes home permissions. Native checker tests run only on x86-64 and AArch64.

For dependencies outside the default system paths, set `VW_REHEARSAL_XVFB`,
`VW_REHEARSAL_CERTUTIL`, `VW_REHEARSAL_FIREFOX` and `VW_REHEARSAL_UI_DEPS` to
operator-supplied absolute paths. Historical temporary extraction paths in the
evidence are provenance, not reusable prerequisites.

```sh
scripts/rehearse-protected-workflow.sh --check
scripts/rehearse-protected-workflow.sh --automated
scripts/rehearse-protected-workflow.sh --human-check
scripts/rehearse-protected-workflow.sh --human
scripts/rehearse-protected-workflow.sh --collision-check
scripts/rehearse-protected-workflow.sh --interrupt
scripts/rehearse-protected-workflow.sh --cleanup-failure
```

`--check` performs non-provisioning checks, including native checker semantics,
the real user manager and a capability-dropped subordinate identity. The full
run additionally proves real `xdg-open` delivery to its private Firefox before
provisioning the synthetic vault. Missing prerequisites are errors, not passing
skips. Optional absolute dependency paths are `VW_REHEARSAL_XVFB`,
`VW_REHEARSAL_CERTUTIL`, `VW_REHEARSAL_FIREFOX` and `VW_REHEARSAL_UI_DEPS`.

The private D-Bus has no automatic service activation. This avoids inadvertently
starting desktop portals or mounting a document portal. Firefox uses a fresh
profile, private Xauthority and Xvfb display in automated mode; its CA is imported only into that
profile. The daemon trusts the same private CA through process-scoped
`SSL_CERT_FILE`. TLS verification remains enabled. Neither the host's browser
profile nor its keyring or trust store is used.

The restricted agent runs under an existing subordinate host UID after dropping
all capability sets and enabling `no_new_privs`. Kernel socket peer credentials
and actual Ed25519 signatures establish its identity. Public `vw-access image
register`, `operation create` and `agent pair` commands perform provisioning.
The approval password travels to the browser through a private pipe and is
entered only through the real UI. The reviewed native checker has one syscall:
`exit`. It validates the fixed target and injected field and cannot read files,
use the network, launch helpers or emit credential output.

The automated sequence covers denial, wrong approval password, success, wrong
injected field, restricted private-artifact access and a repeated UI decision.
Its output describes automated UI evidence; it is not actual human approval.

The explicit failure modes remain synthetic and use the same production path.
`--collision-check` creates a harmless owned sleep service only when the fixed
provider name is absent, proves nested preflight refuses it without changing its
invocation, and removes it. `--interrupt` delivers SIGTERM to the installed
handler with a real signed request pending, then verifies cleanup. It does not
claim interruption in the middle of the immediate native check. `--cleanup-failure`
injects harness-only failures before provider stop and after stop but before
cgroup-empty confirmation, then after actual container removal. Each must retain
private material. Recovery reloads unit identities from the durable ledger and
checks the already-absent owned container without trying to inspect it, then completes cleanup;
no production accessor or manager replacement is used.

The operator approved a private Firefox window on the existing COSMIC Wayland
desktop. `--human-check` validates the owned display socket, launches a new private
profile and proves real `xdg-open` handoff, then cleans up before creating a vault
or provider. This is launch/handoff evidence only: it does not establish that an
operator saw the window or performed approval. Xvfb is not required for this mode.

`--human` uses the same display-only transport. It requires `XDG_SESSION_TYPE=wayland`,
`XDG_CURRENT_DESKTOP=COSMIC`, `XDG_RUNTIME_DIR=/run/user/<uid>` with mode 0700 and
an owned, non-symlink `WAYLAND_DISPLAY=wayland-<name>` socket beneath that runtime.
The Firefox child receives the absolute socket path while retaining its own
private XDG runtime, session bus/keyring, profile and CA. No operator browser
profile, desktop content, host keyring or trust store is inspected; no remote
viewer, extra account or desktop bridge is installed.

Start a genuine human run only when the operator is ready. The new Firefox guide
tab displays instructions and the synthetic-only password; the password is never
printed to the terminal. The guide first asks the operator to wait. Once the
request is open, a boolean transition observer is armed before the guide invites
the decision. It preserves a rapid rejected-while-pending → denied sequence
without recording entered values. Switch to the disposable provider/request
tabs to enter it manually. Unlock the provider only for the initial step. Request
tabs have no provider Unlock or Lock controls; their password form authenticates
only the one-time approval. Denial needs no password. The separate provider tab
retains lifecycle controls and warns that locking or unlocking again invalidates
pending work. The sequence is unlock, deny, wrong-password rejection followed by
deny, correct approval, then approval with a deliberately wrong injected field.
The observer never types a password or submits an approval/denial in human mode.
It verifies cleared fields, actual rejection while pending, terminal outcomes,
history and redaction. Human mode observes disabled terminal controls; it does
not emit an automated replay decision. The actual rejected HTTP replay remains
part of automated mode's separate evidence.

Provider and request tabs share one profile but have separate cookies and
tab-local proof keys. A one-use provider launch grants lifecycle authority for
that daemon's lifetime: Lock, repeated Unlock and vault expiry do not retire it.
Unlock always requires the password. Provider redacted history works while
locked. Request launches cannot grant or rotate provider authority; request
review, history and decisions retain their vault-generation checks. A reset
retires stale request access. Neither cookie alone recovers a proof. Reloading
an existing tab preserves its role and proof; closing the provider tab requires
a fresh secure launch or daemon restart. Restart invalidates both roles. Cookies
are browser-session cookies, not persistent credentials. The fifteen-minute
vault TTL is not an expiry time for provider browser authority.

Each manual wait has a five-minute limit (330-second browser-command ceiling,
335-second parent ceiling including setup/transport overhead). Existing production
request expiry is five minutes from submission and provider session expiry is
fifteen minutes, so either can end a slow run earlier; no bounds are extended.
Closing the owned browser, timeout or interrupt fails the run and invokes the
same ownership-verified cleanup. Expired or invalidated requests cannot be reused;
the UI disables decisions and explains how to obtain a fresh request after the
provider is ready. Generic browser-session retirement does not establish whether
the operation ran: check authoritative status before submitting again. The human
observer fails promptly on these terminal states. Do not retry a human rehearsal
automatically; coordinate operator readiness again.

Restricted-agent failures report only a fixed `submit` or `poll` action and a
recognized closed rejection category. Unknown categories, invalid protocol
frames and malformed JSON produce a generic invalid-response diagnostic;
response bodies, identifiers and parser errors are never diagnostic text. The
stdout secret-redaction gate still runs before parsing. Submission is attempted
once; these diagnostics do not add retries or change provider rejection behavior.

Browser failures report only a fixed allowlisted stage, such as `request-find`,
`request-details` or `human-decision`. The browser and parent independently
sanitize this field; exception messages, DOM content, URLs, passwords and request
bodies are not diagnostics. A stage identifies where observation failed, not its
root cause.

Historical evidence: on 2026-10-14 the earlier human rehearsal passed after the diagnostic update:
actual provider unlock, denial, wrong-password rejection followed by denial,
one successful approved execution, expected wrong-field execution failure,
redaction and independently checked cleanup. An earlier intermittent submission
rejection did not recur, but its original cause remains unconfirmed; this pass
does not establish a fix. Any further human run requires coordinated operator
readiness. Automated verification and diagnostic investigation are recorded
separately.
That run precedes the lifecycle-authority and transition-observer corrections;
it does not establish human acceptance of the corrected behavior.

All owned resources are recorded in a private `ownership.jsonl` under a unique
`.vw-protected-rehearsal-*` directory in the provider's home. Service invocation
IDs and cgroups are fsynced to the ledger immediately after each service starts,
before proceeding to dependent secret-bearing setup. The ledger is validated and
IDs and cgroups are checked before stopping units; the container label and ID
are checked before removal. Cleanup stops the provider and its contained work
before the browser, keyring and bus, then removes the owned container. Private
files are removed only after termination checks and a successful Docker absence
query pass. A disconnected engine cannot prove absence. Retrying cleanup after
confirmed removal accepts an already-absent owned ID without inspecting it.
Any uncertainty produces
a failure and retains the private directory for recovery; do not publish it.
Acceptance additionally checks a pre-cleanup ownership snapshot independently:
the private root, owned runtime, browser-controller process, services, cgroups
and container must actually be absent. Cleanup's own success flag is insufficient.
An ordinary interrupt requests cleanup. SIGKILL, power loss and manager failure
cannot guarantee automatic cleanup; inspect the ledger and exact owned resources
before removing retained material. Do not use broad service or directory globs.

Command stdin/stdout/stderr use nonblocking bounded pumps; child groups are
terminated and reaped within bounded cleanup time. Pipe-holder descendants cannot
extend a command timeout through a blocking write or reader-thread join. Unknown
escaped pipe holders or an unconfirmed reap fail cleanup and retain material.
Provider and supporting-service stdout/stderr flow through private bounded
captures, and browser-driver stderr is captured privately. Each capture is
limited to 4 MiB; overflow fails acceptance. Controller stdout is captured through
shutdown and confirmed EOF. Firefox (`dumpio:false`), Xvfb and desktop/helper
output intentionally discarded by the JavaScript controller is not captured or
audited. Cleanup scans captured streams and retained
CLI/browser observations against the synthetic credential corpus before deleting
private material, including wrong/login/keyring passwords, vault fields, keys,
launch credentials and the private X display cookie. Consumed/rotated
authority-shaped output also fails closed.
Raw captures never go to the journal or published evidence. A leak retains the
private directory. Automated replay supplies valid synthetic authentication and
must reject with unchanged execution/history counts.

The human observer proves a generic `Decision rejected` transition while pending
during the instructed wrong-password step, followed by denial. It does not prove
the precise backend rejection cause or capture entered values. Automated checks
separately exercise authentication rejection.

Focused non-provisioning tests run with:

```sh
cargo test --locked --test protected_rehearsal
npm run test:observer --prefix tests/ui
```

The production test, actual restricted-identity traversal regression, and
dependency-bearing desktop prerequisite probe are ignored in ordinary Cargo runs.
Execute the latter explicitly on x86-64/AArch64 with the rehearsal dependencies:

```sh
cargo test --locked --test protected_rehearsal missing_desktop_prerequisite_fails_before_provisioning -- --ignored --exact
```

Verification details and
unmet acceptance conditions are recorded in
`docs/implementation/protected-workflow-rehearsal-verification.md`.
