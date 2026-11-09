# Native macOS provider: setup after installation

This is the post-install sequence for the native Apple Silicon provider, after
`scripts/macos-provider-install.py` (PR #70) has created the accounts, the empty
layout under `/Library/VaultwardenAccess` and the LaunchDaemon. It covers the
TLS identities, `backend.json`, the API client secret, the companion enrollment,
an agent account and key, a first operation and a first approved request.

> **Not hardware-verified.** Every command in this document was written against
> the source and the installer's layout. The `vw-access setup …` and
> `vaultwarden-accessd --store-bootstrap-secret` commands have source tests
> (temporary directories, never `/Library`). Nothing here was run on an installed
> provider: the distinct `_vwaccess` account, launchd start/stop, the companion
> import into the macOS Keychain and a real Vaultwarden unlock remain
> **UNQUALIFIED** until the owner runs them once. Report any step that fails.

Conventions used below (substitute your values from the reviewed plan):

| Placeholder | Meaning | Installer default |
| --- | --- | --- |
| `V` | installed version, e.g. `0.5.4` | from `plan.json` |
| `PROVIDER` / `PGROUP` | provider account / its primary group | `_vwaccess` / plan input |
| `HUMAN` | human socket group (operator is a member) | `_vwhuman` |
| `AGENT` / `AGENT_GID` | agent socket group / its GID | `_vwagent` |

```sh
BIN=/Library/VaultwardenAccess/versions/$V        # vaultwarden-accessd, vw-access
STATE=/Library/VaultwardenAccess/state             # provider-owned 0700
LABEL=system/com.cantolla.vaultwarden-accessd
PLIST=/Library/LaunchDaemons/com.cantolla.vaultwarden-accessd.plist
```

The LaunchDaemon runs `vaultwarden-accessd --state-root $STATE --backend-config
$STATE/backend.json --agent-socket-dir /Library/VaultwardenAccess/run/agent
--agent-socket-gid $AGENT_GID --companion-listen 127.0.0.1:8443
--companion-tls-cert $STATE/provider-cert.pem --companion-tls-key
$STATE/provider-key.pem --companion-client-ca $STATE/companion-ca.pem`.

## 0. Keep the service stopped until step 5

The provider refuses to serve the companion endpoint until at least one companion
certificate is enrolled, so a service started too early exits and launchd restarts
it every 30 s. Install with `--no-start`, or stop it:

```sh
# stop (the installer has no stop/start verbs; launchctl is the interface)
sudo launchctl bootout $LABEL
# start
sudo launchctl bootstrap system $PLIST
```

`AbandonProcessGroup` is set: stopping the provider never stops programs it
already launched.

## 1. Certificates (as the operator, in your own account)

```sh
umask 077
$BIN/vw-access setup tls --out-dir ~/vw-setup/tls \
  --server-ip 127.0.0.1 --client-name "Mac operator"
```

The PKCS#12 password is prompted twice without echo (or read as one line from
stdin when stdin is not a terminal); it is never an argument. The command runs
`/usr/bin/openssl` (LibreSSL on macOS; `--openssl /abs/path` to choose another)
and creates a new `0700` directory with every file `0600`:

| File | Goes to |
| --- | --- |
| `provider-cert.pem`, `provider-key.pem` | `$STATE/` (provider server identity; SAN `IP:127.0.0.1`, serverAuth) |
| `companion-ca.pem` | `$STATE/` (`--companion-client-ca`) |
| `companion-client.pem` | `$STATE/` temporarily, for enrollment (step 4) |
| `server-ca.der`, `server-leaf.sha256`, `companion-client.p12` | the companion app (step 6) |
| `server-ca.key`, `companion-ca.key`, `companion-client.key` | nowhere: move the CA keys offline, delete the client key after the import |

It prints `server_leaf_sha256=<64 hex>` (the exact leaf pin the companion asks
for) and `client_leaf_sha256=<64 hex>` (compare it with the fingerprint printed by
enrollment and shown by the companion). Two separate CAs are generated: the
server CA only signs the provider certificate, the client CA only signs companion
identities. Keys are RSA-3072, certificates SHA-256, the leaves valid 397 days
(`--days`, at most 825) and the CAs ten years. The PKCS#12 uses
PBE-SHA1-3DES with a SHA-1 MAC: the format the macOS Keychain import accepts on
every release, and the one the packaged-app TLS tests use. Renewing the provider
certificate changes the pin: re-enter it in the companion.

## 2. `backend.json` (as the operator)

From an existing `vaultwarden-cli login` of the same account (API-key login):

```sh
$BIN/vw-access setup backend-json --from-cli-login --out ~/vw-setup/backend.json
```

or explicitly (`--cli-config PATH` reads another `config.json`; explicit flags
override it):

```sh
$BIN/vw-access setup backend-json --out ~/vw-setup/backend.json \
  --server https://vault.example.com --email you@example.com \
  --client-id user.xxxxxxxx --encrypted-key '2.…|…|…' --kdf-iterations 600000
```

Only `server`, `email`, `client_id`, `encrypted_key`, `kdf_iterations` and, when
present, `encrypted_private_key`/`org_keys` (organization bindings) are written.
Tokens, keys and the client secret are never copied. The output is checked with
the provider's own setup reader before the command succeeds. `server` must be an
https origin without path; the KDF must be PBKDF2. Then install the files as the
provider account:

```sh
cd ~/vw-setup
for f in tls/provider-cert.pem tls/provider-key.pem tls/companion-ca.pem backend.json; do
  sudo install -o $PROVIDER -g $PGROUP -m 0600 "$f" "$STATE/$(basename "$f")"
done
```

## 3. API client secret (provider secret file store)

The provider account has no login session and no default Keychain (home
`/var/empty`), so the native macOS provider keeps its two secrets in files under
its state directory instead of the Keychain:

| Record | File |
| --- | --- |
| API client secret (`bootstrap-client-secret`) | `$STATE/secrets/vaultwarden-accessd.bootstrap-client-secret` |
| revocable session (`revocable-session`) | `$STATE/secrets/vaultwarden-accessd.revocable-session` |

`secrets/` is created `0700`, each record is a single-link `0600` regular file
owned by the provider, opened without following links, replaced atomically and
synced. Anything else (wrong owner, mode, a link, an ACL grant) is refused and the
provider fails closed. Root can read these files, as it could read the TLS key
next to them or a System keychain. Provision the secret by prompt (no echo; or one
line on stdin), never as an argument:

```sh
cd / && sudo -u $PROVIDER $BIN/vaultwarden-accessd --state-root $STATE --store-bootstrap-secret
```

Linux keeps the Secret Service keyring; the direct `vaultwarden-cli` keeps the
login Keychain. The session record is cleared at every start, lock and expiry.

## 4. Enroll the companion certificate (service stopped)

Enrollment reads the client certificate as the provider, so it must be a
provider-owned `0600` file:

```sh
sudo install -o $PROVIDER -g $PGROUP -m 0600 ~/vw-setup/tls/companion-client.pem $STATE/companion-client.pem
cd / && sudo -u $PROVIDER $BIN/vaultwarden-accessd --state-root $STATE \
  --companion-enroll-cert $STATE/companion-client.pem \
  --companion-client-ca $STATE/companion-ca.pem --companion-label "Mac operator"
# prints the enrolled fingerprint: it must equal client_leaf_sha256 from step 1
sudo -u $PROVIDER $BIN/vaultwarden-accessd --state-root $STATE --companion-grant-admin <fingerprint>  # optional: device management
sudo -u $PROVIDER $BIN/vaultwarden-accessd --state-root $STATE --companion-list
sudo rm $STATE/companion-client.pem
```

## 5. Start the provider

```sh
sudo launchctl bootstrap system $PLIST     # or re-run the installer's `install` without --no-start
sudo launchctl print $LABEL | grep -E 'state|pid|last exit'
sudo /usr/bin/python3 scripts/macos-provider-install.py status
```

It starts **locked**. A `last exit code` other than 0 with a growing run count is
a crash loop: stop it and check steps 2–4 (all four state files `0600` owned by
the provider, a companion enrolled, the secret store safe).

## 6. Companion app

In the Flutter companion, *Advanced development provider setup*:

1. **HTTPS provider endpoint**: `https://127.0.0.1:8443`
2. **Trusted server leaf SHA-256**: the 64 hex characters of `server-leaf.sha256`
3. **PKCS#12 import passphrase**: the password from step 1
4. **Select CA and import dedicated identity**: choose `server-ca.der`, then
   `companion-client.p12`. Compare the shown client fingerprint with
   `client_leaf_sha256`.

Then remove `companion-client.p12`, `companion-client.key` and the transfer
copies, and move `server-ca.key`/`companion-ca.key` offline. Unlock with the
master password in the companion (**Configure and unlock**).

## 7. Operator commands (`vw-access` defaults)

The operator must be a member of `$HUMAN` (the installer adds it; log out and in
once). On macOS `vw-access` now defaults `--state-root` to the human endpoint
directory named by the root-owned `/Library/VaultwardenAccess/native-identities.json`
(`/Library/VaultwardenAccess/run/human`), so no flag or environment variable is
needed; `--state-root`/`VAULTWARDEN_ACCESS_STATE_ROOT` still override it.

```sh
$BIN/vw-access history --limit 5     # works while locked
```

## 8. Agent account, key and pairing

An agent is a separate, non-admin account whose **primary** group is `$AGENT`
(the native agent socket authenticates the effective GID). Example with UID 520
(pick a free UID; `dscl . -list /Users UniqueID`):

```sh
sudo dscl . -create /Users/vwagent1
sudo dscl . -create /Users/vwagent1 UniqueID 520
sudo dscl . -create /Users/vwagent1 PrimaryGroupID $AGENT_GID
sudo dscl . -create /Users/vwagent1 UserShell /bin/zsh
sudo dscl . -create /Users/vwagent1 NFSHomeDirectory /Users/vwagent1
sudo dscl . -create /Users/vwagent1 IsHidden 1
sudo createhomedir -c -u vwagent1
```

Generate the key as the agent (the raw 32-byte seed, `0600`, never replaced) and
pair its public key as the operator:

```sh
sudo -u vwagent1 -i $BIN/vw-access setup agent-key --out /Users/vwagent1/.vw-agent.key
# prints the base64url public key
$BIN/vw-access agent pair builder --public-key <public-key> --uid 520 --gid $AGENT_GID
# prints the binding id
```

## 9. Image and operation policy (`reviewed_native_macho_arm64_v1`)

The native profile accepts only a root-owned, single-link, non-writable arm64
Mach-O with strict Apple/Developer-ID signature, hardened runtime and only
shared-cache dependencies (see
[the native provider notes](implementation/issue-49-native-provider.md)). The
source tests use `/usr/bin/ssh`. `/usr/bin/true` is rejected (no hardened
runtime). Every state read revalidates registered images, so an image that
changes or disappears (for example `/usr/bin/ssh` after a macOS update) makes the
provider store unavailable; plan to re-provision after OS updates.

```sh
SHA=$(shasum -a 256 /usr/bin/ssh | cut -d' ' -f1)
$BIN/vw-access image register --id system-ssh --execution-root /usr/bin \
  --path /usr/bin/ssh --sha256 "$SHA" --profile reviewed_native_macho_arm64_v1
```

An SSH-key operation (replace the synthetic item ID, destination and host
fingerprint; `ssh-keyscan -t ed25519 host | ssh-keygen -lf -` gives the
fingerprint), saved as `ssh-backup.json`:

```json
{
  "id": "ssh-backup",
  "description": "Back up the fixed resource",
  "image_id": "system-ssh",
  "targets": [], "arguments": [], "credentials": [],
  "ssh": {
    "credential": {"item_id": "22222222-2222-2222-2222-222222222222", "label": "Backup SSH key", "use_type": "ssh"},
    "working_directory": "/var/empty",
    "destination": {"host": "backup.example.test", "port": 22, "user": "backup",
      "resource_path": "/srv/archive",
      "host_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}
  }
}
```

```sh
REVISION=$($BIN/vw-access operation create --file ssh-backup.json | /usr/bin/python3 -c 'import json,sys; print(json.load(sys.stdin)["operation"]["revision"])')
$BIN/vw-access operation show ssh-backup
```

Login-field operations (environment variables) follow
[the policy examples](access-mvp.md#human-operator-provisioning); they need an
image of your own that meets the profile (Developer-ID signed, hardened runtime).
Creation is create-only: an ID can never be replaced, so review before creating.

## 10. First protected request and approval

As the operator (direct human request):

```sh
$BIN/vw-access request ssh-backup --revision "$REVISION"
```

As the agent (signed, noninteractive):

```sh
sudo -u vwagent1 $BIN/vw-access submit ssh-backup \
  --socket /Library/VaultwardenAccess/run/agent/agent.sock \
  --key-file /Users/vwagent1/.vw-agent.key --binding-id <binding-id> \
  --revision "$REVISION" --wait
```

Approve it in the companion (password, or Touch ID once enrolled). The request
reaches a terminal state; `vw-access status <id>` and `vw-access history` show it.

## 11. Verification

```sh
sudo /usr/bin/python3 scripts/macos-provider-install.py status
sudo launchctl print $LABEL | grep -E 'state|pid|last exit'
sudo ls -le $STATE $STATE/secrets        # provider-owned, 0700 dirs / 0600 files, no ACL
$BIN/vw-access history --limit 10
$BIN/vw-access agent list
$BIN/vw-access operation list
```

## Developer gates on a macOS workstation

The native code checks the ownership, mode and ACLs of every ancestor of the
directories it uses, so the gates only pass with private temporary directories.
On a Mac whose `TMPDIR` or checkout lives on a group-writable volume (for example
an external disk mounted `drwxrwxr-x`), or under a symlink such as `/var`, root
`cargo test` reports ~52 `UnsafeState`/`UnsafePath` failures that are not bugs.
Use the qualification script, which copies the tree into `$HOME`, sets `umask
077` and a private `TMPDIR`:

```sh
bash scripts/test-native-protected-macos.sh /absolute/evidence-dir-outside-the-repo
```

For a direct root run, use the canonical per-user temporary directory, `umask
077`, and a checkout whose ancestry is not group-writable (otherwise only
`native_signing_seed_relative_path_rejects_acl_grants_and_symlink_parent`, which
uses the current directory, still fails):

```sh
umask 077
export TMPDIR="$(cd "$(getconf DARWIN_USER_TEMP_DIR)" && pwd -P)/vw-tests"
mkdir -p -m 700 "$TMPDIR"
cargo test -- --test-threads=4
```

CI's Clippy gate is `cargo clippy --all-targets -- -D warnings`. The `justfile`
`check`/`pre-commit` recipes add `-W clippy::pedantic -W clippy::nursery`; that
stricter run fails on `main` with ~480 pre-existing findings (clippy 1.99 and
1.88 alike) and is not a CI gate.
