# Story 3.2 SSH execution contract

SSH approval continues to bind the immutable type-5 Vaultwarden item, reviewed self-contained ELF digest, working directory, exact host, port, user and resource. Requests supply no SSH values or options. Policy revisions and approval authentication/ownership remain unchanged. Login execution keeps its existing environment mapping.

The executable remains an operator-reviewed self-contained ELF image, executed from the verified sealed descriptor. Ordinary dynamically linked Git/OpenSSH and shell scripts remain unsupported by that profile. For SSH operations the image must implement the fixed OpenSSH-style argument contract below and enforce its connection-time trust settings. A generic image which merely ignores these arguments is not an SSH implementation and must not be approved. This feature does not turn an arbitrary approved ELF into an SSH client.

## Operator provisioning

The daemon creates `ssh/` and `ssh/requests/` beneath its provider-private state root, owned by the provider with mode 0700. The state root must be outside agent workspaces and inaccessible to their distinct OS principals; every ancestor must be root/provider owned, non-writable by other principals and free of symbolic links. No state path or material location comes from an agent request.

Provision `ssh/host_keys.json`, a provider-owned regular 0600 single-link file. It contains an array of objects, each with exactly `host`, `port`, and `key`. Example shape (replace the public key with the real operator-approved key):

```json
[{"host":"backup.example.test","port":2222,"key":"ssh-ed25519 BASE64_SSH_WIRE_PUBLIC_KEY"}]
```

The destination host spelling must equal the policy's normalized host; port is an integer. Exactly one matching entry must exist. The SSH wire key type must match its declared type and its SHA256 fingerprint must exactly match the approved policy fingerprint. Missing keys, duplicate matches, wrong host/port, links, unsafe ownership/modes and fingerprint mismatch deny execution before resolving secrets. There is no network key acquisition, TOFU, automatic update, or policy migration.

## Private dispatch

The application first claims exact current approval and verifies the image. It rechecks authority before private filesystem setup, after setup, after backend compatibility checks, after key resolution, after writing material and at supervised release. The backend repeats immutable identity, actual type 5, deletion and SSH-body checks on the response used to resolve the selected private key. Organization and item encryption keys are supported; only the private-key field is decrypted. Sensitive values are zeroizing and redacted in Debug.

A randomly named 0700 request directory contains only `identity` and `known_hosts`: exclusive, no-follow, provider-owned 0600 regular single-link files. Key input is bounded and rejects empty/NUL values; interpretation of supported private-key encodings belongs to the reviewed SSH image. Unusable or passphrase-protected keys cannot prompt or use an agent and fail through the redacted child result. `known_hosts` contains exactly the operator-provisioned key, with standard host spelling for port 22 and `[host]:port` otherwise.

The prepared image receives fixed arguments beginning `-F /dev/null`, followed by provider-generated `-o` settings. These select the request identity and pinned known-hosts file, disable identity agents/certificates and ambient global trust, require strict host checking and public-key-only batch authentication, and disable key updates, DNS trust, proxy commands/jumps, forwarding, local commands, control sockets and terminal allocation. Arguments end `-p PORT -l USER -- HOST RESOURCE`; all values come from approved policy. The image must treat RESOURCE according to its reviewed fixed action and may not reinterpret caller commands. Output is discarded by existing helper containment; environment contains only `LANG=C` and `LC_ALL=C`. No key bytes, authentication/signing sockets or SSH environment overrides cross an agent interface.

A second close-on-exec descriptor carries the checked working directory through the authenticated private helper channel. The SSH transfer variant requires exactly the image and directory descriptors. The helper independently checks the directory descriptor and changes directory with `fchdir` before `execveat`. No untrusted working-directory path is reopened at launch.

## Cleanup and restart

There is no deleting Drop. After supervision, the application explicitly finalizes material only with independent `NotStarted` or `Reaped` evidence. Uncertain containment retains material, closes admission and leaves manager leases and filesystem residuals for recovery. Material cleanup failure does not overwrite proven containment evidence: the application records a redacted failed result when reap is proven and separately closes admission. Any residual directory blocks further SSH preparation, including in a new process.

Cleanup validates directory identity, the complete entry set, types, ownership, modes and link counts before deletion. It never recursively deletes unknown content, symbolic links, hard links or unrelated objects. Removal and parent directory changes are synced. Recovery runs under the existing provider writer lock: manager leases are recovered and every contained workload reaped first; only then are validated residual request directories removed. Unsafe residuals fail startup and require operator repair followed by another ordered recovery. The provider never cleans secrets merely because the main child exited.

## Verification scope

Focused module tests cover host provisioning and pins, ancestry, modes/links, descriptor transfer, explicit cleanup/restart, default denial, backend revalidation, application ordering and redacted terminal failure. Native real-manager scenarios exercise descendant access, fixed arguments and empty ambient environment, nonzero and signaled exits, cancellation, authority loss, provider death, uncertain reap and cleanup interlock/recovery. Failed startup recovery retains both files while descendants remain alive. The native child independently verifies that stdout and stderr resolve to `/dev/null`; a unit-filtered journal alone cannot prove output absence when records lack unit attribution. A separate ignored test creates material under the real provider principal then attempts reads from two subordinate mapped agent UIDs and checks a valid-mode foreign-owned descriptor. Isolated subprocess tests verify creation under permissive umask, while direct tests reject replacement inodes and repeated key installation. Synthetic sentinels only; no live credentials.

Final command results, mutations and any unavailable checks are recorded separately in `3-2-verification.md` and `3-2-evidence/`.
