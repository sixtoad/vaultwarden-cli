# Create and consume secrets

Storage creates personal Login items. It never updates, rotates, deletes, upserts,
or issues a token at another service. Vaultwarden **1.36.0** is the verified backend;
the protected provider remains pinned to that version. The protocol reference is
[Vaultwarden's cipher routes](https://github.com/dani-garcia/vaultwarden/blob/1.36.0/src/api/core/ciphers.rs).
Organization reads remain supported, including wrapped item keys; organization
writes are unsupported.

## Trusted terminal import

Log in and unlock as described in the README. Create the destination folder using
your ordinary vault client first. Obtain the account UUID from that vault account.
Folder labels and references must already be canonical: slash-separated lowercase
ASCII letters, digits and hyphens; each segment starts/ends with a letter or digit,
is at most 64 bytes, and the whole path is at most 256 bytes. There is no rewriting.
For `homelab/production/github/deploy-token`, folder `homelab/production` contains
an item named `github/deploy-token`. Duplicate folder labels or existing personal
items with that name in the resolved folder reject creation.

```sh
vaultwarden-cli create \
  --account 11111111-1111-1111-1111-111111111111 \
  --folder homelab/production \
  --reference homelab/production/github/deploy-token --prompt
```

`--prompt` reads one password with terminal echo disabled. For multiple values,
omit it and feed a bounded JSON document on stdin from a trusted local producer:

```sh
trusted-local-producer | vaultwarden-cli create \
  --account 11111111-1111-1111-1111-111111111111 \
  --folder homelab/production \
  --reference homelab/production/github/deploy-token
```

The JSON shape is below; values here are illustrative, never command arguments:

```json
{"password":"example","notes":"optional notes\n","fields":[{"name":"api-key","value":"example"}]}
```

At least a password or one custom field is required. Notes are optional. The input
limit is 64 KiB, with at most 32 custom fields. Field names use ASCII letters,
digits, `_`, `-`, or `.` and are at most 128 bytes. `vw-access` is reserved.
Unknown keys, duplicate keys/names and malformed input reject the entire import.
UTF-8 string values, including spaces and line breaks, are preserved verbatim.
Custom secrets are stored as hidden fields. All values and names are encrypted
locally with fresh IVs and a fresh wrapped item key.

Every invocation reviews CREATE, server/account, folder label/ID, reference and
field selectors, then requires a fresh `create <random challenge>` response on
the controlling terminal. An unlocked vault or an earlier approval does not bypass
this. No terminal or a denied challenge means no POST. There is no `--yes` switch.
Stdout contains only a JSON receipt with `attempt_id`, `item_id`, and `status`.
Only a fresh authenticated GET and exact private comparison can return `verified`.

## Exact selected reads

```sh
vaultwarden-cli read-field --id ITEM_UUID --field password
vaultwarden-cli read-field --id ITEM_UUID --field notes
vaultwarden-cli read-field --id ITEM_UUID --field custom:api-key
vaultwarden-cli read-field --id ITEM_UUID --field password --journal JOURNAL_PATH
```

These are trusted plaintext outputs: exact UTF-8 bytes, with no appended newline.
Explicit IDs never fall back to names. The optional journal enforces the original
server, account, unique folder ID/label, reference, item ID and selected field.
Use it for durable namespace binding. Moves, renames and scope changes fail closed.
Missing/deleted/wrong-ID responses, invalid authentication, invalid wrapped keys
and duplicate custom fields are rejected. Wrapped-key failure never falls back
to the parent key. Existing `get --format env` and `run` reject normalized name
collisions; `run` also refuses to overwrite an inherited environment variable.

## Protected producer policies

Follow [provider provisioning](access-mvp.md#human-operator-provisioning) to register
a reviewed self-contained executable. The human operator creates a policy with
`vw-access operation create --file create-policy.json`. Policy contains no secrets:

```json
{
  "id": "create-deploy-token",
  "description": "Create a personal deploy credential",
  "image_id": "reviewed-producer",
  "targets": [],
  "arguments": [],
  "credentials": [],
  "create": {
    "server": "https://vault.example",
    "destination": {
      "account_id": "11111111-1111-1111-1111-111111111111",
      "folder": "homelab/production",
      "folder_id": "22222222-2222-2222-2222-222222222222",
      "reference": "homelab/production/github/deploy-token"
    },
    "fields": ["password", "custom:api-key"],
    "eligibility_marker": "deploy"
  }
}
```

Provisioning and execution verify the account and uniquely resolved folder ID.
The schema must match producer output exactly. This version accepts a fixed
producer with empty arguments/targets/credentials and no SSH effect. Update effects
are not part of the closed policy schema. Normal signed agent submission and
fresh human approval are still required for every execution. Reviews on loopback
and native macOS show the create effect, namespace, schema and marker.

The producer receives **fd 3**, a provider-owned bounded memory file. Write a
four-byte unsigned little-endian JSON byte length at offset zero, followed by the
same JSON import format. The file has fixed capacity 65540 bytes and cannot grow
or shrink. The provider reads only after successful exit and confirmed reaping,
then seals writes and validates the frame/schema. Stdout/stderr remain discarded.
No API token, vault key, provider socket or read credential is given to the
producer. Never place values in arguments, logs or stdout/stderr. Producer failure,
timeout, cancellation, lock, malformed output or lost approval prevents mutation.
Existing supervisor containment and cleanup requirements apply.

The provider adds encrypted `vw-access=deploy` metadata as a text field. This
marker alone grants no access. After obtaining the immutable item ID from human
history, separately provision a read operation `deploy` using an explicit binding:

```json
{
  "item_id": "33333333-3333-3333-3333-333333333333",
  "label": "Deploy credential",
  "use_type": "login",
  "namespace": {
    "account_id": "11111111-1111-1111-1111-111111111111",
    "folder": "homelab/production",
    "folder_id": "22222222-2222-2222-2222-222222222222",
    "reference": "homelab/production/github/deploy-token"
  },
  "field_mappings": [
    {"field":"password","environment":"DEPLOY_TOKEN"},
    {"field":{"custom":{"name":"api-key"}},"environment":"DEPLOY_API_KEY"}
  ]
}
```

Put this object in that read operation's `credentials` array. `"notes"` is also a
supported selector. Read policies retain their own pinned executable, mappings,
marker and fresh approval. Agent replies and history contain no secret values.

## Recovery without another creation

Before POST, trusted imports fsync a metadata-only journal under the CLI config
directory's `write-attempts/create-<destination-hash>.json`. Protected operations
persist the same certainty in private provider state and human history. An existing
attempt blocks another create for that destination; there is no automatic retry.
Do not delete an uncertain receipt merely to try again.

These guards reserve a destination only within the same local journal or provider
state store. The trusted CLI, a separate provider store, and external vault clients
do not share an atomic vault-wide name reservation. Simultaneous, separately
authorized writes can pass their preflight checks and create duplicate names.
Resolve such collisions through trusted vault administration; always bind later
reads and recovery to exact immutable item IDs rather than selecting a name match.

| Status | Meaning |
| --- | --- |
| `failed` | A definite rejection was received; no verified item is claimed. |
| `uncertain` | A durable attempt exists; whether POST committed is unknown. |
| `created_unverified` | An ID is known, but comparison with original private values did not succeed. |
| `verified` | Fresh read matched all original values and bindings. |

Inspect a trusted receipt without mutation:

```sh
vaultwarden-cli reconcile --journal JOURNAL_PATH
```

After independently inspecting the vault, explicitly select the candidate item:

```sh
vaultwarden-cli reconcile --journal JOURNAL_PATH --id ITEM_UUID
vw-access reconcile-write REQUEST_ID ITEM_UUID
```

Both reconciliation paths perform reads only. They reject a different ID once
bound and validate account/folder/reference/fields (and the protected marker).
Recovered values cannot be compared to originals after restart, so recovery yields
`created_unverified`, never false `verified`. A previously verified receipt retains
that status. Reconciliation never authorizes execution, creates another item, or
provisions read access. If no candidate can be established, leave it uncertain and
investigate using the vault's trusted administration tools.
