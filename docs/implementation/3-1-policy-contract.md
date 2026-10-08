# Fixed SSH policy contract

Story 3.1 adds policy activation, request admission and human review. SSH execution remains unavailable until Story 3.2 implements confined key resolution, connection-time host verification, execution and cleanup. An approved SSH request dispatched in this version terminates with the existing redacted `execution_unavailable` failure; it never falls through to login execution.

## Synthetic example

The operator supplies a provider-owned image ID already registered under the existing verified-executable rules. The following UUID and fingerprint are synthetic fixtures, not a usable credential or host pin:

```json
{
  "id": "ssh-backup",
  "description": "Back up the fixed resource",
  "image_id": "backup-image",
  "targets": [],
  "arguments": [],
  "credentials": [],
  "ssh": {
    "credential": {
      "item_id": "11111111-1111-1111-1111-111111111111",
      "label": "Backup SSH",
      "use_type": "ssh"
    },
    "working_directory": "/var/empty",
    "destination": {
      "host": "backup.example.test",
      "port": 2222,
      "user": "backup",
      "resource_path": "/srv/archive",
      "host_fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    }
  }
}
```

The fixed executable defines the operation's action. The SSH contract permits neither a command string nor caller-selected arguments. The generic `targets`, `arguments` and login `credentials` arrays must be empty; mixed credential modes are rejected. An SSH request names the operation and revision with an empty values/arguments list. Additional selectors fail closed.

## Destination and trust

The structured destination binds host, port, user and resource path. The fingerprint is scoped to that exact host and port in the same authority object, and every field is included in the revision. No ambient host configuration, caller trust override, trust-on-first-use or disabled verification is authorized by this contract.

Hosts accept ASCII DNS names or IP literals; DNS case/root-dot spelling and IP presentation normalize. Ambiguous legacy numeric forms, URL/SCP syntax, bracketed/scoped IP input, whitespace and wildcards are rejected. Ports are explicit integers from 1 through 65535. User names use a restricted ASCII grammar. Working and resource paths are absolute, bounded and restricted to letters, digits, slash, dot, underscore and hyphen; dot components, repeated separators and trailing separators other than root are rejected.

Host pins use SHA-256 with exactly 32 decoded bytes. Padded and unpadded standard base64 input normalize to the unpadded `SHA256:` spelling. This version supports fingerprint pinning only; a `known_hosts` field is not accepted.

## Credential and review boundary

The backend fetches only the selected immutable item ID and verifies actual Vaultwarden SSH-key type 5, undeleted status and a present SSH object with the required field shapes. Login/custom-field substitutes and the permissive legacy CLI type-6 alias are rejected. SSH eligibility has no custom marker convention and performs no private-key decryption. Unsupported backends deny it by default.

The policy stores the reference and host-trust configuration. Human review and redacted history show the fixed target, directory, pin, credential label and SSH use; they omit the item ID and key material. Agent responses retain the existing status-only boundary.

SSH revision hashing uses its own versioned projection. Changing credential identity/use, resolved executable identity, directory, host, port, user, resource or trust invalidates old authority. Existing login serialization and revision hashing are preserved. Labels and descriptions retain the existing display-only treatment.
