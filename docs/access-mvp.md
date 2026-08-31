# Human-approved agent access MVP

This fork adds a separate access path for an AI agent. It is not a safer alias
for `get`, `run`, or `interpolate`: those existing commands can intentionally
place secret values in the caller's stdout, environment, or files and therefore
remain human-only commands.

## Security boundary

`vw-access` is the untrusted client used by an agent. `vaultwarden-accessd` is
the human user's provider process. The provider owns the Vaultwarden login,
unlocked keyring session, operation policy, browser/native approval prompt, and
child process that receives environment variables.

The agent may request a named operation plus restricted non-secret arguments.
It cannot select a Vault item or field, supply an environment variable name,
or supply a shell command. Policy maps an operation to its fixed command and
Vaultwarden item references. The provider injects the values only into that
fixed child process and returns redacted status and output.

Every approval binds the paired agent identity, operation-policy revision,
arguments, random request ID, and expiry. A policy change or argument change
requires a new approval. An approval is one operation only: no bearer token is
returned to the agent.

## MVP delivery order

1. Pair a client Ed25519 public key with a labelled agent identity. Every
   request is signed by that key; the daemon rejects unsigned requests, key
   substitution, or any mutation after the agent signed it.
2. Add a local Unix-socket request protocol with signed requests and polling.
3. Add the provider browser approval page. It will require the human user's
   platform authenticator (WebAuthn/passkey; biometrics where the OS supports
   it) before authorizing a request.
4. Execute one policy-defined operation through the provider and return only
   redacted output/exit status.

The initial browser prompt is deliberately not reachable from the network; it
is served on loopback and protected by a per-launch random local URL token.
The provider must refuse to start if its policy directory is writable by the
agent account or another untrusted principal.
