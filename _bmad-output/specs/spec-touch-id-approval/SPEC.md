---
id: SPEC-touch-id-approval
status: approved
approved: 2026-10-16
date: 2026-10-16
baseline: 1f97bcfb623f81e95ec104a6c3a12cf3338eec7c
companions:
  - technical-contract.md
  - acceptance.md
  - ../../../docs/companion-protocol.md
sources: []
---

# Touch ID approval

This SPEC and its companions form the scope approved on 2026-10-16. The
existing protocol document describes v1; this contract adds an opt-in biometric
approval path without changing v1 password approval or password-based unlock.
Begin with the native feasibility gate; provider authorization changes require
that gate to pass. Host enrollment, fingerprint-set changes and deployment
still require coordinated operator approval.

## Why

One human operator wants to approve agent requests using a Magic Keyboard with
working Touch ID on a Mac mini M1 (2020), without repeatedly entering the vault
password or keeping an approval terminal open. The existing Mac companion can
present requests; the Linux provider must retain execution and secret custody.

## Capabilities

- **CAP-1**
  - **intent:** The operator can enable fingerprint approval for a trusted Mac without sharing vault credentials.
  - **success:** Explicit enrollment binds a separate approval public key to that companion; transport enrollment alone cannot approve biometrically, and unknown/replaced/revoked keys are rejected.
- **CAP-2**
  - **intent:** The operator can approve exactly the reviewed operation with a fresh fingerprint authorization.
  - **success:** Two successive requests each require a separate touch on the real M1; each permits at most one dispatch, and the agent receives only existing redacted results. Cancellation and stale, altered or replayed proofs cannot approve.
- **CAP-3**
  - **intent:** The operator can deny a request or deliberately choose password approval when fingerprint approval is unavailable.
  - **success:** Denial needs no password or biometric check; explicit password approval uses a fresh review and freshly entered provider password. Cancellation, OS authentication fallback and an already-unlocked Mac never silently approve.
- **CAP-4**
  - **intent:** The operator can revoke and recover fingerprint approval after key loss, fingerprint changes or device replacement.
  - **success:** Revocation invalidates outstanding biometric authority; recovery requires a new key and trusted enrollment. Provider restart/lock/expiry invalidates old work, and password-only clients continue working.
- **CAP-5**
  - **intent:** The operator can distinguish confirmed execution from uncertain delivery and verify the fingerprint feature on real hardware.
  - **success:** Lost responses trigger status queries, never decision replay; redacted history distinguishes the approval method. Native M1 acceptance and automated security tests meet every gate in acceptance.md.

## Constraints

- Keep Linux execution, existing containment/policy checks, private LAN/VPN mTLS and distinct restricted OS identities for agents. Same-user agents on the trusted human account are not a supported isolation boundary.
- Require key-use-enforced biometrics, a separate device-bound approval key, one fresh authentication per approval and a short-lived single-use challenge bound to the full request. No software-key fallback or client-supplied authenticated boolean.
- Linux trusts the explicitly enrolled key and human-controlled Mac; a signature alone is not remote proof of Secure Enclave origin or a particular fingerprint. See technical-contract.md for this trust boundary.
- Preserve password-based vault unlocking and explicit password approval. Never retain/replay a vault password to simulate biometric approval; biometric requests carry no vault password.
- Preserve existing deadlines, bounded inputs, enrollment checks, rate limits, final serialized approval validation and no-replay handling. Biometric prompts cannot extend authority lifetimes.
- No secrets, biometrics, signing material, challenges or signatures in diagnostics/history. Public-key/fingerprint display is restricted to intentional enrollment metadata.
- Native hardware/signing-profile verification is a release gate, not a mocked-test substitute. Tests, targeted mutations and restoration must finish before implementation review; security requirements cannot be weakened to make a test pass.

## Non-goals

- Biometric vault unlock, password caching, unattended/bulk/time-window approvals.
- A macOS provider, Linux keyboard fingerprint support, Windows/iOS clients, browser WebAuthn/passkeys or biometric enrollment management.
- Remote hardware attestation/MDM, public-internet deployment, tunnelling or notarized public distribution.
- Unrelated execution changes, repository branding or backlog cleanup.

## Success signal

With the Linux vault unlocked normally, a restricted agent submits two synthetic
operations. The operator reviews and approves each with a separate touch on the
M1; each runs once and returns only permitted output. Cancellation, replay and
revocation prevent execution, explicit password approval still works, and no
approval terminal is required. Demonstration and cleanup evidence are retained
without credentials.

## Approved design decisions

- One active approval key per companion/provider binding; enrollment, replacement and revocation use trusted local administration while the provider is stopped.
- The existing private-network companion setup and human-controlled Mac are trusted; any fingerprint enrolled in that macOS account may satisfy Touch ID.
- Use the bounded implementation approach in technical-contract.md, subject to the native feasibility gate rather than assuming current ad-hoc signing will work unchanged.

## Open questions

- Which macOS version/build and installed companion build will be used for coordinated native acceptance? If the current signing profile cannot enforce the required key access across relaunch/update, a signing/provisioning decision is required before proceeding.
