# Repository instructions

## Secret access and execution ownership

Before changing protected access, approval, lock/revocation, process lifecycle,
platform support or secret-delivery integration, read
[docs/secret-access-boundary.md](docs/secret-access-boundary.md).

- The CLI/provider authenticates, approves and delivers secrets. Consumer execution
  and sandbox management are outside this project’s responsibility. Secret approval
  does not delegate process-control authority to this CLI.
- Do not make lock, access removal, expiry or pending-request cancellation kill
  consumer programs, their descendants or their sandbox. Do not introduce a CLI
  “stop programs holding this secret” option as a workaround.
- Do not gate macOS secret delivery on proving all-descendant termination, or
  infer that a VM/restricted operation model is required solely for that reason.
- One approval is for one request. Never claim revocation or killing a program
  recalls a delivered password or erases copies. Multiple secrets do not change
  the execution owner's authority.
- Keep authentication, replay protection, private delivery and safe CLI-owned
  resource cleanup. A pipe alone does not authenticate a recipient. Do not remove
  security checks merely to eliminate process supervision.
- Legacy Linux supervision and historical containment specs/tests reflect an
  older contract. Preserve the migrated future-access-only behavior; label legacy
  upgrade limits honestly and test runtime changes. Historical expectations are
  not justification for restoring the rejected requirement.

Observed pitfall: issue 49 was incorrectly blocked on automatic termination of
approved programs. The operator explicitly rejected that responsibility on
2026-10-28. Changing this boundary requires an explicit new product decision.
