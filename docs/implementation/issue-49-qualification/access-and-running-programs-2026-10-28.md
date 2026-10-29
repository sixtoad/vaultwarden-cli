# Clarification: secret access and running programs

Accepted direction, clarified by the operator on 2026-10-28. The authoritative
contract is now [Secret access is not execution authority](../../secret-access-boundary.md).

The earlier proposal in this record separated access revocation from an optional
CLI “Stop running programs” action. The operator subsequently clarified that
consumer execution is outside this project’s scope. **That optional CLI stop
feature is withdrawn too.** Neither automatic nor optional consumer supervision
is a responsibility of this CLI under the accepted design.

The CLI authenticates and approves each request, prevents replay and delivers
only to its authorized recipient/channel. Cancelling a pending request, locking
the vault or removing an app's access affects future delivery, not the lifetime
of a program that already received a secret. One-time approval is not a reusable
permission; an already delivered password cannot be recalled.

The CLI must not signal consumers or turn an access-denied result into an
instruction to terminate them. No external execution-management integration is
required. Supported delivery channels must authenticate recipients; a pipe alone
does not establish permission to receive a value.

When one program receives several secrets, changing future access to one grants
no authority to stop work using the others. The execution owner decides whether
to terminate the agent/sandbox. Killing a process does not erase password copies,
undo remote actions or invalidate sessions already established.

The [historical containment no-go](containment-feasibility-2026-10-27.md) no longer
gates the Mac secret-access port. Authentication, recipient verification, private
delivery and safe CLI-owned resource lifetimes remain required. The previous
recommendations for a restricted in-process-only product or VM do not follow
from the accepted responsibility boundary.

At the time of this decision, Linux still coupled revocation to workload
termination. The subsequent [Linux runtime migration](../issue-49-future-access-only-linux.md)
implements the revised boundary. Historical probe evidence remains unchanged
and does not validate the revised contract; the migration has separate tests.
