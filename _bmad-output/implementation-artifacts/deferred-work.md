# Deferred work

## Issue 50 verification prerequisite

Run the matching CI environment's native installation test and packaged native
TLS smoke before claiming the full host gate green. The existing `install-save`
mutation survives locally because its detecting test is explicitly CI-only;
local source restoration and the other native tests passed. Do not weaken the
trust test, forge CI, or alter a production identity namespace to obtain a green.

The parent issue's remaining enrollment, installation, history and native-client
requirements are tracked in [the capability checklist](../../docs/implementation/issue-50-capabilities.md).
