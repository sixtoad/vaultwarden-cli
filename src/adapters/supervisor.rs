//! Process containment boundary.
//!
//! Story 1.7 deliberately ships the production adapter closed.  The direct
//! `execveat` implementation is useful to controlled fixtures, but it is not
//! a substitute for the manager-owned lifetime, descendant cleanup and crash
//! recovery required before real credentials may be injected.

use crate::access::ports::{
    ChildEnvironment, ExecutionError, ExecutionOutcome, ProcessSupervisor, ProtectedExecution,
};

#[allow(dead_code)]
pub(crate) struct UnavailableProcessSupervisor;

impl<P: ProtectedExecution> ProcessSupervisor<P> for UnavailableProcessSupervisor {
    fn available(&self) -> bool {
        false
    }

    fn supervise(
        &self,
        _prepared: P::Prepared,
        _environment: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::Unavailable)
    }
}

/// Test-only bridge for synthetic ELF fixtures.  It is intentionally absent
/// from production builds: its same-UID fork/reap behaviour makes no
/// containment claim.
#[cfg(test)]
#[allow(dead_code)] // Kept for controlled fixture composition in Story 1.7 tests.
pub(crate) struct FixtureProcessSupervisor;

#[cfg(test)]
impl ProcessSupervisor<super::execution::LinuxExecutablePreparer> for FixtureProcessSupervisor {
    fn available(&self) -> bool {
        true
    }

    fn supervise(
        &self,
        prepared: <super::execution::LinuxExecutablePreparer as ProtectedExecution>::Prepared,
        environment: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        prepared.run_fixture(environment)
    }
}
