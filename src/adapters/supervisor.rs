//! Manager-owned containment. No production direct-child or process-group fallback.
use super::execution::{LinuxExecutablePreparer, PreparedExecutable};
#[cfg(test)]
use crate::access::ports::{ExecutionOutcome, ProtectedExecution};
use crate::access::{
    application::ProviderApplication,
    ports::{
        ChildEnvironment, CleanupEvidence, ExecutionControl, ExecutionDispatcher, ExecutionError,
        ProcessSupervisor, SessionError, Supervision,
    },
};
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
pub(crate) mod bridge;
mod manager;
use bridge::{BridgeListener, Report};
use manager::{Config, Manager};

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum LaunchPhase {
    JobAccepted,
    HelperConnected,
    CredentialsTransferred,
    Release,
    NaturalExit,
}
#[cfg(test)]
type PhaseHook = std::cell::RefCell<Option<Box<dyn FnMut(LaunchPhase)>>>;
#[cfg(test)]
thread_local! { pub(super) static PHASE_HOOK: PhaseHook = std::cell::RefCell::new(None); }
#[cfg(test)]
fn phase(phase: LaunchPhase) {
    PHASE_HOOK.with(|hook| {
        if let Some(hook) = hook.borrow_mut().as_mut() {
            hook(phase);
        }
    });
}

pub struct SystemdProcessSupervisor {
    config: Config,
    healthy: AtomicBool,
    material_root: Option<std::path::PathBuf>,
}
impl SystemdProcessSupervisor {
    /// Fixed production provider identity; test namespaces are never configurable by clients.
    pub fn installed(state_root: &std::path::Path) -> Result<Self, ExecutionError> {
        let helper = std::env::current_exe()
            .map_err(|_error| ExecutionError::Unavailable)?
            .parent()
            .ok_or(ExecutionError::UnsafePath)?
            .join("vaultwarden-access-exec");
        let runtime = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
        let config = Config::new("vaultwarden-accessd.service".into(), helper, &runtime)?;
        let manager = Manager::connect()?;
        manager.provider(&config)?;
        Ok(Self {
            config,
            healthy: AtomicBool::new(true),
            material_root: Some(super::ssh_material::initialize(state_root)?),
        })
    }
    /// Isolated systemd namespace for the explicitly invoked companion acceptance test.
    #[cfg(test)]
    pub(crate) fn companion_fixture(
        provider: String,
        helper: std::path::PathBuf,
    ) -> Result<Self, ExecutionError> {
        let runtime = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
        let config = Config::new(provider, helper, &runtime)?;
        Manager::connect()?.provider(&config)?;
        Ok(Self {
            config,
            healthy: AtomicBool::new(true),
            material_root: None,
        })
    }
    /// Must run under the provider writer lock, before durable validation or admission.
    pub fn recover(&self) -> Result<(), ExecutionError> {
        let manager = Manager::connect()?;
        manager.recover(&self.config)?;
        if let Some(root) = &self.material_root {
            super::ssh_material::recover(root)?;
        }
        Ok(())
    }
    fn execute(
        &self,
        prepared: PreparedExecutable,
        environment: ChildEnvironment,
        control: &dyn ExecutionControl,
    ) -> Supervision {
        let not_started = |error| Supervision {
            outcome: Err(error),
            cleanup: CleanupEvidence::NotStarted,
            helper_reaped: false,
        };
        if !self.healthy.load(Ordering::Acquire) || !control.live() {
            return not_started(ExecutionError::Cancelled);
        }
        let manager = match Manager::connect() {
            Ok(m) => m,
            Err(e) => return not_started(e),
        };
        if let Err(e) = manager.provider(&self.config) {
            return not_started(e);
        }
        let name = match self.config.name() {
            Ok(n) => n,
            Err(e) => return not_started(e),
        };
        let lease = manager.lease(name);
        let listener = match BridgeListener::bind(&self.config.socket(&lease.name)) {
            Ok(l) => l,
            Err(_) => return not_started(ExecutionError::Unavailable),
        };
        if let Err(e) = self.config.record(&lease) {
            return not_started(e);
        }
        let mut observed_channel = None;
        let result = (|| {
            if !control.live() {
                return Err(ExecutionError::Cancelled);
            }
            manager.start(&self.config, &lease, control.remaining())?;
            #[cfg(test)]
            phase(LaunchPhase::JobAccepted);
            let identity = manager
                .owned(&self.config, &lease)?
                .ok_or(ExecutionError::ExecutionFailed)?;
            manager.helper(&self.config, &lease, &identity)?;
            let deadline = Instant::now() + Duration::from_secs(5);
            let channel = loop {
                if !control.live() {
                    return Err(ExecutionError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(ExecutionError::ExecutionFailed);
                }
                if let Some(channel) = listener
                    .accept(identity.pid, Duration::from_millis(20))
                    .map_err(|_error| ExecutionError::ExecutionFailed)?
                {
                    break channel;
                }
            };
            #[cfg(test)]
            phase(LaunchPhase::HelperConnected);
            observed_channel = Some(channel);
            let channel = observed_channel
                .as_mut()
                .ok_or(ExecutionError::ExecutionFailed)?;
            manager.helper(&self.config, &lease, &identity)?;
            if !control.live() {
                return Err(ExecutionError::Cancelled);
            }
            channel
                .send(&prepared, &environment)
                .map_err(|_error| ExecutionError::ExecutionFailed)?;
            #[cfg(test)]
            phase(LaunchPhase::CredentialsTransferred);
            // Drop the provider's cleartext and descriptor as soon as transfer completes.
            drop(environment);
            drop(prepared);
            loop {
                if !control.live() {
                    return Err(ExecutionError::Cancelled);
                }
                if Instant::now() >= deadline {
                    return Err(ExecutionError::ExecutionFailed);
                }
                match channel
                    .receive(Duration::from_millis(20))
                    .map_err(|_error| ExecutionError::ExecutionFailed)?
                {
                    Some(Report::Ready) => break,
                    None => {}
                    _ => return Err(ExecutionError::ExecutionFailed),
                }
            }
            manager.helper(&self.config, &lease, &identity)?;
            #[cfg(test)]
            phase(LaunchPhase::Release);
            control.release(&mut || {
                channel
                    .release()
                    .map_err(|_error| ExecutionError::ExecutionFailed)
            })?;
            let exec_deadline = Instant::now() + Duration::from_secs(5);
            let mut executed = false;
            loop {
                match channel
                    .receive(Duration::from_millis(20))
                    .map_err(|_error| ExecutionError::ExecutionFailed)?
                {
                    Some(Report::ExecConfirmed) if !executed => {
                        executed = true;
                        control.started()?;
                    }
                    Some(Report::Outcome(outcome)) if executed => {
                        #[cfg(test)]
                        phase(LaunchPhase::NaturalExit);
                        return if control.live() {
                            Ok(outcome)
                        } else {
                            Err(ExecutionError::Cancelled)
                        };
                    }
                    None => {}
                    _ => return Err(ExecutionError::ExecutionFailed),
                }
                if !control.live() {
                    return Err(ExecutionError::Cancelled);
                }
                if !executed && Instant::now() >= exec_deadline {
                    return Err(ExecutionError::ExecutionFailed);
                }
                manager.provider(&self.config)?;
            }
        })();
        if result == Err(ExecutionError::UnitCollision) {
            if self.config.forget(&lease).is_err() {
                self.healthy.store(false, Ordering::Release);
            }
            return not_started(ExecutionError::UnitCollision);
        }
        if result == Err(ExecutionError::ManagerUnavailable) {
            self.healthy.store(false, Ordering::Release);
        }
        // Cleanup has its own authority and is attempted even after launch authority disappears.
        let cleanup = manager
            .stop_reap(&self.config, &lease)
            .or_else(|_| Manager::connect()?.stop_reap(&self.config, &lease));
        if cleanup.is_err() || self.config.forget(&lease).is_err() {
            self.healthy.store(false, Ordering::Release);
            return Supervision {
                outcome: Err(ExecutionError::CleanupUncertain),
                cleanup: CleanupEvidence::Uncertain,
                helper_reaped: false,
            };
        }
        let helper_reaped = observed_channel.as_mut().is_some_and(|channel| {
            matches!(
                channel.receive(Duration::from_millis(20)),
                Ok(Some(Report::Reaped))
            )
        });
        Supervision {
            outcome: result,
            cleanup: CleanupEvidence::Reaped,
            helper_reaped,
        }
    }
}
impl ProcessSupervisor<LinuxExecutablePreparer> for SystemdProcessSupervisor {
    fn ssh_material_root(&self) -> Option<&std::path::Path> {
        self.material_root.as_deref()
    }
    fn available(&self) -> bool {
        self.healthy.load(Ordering::Acquire)
            && Manager::connect()
                .and_then(|m| m.provider(&self.config))
                .is_ok()
    }
    #[cfg(test)]
    fn supervise(
        &self,
        _: PreparedExecutable,
        _: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::Unavailable)
    }
    fn supervise_controlled(
        &self,
        prepared: PreparedExecutable,
        environment: ChildEnvironment,
        control: &dyn ExecutionControl,
    ) -> Supervision {
        self.execute(prepared, environment, control)
    }
}

/// One bounded provider worker: approving a request does not block the human transport.
pub struct ExecutionWorker {
    sender: Option<std::sync::mpsc::SyncSender<String>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
struct Dispatch(std::sync::mpsc::SyncSender<String>);
impl ExecutionDispatcher for Dispatch {
    fn dispatch(&self, id: &str) -> Result<(), SessionError> {
        self.0
            .try_send(id.to_owned())
            .map_err(|_error| SessionError::BackendUnavailable)
    }
}
impl ExecutionWorker {
    pub fn start(
        app: Arc<ProviderApplication>,
        supervisor: Arc<SystemdProcessSupervisor>,
    ) -> Result<Self, SessionError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(8);
        let worker = std::thread::Builder::new()
            .name("protected-execution".into())
            .spawn(move || {
                while let Ok(id) = receiver.recv() {
                    let _result = app.run_execution(
                        app.human_owner(),
                        &id,
                        &LinuxExecutablePreparer,
                        supervisor.as_ref(),
                    );
                }
            })
            .map_err(|_error| SessionError::BackendUnavailable)?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
        })
    }
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }
    pub fn dispatcher(&self) -> Arc<dyn ExecutionDispatcher> {
        Arc::new(Dispatch(
            self.sender.as_ref().expect("live execution worker").clone(),
        ))
    }
    /// Call after transports release their dispatcher handles and application shutdown has reaped work.
    pub fn join(mut self) -> Result<(), SessionError> {
        self.sender.take();
        self.worker
            .take()
            .ok_or(SessionError::CleanupFailed)?
            .join()
            .map_err(|_error| SessionError::CleanupFailed)
    }
}

#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct UnavailableProcessSupervisor;
#[cfg(test)]
impl<P: ProtectedExecution> ProcessSupervisor<P> for UnavailableProcessSupervisor {
    fn available(&self) -> bool {
        false
    }
    fn supervise(
        &self,
        _: P::Prepared,
        _: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        Err(ExecutionError::Unavailable)
    }
}
#[cfg(test)]
#[allow(dead_code)]
pub(crate) struct FixtureProcessSupervisor;
#[cfg(test)]
impl ProcessSupervisor<LinuxExecutablePreparer> for FixtureProcessSupervisor {
    fn available(&self) -> bool {
        true
    }
    fn supervise(
        &self,
        prepared: PreparedExecutable,
        environment: ChildEnvironment,
    ) -> Result<ExecutionOutcome, ExecutionError> {
        prepared.run_fixture(environment)
    }
}

#[cfg(test)]
mod real_tests;
