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
        atomic::{AtomicBool, AtomicUsize, Ordering},
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
    /// Trusted-console recovery only while the provider writer lock is held.
    /// Also verifies the fixed service is stopped: an alternate state-root lock
    /// cannot authorize cleanup of a live provider's global runtime/session.
    pub(crate) fn recover_stopped(
        state_root: &std::path::Path,
        clear_session: impl FnOnce() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        const PROVIDER: &str = "vaultwarden-accessd.service";
        let manager = Manager::connect()?;
        manager.require_provider_stopped(PROVIDER)?;
        let helper = std::env::current_exe()
            .map_err(|_error| ExecutionError::Unavailable)?
            .parent()
            .ok_or(ExecutionError::UnsafePath)?
            .join("vaultwarden-access-exec");
        let runtime = std::path::PathBuf::from(format!("/run/user/{}", unsafe { libc::geteuid() }));
        let config = Config::new(PROVIDER.into(), helper, &runtime)?;
        manager.recover_strict(&config)?;
        let material = super::ssh_material::initialize(state_root)?;
        super::ssh_material::recover_stopped(&material)?;
        manager.require_provider_stopped(PROVIDER)?;
        clear_session()?;
        manager.require_provider_stopped(PROVIDER)
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
            // Residual SSH resources restrict SSH admission, not ordinary delivery.
            let _ssh_residual = super::ssh_material::recover(root);
        }
        Ok(())
    }
    fn execute(
        &self,
        mut prepared: PreparedExecutable,
        environment: ChildEnvironment,
        control: &dyn ExecutionControl,
    ) -> Supervision {
        let agent = prepared.ssh_agent.take();
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
        let mut released = false;
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
            released = true;
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
                        if let Some(agent) = &agent {
                            agent.borrow_mut().recipient(
                                channel
                                    .take_recipient()
                                    .ok_or(ExecutionError::ExecutionFailed)?,
                            )?;
                        }
                    }
                    Some(Report::Outcome(outcome)) if executed => {
                        #[cfg(test)]
                        phase(LaunchPhase::NaturalExit);
                        return Ok(outcome);
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
                if executed && let Some(agent) = &agent {
                    agent.borrow_mut().poll(control)?;
                }
                manager.provider(&self.config)?;
            }
        })();
        if let Some(agent) = &agent {
            agent.borrow_mut().close();
        }
        if result == Err(ExecutionError::UnitCollision) {
            if self.config.forget(&lease).is_err() {
                self.healthy.store(false, Ordering::Release);
            }
            return not_started(ExecutionError::UnitCollision);
        }
        if result == Err(ExecutionError::ManagerUnavailable) {
            self.healthy.store(false, Ordering::Release);
        }
        // Closing our private channel cancels a helper that has not received release.
        // It never signals a consumer. A released helper may continue observing on its own.
        let helper_reaped = observed_channel.as_mut().is_some_and(|channel| {
            matches!(
                channel.receive(Duration::from_millis(20)),
                Ok(Some(Report::Reaped))
            )
        });
        drop(observed_channel);
        // A helper can already be connected in the listener backlog when
        // cancellation wins before accept. Close that provider-owned endpoint
        // too, so the unreleased helper observes EOF instead of its timeout.
        drop(listener);
        let deadline = Instant::now() + Duration::from_millis(if released { 200 } else { 1000 });
        let unused = loop {
            if matches!(manager.unused(&self.config, &lease), Ok(true)) {
                break true;
            }
            if Instant::now() >= deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(20));
        };
        if unused && self.config.forget(&lease).is_err() {
            self.healthy.store(false, Ordering::Release);
        }
        Supervision {
            outcome: if released && result.is_err() {
                Err(ExecutionError::ObservationLost)
            } else {
                result
            },
            cleanup: if unused {
                CleanupEvidence::Reaped
            } else {
                CleanupEvidence::Detached
            },
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
const EXECUTION_QUEUE_CAPACITY: usize = 8;
#[derive(Default)]
struct WorkerStatus {
    alive: AtomicBool,
    queued: AtomicUsize,
}
struct WorkerAlive(Arc<WorkerStatus>);
impl Drop for WorkerAlive {
    fn drop(&mut self) {
        self.0.alive.store(false, Ordering::Release);
    }
}
pub struct ExecutionWorker {
    sender: Option<std::sync::mpsc::SyncSender<String>>,
    worker: Option<std::thread::JoinHandle<()>>,
    status: Arc<WorkerStatus>,
    supervisor: Arc<SystemdProcessSupervisor>,
}
struct Dispatch {
    sender: std::sync::mpsc::SyncSender<String>,
    status: Arc<WorkerStatus>,
    supervisor: Arc<SystemdProcessSupervisor>,
}
impl ExecutionDispatcher for Dispatch {
    fn available(&self) -> bool {
        self.status.alive.load(Ordering::Acquire)
            && self.status.queued.load(Ordering::Acquire) < EXECUTION_QUEUE_CAPACITY
            && self.supervisor.available()
    }
    fn dispatch(&self, id: &str) -> Result<(), SessionError> {
        let mut queued = self.status.queued.load(Ordering::Acquire);
        loop {
            if queued >= EXECUTION_QUEUE_CAPACITY {
                return Err(SessionError::BackendUnavailable);
            }
            match self.status.queued.compare_exchange_weak(
                queued,
                queued + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => queued = actual,
            }
        }
        if self.sender.try_send(id.to_owned()).is_err() {
            self.status.queued.fetch_sub(1, Ordering::AcqRel);
            return Err(SessionError::BackendUnavailable);
        }
        Ok(())
    }
}
impl ExecutionWorker {
    pub fn start(
        app: Arc<ProviderApplication>,
        supervisor: Arc<SystemdProcessSupervisor>,
    ) -> Result<Self, SessionError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(EXECUTION_QUEUE_CAPACITY);
        let status = Arc::new(WorkerStatus::default());
        let worker_status = status.clone();
        let worker_supervisor = supervisor.clone();
        let worker = std::thread::Builder::new()
            .name("protected-execution".into())
            .spawn(move || {
                let _alive = WorkerAlive(worker_status.clone());
                worker_status.alive.store(true, Ordering::Release);
                while let Ok(id) = receiver.recv() {
                    worker_status.queued.fetch_sub(1, Ordering::AcqRel);
                    let _result = app.run_execution(
                        app.human_owner(),
                        &id,
                        &LinuxExecutablePreparer,
                        worker_supervisor.as_ref(),
                    );
                }
            })
            .map_err(|_error| SessionError::BackendUnavailable)?;
        Ok(Self {
            sender: Some(sender),
            worker: Some(worker),
            status,
            supervisor,
        })
    }
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }
    pub fn dispatcher(&self) -> Arc<dyn ExecutionDispatcher> {
        Arc::new(Dispatch {
            sender: self.sender.as_ref().expect("live execution worker").clone(),
            status: self.status.clone(),
            supervisor: self.supervisor.clone(),
        })
    }
    /// Call after transports release their dispatchers and shutdown has settled observers.
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
mod dispatcher_tests {
    use super::*;
    fn supervisor() -> Arc<SystemdProcessSupervisor> {
        Arc::new(SystemdProcessSupervisor {
            config: Config {
                provider: "unavailable.service".into(),
                helper: "/unused".into(),
                runtime: "/unused".into(),
                prefix: "unused-".into(),
                test_environment: Vec::new(),
            },
            healthy: AtomicBool::new(false),
            material_root: None,
        })
    }
    #[test]
    fn management_dispatcher_reports_unhealthy_worker_and_bounds_real_queue() {
        let (sender, receiver) = std::sync::mpsc::sync_channel(EXECUTION_QUEUE_CAPACITY);
        let status = Arc::new(WorkerStatus::default());
        status.alive.store(true, Ordering::Release);
        let dispatcher = Dispatch {
            sender,
            status: status.clone(),
            supervisor: supervisor(),
        };
        assert!(!dispatcher.available()); // alive, but actual supervisor unhealthy
        for _ in 0..EXECUTION_QUEUE_CAPACITY {
            dispatcher.dispatch("request").unwrap();
        }
        assert!(dispatcher.dispatch("overflow").is_err());
        assert_eq!(
            status.queued.load(Ordering::Acquire),
            EXECUTION_QUEUE_CAPACITY
        );
        receiver.recv().unwrap();
        status.queued.fetch_sub(1, Ordering::AcqRel);
        dispatcher.dispatch("replacement").unwrap();
        drop(receiver);
        status.queued.store(0, Ordering::Release);
        assert!(dispatcher.dispatch("disconnected").is_err());
        assert_eq!(status.queued.load(Ordering::Acquire), 0);
        let guard = WorkerAlive(status.clone());
        drop(guard);
        assert!(!status.alive.load(Ordering::Acquire));
        assert!(!dispatcher.available());
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
