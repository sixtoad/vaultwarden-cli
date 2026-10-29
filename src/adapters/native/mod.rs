//! Native Apple Silicon execution. Authorization remains in the portable application.
pub(crate) mod identity;
mod image;
mod reaper;
#[cfg(test)]
pub(crate) use image::test_requirement;
pub(crate) mod platform;
use crate::access::{
    application::ProviderApplication,
    policy::ExecutionProfile,
    ports::{
        ChildEnvironment, CleanupEvidence, ExecutionControl, ExecutionDispatcher, ExecutionError,
        ExecutionImage, ExecutionOutcome, ImageVerifier, ProcessSupervisor, ProtectedExecution,
        SessionError, Supervision,
    },
};
use std::{
    ffi::CString,
    fs::File,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

pub(crate) struct NativeExecutablePreparer;
pub(crate) struct PreparedExecutable {
    file: File,
    path: PathBuf,
    sha256: String,
    requirement: String,
    argv: Vec<CString>,
    cwd: Option<File>,
    agent: Option<std::rc::Rc<std::cell::RefCell<super::ssh_agent::Agent>>>,
    reaping: reaper::Reservation,
}
impl ImageVerifier for NativeExecutablePreparer {
    fn verify(&self, image: ExecutionImage<'_>) -> Result<(), ExecutionError> {
        self.prepare(image, vec!["reviewed-image".into()]).map(drop)
    }
}
impl ProtectedExecution for NativeExecutablePreparer {
    type Prepared = PreparedExecutable;
    fn prepare(
        &self,
        selected: ExecutionImage<'_>,
        argv: Vec<String>,
    ) -> Result<PreparedExecutable, ExecutionError> {
        if !platform::available()
            || selected.profile != ExecutionProfile::ReviewedNativeMachOArm64V1
            || !selected.path.starts_with(selected.root)
        {
            return Err(ExecutionError::UnsupportedImage);
        }
        let reaping = reaper::reserve()?;
        let file = platform::open_no_writers(selected.path, true)?;
        validate_file(&file, selected.sha256)?;
        let requirement = image::signature(selected.path)?;
        Ok(PreparedExecutable {
            file,
            path: selected.path.into(),
            sha256: selected.sha256.into(),
            requirement,
            argv: arguments(argv)?,
            cwd: None,
            agent: None,
            reaping,
        })
    }
    fn prepare_ssh(
        &self,
        prepared: &mut PreparedExecutable,
        root: &Path,
        ssh: &crate::access::policy::SshOperation,
    ) -> Result<Box<dyn crate::access::ports::SshMaterial>, ExecutionError> {
        let (material, options, cwd) = super::ssh_material::prepare(root, ssh)?;
        let mut argv = vec![prepared.argv[0].to_string_lossy().into_owned()];
        argv.extend(options);
        prepared.argv = arguments(argv)?;
        prepared.cwd = Some(cwd);
        prepared.agent = Some(material.agent.clone());
        Ok(Box::new(material))
    }
    // Producer protocols need a bounded anonymous native channel; unsupported modes deny
    // before secret resolution through the port's default, without disabling login or SSH.
}
fn arguments(args: Vec<String>) -> Result<Vec<CString>, ExecutionError> {
    if args.is_empty()
        || args.len() > 128
        || args[0].is_empty()
        || args.iter().map(|s| s.len() + 1).sum::<usize>() > 32768
    {
        return Err(ExecutionError::InvalidArguments);
    }
    args.into_iter()
        .map(|s| CString::new(s).map_err(|_error| ExecutionError::InvalidArguments))
        .collect()
}
fn validate_file(file: &File, expected: &str) -> Result<(), ExecutionError> {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::FileExt;
    let m = file
        .metadata()
        .map_err(|_error| ExecutionError::UnsafeSource)?;
    if !m.is_file()
        || m.uid() != 0
        || m.nlink() != 1
        || m.mode() & 0o7022 != 0
        || m.mode() & 0o111 == 0
        || m.len() > 64 * 1024 * 1024
    {
        return Err(ExecutionError::UnsafeSource);
    }
    platform::no_acl(file)?;
    let mut bytes = vec![0u8; m.len() as usize];
    file.read_exact_at(&mut bytes, 0)
        .map_err(|_error| ExecutionError::InvalidImage)?;
    let hash = Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if hash != expected {
        return Err(ExecutionError::DigestMismatch);
    }
    image::macho(&bytes).map(drop)
}

/// The unreaped direct child reserves its PID. Only this owner may call waitpid.
/// Dropping observation transfers ownership to the bounded natural reaper; it never signals.
pub(crate) struct Recipient {
    pub(crate) pid: u32,
    pub(crate) requirement: String,
}
impl Recipient {
    pub(crate) fn peer(&self, stream: &impl AsRawFd) -> bool {
        platform::audit(stream).is_ok_and(|token| {
            token[1] == unsafe { libc::geteuid() }
                && token[5] == self.pid
                && image::dynamic(&token, &self.requirement).is_ok()
        })
    }
}
/// Installed daemon file name; a concurrent reconcile under the lock also counts.
const PROVIDER_EXECUTABLE: &str = "vaultwarden-accessd";
pub struct NativeProcessSupervisor {
    material: PathBuf,
}
impl NativeProcessSupervisor {
    pub fn installed(root: &Path) -> Result<Self, ExecutionError> {
        let identity = identity::load()?;
        if !platform::available() || identity.provider_uid != unsafe { libc::geteuid() } {
            return Err(ExecutionError::Unavailable);
        }
        let runtime = platform::open_no_writers(&identity.ssh_runtime_dir, false)?;
        if runtime
            .metadata()
            .map_err(|_error| ExecutionError::UnsafePath)?
            .mode()
            & 0o7777
            != 0o700
        {
            return Err(ExecutionError::UnsafePath);
        }
        // No crash/core artifacts are permitted for the provider or inherited consumers.
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0 {
            return Err(ExecutionError::Unavailable);
        }
        Ok(Self {
            material: super::ssh_material::initialize(root)?,
        })
    }
    pub fn recover(&self) -> Result<(), ExecutionError> {
        let _retained = super::ssh_material::recover(&self.material);
        Ok(())
    }
    /// Trusted-console recovery only while the provider writer lock is held.
    /// An alternate state-root lock cannot authorize cleanup of a live provider's
    /// global SSH runtime/Keychain session, so no other provider process may run
    /// as the enrolled account before, between or after cleanup. launchd output
    /// is not an API; kernel process evidence also covers a provider started
    /// outside launchd. Consumers are distinct images and are never signalled.
    pub(crate) fn recover_stopped(
        state_root: &Path,
        clear_session: impl FnOnce() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        let identity = identity::load()?;
        if !platform::available() || identity.provider_uid != unsafe { libc::geteuid() } {
            return Err(ExecutionError::Unavailable);
        }
        let stopped = || {
            if platform::other_process_named(
                identity.provider_uid,
                std::ffi::OsStr::new(PROVIDER_EXECUTABLE),
            )? {
                return Err(ExecutionError::ManagerUnavailable);
            }
            Ok(())
        };
        stopped()?;
        let material = super::ssh_material::initialize(state_root)?;
        super::ssh_material::recover_stopped(&material)?;
        stopped()?;
        clear_session()?;
        stopped()
    }
}
impl ProcessSupervisor<NativeExecutablePreparer> for NativeProcessSupervisor {
    fn ssh_material_root(&self) -> Option<&Path> {
        Some(&self.material)
    }
    fn available(&self) -> bool {
        platform::available()
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
        let mut pid = 0;
        let result = (|| {
            // The retained descriptor plus root-owned no-writer chain makes path spawn safe.
            let current = platform::open_no_writers(&prepared.path, true)?;
            let a = current
                .metadata()
                .map_err(|_error| ExecutionError::UnsafeSource)?;
            let b = prepared
                .file
                .metadata()
                .map_err(|_error| ExecutionError::UnsafeSource)?;
            if (a.dev(), a.ino()) != (b.dev(), b.ino()) {
                return Err(ExecutionError::UnsafeSource);
            }
            validate_file(&current, &prepared.sha256)?;
            if image::signature(&prepared.path)? != prepared.requirement {
                return Err(ExecutionError::InvalidImage);
            }
            let mut launch = Spawn::new(&prepared, &environment)?;
            control.release(&mut || {
                pid = launch.start()?;
                Ok(())
            })?;
            drop(launch);
            drop(environment);
            control.started()?;
            if let Some(agent) = &prepared.agent {
                agent.borrow_mut().recipient(Recipient {
                    pid: pid as u32,
                    requirement: prepared.requirement.clone(),
                })?;
            }
            loop {
                // Service signing before waitpid: the PID lease must still be held.
                if !control.live() {
                    return Err(ExecutionError::ObservationLost);
                }
                if let Some(agent) = &prepared.agent {
                    agent.borrow_mut().poll(control)?;
                }
                let mut status = 0;
                let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if result == pid {
                    pid = 0;
                    return Ok(if libc::WIFEXITED(status) {
                        if libc::WEXITSTATUS(status) == 0 {
                            ExecutionOutcome::ExitedZero
                        } else {
                            ExecutionOutcome::ExitedNonZero
                        }
                    } else {
                        ExecutionOutcome::Signaled
                    });
                }
                if result < 0 {
                    return Err(ExecutionError::ObservationLost);
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if let Some(agent) = prepared.agent {
            agent.borrow_mut().close();
        }
        let started = pid != 0 || result.is_ok();
        if pid > 0 {
            prepared.reaping.detach(pid);
        }
        Supervision {
            outcome: if started && result.is_err() {
                Err(ExecutionError::ObservationLost)
            } else {
                result
            },
            cleanup: if pid > 0 {
                CleanupEvidence::Detached
            } else if started {
                CleanupEvidence::Reaped
            } else {
                CleanupEvidence::NotStarted
            },
            helper_reaped: false,
        }
    }
}
struct Spawn {
    attributes: libc::posix_spawnattr_t,
    actions: libc::posix_spawn_file_actions_t,
    path: CString,
    argv: Vec<*mut libc::c_char>,
    environment: Vec<*mut libc::c_char>,
}
impl Spawn {
    fn new(
        prepared: &PreparedExecutable,
        environment: &ChildEnvironment,
    ) -> Result<Self, ExecutionError> {
        use std::os::unix::ffi::OsStrExt;
        let mut attributes = std::ptr::null_mut();
        let mut actions = std::ptr::null_mut();
        if unsafe { libc::posix_spawnattr_init(&mut attributes) } != 0 {
            return Err(ExecutionError::Unavailable);
        }
        if unsafe { libc::posix_spawn_file_actions_init(&mut actions) } != 0 {
            unsafe {
                libc::posix_spawnattr_destroy(&mut attributes);
            };
            return Err(ExecutionError::Unavailable);
        }
        let mut launch = Self {
            attributes,
            actions,
            path: CString::new(prepared.path.as_os_str().as_bytes())
                .map_err(|_error| ExecutionError::UnsafePath)?,
            argv: prepared
                .argv
                .iter()
                .map(|s| s.as_ptr().cast_mut())
                .chain([std::ptr::null_mut()])
                .collect(),
            environment: environment
                .entries()
                .map(|s| s.as_ptr().cast_mut().cast())
                .chain([std::ptr::null_mut()])
                .collect(),
        };
        let mut arch = 0x0100000c;
        let mut count = 0;
        if unsafe {
            libc::posix_spawnattr_setflags(
                &mut launch.attributes,
                libc::POSIX_SPAWN_CLOEXEC_DEFAULT as i16,
            )
        } != 0
            || unsafe {
                libc::posix_spawnattr_setbinpref_np(
                    &mut launch.attributes,
                    1,
                    &mut arch,
                    &mut count,
                )
            } != 0
            || count != 1
        {
            return Err(ExecutionError::Unavailable);
        }
        for fd in 0..=2 {
            if unsafe {
                libc::posix_spawn_file_actions_addopen(
                    &mut launch.actions,
                    fd,
                    c"/dev/null".as_ptr(),
                    if fd == 0 {
                        libc::O_RDONLY
                    } else {
                        libc::O_WRONLY
                    },
                    0,
                )
            } != 0
            {
                return Err(ExecutionError::Unavailable);
            }
        }
        if let Some(cwd) = &prepared.cwd
            && unsafe {
                libc::posix_spawn_file_actions_addfchdir_np(&mut launch.actions, cwd.as_raw_fd())
            } != 0
        {
            return Err(ExecutionError::Unavailable);
        }
        Ok(launch)
    }
    fn start(&mut self) -> Result<libc::pid_t, ExecutionError> {
        let mut pid = 0;
        if unsafe {
            libc::posix_spawn(
                &mut pid,
                self.path.as_ptr(),
                &self.actions,
                &self.attributes,
                self.argv.as_ptr(),
                self.environment.as_ptr(),
            )
        } != 0
            || pid <= 0
        {
            return Err(ExecutionError::ExecutionFailed);
        }
        Ok(pid)
    }
}
impl Drop for Spawn {
    fn drop(&mut self) {
        unsafe {
            libc::posix_spawnattr_destroy(&mut self.attributes);
            libc::posix_spawn_file_actions_destroy(&mut self.actions);
        }
    }
}

pub struct ExecutionWorker {
    sender: Option<std::sync::mpsc::SyncSender<String>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
struct Dispatch(std::sync::mpsc::SyncSender<String>);
impl ExecutionDispatcher for Dispatch {
    fn dispatch(&self, id: &str) -> Result<(), SessionError> {
        self.0
            .try_send(id.into())
            .map_err(|_error| SessionError::BackendUnavailable)
    }
}
impl ExecutionWorker {
    pub fn start(
        app: Arc<ProviderApplication>,
        supervisor: Arc<NativeProcessSupervisor>,
    ) -> Result<Self, SessionError> {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<String>(8);
        let worker = std::thread::Builder::new()
            .name("native-protected-execution".into())
            .spawn(move || {
                while let Ok(id) = receiver.recv() {
                    let _result = app.run_execution(
                        app.human_owner(),
                        &id,
                        &NativeExecutablePreparer,
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
    pub fn dispatcher(&self) -> Arc<dyn ExecutionDispatcher> {
        Arc::new(Dispatch(self.sender.as_ref().expect("live worker").clone()))
    }
    pub fn is_finished(&self) -> bool {
        self.worker
            .as_ref()
            .is_none_or(std::thread::JoinHandle::is_finished)
    }
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
mod tests;

#[cfg(test)]
pub(crate) fn native_ssh_requirement() -> Result<String, ExecutionError> {
    image::signature(Path::new("/usr/bin/ssh"))
}
