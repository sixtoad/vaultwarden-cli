//! Typed systemd transaction and independent post-stop process observation.
use crate::access::ports::ExecutionError;
use dbus::{
    Path as BusPath,
    arg::{Get, RefArg, Variant},
    blocking::{Connection, stdintf::org_freedesktop_dbus::Properties},
    message::MatchRule,
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    io::Write,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const DEST: &str = "org.freedesktop.systemd1";
const ROOT: &str = "/org/freedesktop/systemd1";
const MANAGER: &str = "org.freedesktop.systemd1.Manager";
const UNIT: &str = "org.freedesktop.systemd1.Unit";
const SERVICE: &str = "org.freedesktop.systemd1.Service";
const WAIT: Duration = Duration::from_secs(10);
// Remove loader/runtime controls even if absent from the manager snapshot, plus
// systemd-generated variables. The helper needs no ambient environment.
const HELPER_UNSET: &[&str] = &[
    "LD_PRELOAD",
    "LD_LIBRARY_PATH",
    "LD_AUDIT",
    "LD_DEBUG",
    "LD_DEBUG_OUTPUT",
    "LD_PROFILE",
    "LD_PROFILE_OUTPUT",
    "LD_ORIGIN_PATH",
    "LD_BIND_NOW",
    "LD_BIND_NOT",
    "LD_DYNAMIC_WEAK",
    "LD_HWCAP_MASK",
    "LD_SHOW_AUXV",
    "LD_USE_LOAD_BIAS",
    "LD_TRACE_LOADED_OBJECTS",
    "GLIBC_TUNABLES",
    "GCONV_PATH",
    "LOCPATH",
    "NLSPATH",
    "MALLOC_CHECK_",
    "MALLOC_TRACE",
    "MALLOC_PERTURB_",
    "RUST_BACKTRACE",
    "RUST_LIB_BACKTRACE",
    "RUST_LOG",
    "TMPDIR",
    "PATH",
    "LANG",
    "LC_ALL",
    "HOME",
    "USER",
    "LOGNAME",
    "SHELL",
    "INVOCATION_ID",
    "JOURNAL_STREAM",
    "SYSTEMD_EXEC_PID",
    "NOTIFY_SOCKET",
    "LISTEN_PID",
    "LISTEN_FDS",
    "LISTEN_FDNAMES",
    "WATCHDOG_PID",
    "WATCHDOG_USEC",
    "CREDENTIALS_DIRECTORY",
    "RUNTIME_DIRECTORY",
    "STATE_DIRECTORY",
    "CACHE_DIRECTORY",
    "LOGS_DIRECTORY",
    "CONFIGURATION_DIRECTORY",
    "MEMORY_PRESSURE_WATCH",
    "MEMORY_PRESSURE_WRITE",
    "NSS_DYNAMIC_BYPASS",
];
fn environment_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && name
            .bytes()
            .enumerate()
            .all(|(i, b)| b == b'_' || b.is_ascii_alphabetic() || (i > 0 && b.is_ascii_digit()))
}
fn helper_unset_environment(environment: Vec<String>) -> Result<Vec<String>, ExecutionError> {
    let environment = zeroize::Zeroizing::new(environment);
    if environment.len() > 4096 {
        return Err(ExecutionError::ManagerUnavailable);
    }
    let mut names: BTreeSet<String> = HELPER_UNSET.iter().map(|s| (*s).to_owned()).collect();
    for assignment in environment.iter() {
        let (name, _) = assignment
            .split_once('=')
            .ok_or(ExecutionError::ManagerUnavailable)?;
        if !environment_name(name) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        names.insert(name.to_owned());
    }
    Ok(names.into_iter().collect())
}
fn valid_helper_unset(names: &[String]) -> bool {
    names.len() <= 4096 + HELPER_UNSET.len()
        && names.iter().all(|name| environment_name(name))
        && HELPER_UNSET
            .iter()
            .all(|required| names.iter().any(|name| name == required))
}

pub(super) type PropertiesList = Vec<(String, Variant<Box<dyn RefArg>>)>;
type ListedUnit = (
    String,
    String,
    String,
    String,
    String,
    String,
    BusPath<'static>,
    u32,
    String,
    BusPath<'static>,
);
type ObservedExec = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
fn failure<T>(_: T) -> ExecutionError {
    ExecutionError::ManagerUnavailable
}
fn property<T: RefArg + 'static>(name: &str, value: T) -> (String, Variant<Box<dyn RefArg>>) {
    (name.into(), Variant(Box::new(value)))
}

#[derive(Clone)]
pub(super) struct Config {
    pub provider: String,
    pub helper: PathBuf,
    pub runtime: PathBuf,
    pub prefix: String,
    #[cfg(test)]
    pub test_environment: Vec<String>,
}
impl Config {
    pub fn new(
        provider: String,
        helper: PathBuf,
        runtime_parent: &Path,
    ) -> Result<Self, ExecutionError> {
        checked_installation(&helper)?;
        checked_directory(runtime_parent, true)?;
        let digest =
            Sha256::digest(format!("{}:{provider}", unsafe { libc::geteuid() }).as_bytes());
        let namespace: String = digest[..8].iter().map(|b| format!("{b:02x}")).collect();
        let runtime = runtime_parent.join(format!("vw-access-{namespace}"));
        match std::fs::DirBuilder::new().mode(0o700).create(&runtime) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(failure(e)),
        }
        checked_directory(&runtime, true)?;
        Ok(Self {
            provider,
            helper,
            runtime,
            prefix: format!("vw-access-{namespace}-"),
            #[cfg(test)]
            test_environment: Vec::new(),
        })
    }
    pub fn owns_name(&self, name: &str) -> bool {
        name.strip_prefix(&self.prefix)
            .and_then(|s| s.strip_suffix(".service"))
            .is_some_and(|s| {
                s.len() == 32
                    && s.bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
    pub fn name(&self) -> Result<String, ExecutionError> {
        let mut random = [0u8; 16];
        getrandom::fill(&mut random).map_err(failure)?;
        Ok(format!(
            "{}{}.service",
            self.prefix,
            random
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>()
        ))
    }
    pub fn socket(&self, name: &str) -> PathBuf {
        // Unix socket paths have a fixed kernel bound; namespace already lives in parent.
        self.runtime
            .join(format!("{}.sock", &name[self.prefix.len()..name.len() - 8]))
    }
    fn lease_path(&self, name: &str) -> PathBuf {
        self.runtime.join(format!("{name}.json"))
    }
    fn staging_path(&self, name: &str) -> Result<PathBuf, ExecutionError> {
        let random = self.name()?;
        Ok(self.runtime.join(format!(
            ".staging.{name}.{}",
            &random[self.prefix.len()..random.len() - 8]
        )))
    }
    fn owns_staging(&self, filename: &str) -> bool {
        filename
            .strip_prefix(".staging.")
            .and_then(|s| s.rsplit_once('.'))
            .is_some_and(|(name, nonce)| {
                self.owns_name(name)
                    && nonce.len() == 32
                    && nonce
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
    }
    pub fn record(&self, lease: &Lease) -> Result<(), ExecutionError> {
        if !self.owns_name(&lease.name) {
            return Err(ExecutionError::CleanupUncertain);
        }
        let staging = self.staging_path(&lease.name)?;
        // If exclusive creation fails, do not unlink somebody else's staging file.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&staging)
            .map_err(failure)?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(lease).map_err(failure)?)
                .map_err(failure)?;
            file.sync_all().map_err(failure)?;
            // Publishing a hard link is atomic and refuses an existing final name.
            // A crash before publication leaves only a precisely owned staging file.
            std::fs::hard_link(&staging, self.lease_path(&lease.name)).map_err(failure)?;
            std::fs::File::open(&self.runtime)
                .and_then(|f| f.sync_all())
                .map_err(failure)
        })();
        let removed = std::fs::remove_file(&staging);
        result?;
        removed.map_err(failure)?;
        std::fs::File::open(&self.runtime)
            .and_then(|f| f.sync_all())
            .map_err(failure)?;
        #[cfg(test)]
        super::real_tests::record_identity(lease);
        Ok(())
    }
    pub fn forget(&self, lease: &Lease) -> Result<(), ExecutionError> {
        std::fs::remove_file(self.lease_path(&lease.name)).map_err(failure)?;
        std::fs::File::open(&self.runtime)
            .and_then(|f| f.sync_all())
            .map_err(failure)
    }
    pub fn leases(&self) -> Result<Vec<Lease>, ExecutionError> {
        let mut leases = Vec::new();
        for entry in std::fs::read_dir(&self.runtime).map_err(failure)? {
            let entry = entry.map_err(failure)?;
            let filename = entry.file_name();
            let filename = filename
                .to_str()
                .ok_or(ExecutionError::ManagerUnavailable)?;
            if self.owns_staging(filename) {
                let metadata = std::fs::symlink_metadata(entry.path()).map_err(failure)?;
                if !metadata.is_file()
                    || metadata.uid() != unsafe { libc::geteuid() }
                    || metadata.mode() & 0o7777 != 0o600
                {
                    return Err(ExecutionError::CleanupUncertain);
                }
                std::fs::remove_file(entry.path()).map_err(failure)?;
                std::fs::File::open(&self.runtime)
                    .and_then(|f| f.sync_all())
                    .map_err(failure)?;
                continue;
            }
            let Some(name) = filename.strip_suffix(".json") else {
                continue;
            };
            if !self.owns_name(name) {
                continue;
            }
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(entry.path())
                .map_err(failure)?;
            let m = file.metadata().map_err(failure)?;
            if !m.is_file()
                || m.uid() != unsafe { libc::geteuid() }
                || m.mode() & 0o7777 != 0o600
                || m.len() > 4096
            {
                return Err(ExecutionError::CleanupUncertain);
            }
            let lease: Lease = serde_json::from_reader(file).map_err(failure)?;
            if lease.name != name {
                return Err(ExecutionError::CleanupUncertain);
            }
            leases.push(lease);
        }
        Ok(leases)
    }
}
use std::os::unix::fs::DirBuilderExt;

#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Lease {
    pub name: String,
    pub cgroup: String,
}
pub(super) struct Identity {
    pub pid: u32,
    pub invocation: Vec<u8>,
}
pub(super) struct Manager {
    connection: Connection,
    jobs: Arc<Mutex<JobObservation>>,
    root_cgroup: String,
}
#[derive(Default)]
struct JobObservation {
    unit: String,
    result: Option<(String, String)>,
}
impl JobObservation {
    fn observe(&mut self, job: String, unit: &str, result: String) {
        if unit == self.unit {
            self.result = Some((job, result));
        }
    }
}
#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Fault {
    None,
    Missing,
    Job,
    Exec,
    Monitor,
    Stop,
}
#[cfg(test)]
thread_local! { pub(super) static FAULT: std::cell::Cell<Fault> = const { std::cell::Cell::new(Fault::None) }; }
fn supported_version(version: &str) -> bool {
    version
        .split(|c: char| !c.is_ascii_digit())
        .next()
        .and_then(|v| v.parse::<u32>().ok())
        .is_some_and(|v| v >= 255)
}
impl Manager {
    pub fn connect() -> Result<Self, ExecutionError> {
        #[cfg(test)]
        if FAULT.with(|f| f.get() == Fault::Missing) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        if !Path::new("/sys/fs/cgroup/cgroup.controllers").is_file() {
            return Err(ExecutionError::ManagerUnavailable);
        }
        let connection = Connection::new_address(&format!("unix:path=/run/user/{}/bus", unsafe {
            libc::geteuid()
        }))
        .map_err(failure)?;
        let proxy = connection.with_proxy(DEST, ROOT, Duration::from_secs(2));
        let version: String = proxy.get(MANAGER, "Version").map_err(failure)?;
        if !supported_version(&version) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        let root_cgroup: String = proxy.get(MANAGER, "ControlGroup").map_err(failure)?;
        if !valid_cgroup(&root_cgroup) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        let jobs = Arc::new(Mutex::new(JobObservation::default()));
        let observed = jobs.clone();
        let mut rule = MatchRule::new_signal(MANAGER, "JobRemoved");
        rule.sender = Some(DEST.into());
        rule.path = Some(ROOT.into());
        connection
            .add_match(
                rule,
                move |(_id, job, unit, result): (u32, BusPath<'static>, String, String), _, _| {
                    if let Ok(mut jobs) = observed.lock() {
                        jobs.observe(job.to_string(), &unit, result);
                    }
                    true
                },
            )
            .map_err(failure)?;
        let (): () = proxy
            .method_call(MANAGER, "Subscribe", ())
            .map_err(failure)?;
        Ok(Self {
            connection,
            jobs,
            root_cgroup,
        })
    }
    fn get<T: for<'b> Get<'b> + 'static>(
        &self,
        path: &BusPath<'_>,
        interface: &str,
        name: &str,
    ) -> Result<T, ExecutionError> {
        self.connection
            .with_proxy(DEST, path.clone(), Duration::from_secs(2))
            .get(interface, name)
            .map_err(failure)
    }
    pub(super) fn unit(&self, name: &str) -> Result<Option<BusPath<'static>>, ExecutionError> {
        let result: Result<(BusPath<'static>,), _> = self
            .connection
            .with_proxy(DEST, ROOT, Duration::from_secs(2))
            .method_call(MANAGER, "GetUnit", (name,));
        match result {
            Ok((path,)) => Ok(Some(path)),
            Err(e) if e.name() == Some("org.freedesktop.systemd1.NoSuchUnit") => Ok(None),
            Err(e) => Err(failure(e)),
        }
    }
    pub fn provider(&self, config: &Config) -> Result<(), ExecutionError> {
        #[cfg(test)]
        if FAULT.with(|f| f.get() == Fault::Monitor) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        let (path,): (BusPath<'static>,) = self
            .connection
            .with_proxy(DEST, ROOT, Duration::from_secs(2))
            .method_call(MANAGER, "GetUnitByPID", (std::process::id(),))
            .map_err(failure)?;
        if self.get::<String>(&path, UNIT, "Id")? != config.provider
            || self.get::<String>(&path, UNIT, "ActiveState")? != "active"
            || self.get::<u32>(&path, SERVICE, "MainPID")? != std::process::id()
        {
            return Err(ExecutionError::ManagerUnavailable);
        }
        Ok(())
    }
    pub fn lease(&self, name: String) -> Lease {
        Lease {
            cgroup: format!("{}/app.slice/{name}", self.root_cgroup),
            name,
        }
    }
    pub fn owned(
        &self,
        config: &Config,
        lease: &Lease,
    ) -> Result<Option<Identity>, ExecutionError> {
        if !config.owns_name(&lease.name) || lease.cgroup != self.lease(lease.name.clone()).cgroup {
            return Err(ExecutionError::CleanupUncertain);
        }
        let Some(path) = self.unit(&lease.name)? else {
            return Ok(None);
        };
        if !self.get::<bool>(&path, UNIT, "Transient")?
            || self.get::<String>(&path, UNIT, "Id")? != lease.name
            || self.get::<String>(&path, UNIT, "CollectMode")? != "inactive-or-failed"
        {
            return Err(ExecutionError::CleanupUncertain);
        }
        for relationship in ["BindsTo", "PartOf"] {
            if self.get::<Vec<String>>(&path, UNIT, relationship)? != vec![config.provider.clone()]
            {
                return Err(ExecutionError::CleanupUncertain);
            }
        }
        if !self
            .get::<Vec<String>>(&path, UNIT, "After")?
            .contains(&config.provider)
        {
            return Err(ExecutionError::CleanupUncertain);
        }
        let exec: Vec<ObservedExec> = self.get(&path, SERVICE, "ExecStart")?;
        let helper = config
            .helper
            .to_str()
            .ok_or(ExecutionError::ManagerUnavailable)?;
        let socket = config.socket(&lease.name);
        if exec.len() != 1
            || exec[0].0 != helper
            || exec[0].1.len() != 3
            || exec[0].1[0] != helper
            || exec[0].1[1] != socket.to_str().ok_or(ExecutionError::ManagerUnavailable)?
            || exec[0].1[2].parse::<u32>().ok().is_none_or(|pid| pid == 0)
            || exec[0].2
        {
            return Err(ExecutionError::CleanupUncertain);
        }
        for (name, expected) in [
            ("KillMode", "control-group"),
            ("Restart", "no"),
            ("Type", "exec"),
            ("ExitType", "main"),
            ("StandardInput", "null"),
            ("StandardOutput", "null"),
            ("StandardError", "null"),
        ] {
            if self.get::<String>(&path, SERVICE, name)? != expected {
                return Err(ExecutionError::CleanupUncertain);
            }
        }
        #[cfg(test)]
        let expected_environment = config.test_environment.clone();
        #[cfg(not(test))]
        let expected_environment: Vec<String> = Vec::new();
        // An old unit remains owned if manager names change after creation. Only
        // the stable removal contract and name-only shape are ownership evidence.
        if !valid_helper_unset(&self.get::<Vec<String>>(&path, SERVICE, "UnsetEnvironment")?)
            || !self.get::<bool>(&path, SERVICE, "SendSIGKILL")?
            || self.get::<Vec<String>>(&path, SERVICE, "Environment")? != expected_environment
            || self.get::<u64>(&path, SERVICE, "TimeoutStartUSec")? != 5_000_000
            || self.get::<u64>(&path, SERVICE, "TimeoutStopUSec")? != 2_000_000
            || matches!(
                self.get::<u64>(&path, SERVICE, "RuntimeMaxUSec")?,
                0 | u64::MAX
            )
        {
            return Err(ExecutionError::CleanupUncertain);
        }
        let cg: String = self.get(&path, SERVICE, "ControlGroup")?;
        if !cg.is_empty() && cg != lease.cgroup {
            return Err(ExecutionError::CleanupUncertain);
        }
        let invocation: Vec<u8> = self.get(&path, UNIT, "InvocationID")?;
        let pid = self.get(&path, SERVICE, "MainPID")?;
        Ok(Some(Identity { pid, invocation }))
    }
    pub fn helper(
        &self,
        config: &Config,
        lease: &Lease,
        identity: &Identity,
    ) -> Result<(), ExecutionError> {
        self.provider(config)?;
        let current = self
            .owned(config, lease)?
            .ok_or(ExecutionError::ExecutionFailed)?;
        if identity.pid == 0
            || identity.invocation.len() != 16
            || identity.invocation.iter().all(|v| *v == 0)
            || current.pid != identity.pid
            || current.invocation != identity.invocation
        {
            return Err(ExecutionError::ExecutionFailed);
        }
        let cgroup =
            std::fs::read_to_string(format!("/proc/{}/cgroup", identity.pid)).map_err(failure)?;
        if !cgroup
            .lines()
            .any(|line| line == format!("0::{}", lease.cgroup))
        {
            return Err(ExecutionError::ExecutionFailed);
        }
        Ok(())
    }
    pub fn start(
        &self,
        config: &Config,
        lease: &Lease,
        runtime: Duration,
    ) -> Result<(), ExecutionError> {
        #[cfg(test)]
        if FAULT.with(|f| f.get() == Fault::Job) {
            return Err(ExecutionError::ExecutionFailed);
        }
        // The same-UID manager is trusted: it can already replace units/binaries.
        // Snapshot names immediately before start; never forward manager values.
        let environment: Vec<String> = self
            .connection
            .with_proxy(DEST, ROOT, Duration::from_secs(2))
            .get(MANAGER, "Environment")
            .map_err(failure)?;
        #[cfg(test)]
        let environment = {
            let mut environment = environment;
            environment.extend(config.test_environment.clone());
            environment
        };
        let unset = helper_unset_environment(environment)?;
        let properties = properties(config, &lease.name, runtime, unset)?;
        #[cfg(test)]
        let properties = {
            let mut properties = properties;
            super::real_tests::apply_environment_fixture(&mut properties, &config.test_environment);
            if FAULT.with(|f| f.get() == Fault::Exec) {
                properties.push(property(
                    "SystemCallFilter",
                    (false, vec!["execveat".to_owned()]),
                ));
                properties.push(property("SystemCallErrorNumber", libc::EPERM));
            }
            properties
        };
        self.expect_job(&lease.name)?;
        let aux: Vec<(String, PropertiesList)> = Vec::new();
        let (job,): (BusPath<'static>,) = self
            .connection
            .with_proxy(DEST, ROOT, Duration::from_secs(2))
            .method_call(
                MANAGER,
                "StartTransientUnit",
                (&lease.name, "fail", properties, aux),
            )
            .map_err(|error| {
                if error.name() == Some("org.freedesktop.systemd1.UnitExists") {
                    ExecutionError::UnitCollision
                } else {
                    failure(error)
                }
            })?;
        self.wait_job(&job, &lease.name)
    }
    fn expect_job(&self, name: &str) -> Result<(), ExecutionError> {
        *self.jobs.lock().map_err(failure)? = JobObservation {
            unit: name.to_owned(),
            result: None,
        };
        Ok(())
    }
    fn wait_job(&self, job: &BusPath<'_>, _name: &str) -> Result<(), ExecutionError> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some((observed, outcome)) = self.jobs.lock().map_err(failure)?.result.take()
                && observed == job.to_string()
            {
                return if outcome == "done" {
                    Ok(())
                } else {
                    Err(ExecutionError::ExecutionFailed)
                };
            }
            if Instant::now() >= deadline {
                return Err(ExecutionError::ManagerUnavailable);
            }
            self.connection
                .process(Duration::from_millis(20))
                .map_err(failure)?;
        }
    }
    pub fn stop_reap(&self, config: &Config, lease: &Lease) -> Result<(), ExecutionError> {
        #[cfg(test)]
        if FAULT.with(|f| f.get() == Fault::Stop) {
            return Err(ExecutionError::ManagerUnavailable);
        }
        if self.owned(config, lease)?.is_some() {
            self.expect_job(&lease.name)?;
            let (job,): (BusPath<'static>,) = self
                .connection
                .with_proxy(DEST, ROOT, Duration::from_secs(2))
                .method_call(MANAGER, "StopUnit", (&lease.name, "replace"))
                .map_err(failure)?;
            self.wait_job(&job, &lease.name)?;
        }
        // Job completion closes containment. Independent /proc scans include zombies,
        // which neither cgroup.procs nor populated=0 can establish as reaped.
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(path) = self.unit(&lease.name)? {
                let active: String = self.get(&path, UNIT, "ActiveState")?;
                if !matches!(active.as_str(), "inactive" | "failed") {
                    if Instant::now() >= deadline {
                        return Err(ExecutionError::CleanupUncertain);
                    }
                    std::thread::sleep(Duration::from_millis(20));
                    continue;
                }
            }
            // Process exit can tear an unrelated proc snapshot. Retry until a
            // complete scan is available; persistent unreadability stays uncertain.
            if matches!(
                proc_empty_until(Path::new("/proc"), &lease.cgroup, deadline),
                Ok(true)
            ) {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(ExecutionError::CleanupUncertain);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }
    pub fn recover(&self, config: &Config) -> Result<(), ExecutionError> {
        // Recovery is called only under ProviderStore's exclusive writer lock.
        let mut leases = config.leases()?;
        let (units,): (Vec<ListedUnit>,) = self
            .connection
            .with_proxy(DEST, ROOT, Duration::from_secs(2))
            .method_call(MANAGER, "ListUnits", ())
            .map_err(failure)?;
        for (name, ..) in units {
            if !config.owns_name(&name) || leases.iter().any(|lease| lease.name == name) {
                continue;
            }
            let lease = self.lease(name);
            // Namespace lookalikes without the exact ownership contract are unrelated.
            match self.owned(config, &lease) {
                Ok(Some(_)) => {
                    config.record(&lease)?;
                    leases.push(lease);
                }
                Ok(None) | Err(ExecutionError::CleanupUncertain) => {}
                Err(error) => return Err(error),
            }
        }
        for lease in leases {
            self.stop_reap(config, &lease)?;
            config.forget(&lease)?;
            match std::fs::remove_file(config.socket(&lease.name)) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(failure(e)),
            }
        }
        Ok(())
    }
}

pub(super) fn properties(
    config: &Config,
    name: &str,
    runtime: Duration,
    unset_environment: Vec<String>,
) -> Result<PropertiesList, ExecutionError> {
    if !valid_helper_unset(&unset_environment) {
        return Err(ExecutionError::ManagerUnavailable);
    }
    let helper = config
        .helper
        .to_str()
        .ok_or(ExecutionError::ManagerUnavailable)?
        .to_owned();
    let socket = config
        .socket(name)
        .to_str()
        .ok_or(ExecutionError::ManagerUnavailable)?
        .to_owned();
    let args = vec![helper.clone(), socket, std::process::id().to_string()];
    let micros = u64::try_from(runtime.as_micros()).map_err(failure)?;
    if micros == 0 {
        return Err(ExecutionError::Cancelled);
    }
    Ok(vec![
        property("Description", "Vaultwarden protected execution".to_owned()),
        property("UnsetEnvironment", unset_environment),
        property("BindsTo", vec![config.provider.clone()]),
        property("PartOf", vec![config.provider.clone()]),
        property("After", vec![config.provider.clone()]),
        property("ExecStart", vec![(helper, args, false)]),
        property("Slice", "app.slice".to_owned()),
        property("Type", "exec".to_owned()),
        property("ExitType", "main".to_owned()),
        property("KillMode", "control-group".to_owned()),
        property("CollectMode", "inactive-or-failed".to_owned()),
        property("SendSIGKILL", true),
        property("Restart", "no".to_owned()),
        property("TimeoutStartUSec", 5_000_000u64),
        property("TimeoutStopUSec", 2_000_000u64),
        property("RuntimeMaxUSec", micros),
        property("StandardInput", "null".to_owned()),
        property("StandardOutput", "null".to_owned()),
        property("StandardError", "null".to_owned()),
        property("LimitCORE", 0u64),
        property("LimitCORESoft", 0u64),
        property("NoNewPrivileges", true),
    ])
}
fn valid_cgroup(path: &str) -> bool {
    path.starts_with('/')
        && path.len() < 2048
        && !path.split('/').any(|s| matches!(s, "." | ".."))
        && !path.chars().any(char::is_control)
}
fn belongs(observed: &str, cgroup: &str) -> bool {
    let observed = observed.strip_suffix(" (deleted)").unwrap_or(observed);
    observed == cgroup
        || observed
            .strip_prefix(cgroup)
            .is_some_and(|suffix| suffix.starts_with('/'))
}
fn start_time(stat: &str) -> Option<&str> {
    stat.rsplit_once(") ")?.1.split_whitespace().nth(19)
}
#[cfg(test)]
pub(super) fn proc_empty(root: &Path, cgroup: &str) -> Result<bool, ExecutionError> {
    proc_empty_until(root, cgroup, Instant::now() + WAIT)
}
fn proc_empty_until(root: &Path, cgroup: &str, deadline: Instant) -> Result<bool, ExecutionError> {
    proc_empty_with_budget(root, cgroup, || Instant::now() < deadline)
}
fn proc_empty_with_budget(
    root: &Path,
    cgroup: &str,
    mut has_budget: impl FnMut() -> bool,
) -> Result<bool, ExecutionError> {
    if !valid_cgroup(cgroup) {
        return Err(ExecutionError::CleanupUncertain);
    }
    for entry in std::fs::read_dir(root).map_err(failure)? {
        // Use the caller's remaining cleanup budget, including non-process entries.
        // An interrupted inventory cannot prove absence.
        if !has_budget() {
            return Err(ExecutionError::CleanupUncertain);
        }
        let entry = entry.map_err(failure)?;
        if entry
            .file_name()
            .to_str()
            .is_none_or(|s| s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()))
        {
            continue;
        }
        let path = entry.path();
        let read = |name: &str| -> Result<Option<String>, ExecutionError> {
            match std::fs::read_to_string(path.join(name)) {
                Ok(s) => Ok(Some(s)),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                Err(_) => Err(ExecutionError::CleanupUncertain),
            }
        };
        let Some(before) = read("stat")? else {
            continue;
        };
        let Some(groups) = read("cgroup")? else {
            continue;
        };
        let Some(after) = read("stat")? else {
            continue;
        };
        let before = start_time(&before).ok_or(ExecutionError::CleanupUncertain)?;
        let after = start_time(&after).ok_or(ExecutionError::CleanupUncertain)?;
        if before != after {
            return Err(ExecutionError::CleanupUncertain);
        }
        if groups
            .lines()
            .filter_map(|line| line.strip_prefix("0::"))
            .any(|path| belongs(path, cgroup))
        {
            return Ok(false);
        }
        if !groups.lines().any(|line| line.starts_with("0::")) {
            return Err(ExecutionError::CleanupUncertain);
        }
    }
    if !has_budget() {
        return Err(ExecutionError::CleanupUncertain);
    }
    Ok(true)
}
fn checked_directory(path: &Path, private: bool) -> Result<(), ExecutionError> {
    let m = std::fs::symlink_metadata(path).map_err(failure)?;
    let uid = unsafe { libc::geteuid() };
    if !m.is_dir()
        || m.file_type().is_symlink()
        || (m.uid() != uid && m.uid() != 0)
        || m.mode() & 0o7022 != 0
        || (private && (m.uid() != uid || m.mode() & 0o7777 != 0o700))
    {
        return Err(ExecutionError::UnsafePath);
    }
    if let Some(parent) = path.parent()
        && parent != path
    {
        checked_directory(parent, false)?;
    }
    Ok(())
}
fn checked_installation(path: &Path) -> Result<(), ExecutionError> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(ExecutionError::UnsafePath);
    }
    checked_directory(path.parent().ok_or(ExecutionError::UnsafePath)?, false)?;
    let m = std::fs::symlink_metadata(path).map_err(failure)?;
    if !m.is_file()
        || m.file_type().is_symlink()
        || m.uid() != unsafe { libc::geteuid() }
        || m.mode() & 0o7022 != 0
        || m.mode() & 0o500 != 0o500
    {
        return Err(ExecutionError::UnsafeSource);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    fn config() -> Config {
        Config {
            provider: "vaultwarden-accessd.service".into(),
            helper: "/home/owner/bin/vaultwarden-access-exec".into(),
            runtime: "/run/user/1000/vw-access-test".into(),
            prefix: "vw-access-0123456789abcdef-".into(),
            test_environment: Vec::new(),
        }
    }
    #[test]
    fn exact_typed_manager_contract_and_no_secret_properties() {
        let config = config();
        let name = config.name().unwrap();
        let values = properties(
            &config,
            &name,
            Duration::from_secs(12),
            helper_unset_environment(Vec::new()).unwrap(),
        )
        .unwrap();
        assert_eq!(values.signature().to_string(), "a(sv)");
        let values: HashMap<_, _> = values.into_iter().collect();
        for key in ["BindsTo", "PartOf", "After"] {
            assert_eq!(values[key].0.signature().to_string(), "as");
            assert_eq!(
                values[key].0.as_iter().unwrap().next().unwrap().as_str(),
                Some(config.provider.as_str())
            );
        }
        assert_eq!(values["ExecStart"].0.signature().to_string(), "a(sasb)");
        assert_eq!(values["SendSIGKILL"].0.signature().to_string(), "b");
        for key in ["RuntimeMaxUSec", "TimeoutStartUSec", "TimeoutStopUSec"] {
            assert_eq!(values[key].0.signature().to_string(), "t");
            assert!(values[key].0.as_u64().unwrap() > 0);
        }
        for key in [
            "Environment",
            "EnvironmentFile",
            "EnvironmentFiles",
            "SetEnvironment",
            "LoadCredential",
            "SetCredential",
        ] {
            assert!(!values.contains_key(key));
        }
        assert_eq!(values["KillMode"].0.as_str(), Some("control-group"));
        assert_eq!(values["CollectMode"].0.signature().to_string(), "s");
        assert_eq!(values["CollectMode"].0.as_str(), Some("inactive-or-failed"));
        assert_eq!(values["Type"].0.as_str(), Some("exec"));
        assert!(
            properties(
                &config,
                &name,
                Duration::ZERO,
                helper_unset_environment(Vec::new()).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn proc_inventory_stops_at_the_entry_that_exhausts_the_remaining_budget() {
        let root = tempfile::tempdir().unwrap();
        for name in ["non-process-a", "non-process-b", "non-process-c"] {
            std::fs::write(root.path().join(name), b"").unwrap();
        }
        let mut observations = 0;
        assert_eq!(
            proc_empty_with_budget(root.path(), "/owned", || {
                observations += 1;
                observations < 2
            }),
            Err(ExecutionError::CleanupUncertain)
        );
        assert_eq!(observations, 2, "must stop inside the inventory");
        assert_eq!(
            proc_empty_until(root.path(), "/owned", Instant::now()),
            Err(ExecutionError::CleanupUncertain)
        );
        let empty = tempfile::tempdir().unwrap();
        assert_eq!(
            proc_empty_with_budget(empty.path(), "/owned", || false),
            Err(ExecutionError::CleanupUncertain)
        );
        assert_eq!(
            proc_empty_with_budget(empty.path(), "/owned", || true),
            Ok(true)
        );
    }
    #[test]
    fn helper_environment_is_name_only_complete_and_recovery_stable() {
        let names = helper_unset_environment(vec![
            "PRIVATE_LOGIN=never-copy-this-value".into(),
            "LD_PRELOAD=never-copy-this-value".into(),
            "CUSTOM_RUNTIME=a=b".into(),
        ])
        .unwrap();
        assert!(valid_helper_unset(&names));
        for name in [
            "PRIVATE_LOGIN",
            "LD_PRELOAD",
            "CUSTOM_RUNTIME",
            "GLIBC_TUNABLES",
            "RUST_BACKTRACE",
            "INVOCATION_ID",
        ] {
            assert!(names.iter().any(|value| value == name));
        }
        assert!(
            !names
                .iter()
                .any(|value| value.contains('=') || value.contains("never-copy"))
        );
        let mut changed = helper_unset_environment(vec!["NEW_MANAGER_NAME=value".into()]).unwrap();
        assert_ne!(names, changed);
        assert!(
            valid_helper_unset(&names),
            "recovery does not require today's manager snapshot"
        );
        changed.retain(|name| name != "LD_PRELOAD");
        assert!(!valid_helper_unset(&changed));
        for value in [
            "missing-assignment",
            "=value",
            "0NAME=value",
            "BAD-NAME=value",
        ] {
            assert!(helper_unset_environment(vec![value.into()]).is_err());
        }
        let mut assignment = names.clone();
        assignment.push("NAME=value".into());
        assert!(!valid_helper_unset(&assignment));
        let config = config();
        let values = properties(
            &config,
            &config.name().unwrap(),
            Duration::from_secs(1),
            names.clone(),
        )
        .unwrap();
        let value = &values
            .iter()
            .find(|(key, _)| key == "UnsetEnvironment")
            .unwrap()
            .1;
        assert_eq!(value.0.signature().to_string(), "as");
        let observed: Vec<_> = value
            .0
            .as_iter()
            .unwrap()
            .map(|v| v.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(observed, names);
    }
    #[test]
    fn job_observation_discards_unrelated_churn() {
        let mut jobs = JobObservation {
            unit: "owned.service".into(),
            result: None,
        };
        for id in 0..10_000 {
            jobs.observe(format!("/job/{id}"), "unrelated.service", "done".into());
        }
        assert!(jobs.result.is_none());
        jobs.observe("/job/owned".into(), "owned.service", "done".into());
        jobs.observe("/job/other".into(), "other.service", "failed".into());
        assert_eq!(jobs.result, Some(("/job/owned".into(), "done".into())));
    }
    #[test]
    fn lease_publication_is_atomic_collision_safe_and_recovers_interrupted_staging() {
        let root = tempfile::tempdir().unwrap();
        let mut config = config();
        config.runtime = root.path().to_owned();
        let lease = Lease {
            name: config.name().unwrap(),
            cgroup: "/owned".into(),
        };
        let abandoned = config.staging_path(&lease.name).unwrap();
        let mut partial = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&abandoned)
            .unwrap();
        partial.write_all(b"{\"name\":").unwrap();
        partial.sync_all().unwrap();
        drop(partial);
        let unrelated = root
            .path()
            .join(".staging.unrelated.service.0123456789abcdef0123456789abcdef");
        std::fs::write(&unrelated, b"preserve").unwrap();
        assert!(config.leases().unwrap().is_empty());
        assert!(!abandoned.exists());
        assert!(unrelated.exists());
        config.record(&lease).unwrap();
        let original = std::fs::read(config.lease_path(&lease.name)).unwrap();
        let collision = Lease {
            name: lease.name.clone(),
            cgroup: "/replacement".into(),
        };
        assert!(config.record(&collision).is_err());
        assert_eq!(
            std::fs::read(config.lease_path(&lease.name)).unwrap(),
            original
        );
        // Death after publication but before unlink leaves a complete final record.
        let published_staging = config.staging_path(&lease.name).unwrap();
        std::fs::hard_link(config.lease_path(&lease.name), &published_staging).unwrap();
        let leases = config.leases().unwrap();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].cgroup, "/owned");
        assert!(!published_staging.exists());
        assert!(unrelated.exists());
        assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 2);
    }
    #[test]
    fn incompatible_manager_versions_fail_closed() {
        for value in ["", "systemd 255", "254", "garbage", "999999999999999999999"] {
            assert!(!supported_version(value));
        }
        for value in ["255", "255.4-ubuntu", "256"] {
            assert!(supported_version(value));
        }
    }
    #[test]
    fn strict_ownership_namespace_and_random_names() {
        let config = config();
        let first = config.name().unwrap();
        assert!(config.owns_name(&first));
        assert_ne!(first, config.name().unwrap());
        for name in [
            "vw-access-0123456789abcdef-other.service",
            "vw-access-other-0123456789abcdef0123456789abcdef.service",
            "vw-access-0123456789abcdef-0123456789abcdef0123456789abcdef.service.extra",
            "vw-access-0123456789abcdef-0123456789ABCDEF0123456789abcdef.service",
        ] {
            assert!(!config.owns_name(name));
        }
    }
    #[test]
    fn independent_reaping_observes_zombies_deleted_groups_and_subtrees() {
        let root = tempfile::tempdir().unwrap();
        let non_pid = root.path().join("self");
        std::fs::create_dir(&non_pid).unwrap();
        std::fs::write(non_pid.join("stat"), "not a process stat").unwrap();
        std::fs::write(non_pid.join("cgroup"), "0::/owned\n").unwrap();
        assert!(proc_empty(root.path(), "/owned").unwrap());
        let pid = root.path().join("100");
        std::fs::create_dir(&pid).unwrap();
        let stat = format!(
            "100 (name with ) spaces) Z {} 999 0",
            vec!["0"; 18].join(" ")
        );
        std::fs::write(pid.join("stat"), stat).unwrap();
        for group in [
            "/owned",
            "/owned/child",
            "/owned (deleted)",
            "/owned/child (deleted)",
        ] {
            std::fs::write(pid.join("cgroup"), format!("0::{group}\n")).unwrap();
            assert!(!proc_empty(root.path(), "/owned").unwrap());
        }
        std::fs::write(pid.join("cgroup"), "0::/owned-lookalike\n").unwrap();
        assert!(proc_empty(root.path(), "/owned").unwrap());
        std::fs::write(pid.join("cgroup"), "1:legacy:/owned\n").unwrap();
        assert_eq!(
            proc_empty(root.path(), "/owned"),
            Err(ExecutionError::CleanupUncertain)
        );
        std::fs::remove_file(pid.join("cgroup")).unwrap();
        assert!(proc_empty(root.path(), "/owned").unwrap());
        std::fs::create_dir(pid.join("cgroup")).unwrap();
        assert_eq!(
            proc_empty(root.path(), "/owned"),
            Err(ExecutionError::CleanupUncertain)
        );
    }
}
