//! Disposable, black-box production acceptance. No provider application is
//! constructed here and no lifecycle, policy or pairing files are injected.
#[path = "real_vaultwarden_pilot.rs"]
pub mod pilot;
use aes::cipher::{BlockModeEncrypt, KeyIvInit, block_padding::Pkcs7};
use anyhow::{Context, Result, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use ed25519_dalek::SigningKey;
use hmac::{Hmac, KeyInit, Mac};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    cell::{Cell, RefCell},
    fs::{self, OpenOptions},
    io::{Read, Write},
    os::fd::AsRawFd,
    os::unix::{
        fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        process::CommandExt,
    },
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use vaultwarden_cli::{
    access::protocol::{AgentFailure, AgentRejection, AgentResponse, AgentStatus},
    crypto::{KdfIterations, MasterKey},
};

const UNIT: &str = "vaultwarden-accessd.service";
// Public synthetic fixtures, never passwords belonging to an existing account.
const PASSWORD: &str = "Disposable-Rehearsal-Only!2026";
const FIELD: &str = "disposable-rehearsal-field-v1";
const WRONG_FIELD: &str = "deliberately-wrong-rehearsal-field";
const TARGET: &str = "rehearsal.invalid";
const CAPTURE_LIMIT: usize = 4 * 1024 * 1024;
fn initial_secrets() -> Vec<Vec<u8>> {
    [
        PASSWORD,
        FIELD,
        WRONG_FIELD,
        "deliberately-wrong-synthetic-password",
        "disposable-private-keyring",
        "unused-synthetic-login-password",
    ]
    .into_iter()
    .map(|value| value.as_bytes().to_vec())
    .collect()
}
fn contains_secret(bytes: &[u8], secrets: &[Vec<u8>]) -> bool {
    secrets.iter().any(|secret| {
        !secret.is_empty() && bytes.windows(secret.len()).any(|window| window == secret)
    })
}
struct PrivateCapture {
    fifo: PathBuf,
    file: PathBuf,
    stop: Arc<AtomicBool>,
    failed: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl PrivateCapture {
    fn start(directory: &Path, name: &str) -> Result<Self> {
        let fifo = directory.join(format!("{name}.pipe"));
        let file = directory.join(format!("{name}.capture"));
        let path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())?;
        ensure!(
            unsafe { libc::mkfifo(path.as_ptr(), 0o600) } == 0,
            "private capture pipe unavailable"
        );
        let mut reader = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(&fifo)?;
        let mut destination = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&file)?;
        let stop = Arc::new(AtomicBool::new(false));
        let failed = Arc::new(AtomicBool::new(false));
        let (stopping, failure) = (stop.clone(), failed.clone());
        let worker = std::thread::spawn(move || {
            let mut total = 0usize;
            let mut drain_ticks = 0usize;
            let mut buffer = [0u8; 8192];
            loop {
                if stopping.load(Ordering::Acquire) {
                    drain_ticks += 1;
                    if drain_ticks > 128 {
                        failure.store(true, Ordering::Release);
                        break;
                    }
                }
                match reader.read(&mut buffer) {
                    Ok(0) => {
                        if stopping.load(Ordering::Acquire) {
                            break;
                        }
                    }
                    Ok(count) => {
                        total = total.saturating_add(count);
                        if total > CAPTURE_LIMIT || destination.write_all(&buffer[..count]).is_err()
                        {
                            failure.store(true, Ordering::Release);
                        }
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        if stopping.load(Ordering::Acquire) {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        failure.store(true, Ordering::Release);
                        break;
                    }
                }
            }
            if destination.sync_all().is_err() {
                failure.store(true, Ordering::Release);
            }
        });
        Ok(Self {
            fifo,
            file,
            stop,
            failed,
            worker: Some(worker),
        })
    }
    fn finish(&mut self) -> Result<()> {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            ensure!(worker.join().is_ok(), "private capture worker failed");
        }
        ensure!(
            !self.failed.load(Ordering::Acquire),
            "private output capture overflow or failure"
        );
        Ok(())
    }
}
impl Drop for PrivateCapture {
    fn drop(&mut self) {
        let _result = self.finish();
    }
}
// Preserve every controller byte, including output after the final reply. EOF
// is a separate requirement from reaping the controller process.
struct ControllerOutput {
    reader: Option<std::process::ChildStdout>,
    file: fs::File,
    path: PathBuf,
    total: usize,
    failed: bool,
}
impl ControllerOutput {
    fn new(reader: std::process::ChildStdout, path: PathBuf) -> Result<Self> {
        nonblocking(reader.as_raw_fd())?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        Ok(Self {
            reader: Some(reader),
            file,
            path,
            total: 0,
            failed: false,
        })
    }
    fn read(&mut self, bytes: &mut [u8]) -> Result<Option<usize>> {
        let Some(reader) = self.reader.as_mut() else {
            return Ok(Some(0));
        };
        match reader.read(bytes) {
            Ok(0) => {
                self.reader = None;
                Ok(Some(0))
            }
            Ok(count) => {
                if self.total.saturating_add(count) > CAPTURE_LIMIT {
                    self.failed = true;
                    anyhow::bail!("controller output overflow; private material retained");
                }
                self.total += count;
                if self.file.write_all(&bytes[..count]).is_err() {
                    self.failed = true;
                    anyhow::bail!("controller capture failed; private material retained");
                }
                Ok(Some(count))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                ) =>
            {
                Ok(None)
            }
            Err(_) => {
                self.failed = true;
                anyhow::bail!("controller output observation failed");
            }
        }
    }
    fn finish(&mut self, limit: Duration) -> Result<()> {
        let deadline = Instant::now() + limit;
        while self.reader.is_some() && !self.failed {
            ensure!(
                Instant::now() < deadline,
                "controller output EOF unconfirmed; private material retained"
            );
            if self.read(&mut [0; 8192])?.is_none() {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        self.file.sync_all()?;
        ensure!(
            !self.failed,
            "controller output capture failed; private material retained"
        );
        Ok(())
    }
}
fn path_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => anyhow::bail!("filesystem absence unconfirmed; private material retained"),
    }
}
fn confirm_driver_reaped(
    driver: &mut Option<Child>,
    mut observe: impl FnMut(&mut Child) -> Result<bool>,
) -> Result<()> {
    if let Some(child) = driver.as_mut() {
        ensure!(
            observe(child)?,
            "controller reap unconfirmed; private material retained"
        );
        *driver = None;
    }
    Ok(())
}
// Independently sanitize the child boundary, even if a driver regresses and
// sends exception text or DOM/request data in its purported stage field.
pub fn browser_failure_stage(reply: &Value) -> &'static str {
    match reply["gate"].as_str() {
        Some("startup") => "startup",
        Some("approved-wayland-transport") => "approved-wayland-transport",
        Some("private-xauthority") => "private-xauthority",
        Some("private-xserver") => "private-xserver",
        Some("private-browser-trust") => "private-browser-trust",
        Some("private-firefox") => "private-firefox",
        Some("real-xdg-open") => "real-xdg-open",
        Some("firefox-desktop-handoff") => "firefox-desktop-handoff",
        Some("human-guide") => "human-guide",
        Some("provider-open") => "provider-open",
        Some("provider-unlock") => "provider-unlock",
        Some("request-find") => "request-find",
        Some("request-pending") => "request-pending",
        Some("request-details") => "request-details",
        Some("human-decision") => "human-decision",
        Some("request-submit") => "request-submit",
        Some("request-terminal") => "request-terminal",
        Some("request-replay") => "request-replay",
        Some("protocol") => "protocol",
        _ => "unspecified",
    }
}

#[derive(Clone, Copy)]
pub enum AgentAction {
    Submit,
    Poll,
}
impl AgentAction {
    fn label(self) -> &'static str {
        match self {
            Self::Submit => "submit",
            Self::Poll => "poll",
        }
    }
}

// Parse the closed production protocol before constructing a diagnostic. Never
// format response bytes, identifiers, or serde errors, even for malformed JSON.
// The caller must run its secret-redaction gate before invoking this parser.
pub fn agent_response(action: AgentAction, bytes: &[u8]) -> Result<Value> {
    let invalid = || anyhow::anyhow!("restricted agent {} response invalid", action.label());
    let response = AgentResponse::parse(bytes).map_err(|_error| invalid())?;
    if let AgentResponse::Rejected { category, .. } = response {
        let category = match category {
            AgentRejection::Unauthorized => "unauthorized",
            AgentRejection::Malformed => "malformed",
            AgentRejection::UnsupportedVersion => "unsupported_version",
            AgentRejection::Replay => "replay",
            AgentRejection::StaleRevision => "stale_revision",
            AgentRejection::InvalidArguments => "invalid_arguments",
            AgentRejection::Locked => "locked",
            AgentRejection::Busy => "busy",
            AgentRejection::Unavailable => "unavailable",
        };
        anyhow::bail!("restricted agent {} rejected: {category}", action.label());
    }
    serde_json::to_value(response).map_err(|_error| invalid())
}

pub fn agent_terminal_status(state: &Value, expected: &AgentStatus) -> Result<bool> {
    ensure!(expected.is_terminal(), "rehearsal expected status invalid");
    let state: AgentStatus = serde_json::from_value(state.clone())
        .map_err(|_error| anyhow::anyhow!("restricted agent poll status invalid"))?;
    if !state.is_terminal() {
        return Ok(false);
    }
    ensure!(
        state == *expected,
        "restricted agent poll terminal status mismatch"
    );
    Ok(true)
}

// Agent responses have already passed redaction and strict protocol parsing.
// A terminal mismatch is final: another poll cannot make the observation match.
pub fn wait_for_agent_terminal(
    mut poll: impl FnMut() -> Result<Value>,
    expected: &AgentStatus,
) -> Result<()> {
    wait_for(|| agent_terminal_status(&poll()?["state"], expected))
}
static INTERRUPTED: AtomicBool = AtomicBool::new(false);
static PROCESS_CLEANUP_UNCERTAIN: AtomicBool = AtomicBool::new(false);
extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::Relaxed);
}

fn command(program: impl AsRef<std::ffi::OsStr>) -> Command {
    let mut cmd = Command::new(program);
    cmd.env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

// Nonblocking pipes share one absolute deadline. There are no writer/reader
// threads to strand, and no blocking write_all(), wait() or thread joins.
fn output(cmd: &mut Command, input: Option<&[u8]>, seconds: u64) -> Result<Output> {
    output_limit(cmd, input, Duration::from_secs(seconds))
}
fn nonblocking(fd: i32) -> Result<()> {
    // SAFETY: fcntl validates the live owned pipe descriptor.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(
        flags >= 0 && unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0,
        "pipe setup failed"
    );
    Ok(())
}
fn read_available(pipe: &mut Option<impl Read>, bytes: &mut Vec<u8>) -> Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0u8; 8192];
    // Bound work per tick even when a child writes continuously.
    for _ in 0..8 {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(count) => {
                ensure!(
                    bytes.len() + count <= 4 * 1024 * 1024,
                    "command output bound"
                );
                bytes.extend_from_slice(&buffer[..count]);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}
fn exited_unreaped(pid: libc::pid_t) -> Result<bool> {
    let mut info = std::mem::MaybeUninit::<libc::siginfo_t>::zeroed();
    // Keep the group leader waitable until after killpg, so its numeric PGID
    // cannot be recycled underneath cleanup.
    ensure!(
        unsafe {
            libc::waitid(
                libc::P_PID,
                pid as u32,
                info.as_mut_ptr(),
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
            )
        } == 0,
        "child observation failed"
    );
    Ok(unsafe { info.assume_init().si_pid() } == pid)
}
fn stop_group(child: &mut Child) -> Result<std::process::ExitStatus> {
    let pid = libc::pid_t::try_from(child.id())?;
    // Only the fresh session/group made by this invocation is addressed.
    let _signal_result = unsafe { libc::kill(-pid, libc::SIGKILL) };
    let deadline = Instant::now() + Duration::from_secs(3);
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        ensure!(Instant::now() < deadline, "command leader reap deadline");
        std::thread::sleep(Duration::from_millis(5));
    };
    loop {
        let mut status = 0;
        // Reap only adopted descendants in this exact owned process group.
        let reaped = unsafe { libc::waitpid(-pid, &raw mut status, libc::WNOHANG) };
        if reaped > 0 {
            continue;
        }
        if unsafe { libc::kill(-pid, 0) } < 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
        {
            break;
        }
        ensure!(
            Instant::now() < deadline,
            "command descendants reap deadline"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    Ok(status)
}
fn output_limit(cmd: &mut Command, input: Option<&[u8]>, limit: Duration) -> Result<Output> {
    if input.is_some() {
        cmd.stdin(Stdio::piped());
    }
    // Become a subreaper so ordinary grandchildren in the command's session
    // can be reaped explicitly; other process groups are never waited/killed.
    ensure!(
        unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) } == 0,
        "subreaper unavailable"
    );
    unsafe {
        cmd.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("spawn prerequisite/owned command")?;
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let mut stdin = child.stdin.take();
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut offset = 0;
    let result = (|| -> Result<()> {
        for fd in [
            stdout.as_ref().map(AsRawFd::as_raw_fd),
            stderr.as_ref().map(AsRawFd::as_raw_fd),
            stdin.as_ref().map(AsRawFd::as_raw_fd),
        ]
        .into_iter()
        .flatten()
        {
            nonblocking(fd)?;
        }
        let deadline = Instant::now() + limit;
        loop {
            ensure!(Instant::now() < deadline, "bounded command deadline");
            read_available(&mut stdout, &mut out)?;
            read_available(&mut stderr, &mut err)?;
            if let (Some(pipe), Some(input)) = (stdin.as_mut(), input) {
                if offset < input.len() {
                    match pipe.write(&input[offset..input.len().min(offset + 8192)]) {
                        Ok(0) => anyhow::bail!("command stdin closed"),
                        Ok(count) => offset += count,
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                            ) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if offset == input.len() {
                    stdin = None;
                }
            }
            if exited_unreaped(child.id() as libc::pid_t)? && stdout.is_none() && stderr.is_none() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    drop(stdin);
    let status = stop_group(&mut child).inspect_err(|_error| {
        PROCESS_CLEANUP_UNCERTAIN.store(true, Ordering::Relaxed);
    })?;
    // A writer that escaped the owned group must not turn timeout into a
    // successful cleanup claim. Never wait indefinitely for its pipe EOF.
    if result.is_err() {
        let deadline = Instant::now() + Duration::from_millis(200);
        while Instant::now() < deadline && (stdout.is_some() || stderr.is_some()) {
            let _out = read_available(&mut stdout, &mut Vec::new());
            let _err = read_available(&mut stderr, &mut Vec::new());
            std::thread::sleep(Duration::from_millis(5));
        }
        if stdout.is_some() || stderr.is_some() {
            PROCESS_CLEANUP_UNCERTAIN.store(true, Ordering::Relaxed);
        }
    }
    result?;
    Ok(Output {
        status,
        stdout: out,
        stderr: err,
    })
}
fn checked(cmd: &mut Command) -> Result<Vec<u8>> {
    let out = output(cmd, None, 30)?;
    ensure!(out.status.success(), "bounded command rejected");
    Ok(out.stdout)
}
fn text(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)?.trim().to_owned())
}
fn restricted() -> Command {
    let mut cmd = command("/usr/bin/unshare");
    cmd.args([
        "--user",
        "--map-root-user",
        "--map-auto",
        "--setgroups=allow",
        "--",
        "/usr/bin/setpriv",
        "--reuid=1",
        "--regid=0",
        "--clear-groups",
        "--bounding-set=-all",
        "--inh-caps=-all",
        "--ambient-caps=-all",
        "--no-new-privs",
    ]);
    cmd
}
fn require_restricted_traversal(path: &Path) -> Result<()> {
    ensure!(
        output(
            restricted().args(["/usr/bin/test", "-x"]).arg(path),
            None,
            5
        )?
        .status
        .success(),
        "restricted identity cannot traverse rehearsal home; no resources provisioned"
    );
    Ok(())
}

pub fn restricted_traversal_regression() -> Result<()> {
    ensure!(unsafe { libc::geteuid() } != 0, "never run as host root");
    ensure!(
        checked(restricted().args(["/usr/bin/id", "-u"]))? == b"1\n",
        "restricted test identity unavailable"
    );
    // Use only owned, empty directories beneath /tmp, independently of HOME and
    // the secure-temp wrapper. A private ancestor must block even a 0755 child.
    let root = tempfile::Builder::new()
        .prefix("vw-traversal-regression-")
        .tempdir_in("/tmp")?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))?;
    let private = root.path().join("private");
    directory(&private, 0o700)?;
    let child = private.join("child");
    directory(&child, 0o755)?;
    require_restricted_traversal(root.path())?;
    let rejected = require_restricted_traversal(&child)
        .err()
        .context("inaccessible ancestor accepted")?;
    ensure!(
        rejected.to_string()
            == "restricted identity cannot traverse rehearsal home; no resources provisioned",
        "wrong restricted traversal failure"
    );
    // The same namespace and target must pass after changing only our fixture.
    fs::set_permissions(&private, fs::Permissions::from_mode(0o755))?;
    require_restricted_traversal(&child)?;
    let path = root.path().to_owned();
    root.close()?;
    assert_absent(&path)?;
    Ok(())
}
fn private_file(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(data)?;
    Ok(())
}
fn directory(path: &Path, mode: u32) -> Result<()> {
    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    Ok(())
}
fn wait_for(mut condition: impl FnMut() -> Result<bool>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    while !condition()? {
        ensure!(!INTERRUPTED.load(Ordering::Relaxed), "interrupted");
        ensure!(Instant::now() < deadline, "readiness deadline exceeded");
        std::thread::sleep(Duration::from_millis(50));
    }
    Ok(())
}
pub fn subordinate_id(map: &str, user: &str) -> Option<u32> {
    map.lines().find_map(|line| {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 3 || fields[0] != user {
            return None;
        }
        let start = fields[1].parse::<u32>().ok()?;
        let count = fields[2].parse::<u32>().ok()?;
        (start >= 65536 && count > 0 && start.checked_add(count).is_some()).then_some(start)
    })
}
fn manager() -> Command {
    let mut cmd = command("/usr/bin/systemctl");
    cmd.args(["--user"])
        .env(
            "XDG_RUNTIME_DIR",
            format!("/run/user/{}", unsafe { libc::geteuid() }),
        )
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{}/bus", unsafe { libc::geteuid() }),
        );
    cmd
}
fn property(unit: &str, name: &str) -> Result<String> {
    text(checked(manager().args([
        "show",
        unit,
        "--value",
        &format!("--property={name}"),
    ]))?)
}
fn safe_home(path: &Path) -> Result<()> {
    ensure!(path.is_absolute(), "absolute home required");
    for ancestor in path.ancestors() {
        let m = fs::symlink_metadata(ancestor)?;
        ensure!(
            m.is_dir()
                && !m.file_type().is_symlink()
                && m.mode() & 0o7022 == 0
                && [0, unsafe { libc::geteuid() }].contains(&m.uid()),
            "unsafe home ancestry"
        );
    }
    ensure!(
        fs::metadata(path)?.uid() == unsafe { libc::geteuid() },
        "home ownership"
    );
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnedUnit {
    name: String,
    invocation: String,
    cgroup: PathBuf,
}

// Captured before cleanup and verified by the acceptance caller afterward.
// No cleanup return flag or mutable resource inventory is evidence of removal.
struct CleanupObservation {
    root: PathBuf,
    units: Vec<OwnedUnit>,
    container: Option<String>,
    runtime: Option<PathBuf>,
    driver_pid: Option<u32>,
}
fn assert_absent(path: &Path) -> Result<()> {
    ensure!(
        matches!(fs::symlink_metadata(path), Err(error)
        if error.kind() == std::io::ErrorKind::NotFound),
        "post-cleanup resource still present or absence unconfirmed"
    );
    Ok(())
}
fn cleanup_container(
    id: &str,
    owner: &str,
    mut run: impl FnMut(&[&str]) -> Result<Output>,
) -> Result<()> {
    let filter = format!("id={id}");
    let query = ["ps", "--all", "--quiet", "--no-trunc", "--filter", &filter];
    let before = run(&query)?;
    ensure!(
        before.status.success(),
        "container absence unconfirmed; material retained"
    );
    let present = text(before.stdout)?;
    if present.is_empty() {
        return Ok(());
    }
    ensure!(
        present == id,
        "container identity mismatch; material retained"
    );
    let label = run(&[
        "inspect",
        "--format",
        "{{index .Config.Labels \"vw.rehearsal\"}}",
        id,
    ])?;
    ensure!(
        label.status.success() && text(label.stdout)? == owner,
        "container ownership changed"
    );
    let _removal = run(&["rm", "--force", id])?;
    let after = run(&query)?;
    ensure!(
        after.status.success() && after.stdout.is_empty(),
        "container absence unconfirmed; material retained"
    );
    Ok(())
}
impl CleanupObservation {
    fn capture(run: &Rehearsal) -> Self {
        Self {
            root: run.root.clone(),
            units: run.units.clone(),
            container: run.container.clone(),
            runtime: run.runtime_owned.then(|| run.runtime.clone()),
            driver_pid: run.driver.as_ref().map(Child::id),
        }
    }
    fn verify(&self) -> Result<()> {
        assert_absent(&self.root)?;
        if let Some(runtime) = &self.runtime {
            assert_absent(runtime)?;
        }
        if let Some(pid) = self.driver_pid {
            assert_absent(Path::new(&format!("/proc/{pid}")))?;
        }
        for unit in &self.units {
            ensure!(
                property(&unit.name, "LoadState")? == "not-found",
                "post-cleanup unit still present"
            );
            assert_absent(&unit.cgroup)?;
        }
        if let Some(id) = &self.container {
            let mut docker = command("/usr/bin/docker");
            docker
                .env("DOCKER_HOST", "unix:///var/run/docker.sock")
                .env("DOCKER_CONFIG", self.root.join("private/docker"))
                .args([
                    "ps",
                    "--all",
                    "--quiet",
                    "--no-trunc",
                    "--filter",
                    &format!("id={id}"),
                ]);
            ensure!(
                checked(&mut docker)?.is_empty(),
                "post-cleanup container still present"
            );
        }
        Ok(())
    }
}
struct Rehearsal {
    root: PathBuf,
    uid: u32,
    gid: u32,
    agent_uid: u32,
    units: Vec<OwnedUnit>,
    container: Option<String>,
    driver: Option<Child>,
    driver_lines: Option<ControllerOutput>,
    runtime: PathBuf,
    runtime_owned: bool,
    cleaned: bool,
    ownership_uncertain: bool,
    secrets: Vec<Vec<u8>>,
    evidence: RefCell<Vec<Vec<u8>>>,
    fail_provider_stop: bool,
    fail_provider_reap: bool,
    fail_after_container_removal: bool,
    human_display: Option<PathBuf>,
    human_mode: bool,
    captures: Vec<PrivateCapture>,
    leaked: Cell<bool>,
}
impl Rehearsal {
    fn observe(&self, bytes: &[u8]) -> Result<()> {
        let mut evidence = self.evidence.borrow_mut();
        if evidence.iter().map(Vec::len).sum::<usize>() + bytes.len() > 32 * 1024 * 1024 {
            self.leaked.set(true);
            anyhow::bail!("private observation bound exceeded; material retained");
        }
        evidence.push(bytes.to_vec());
        self.redacted(bytes)
    }
    fn capture(&mut self, name: &str) -> Result<PathBuf> {
        let capture_directory = self.root.join("captures");
        if !capture_directory.exists() {
            directory(&capture_directory, 0o700)?;
        }
        let capture = PrivateCapture::start(&capture_directory, name)?;
        let fifo = capture.fifo.clone();
        self.captures.push(capture);
        Ok(fifo)
    }
    fn ledger(&self, event: &str, resource: &str) -> Result<()> {
        self.ledger_record(&json!({"event":event,"resource":resource}))
    }
    fn ledger_record(&self, record: &Value) -> Result<()> {
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(self.root.join("ownership.jsonl"))?;
        writeln!(file, "{record}")?;
        file.sync_all()?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
    fn record_unit(&mut self, unit: OwnedUnit) -> Result<()> {
        self.units.push(unit.clone());
        self.ledger_record(&json!({"event":"owned-unit","resource":unit.name,"unit":unit}))?;
        self.ownership_uncertain = false;
        Ok(())
    }
    fn recorded_units(&self) -> Result<Vec<OwnedUnit>> {
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(self.root.join("ownership.jsonl"))?;
        let meta = file.metadata()?;
        ensure!(
            meta.is_file()
                && meta.uid() == self.uid
                && meta.mode() & 0o777 == 0o600
                && meta.nlink() == 1
                && meta.len() <= 1024 * 1024,
            "unsafe ownership ledger"
        );
        let mut data = String::new();
        file.read_to_string(&mut data)?;
        let tag = self
            .root
            .file_name()
            .context("root name")?
            .to_string_lossy();
        let tag = tag.trim_start_matches('.');
        let mut units = Vec::new();
        for line in data.lines() {
            let record: Value = serde_json::from_str(line)?;
            if record["event"] == "retired-unit" {
                let retired: OwnedUnit = serde_json::from_value(record["unit"].clone())?;
                // A pilot may bootstrap and later restart the fixed provider.
                // Retirement removes only an exact previously recorded lifetime;
                // unmatched or repeated retirement is never accepted.
                let position = units
                    .iter()
                    .position(|unit| unit == &retired)
                    .context("unowned or already retired ledger unit")?;
                ensure!(retired.name == UNIT, "only provider bootstrap may retire");
                units.remove(position);
                continue;
            }
            if record["event"] != "owned-unit" {
                continue;
            }
            let unit: OwnedUnit = serde_json::from_value(record["unit"].clone())?;
            ensure!(
                unit.name == UNIT
                    || ["bus", "keyring", "browser"]
                        .iter()
                        .any(|suffix| unit.name == format!("{tag}-{suffix}.service")),
                "unowned ledger unit"
            );
            ensure!(
                unit.invocation.len() == 32
                    && unit.invocation.bytes().all(|b| b.is_ascii_hexdigit())
                    && unit.cgroup.starts_with("/sys/fs/cgroup/user.slice")
                    && unit
                        .cgroup
                        .file_name()
                        .is_some_and(|leaf| leaf == unit.name.as_str())
                    && !unit.cgroup.components().any(|part| matches!(
                        part,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    ))
                    && !units.iter().any(|old: &OwnedUnit| old.name == unit.name),
                "invalid ownership record"
            );
            units.push(unit);
        }
        Ok(units)
    }
    fn env(&self, cmd: &mut Command) {
        cmd.env("HOME", self.root.join("private"))
            .env("XDG_CONFIG_HOME", self.root.join("private/.config"))
            .env("XDG_DATA_HOME", self.root.join("private/.local/share"))
            .env("XDG_CACHE_HOME", self.root.join("private/cache"))
            .env("XDG_RUNTIME_DIR", self.root.join("private/runtime"))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}/private/bus", self.root.display()),
            )
            .env(
                "DBUS_SYSTEM_BUS_ADDRESS",
                format!("unix:path={}/private/no-system-bus", self.root.display()),
            );
    }
    fn docker(&self) -> Command {
        let mut cmd = command("/usr/bin/docker");
        cmd.env("DOCKER_HOST", "unix:///var/run/docker.sock")
            .env("DOCKER_CONFIG", self.root.join("private/docker"));
        cmd
    }
    fn start_unit(&mut self, name: &str, args: &[String]) -> Result<()> {
        ensure!(
            property(name, "LoadState")? == "not-found",
            "existing unit collision"
        );
        self.ledger("intent-unit", name)?;
        self.ownership_uncertain = true;
        // Keep distinct bounded captures when the pilot restarts an owned unit.
        let capture_generation = self.captures.len();
        let stdout = self.capture(&format!("{name}-{capture_generation}-stdout"))?;
        let stderr = self.capture(&format!("{name}-{capture_generation}-stderr"))?;
        let mut cmd = command("/usr/bin/systemd-run");
        cmd.arg(format!(
            "--property=StandardOutput=file:{}",
            stdout.display()
        ))
        .arg(format!(
            "--property=StandardError=file:{}",
            stderr.display()
        ));
        if name.ends_with("-keyring.service") {
            cmd.arg(format!(
                "--property=StandardInput=file:{}/private/keyring-input",
                self.root.display()
            ));
        }
        cmd.env("XDG_RUNTIME_DIR", format!("/run/user/{}", self.uid))
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path=/run/user/{}/bus", self.uid),
            )
            .args([
                "--user",
                "--quiet",
                "--collect",
                "--service-type=exec",
                "--unit",
                name,
                "--property=KillMode=control-group",
                "--property=TimeoutStopSec=10",
                "--property=UMask=0077",
                "--",
                "/usr/bin/env",
                "-i",
                "PATH=/usr/bin:/bin",
            ])
            .args(args);
        checked(&mut cmd)?;
        let invocation = property(name, "InvocationID")?;
        let cg = property(name, "ControlGroup")?;
        ensure!(
            !invocation.is_empty() && cg.starts_with("/user.slice/"),
            "unit ownership unconfirmed"
        );
        self.record_unit(OwnedUnit {
            name: name.into(),
            invocation,
            cgroup: PathBuf::from("/sys/fs/cgroup").join(cg.trim_start_matches('/')),
        })?;
        Ok(())
    }
    fn service_env(&self) -> Vec<String> {
        let mut cmd = command("unused");
        self.env(&mut cmd);
        cmd.get_envs()
            .filter_map(|(k, v)| {
                v.map(|v| format!("{}={}", k.to_string_lossy(), v.to_string_lossy()))
            })
            .collect()
    }
    fn cli(&self, args: &[&str]) -> Result<Value> {
        let mut cmd = command(self.root.join("bin/vw-access"));
        self.env(&mut cmd);
        cmd.arg("--state-root")
            .arg(self.root.join("private/state"))
            .args(args);
        let out = output(&mut cmd, None, 30)?;
        self.observe(&out.stderr)?;
        self.observe(&out.stdout)?;
        ensure!(out.status.success(), "human CLI rejected");
        let bytes = out.stdout;
        self.redacted(&bytes)?;
        Ok(serde_json::from_slice(&bytes)?)
    }
    fn agent(&self, action: AgentAction, args: &[&str]) -> Result<Value> {
        let mut cmd = restricted();
        cmd.arg(self.root.join("bin/vw-access"))
            .arg(action.label())
            .args(args);
        let out = output(&mut cmd, None, 30).map_err(|_error| {
            anyhow::anyhow!("restricted agent {} transport failed", action.label())
        })?;
        self.observe(&out.stderr)?;
        self.observe(&out.stdout)?;
        ensure!(
            matches!(out.status.code(), Some(0 | 1)) && out.stderr.is_empty(),
            "restricted agent {} transport failed",
            action.label()
        );
        let bytes = out.stdout;
        self.redacted(&bytes)?;
        let response = agent_response(action, &bytes)?;
        Ok(response)
    }
    fn redacted(&self, bytes: &[u8]) -> Result<()> {
        if contains_secret(bytes, &self.secrets) {
            self.leaked.set(true);
            anyhow::bail!("redaction gate failed; private material retained");
        }
        Ok(())
    }
    fn redacted_output(&self, bytes: &[u8]) -> Result<()> {
        self.redacted(bytes)?;
        // This stream has no public digest fields. Fail closed on consumed
        // one-use capabilities and rotated keys without recovering their proofs.
        if bytes
            .split(|byte| !(byte.is_ascii_alphanumeric() || b"_-".contains(byte)))
            .any(|word| word.len() >= 43)
        {
            self.leaked.set(true);
            anyhow::bail!("authority-shaped private output; material retained");
        }
        Ok(())
    }
    fn browser(&mut self, request: Value) -> Result<Value> {
        let driver = self.driver.as_mut().context("private browser absent")?;
        let input = driver.stdin.as_mut().context("private browser input")?;
        serde_json::to_writer(&mut *input, &request)?;
        input.write_all(b"\n")?;
        input.flush()?;
        let mut line = String::new();
        // Node bounds each operation. Its error response contains no browser
        // URL, request body, DOM dump, screenshot, or captured password.
        let reader = self.driver_lines.as_mut().context("browser output")?;
        let deadline = Instant::now() + Duration::from_secs(if self.human_mode { 335 } else { 65 });
        let observation = (|| -> Result<()> {
            loop {
                ensure!(
                    Instant::now() < deadline && !INTERRUPTED.load(Ordering::Relaxed),
                    "browser response deadline"
                );
                // Consume one byte: a partial line cannot defeat the bound.
                let mut byte = [0u8; 1];
                if let Some(count) = reader.read(&mut byte)? {
                    ensure!(count == 1, "browser exited");
                    if byte[0] == b'\n' {
                        break;
                    }
                    ensure!(
                        line.len() < 1024 && byte[0].is_ascii(),
                        "invalid browser response"
                    );
                    line.push(char::from(byte[0]));
                } else {
                    std::thread::sleep(Duration::from_millis(5));
                }
            }
            Ok(())
        })();
        self.observe(line.as_bytes())?;
        self.redacted_output(line.as_bytes())?;
        if observation.is_err() {
            self.leaked.set(true);
        }
        observation?;
        let reply: Value = serde_json::from_str(&line)
            .map_err(|_error| anyhow::anyhow!("invalid browser response"))?;
        ensure!(
            reply["ok"] == true,
            "private browser gate failed at {}",
            browser_failure_stage(&reply)
        );
        Ok(reply)
    }
    fn cleanup(&mut self) -> Result<()> {
        if self.cleaned {
            return Ok(());
        }
        let mut good =
            !self.ownership_uncertain && !PROCESS_CLEANUP_UNCERTAIN.load(Ordering::Relaxed);
        ensure!(
            self.recorded_units()? == self.units,
            "ownership ledger mismatch; material retained"
        );
        // Stop provider before browser/keyring. BindsTo/PartOf stops contained
        // helpers; every recorded cgroup must be empty before material deletion.
        for unit in self.units.iter().rev() {
            let state = property(&unit.name, "LoadState");
            if !matches!(state.as_deref(), Ok("not-found")) {
                if !property(&unit.name, "InvocationID").is_ok_and(|id| id == unit.invocation) {
                    good = false;
                    continue;
                }
                if unit.name == UNIT && self.fail_provider_stop {
                    self.ledger("injected-stop-failure", UNIT)?;
                    anyhow::bail!("injected stop failure; material retained");
                }
                if checked(manager().args(["stop", &unit.name])).is_err() {
                    good = false;
                    continue;
                }
            }
            if unit.name == UNIT && self.fail_provider_reap {
                self.ledger("injected-reap-observation-failure", UNIT)?;
                anyhow::bail!("injected reap observation failure; material retained");
            }
            if wait_for(|| {
                Ok(!path_present(&unit.cgroup)?
                    || fs::read_to_string(unit.cgroup.join("cgroup.events"))?
                        .lines()
                        .any(|line| line == "populated 0"))
            })
            .is_err()
            {
                good = false;
            }
        }
        let reaped = confirm_driver_reaped(&mut self.driver, |child| {
            drop(child.stdin.take());
            let deadline = Instant::now() + Duration::from_secs(15);
            loop {
                match child.try_wait() {
                    Ok(Some(_)) => return Ok(true),
                    _ if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(30)),
                    _ => {
                        let _kill = child.kill();
                        let reap_deadline = Instant::now() + Duration::from_secs(3);
                        loop {
                            if matches!(child.try_wait(), Ok(Some(_))) {
                                return Ok(true);
                            }
                            if Instant::now() >= reap_deadline {
                                return Ok(false);
                            }
                            std::thread::sleep(Duration::from_millis(10));
                        }
                    }
                }
            }
        });
        if reaped.is_err() {
            good = false;
        }
        if let Some(capture) = self.driver_lines.as_mut()
            && capture.finish(Duration::from_secs(3)).is_err()
        {
            good = false;
        }
        if let Some(id) = &self.container {
            cleanup_container(
                id,
                &self.root.file_name().unwrap().to_string_lossy(),
                |args| output(self.docker().args(args), None, 10),
            )?;
            ensure!(
                !self.fail_after_container_removal,
                "injected post-removal failure; material retained"
            );
        }
        // The supervisor namespace was checked absent before startup. A live
        // helper or retained lease is cleanup failure, even if the provider died.
        if path_present(&self.runtime)?
            && (!self.runtime_owned || fs::read_dir(&self.runtime)?.next().is_some())
        {
            good = false;
        }
        self.ledger(
            if good {
                "cleanup-confirmed"
            } else {
                "cleanup-uncertain"
            },
            "owned-resources",
        )?;
        ensure!(good, "cleanup uncertain; private directory retained");
        let xauthority = self.root.join("private/Xauthority");
        if path_present(&xauthority)? {
            // This private query registers the synthetic display credential;
            // its raw output is never published or treated as redacted evidence.
            let authority = output(
                command("/usr/bin/xauth")
                    .arg("-f")
                    .arg(xauthority)
                    .arg("list"),
                None,
                10,
            )?;
            ensure!(
                authority.status.success(),
                "display credential audit failed; material retained"
            );
            let listing = std::str::from_utf8(&authority.stdout)
                .map_err(|_error| anyhow::anyhow!("invalid display credential audit"))?;
            ensure!(
                !listing.trim().is_empty(),
                "empty display credential audit; material retained"
            );
            let mut audit = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(self.root.join("private/Xauthority.audit"))?;
            audit.write_all(&authority.stdout)?;
            audit.sync_all()?;
            for line in listing.lines() {
                let cookie = line
                    .split_whitespace()
                    .last()
                    .context("missing display credential")?;
                ensure!(
                    cookie.len() == 32 && cookie.bytes().all(|byte| byte.is_ascii_hexdigit()),
                    "invalid display credential audit"
                );
                self.secrets.push(cookie.to_ascii_lowercase().into_bytes());
                self.secrets.push(cookie.to_ascii_uppercase().into_bytes());
                self.secrets.push(
                    (0..32)
                        .step_by(2)
                        .map(|index| u8::from_str_radix(&cookie[index..index + 2], 16))
                        .collect::<std::result::Result<Vec<_>, _>>()?,
                );
            }
            self.observe(&authority.stderr)?;
            self.redacted_output(&authority.stderr)?;
        }
        for capture in &mut self.captures {
            capture.finish()?;
        }
        for capture in &self.captures {
            let bytes = fs::read(&capture.file)?;
            self.redacted_output(&bytes)?;
        }
        if let Some(capture) = &self.driver_lines {
            self.redacted_output(&fs::read(&capture.path)?)?;
        }
        for record in self.evidence.borrow().iter() {
            self.redacted(record)?;
        }
        ensure!(
            !self.leaked.get(),
            "redaction failure; private material retained"
        );
        println!(
            "PASS: bounded private stdout/stderr and redacted observations scanned before deletion"
        );
        if self.runtime_owned && path_present(&self.runtime)? {
            fs::remove_dir(&self.runtime)?;
        }
        if path_present(&self.root.join("agent"))?
            && fs::metadata(self.root.join("agent"))?.uid() == self.agent_uid
        {
            checked(
                restricted()
                    .args(["/bin/rm", "-f", "--"])
                    .arg(self.root.join("agent/key")),
            )?;
            fs::remove_dir(self.root.join("agent"))?;
        }
        fs::remove_dir_all(&self.root)?;
        self.cleaned = true;
        println!("PASS: owned processes/units/container stopped before private files removed");
        Ok(())
    }
}
impl Drop for Rehearsal {
    fn drop(&mut self) {
        if !self.cleaned && self.cleanup().is_err() {
            eprintln!(
                "FAIL: cleanup uncertain; retained private ownership ledger at {}",
                self.root.display()
            );
        }
    }
}

fn compile_checker(path: &Path) -> Result<()> {
    checked(
        command("/usr/bin/cc")
            .args([
                "-nostdlib",
                "-static",
                "-no-pie",
                "-fno-stack-protector",
                "-fno-builtin",
                "-O2",
                "-Wl,--build-id=none",
                "-o",
            ])
            .arg(path)
            .arg(
                Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/protected-credential-check.c"),
            ),
    )?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o500))?;
    Ok(())
}
pub fn check_fixture() -> Result<()> {
    let root = tempfile::tempdir()?;
    let binary = root.path().join("check");
    compile_checker(&binary)?;
    for (target, field, ambient, success) in [
        (TARGET, Some(FIELD), false, true),
        (TARGET, Some(WRONG_FIELD), false, false),
        (TARGET, None, false, false),
        ("other.invalid", Some(FIELD), false, false),
        (TARGET, Some(FIELD), true, false),
    ] {
        let mut cmd = command(&binary);
        cmd.env_clear().arg(target);
        if let Some(field) = field {
            cmd.env("REHEARSAL_CREDENTIAL", field);
        }
        if ambient {
            cmd.env("UNREVIEWED", "1");
        }
        let out = output(&mut cmd, None, 5)?;
        ensure!(
            out.status.success() == success && out.stdout.is_empty() && out.stderr.is_empty(),
            "checker semantic gate"
        );
    }
    Ok(())
}

pub fn bounded_pipes_regression() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (index, script, input) in [
        (
            0,
            "printf '%s' $$ > \"$1\"; exec /bin/sleep 30",
            Some(vec![b'x'; 1024 * 1024]),
        ),
        (1, "/bin/sleep 30 & printf '%s' $! > \"$1\"; exit 0", None),
        (
            2,
            "printf '%s' $$ > \"$1\"; trap '' TERM; while :; do printf 'bounded-output'; done",
            None,
        ),
    ] {
        let pidfile = root.path().join(format!("{index}.pid"));
        let mut cmd = command("/bin/sh");
        cmd.args(["-c", script, "pipe-regression"]).arg(&pidfile);
        let started = Instant::now();
        ensure!(
            output_limit(&mut cmd, input.as_deref(), Duration::from_millis(150)).is_err(),
            "hanging command unexpectedly passed"
        );
        ensure!(
            started.elapsed() < Duration::from_secs(2),
            "command bound exceeded"
        );
        let pid = fs::read_to_string(pidfile)?.parse::<i32>()?;
        ensure!(
            !Path::new(&format!("/proc/{pid}")).exists(),
            "owned command/descendant not reaped"
        );
    }
    ensure!(
        !PROCESS_CLEANUP_UNCERTAIN.load(Ordering::Relaxed),
        "ordinary owned pipe holders not cleaned"
    );
    Ok(())
}

fn prerequisite_failure(mode: &str, missing: Option<&str>) -> Result<()> {
    let mut cmd = command("/bin/bash");
    cmd.arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("scripts/rehearse-protected-workflow.sh"))
        .arg(mode);
    for name in [
        "PATH",
        "HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "VW_REHEARSAL_XVFB",
        "VW_REHEARSAL_CERTUTIL",
        "VW_REHEARSAL_FIREFOX",
        "VW_REHEARSAL_UI_DEPS",
    ] {
        if let Some(value) = std::env::var_os(name) {
            cmd.env(name, value);
        }
    }
    if let Some(name) = missing {
        cmd.env(name, "/definitely-absent-rehearsal-prerequisite");
    }
    let out = output(&mut cmd, None, 10)?;
    ensure!(!out.status.success(), "invalid prerequisite accepted");
    let expected = if missing.is_some() {
        "FAIL: private desktop dependency unavailable"
    } else {
        "FAIL: occupied or unavailable provider unit"
    };
    ensure!(
        String::from_utf8(out.stdout)?.contains(expected),
        "wrong fail-closed gate"
    );
    Ok(())
}

pub fn missing_prerequisite_regression() -> Result<()> {
    prerequisite_failure("--automated", Some("VW_REHEARSAL_XVFB"))
}

pub fn cleanup_removal_regression() -> Result<()> {
    let root = tempfile::tempdir()?;
    let observation = CleanupObservation {
        root: root.path().to_path_buf(),
        units: Vec::new(),
        container: None,
        runtime: None,
        driver_pid: None,
    };
    // Model an omitted final removal with an otherwise successful cleanup:
    // the independent acceptance check must fail even for an empty root.
    ensure!(
        observation.verify().is_err(),
        "retained private root accepted"
    );
    root.close()?;
    observation.verify()?;
    Ok(())
}

pub fn docker_absence_regression() -> Result<()> {
    use std::os::unix::process::ExitStatusExt;
    let reply = |success: bool, bytes: &[u8]| Output {
        status: std::process::ExitStatus::from_raw(if success { 0 } else { 256 }),
        stdout: bytes.to_vec(),
        stderr: Vec::new(),
    };
    let id = "a".repeat(64);
    let present = format!("{id}\n");
    for responses in [
        vec![(false, "")],
        vec![
            (true, present.as_str()),
            (true, "owner\n"),
            (true, ""),
            (false, ""),
        ],
        vec![(true, present.as_str()), (true, "other-owner\n")],
        vec![
            (true, present.as_str()),
            (true, "owner\n"),
            (true, ""),
            (true, present.as_str()),
        ],
    ] {
        let mut replies = responses.into_iter();
        ensure!(
            cleanup_container(&id, "owner", |_| {
                let (success, text) = replies.next().context("unexpected Docker action")?;
                Ok(reply(success, text.as_bytes()))
            })
            .is_err(),
            "uncertain Docker cleanup accepted"
        );
        ensure!(
            replies.next().is_none(),
            "cleanup continued after uncertain ownership/absence"
        );
    }
    // A retry after successful removal must neither inspect nor remove again.
    let mut calls = 0;
    cleanup_container(&id, "owner", |args| {
        calls += 1;
        ensure!(args[0] == "ps", "absent container was inspected or removed");
        Ok(reply(true, b""))
    })?;
    ensure!(calls == 1, "absence retry was not idempotent");
    let mut replies = [
        (true, present.as_str()),
        (true, "owner\n"),
        (true, ""),
        (true, ""),
    ]
    .into_iter();
    cleanup_container(&id, "owner", |_| {
        let (success, bytes) = replies.next().context("unexpected Docker action")?;
        Ok(reply(success, bytes.as_bytes()))
    })?;
    Ok(())
}

pub fn private_capture_regression() -> Result<()> {
    let root = tempfile::tempdir()?;
    for stream in ["stdout", "stderr"] {
        let mut capture = PrivateCapture::start(root.path(), stream)?;
        let mut writer = OpenOptions::new().write(true).open(&capture.fifo)?;
        writer.write_all(b"synthetic-leak-sentinel")?;
        drop(writer);
        capture.finish()?;
        ensure!(
            fs::read(&capture.file)? == b"synthetic-leak-sentinel",
            "private capture lost output"
        );
        ensure!(
            fs::metadata(&capture.file)?.mode() & 0o777 == 0o600,
            "capture was not private"
        );
    }
    let secrets = initial_secrets();
    for (index, secret) in secrets.iter().enumerate() {
        for stream in ["stdout", "stderr"] {
            let mut capture =
                PrivateCapture::start(root.path(), &format!("credential-{index}-{stream}"))?;
            let mut writer = OpenOptions::new().write(true).open(&capture.fifo)?;
            writer.write_all(secret)?;
            drop(writer);
            capture.finish()?;
            ensure!(
                contains_secret(&fs::read(&capture.file)?, &secrets),
                "synthetic credential escaped private output audit"
            );
        }
    }
    ensure!(
        !contains_secret(b"redacted success", &secrets),
        "redacted output rejected"
    );
    let mut capture = PrivateCapture::start(root.path(), "overflow")?;
    let mut writer = OpenOptions::new().write(true).open(&capture.fifo)?;
    writer.write_all(&vec![b'x'; CAPTURE_LIMIT + 8192])?;
    drop(writer);
    ensure!(capture.finish().is_err(), "capture overflow accepted");
    ensure!(
        fs::metadata(&capture.file)?.len() <= CAPTURE_LIMIT as u64,
        "capture exceeded private bound"
    );
    Ok(())
}

fn cleanup_regression_fixture(root: PathBuf) -> Result<Rehearsal> {
    let run = Rehearsal {
        runtime: root.join("runtime"),
        root,
        uid: unsafe { libc::geteuid() },
        gid: unsafe { libc::getegid() },
        agent_uid: unsafe { libc::geteuid() },
        units: Vec::new(),
        container: None,
        driver: None,
        driver_lines: None,
        runtime_owned: false,
        cleaned: false,
        ownership_uncertain: false,
        secrets: vec![b"synthetic-leak-sentinel".to_vec()],
        evidence: RefCell::new(Vec::new()),
        fail_provider_stop: false,
        fail_provider_reap: false,
        fail_after_container_removal: false,
        human_display: None,
        human_mode: false,
        captures: Vec::new(),
        leaked: Cell::new(false),
    };
    run.ledger("regression", "private-fixture")?;
    Ok(run)
}

pub fn controller_output_regression() -> Result<()> {
    let root = tempfile::tempdir()?;
    for (name, script, overflow) in [
        (
            "trailing",
            "printf '{\"ok\":true}\\n'; printf 'synthetic-leak-sentinel'",
            false,
        ),
        (
            "overflow",
            "printf '{\"ok\":true}\\n'; /usr/bin/dd if=/dev/zero bs=8192 count=513 2>/dev/null",
            true,
        ),
    ] {
        let private = tempfile::tempdir_in(root.path())?;
        let mut run = cleanup_regression_fixture(private.path().to_path_buf())?;
        let mut child = command("/bin/sh").args(["-c", script]).spawn()?;
        let mut capture =
            ControllerOutput::new(child.stdout.take().unwrap(), private.path().join(name))?;
        let deadline = Instant::now() + Duration::from_secs(3);
        let mut reply = Vec::new();
        loop {
            ensure!(
                Instant::now() < deadline,
                "controller regression response deadline"
            );
            let mut byte = [0];
            if capture.read(&mut byte)? == Some(1) {
                reply.push(byte[0]);
                if byte[0] == b'\n' {
                    break;
                }
            } else {
                std::thread::sleep(Duration::from_millis(5));
            }
        }
        ensure!(
            serde_json::from_slice::<Value>(&reply)?["ok"] == true,
            "valid reply lost"
        );
        let result = capture.finish(Duration::from_secs(3));
        let _kill = child.kill();
        child.wait()?;
        let bytes = fs::read(&capture.path)?;
        if overflow {
            ensure!(
                result.is_err() && capture.finish(Duration::from_millis(10)).is_err(),
                "controller overflow accepted on initial or retry audit"
            );
            ensure!(
                bytes.len() <= CAPTURE_LIMIT,
                "controller capture exceeded bound"
            );
        } else {
            result?;
            ensure!(
                contains_secret(&bytes, &[b"synthetic-leak-sentinel".to_vec()]),
                "trailing controller leak escaped audit"
            );
        }
        run.driver_lines = Some(capture);
        let cleanup = run.cleanup();
        // TempDir owns these known synthetic fixtures after the real cleanup check.
        run.cleaned = true;
        ensure!(
            cleanup.is_err() && private.path().is_dir(),
            "controller audit accepted deletion of private leak/overflow evidence"
        );
    }
    let mut child = command("/bin/sleep").arg("30").spawn()?;
    let mut capture = ControllerOutput::new(
        child.stdout.take().unwrap(),
        root.path().join("uncertain-eof"),
    )?;
    ensure!(
        capture.finish(Duration::from_millis(20)).is_err(),
        "uncertain controller EOF accepted"
    );
    ensure!(
        capture.reader.is_some(),
        "uncertain controller output handle lost"
    );
    child.kill()?;
    child.wait()?;
    capture.finish(Duration::from_secs(1))?;
    Ok(())
}

pub fn cleanup_observation_regression() -> Result<()> {
    let mut driver = Some(command("/bin/sleep").arg("30").spawn()?);
    let pid = driver.as_ref().unwrap().id();
    ensure!(
        confirm_driver_reaped(&mut driver, |_| Ok(false)).is_err(),
        "unreaped controller accepted"
    );
    ensure!(
        driver.as_ref().map(Child::id) == Some(pid),
        "controller identity lost on retry"
    );
    ensure!(
        confirm_driver_reaped(&mut driver, |_| anyhow::bail!("observation unavailable")).is_err(),
        "uncertain controller accepted"
    );
    ensure!(
        driver.as_ref().map(Child::id) == Some(pid),
        "controller identity lost on observation failure"
    );
    confirm_driver_reaped(&mut driver, |child| {
        child.kill()?;
        child.wait()?;
        Ok(true)
    })?;
    ensure!(driver.is_none(), "reaped controller retained");
    let root = tempfile::tempdir()?;
    ensure!(
        !path_present(&root.path().join("absent"))?,
        "absent path rejected"
    );
    ensure!(
        path_present(root.path())?,
        "present path accepted as absent"
    );
    fs::write(root.path().join("file"), b"retained")?;
    ensure!(
        path_present(&root.path().join("file/child")).is_err(),
        "metadata failure accepted as absence"
    );
    ensure!(
        fs::read(root.path().join("file"))? == b"retained",
        "uncertain observation deleted material"
    );
    let mut run = cleanup_regression_fixture(root.path().to_path_buf())?;
    run.runtime = root.path().join("file/child");
    let cleanup = run.cleanup();
    run.cleaned = true;
    ensure!(
        cleanup.is_err() && root.path().is_dir(),
        "cleanup deleted material after uncertain filesystem observation"
    );
    Ok(())
}

fn validate_wayland_socket(runtime: &Path, display: &str, uid: u32) -> Result<PathBuf> {
    ensure!(
        display.starts_with("wayland-")
            && display.len() <= 64
            && display
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "unsupported visible display name"
    );
    let directory = fs::symlink_metadata(runtime)?;
    ensure!(
        directory.is_dir() && directory.uid() == uid && directory.mode() & 0o777 == 0o700,
        "unsafe visible display runtime"
    );
    let path = runtime.join(display);
    let socket = fs::symlink_metadata(&path)?;
    ensure!(
        socket.file_type().is_socket() && socket.uid() == uid,
        "visible display must be an owned socket, not a symlink"
    );
    Ok(path)
}

fn human_display(uid: u32) -> Result<PathBuf> {
    ensure!(
        std::env::var("XDG_SESSION_TYPE").as_deref() == Ok("wayland")
            && std::env::var("XDG_CURRENT_DESKTOP").as_deref() == Ok("COSMIC"),
        "approved COSMIC Wayland session required"
    );
    let runtime = PathBuf::from(format!("/run/user/{uid}"));
    ensure!(
        std::env::var_os("XDG_RUNTIME_DIR").as_deref() == Some(runtime.as_os_str()),
        "visible display runtime mismatch"
    );
    validate_wayland_socket(&runtime, &std::env::var("WAYLAND_DISPLAY")?, uid)
}

pub fn human_display_regression() -> Result<()> {
    let root = tempfile::tempdir()?;
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))?;
    let socket = root.path().join("wayland-1");
    let _listener = std::os::unix::net::UnixListener::bind(&socket)?;
    let uid = unsafe { libc::geteuid() };
    ensure!(
        validate_wayland_socket(root.path(), "wayland-1", uid)? == socket,
        "valid display rejected"
    );
    for invalid in [
        "../wayland-1",
        "/run/user/1000/wayland-1",
        "wayland-1/child",
        "",
        "other",
    ] {
        ensure!(
            validate_wayland_socket(root.path(), invalid, uid).is_err(),
            "unsafe display accepted"
        );
    }
    std::os::unix::fs::symlink(&socket, root.path().join("wayland-link"))?;
    ensure!(
        validate_wayland_socket(root.path(), "wayland-link", uid).is_err(),
        "display symlink accepted"
    );
    ensure!(
        validate_wayland_socket(root.path(), "wayland-1", uid + 1).is_err(),
        "foreign display accepted"
    );
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o755))?;
    ensure!(
        validate_wayland_socket(root.path(), "wayland-1", uid).is_err(),
        "public display runtime accepted"
    );
    Ok(())
}

fn encrypted(bytes: &[u8], enc: &[u8], mac: &[u8]) -> String {
    let mut iv = [0u8; 16];
    getrandom::fill(&mut iv).unwrap();
    let mut buffer = vec![0u8; (bytes.len() / 16 + 1) * 16];
    buffer[..bytes.len()].copy_from_slice(bytes);
    let cipher = cbc::Encryptor::<aes::Aes256>::new_from_slices(enc, &iv)
        .unwrap()
        .encrypt_padded::<Pkcs7>(&mut buffer, bytes.len())
        .unwrap();
    let mut auth = <Hmac<Sha256> as KeyInit>::new_from_slice(mac).unwrap();
    auth.update(&iv);
    auth.update(cipher);
    format!(
        "2.{}|{}|{}",
        STANDARD.encode(iv),
        STANDARD.encode(cipher),
        STANDARD.encode(auth.finalize().into_bytes())
    )
}
fn response(request: reqwest::blocking::RequestBuilder) -> Result<Value> {
    let response = request.send()?;
    ensure!(
        response.status().is_success(),
        "synthetic server rejected setup"
    );
    Ok(response.json()?)
}
fn string<'a>(value: &'a Value, lower: &str, upper: &str) -> Result<&'a str> {
    value[lower]
        .as_str()
        .or_else(|| value[upper].as_str())
        .context("required synthetic response field")
}
fn setup_vault(run: &mut Rehearsal, url: &str, ca: &Path) -> Result<(String, String)> {
    let mut ids = setup_vault_items(
        run,
        url,
        ca,
        &[("rehearsal-check", FIELD), ("rehearsal-wrong", WRONG_FIELD)],
    )?;
    Ok((ids.remove(0), ids.remove(0)))
}
fn setup_vault_items(
    run: &mut Rehearsal,
    url: &str,
    ca: &Path,
    items: &[(&str, &str)],
) -> Result<Vec<String>> {
    vaultwarden_cli::install_rustls_crypto_provider();
    let http = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(10))
        .tls_certs_only([reqwest::Certificate::from_pem(&fs::read(ca)?)?])
        .build()?;
    wait_for(|| {
        Ok(http
            .get(format!("{url}/alive"))
            .send()
            .is_ok_and(|r| r.status().is_success()))
    })?;
    // Demonstrate that the disposable server is not accepted by ambient trust.
    let untrusted = Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(5))
        .build()?;
    ensure!(
        untrusted.get(format!("{url}/alive")).send().is_err(),
        "ambient trust unexpectedly accepted private CA"
    );
    let email = "protected-rehearsal@test.invalid";
    let master = MasterKey::derive(
        PASSWORD,
        email,
        KdfIterations::new(100_000).context("positive iterations")?,
    );
    let stretched = master.stretch()?;
    for bytes in [
        master.as_bytes().as_slice(),
        stretched.enc_key().as_slice(),
        stretched.mac_key().as_slice(),
    ] {
        run.secrets.push(bytes.to_vec());
        run.secrets.push(STANDARD.encode(bytes).into_bytes());
    }
    let mut symmetric = [0u8; 64];
    getrandom::fill(&mut symmetric).map_err(|_error| anyhow::anyhow!("random source"))?;
    for bytes in [&symmetric[..], &symmetric[..32], &symmetric[32..]] {
        run.secrets.push(bytes.to_vec());
        run.secrets.push(STANDARD.encode(bytes).into_bytes());
    }
    let protected = encrypted(&symmetric, stretched.enc_key(), stretched.mac_key());
    let mut hash = [0u8; 32];
    pbkdf2::pbkdf2_hmac::<Sha256>(master.as_bytes(), PASSWORD.as_bytes(), 1, &mut hash);
    let hash = STANDARD.encode(hash);
    run.secrets.push(hash.as_bytes().to_vec());
    let registration=http.post(format!("{url}/identity/accounts/register")).json(&json!({"email":email,"name":"Disposable protected rehearsal","masterPasswordHash":hash,"key":protected,"kdfType":0,"kdfIterations":100_000})).send()?;
    ensure!(
        registration.status().is_success(),
        "synthetic registration failed"
    );
    let token = response(http.post(format!("{url}/identity/connect/token")).form(&[
        ("grant_type", "password"),
        ("username", email),
        ("password", hash.as_str()),
        ("scope", "api offline_access"),
        ("client_id", "web"),
        ("deviceType", "9"),
        ("deviceIdentifier", "disposable-rehearsal"),
        ("deviceName", "rehearsal"),
    ]))?;
    let bearer = string(&token, "access_token", "access_token")?;
    run.secrets.push(bearer.as_bytes().to_vec());
    if let Some(refresh) = token["refresh_token"].as_str() {
        run.secrets.push(refresh.as_bytes().to_vec());
    }
    let sync = response(http.get(format!("{url}/api/sync")).bearer_auth(bearer))?;
    let profile = sync
        .get("profile")
        .or_else(|| sync.get("Profile"))
        .context("synthetic profile")?;
    let client_id = format!("user.{}", string(profile, "id", "Id")?);
    let rotated = response(
        http.post(format!("{url}/api/accounts/rotate-api-key"))
            .bearer_auth(bearer)
            .json(&json!({"masterPasswordHash":hash})),
    )?;
    let secret = string(&rotated, "apiKey", "ApiKey")?;
    run.secrets.push(secret.as_bytes().to_vec());
    let mut keyring = command("/usr/bin/secret-tool");
    run.env(&mut keyring);
    keyring.args([
        "store",
        "--label=Disposable provider bootstrap",
        "service",
        "vaultwarden-accessd",
        "username",
        "bootstrap-client-secret",
    ]);
    ensure!(
        output(&mut keyring, Some(secret.as_bytes()), 10)?
            .status
            .success(),
        "private bootstrap keyring rejected write"
    );
    private_file(
        &run.root.join("private/setup.json"),
        &serde_json::to_vec(
            &json!({"server":url,"email":email,"client_id":client_id,"encrypted_key":protected,"kdf_iterations":100_000,"org_keys":{}}),
        )?,
    )?;
    let encrypt = |value: &str| encrypted(value.as_bytes(), &symmetric[..32], &symmetric[32..]);
    let mut ids = Vec::new();
    for &(operation, value) in items {
        let cipher=response(http.post(format!("{url}/api/ciphers")).bearer_auth(bearer).json(&json!({
            "type":1,"name":encrypt("Disposable rehearsal Login"),"notes":null,"favorite":false,
            "login":{"username":encrypt("synthetic"),"password":encrypt("unused-synthetic-login-password"),"uris":[]},
            "fields":[{"type":0,"name":encrypt("vw-access"),"value":encrypt(operation)},
                {"type":1,"name":encrypt("rehearsal-field"),"value":encrypt(value)}]
        })))?;
        ids.push(string(&cipher, "id", "Id")?.to_owned());
    }
    Ok(ids)
}

pub fn run() -> Result<()> {
    ensure!(
        cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
        "unsupported rehearsal architecture"
    );
    let mode = std::env::var("VW_REHEARSAL_MODE").context("explicit runner required")?;
    ensure!(
        [
            "--check",
            "--automated",
            "--human",
            "--human-check",
            "--interrupt",
            "--cleanup-failure",
            "--collision-check"
        ]
        .contains(&mode.as_str()),
        "invalid mode"
    );
    let home = PathBuf::from(std::env::var_os("HOME").context("home")?);
    safe_home(&home)?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    ensure!(uid != 0, "never run as host root");
    let human_display = if matches!(mode.as_str(), "--human" | "--human-check") {
        Some(human_display(uid)?)
    } else {
        None
    };
    ensure!(
        property(UNIT, "LoadState")? == "not-found",
        "provider unit collision"
    );
    let user = text(checked(command("/usr/bin/id").arg("-un"))?)?;
    let agent_uid = subordinate_id(&fs::read_to_string("/etc/subuid")?, &user)
        .context("existing subordinate UID required")?;
    let map = text(checked(
        restricted().args(["/usr/bin/cat", "/proc/self/uid_map"]),
    )?)?;
    ensure!(
        map.lines()
            .any(|line| line.split_whitespace().take(2).collect::<Vec<_>>()
                == vec!["1", &agent_uid.to_string()]),
        "kernel restricted identity unavailable"
    );
    ensure!(
        !output(
            restricted().args(["/usr/bin/setpriv", "--reuid=0", "/usr/bin/true"]),
            None,
            5
        )?
        .status
        .success(),
        "agent can regain provider identity"
    );
    require_restricted_traversal(&home)?;
    let namespace = Sha256::digest(format!("{uid}:{UNIT}").as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    let runtime = PathBuf::from(format!("/run/user/{uid}/vw-access-{namespace}"));
    ensure!(!runtime.exists(), "supervisor runtime collision");
    ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "cgroup v2 required"
    );
    for name in [
        "VW_REHEARSAL_XVFB",
        "VW_REHEARSAL_CERTUTIL",
        "VW_REHEARSAL_FIREFOX",
        "VW_REHEARSAL_NODE",
    ] {
        if name == "VW_REHEARSAL_XVFB" && human_display.is_some() {
            continue;
        }
        ensure!(
            Path::new(&std::env::var(name)?).is_file(),
            "private desktop dependency unavailable"
        );
    }
    check_fixture()?;
    println!(
        "PASS: preflight; fixed provider unit/runtime absent, real manager and distinct kernel UID available"
    );
    if mode == "--check" {
        return Ok(());
    }
    // Signal handlers only set an atomic flag; normal Rust cleanup owns work.
    unsafe {
        libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            interrupted as *const () as libc::sighandler_t,
        );
    }
    let root = tempfile::Builder::new()
        .prefix(".vw-protected-rehearsal-")
        .tempdir_in(&home)?
        .keep();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750))?;
    let mut run = Rehearsal {
        root,
        uid,
        gid,
        agent_uid,
        units: Vec::new(),
        container: None,
        driver: None,
        driver_lines: None,
        runtime,
        runtime_owned: false,
        cleaned: false,
        ownership_uncertain: false,
        secrets: initial_secrets(),
        evidence: RefCell::new(Vec::new()),
        fail_provider_stop: false,
        fail_provider_reap: false,
        fail_after_container_removal: false,
        human_display,
        human_mode: mode == "--human",
        captures: Vec::new(),
        leaked: Cell::new(false),
    };
    run.ledger("owned-directory", "private rehearsal root")?;
    if mode == "--collision-check" {
        run.start_unit(UNIT, &["/usr/bin/sleep".into(), "60".into()])?;
        let invocation = property(UNIT, "InvocationID")?;
        let result = prerequisite_failure("--check", None);
        ensure!(
            property(UNIT, "InvocationID")? == invocation,
            "collision displaced owned sentinel"
        );
        let observation = CleanupObservation::capture(&run);
        run.cleanup()?;
        observation.verify()?;
        println!("PASS: independent post-cleanup resource absence checks");
        result?;
        println!(
            "PASS: occupied fixed provider refused before setup; original invocation preserved"
        );
        return Ok(());
    }
    let result = execute(&mut run, &mode);
    if mode == "--cleanup-failure" && result.is_ok() {
        run.fail_provider_stop = true;
        ensure!(run.cleanup().is_err(), "injected cleanup failure accepted");
        ensure!(
            run.root.join("private/setup.json").is_file()
                && property(UNIT, "ActiveState")? == "active",
            "cleanup failure removed live private material"
        );
        let snapshots = run.units.clone();
        run.units.clear();
        run.units = run.recorded_units()?;
        ensure!(
            run.units == snapshots,
            "durable recovery lost unit identities"
        );
        run.fail_provider_stop = false;
        println!(
            "PASS: injected stop failure retained live material; unit identities recovered from durable ledger"
        );
        run.fail_provider_reap = true;
        ensure!(
            run.cleanup().is_err() && run.root.join("private/setup.json").is_file(),
            "uncertain reap observation removed private material"
        );
        ensure!(
            property(UNIT, "LoadState")? == "not-found",
            "owned provider did not stop"
        );
        run.fail_provider_reap = false;
        println!(
            "PASS: injected post-stop reap observation failure retained private material for verified recovery"
        );
        run.fail_after_container_removal = true;
        ensure!(
            run.cleanup().is_err() && run.root.join("private/setup.json").is_file(),
            "post-removal failure deleted private material"
        );
        let id = run.container.as_ref().context("owned container missing")?;
        ensure!(
            checked(run.docker().args([
                "ps",
                "--all",
                "--quiet",
                "--no-trunc",
                "--filter",
                &format!("id={id}")
            ]))?
            .is_empty(),
            "removed container absence unconfirmed"
        );
        run.fail_after_container_removal = false;
        println!(
            "PASS: post-container-removal failure retained material; retry confirms absent owned ID without inspection"
        );
    }
    let observation = CleanupObservation::capture(&run);
    run.cleanup()?;
    observation.verify()?;
    println!("PASS: independent post-cleanup resource absence checks");
    result?;
    Ok(())
}

fn setup_private_services(run: &mut Rehearsal) -> Result<(PathBuf, String, PathBuf)> {
    for (name, permission) in [
        ("private", 0o700),
        ("bin", 0o750),
        ("socket", 0o750),
        ("agent", 0o700),
    ] {
        directory(&run.root.join(name), permission)?;
    }
    for name in [
        "runtime", "tls", "profile", ".config", ".local", "cache", "docker",
    ] {
        directory(&run.root.join("private").join(name), 0o700)?;
    }
    directory(&run.root.join("private/.local/share"), 0o700)?;
    directory(&run.root.join("private/.local/share/applications"), 0o700)?;
    for (name, source) in [
        (
            "vaultwarden-accessd",
            env!("CARGO_BIN_EXE_vaultwarden-accessd"),
        ),
        (
            "vaultwarden-access-exec",
            env!("CARGO_BIN_EXE_vaultwarden-access-exec"),
        ),
        ("vw-access", env!("CARGO_BIN_EXE_vw-access")),
    ] {
        let path = run.root.join("bin").join(name);
        fs::copy(source, &path)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o550))?;
    }
    let checker = run.root.join("private/credential-check");
    compile_checker(&checker)?;
    // Chown only the new agent directory through an existing subordinate map.
    checked(
        command("/usr/bin/unshare")
            .args([
                "--user",
                "--map-root-user",
                "--map-auto",
                "--setgroups=allow",
                "--",
                "/usr/bin/chown",
                "1:0",
            ])
            .arg(run.root.join("agent")),
    )?;
    ensure!(
        fs::metadata(run.root.join("agent"))?.uid() == run.agent_uid,
        "agent ownership mapping mismatch"
    );
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_error| anyhow::anyhow!("random source"))?;
    run.secrets.push(seed.to_vec());
    run.secrets.push(STANDARD.encode(seed).into_bytes());
    let mut agent_key = restricted();
    agent_key
        .args([
            "/bin/sh",
            "-c",
            "umask 077; dd of=\"$1\" status=none",
            "rehearsal-agent-key",
        ])
        .arg(run.root.join("agent/key"));
    ensure!(
        output(&mut agent_key, Some(&seed), 10)?.status.success(),
        "agent key creation failed"
    );
    let public = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&seed).verifying_key().as_bytes());
    let tls = run.root.join("private/tls");
    checked(
        command("/usr/bin/openssl")
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-days",
                "1",
                "-subj",
                "/CN=Disposable rehearsal CA",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-keyout",
            ])
            .arg(tls.join("ca.key"))
            .arg("-out")
            .arg(tls.join("ca.pem")),
    )?;
    checked(
        command("/usr/bin/openssl")
            .args([
                "req",
                "-new",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-subj",
                "/CN=localhost",
                "-keyout",
            ])
            .arg(tls.join("server.key"))
            .arg("-out")
            .arg(tls.join("server.csr")),
    )?;
    private_file(&tls.join("extensions"),b"subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n")?;
    checked(
        command("/usr/bin/openssl")
            .args(["x509", "-req", "-days", "1", "-in"])
            .arg(tls.join("server.csr"))
            .arg("-CA")
            .arg(tls.join("ca.pem"))
            .arg("-CAkey")
            .arg(tls.join("ca.key"))
            .arg("-CAcreateserial")
            .arg("-extfile")
            .arg(tls.join("extensions"))
            .arg("-out")
            .arg(tls.join("server.pem")),
    )?;
    for name in ["ca.key", "server.key"] {
        fs::set_permissions(tls.join(name), fs::Permissions::from_mode(0o600))?;
        let key = fs::read(tls.join(name))?;
        for line in key
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty() && !line.starts_with(b"-----"))
        {
            run.secrets.push(line.to_vec());
        }
        run.secrets.push(key);
    }
    let tag = run
        .root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .trim_start_matches('.')
        .to_owned();
    private_file(&run.root.join("private/bus.conf"),b"<busconfig><type>session</type><listen>unix:tmpdir=/tmp</listen><auth>EXTERNAL</auth><policy context=\"default\"><allow own=\"*\"/><allow send_destination=\"*\"/><allow receive_sender=\"*\"/></policy></busconfig>")?;
    let mut bus = run.service_env();
    bus.extend([
        "/usr/bin/dbus-daemon".into(),
        format!("--config-file={}/private/bus.conf", run.root.display()),
        "--nofork".into(),
        "--nopidfile".into(),
        format!("--address=unix:path={}/private/bus", run.root.display()),
    ]);
    run.start_unit(&format!("{tag}-bus.service"), &bus)?;
    wait_for(|| Ok(run.root.join("private/bus").exists()))?;
    let mut keyring = run.service_env();
    private_file(
        &run.root.join("private/keyring-input"),
        b"disposable-private-keyring\n",
    )?;
    keyring.extend([
        "/usr/bin/gnome-keyring-daemon".into(),
        "--foreground".into(),
        "--components=secrets".into(),
        "--unlock".into(),
    ]);
    run.start_unit(&format!("{tag}-keyring.service"), &keyring)?;
    wait_for(|| {
        let mut probe = command("/usr/bin/gdbus");
        run.env(&mut probe);
        Ok(text(checked(probe.args([
            "call",
            "--session",
            "--dest",
            "org.freedesktop.DBus",
            "--object-path",
            "/org/freedesktop/DBus",
            "--method",
            "org.freedesktop.DBus.NameHasOwner",
            "org.freedesktop.secrets",
        ]))?)?
        .contains("true"))
    })?;
    Ok((checker, public, tls))
}

fn execute(run: &mut Rehearsal, mode: &str) -> Result<()> {
    let repo = Path::new(env!("CARGO_MANIFEST_DIR"));
    let (checker, public, tls) = setup_private_services(run)?;
    let tag = run
        .root
        .file_name()
        .unwrap()
        .to_string_lossy()
        .trim_start_matches('.')
        .to_owned();
    // UI controller launches Xvfb and Firefox inside its manager-owned cgroup.
    let mut driver = command("/usr/bin/systemd-run");
    let driver_stderr = run.capture("browser-driver-stderr")?;
    let browser_unit = format!("{tag}-browser.service");
    driver
        .env("XDG_RUNTIME_DIR", format!("/run/user/{}", run.uid))
        .env(
            "DBUS_SESSION_BUS_ADDRESS",
            format!("unix:path=/run/user/{}/bus", run.uid),
        )
        .args([
            "--user",
            "--quiet",
            "--collect",
            "--pipe",
            "--wait",
            "--service-type=exec",
            "--unit",
            &browser_unit,
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=10",
            "--property=UMask=0077",
            "--",
            "/usr/bin/env",
            "-i",
            "PATH=/usr/bin:/bin",
        ])
        .args(run.service_env());
    for name in [
        "VW_REHEARSAL_XVFB",
        "VW_REHEARSAL_CERTUTIL",
        "VW_REHEARSAL_FIREFOX",
        "VW_REHEARSAL_UI_DEPS",
    ] {
        driver.arg(format!("{name}={}", std::env::var(name)?));
    }
    if let Some(display) = &run.human_display {
        driver
            .arg(format!("WAYLAND_DISPLAY={}", display.display()))
            .arg("MOZ_ENABLE_WAYLAND=1")
            .arg("GDK_BACKEND=wayland");
    }
    driver
        .arg(std::env::var("VW_REHEARSAL_NODE")?)
        .arg(repo.join("tests/ui/protected-rehearsal.mjs"))
        .arg(&run.root)
        .arg(mode)
        .stdin(Stdio::piped())
        .stderr(Stdio::from(
            OpenOptions::new().write(true).open(driver_stderr)?,
        ));
    run.ownership_uncertain = true;
    let child = driver.spawn()?;
    run.driver = Some(child);
    run.driver_lines = Some(ControllerOutput::new(
        run.driver
            .as_mut()
            .unwrap()
            .stdout
            .take()
            .context("driver stdout")?,
        run.root.join("captures/controller-stdout.capture"),
    )?);
    wait_for(|| Ok(property(&browser_unit, "ActiveState")? == "active"))?;
    run.record_unit(OwnedUnit {
        name: browser_unit.clone(),
        invocation: property(&browser_unit, "InvocationID")?,
        cgroup: PathBuf::from("/sys/fs/cgroup")
            .join(property(&browser_unit, "ControlGroup")?.trim_start_matches('/')),
    })?;
    let browser = run.browser(json!({"action":"start"}))?;
    let display = browser["display"].as_str().context("display transport")?;
    if run.human_display.is_none() {
        ensure!(
            browser["authenticatedXSetup"] == true && browser["unauthenticatedXRejected"] == true,
            "private display authentication controls unconfirmed"
        );
        println!("PASS: authenticated X setup succeeds; unauthenticated X setup rejects");
    }
    println!("PASS: real xdg-open delivered to isolated trusted Firefox");
    ensure!(
        run.recorded_units()? == run.units && run.units.len() == 3,
        "desktop ownership not durable before vault setup"
    );
    if mode == "--human-check" {
        println!(
            "PASS: visible private-profile desktop check only; no vault, provider or human approval exercised"
        );
        return Ok(());
    }
    // Provision a vault only after the real private desktop gate has passed.
    run.ownership_uncertain = true;
    let id = text(checked(run.docker().args([
        "create",
        "--label",
        &format!(
            "vw.rehearsal={}",
            run.root.file_name().unwrap().to_string_lossy()
        ),
        "--publish",
        "127.0.0.1::80",
        "--tmpfs",
        "/data:rw,nosuid,nodev,noexec",
        "--mount",
        &format!(
            "type=bind,src={},dst=/rehearsal-tls,readonly",
            tls.display()
        ),
        "--env",
        "SIGNUPS_ALLOWED=true",
        "--env",
        "LOG_LEVEL=error",
        "--env",
        "ROCKET_TLS={certs=\"/rehearsal-tls/server.pem\",key=\"/rehearsal-tls/server.key\"}",
        "vaultwarden/server:1.36.0",
    ]))?)?;
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid owned container ID"
    );
    run.container = Some(id.clone());
    run.ownership_uncertain = false;
    run.ledger("owned-container", &id)?;
    checked(run.docker().args(["start", &id]))?;
    let endpoint = text(checked(run.docker().args(["port", &id, "80/tcp"]))?)?;
    ensure!(
        endpoint.starts_with("127.0.0.1:") && !endpoint.contains('\n'),
        "non-loopback backend"
    );
    let (good_item, bad_item) =
        setup_vault(run, &format!("https://{endpoint}"), &tls.join("ca.pem"))?;
    println!("PASS: synthetic HTTPS vault and private provider bootstrap provisioned");
    let mut provider = run.service_env();
    if let Some(socket) = &run.human_display {
        provider.extend([
            format!("WAYLAND_DISPLAY={}", socket.display()),
            "MOZ_ENABLE_WAYLAND=1".into(),
            "GDK_BACKEND=wayland".into(),
        ]);
    } else {
        provider.extend([
            format!("DISPLAY={display}"),
            format!("XAUTHORITY={}/private/Xauthority", run.root.display()),
        ]);
    }
    provider.extend([
        "XDG_CURRENT_DESKTOP=X-Generic".into(),
        format!("SSL_CERT_FILE={}", tls.join("ca.pem").display()),
        run.root
            .join("bin/vaultwarden-accessd")
            .display()
            .to_string(),
        "--state-root".into(),
        run.root.join("private/state").display().to_string(),
        "--backend-config".into(),
        run.root.join("private/setup.json").display().to_string(),
        "--agent-socket-dir".into(),
        run.root.join("socket").display().to_string(),
        "--agent-socket-gid".into(),
        run.gid.to_string(),
        "--ui-tls-cert".into(),
        tls.join("server.pem").display().to_string(),
        "--ui-tls-key".into(),
        tls.join("server.key").display().to_string(),
    ]);
    run.start_unit(UNIT, &provider)?;
    wait_for(|| {
        Ok(run
            .root
            .join("private/state/open-vaultwarden-access.html")
            .exists())
    })?;
    run.runtime_owned = true;
    let launch = fs::read_to_string(run.root.join("private/state/open-vaultwarden-access.html"))?;
    if let Some(capability) = launch
        .split('#')
        .nth(1)
        .and_then(|value| value.split('"').next())
    {
        run.secrets.push(capability.as_bytes().to_vec());
    }
    if run.human_mode {
        run.browser(json!({"action":"guide","password":PASSWORD}))?;
        println!(
            "HUMAN: unlock the disposable provider; instructions and synthetic password are in its private Firefox guide tab (five-minute limit)"
        );
        run.browser(json!({"action":"unlock"}))?;
    } else {
        run.browser(json!({"action":"unlock","password":PASSWORD}))?;
    }
    let mut session = command("/usr/bin/secret-tool");
    run.env(&mut session);
    let session: Value = serde_json::from_slice(&checked(session.args([
        "lookup",
        "service",
        "vaultwarden-accessd",
        "username",
        "revocable-session",
    ]))?)?;
    for key in ["access_token", "enc_key", "mac_key"] {
        run.secrets.push(
            session[key]
                .as_str()
                .context("private provider session audit")?
                .as_bytes()
                .to_vec(),
        );
    }
    println!("PASS: production daemon unlocked through trusted browser UI");
    run.cli(&[
        "image",
        "register",
        "--id",
        "credential-check",
        "--execution-root",
        &run.root.join("private").display().to_string(),
        "--path",
        &checker.display().to_string(),
        "--sha256",
        &Sha256::digest(fs::read(&checker)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "--profile",
        "reviewed_self_contained_elf64_v1",
    ])?;
    let mut revisions = Vec::new();
    for (operation, item) in [
        ("rehearsal-check", good_item),
        ("rehearsal-wrong", bad_item),
    ] {
        let path = run.root.join("private").join(format!("{operation}.json"));
        private_file(
            &path,
            &serde_json::to_vec(
                &json!({"id":operation,"description":"Validate disposable injected field","image_id":"credential-check","targets":[TARGET],"arguments":[{"type":"target"}],"credentials":[{"item_id":item,"label":"Disposable rehearsal Login","use_type":"login","field_mappings":[{"field":{"custom":{"name":"rehearsal-field"}},"environment":"REHEARSAL_CREDENTIAL"}]}]}),
            )?,
        )?;
        let created = run.cli(&["operation", "create", "--file", &path.display().to_string()])?;
        revisions.push(
            created["operation"]["revision"]
                .as_str()
                .context("policy revision")?
                .to_owned(),
        );
    }
    let pairing = run.cli(&[
        "agent",
        "pair",
        "Disposable restricted agent",
        "--public-key",
        &public,
        "--uid",
        &run.agent_uid.to_string(),
        "--gid",
        &run.gid.to_string(),
    ])?;
    let binding = pairing["agent"]["id"]
        .as_str()
        .context("paired binding")?
        .to_owned();
    for private in [
        "private/state",
        "private/setup.json",
        "private/bus",
        "private/profile",
        "private/tls/server.key",
    ] {
        let mut probe = restricted();
        probe
            .args(["/usr/bin/test", "-r"])
            .arg(run.root.join(private));
        ensure!(
            !output(&mut probe, None, 5)?.status.success(),
            "agent reached private material"
        );
    }
    let socket = run.root.join("socket/agent.sock").display().to_string();
    let key = run.root.join("agent/key").display().to_string();
    for (scenario, operation, revision, decision, expected) in [
        (
            "denied",
            "rehearsal-check",
            &revisions[0],
            "deny",
            AgentStatus::Denied,
        ),
        (
            "wrong-password",
            "rehearsal-check",
            &revisions[0],
            "wrong",
            AgentStatus::Denied,
        ),
        (
            "approved",
            "rehearsal-check",
            &revisions[0],
            "approve",
            AgentStatus::Completed { exit_code: 0 },
        ),
        (
            "wrong-field",
            "rehearsal-wrong",
            &revisions[1],
            "approve",
            AgentStatus::Failed {
                category: AgentFailure::ExecutionNonzero,
            },
        ),
    ] {
        if run.human_mode {
            // Publish instructions before submission opens the request tab.
            run.browser(json!({"action":"prepare-decision","decision":decision}))?;
        }
        let submitted = run.agent(
            AgentAction::Submit,
            &[
                operation,
                "--socket",
                &socket,
                "--key-file",
                &key,
                "--binding-id",
                &binding,
                "--revision",
                revision,
                "--",
                TARGET,
            ],
        )?;
        let id = submitted["request_id"]
            .as_str()
            .or_else(|| submitted["receipt"]["id"].as_str())
            .or_else(|| submitted["id"].as_str())
            .context("agent receipt")?
            .to_owned();
        ensure!(
            submitted["status"] == "pending",
            "request was not pending before approval"
        );
        let pending = run.cli(&["status", &id])?;
        ensure!(
            pending["state"]["status"] == "pending",
            "execution bypassed approval"
        );
        if mode == "--interrupt" || mode == "--cleanup-failure" {
            ensure!(
                run.recorded_units()? == run.units,
                "provider ownership not durable"
            );
            if mode == "--interrupt" {
                // Exercise the installed handler at active production work, not
                // during setup. The native checker is intentionally immediate;
                // this proves pending-request interruption, not mid-checker kill.
                ensure!(
                    unsafe { libc::raise(libc::SIGTERM) } == 0
                        && INTERRUPTED.load(Ordering::Relaxed),
                    "interrupt handler not observed"
                );
                println!("PASS: SIGTERM observed with genuine signed production request pending");
            }
            return Ok(());
        }
        if run.human_mode {
            println!(
                "HUMAN: {scenario}; follow the private Firefox guide and enter the decision yourself (five-minute limit)"
            );
            run.browser(json!({"action":"decision","id":id,"decision":decision}))?;
        } else {
            run.browser(
                json!({"action":"decision","id":id,"decision":decision,"password":PASSWORD}),
            )?;
        }
        wait_for_agent_terminal(
            || {
                run.agent(
                    AgentAction::Poll,
                    &[
                        &id,
                        "--socket",
                        &socket,
                        "--key-file",
                        &key,
                        "--binding-id",
                        &binding,
                    ],
                )
            },
            &expected,
        )?;
        let history = run.cli(&["history", "--limit", "200"])?;
        let events = history["events"].as_array().context("history events")?;
        let starts = events
            .iter()
            .filter(|e| e["request_id"] == id && e["outcome"] == "execution_started")
            .count();
        ensure!(
            starts == usize::from(decision == "approve"),
            "execution count mismatch"
        );
        ensure!(
            events
                .iter()
                .filter(|e| e["request_id"] == id && e["outcome"] == "succeeded")
                .count()
                == usize::from(scenario == "approved"),
            "false positive completion"
        );
        let result = run.cli(&["status", &id])?;
        if matches!(expected, AgentStatus::Completed { .. }) {
            ensure!(
                result["state"]["status"]["exit_code"]
                    .as_i64()
                    .or_else(|| result["state"]["exit_code"].as_i64())
                    .is_some_and(|code| (code == 0) == (scenario == "approved")),
                "checker result does not match injected field"
            );
        }
        if scenario == "wrong-field" {
            ensure!(
                result["state"]["reason"] == "execution_nonzero",
                "wrong field did not reach checker failure"
            );
        }
        let replay = if run.human_mode {
            json!({"action":"replay","id":id})
        } else {
            json!({"action":"replay","id":id,"password":PASSWORD})
        };
        run.browser(replay)?;
        let after = run.cli(&["history", "--limit", "200"])?;
        ensure!(
            history == after,
            "replayed approval changed execution history"
        );
        if run.human_mode {
            println!(
                "PASS: {scenario}; human decision observed, terminal controls disabled and redacted restricted-agent result"
            );
        } else {
            println!("PASS: {scenario}; one-time decision and redacted restricted-agent result");
        }
    }
    for entry in fs::read_dir(run.root.join("private/state"))? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e == "html") {
            let html = fs::read_to_string(path)?;
            if let Some(fragment) = html.split('#').nth(1).and_then(|s| s.split('"').next()) {
                for capability in fragment.split(':') {
                    run.secrets.push(capability.as_bytes().to_vec());
                }
            }
        }
    }
    for record in run.evidence.borrow().iter() {
        run.redacted(record)?;
    }
    println!(
        "PASS: agent responses and human history redaction; private service output scanned during cleanup"
    );
    println!(
        "Approval evidence: {}",
        if mode == "--human" {
            "human-operated browser decisions observed"
        } else {
            "AUTOMATED UI ONLY; no actual human approval claimed"
        }
    );
    Ok(())
}
