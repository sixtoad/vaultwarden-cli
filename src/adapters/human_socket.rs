//! Private, bounded human-only Unix transport. No browser capability crosses it.
use crate::access::{
    application::ProviderApplication,
    direct_request::{
        AuthenticatedHuman, DirectRequestError, DirectStatus, DirectSubmission, SubmissionReceipt,
    },
    ports::DirectReviewLauncher,
};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Write},
    net::Shutdown,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
    },
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};

pub const SOCKET_NAME: &str = "human.sock";
const MAX_FRAME: usize = 2 * 1024 * 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_WORKERS: usize = 16;

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanMessage {
    pub version: u8,
    pub command: HumanCommand,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanCommand {
    Request { submission: DirectSubmission },
    Status { id: String },
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case", deny_unknown_fields)]
pub enum HumanResponse {
    Submitted { receipt: SubmissionReceipt },
    Status { state: DirectStatus },
    Rejected { reason: DirectRequestError },
    InvalidRequest,
    Unauthorized,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HumanTransportError;
impl std::fmt::Display for HumanTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("human transport unavailable")
    }
}
impl std::error::Error for HumanTransportError {}

pub struct HumanSocket {
    listener: UnixListener,
    path: PathBuf,
    identity: (u64, u64),
}
impl HumanSocket {
    /// Caller holds the provider's stable lifecycle lock before binding.
    pub fn bind(root: &Path) -> Result<Self, HumanTransportError> {
        private_directory(root)?;
        let path = root.join(SOCKET_NAME);
        if let Some(metadata) = existing_socket_metadata(fs::symlink_metadata(&path))? {
            private_socket(&metadata)?;
            match connect_private(&path) {
                Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => {
                    fs::remove_file(&path).map_err(|_error| HumanTransportError)?;
                }
                _ => return Err(HumanTransportError),
            }
        }
        let listener = UnixListener::bind(&path).map_err(|_error| HumanTransportError)?;
        let metadata = fs::symlink_metadata(&path).map_err(|_error| HumanTransportError)?;
        let socket = Self {
            listener,
            path,
            identity: (metadata.dev(), metadata.ino()),
        };
        fs::set_permissions(&socket.path, fs::Permissions::from_mode(0o600))
            .map_err(|_error| HumanTransportError)?;
        socket
            .listener
            .set_nonblocking(true)
            .map_err(|_error| HumanTransportError)?;
        Ok(socket)
    }

    pub fn serve(
        self,
        app: Arc<ProviderApplication>,
        launcher: Arc<dyn DirectReviewLauncher>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), HumanTransportError> {
        let mut workers = Vec::<std::thread::JoinHandle<()>>::new();
        let result = loop {
            if reap_finished_workers(&mut workers) {
                break Err(HumanTransportError);
            }
            if stop.load(Ordering::Acquire) {
                break Ok(());
            }
            match accepted_connection(self.listener.accept()) {
                Ok(Some(stream)) => {
                    if workers.len() >= MAX_WORKERS {
                        drop(stream);
                        continue;
                    }
                    // Peer identity is authenticated before any bytes are decoded.
                    let owner = match authenticate_peer(&stream) {
                        Ok(owner) => owner,
                        Err(_) => {
                            drop(stream);
                            continue;
                        }
                    };
                    let app = app.clone();
                    let launcher = launcher.clone();
                    workers.push(std::thread::spawn(move || {
                        serve_one(stream, owner, &app, launcher.as_ref());
                    }));
                }
                Ok(None) => std::thread::sleep(Duration::from_millis(10)),
                Err(error) => break Err(error),
            }
        };
        // Publish closure before joining requests already admitted on either transport.
        app.close_admission();
        let mut clean = result;
        for worker in workers {
            if worker.join().is_err() {
                clean = Err(HumanTransportError);
            }
        }
        clean
    }
}
impl Drop for HumanSocket {
    fn drop(&mut self) {
        if let Ok(metadata) = fs::symlink_metadata(&self.path)
            && (metadata.dev(), metadata.ino()) == self.identity
            && metadata.file_type().is_socket()
        {
            let _ignored = fs::remove_file(&self.path);
        }
    }
}

/// Release completed capacity and preserve any worker failure for the caller.
fn reap_finished_workers(workers: &mut Vec<std::thread::JoinHandle<()>>) -> bool {
    let mut worker_failed = false;
    for index in (0..workers.len()).rev() {
        if workers[index].is_finished() {
            worker_failed |= workers.swap_remove(index).join().is_err();
        }
    }
    worker_failed
}

/// An empty nonblocking backlog is retryable; a broken listener closes admission.
fn accepted_connection(
    result: std::io::Result<(UnixStream, std::os::unix::net::SocketAddr)>,
) -> Result<Option<UnixStream>, HumanTransportError> {
    match result {
        Ok((stream, _)) => Ok(Some(stream)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(_) => Err(HumanTransportError),
    }
}

/// Only absence permits initial creation; other lookup failures cannot justify
/// proceeding to bind, even if a second filesystem operation might succeed.
fn existing_socket_metadata(
    result: std::io::Result<fs::Metadata>,
) -> Result<Option<fs::Metadata>, HumanTransportError> {
    match result {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(HumanTransportError),
    }
}

/// Nonblocking Unix connect fails immediately when the listener backlog is full.
fn connect_private(path: &Path) -> std::io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidInput));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (destination, source) in address.sun_path.iter_mut().zip(bytes) {
        *destination = *source as libc::c_char;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
            0,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { UnixStream::from_raw_fd(fd) };
    let result = unsafe {
        libc::connect(
            stream.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error());
    }
    stream.set_nonblocking(false)?;
    Ok(stream)
}
fn authenticate_peer(stream: &UnixStream) -> Result<AuthenticatedHuman, HumanTransportError> {
    let uid = peer_uid(stream)?;
    require_human_uid(uid, unsafe { libc::geteuid() })?;
    Ok(AuthenticatedHuman::from_peer_uid(uid))
}

fn require_human_uid(uid: u32, provider_uid: u32) -> Result<(), HumanTransportError> {
    if uid != provider_uid {
        return Err(HumanTransportError);
    }
    Ok(())
}
fn private_metadata(
    expected_kind: bool,
    uid: u32,
    mode: u32,
    owner_uid: u32,
    permissions: u32,
) -> Result<(), HumanTransportError> {
    if !expected_kind || uid != owner_uid || mode & 0o777 != permissions {
        return Err(HumanTransportError);
    }
    Ok(())
}
fn private_directory(root: &Path) -> Result<(), HumanTransportError> {
    let metadata = fs::symlink_metadata(root).map_err(|_error| HumanTransportError)?;
    private_metadata(
        metadata.is_dir(),
        metadata.uid(),
        metadata.mode(),
        unsafe { libc::geteuid() },
        0o700,
    )
}
fn private_socket(metadata: &fs::Metadata) -> Result<(), HumanTransportError> {
    private_metadata(
        metadata.file_type().is_socket(),
        metadata.uid(),
        metadata.mode(),
        unsafe { libc::geteuid() },
        0o600,
    )
}
#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<u32, HumanTransportError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    validated_peer_uid(result, size, credentials.uid)
}
#[cfg(target_os = "linux")]
fn validated_peer_uid(
    result: libc::c_int,
    returned_size: libc::socklen_t,
    uid: libc::uid_t,
) -> Result<u32, HumanTransportError> {
    if result != 0 || returned_size as usize != std::mem::size_of::<libc::ucred>() {
        return Err(HumanTransportError);
    }
    Ok(uid)
}
#[cfg(not(target_os = "linux"))]
fn peer_uid(_: &UnixStream) -> Result<u32, HumanTransportError> {
    Err(HumanTransportError)
}

fn read_frame(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>, HumanTransportError> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(HumanTransportError)?;
        stream
            .set_read_timeout(Some(remaining))
            .map_err(|_error| HumanTransportError)?;
        let count = stream
            .read(&mut chunk)
            .map_err(|_error| HumanTransportError)?;
        if count == 0 {
            return Ok(bytes);
        }
        if count > MAX_FRAME.saturating_sub(bytes.len()) {
            return Err(HumanTransportError);
        }
        bytes.extend_from_slice(&chunk[..count]);
    }
}
fn write_frame(stream: &mut UnixStream, bytes: &[u8]) -> Result<(), HumanTransportError> {
    if bytes.len() > MAX_FRAME {
        return Err(HumanTransportError);
    }
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut remaining = bytes;
    while !remaining.is_empty() {
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(HumanTransportError)?;
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|_error| HumanTransportError)?;
        let count = stream
            .write(remaining)
            .map_err(|_error| HumanTransportError)?;
        if count == 0 {
            return Err(HumanTransportError);
        }
        remaining = &remaining[count..];
    }
    stream
        .shutdown(Shutdown::Write)
        .map_err(|_error| HumanTransportError)
}
fn serve_one(
    mut stream: UnixStream,
    owner: AuthenticatedHuman,
    app: &ProviderApplication,
    launcher: &dyn DirectReviewLauncher,
) {
    let response = match read_frame(&mut stream, IO_TIMEOUT)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<HumanMessage>(&bytes).ok())
    {
        Some(HumanMessage {
            version: 1,
            command,
        }) => match command {
            HumanCommand::Request { submission } => {
                match app.submit_direct(owner, submission, launcher) {
                    Ok(receipt) => HumanResponse::Submitted { receipt },
                    Err(reason) => HumanResponse::Rejected { reason },
                }
            }
            HumanCommand::Status { id } => match app.direct_status(owner, &id) {
                Ok(state) => HumanResponse::Status { state },
                Err(reason) => HumanResponse::Rejected { reason },
            },
        },
        _ => HumanResponse::InvalidRequest,
    };
    if let Ok(bytes) = serde_json::to_vec(&response) {
        let _ignored = write_frame(&mut stream, &bytes);
    }
}

/// Validate filesystem ownership and server kernel credentials before sending input.
pub fn exchange(root: &Path, command: HumanCommand) -> Result<HumanResponse, HumanTransportError> {
    private_directory(root)?;
    let path = root.join(SOCKET_NAME);
    private_socket(&fs::symlink_metadata(&path).map_err(|_error| HumanTransportError)?)?;
    let mut stream = connect_private(&path).map_err(|_error| HumanTransportError)?;
    require_human_uid(peer_uid(&stream)?, unsafe { libc::geteuid() })?;
    let bytes = serde_json::to_vec(&HumanMessage {
        version: 1,
        command,
    })
    .map_err(|_error| HumanTransportError)?;
    write_frame(&mut stream, &bytes)?;
    serde_json::from_slice(&read_frame(&mut stream, Duration::from_secs(10))?)
        .map_err(|_error| HumanTransportError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{ports::*, provider::Provider};
    use crate::adapters::session::MonotonicClock;
    use std::sync::atomic::AtomicUsize;
    struct Backend;
    impl ProviderSession for Backend {
        fn probe_compatibility(&mut self) -> Result<(), SessionError> {
            Ok(())
        }
        fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
            Ok(Duration::from_secs(900))
        }
        fn clear(&mut self) -> Result<(), SessionError> {
            Ok(())
        }
    }
    impl SecretBackend for Backend {
        fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
            Ok(true)
        }
        fn resolve(
            &mut self,
            _: &CredentialBinding<'_>,
        ) -> Result<Vec<SensitiveString>, SessionError> {
            panic!("transport must not resolve credentials")
        }
    }
    struct Launcher(AtomicUsize);
    impl DirectReviewLauncher for Launcher {
        fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
            self.0.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }
    fn private_temp() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    fn raw_exchange(root: &Path, bytes: &[u8]) -> HumanResponse {
        let mut client = connect_private(&root.join(SOCKET_NAME)).unwrap();
        write_frame(&mut client, bytes).unwrap();
        serde_json::from_slice(&read_frame(&mut client, Duration::from_secs(10)).unwrap()).unwrap()
    }
    #[test]
    fn actual_socket_authenticates_kernel_peer_rejects_input_and_cleans_up() {
        let directory = private_temp();
        let root = directory.path().join("provider");
        let app = Arc::new(
            ProviderApplication::new(
                Provider::start(&root).unwrap(),
                Box::new(Backend),
                Box::<MonotonicClock>::default(),
            )
            .unwrap(),
        );
        let before = fs::read(root.join("provider-state.json")).unwrap();
        let socket = HumanSocket::bind(&root).unwrap();
        assert_eq!(
            fs::metadata(root.join(SOCKET_NAME)).unwrap().mode() & 0o777,
            0o600
        );
        let launcher = Arc::new(Launcher(AtomicUsize::new(0)));
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let app = app.clone();
            let launcher = launcher.clone();
            let stop = stop.clone();
            std::thread::spawn(move || socket.serve(app, launcher, stop))
        };
        let response = exchange(
            &root,
            HumanCommand::Request {
                submission: DirectSubmission {
                    operation: "deploy".into(),
                    revision: None,
                    values: vec!["private-input-sentinel".into()],
                },
            },
        )
        .unwrap();
        assert!(matches!(
            response,
            HumanResponse::Rejected {
                reason: DirectRequestError::Locked
            }
        ));
        for input in [
            r#"{"version":2,"command":{"kind":"status","id":"sentinel"}}"#,
            r#"{"version":1,"uid":0,"command":{"kind":"status","id":"sentinel"}}"#,
            r#"{"version":1,"command":{"kind":"status","id":"sentinel","time":0}}"#,
            r#"{"version":1,"command":{"kind":"request","submission":{"operation":"deploy","revision":null,"values":[],"expires_at":999}}}"#,
            r#"{"version":1,"command":{"kind":"request","submission":{"operation":"deploy","revision":null,"values":[],"owner":"sentinel"}}}"#,
            "private-input-sentinel",
        ] {
            let response = raw_exchange(&root, input.as_bytes());
            assert!(matches!(response, HumanResponse::InvalidRequest));
            assert!(
                !serde_json::to_string(&response)
                    .unwrap()
                    .contains("sentinel")
            );
        }
        assert_eq!(launcher.0.load(Ordering::Relaxed), 0);
        assert_eq!(fs::read(root.join("provider-state.json")).unwrap(), before);
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        assert!(!root.join(SOCKET_NAME).exists());
    }
    #[test]
    fn private_boundary_rejects_unsafe_root_socket_symlink_and_active_listener() {
        let directory = private_temp();
        let socket = HumanSocket::bind(directory.path()).unwrap();
        assert!(HumanSocket::bind(directory.path()).is_err());
        let (client, server) = UnixStream::pair().unwrap();
        assert_eq!(peer_uid(&client).unwrap(), unsafe { libc::geteuid() });
        assert!(authenticate_peer(&server).is_ok());
        fs::set_permissions(
            directory.path().join(SOCKET_NAME),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert!(
            exchange(
                directory.path(),
                HumanCommand::Status {
                    id: "sentinel".into()
                }
            )
            .is_err()
        );
        drop(socket);
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o755)).unwrap();
        assert!(HumanSocket::bind(directory.path()).is_err());
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink("missing", directory.path().join(SOCKET_NAME)).unwrap();
        assert!(HumanSocket::bind(directory.path()).is_err());
    }
    #[test]
    fn full_live_listener_backlog_is_not_recovered_as_a_stale_socket() {
        let directory = private_temp();
        let path = directory.path().join(SOCKET_NAME);
        let socket = HumanSocket::bind(directory.path()).unwrap();
        // A small real kernel backlog makes saturation bounded and deterministic.
        assert_eq!(unsafe { libc::listen(socket.listener.as_raw_fd(), 1) }, 0);
        let before = fs::symlink_metadata(&path).unwrap();
        let fallback_listener = socket.listener.try_clone().unwrap();
        let (release, wait) = std::sync::mpsc::channel();
        let fallback = std::thread::spawn(move || {
            // A broken nonblocking flag must fail this test, not hang its process.
            if wait.recv_timeout(Duration::from_secs(10))
                != Err(std::sync::mpsc::RecvTimeoutError::Timeout)
            {
                return;
            }
            loop {
                match wait.try_recv() {
                    Ok(()) | Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
                    Err(std::sync::mpsc::TryRecvError::Empty) => {}
                }
                let _ignored = fallback_listener.accept();
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        let mut clients = Vec::new();
        loop {
            match connect_private(&path) {
                Ok(client) => {
                    clients.push(client);
                    assert!(clients.len() < 16, "listener backlog did not saturate");
                }
                Err(error) => {
                    assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
                    break;
                }
            }
        }
        // All ownership, type and mode checks pass. Only the non-refused connect
        // error must stop recovery, before either unlinking or rebinding the path.
        assert!(HumanSocket::bind(directory.path()).is_err());
        let after = fs::symlink_metadata(&path).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        let (_accepted, _) = socket.listener.accept().unwrap();
        assert!(connect_private(&path).is_ok());
        release.send(()).unwrap();
        fallback.join().unwrap();
    }
    #[test]
    fn descriptor_exhaustion_and_valid_zero_are_isolated_in_child_processes() {
        for case in ["exhausted", "zero"] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "adapters::human_socket::tests::isolated_descriptor_fixture",
                    "--ignored",
                    "--nocapture",
                ])
                .env("VW_TEST_SOCKET_DESCRIPTOR_CASE", case)
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "descriptor case {case} failed: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    #[test]
    #[ignore = "isolated process fixture invoked by descriptor regression wrapper"]
    fn isolated_descriptor_fixture() {
        match std::env::var("VW_TEST_SOCKET_DESCRIPTOR_CASE")
            .unwrap()
            .as_str()
        {
            "exhausted" => {
                let limit = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
                assert_eq!(
                    connect_private(Path::new("/unused-synthetic-socket"))
                        .unwrap_err()
                        .raw_os_error(),
                    Some(libc::EMFILE)
                );
            }
            "zero" => {
                let directory = private_temp();
                let socket = HumanSocket::bind(directory.path()).unwrap();
                assert_eq!(unsafe { libc::close(libc::STDIN_FILENO) }, 0);
                let stream = connect_private(&socket.path).unwrap();
                assert_eq!(stream.as_raw_fd(), 0);
                assert_eq!(peer_uid(&stream).unwrap(), unsafe { libc::geteuid() });
            }
            _ => panic!("unknown isolated descriptor case"),
        }
    }
    #[test]
    fn connected_transport_descriptor_remains_close_on_exec() {
        let directory = private_temp();
        let socket = HumanSocket::bind(directory.path()).unwrap();
        let client = connect_private(&socket.path).unwrap();
        let flags = unsafe { libc::fcntl(client.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::FD_CLOEXEC, 0);
    }
    #[test]
    fn empty_and_embedded_nul_paths_fail_before_connecting_a_valid_prefix() {
        use std::os::unix::ffi::OsStringExt;
        assert_eq!(
            connect_private(Path::new("")).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        let directory = private_temp();
        let socket = HumanSocket::bind(directory.path()).unwrap();
        let mut bytes = socket.path.as_os_str().as_bytes().to_vec();
        bytes.extend_from_slice(b"\0ignored-suffix");
        let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        assert_eq!(
            connect_private(&path).unwrap_err().kind(),
            std::io::ErrorKind::InvalidInput
        );
        assert_eq!(
            socket.listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn oversized_path_is_rejected_before_kernel_truncation_can_connect() {
        // Linux can bind a full 108-byte sockaddr path. Rust's connector contract
        // reserves a trailing NUL; a skipped length check would silently connect
        // to this valid truncated prefix instead of rejecting the longer input.
        let directory = private_temp();
        let prefix = format!("{}/", directory.path().display());
        let name = format!("{}{}", prefix, "x".repeat(108 - prefix.len()));
        let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
        assert_eq!(address.sun_path.len(), 108);
        address.sun_family = libc::AF_UNIX as libc::sa_family_t;
        for (destination, source) in address.sun_path.iter_mut().zip(name.as_bytes()) {
            *destination = *source as libc::c_char;
        }
        let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
        assert!(fd >= 0);
        let listener = unsafe { UnixListener::from_raw_fd(fd) };
        assert_eq!(
            unsafe {
                libc::bind(
                    listener.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
                )
            },
            0
        );
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 1) }, 0);
        listener.set_nonblocking(true).unwrap();
        for name in [name.clone(), format!("{name}extra")] {
            assert_eq!(
                connect_private(Path::new(&name)).unwrap_err().kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }
    fn wait_finished(worker: &std::thread::JoinHandle<()>) {
        let deadline = Instant::now() + Duration::from_secs(10);
        while !worker.is_finished() {
            assert!(Instant::now() < deadline, "worker did not finish");
            std::thread::yield_now();
        }
    }
    #[test]
    fn finished_successful_workers_release_capacity_without_failure() {
        let mut workers: Vec<_> = (0..24).map(|_| std::thread::spawn(|| {})).collect();
        for worker in &workers {
            wait_finished(worker);
        }
        assert!(!reap_finished_workers(&mut workers));
        assert!(workers.is_empty());
        assert!(!reap_finished_workers(&mut workers));
    }
    #[test]
    fn any_panicked_worker_is_reported_while_running_workers_remain() {
        for failures in [1, 2] {
            let (release, wait) = std::sync::mpsc::channel();
            // Bound even a mutant that mistakenly joins the live worker; a timeout
            // lets that mutation finish and fail an assertion rather than hang.
            let running = std::thread::spawn(move || {
                let _ignored = wait.recv_timeout(Duration::from_secs(10));
            });
            let successful = std::thread::spawn(|| {});
            wait_finished(&successful);
            let mut workers = vec![running, successful];
            for _ in 0..failures {
                let failed = std::thread::spawn(|| panic!("synthetic worker failure"));
                wait_finished(&failed);
                workers.push(failed);
            }
            // Reverse traversal joins the panics before a success. Neither a later
            // success nor a second panic may erase an earlier failure.
            assert!(reap_finished_workers(&mut workers));
            assert_eq!(workers.len(), 1);
            assert!(!workers[0].is_finished());
            assert!(!reap_finished_workers(&mut workers));
            release.send(()).unwrap();
            wait_finished(&workers[0]);
            assert!(!reap_finished_workers(&mut workers));
            assert!(workers.is_empty());
        }
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn peer_credentials_require_success_and_complete_structure_independently() {
        let complete = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
        for uid in [0, 1, 4242, u32::MAX] {
            assert_eq!(validated_peer_uid(0, complete, uid), Ok(uid));
            assert!(validated_peer_uid(-1, complete, uid).is_err());
            assert!(validated_peer_uid(1, complete, uid).is_err());
            for incomplete in [0, complete - 1, complete + 1] {
                assert!(validated_peer_uid(0, incomplete, uid).is_err());
            }
        }
    }
    #[test]
    fn only_an_empty_nonblocking_accept_backlog_is_retryable() {
        use std::io::{Error, ErrorKind};
        assert!(
            accepted_connection(Err(Error::from(ErrorKind::WouldBlock)))
                .unwrap()
                .is_none()
        );
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::ConnectionAborted,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert!(accepted_connection(Err(Error::from(kind))).is_err());
        }
        let (client, server) = UnixStream::pair().unwrap();
        let address = server.peer_addr().unwrap();
        let returned = accepted_connection(Ok((server, address))).unwrap().unwrap();
        assert_eq!(peer_uid(&returned).unwrap(), peer_uid(&client).unwrap());
    }
    #[test]
    fn socket_lookup_allows_only_missing_and_rejects_other_errors_before_bind() {
        use std::io::{Error, ErrorKind};
        assert!(
            existing_socket_metadata(Err(Error::from(ErrorKind::NotFound)))
                .unwrap()
                .is_none()
        );
        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::Interrupted,
            ErrorKind::WouldBlock,
            ErrorKind::InvalidInput,
            ErrorKind::Other,
        ] {
            assert!(existing_socket_metadata(Err(Error::from(kind))).is_err());
        }
        // Successful lookup is preserved for the subsequent independent socket
        // ownership/type/mode checks; this classifier does not confer authority.
        let directory = private_temp();
        let original = fs::symlink_metadata(directory.path()).unwrap();
        let returned = existing_socket_metadata(Ok(original.clone()))
            .unwrap()
            .unwrap();
        assert_eq!(
            (returned.dev(), returned.ino()),
            (original.dev(), original.ino())
        );
    }
    #[test]
    fn stale_socket_rebinds_and_drop_preserves_replacement_inode() {
        let directory = private_temp();
        let path = directory.path().join(SOCKET_NAME);
        let stale = UnixListener::bind(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        drop(stale);
        let socket = HumanSocket::bind(directory.path()).unwrap();
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        drop(socket);
        assert!(path.exists());
        drop(replacement);
    }
    #[test]
    fn frames_require_eof_reject_oversize_and_bound_slow_input_time() {
        let (mut client, mut server) = UnixStream::pair().unwrap();
        client.write_all(b"{}").unwrap();
        let start = Instant::now();
        assert!(read_frame(&mut server, Duration::from_millis(30)).is_err());
        assert!(start.elapsed() < Duration::from_secs(1));
        let (mut client, mut server) = UnixStream::pair().unwrap();
        let writer = std::thread::spawn(move || {
            let _ignored = client.write_all(&vec![b'x'; MAX_FRAME + 1]);
        });
        assert!(read_frame(&mut server, IO_TIMEOUT).is_err());
        drop(server);
        writer.join().unwrap();
        let (mut client, _) = UnixStream::pair().unwrap();
        assert!(write_frame(&mut client, &vec![0; MAX_FRAME + 1]).is_err());
    }
    #[test]
    fn client_allows_desktop_handoff_longer_than_hostile_input_deadline() {
        let directory = private_temp();
        let socket = HumanSocket::bind(directory.path()).unwrap();
        let root = directory.path().to_owned();
        let client = std::thread::spawn(move || {
            exchange(
                &root,
                HumanCommand::Status {
                    id: "opaque".into(),
                },
            )
        });
        let accept_deadline = Instant::now() + Duration::from_secs(10);
        let mut server = loop {
            assert!(
                Instant::now() < accept_deadline,
                "client failed to connect before deadline"
            );
            match socket.listener.accept() {
                Ok((server, _)) => break server,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                Err(e) => panic!("accept failed: {e}"),
            }
        };
        read_frame(&mut server, IO_TIMEOUT).unwrap();
        std::thread::sleep(IO_TIMEOUT + Duration::from_millis(100));
        write_frame(
            &mut server,
            br#"{"result":"status","state":{"status":"pending"}}"#,
        )
        .unwrap();
        assert!(matches!(
            client.join().unwrap().unwrap(),
            HumanResponse::Status {
                state: DirectStatus::Pending
            }
        ));
    }
    #[test]
    fn uid_and_private_metadata_reject_each_independent_wrong_condition() {
        assert!(require_human_uid(1000, 1000).is_ok());
        assert!(require_human_uid(1001, 1000).is_err());
        assert!(require_human_uid(0, 1000).is_err());
        assert!(require_human_uid(1000, 0).is_err());
        for permissions in [0o600, 0o700] {
            assert!(
                private_metadata(true, 1000, 0o100000 | permissions, 1000, permissions).is_ok()
            );
            assert!(private_metadata(false, 1000, permissions, 1000, permissions).is_err());
            assert!(private_metadata(true, 1001, permissions, 1000, permissions).is_err());
            assert!(private_metadata(true, 1000, permissions | 0o040, 1000, permissions).is_err());
            assert!(private_metadata(true, 1000, permissions | 0o004, 1000, permissions).is_err());
            assert!(private_metadata(true, 1000, permissions ^ 0o200, 1000, permissions).is_err());
        }
        let dir = private_temp();
        let real = dir.path().join("private");
        fs::create_dir(&real).unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o700)).unwrap();
        let linked = dir.path().join("linked");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert!(private_directory(&real).is_ok());
        assert!(private_directory(&linked).is_err());
        let ordinary = dir.path().join("ordinary");
        fs::write(&ordinary, b"").unwrap();
        fs::set_permissions(&ordinary, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(private_socket(&fs::symlink_metadata(ordinary).unwrap()).is_err());
    }
    #[test]
    fn literal_two_mebibyte_frame_boundary_is_independent_of_production_constant() {
        for size in [2_097_152, 2_097_153] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let writer = std::thread::spawn(move || {
                let _ignored = client.write_all(&vec![b'x'; size]);
            });
            let result = read_frame(&mut server, Duration::from_secs(5));
            drop(server);
            writer.join().unwrap();
            if size == 2_097_152 {
                assert_eq!(result.unwrap(), vec![b'x'; 2_097_152]);
            } else {
                assert!(result.is_err());
            }
        }
        for size in [2_097_152, 2_097_153] {
            let (mut client, mut server) = UnixStream::pair().unwrap();
            let reader = std::thread::spawn(move || {
                server
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut bytes = Vec::new();
                server.read_to_end(&mut bytes).unwrap();
                bytes
            });
            let result = write_frame(&mut client, &vec![b'x'; size]);
            drop(client);
            let bytes = reader.join().unwrap();
            if size == 2_097_152 {
                assert!(result.is_ok());
                assert_eq!(bytes, vec![b'x'; 2_097_152]);
            } else {
                assert!(result.is_err());
                assert!(bytes.is_empty());
            }
        }
    }
    #[test]
    #[cfg(target_os = "linux")]
    fn sixteen_admitted_socket_workers_reject_excess_then_recover_capacity() {
        let directory = private_temp();
        let root = directory.path().join("provider");
        let app = Arc::new(
            ProviderApplication::new(
                Provider::start(&root).unwrap(),
                Box::new(Backend),
                Box::<MonotonicClock>::default(),
            )
            .unwrap(),
        );
        let socket = HumanSocket::bind(&root).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker = {
            let (app, stop) = (app.clone(), stop.clone());
            std::thread::spawn(move || {
                socket.serve(app, Arc::new(Launcher(AtomicUsize::new(0))), stop)
            })
        };
        let mut held = Vec::new();
        for _ in 0..16 {
            let mut stream = connect_private(&root.join(SOCKET_NAME)).unwrap();
            stream.write_all(b"{").unwrap();
            // On a Unix stream, TIOCOUTQ reaches zero when the peer consumes our
            // prefix. This synchronizes with the real admitted parsing worker;
            // withholding EOF then keeps that worker inside its bounded read.
            let limit = Instant::now() + Duration::from_secs(1);
            loop {
                let mut pending: libc::c_int = -1;
                assert_eq!(
                    unsafe { libc::ioctl(stream.as_raw_fd(), libc::TIOCOUTQ, &mut pending) },
                    0
                );
                if pending == 0 {
                    break;
                }
                assert!(Instant::now() < limit, "worker did not consume prefix");
                std::thread::yield_now();
            }
            stream.set_nonblocking(true).unwrap();
            let mut byte = [0];
            assert!(
                matches!(stream.read(&mut byte),Err(error) if error.kind()==std::io::ErrorKind::WouldBlock)
            );
            stream.set_nonblocking(false).unwrap();
            held.push(stream);
        }
        let mut excess = connect_private(&root.join(SOCKET_NAME)).unwrap();
        excess
            .set_read_timeout(Some(Duration::from_millis(250)))
            .unwrap();
        let mut byte = [0];
        let rejected = match excess.read(&mut byte) {
            Ok(0) => true,
            Err(error) => error.kind() == std::io::ErrorKind::ConnectionReset,
            _ => false,
        };
        for stream in &held {
            stream.shutdown(Shutdown::Write).unwrap();
        }
        for mut stream in held {
            let bytes = read_frame(&mut stream, Duration::from_secs(2)).unwrap();
            assert!(matches!(
                serde_json::from_slice::<HumanResponse>(&bytes).unwrap(),
                HumanResponse::InvalidRequest
            ));
        }
        let limit = Instant::now() + Duration::from_secs(2);
        let recovered = loop {
            if let Ok(response) = exchange(
                &root,
                HumanCommand::Status {
                    id: "unknown".into(),
                },
            ) {
                break matches!(
                    response,
                    HumanResponse::Rejected {
                        reason: DirectRequestError::NotFound
                    }
                );
            }
            if Instant::now() >= limit {
                break false;
            }
            std::thread::yield_now();
        };
        stop.store(true, Ordering::Release);
        worker.join().unwrap().unwrap();
        assert!(
            rejected,
            "seventeenth connection must be rejected while all sixteen workers are admitted"
        );
        assert!(
            recovered,
            "released parsing capacity must accept a new request"
        );
    }
}
