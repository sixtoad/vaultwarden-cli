//! Bounded agent-only transport. Kernel identity is checked before JSON decoding.
use crate::access::{
    application::ProviderApplication,
    ports::DirectReviewLauncher,
    protocol::{
        AgentEnvelope, AgentRejection, AgentResponse, MAX_REQUEST_FRAME_BYTES,
        MAX_RESPONSE_FRAME_BYTES, SignedStatusQuery, SignedSubmission,
    },
};
use ed25519_dalek::SigningKey;
use std::{
    ffi::CString,
    fs::{self, File},
    io::Read,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
            net::UnixListener as StdListener,
        },
    },
    path::{Component, Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::Semaphore,
    task::JoinSet,
    time::{Instant, timeout, timeout_at},
};
use zeroize::Zeroizing;

pub const SOCKET_NAME: &str = "agent.sock";
const MAX_CONNECTIONS: usize = 32;
const MAX_GROUPS: usize = 65536;
const IO_TIMEOUT: Duration = Duration::from_secs(5);
#[cfg(test)]
type ClientConnectedHook = std::cell::RefCell<Option<Box<dyn FnOnce(&Path)>>>;
#[cfg(test)]
thread_local! { static CLIENT_CONNECTED_HOOK: ClientConnectedHook = std::cell::RefCell::new(None); }
#[cfg(test)]
type FrameChunkHook = std::cell::RefCell<Option<Box<dyn FnMut(&[u8])>>>;
#[cfg(test)]
thread_local! { static FRAME_CHUNK_HOOK: FrameChunkHook = std::cell::RefCell::new(None); }

#[cfg(test)]
type ClientResponseReadHook = std::cell::RefCell<
    Option<(
        tokio::sync::oneshot::Sender<()>,
        tokio::sync::oneshot::Receiver<()>,
    )>,
>;
#[cfg(test)]
thread_local! { static CLIENT_RESPONSE_READ_HOOK: ClientResponseReadHook = const { std::cell::RefCell::new(None) }; }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentTransportError;
impl std::fmt::Display for AgentTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("agent transport unavailable")
    }
}
impl std::error::Error for AgentTransportError {}

/// Open each directory component without following links and retain its inode.
/// All later socket operations are relative to this descriptor, including cleanup.
fn open_directory(path: &Path) -> Result<File, AgentTransportError> {
    let mut directory = open_at(
        libc::AT_FDCWD,
        if path.is_absolute() { b"/" } else { b"." },
        libc::O_PATH | libc::O_DIRECTORY,
    )?;
    for part in path.components() {
        match part {
            Component::RootDir | Component::CurDir => {}
            Component::Normal(name) => {
                directory = open_at(
                    directory.as_raw_fd(),
                    name.as_bytes(),
                    libc::O_PATH | libc::O_DIRECTORY,
                )?
            }
            _ => return Err(AgentTransportError),
        }
    }
    Ok(directory)
}
fn open_at(
    parent: libc::c_int,
    name: &[u8],
    flags: libc::c_int,
) -> Result<File, AgentTransportError> {
    let name = CString::new(name).map_err(|_error| AgentTransportError)?;
    let fd = unsafe {
        libc::openat(
            parent,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(AgentTransportError);
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn descriptor_path(directory: &File, name: &std::ffi::OsStr) -> PathBuf {
    PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd())).join(name)
}
fn checked_directory(
    directory: &File,
    owner: Option<u32>,
    gid: Option<u32>,
) -> Result<fs::Metadata, AgentTransportError> {
    let metadata = directory.metadata().map_err(|_error| AgentTransportError)?;
    if !metadata.is_dir()
        || metadata.mode() & 0o7777 != 0o750
        || owner.is_some_and(|uid| metadata.uid() != uid)
        || gid.is_some_and(|gid| metadata.gid() != gid)
    {
        return Err(AgentTransportError);
    }
    Ok(metadata)
}
fn checked_socket(
    path: &Path,
    directory: &fs::Metadata,
) -> Result<fs::Metadata, AgentTransportError> {
    let metadata = fs::symlink_metadata(path).map_err(|_error| AgentTransportError)?;
    if !metadata.file_type().is_socket()
        || metadata.mode() & 0o7777 != 0o660
        || metadata.uid() != directory.uid()
        || metadata.gid() != directory.gid()
    {
        return Err(AgentTransportError);
    }
    Ok(metadata)
}

pub struct AgentSocket {
    listener: Option<StdListener>,
    directory: File,
    identity: (u64, u64),
}
impl AgentSocket {
    /// The deployment provisions the provider-owned 0750 directory and group.
    /// Refuse active listeners and unlink only a checked stale socket inode.
    pub fn bind(root: &Path, gid: u32) -> Result<Self, AgentTransportError> {
        let directory = open_directory(root)?;
        let metadata = checked_directory(&directory, Some(unsafe { libc::geteuid() }), Some(gid))?;
        let path = descriptor_path(&directory, SOCKET_NAME.as_ref());
        match fs::symlink_metadata(&path) {
            Ok(_) => {
                let before = checked_socket(&path, &metadata)?;
                match connect_nonblocking(&path) {
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {
                        let current = checked_socket(&path, &metadata)?;
                        if (before.dev(), before.ino()) != (current.dev(), current.ino()) {
                            return Err(AgentTransportError);
                        }
                        fs::remove_file(&path).map_err(|_error| AgentTransportError)?;
                    }
                    _ => return Err(AgentTransportError),
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(AgentTransportError),
        }
        let listener = StdListener::bind(&path).map_err(|_error| AgentTransportError)?;
        let inode = fs::symlink_metadata(&path).map_err(|_error| AgentTransportError)?;
        let socket = Self {
            listener: Some(listener),
            directory,
            identity: (inode.dev(), inode.ino()),
        };
        let name = c"agent.sock";
        if unsafe {
            libc::fchownat(
                socket.directory.as_raw_fd(),
                name.as_ptr(),
                metadata.uid(),
                gid,
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } != 0
            || unsafe { libc::fchmodat(socket.directory.as_raw_fd(), name.as_ptr(), 0o660, 0) } != 0
        {
            return Err(AgentTransportError);
        }
        let listener = socket.listener.as_ref().ok_or(AgentTransportError)?;
        if unsafe { libc::listen(listener.as_raw_fd(), MAX_CONNECTIONS as libc::c_int) } != 0 {
            return Err(AgentTransportError);
        }
        listener
            .set_nonblocking(true)
            .map_err(|_error| AgentTransportError)?;
        checked_socket(&path, &metadata)?;
        Ok(socket)
    }

    pub async fn serve(
        mut self,
        app: Arc<ProviderApplication>,
        launcher: Arc<dyn DirectReviewLauncher>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), AgentTransportError> {
        let listener = UnixListener::from_std(self.listener.take().ok_or(AgentTransportError)?)
            .map_err(|_error| AgentTransportError)?;
        let capacity = Arc::new(Semaphore::new(MAX_CONNECTIONS));
        let mut workers = JoinSet::new();
        let result = loop {
            if stop.load(Ordering::Acquire) || app.admission_closed() {
                break Ok(());
            }
            tokio::select! {
                result = workers.join_next(), if !workers.is_empty() => {
                    if !matches!(result, Some(Ok(()))) { break Err(AgentTransportError); }
                }
                accepted = listener.accept() => {
                    let (stream, _) = match accepted { Ok(pair) => pair, Err(_) => break Err(AgentTransportError) };
                    // Also bound completed-but-not-yet-reaped task registry entries.
                    if workers.len() >= MAX_CONNECTIONS { continue; }
                    let Ok(permit) = capacity.clone().try_acquire_owned() else { continue; };
                    let deadline = Instant::now() + IO_TIMEOUT;
                    let credentials = match peer_credentials(&stream) { Ok(peer) => peer, Err(_) => continue };
                    workers.spawn(serve_one(stream, credentials, app.clone(), launcher.clone(), Arc::new(permit), deadline));
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        };
        drop(listener);
        let closure = tokio::task::spawn_blocking(move || app.close_admission()).await;
        let mut clean = if closure.is_err() {
            Err(AgentTransportError)
        } else {
            result
        };
        // Never abort/detach authority work on input timeout or service shutdown.
        while let Some(result) = workers.join_next().await {
            if result.is_err() {
                clean = Err(AgentTransportError);
            }
        }
        clean
    }
}
impl Drop for AgentSocket {
    fn drop(&mut self) {
        let path = descriptor_path(&self.directory, SOCKET_NAME.as_ref());
        if let Ok(metadata) = fs::symlink_metadata(&path)
            && metadata.file_type().is_socket()
            && (metadata.dev(), metadata.ino()) == self.identity
        {
            let _ignored = fs::remove_file(path);
        }
    }
}

fn connect_nonblocking(path: &Path) -> std::io::Result<std::os::unix::net::UnixStream> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    let bytes = path.as_os_str().as_bytes();
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(std::io::ErrorKind::InvalidInput.into());
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
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(fd) };
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(stream)
}

struct PeerCredentials {
    uid: u32,
    groups: Vec<u32>,
}
fn peer_credentials(stream: &impl AsRawFd) -> Result<PeerCredentials, AgentTransportError> {
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut size = std::mem::size_of_val(&credentials) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut size,
        )
    };
    validate_peer_length(result, size as usize)?;
    let mut groups = vec![0u32; MAX_GROUPS];
    let mut size = (groups.len() * std::mem::size_of::<u32>()) as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERGROUPS,
            groups.as_mut_ptr().cast(),
            &mut size,
        )
    };
    let count = group_count(result, size as usize)?;
    groups.truncate(count);
    if !groups.contains(&credentials.gid) {
        groups.push(credentials.gid);
    }
    Ok(PeerCredentials {
        uid: credentials.uid,
        groups,
    })
}
fn validate_peer_length(result: libc::c_int, bytes: usize) -> Result<(), AgentTransportError> {
    if result != 0 || bytes != std::mem::size_of::<libc::ucred>() {
        return Err(AgentTransportError);
    }
    Ok(())
}
fn group_count(result: libc::c_int, bytes: usize) -> Result<usize, AgentTransportError> {
    if result != 0
        || bytes > MAX_GROUPS * std::mem::size_of::<u32>()
        || !bytes.is_multiple_of(std::mem::size_of::<u32>())
    {
        return Err(AgentTransportError);
    }
    Ok(bytes / std::mem::size_of::<u32>())
}

async fn serve_one(
    mut stream: UnixStream,
    peer: PeerCredentials,
    app: Arc<ProviderApplication>,
    launcher: Arc<dyn DirectReviewLauncher>,
    permit: Arc<tokio::sync::OwnedSemaphorePermit>,
    deadline: Instant,
) {
    let (eligibility_app, eligibility_permit, groups) =
        (app.clone(), permit.clone(), peer.groups.clone());
    let eligibility = tokio::task::spawn_blocking(move || {
        let _retained = eligibility_permit;
        eligibility_app.agent_peer_eligible(peer.uid, &groups)
    })
    .await;
    let response = match eligibility {
        Ok(Ok(())) => match read_frame(&mut stream, MAX_REQUEST_FRAME_BYTES, deadline).await {
            Ok(bytes) => match AgentEnvelope::parse(&bytes) {
                Ok(input) => {
                    let retained = permit.clone();
                    match tokio::task::spawn_blocking(move || {
                        let _retained = retained;
                        match input {
                            AgentEnvelope::Submission(input) => app
                                .submit_signed(peer.uid, &peer.groups, input, launcher.as_ref())
                                .map(AgentResponse::pending),
                            AgentEnvelope::Status(input) => app
                                .signed_agent_status(peer.uid, &peer.groups, &input)
                                .map(|state| AgentResponse::Status {
                                    protocol_version: crate::access::PROTOCOL_VERSION,
                                    request_id: input.request_id,
                                    state,
                                }),
                        }
                    })
                    .await
                    {
                        Ok(Ok(response)) => response,
                        Ok(Err(category)) => AgentResponse::rejected(category),
                        Err(_) => AgentResponse::rejected(AgentRejection::Unavailable),
                    }
                }
                Err(category) => AgentResponse::rejected(category),
            },
            Err(_) => AgentResponse::rejected(AgentRejection::Malformed),
        },
        Ok(Err(category)) => AgentResponse::rejected(category),
        Err(_) => AgentResponse::rejected(AgentRejection::Unavailable),
    };
    let _ignored = write_response(&mut stream, &response).await;
    // Closing a Unix stream with unread input resets the peer, even after the
    // rejection was written. Discard only after the response's write-half EOF;
    // this never parses input and retains the original deadline and byte bound.
    let _ignored = timeout_at(deadline, async {
        let mut chunk = [0u8; 4096];
        let mut remaining = MAX_REQUEST_FRAME_BYTES + 1;
        while remaining > 0 {
            let size = remaining.min(chunk.len());
            match stream.read(&mut chunk[..size]).await {
                Ok(0) | Err(_) => break,
                Ok(read) => remaining -= read,
            }
        }
    })
    .await;
}

async fn read_frame(
    stream: &mut UnixStream,
    limit: usize,
    deadline: Instant,
) -> Result<Vec<u8>, AgentTransportError> {
    timeout_at(deadline, async {
        let mut bytes = Vec::new();
        let mut saw_lf = false;
        let mut chunk = [0u8; 4096];
        loop {
            if Instant::now() >= deadline {
                return Err(AgentTransportError);
            }
            let read = stream
                .read(&mut chunk)
                .await
                .map_err(|_error| AgentTransportError)?;
            if Instant::now() >= deadline {
                return Err(AgentTransportError);
            }
            if read == 0 {
                break;
            }
            if saw_lf || bytes.len() + read > limit {
                return Err(AgentTransportError);
            }
            if let Some(index) = chunk[..read].iter().position(|byte| *byte == b'\n') {
                if index + 1 != read {
                    return Err(AgentTransportError);
                }
                saw_lf = true;
            }
            bytes.extend_from_slice(&chunk[..read]);
            #[cfg(test)]
            FRAME_CHUNK_HOOK.with(|hook| {
                if let Some(observe) = hook.borrow_mut().as_mut() {
                    observe(&chunk[..read]);
                }
            });
        }
        if !saw_lf || bytes.pop() != Some(b'\n') || bytes.is_empty() || bytes.last() == Some(&b'\r')
        {
            return Err(AgentTransportError);
        }
        Ok(bytes)
    })
    .await
    .map_err(|_error| AgentTransportError)?
}
async fn write_response(
    stream: &mut UnixStream,
    response: &AgentResponse,
) -> Result<(), AgentTransportError> {
    let mut bytes = serde_json::to_vec(response).map_err(|_error| AgentTransportError)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_RESPONSE_FRAME_BYTES {
        return Err(AgentTransportError);
    }
    timeout(IO_TIMEOUT, async {
        stream
            .write_all(&bytes)
            .await
            .map_err(|_error| AgentTransportError)?;
        stream
            .shutdown()
            .await
            .map_err(|_error| AgentTransportError)
    })
    .await
    .map_err(|_error| AgentTransportError)?
}

/// Raw 32-byte agent-owned 0600 seed, read through an already checked descriptor.
pub fn load_signing_key(path: &Path) -> Result<SigningKey, AgentTransportError> {
    let parent = open_directory(
        path.parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    let name = path.file_name().ok_or(AgentTransportError)?;
    let file = open_at(parent.as_raw_fd(), name.as_bytes(), libc::O_RDONLY)?;
    let metadata = file.metadata().map_err(|_error| AgentTransportError)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.len() != 32
    {
        return Err(AgentTransportError);
    }
    let mut seed = Zeroizing::new([0u8; 33]);
    let mut count = 0;
    let mut bounded = file.take(33);
    while count < seed.len() {
        let read = bounded
            .read(&mut seed[count..])
            .map_err(|_error| AgentTransportError)?;
        if read == 0 {
            break;
        }
        count += read;
    }
    if count != 32 {
        return Err(AgentTransportError);
    }
    let mut key_bytes = Zeroizing::new([0u8; 32]);
    key_bytes.copy_from_slice(&seed[..32]);
    Ok(SigningKey::from_bytes(&key_bytes))
}

/// Authenticate the socket owner before transmitting signed input. Never retries.
pub async fn exchange(
    path: &Path,
    input: &SignedSubmission,
) -> Result<AgentResponse, AgentTransportError> {
    let response = exchange_envelope(path, input).await?;
    match response {
        AgentResponse::Pending { .. } | AgentResponse::Rejected { .. } => Ok(response),
        AgentResponse::Status { .. } => Err(AgentTransportError),
    }
}

/// A fresh signature is required for each observation, including reconnects.
pub async fn query_exchange(
    path: &Path,
    input: &SignedStatusQuery,
) -> Result<AgentResponse, AgentTransportError> {
    let response = exchange_envelope(path, input).await?;
    match &response {
        AgentResponse::Status { request_id, .. } if request_id == &input.request_id => Ok(response),
        AgentResponse::Rejected { .. } => Ok(response),
        _ => Err(AgentTransportError),
    }
}

async fn exchange_envelope(
    path: &Path,
    input: &impl serde::Serialize,
) -> Result<AgentResponse, AgentTransportError> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut bytes = serde_json::to_vec(input).map_err(|_error| AgentTransportError)?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REQUEST_FRAME_BYTES {
        return Err(AgentTransportError);
    }
    let directory = open_directory(path.parent().ok_or(AgentTransportError)?)?;
    let owner = checked_directory(&directory, None, None)?;
    let pinned = descriptor_path(&directory, path.file_name().ok_or(AgentTransportError)?);
    let before = checked_socket(&pinned, &owner)?;
    let mut stream = timeout_at(deadline, UnixStream::connect(&pinned))
        .await
        .map_err(|_error| AgentTransportError)?
        .map_err(|_error| AgentTransportError)?;
    #[cfg(test)]
    CLIENT_CONNECTED_HOOK.with(|hook| {
        if let Some(replace) = hook.borrow_mut().take() {
            replace(&pinned);
        }
    });
    let after = checked_socket(&pinned, &owner)?;
    if (before.dev(), before.ino()) != (after.dev(), after.ino())
        || peer_credentials(&stream)?.uid != owner.uid()
    {
        return Err(AgentTransportError);
    }
    timeout_at(deadline, async {
        stream
            .write_all(&bytes)
            .await
            .map_err(|_error| AgentTransportError)?;
        stream
            .shutdown()
            .await
            .map_err(|_error| AgentTransportError)
    })
    .await
    .map_err(|_error| AgentTransportError)??;
    #[cfg(test)]
    {
        let hook = CLIENT_RESPONSE_READ_HOOK.with(|hook| hook.borrow_mut().take());
        if let Some((reached, resume)) = hook {
            reached.send(()).expect("exchange test observer dropped");
            resume.await.expect("exchange test controller dropped");
        }
    }
    let response = read_frame(&mut stream, MAX_RESPONSE_FRAME_BYTES, deadline).await?;
    AgentResponse::parse(&response).map_err(|_error| AgentTransportError)
}

#[cfg(test)]
#[path = "unix_socket_tests.rs"]
mod tests;
