//! Provider-private capability transfer. No credential enters systemd properties.
//! The manager must authenticate service identity and containment before `send`.

use crate::{
    access::ports::{ChildEnvironment, ExecutionOutcome},
    adapters::execution::PreparedExecutable,
};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    mem::{self, size_of},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd, RawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAGIC: &[u8; 5] = b"VWEX\x01";
const TRANSFER: u8 = 1;
const RELEASE: u8 = 2;
const READY: u8 = 3;
const EXEC: u8 = 4;
const ZERO: u8 = 5;
const NONZERO: u8 = 6;
const SIGNAL: u8 = 7;
const REAPED: u8 = 8;
const FAILED: u8 = 9;
const MAX_PACKET: usize = 2 * 32 * 1024 + 1024;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
const SEALS: i32 =
    libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL | 0x20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BridgeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Report {
    Ready,
    ExecConfirmed,
    Outcome(ExecutionOutcome),
    Reaped,
    Failed,
}

pub(crate) struct BridgeListener {
    socket: OwnedFd,
    directory: File,
    name: CString,
}

/// Directory handles keep bind and unlink scoped even if pathname components move.
impl BridgeListener {
    pub(crate) fn bind(path: &Path) -> Result<Self, BridgeError> {
        let _address_check = socket_address(path.as_os_str())?;
        let directory = private_parent(path)?;
        let name = CString::new(path.file_name().ok_or(BridgeError)?.as_bytes())
            .map_err(|_error| BridgeError)?;
        let anchored = format!("/proc/self/fd/{}/", directory.as_raw_fd());
        let mut address = anchored.into_bytes();
        address.extend_from_slice(name.as_bytes());
        let (address, length) = socket_address(OsStr::from_bytes(&address))?;
        let socket = socket()?;
        if unsafe {
            libc::bind(
                socket.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                length,
            )
        } != 0
        {
            return Err(BridgeError);
        }
        let listener = Self {
            socket,
            directory,
            name,
        };
        if unsafe {
            libc::fchmodat(
                listener.directory.as_raw_fd(),
                listener.name.as_ptr(),
                0o600,
                0,
            )
        } != 0
            || unsafe { libc::listen(listener.socket.as_raw_fd(), 1) } != 0
        {
            return Err(BridgeError);
        }
        Ok(listener)
    }

    /// A timeout is not a launch failure; callers can revalidate authority and poll.
    pub(crate) fn accept(
        &self,
        helper_pid: u32,
        timeout: Duration,
    ) -> Result<Option<Bridge>, BridgeError> {
        if !poll(self.socket.as_raw_fd(), libc::POLLIN, timeout)? {
            return Ok(None);
        }
        let raw = unsafe {
            libc::accept4(
                self.socket.as_raw_fd(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            )
        };
        if raw < 0 {
            return Err(BridgeError);
        }
        let socket = unsafe { OwnedFd::from_raw_fd(raw) };
        authenticate(socket.as_raw_fd(), helper_pid)?;
        Ok(Some(Bridge {
            socket,
            state: State::Connected,
        }))
    }
}
impl Drop for BridgeListener {
    fn drop(&mut self) {
        // Only remove the endpoint created by this listener in the retained directory.
        unsafe {
            libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0);
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Connected,
    Transferred,
    Ready,
    Released,
    Executed,
    Outcome,
    Failed,
    Reaped,
}
pub(crate) struct Bridge {
    socket: OwnedFd,
    state: State,
}
impl Bridge {
    pub(crate) fn send(
        &mut self,
        prepared: &PreparedExecutable,
        environment: &ChildEnvironment,
    ) -> Result<(), BridgeError> {
        if self.state != State::Connected {
            return Err(BridgeError);
        }
        let (fd, arguments) = prepared.descriptor_and_arguments();
        validate_descriptor(fd.as_raw_fd())?;
        let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PACKET));
        bytes.extend_from_slice(MAGIC);
        bytes.push(TRANSFER);
        bytes.extend_from_slice(&(arguments.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&(environment.entries().len() as u16).to_le_bytes());
        for entry in arguments
            .iter()
            .map(|s| s.as_bytes_with_nul())
            .chain(environment.entries())
        {
            bytes.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            bytes.extend_from_slice(entry);
        }
        if bytes.len() > MAX_PACKET {
            return Err(BridgeError);
        }
        send_packet(self.socket.as_raw_fd(), &bytes, Some(fd.as_raw_fd()))?;
        self.state = State::Transferred;
        Ok(())
    }

    /// Call only inside the provider's final authority/cancellation serialization.
    pub(crate) fn release(&mut self) -> Result<(), BridgeError> {
        if self.state != State::Ready {
            return Err(BridgeError);
        }
        send_code(self.socket.as_raw_fd(), RELEASE)?;
        self.state = State::Released;
        Ok(())
    }

    pub(crate) fn receive(&mut self, timeout: Duration) -> Result<Option<Report>, BridgeError> {
        let Some(packet) = receive_packet(self.socket.as_raw_fd(), timeout)? else {
            return Ok(None);
        };
        let code = packet.code()?;
        if !packet.fds.is_empty() || packet.bytes.len() != MAGIC.len() + 1 {
            return Err(BridgeError);
        }
        let (report, state) = match (code, self.state) {
            (READY, State::Transferred) => (Report::Ready, State::Ready),
            (EXEC, State::Released) => (Report::ExecConfirmed, State::Executed),
            (ZERO, State::Executed) => (
                Report::Outcome(ExecutionOutcome::ExitedZero),
                State::Outcome,
            ),
            (NONZERO, State::Executed) => (
                Report::Outcome(ExecutionOutcome::ExitedNonZero),
                State::Outcome,
            ),
            (SIGNAL, State::Executed) => {
                (Report::Outcome(ExecutionOutcome::Signaled), State::Outcome)
            }
            (FAILED, State::Transferred | State::Ready | State::Released | State::Executed) => {
                (Report::Failed, State::Failed)
            }
            (REAPED, State::Outcome | State::Failed) => (Report::Reaped, State::Reaped),
            _ => return Err(BridgeError),
        };
        self.state = state;
        Ok(Some(report))
    }
}

fn private_parent(path: &Path) -> Result<File, BridgeError> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|p| p == b"." || p == b"..")
    {
        return Err(BridgeError);
    }
    let parent = path.parent().ok_or(BridgeError)?;
    let mut fd = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_RDONLY,
        )
    };
    if fd < 0 {
        return Err(BridgeError);
    }
    let mut directory = unsafe { File::from_raw_fd(fd) };
    for component in parent.components() {
        if component == Component::RootDir {
            continue;
        }
        let Component::Normal(name) = component else {
            return Err(BridgeError);
        };
        let name = CString::new(name.as_bytes()).map_err(|_error| BridgeError)?;
        fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_RDONLY,
            )
        };
        if fd < 0 {
            return Err(BridgeError);
        }
        directory = unsafe { File::from_raw_fd(fd) };
        let metadata = directory.metadata().map_err(|_error| BridgeError)?;
        let uid = unsafe { libc::geteuid() };
        // A root-owned sticky directory (e.g. /tmp) cannot replace our owned child.
        if !(metadata.uid() == 0 || metadata.uid() == uid)
            || (metadata.mode() & 0o022 != 0
                && !(metadata.uid() == 0 && metadata.mode() & 0o1000 != 0))
        {
            return Err(BridgeError);
        }
    }
    let metadata = directory.metadata().map_err(|_error| BridgeError)?;
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o7777 != 0o700 {
        return Err(BridgeError);
    }
    Ok(directory)
}

fn socket_address(path: &OsStr) -> Result<(libc::sockaddr_un, libc::socklen_t), BridgeError> {
    let bytes = path.as_bytes();
    let mut address: libc::sockaddr_un = unsafe { mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(BridgeError);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    let length =
        (mem::offset_of!(libc::sockaddr_un, sun_path) + bytes.len() + 1) as libc::socklen_t;
    Ok((address, length))
}
fn socket() -> Result<OwnedFd, BridgeError> {
    let raw = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if raw < 0 {
        Err(BridgeError)
    } else {
        Ok(unsafe { OwnedFd::from_raw_fd(raw) })
    }
}
fn authenticate(fd: RawFd, pid: u32) -> Result<(), BridgeError> {
    let mut credentials: libc::ucred = unsafe { mem::zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    if pid == 0
        || pid > i32::MAX as u32
        || unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut credentials as *mut libc::ucred).cast(),
                &mut length,
            )
        } != 0
        || length as usize != size_of::<libc::ucred>()
        || credentials.pid != pid as i32
        || credentials.uid != unsafe { libc::geteuid() }
    {
        return Err(BridgeError);
    }
    Ok(())
}
fn poll(fd: RawFd, events: i16, timeout: Duration) -> Result<bool, BridgeError> {
    let deadline = Instant::now().checked_add(timeout).ok_or(BridgeError)?;
    loop {
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(i32::MAX as u128) as i32;
        let mut descriptor = libc::pollfd {
            fd,
            events,
            revents: 0,
        };
        let count = unsafe { libc::poll(&mut descriptor, 1, millis) };
        if count == 0 {
            return Ok(false);
        }
        if count > 0 {
            // A queued final packet remains readable even after peer close.
            if descriptor.revents & events != 0 {
                return Ok(true);
            }
            return Err(BridgeError);
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(BridgeError);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
    }
}

fn send_code(fd: RawFd, code: u8) -> Result<(), BridgeError> {
    let mut bytes = [0u8; 6];
    bytes[..5].copy_from_slice(MAGIC);
    bytes[5] = code;
    send_packet(fd, &bytes, None)
}
fn send_packet(fd: RawFd, bytes: &[u8], descriptor: Option<RawFd>) -> Result<(), BridgeError> {
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // usize alignment is sufficient for cmsghdr on supported Linux platforms.
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if let Some(descriptor) = descriptor {
        message.msg_control = control.as_mut_ptr().cast();
        // Ancillary lengths are u32 on musl and usize on glibc; these fixed
        // single-descriptor lengths fit either ABI's destination fields.
        message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as _;
            std::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), descriptor);
        }
    }
    // Nonblocking even at the release boundary: never wait while holding authority.
    let sent = unsafe { libc::sendmsg(fd, &message, libc::MSG_NOSIGNAL | libc::MSG_DONTWAIT) };
    if sent != bytes.len() as isize {
        return Err(BridgeError);
    }
    Ok(())
}

struct Packet {
    bytes: Zeroizing<Vec<u8>>,
    fds: Vec<OwnedFd>,
}
impl Packet {
    fn code(&self) -> Result<u8, BridgeError> {
        if self.bytes.len() < 6 || &self.bytes[..5] != MAGIC {
            return Err(BridgeError);
        }
        Ok(self.bytes[5])
    }
}
fn receive_packet(fd: RawFd, timeout: Duration) -> Result<Option<Packet>, BridgeError> {
    if !poll(fd, libc::POLLIN, timeout)? {
        return Ok(None);
    }
    let mut packet = Packet {
        bytes: Zeroizing::new(vec![0u8; MAX_PACKET]),
        fds: Vec::new(),
    };
    let mut vector = libc::iovec {
        iov_base: packet.bytes.as_mut_ptr().cast(),
        iov_len: packet.bytes.len(),
    };
    // Deliberately accommodate extra FDs so every installed fd is owned and closed.
    let mut control = [0usize; 64];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    // This fixed buffer fits both musl's u32 and glibc's usize length field.
    message.msg_controllen = size_of_val(&control) as _;
    let count = unsafe {
        libc::recvmsg(
            fd,
            &mut message,
            libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
        )
    };
    if count < 0 {
        return Err(BridgeError);
    }
    // A zero-byte SEQPACKET can still carry SCM_RIGHTS. Own every installed
    // descriptor before rejecting the empty protocol frame below.
    let mut invalid = message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0;
    let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    while !header.is_null() {
        let h = unsafe { &*header };
        // Widen musl's u32 length to usize before buffer arithmetic.
        let length: usize = h.cmsg_len as _;
        let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
        if length < minimum {
            invalid = true;
            break;
        }
        let size = length - minimum;
        if h.cmsg_level != libc::SOL_SOCKET
            || h.cmsg_type != libc::SCM_RIGHTS
            || !size.is_multiple_of(size_of::<RawFd>())
        {
            invalid = true;
        } else {
            for index in 0..size / size_of::<RawFd>() {
                let raw = unsafe {
                    std::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<RawFd>().add(index))
                };
                if raw < 0 {
                    invalid = true;
                } else {
                    packet.fds.push(unsafe { OwnedFd::from_raw_fd(raw) });
                }
            }
        }
        header = unsafe { libc::CMSG_NXTHDR(&message, header) };
    }
    if invalid {
        return Err(BridgeError);
    }
    packet.bytes.truncate(count as usize);
    packet.code()?;
    Ok(Some(packet))
}

fn validate_descriptor(fd: RawFd) -> Result<(), BridgeError> {
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if ![SEALS, SEALS | libc::F_SEAL_FUTURE_WRITE].contains(&seals)
        || unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o7777 != 0o500
        || stat.st_uid != unsafe { libc::geteuid() }
        || !(64..=64 * 1024 * 1024).contains(&stat.st_size)
        || unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0
    {
        return Err(BridgeError);
    }
    Ok(())
}

struct Launch {
    packet: Packet,
    arguments: Vec<usize>,
    environment: Vec<usize>,
}
impl Launch {
    fn parse(packet: Packet) -> Result<Self, BridgeError> {
        if packet.code()? != TRANSFER || packet.bytes.len() < 10 || packet.fds.len() != 1 {
            return Err(BridgeError);
        }
        validate_descriptor(packet.fds[0].as_raw_fd())?;
        let argc = u16::from_le_bytes([packet.bytes[6], packet.bytes[7]]) as usize;
        let envc = u16::from_le_bytes([packet.bytes[8], packet.bytes[9]]) as usize;
        if !(1..=128).contains(&argc) || !(2..=32).contains(&envc) {
            return Err(BridgeError);
        }
        let mut cursor = 10;
        let mut arguments = Vec::with_capacity(argc);
        let mut environment = Vec::with_capacity(envc);
        let mut totals = [0usize; 2];
        for index in 0..argc + envc {
            let length_bytes: [u8; 4] = packet
                .bytes
                .get(cursor..cursor + 4)
                .ok_or(BridgeError)?
                .try_into()
                .map_err(|_error| BridgeError)?;
            let length = u32::from_le_bytes(length_bytes) as usize;
            cursor += 4;
            let end = cursor.checked_add(length).ok_or(BridgeError)?;
            let value = packet.bytes.get(cursor..end).ok_or(BridgeError)?;
            if value.last() != Some(&0)
                || value[..value.len() - 1].contains(&0)
                || (index == 0 && value.len() < 2)
            {
                return Err(BridgeError);
            }
            let group = usize::from(index >= argc);
            totals[group] = totals[group].checked_add(length).ok_or(BridgeError)?;
            if totals[group] > 32 * 1024 {
                return Err(BridgeError);
            }
            if group == 0 {
                arguments.push(cursor);
            } else {
                environment.push(cursor);
            }
            cursor = end;
        }
        if cursor != packet.bytes.len() {
            return Err(BridgeError);
        }
        let mut names = std::collections::HashSet::new();
        for (index, offset) in environment.iter().enumerate() {
            let value =
                unsafe { std::ffi::CStr::from_ptr(packet.bytes.as_ptr().add(*offset).cast()) }
                    .to_bytes();
            if index < 2 {
                if value != [b"LANG=C".as_slice(), b"LC_ALL=C".as_slice()][index] {
                    return Err(BridgeError);
                }
                continue;
            }
            let equals = value.iter().position(|b| *b == b'=').ok_or(BridgeError)?;
            let name = &value[..equals];
            if name.is_empty()
                || name.len() > 128
                || !name.iter().enumerate().all(|(i, b)| {
                    *b == b'_' || b.is_ascii_uppercase() || (i > 0 && b.is_ascii_digit())
                })
                || [
                    b"LANG".as_slice(),
                    b"LC_ALL",
                    b"PATH",
                    b"IFS",
                    b"SHELL",
                    b"LD_PRELOAD",
                    b"LD_LIBRARY_PATH",
                ]
                .contains(&name)
                || name.starts_with(b"VAULTWARDEN_")
                || name.starts_with(b"BITWARDEN_")
                || !names.insert(name)
            {
                return Err(BridgeError);
            }
        }
        Ok(Self {
            packet,
            arguments,
            environment,
        })
    }
    fn pointers(&self, offsets: &[usize]) -> Vec<*const libc::c_char> {
        offsets
            .iter()
            .map(|offset| unsafe { self.packet.bytes.as_ptr().add(*offset).cast() })
            .chain(std::iter::once(std::ptr::null()))
            .collect()
    }
}

static TERMINATING: AtomicBool = AtomicBool::new(false);
extern "C" fn terminate(_: i32) {
    TERMINATING.store(true, Ordering::Relaxed);
}
fn initialize_helper() -> Result<(), BridgeError> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } != 0
        || unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } != 0
        || unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } != 0
    {
        return Err(BridgeError);
    }
    let mut action: libc::sigaction = unsafe { mem::zeroed() };
    action.sa_sigaction = terminate as *const () as usize;
    unsafe {
        libc::sigemptyset(&mut action.sa_mask);
    }
    for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
        if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } != 0 {
            return Err(BridgeError);
        }
    }
    Ok(())
}

/// Errors deliberately produce neither stderr nor interpolated OS diagnostics.
pub(crate) fn helper_entry() -> i32 {
    match helper() {
        Ok(()) => 0,
        Err(_) => 1,
    }
}
fn helper() -> Result<(), BridgeError> {
    initialize_helper()?;
    let mut arguments = std::env::args_os().skip(1);
    let path = arguments.next().ok_or(BridgeError)?;
    let provider_pid: u32 = arguments
        .next()
        .ok_or(BridgeError)?
        .to_str()
        .ok_or(BridgeError)?
        .parse()
        .map_err(|_error| BridgeError)?;
    if arguments.next().is_some() {
        return Err(BridgeError);
    }
    let _directory = private_parent(Path::new(&path))?;
    let socket = socket()?;
    let (address, length) = socket_address(&path)?;
    if unsafe {
        libc::connect(
            socket.as_raw_fd(),
            (&address as *const libc::sockaddr_un).cast(),
            length,
        )
    } != 0
    {
        return Err(BridgeError);
    }
    authenticate(socket.as_raw_fd(), provider_pid)?;
    let result = helper_session(socket.as_raw_fd());
    if result.is_err() {
        let _ignored = send_code(socket.as_raw_fd(), FAILED);
    }
    result
}
fn helper_session(socket: RawFd) -> Result<(), BridgeError> {
    let packet = receive_packet(socket, HANDSHAKE_TIMEOUT)?.ok_or(BridgeError)?;
    let launch = Launch::parse(packet)?;
    send_code(socket, READY)?;
    let packet = receive_packet(socket, HANDSHAKE_TIMEOUT)?.ok_or(BridgeError)?;
    if packet.code()? != RELEASE
        || packet.bytes.len() != 6
        || !packet.fds.is_empty()
        || TERMINATING.load(Ordering::Relaxed)
    {
        return Err(BridgeError);
    }
    let argv = launch.pointers(&launch.arguments);
    let envp = launch.pointers(&launch.environment);
    let mut pipe = [-1; 2];
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(BridgeError);
    }
    let read = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let null = unsafe {
        libc::open(
            c"/dev/null".as_ptr(),
            libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if null < 0 {
        return Err(BridgeError);
    }
    let null = unsafe { OwnedFd::from_raw_fd(null) };
    // Serialize local termination observation with fork. Pending stop signals
    // observed before the fork must never create a protected process.
    let mut blocked: libc::sigset_t = unsafe { mem::zeroed() };
    let mut previous: libc::sigset_t = unsafe { mem::zeroed() };
    unsafe {
        libc::sigemptyset(&mut blocked);
        for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
            libc::sigaddset(&mut blocked, signal);
        }
    }
    if unsafe { libc::sigprocmask(libc::SIG_BLOCK, &blocked, &mut previous) } != 0 {
        return Err(BridgeError);
    }
    let mut pending: libc::sigset_t = unsafe { mem::zeroed() };
    let stopping = unsafe { libc::sigpending(&mut pending) } != 0
        || TERMINATING.load(Ordering::Relaxed)
        || [libc::SIGTERM, libc::SIGINT, libc::SIGHUP]
            .iter()
            .any(|signal| unsafe { libc::sigismember(&pending, *signal) } == 1);
    if stopping {
        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        }
        return Err(BridgeError);
    }
    let parent = unsafe { libc::getpid() };
    let child = unsafe { libc::fork() };
    if child != 0 {
        unsafe {
            libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        }
    }
    if child < 0 {
        return Err(BridgeError);
    }
    if child == 0 {
        // Only async-signal-safe syscalls in this branch. The real creating thread
        // remains alive in the single-threaded helper until every child is reaped.
        unsafe {
            libc::close(read.as_raw_fd());
            if !arm_parent_death(parent) {
                child_fail(write.as_raw_fd());
            }
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(signal, libc::SIG_DFL);
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) != 0 {
                child_fail(write.as_raw_fd());
            }
            for output in 0..=2 {
                if libc::dup2(null.as_raw_fd(), output) < 0 {
                    child_fail(write.as_raw_fd());
                }
            }
            // A kernel exec event rules out EOF caused by pre-exec SIGKILL.
            if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0
                || libc::kill(libc::getpid(), libc::SIGSTOP) != 0
            {
                child_fail(write.as_raw_fd());
            }
            libc::syscall(
                libc::SYS_execveat,
                launch.packet.fds[0].as_raw_fd(),
                c"".as_ptr(),
                argv.as_ptr(),
                envp.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
            child_fail(write.as_raw_fd());
        }
    }
    drop(write);
    drop(null);
    // Parent no longer needs secret bytes or the image capability.
    drop(argv);
    drop(envp);
    drop(launch);
    report_exec_and_reap(socket, child, read)
}
fn report_exec_and_reap(
    socket: RawFd,
    child: libc::pid_t,
    read: OwnedFd,
) -> Result<(), BridgeError> {
    // A CLOEXEC error pipe is separate from the helper's successful exec/start job.
    // HUP is expected after successful exec, so observe read directly when poll returns.
    let confirmed = trace_exec(child) && confirm_exec(read.as_raw_fd());
    drop(read);
    let _ignored = send_code(socket, if confirmed { EXEC } else { FAILED });
    reap_all(socket, child, confirmed)
}
// Must compare against the actual creating helper, including death before prctl.
unsafe fn arm_parent_death(parent: libc::pid_t) -> bool {
    unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) == 0 && libc::getppid() == parent }
}
unsafe fn child_fail(fd: RawFd) -> ! {
    unsafe {
        libc::write(fd, [1u8].as_ptr().cast(), 1);
        libc::_exit(127);
    }
}
fn trace_exec(child: libc::pid_t) -> bool {
    fn wait(child: libc::pid_t) -> Option<i32> {
        loop {
            let mut status = 0;
            if unsafe { libc::waitpid(child, &mut status, 0) } == child {
                return Some(status);
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return None;
            }
        }
    }
    let Some(stopped) = wait(child) else {
        return false;
    };
    if !libc::WIFSTOPPED(stopped) || libc::WSTOPSIG(stopped) != libc::SIGSTOP {
        return false;
    }
    if unsafe {
        libc::ptrace(
            libc::PTRACE_SETOPTIONS,
            child,
            0,
            libc::PTRACE_O_TRACEEXEC | libc::PTRACE_O_EXITKILL,
        )
    } != 0
        || unsafe { libc::ptrace(libc::PTRACE_CONT, child, 0, 0) } != 0
    {
        return false;
    }
    let Some(event) = wait(child) else {
        return false;
    };
    libc::WIFSTOPPED(event)
        && event >> 16 == libc::PTRACE_EVENT_EXEC
        && unsafe { libc::ptrace(libc::PTRACE_DETACH, child, 0, 0) } == 0
}
fn confirm_exec(fd: RawFd) -> bool {
    loop {
        let mut byte = 0u8;
        let read = unsafe { libc::read(fd, (&mut byte as *mut u8).cast(), 1) };
        if read == 0 {
            return true;
        }
        if read > 0 {
            return false;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::WouldBlock && error.kind() != io::ErrorKind::Interrupted {
            return false;
        }
        let mut descriptor = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut descriptor, 1, 100);
        }
    }
}
fn reap_all(socket: RawFd, main: libc::pid_t, confirmed: bool) -> Result<(), BridgeError> {
    loop {
        let mut status = 0;
        let child = unsafe { libc::waitpid(-1, &mut status, 0) };
        if child > 0 {
            if child == main && confirmed {
                let code = if libc::WIFEXITED(status) {
                    if libc::WEXITSTATUS(status) == 0 {
                        ZERO
                    } else {
                        NONZERO
                    }
                } else {
                    SIGNAL
                };
                let _ignored = send_code(socket, code);
            }
            continue;
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if error.raw_os_error() == Some(libc::ECHILD) {
            let _ignored = send_code(socket, REAPED);
            return Ok(());
        }
        return Err(BridgeError);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn pair() -> (OwnedFd, OwnedFd) {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                    0,
                    fds.as_mut_ptr(),
                )
            },
            0
        );
        unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
    }
    fn sealed() -> OwnedFd {
        let fd = unsafe {
            libc::memfd_create(
                c"bridge-fixture".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x10,
            )
        };
        assert!(fd >= 0);
        let fd = unsafe { OwnedFd::from_raw_fd(fd) };
        assert_eq!(unsafe { libc::fchmod(fd.as_raw_fd(), 0o500) }, 0);
        assert_eq!(unsafe { libc::ftruncate(fd.as_raw_fd(), 64) }, 0);
        assert_eq!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, SEALS) },
            0
        );
        fd
    }
    fn transfer_bytes(entries: &[&[u8]], argc: u16) -> Zeroizing<Vec<u8>> {
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.extend_from_slice(MAGIC);
        bytes.push(TRANSFER);
        bytes.extend_from_slice(&argc.to_le_bytes());
        bytes.extend_from_slice(&((entries.len() as u16) - argc).to_le_bytes());
        for entry in entries {
            bytes.extend_from_slice(&(entry.len() as u32).to_le_bytes());
            bytes.extend_from_slice(entry);
        }
        bytes
    }
    fn packet(entries: &[&[u8]]) -> Packet {
        Packet {
            bytes: transfer_bytes(entries, 1),
            fds: vec![sealed()],
        }
    }

    #[test]
    fn protocol_authenticates_pid_and_checks_private_endpoint() {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("bridge.sock");
        let listener = BridgeListener::bind(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().mode() & 0o777, 0o600);
        assert!(BridgeListener::bind(&path).is_err());
        assert!(
            listener
                .accept(std::process::id(), Duration::ZERO)
                .unwrap()
                .is_none()
        );
        let client = socket().unwrap();
        let (address, length) = socket_address(path.as_os_str()).unwrap();
        assert_eq!(
            unsafe {
                libc::connect(
                    client.as_raw_fd(),
                    (&address as *const libc::sockaddr_un).cast(),
                    length,
                )
            },
            0
        );
        authenticate(client.as_raw_fd(), std::process::id()).unwrap();
        assert!(authenticate(client.as_raw_fd(), std::process::id() + 1).is_err());
        assert!(
            listener
                .accept(std::process::id() + 1, Duration::from_secs(1))
                .is_err()
        );
        drop(listener);
        assert!(!path.exists());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(BridgeListener::bind(&path).is_err());
    }

    #[test]
    fn received_descriptor_is_cloexec_and_resources_close_after_parse_failure() {
        let (sender, receiver) = pair();
        let descriptor = sealed();
        let bytes = transfer_bytes(&[b"fixture\0", b"LANG=C\0", b"LC_ALL=C\0"], 1);
        send_packet(sender.as_raw_fd(), &bytes, Some(descriptor.as_raw_fd())).unwrap();
        let mut received = receive_packet(receiver.as_raw_fd(), Duration::from_secs(1))
            .unwrap()
            .unwrap();
        let raw = received.fds[0].as_raw_fd();
        validate_descriptor(raw).unwrap();
        received.bytes.push(0); // trailing bytes are never accepted
        assert!(Launch::parse(received).is_err());
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, -1);
    }

    #[test]
    fn payload_rejects_wrong_seals_counts_nuls_environment_and_extra_descriptors() {
        let valid = [b"fixture\0".as_slice(), b"LANG=C\0", b"LC_ALL=C\0"];
        assert!(Launch::parse(packet(&valid)).is_ok());
        for entries in [
            [b"\0".as_slice(), b"LANG=C\0", b"LC_ALL=C\0"],
            [b"fixture\0".as_slice(), b"LANG=C\0", b"LC_ALL=C"],
            [b"fixture\0".as_slice(), b"LANG=\0C\0", b"LC_ALL=C\0"],
            [b"fixture\0".as_slice(), b"LANG=x\0", b"LC_ALL=C\0"],
        ] {
            assert!(Launch::parse(packet(&entries)).is_err());
        }
        for unsafe_entry in [
            b"PATH=/tmp\0".as_slice(),
            b"LD_PRELOAD=/tmp/evil\0",
            b"VAULTWARDEN_TOKEN=x\0",
            b"bad=x\0",
            b"NOEQUALS\0",
        ] {
            assert!(Launch::parse(packet(&[valid[0], valid[1], valid[2], unsafe_entry])).is_err());
        }
        assert!(
            Launch::parse(packet(&[
                valid[0],
                valid[1],
                valid[2],
                b"TOKEN=x\0",
                b"TOKEN=y\0"
            ]))
            .is_err()
        );
        let mut extra = packet(&valid);
        extra.fds.push(sealed());
        assert!(Launch::parse(extra).is_err());
        let mut missing = packet(&valid);
        missing.fds.clear();
        assert!(Launch::parse(missing).is_err());
        let mut bad_count = packet(&valid);
        bad_count.bytes[6..8].copy_from_slice(&129u16.to_le_bytes());
        assert!(Launch::parse(bad_count).is_err());
        let mut wrong_seals = packet(&valid);
        wrong_seals.fds = vec![tempfile::tempfile().unwrap().into()];
        assert!(Launch::parse(wrong_seals).is_err());
        let large = vec![b'x'; 32 * 1024 + 1];
        assert!(Launch::parse(packet(&[&large, valid[1], valid[2]])).is_err());
    }

    #[test]
    fn zero_length_packet_closes_every_received_descriptor() {
        use std::os::unix::fs::MetadataExt;
        let (sender, receiver) = pair();
        let image = sealed();
        let identity = std::fs::metadata(format!("/proc/self/fd/{}", image.as_raw_fd())).unwrap();
        let matching_descriptors = || {
            std::fs::read_dir("/proc/self/fd")
                .unwrap()
                .filter_map(Result::ok)
                .filter_map(|entry| std::fs::metadata(entry.path()).ok())
                .filter(|metadata| {
                    metadata.ino() == identity.ino() && metadata.dev() == identity.dev()
                })
                .count()
        };
        assert_eq!(matching_descriptors(), 1);
        send_packet(sender.as_raw_fd(), &[], Some(image.as_raw_fd())).unwrap();
        assert!(receive_packet(receiver.as_raw_fd(), Duration::from_secs(1)).is_err());
        assert_eq!(
            matching_descriptors(),
            1,
            "zero-byte payload can still install SCM_RIGHTS descriptors"
        );
    }

    #[test]
    fn protocol_rejects_truncation_wrong_version_and_unexpected_rights() {
        let (sender, receiver) = pair();
        let large = vec![b'x'; MAX_PACKET + 1];
        send_packet(sender.as_raw_fd(), &large, Some(sealed().as_raw_fd())).unwrap();
        assert!(receive_packet(receiver.as_raw_fd(), Duration::from_secs(1)).is_err());
        send_packet(sender.as_raw_fd(), b"VWEX\x02\x03", None).unwrap();
        assert!(receive_packet(receiver.as_raw_fd(), Duration::from_secs(1)).is_err());
        let mut bridge = Bridge {
            socket: receiver,
            state: State::Transferred,
        };
        send_packet(
            sender.as_raw_fd(),
            b"VWEX\x01\x03",
            Some(sealed().as_raw_fd()),
        )
        .unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
    }

    #[test]
    fn release_requires_readiness_and_reports_require_observed_exec_before_outcome() {
        let (sender, receiver) = pair();
        let mut bridge = Bridge {
            socket: receiver,
            state: State::Transferred,
        };
        assert!(bridge.release().is_err());
        assert!(bridge.receive(Duration::ZERO).unwrap().is_none());
        send_code(sender.as_raw_fd(), READY).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::Ready)
        );
        bridge.release().unwrap();
        assert_eq!(
            receive_packet(sender.as_raw_fd(), Duration::from_secs(1))
                .unwrap()
                .unwrap()
                .code()
                .unwrap(),
            RELEASE
        );
        assert!(bridge.release().is_err());
        send_code(sender.as_raw_fd(), ZERO).unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
        send_code(sender.as_raw_fd(), EXEC).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::ExecConfirmed)
        );
        send_code(sender.as_raw_fd(), ZERO).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::Outcome(ExecutionOutcome::ExitedZero))
        );
        send_code(sender.as_raw_fd(), REAPED).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::Reaped)
        );
        send_code(sender.as_raw_fd(), EXEC).unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
    }

    #[test]
    fn error_pipe_distinguishes_exec_failure_from_close_on_exec() {
        let mut fds = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) },
            0
        );
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        assert_eq!(
            unsafe { libc::write(writer.as_raw_fd(), [1u8].as_ptr().cast(), 1) },
            1
        );
        assert!(!confirm_exec(reader.as_raw_fd()));
        drop(writer);
        assert!(confirm_exec(reader.as_raw_fd()));
    }

    #[test]
    fn pre_exec_sigkill_with_empty_error_pipe_reports_failure_and_confirmed_cleanup() {
        let (sender, receiver) = pair();
        // Keep reap_all's waitpid(-1) away from the multithreaded test runner's
        // other children. The isolated branch uses only syscalls and stack data.
        let runner = unsafe { libc::fork() };
        assert!(runner >= 0);
        if runner == 0 {
            unsafe {
                libc::close(receiver.as_raw_fd());
                libc::_exit(pre_exec_sigkill_case(sender.as_raw_fd()));
            }
        }
        drop(sender);
        let mut bridge = Bridge {
            socket: receiver,
            state: State::Released,
        };
        // Collect before asserting so even an incorrect EXEC report cannot skip
        // reaping the isolated runner. Its alarm bounds a broken trace handshake.
        let first = bridge.receive(Duration::from_secs(10));
        let second = bridge.receive(Duration::from_secs(10));
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
        assert!(libc::WIFEXITED(status), "runner status: {status}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "fixture/cleanup failed");
        // EXEC/ExecConfirmed is the provider's only start-authorizing report.
        assert_eq!(
            [first, second],
            [Ok(Some(Report::Failed)), Ok(Some(Report::Reaped))],
            "pre-exec death must not authorize the provider's started notification"
        );
        let mut byte = 0u8;
        assert_eq!(
            unsafe {
                libc::recv(
                    bridge.socket.as_raw_fd(),
                    (&mut byte as *mut u8).cast(),
                    1,
                    libc::MSG_DONTWAIT,
                )
            },
            0,
            "the closed helper sent exactly Failed and Reaped"
        );
    }

    unsafe fn pre_exec_sigkill_case(socket: RawFd) -> i32 {
        unsafe {
            libc::alarm(5);
            let mut fds = [-1; 2];
            if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
                return 1;
            }
            let parent = libc::getpid();
            let child = libc::fork();
            if child < 0 {
                return 2;
            }
            if child == 0 {
                libc::close(socket);
                libc::close(fds[0]);
                libc::alarm(4);
                if !arm_parent_death(parent)
                    || libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0
                    || libc::kill(libc::getpid(), libc::SIGSTOP) != 0
                {
                    child_fail(fds[1]);
                }
                // The SIGSTOP rendezvous requires trace_exec to resume us.
                // SIGKILL then closes the error pipe without writing an error
                // byte or producing a PTRACE_EVENT_EXEC; no timing race exists.
                libc::kill(libc::getpid(), libc::SIGKILL);
                child_fail(fds[1]);
            }
            libc::close(fds[1]);
            let reader = OwnedFd::from_raw_fd(fds[0]);
            let eof_check = libc::dup(reader.as_raw_fd());
            if eof_check < 0 {
                return 3;
            }
            if report_exec_and_reap(socket, child, reader).is_err() {
                return 4;
            }
            let mut byte = 0u8;
            let empty_eof = libc::read(eof_check, (&mut byte as *mut u8).cast(), 1) == 0;
            libc::close(eof_check);
            if !empty_eof {
                return 5;
            }
            let mut status = 0;
            if libc::waitpid(-1, &mut status, libc::WNOHANG) != -1
                || *libc::__errno_location() != libc::ECHILD
            {
                return 6;
            }
            0
        }
    }

    #[test]
    fn parent_death_before_and_after_prctl_uses_actual_helper_identity() {
        // Isolate subreaper state from the multithreaded test runner. All fork
        // branches below use only syscalls and fixed stack data; alarms bound them.
        for before in [true, false] {
            let runner = unsafe { libc::fork() };
            assert!(runner >= 0);
            if runner == 0 {
                unsafe {
                    libc::_exit(parent_death_case(before));
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0, "before={before}");
        }
    }
    unsafe fn parent_death_case(before: bool) -> i32 {
        unsafe {
            libc::alarm(5);
            if libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) != 0 {
                return 1;
            }
            let mut ready = [-1; 2];
            let mut release = [-1; 2];
            if libc::pipe(ready.as_mut_ptr()) != 0 || libc::pipe(release.as_mut_ptr()) != 0 {
                return 2;
            }
            let helper = libc::fork();
            if helper < 0 {
                return 3;
            }
            if helper == 0 {
                libc::alarm(4);
                let helper_pid = libc::getpid();
                let child = libc::fork();
                if child < 0 {
                    libc::_exit(4);
                }
                if child == 0 {
                    libc::alarm(3);
                    if !before && !arm_parent_death(helper_pid) {
                        libc::_exit(5);
                    }
                    let child_pid = libc::getpid();
                    if libc::write(
                        ready[1],
                        (&child_pid as *const libc::pid_t).cast(),
                        std::mem::size_of::<libc::pid_t>(),
                    ) != std::mem::size_of::<libc::pid_t>() as isize
                    {
                        libc::_exit(6);
                    }
                    if before {
                        let mut byte = 0u8;
                        if libc::read(release[0], (&mut byte as *mut u8).cast(), 1) != 1 {
                            libc::_exit(7);
                        }
                        libc::_exit(if arm_parent_death(helper_pid) { 8 } else { 42 });
                    }
                    loop {
                        libc::pause();
                    }
                }
                if before {
                    libc::_exit(0);
                }
                loop {
                    libc::pause();
                }
            }
            let mut child = 0 as libc::pid_t;
            if libc::read(
                ready[0],
                (&mut child as *mut libc::pid_t).cast(),
                std::mem::size_of::<libc::pid_t>(),
            ) != std::mem::size_of::<libc::pid_t>() as isize
            {
                return 9;
            }
            if !before && libc::kill(helper, libc::SIGKILL) != 0 {
                return 10;
            }
            let mut status = 0;
            if libc::waitpid(helper, &mut status, 0) != helper {
                return 11;
            }
            if before && libc::write(release[1], [1u8].as_ptr().cast(), 1) != 1 {
                return 12;
            }
            if libc::waitpid(child, &mut status, 0) != child {
                return 13;
            }
            let expected = if before {
                libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42
            } else {
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == libc::SIGKILL
            };
            if !expected {
                return 14;
            }
            if libc::waitpid(-1, &mut status, libc::WNOHANG) != -1
                || *libc::__errno_location() != libc::ECHILD
            {
                return 15;
            }
            0
        }
    }
}
