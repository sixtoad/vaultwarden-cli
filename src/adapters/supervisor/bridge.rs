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
const TRANSFER_SSH: u8 = 10;
const TRANSFER_PRODUCER: u8 = 11;
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
            recipient: None,
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
    recipient: Option<(u32, OwnedFd)>,
}
impl Bridge {
    /// Authenticated helper proof for the exact, already-executed consumer.
    pub(crate) fn take_recipient(&mut self) -> Option<(u32, OwnedFd)> {
        self.recipient.take()
    }

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
        let cwd = prepared.working_directory();
        bytes.push(if prepared.producer_output().is_some() {
            if cwd.is_some() {
                return Err(BridgeError);
            }
            TRANSFER_PRODUCER
        } else if cwd.is_some() {
            TRANSFER_SSH
        } else {
            TRANSFER
        });
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
        let mut descriptors = vec![fd.as_raw_fd()];
        if let Some(cwd) = cwd {
            validate_directory(cwd.as_raw_fd())?;
            descriptors.push(cwd.as_raw_fd());
        }
        if let Some(output) = prepared.producer_output() {
            validate_producer_output(output.as_raw_fd())?;
            descriptors.push(output.as_raw_fd());
        }
        send_descriptors(self.socket.as_raw_fd(), &bytes, &descriptors)?;
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
        let Some(mut packet) = receive_packet(self.socket.as_raw_fd(), timeout)? else {
            return Ok(None);
        };
        let code = packet.code()?;
        if code == EXEC {
            if self.state != State::Released || packet.fds.len() != 1 || packet.bytes.len() != 10 {
                return Err(BridgeError);
            }
            let pid = u32::from_le_bytes(
                packet.bytes[6..10]
                    .try_into()
                    .map_err(|_error| BridgeError)?,
            );
            let pidfd = packet.fds.pop().ok_or(BridgeError)?;
            validate_recipient(pid, &pidfd)?;
            self.recipient = Some((pid, pidfd));
        } else if !packet.fds.is_empty() || packet.bytes.len() != MAGIC.len() + 1 {
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

fn child_pidfd(child: libc::pid_t) -> Result<OwnedFd, BridgeError> {
    if child <= 0 {
        return Err(BridgeError);
    }
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, child, 0) };
    if raw < 0 {
        return Err(BridgeError);
    }
    Ok(unsafe { OwnedFd::from_raw_fd(raw as RawFd) })
}

fn validate_recipient(pid: u32, pidfd: &OwnedFd) -> Result<(), BridgeError> {
    if pid == 0 || pid > i32::MAX as u32 {
        return Err(BridgeError);
    }
    let descriptor = pidfd.as_raw_fd();
    let target =
        std::fs::read_link(format!("/proc/self/fd/{descriptor}")).map_err(|_error| BridgeError)?;
    if target != Path::new("anon_inode:[pidfd]") {
        return Err(BridgeError);
    }
    let info = std::fs::read_to_string(format!("/proc/self/fdinfo/{descriptor}"))
        .map_err(|_error| BridgeError)?;
    let actual = info
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .ok_or(BridgeError)?
        .parse::<i32>()
        .map_err(|_error| BridgeError)?;
    // A fast consumer may already have been reaped after the helper sent EXEC.
    // Accept the honest execution report; a dead pidfd cannot authorize key use.
    if actual != pid as i32 && actual != -1 {
        return Err(BridgeError);
    }
    Ok(())
}

fn send_exec(fd: RawFd, child: libc::pid_t, pidfd: &OwnedFd) -> Result<(), BridgeError> {
    let mut bytes = [0u8; 10];
    bytes[..5].copy_from_slice(MAGIC);
    bytes[5] = EXEC;
    bytes[6..].copy_from_slice(&(child as u32).to_le_bytes());
    send_descriptors(fd, &bytes, &[pidfd.as_raw_fd()])
}

fn send_code(fd: RawFd, code: u8) -> Result<(), BridgeError> {
    let mut bytes = [0u8; 6];
    bytes[..5].copy_from_slice(MAGIC);
    bytes[5] = code;
    send_packet(fd, &bytes, None)
}
fn send_packet(fd: RawFd, bytes: &[u8], descriptor: Option<RawFd>) -> Result<(), BridgeError> {
    send_descriptors(fd, bytes, &descriptor.into_iter().collect::<Vec<_>>())
}
fn send_descriptors(fd: RawFd, bytes: &[u8], descriptors: &[RawFd]) -> Result<(), BridgeError> {
    if descriptors.len() > 2 {
        return Err(BridgeError);
    }
    let mut vector = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    // usize alignment is sufficient for cmsghdr on supported Linux platforms.
    let mut control = [0usize; 8];
    let mut message: libc::msghdr = unsafe { mem::zeroed() };
    message.msg_iov = &mut vector;
    message.msg_iovlen = 1;
    if !descriptors.is_empty() {
        message.msg_control = control.as_mut_ptr().cast();
        // Ancillary lengths are u32 on musl and usize on glibc; these fixed
        // bounded descriptor lengths fit either ABI's destination fields.
        message.msg_controllen =
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) } as _;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as _;
            for (index, descriptor) in descriptors.iter().enumerate() {
                std::ptr::write_unaligned(
                    libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                    *descriptor,
                );
            }
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

fn validate_directory(fd: RawFd) -> Result<(), BridgeError> {
    let mut stat: libc::stat = unsafe { mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        || (stat.st_uid != 0 && stat.st_uid != unsafe { libc::geteuid() })
        || stat.st_mode & 0o7022 != 0
        || unsafe { libc::fcntl(fd, libc::F_GETFD) } & libc::FD_CLOEXEC == 0
    {
        return Err(BridgeError);
    }
    Ok(())
}
fn validate_producer_output(fd: RawFd) -> Result<(), BridgeError> {
    let mut metadata: libc::stat = unsafe { mem::zeroed() };
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    let required = libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
    if unsafe { libc::fstat(fd, &raw mut metadata) } != 0
        || metadata.st_mode & libc::S_IFMT != libc::S_IFREG
        || metadata.st_size
            != i64::try_from(crate::secret_storage::MAX_IMPORT_BYTES + 4)
                .map_err(|_error| BridgeError)?
        || seals < 0
        || seals & required != required
        || seals & (libc::F_SEAL_WRITE | libc::F_SEAL_SEAL) != 0
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
        let ssh = packet.code()? == TRANSFER_SSH;
        let producer = packet.code()? == TRANSFER_PRODUCER;
        if (!ssh && !producer && packet.code()? != TRANSFER)
            || packet.bytes.len() < 10
            || packet.fds.len() != if ssh || producer { 2 } else { 1 }
        {
            return Err(BridgeError);
        }
        validate_descriptor(packet.fds[0].as_raw_fd())?;
        if ssh {
            validate_directory(packet.fds[1].as_raw_fd())?;
        }
        if producer {
            validate_producer_output(packet.fds[1].as_raw_fd())?;
        }
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
    let producer = launch.packet.code()? == TRANSFER_PRODUCER;
    let ssh = launch.packet.code()? == TRANSFER_SSH;
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
    // TRACEME works with the inherited non-dumpable state. Do not introduce
    // a SIGSTOP rendezvous: an exec trap automatically resumes on tracer death.
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
            for signal in [libc::SIGTERM, libc::SIGINT, libc::SIGHUP] {
                libc::signal(signal, libc::SIG_DFL);
            }
            if libc::sigprocmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut()) != 0 {
                child_fail(write.as_raw_fd());
            }
            if ssh && libc::fchdir(launch.packet.fds[1].as_raw_fd()) != 0 {
                child_fail(write.as_raw_fd());
            }
            for output in 0..=2 {
                if libc::dup2(null.as_raw_fd(), output) < 0 {
                    child_fail(write.as_raw_fd());
                }
            }
            if producer && libc::dup2(launch.packet.fds[1].as_raw_fd(), 3) < 0 {
                child_fail(write.as_raw_fd());
            }
            // Never accidentally trace against a new adopter if the helper died
            // around fork. Once attached, tracer death detaches without killing.
            if libc::getppid() != parent
                || libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0
                || libc::getppid() != parent
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
    // On detach failure unwind out of the single-threaded helper. Its exit
    // relinquishes ptrace ownership; waiting here could strand a stopped child.
    // This is our unreaped direct child: its PID cannot be recycled before the
    // pidfd is captured. Never use this descriptor to signal the consumer.
    let pidfd = child_pidfd(child)?;
    let confirmed = trace_exec(child, read.as_raw_fd())?;
    drop(read);
    let _ignored = if confirmed {
        send_exec(socket, child, &pidfd)
    } else {
        send_code(socket, FAILED)
    };
    reap_all(socket, child, confirmed)
}
unsafe fn child_fail(fd: RawFd) -> ! {
    unsafe {
        libc::write(fd, [1u8].as_ptr().cast(), 1);
        libc::_exit(127);
    }
}
#[cfg(test)]
thread_local! { static FAIL_DETACH: std::cell::Cell<bool> = const { std::cell::Cell::new(false) }; }
fn trace_exec(child: libc::pid_t, error_pipe: RawFd) -> Result<bool, BridgeError> {
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
    let Some(event) = wait(child) else {
        return Ok(false);
    };
    if !libc::WIFSTOPPED(event) {
        return Ok(false);
    }
    // A live tracee stopped at SIGTRAP plus CLOEXEC EOF is positive exec
    // evidence. Pre-exec SIGKILL has no stopped tracee; a pre-exec SIGTRAP
    // retains the write descriptor and yields EAGAIN. Check before detaching.
    let confirmed =
        libc::WSTOPSIG(event) == libc::SIGTRAP && event >> 16 == 0 && confirm_exec(error_pipe);
    // Only our confirmed exec trap is synthetic. Preserve an execution owner's
    // termination or suspension signal observed before exec.
    let signal = if confirmed { 0 } else { libc::WSTOPSIG(event) };
    #[cfg(test)]
    if FAIL_DETACH.with(std::cell::Cell::get) {
        return Err(BridgeError);
    }
    if unsafe { libc::ptrace(libc::PTRACE_DETACH, child, 0, signal) } != 0 {
        return Err(BridgeError);
    }
    Ok(confirmed)
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
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return false;
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
    fn isolated_descriptor_test(name: &str) -> bool {
        const CHILD: &str = "VW_BRIDGE_DESCRIPTOR_CHILD";
        if std::env::var(CHILD).as_deref() == Ok(name) {
            return true;
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", name, "--test-threads=1", "--nocapture"])
            .env(CHILD, name)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "isolated descriptor test failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        false
    }
    fn assert_closed(descriptors: &[RawFd]) {
        for raw in descriptors {
            assert_eq!(
                unsafe { libc::fcntl(*raw, libc::F_GETFD) },
                -1,
                "received fd {raw} leaked"
            );
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::EBADF)
            );
        }
    }
    #[test]
    fn ssh_transfer_requires_checked_directory_and_closes_both_received_descriptors() {
        if !isolated_descriptor_test(
            "adapters::supervisor::bridge::tests::ssh_transfer_requires_checked_directory_and_closes_both_received_descriptors",
        ) {
            return;
        }
        // No other tests run in this subprocess: a reused fd cannot mask closure.
        let root = tempfile::tempdir().unwrap();
        let directory = crate::adapters::ssh_material::directory(root.path(), true).unwrap();
        let mut bytes = transfer_bytes(&[b"fixture\0", b"LANG=C\0", b"LC_ALL=C\0"], 1);
        bytes[5] = TRANSFER_SSH;
        for case in [
            "success",
            "wrong-cwd",
            "missing-cwd",
            "extra-fd",
            "trailing-byte",
        ] {
            let (sender, receiver) = pair();
            let mut originals: Vec<OwnedFd> = vec![sealed(), directory.try_clone().unwrap().into()];
            if case == "wrong-cwd" {
                originals[1] = sealed();
            } else if case == "missing-cwd" {
                originals.pop();
            } else if case == "extra-fd" {
                originals.push(sealed());
            }
            let descriptors: Vec<_> = originals.iter().map(AsRawFd::as_raw_fd).collect();
            if case == "extra-fd" {
                // The production sender forbids extra descriptors; exercise hostile SCM_RIGHTS.
                let mut vector = libc::iovec {
                    iov_base: bytes.as_ptr().cast_mut().cast(),
                    iov_len: bytes.len(),
                };
                let mut control = [0usize; 8];
                let mut message: libc::msghdr = unsafe { mem::zeroed() };
                message.msg_iov = &mut vector;
                message.msg_iovlen = 1;
                message.msg_control = control.as_mut_ptr().cast();
                let length = std::mem::size_of_val(descriptors.as_slice()) as u32;
                message.msg_controllen = unsafe { libc::CMSG_SPACE(length) } as _;
                unsafe {
                    let header = libc::CMSG_FIRSTHDR(&message);
                    (*header).cmsg_level = libc::SOL_SOCKET;
                    (*header).cmsg_type = libc::SCM_RIGHTS;
                    (*header).cmsg_len = libc::CMSG_LEN(length) as _;
                    for (index, raw) in descriptors.iter().enumerate() {
                        std::ptr::write_unaligned(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                            *raw,
                        );
                    }
                    assert_eq!(
                        libc::sendmsg(sender.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                        bytes.len() as isize
                    );
                }
            } else {
                send_descriptors(sender.as_raw_fd(), &bytes, &descriptors).unwrap();
            }
            let mut received = receive_packet(receiver.as_raw_fd(), Duration::from_secs(1))
                .unwrap()
                .unwrap();
            assert_eq!(received.fds.len(), originals.len(), "{case}");
            let raw: Vec<_> = received.fds.iter().map(AsRawFd::as_raw_fd).collect();
            if case == "trailing-byte" {
                received.bytes.push(0);
            }
            if case == "success" {
                let launch = Launch::parse(received).unwrap();
                for fd in &raw {
                    assert!(unsafe { libc::fcntl(*fd, libc::F_GETFD) } >= 0);
                }
                drop(launch);
            } else {
                assert!(Launch::parse(received).is_err(), "{case}");
            }
            assert_closed(&raw);
            // Ownership of sender descriptors is independent from received copies.
            for fd in &originals {
                assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
            }
        }
    }
    fn packet(entries: &[&[u8]]) -> Packet {
        Packet {
            bytes: transfer_bytes(entries, 1),
            fds: vec![sealed()],
        }
    }

    #[test]
    fn private_producer_frame_crosses_only_the_bounded_descriptor_and_requires_reaping() {
        use crate::access::{
            policy::{ApprovedImage, test_approved_image},
            ports::{CleanupEvidence, ProtectedExecution},
        };
        use crate::adapters::execution::LinuxExecutablePreparer;
        use sha2::{Digest, Sha256};
        use std::os::unix::fs::PermissionsExt;
        if !isolated_descriptor_test(
            "adapters::supervisor::bridge::tests::private_producer_frame_crosses_only_the_bounded_descriptor_and_requires_reaping",
        ) {
            return;
        }
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let base = test_approved_image(root.path(), "producer").metadata();
        let mut bytes = std::fs::read(&base.path).unwrap();
        bytes.truncate(120);
        #[cfg(target_arch = "x86_64")]
        let code =
            include_bytes!("../../../tests/fixtures/protected-producer-x86_64.bin").as_slice();
        #[cfg(target_arch = "aarch64")]
        let code =
            include_bytes!("../../../tests/fixtures/protected-producer-aarch64.bin").as_slice();
        bytes[96..104].copy_from_slice(&(code.len() as u64).to_le_bytes());
        bytes[104..112].copy_from_slice(&(code.len() as u64).to_le_bytes());
        bytes.extend_from_slice(code);
        std::fs::set_permissions(&base.path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::write(&base.path, &bytes).unwrap();
        std::fs::set_permissions(&base.path, std::fs::Permissions::from_mode(0o500)).unwrap();
        let digest = Sha256::digest(&bytes)
            .iter()
            .fold(String::new(), |mut output, byte| {
                use std::fmt::Write;
                write!(output, "{byte:02x}").expect("writing to String cannot fail");
                output
            });
        let image = ApprovedImage::new(
            base.id,
            base.execution_root,
            base.path,
            digest,
            base.profile,
        )
        .unwrap();
        let mut prepared = LinuxExecutablePreparer
            .prepare(image.execution_image(), vec!["producer".into()])
            .unwrap();
        let mut output = LinuxExecutablePreparer
            .prepare_producer(&mut prepared)
            .unwrap();
        let descriptor = prepared.producer_output().unwrap().as_raw_fd();
        assert_eq!(unsafe { libc::ftruncate(descriptor, 1_000_000) }, -1);
        assert!(output.read(CleanupEvidence::NotStarted).is_err());
        let (provider, helper) = pair();
        let worker = std::thread::spawn(move || helper_session(helper.as_raw_fd()));
        let mut bridge = Bridge {
            socket: provider,
            state: State::Connected,
            recipient: None,
        };
        bridge
            .send(
                &prepared,
                &ChildEnvironment::from_mappings(Vec::new()).unwrap(),
            )
            .unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(3)).unwrap(),
            Some(Report::Ready)
        );
        bridge.release().unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(3)).unwrap(),
            Some(Report::ExecConfirmed)
        );
        assert_eq!(
            bridge.receive(Duration::from_secs(3)).unwrap(),
            Some(Report::Outcome(ExecutionOutcome::ExitedZero))
        );
        assert_eq!(
            bridge.receive(Duration::from_secs(3)).unwrap(),
            Some(Report::Reaped)
        );
        worker.join().unwrap().unwrap();
        let input = output.read(CleanupEvidence::Reaped).unwrap();
        assert_eq!(input.password.as_deref(), Some("private-producer-sentinel"));
        assert_eq!(
            unsafe { libc::pwrite(descriptor, b"x".as_ptr().cast(), 1, 0) },
            -1
        );
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
        if !isolated_descriptor_test(
            "adapters::supervisor::bridge::tests::received_descriptor_is_cloexec_and_resources_close_after_parse_failure",
        ) {
            return;
        }
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
        assert_closed(&[raw]);
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
            recipient: None,
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
            recipient: None,
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
        let pid = unsafe { libc::getpid() };
        let pidfd = child_pidfd(pid).unwrap();
        send_exec(sender.as_raw_fd(), pid, &pidfd).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::ExecConfirmed)
        );
        let (received_pid, received_fd) = bridge.take_recipient().unwrap();
        assert_eq!(received_pid, pid as u32);
        validate_recipient(received_pid, &received_fd).unwrap();
        assert!(bridge.take_recipient().is_none());
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
    fn exec_report_requires_matching_pidfd_and_exact_payload() {
        let (sender, receiver) = pair();
        let mut bridge = Bridge {
            socket: receiver,
            state: State::Released,
            recipient: None,
        };
        let pid = unsafe { libc::getpid() };
        let pidfd = child_pidfd(pid).unwrap();
        let mut bytes = Vec::from(&MAGIC[..]);
        bytes.push(EXEC);
        bytes.extend_from_slice(&(pid as u32).to_le_bytes());
        for bad in [
            bytes[..6].to_vec(),
            bytes[..9].to_vec(),
            [bytes.as_slice(), &[0]].concat(),
        ] {
            send_descriptors(sender.as_raw_fd(), &bad, &[pidfd.as_raw_fd()]).unwrap();
            assert!(bridge.receive(Duration::from_secs(1)).is_err());
        }
        send_descriptors(sender.as_raw_fd(), &bytes, &[]).unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
        send_descriptors(
            sender.as_raw_fd(),
            &bytes,
            &[pidfd.as_raw_fd(), pidfd.as_raw_fd()],
        )
        .unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
        send_descriptors(sender.as_raw_fd(), &bytes, &[sealed().as_raw_fd()]).unwrap();
        assert!(bridge.receive(Duration::from_secs(1)).is_err());
        for mismatch in [0u32, (pid as u32).saturating_add(1), u32::MAX] {
            bytes[6..].copy_from_slice(&mismatch.to_le_bytes());
            send_descriptors(sender.as_raw_fd(), &bytes, &[pidfd.as_raw_fd()]).unwrap();
            assert!(bridge.receive(Duration::from_secs(1)).is_err());
        }
        assert!(bridge.take_recipient().is_none());
        send_exec(sender.as_raw_fd(), pid, &pidfd).unwrap();
        assert_eq!(
            bridge.receive(Duration::from_secs(1)).unwrap(),
            Some(Report::ExecConfirmed)
        );
        let (_, fd) = bridge.take_recipient().unwrap();
        assert_ne!(
            unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
    }

    #[test]
    fn error_pipe_distinguishes_exec_failure_from_close_on_exec() {
        // Create the pipe after isolation: other tests fork concurrently and
        // could otherwise inherit its writer, delaying EOF after our close.
        let runner = unsafe { libc::fork() };
        assert!(runner >= 0);
        if runner == 0 {
            unsafe {
                libc::alarm(5);
                let mut fds = [-1; 2];
                if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0
                    || libc::write(fds[1], [1u8].as_ptr().cast(), 1) != 1
                {
                    libc::_exit(1);
                }
                if confirm_exec(fds[0]) {
                    libc::_exit(2);
                }
                libc::close(fds[1]);
                libc::_exit(if confirm_exec(fds[0]) { 0 } else { 3 });
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    #[test]
    // Tarpaulin uses ptrace for instrumentation; nesting this fixture's
    // PTRACE_TRACEME/exec-trap handshake under that tracer changes the
    // child-stop semantics it is specifically testing. Run it in the normal
    // process test suite instead of treating coverage instrumentation as the
    // provider's exec-event implementation.
    #[cfg_attr(tarpaulin, ignore)]
    fn pre_exec_sigkill_with_empty_error_pipe_reports_failure_and_confirmed_cleanup() {
        for signal in [libc::SIGKILL, libc::SIGTRAP] {
            let (sender, receiver) = pair();
            // Keep reap_all's waitpid(-1) away from the multithreaded test runner's
            // other children. The isolated branch uses only syscalls and stack data.
            let runner = unsafe { libc::fork() };
            assert!(runner >= 0);
            if runner == 0 {
                unsafe {
                    libc::close(receiver.as_raw_fd());
                    libc::_exit(pre_exec_signal_case(sender.as_raw_fd(), signal));
                }
            }
            drop(sender);
            let mut bridge = Bridge {
                socket: receiver,
                state: State::Released,
                recipient: None,
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
    }
    unsafe fn pre_exec_signal_case(socket: RawFd, signal: i32) -> i32 {
        unsafe {
            if initialize_helper().is_err() {
                return 99;
            }
            libc::alarm(5);
            let mut fds = [-1; 2];
            if libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
                return 1;
            }
            let child = libc::fork();
            if child < 0 {
                return 2;
            }
            if child == 0 {
                libc::close(socket);
                libc::close(fds[0]);
                libc::alarm(4);
                // Death yields EOF without a live stopped tracee; an injected
                // trap has a live tracee but retains the CLOEXEC writer. Neither
                // can be mistaken for successful exec.
                if signal == libc::SIGTRAP && libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                    libc::_exit(8);
                }
                libc::kill(libc::getpid(), signal);
                libc::_exit(0);
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
    fn hardened_observer_death_during_exec_never_stops_or_kills_consumer() {
        for during_exec in [false, true] {
            let runner = unsafe { libc::fork() };
            assert!(runner >= 0);
            if runner == 0 {
                unsafe {
                    libc::_exit(observer_death_case(during_exec));
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0, "during_exec={during_exec}");
        }
    }
    unsafe fn observer_death_case(during_exec: bool) -> i32 {
        unsafe {
            libc::alarm(5);
            if initialize_helper().is_err() {
                return 1;
            }
            let mut ready = [-1; 2];
            let mut gate = [-1; 2];
            if libc::pipe(ready.as_mut_ptr()) != 0 || libc::pipe(gate.as_mut_ptr()) != 0 {
                return 2;
            }
            let helper = libc::fork();
            if helper < 0 {
                return 3;
            }
            if helper == 0 {
                let child = libc::fork();
                if child < 0 {
                    libc::_exit(4);
                }
                if child == 0 {
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                        libc::_exit(7);
                    }
                    if !during_exec {
                        let pid = libc::getpid();
                        libc::write(
                            ready[1],
                            (&pid as *const libc::pid_t).cast(),
                            mem::size_of::<libc::pid_t>(),
                        );
                    }
                    let mut byte = 0u8;
                    if libc::read(gate[0], (&mut byte as *mut u8).cast(), 1) != 1 {
                        libc::_exit(5);
                    }
                    libc::execl(
                        c"/bin/true".as_ptr(),
                        c"true".as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                    );
                    libc::_exit(6);
                }
                if during_exec {
                    libc::write(gate[1], [1u8].as_ptr().cast(), 1);
                    let mut status = 0;
                    if libc::waitpid(child, &mut status, 0) != child
                        || !libc::WIFSTOPPED(status)
                        || libc::WSTOPSIG(status) != libc::SIGTRAP
                    {
                        libc::_exit(8);
                    }
                }
                if during_exec {
                    libc::write(
                        ready[1],
                        (&child as *const libc::pid_t).cast(),
                        mem::size_of::<libc::pid_t>(),
                    );
                }
                loop {
                    libc::pause();
                }
            }
            let mut child = 0 as libc::pid_t;
            if libc::read(
                ready[0],
                (&mut child as *mut libc::pid_t).cast(),
                mem::size_of::<libc::pid_t>(),
            ) != mem::size_of::<libc::pid_t>() as isize
            {
                return 9;
            }
            if libc::kill(helper, libc::SIGKILL) != 0 {
                return 10;
            }
            let mut status = 0;
            if libc::waitpid(helper, &mut status, 0) != helper {
                return 11;
            }
            if !during_exec {
                libc::write(gate[1], [1u8].as_ptr().cast(), 1);
            }
            if libc::waitpid(child, &mut status, 0) != child {
                return 12;
            }
            if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
                return 13;
            }
            0
        }
    }
    #[test]
    fn external_pre_exec_termination_and_suspension_are_forwarded() {
        for signal in [libc::SIGTERM, libc::SIGSTOP] {
            let runner = unsafe { libc::fork() };
            assert!(runner >= 0);
            if runner == 0 {
                unsafe {
                    libc::_exit(external_signal_case(signal));
                }
            }
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
            assert!(libc::WIFEXITED(status));
            assert_eq!(libc::WEXITSTATUS(status), 0, "signal={signal}");
        }
    }
    unsafe fn external_signal_case(signal: i32) -> i32 {
        unsafe {
            libc::alarm(10);
            if initialize_helper().is_err() {
                return 1;
            }
            let mut gate = [-1; 2];
            let mut ready = [-1; 2];
            let mut result = [-1; 2];
            let mut error = [-1; 2];
            if libc::pipe(gate.as_mut_ptr()) != 0
                || libc::pipe(ready.as_mut_ptr()) != 0
                || libc::pipe(result.as_mut_ptr()) != 0
                || libc::pipe2(error.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0
            {
                return 2;
            }
            let helper = libc::fork();
            if helper < 0 {
                return 3;
            }
            if helper == 0 {
                let child = libc::fork();
                if child < 0 {
                    libc::_exit(4);
                }
                if child == 0 {
                    libc::close(error[0]);
                    libc::signal(libc::SIGTERM, libc::SIG_DFL);
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                        libc::_exit(5);
                    }
                    let pid = libc::getpid();
                    libc::write(
                        ready[1],
                        (&pid as *const libc::pid_t).cast(),
                        size_of::<libc::pid_t>(),
                    );
                    let mut byte = 0u8;
                    libc::read(gate[0], (&mut byte as *mut u8).cast(), 1);
                    libc::_exit(42);
                }
                libc::close(error[1]);
                if trace_exec(child, error[0]) != Ok(false) {
                    libc::_exit(6);
                }
                let mut status = 0;
                if libc::waitpid(child, &mut status, libc::WUNTRACED) != child {
                    libc::_exit(7);
                }
                libc::write(result[1], (&status as *const i32).cast(), size_of::<i32>());
                if libc::WIFSTOPPED(status) {
                    if libc::waitpid(child, &mut status, 0) != child {
                        libc::_exit(8);
                    }
                    libc::write(result[1], (&status as *const i32).cast(), size_of::<i32>());
                }
                libc::_exit(0);
            }
            libc::close(error[0]);
            libc::close(error[1]);
            let mut child = 0 as libc::pid_t;
            if libc::read(
                ready[0],
                (&mut child as *mut libc::pid_t).cast(),
                size_of::<libc::pid_t>(),
            ) != size_of::<libc::pid_t>() as isize
            {
                return 9;
            }
            if libc::kill(child, signal) != 0 {
                return 10;
            }
            let mut pollfd = libc::pollfd {
                fd: result[0],
                events: libc::POLLIN,
                revents: 0,
            };
            let observed = libc::poll(&mut pollfd, 1, 2000) == 1;
            // Independent fixture owner resumes its suspended workload, including
            // on assertion failure; the delivery helper never resumes it for us.
            if !observed || signal == libc::SIGSTOP {
                libc::kill(child, libc::SIGCONT);
                libc::write(gate[1], [1u8].as_ptr().cast(), 1);
            }
            let mut status = 0;
            if libc::read(
                result[0],
                (&mut status as *mut i32).cast(),
                size_of::<i32>(),
            ) != size_of::<i32>() as isize
            {
                return 11;
            }
            let expected = if signal == libc::SIGTERM {
                libc::WIFSIGNALED(status) && libc::WTERMSIG(status) == signal
            } else {
                libc::WIFSTOPPED(status) && libc::WSTOPSIG(status) == signal
            };
            if observed
                && signal == libc::SIGSTOP
                && (libc::read(
                    result[0],
                    (&mut status as *mut i32).cast(),
                    size_of::<i32>(),
                ) != size_of::<i32>() as isize
                    || !libc::WIFEXITED(status)
                    || libc::WEXITSTATUS(status) != 42)
            {
                return 12;
            }
            if libc::waitpid(helper, &mut status, 0) != helper
                || !libc::WIFEXITED(status)
                || libc::WEXITSTATUS(status) != 0
            {
                return 13;
            }
            if !observed || !expected {
                return 14;
            }
            0
        }
    }

    #[test]
    fn failed_detach_exits_observer_and_releases_live_exec_trap() {
        let runner = unsafe { libc::fork() };
        assert!(runner >= 0);
        if runner == 0 {
            unsafe {
                libc::_exit(failed_detach_case());
            }
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(runner, &mut status, 0) }, runner);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }
    unsafe fn failed_detach_case() -> i32 {
        unsafe {
            libc::alarm(10);
            if initialize_helper().is_err() {
                return 1;
            }
            let mut ready = [-1; 2];
            if libc::pipe(ready.as_mut_ptr()) != 0 {
                return 2;
            }
            let helper = libc::fork();
            if helper < 0 {
                return 3;
            }
            if helper == 0 {
                let mut error = [-1; 2];
                if libc::pipe2(error.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) != 0 {
                    libc::_exit(4);
                }
                let child = libc::fork();
                if child < 0 {
                    libc::_exit(5);
                }
                if child == 0 {
                    libc::close(error[0]);
                    if libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0) != 0 {
                        libc::_exit(6);
                    }
                    libc::execl(
                        c"/bin/true".as_ptr(),
                        c"true".as_ptr(),
                        std::ptr::null::<libc::c_char>(),
                    );
                    libc::_exit(7);
                }
                libc::close(error[1]);
                libc::write(
                    ready[1],
                    (&child as *const libc::pid_t).cast(),
                    size_of::<libc::pid_t>(),
                );
                FAIL_DETACH.with(|fail| fail.set(true));
                let error =
                    report_exec_and_reap(-1, child, OwnedFd::from_raw_fd(error[0])).is_err();
                libc::_exit(if error { 42 } else { 8 });
            }
            let mut child = 0 as libc::pid_t;
            if libc::read(
                ready[0],
                (&mut child as *mut libc::pid_t).cast(),
                size_of::<libc::pid_t>(),
            ) != size_of::<libc::pid_t>() as isize
            {
                return 9;
            }
            let mut status = 0;
            let mut exited = false;
            for _ in 0..200 {
                if libc::waitpid(helper, &mut status, libc::WNOHANG) == helper {
                    exited = true;
                    break;
                }
                libc::usleep(10_000);
            }
            let expected = exited && libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 42;
            if !exited {
                // Failure cleanup affects only our synthetic observer. The
                // consumer must still resume and exit naturally below.
                libc::kill(helper, libc::SIGKILL);
                libc::waitpid(helper, &mut status, 0);
            }
            if libc::waitpid(child, &mut status, 0) != child
                || !libc::WIFEXITED(status)
                || libc::WEXITSTATUS(status) != 0
            {
                return 10;
            }
            if !expected {
                return 11;
            }
            0
        }
    }
}
