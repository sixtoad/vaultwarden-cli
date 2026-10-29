//! Darwin kernel evidence. No /proc emulation or PID-to-path authentication.
use crate::access::ports::ExecutionError;
use std::{
    ffi::{CStr, CString},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::{Component, Path, PathBuf},
};

pub(crate) fn available() -> bool {
    if !cfg!(target_arch = "aarch64") {
        return false;
    }
    let mut translated: libc::c_int = 0;
    let mut size = std::mem::size_of_val(&translated);
    let result = unsafe {
        libc::sysctlbyname(
            c"sysctl.proc_translated".as_ptr(),
            (&mut translated as *mut libc::c_int).cast(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (result == 0 && size == std::mem::size_of_val(&translated) && translated == 0)
        || (result != 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT))
}

/// F_GETPATH returns a pathname, never a descriptor-relative socket capability.
/// Callers keep the directory descriptor and verify all ancestors deny untrusted writers.
pub(crate) fn descriptor_path(file: &File) -> Result<PathBuf, ExecutionError> {
    let mut bytes = [0u8; libc::PATH_MAX as usize];
    if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETPATH, bytes.as_mut_ptr()) } != 0 {
        return Err(ExecutionError::UnsafePath);
    }
    let name = CStr::from_bytes_until_nul(&bytes).map_err(|_error| ExecutionError::UnsafePath)?;
    let path = PathBuf::from(std::ffi::OsStr::from_bytes(name.to_bytes()));
    let opened = file
        .metadata()
        .map_err(|_error| ExecutionError::UnsafePath)?;
    let current = std::fs::symlink_metadata(&path).map_err(|_error| ExecutionError::UnsafePath)?;
    if (opened.dev(), opened.ino()) != (current.dev(), current.ino()) {
        return Err(ExecutionError::UnsafePath);
    }
    Ok(path)
}

// <sys/proc_info.h> proc_listpids selectors: effective and real UID.
const PROC_UID_ONLY: u32 = 4;
const PROC_RUID_ONLY: u32 = 5;

/// Whether a process other than the caller, with effective or real `uid`, executes
/// a file named `name`. Kernel evidence only; any listing or path failure other
/// than the process having exited is uncertain and fails closed.
pub(crate) fn other_process_named(
    uid: u32,
    name: &std::ffi::OsStr,
) -> Result<bool, ExecutionError> {
    let own = std::process::id() as libc::pid_t;
    for kind in [PROC_UID_ONLY, PROC_RUID_ONLY] {
        for pid in pids(kind, uid)? {
            if pid == own || pid == 0 {
                continue;
            }
            let mut bytes = [0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
            let length =
                unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), bytes.len() as u32) };
            if length <= 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH) {
                    continue;
                }
                return Err(ExecutionError::ManagerUnavailable);
            }
            let path = Path::new(std::ffi::OsStr::from_bytes(&bytes[..length as usize]));
            if path.file_name() == Some(name) {
                return Ok(true);
            }
        }
    }
    Ok(false)
}
fn pids(kind: u32, uid: u32) -> Result<Vec<libc::pid_t>, ExecutionError> {
    const PID: usize = std::mem::size_of::<libc::pid_t>();
    let estimate = unsafe { libc::proc_listpids(kind, uid, std::ptr::null_mut(), 0) };
    if estimate <= 0 {
        return Err(ExecutionError::ManagerUnavailable);
    }
    // Headroom for processes started between calls; a full buffer may be truncated.
    let mut pids: Vec<libc::pid_t> = vec![0; estimate as usize / PID + 64];
    let capacity = (pids.len() * PID) as libc::c_int;
    let written = unsafe { libc::proc_listpids(kind, uid, pids.as_mut_ptr().cast(), capacity) };
    if written < 0 || written >= capacity {
        return Err(ExecutionError::ManagerUnavailable);
    }
    pids.truncate(written as usize / PID);
    Ok(pids)
}

unsafe extern "C" {
    fn acl_get_fd_np(fd: libc::c_int, kind: libc::c_int) -> *mut libc::c_void;
    fn acl_get_entry(
        acl: *mut libc::c_void,
        entry_id: libc::c_int,
        entry: *mut *mut libc::c_void,
    ) -> libc::c_int;
    fn acl_get_tag_type(entry: *mut libc::c_void, tag: *mut libc::c_int) -> libc::c_int;
    fn acl_free(value: *mut libc::c_void) -> libc::c_int;
}
/// POSIX mode bits omit ACL grants. Allow only deny entries, never extra access.
pub(crate) fn no_acl(file: &File) -> Result<(), ExecutionError> {
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        return if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            Ok(())
        } else {
            Err(ExecutionError::UnsafePath)
        };
    }
    let result = (|| {
        for index in 0..128 {
            let mut entry = std::ptr::null_mut();
            if unsafe { acl_get_entry(acl, if index == 0 { 0 } else { -1 }, &mut entry) } != 0 {
                return if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    Ok(())
                } else {
                    Err(ExecutionError::UnsafePath)
                };
            }
            let mut tag = 0;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0 || tag != 2 {
                return Err(ExecutionError::UnsafePath);
            }
        }
        Err(ExecutionError::UnsafePath)
    })();
    unsafe {
        acl_free(acl);
    }
    result
}

pub(crate) fn open_no_writers(path: &Path, root_owned: bool) -> Result<File, ExecutionError> {
    if !path.is_absolute()
        || path
            .as_os_str()
            .as_bytes()
            .split(|b| *b == b'/')
            .any(|p| p == b"." || p == b"..")
    {
        return Err(ExecutionError::UnsafePath);
    }
    let raw = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(ExecutionError::UnsafePath);
    }
    let mut file = unsafe { File::from_raw_fd(raw) };
    for component in path.components() {
        if let Component::Normal(name) = component {
            let name =
                CString::new(name.as_bytes()).map_err(|_error| ExecutionError::UnsafePath)?;
            let raw = unsafe {
                libc::openat(
                    file.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
            };
            if raw < 0 {
                return Err(ExecutionError::UnsafePath);
            }
            file = unsafe { File::from_raw_fd(raw) };
        } else if component != Component::RootDir {
            return Err(ExecutionError::UnsafePath);
        }
        let metadata = file
            .metadata()
            .map_err(|_error| ExecutionError::UnsafePath)?;
        if metadata.mode() & 0o022 != 0
            || (metadata.uid() != 0
                && (root_owned
                    || metadata.uid() != unsafe { libc::geteuid() }
                        && metadata.uid() != super::identity::load()?.provider_uid))
        {
            return Err(ExecutionError::UnsafePath);
        }
        no_acl(&file)?;
    }
    Ok(file)
}

pub(crate) fn socket() -> std::io::Result<std::os::unix::net::UnixStream> {
    let raw = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM, 0) };
    if raw < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let stream = unsafe { std::os::unix::net::UnixStream::from_raw_fd(raw) };
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    stream.set_nonblocking(true)?;
    Ok(stream)
}

pub(crate) fn audit(stream: &impl AsRawFd) -> Result<[u32; 8], ExecutionError> {
    let mut token = [0u32; 8];
    let mut size = std::mem::size_of_val(&token) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            0,
            libc::LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast(),
            &mut size,
        )
    } != 0
        || size as usize != std::mem::size_of_val(&token)
    {
        return Err(ExecutionError::Unavailable);
    }
    Ok(token)
}
