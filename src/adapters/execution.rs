//! Immutable executable preparation. This does not confer approval or spawn a child.

use crate::access::{
    policy::ExecutionProfile,
    ports::{ExecutionError, ExecutionImage, ProtectedExecution},
};
use std::{ffi::CString, fmt};

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_EXECUTION_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    pub(crate) static TEST_LAUNCH_ATTEMPTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(target_os = "linux")]
const MAX_IMAGE: u64 = 64 * 1024 * 1024;
const MAX_ARGS: usize = 128;
const MAX_ARG_BYTES: usize = 32 * 1024;

pub(crate) struct LinuxExecutablePreparer;

/// Noncloneable bytes capability, deliberately independent of approval authority.
#[allow(dead_code)] // Consumed by supervised dispatch in Story 1.7.
pub(crate) struct PreparedExecutable {
    #[cfg(target_os = "linux")]
    file: std::fs::File,
    argv: Vec<CString>,
}
impl fmt::Debug for PreparedExecutable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PreparedExecutable([REDACTED])")
    }
}

impl ProtectedExecution for LinuxExecutablePreparer {
    type Prepared = PreparedExecutable;
    fn prepare(
        &self,
        image: ExecutionImage<'_>,
        argv: Vec<String>,
    ) -> Result<PreparedExecutable, ExecutionError> {
        let argv = checked_arguments(argv)?;
        match image.profile {
            ExecutionProfile::ReviewedSelfContainedElf64V1 => {}
        }
        #[cfg(target_os = "linux")]
        {
            let source = linux::open_source(image.root, image.path)?;
            #[cfg(test)]
            {
                linux::snapshot(source, image.sha256, argv, |_| {})
            }
            #[cfg(not(test))]
            {
                linux::snapshot(source, image.sha256, argv)
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (image, argv);
            Err(ExecutionError::Unavailable)
        }
    }
}

fn checked_arguments(argv: Vec<String>) -> Result<Vec<CString>, ExecutionError> {
    if argv.is_empty() || argv.len() > MAX_ARGS || argv[0].is_empty() {
        return Err(ExecutionError::InvalidArguments);
    }
    let mut size = 0usize;
    argv.into_iter()
        .map(|arg| {
            size = size
                .checked_add(arg.len() + 1)
                .ok_or(ExecutionError::InvalidArguments)?;
            if size > MAX_ARG_BYTES {
                return Err(ExecutionError::InvalidArguments);
            }
            CString::new(arg).map_err(|_error| ExecutionError::InvalidArguments)
        })
        .collect()
}

impl PreparedExecutable {
    /// Replaces the current, already supervised process; never forks or uses a path.
    #[allow(dead_code)] // Story 1.7 will invoke this only after consuming authority.
    pub(crate) fn execute(self) -> Result<std::convert::Infallible, ExecutionError> {
        #[cfg(target_os = "linux")]
        {
            use std::os::fd::AsRawFd;
            linux::execute_fd(self.file.as_raw_fd(), &self.argv)
        }
        #[cfg(not(target_os = "linux"))]
        Err(ExecutionError::Unavailable)
    }
}

#[cfg(all(test, not(target_os = "linux")))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn valid_preparation_is_unavailable_without_linux() {
        assert_eq!(
            LinuxExecutablePreparer
                .prepare(
                    ExecutionImage {
                        root: std::path::Path::new("/provider"),
                        path: std::path::Path::new("/provider/image"),
                        sha256: &"0".repeat(64),
                        profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
                    },
                    vec!["fixture".into(), "mark".into()],
                )
                .unwrap_err(),
            ExecutionError::Unavailable
        );
    }

    #[test]
    fn execution_is_unavailable_without_linux() {
        let prepared = PreparedExecutable {
            argv: checked_arguments(vec!["fixture".into()]).unwrap(),
        };
        assert_eq!(prepared.execute().unwrap_err(), ExecutionError::Unavailable);
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::{
        fs::{File, Metadata},
        io::{Read, Seek, SeekFrom},
        os::{
            fd::{AsRawFd, FromRawFd, RawFd},
            unix::{ffi::OsStrExt, fs::MetadataExt},
        },
        path::{Component, Path},
    };

    // Linux 6.3 executable memfd API. Explicit constants preserve libc/MSRV portability.
    const MFD_EXEC: libc::c_uint = 0x0010;
    const F_SEAL_EXEC: libc::c_int = 0x0020;
    const SEALS: libc::c_int = libc::F_SEAL_WRITE
        | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK
        | F_SEAL_EXEC
        | libc::F_SEAL_SEAL;

    fn open_at(
        dir: RawFd,
        name: &std::ffi::OsStr,
        directory: bool,
    ) -> Result<File, ExecutionError> {
        let name = CString::new(name.as_bytes()).map_err(|_error| ExecutionError::UnsafePath)?;
        let flags = libc::O_RDONLY
            | libc::O_CLOEXEC
            | libc::O_NOFOLLOW
            | libc::O_NONBLOCK
            | libc::O_NOCTTY
            | if directory { libc::O_DIRECTORY } else { 0 };
        // Every call names exactly one validated component; NOFOLLOW also covers the leaf.
        let fd = unsafe { libc::openat(dir, name.as_ptr(), flags) };
        if fd < 0 {
            return Err(ExecutionError::UnsafePath);
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    fn directory_ok(meta: &Metadata, private: bool, uid: u32) -> bool {
        let mode = meta.mode();
        meta.is_dir()
            && if private {
                meta.uid() == uid && mode & 0o7777 == 0o700
            } else {
                (meta.uid() == 0 || meta.uid() == uid) && mode & 0o7022 == 0
            }
    }

    fn components(path: &Path, absolute: bool) -> Result<Vec<&std::ffi::OsStr>, ExecutionError> {
        // Path::components normalizes interior '.', so reject it before decomposition.
        if path.is_absolute() != absolute
            || path
                .as_os_str()
                .as_bytes()
                .split(|b| *b == b'/')
                .any(|part| part == b"." || part == b"..")
        {
            return Err(ExecutionError::UnsafePath);
        }
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                Component::RootDir if absolute => {}
                Component::Normal(name) => parts.push(name),
                _ => return Err(ExecutionError::UnsafePath),
            }
        }
        if parts.is_empty() {
            return Err(ExecutionError::UnsafePath);
        }
        Ok(parts)
    }

    pub(super) fn open_source(root: &Path, path: &Path) -> Result<File, ExecutionError> {
        let roots = components(root, true)?;
        let relative = path
            .strip_prefix(root)
            .map_err(|_error| ExecutionError::UnsafePath)?;
        let images = components(relative, false)?;
        // Also validate original spelling before strip_prefix can normalize it.
        let _validated = components(path, true)?;
        let uid = unsafe { libc::geteuid() };
        let mut directory = open_at(libc::AT_FDCWD, std::ffi::OsStr::new("/"), true)?;
        if !directory_ok(
            &directory
                .metadata()
                .map_err(|_error| ExecutionError::UnsafePath)?,
            false,
            uid,
        ) {
            return Err(ExecutionError::UnsafePath);
        }
        for (index, part) in roots.iter().enumerate() {
            directory = open_at(directory.as_raw_fd(), part, true)?;
            if !directory_ok(
                &directory
                    .metadata()
                    .map_err(|_error| ExecutionError::UnsafePath)?,
                index + 1 == roots.len(),
                uid,
            ) {
                return Err(ExecutionError::UnsafePath);
            }
        }
        open_relative(directory, &images, uid)
    }

    fn open_relative(
        mut directory: File,
        images: &[&std::ffi::OsStr],
        uid: u32,
    ) -> Result<File, ExecutionError> {
        if !directory_ok(
            &directory
                .metadata()
                .map_err(|_error| ExecutionError::UnsafePath)?,
            true,
            uid,
        ) {
            return Err(ExecutionError::UnsafePath);
        }
        for part in &images[..images.len() - 1] {
            directory = open_at(directory.as_raw_fd(), part, true)?;
            if !directory_ok(
                &directory
                    .metadata()
                    .map_err(|_error| ExecutionError::UnsafePath)?,
                true,
                uid,
            ) {
                return Err(ExecutionError::UnsafePath);
            }
        }
        let source = open_at(directory.as_raw_fd(), images[images.len() - 1], false)?;
        source_metadata(&source)?;
        Ok(source)
    }

    fn source_metadata(source: &File) -> Result<Metadata, ExecutionError> {
        let meta = source
            .metadata()
            .map_err(|_error| ExecutionError::UnsafeSource)?;
        if !source_ok(&meta, unsafe { libc::geteuid() }) {
            return Err(ExecutionError::UnsafeSource);
        }
        Ok(meta)
    }

    fn source_ok(meta: &Metadata, uid: u32) -> bool {
        let mode = meta.mode();
        meta.is_file()
            && meta.uid() == uid
            && mode & 0o500 == 0o500
            && mode & 0o7222 == 0
            && meta.len() >= 64
            && meta.len() <= MAX_IMAGE
    }

    #[cfg(test)]
    #[derive(Clone, Copy)]
    pub(super) enum Boundary {
        Opened,
        Copied,
        Sealed,
        Verified,
    }

    pub(super) fn snapshot(
        mut source: File,
        digest: &str,
        argv: Vec<CString>,
        #[cfg(test)] mut hook: impl FnMut(Boundary),
    ) -> Result<PreparedExecutable, ExecutionError> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err(ExecutionError::InvalidImage);
        }
        let before = source_metadata(&source)?;
        #[cfg(test)]
        hook(Boundary::Opened);
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"protected-image".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC,
            )
        };
        if fd < 0 {
            return Err(ExecutionError::Unavailable);
        }
        let mut sealed = unsafe { File::from_raw_fd(fd as RawFd) };
        if unsafe { libc::fchmod(sealed.as_raw_fd(), 0o500) } != 0 {
            return Err(ExecutionError::Unavailable);
        }
        let copied = std::io::copy(&mut (&mut source).take(MAX_IMAGE + 1), &mut sealed)
            .map_err(|_error| ExecutionError::Unavailable)?;
        let after = source_metadata(&source)?;
        if copied != before.len()
            || copied > MAX_IMAGE
            || before.len() != after.len()
            || before.mtime() != after.mtime()
            || before.mtime_nsec() != after.mtime_nsec()
            || before.ctime() != after.ctime()
            || before.ctime_nsec() != after.ctime_nsec()
            || before.mode() != after.mode()
            || before.uid() != after.uid()
        {
            return Err(ExecutionError::UnsafeSource);
        }
        #[cfg(test)]
        hook(Boundary::Copied);
        seal_fd(sealed.as_raw_fd())?;
        #[cfg(test)]
        hook(Boundary::Sealed);
        sealed
            .seek(SeekFrom::Start(0))
            .map_err(|_error| ExecutionError::Unavailable)?;
        let mut bytes = Vec::with_capacity(copied as usize);
        sealed
            .read_to_end(&mut bytes)
            .map_err(|_error| ExecutionError::Unavailable)?;
        if Sha256::digest(&bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
            != digest
        {
            return Err(ExecutionError::DigestMismatch);
        }
        validate_elf(&bytes)?;
        #[cfg(test)]
        hook(Boundary::Verified);
        Ok(PreparedExecutable { file: sealed, argv })
    }

    fn seal_fd(fd: RawFd) -> Result<(), ExecutionError> {
        if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } < 0 {
            return Err(ExecutionError::Unavailable);
        }
        let observed = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        if observed < 0 || observed & SEALS != SEALS {
            return Err(ExecutionError::Unavailable);
        }
        Ok(())
    }

    pub(super) fn execute_fd(
        fd: RawFd,
        argv: &[CString],
    ) -> Result<std::convert::Infallible, ExecutionError> {
        #[cfg(test)]
        TEST_EXECUTION_ATTEMPTS.with(|calls| calls.set(calls.get() + 1));
        let observed = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        if observed < 0 || observed & SEALS != SEALS {
            return Err(ExecutionError::ExecutionFailed);
        }
        let mut pointers: Vec<_> = argv.iter().map(|arg| arg.as_ptr()).collect();
        pointers.push(std::ptr::null());
        let environment: [*const libc::c_char; 1] = [std::ptr::null()];
        #[cfg(test)]
        TEST_LAUNCH_ATTEMPTS.with(|calls| calls.set(calls.get() + 1));
        unsafe {
            libc::syscall(
                libc::SYS_execveat,
                fd,
                c"".as_ptr(),
                pointers.as_ptr(),
                environment.as_ptr(),
                libc::AT_EMPTY_PATH,
            );
        }
        Err(ExecutionError::ExecutionFailed)
    }

    fn validate_elf(b: &[u8]) -> Result<(), ExecutionError> {
        let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        let page_size = u64::try_from(page_size).map_err(|_error| ExecutionError::Unavailable)?;
        validate_elf_for_page_size(b, page_size)
    }

    // The caller validates page_size. Keeping the architecture range and page
    // rounding together lets both supported profiles be checked on either host.
    fn checked_userspace_mapping_end(
        machine: u16,
        page_size: u64,
        end: u64,
    ) -> Result<u64, ExecutionError> {
        // V1 deliberately fits the minimum supported Linux userspace ranges.
        // x86-64 TASK_SIZE excludes the final page below 2^47; arm64 can use
        // CONFIG_ARM64_VA_BITS_36. See the Linux 6.3 sources in access-mvp.md.
        let userspace_end = match machine {
            62 => (1u64 << 47)
                .checked_sub(page_size)
                .ok_or(ExecutionError::Unavailable)?,
            183 => 1u64 << 36,
            _ => return Err(ExecutionError::UnsupportedImage),
        };
        let page_end = end
            .checked_add(page_size - 1)
            .ok_or(ExecutionError::UnsupportedImage)?
            & !(page_size - 1);
        if page_end > userspace_end {
            return Err(ExecutionError::UnsupportedImage);
        }
        Ok(page_end)
    }

    fn validate_elf_for_page_size(b: &[u8], page_size: u64) -> Result<(), ExecutionError> {
        if page_size < 4096 || !page_size.is_power_of_two() {
            return Err(ExecutionError::Unavailable);
        }
        let bad = ExecutionError::UnsupportedImage;
        let u16_at = |n| u16::from_le_bytes([b[n], b[n + 1]]);
        let u32_at = |n| u32::from_le_bytes(b[n..n + 4].try_into().expect("bounded ELF field"));
        let u64_at = |n| u64::from_le_bytes(b[n..n + 8].try_into().expect("bounded ELF field"));
        let machine = if cfg!(target_arch = "x86_64") {
            62
        } else if cfg!(target_arch = "aarch64") {
            183
        } else {
            return Err(bad);
        };
        if b.len() < 64
            || &b[..4] != b"\x7fELF"
            || b[4] != 2
            || b[5] != 1
            || b[6] != 1
            || !matches!(b[7], 0 | 3)
            || b[8] != 0
            || b[9..16].iter().any(|v| *v != 0)
            || u16_at(16) != 2
            || u16_at(18) != machine
            || u32_at(20) != 1
            || u32_at(48) != 0
            || u16_at(52) != 64
            || u16_at(54) != 56
        {
            return Err(bad);
        }
        let phoff = u64_at(32);
        let count = u16_at(56) as u64;
        if count == 0
            || count > 1024
            || phoff < 64
            || phoff
                .checked_add(count * 56)
                .is_none_or(|end| end > b.len() as u64)
        {
            return Err(bad);
        }
        let shoff = u64_at(40);
        let shnum = u16_at(60) as u64;
        if shoff == 0 {
            if shnum != 0 || u16_at(62) != 0 {
                return Err(bad);
            }
        } else if shnum == 0
            || u16_at(58) != 64
            || shoff < 64
            || shoff
                .checked_add(shnum * 64)
                .is_none_or(|end| end > b.len() as u64)
            || u16_at(62) as u64 >= shnum
        {
            return Err(bad);
        }
        for index in 0..shnum {
            let n = (shoff + index * 64) as usize;
            let kind = u32_at(n + 4);
            let offset = u64_at(n + 24);
            let size = u64_at(n + 32);
            let align = u64_at(n + 48);
            let entry_size = u64_at(n + 56);
            if (kind != 8
                && offset
                    .checked_add(size)
                    .is_none_or(|end| end > b.len() as u64))
                || (align > 1 && !align.is_power_of_two())
                || (entry_size != 0 && size % entry_size != 0)
                || u32_at(n + 40) as u64 >= shnum
            {
                return Err(bad);
            }
        }
        let entry = u64_at(24);
        let mut entry_found = false;
        let mut loads = Vec::new();
        for index in 0..count {
            let n = (phoff + index * 56) as usize;
            let kind = u32_at(n);
            let flags = u32_at(n + 4);
            let offset = u64_at(n + 8);
            let address = u64_at(n + 16);
            let filesz = u64_at(n + 32);
            let memsz = u64_at(n + 40);
            let align = u64_at(n + 48);
            if kind == 2 || kind == 3 || (kind == 0x6474e551 && flags & 1 != 0) {
                return Err(bad);
            }
            if offset
                .checked_add(filesz)
                .is_none_or(|end| end > b.len() as u64)
            {
                return Err(bad);
            }
            if kind == 1 {
                if flags & !7 != 0
                    || flags & 3 == 3
                    || filesz > memsz
                    || memsz == 0
                    || address.checked_add(memsz).is_none()
                    || (align > 1
                        && (!align.is_power_of_two() || address % align != offset % align))
                    || address % page_size != offset % page_size
                {
                    return Err(bad);
                }
                let end = address + memsz;
                // Reject overlapping mappings, including overlap at page granularity.
                let page_start = address & !(page_size - 1);
                let page_end = checked_userspace_mapping_end(machine, page_size, end)?;
                if loads
                    .iter()
                    .any(|(start, stop)| page_start < *stop && *start < page_end)
                {
                    return Err(bad);
                }
                if loads.last().is_some_and(|(start, _)| page_start <= *start) {
                    return Err(bad);
                }
                loads.push((page_start, page_end));
                if flags & 1 != 0 && entry >= address && entry < address + filesz {
                    entry_found = true;
                }
            }
        }
        if !entry_found {
            return Err(bad);
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests;
}
