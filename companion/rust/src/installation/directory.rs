//! Account-private activation directory. Unix mutations are descriptor-relative;
//! Windows pins every directory with handles that deny deletion/rename sharing.
use super::{fail, regular};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};

pub(super) struct Directory {
    pub path: PathBuf,
    handle: File,
    _ancestors: Vec<File>,
    #[cfg(test)]
    pub fail_final_sync: bool,
}
#[cfg(unix)]
fn owned(metadata: &fs::Metadata) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.permissions().mode() & 0o022 != 0 {
        return Err(fail(
            "Every directory inside your home must be owned by you and not writable by other users",
        ));
    }
    Ok(())
}
#[cfg(windows)]
fn owned(_metadata: &fs::Metadata) -> Result<(), String> {
    Ok(())
}
#[cfg(unix)]
fn name(value: &str) -> Result<std::ffi::CString, String> {
    if value.is_empty()
        || value.contains('/')
        || value.contains('\\')
        || value == "."
        || value == ".."
    {
        return Err(fail("Invalid managed filename"));
    }
    std::ffi::CString::new(value).map_err(|_| fail("Invalid managed filename"))
}
#[cfg(unix)]
fn open_at(parent: &File, value: &str, flags: i32, mode: u32) -> Result<File, String> {
    use std::os::fd::{AsRawFd, FromRawFd};
    let value = name(value)?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            value.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            mode as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(fail(
            "Cannot open managed file or directory; check permissions and links",
        ));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn open_directory(path: &Path, search_only: bool) -> Result<File, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let flags = libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
        #[cfg(target_os = "macos")]
        let flags = if search_only {
            flags | libc::O_SEARCH
        } else {
            flags
        };
        #[cfg(not(target_os = "macos"))]
        let _ = search_only;
        options.custom_flags(flags);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        let _ = search_only;
        // BACKUP_SEMANTICS permits directory handles; OPEN_REPARSE_POINT makes
        // metadata inspect the link itself. No FILE_SHARE_DELETE pins the name.
        options
            .custom_flags(0x02000000 | 0x00200000)
            .share_mode(1 | 2);
    }
    let file = options
        .open(path)
        .map_err(|_| fail("Cannot open user command directory"))?;
    let m = file
        .metadata()
        .map_err(|_| fail("Cannot inspect user directory"))?;
    if !m.is_dir() {
        return Err(fail("User command path is not a directory"));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if m.file_attributes() & 0x400 != 0 {
            return Err(fail("Reparse directories are not accepted"));
        }
    }
    owned(&m)?;
    #[cfg(target_os = "macos")]
    macos_private(&file)?;
    #[cfg(windows)]
    windows_private(&file)?;
    Ok(file)
}
#[cfg(unix)]
fn sync_created_directory(parent: &File) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        use std::os::fd::{AsRawFd, FromRawFd};
        let fd = unsafe {
            libc::openat(
                parent.as_raw_fd(),
                c".".as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(fail("Cannot open directory for durable creation"));
        }
        let full = unsafe { File::from_raw_fd(fd) };
        full.sync_all()
            .map_err(|_| fail("Cannot persist user command directory"))
    }
    #[cfg(not(target_os = "macos"))]
    parent
        .sync_all()
        .map_err(|_| fail("Cannot persist user command directory"))
}
impl Directory {
    pub fn open(home: &Path, requested: &Path, forbidden: &Path) -> Result<Self, String> {
        if !requested.is_absolute()
            || requested
                .components()
                .any(|c| matches!(c, Component::ParentDir))
        {
            return Err(fail("Select an absolute directory inside your home"));
        }
        let canonical_home = home
            .canonicalize()
            .map_err(|_| fail("Cannot resolve user home"))?;
        let relative = requested
            .strip_prefix(&canonical_home)
            .or_else(|_| requested.strip_prefix(home))
            .map_err(|_| {
                fail("Select a folder inside your account home; system installation is not offered")
            })?;
        if canonical_home.join(relative).starts_with(forbidden) {
            return Err(fail(
                "Command directory must be outside the application bundle",
            ));
        }
        let mut current = open_directory(&canonical_home, relative.components().next().is_some())?;
        let mut path = canonical_home;
        let mut ancestors = Vec::new();
        let components: Vec<_> = relative.components().collect();
        for (index, component) in components.iter().enumerate() {
            #[cfg(windows)]
            let _ = index;
            let Component::Normal(value) = component else {
                return Err(fail("Invalid user directory path"));
            };
            let value = value
                .to_str()
                .ok_or_else(|| fail("Directory path must be valid Unicode"))?;
            #[cfg(unix)]
            let next = {
                use std::os::fd::AsRawFd;
                let child = name(value)?;
                let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
                let observed = unsafe {
                    libc::fstatat(
                        current.as_raw_fd(),
                        child.as_ptr(),
                        &mut metadata,
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                };
                if observed != 0 {
                    if std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT) {
                        return Err(fail("Cannot inspect user directory ancestor"));
                    }
                    if unsafe { libc::mkdirat(current.as_raw_fd(), child.as_ptr(), 0o700) } != 0 {
                        return Err(fail("Cannot create user command directory"));
                    }
                    sync_created_directory(&current)?;
                }
                let flags = libc::O_RDONLY | libc::O_DIRECTORY;
                #[cfg(target_os = "macos")]
                let flags = if index + 1 < components.len() {
                    libc::O_SEARCH
                } else {
                    flags
                };
                #[cfg(not(target_os = "macos"))]
                let _ = index;
                open_at(&current, value, flags, 0)?
            };
            path.push(value);
            #[cfg(windows)]
            let next = {
                if !path.exists() {
                    fs::create_dir(&path)
                        .map_err(|_| fail("Cannot create user command directory"))?;
                }
                open_directory(&path, false)?
            };
            let metadata = next
                .metadata()
                .map_err(|_| fail("Cannot inspect user directory"))?;
            if !metadata.is_dir() {
                return Err(fail("Invalid user command directory"));
            }
            owned(&metadata)?;
            #[cfg(target_os = "macos")]
            macos_private(&next)?;
            ancestors.push(current);
            current = next;
        }
        Ok(Self {
            path,
            handle: current,
            _ancestors: ancestors,
            #[cfg(test)]
            fail_final_sync: false,
        })
    }
    pub fn exists(&self, value: &str) -> bool {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let Ok(value) = name(value) else {
                return true;
            };
            let mut data: libc::stat = unsafe { std::mem::zeroed() };
            let result = unsafe {
                libc::fstatat(
                    self.handle.as_raw_fd(),
                    value.as_ptr(),
                    &mut data,
                    libc::AT_SYMLINK_NOFOLLOW,
                )
            };
            result == 0 || std::io::Error::last_os_error().raw_os_error() != Some(libc::ENOENT)
        }
        #[cfg(windows)]
        {
            fs::symlink_metadata(self.path.join(value)).is_ok()
        }
    }
    fn read_file(&self, value: &str) -> Result<File, String> {
        #[cfg(unix)]
        let file = open_at(&self.handle, value, libc::O_RDONLY | libc::O_NONBLOCK, 0)?;
        #[cfg(windows)]
        let file = {
            regular(&self.path.join(value))?;
            super::open_read(&self.path.join(value))?
        };
        let metadata = file
            .metadata()
            .map_err(|_| fail("Cannot inspect managed file"))?;
        if !metadata.is_file() {
            return Err(fail("Managed command is not a regular file"));
        }
        owned(&metadata)?;
        #[cfg(target_os = "macos")]
        macos_private(&file)?;
        #[cfg(windows)]
        windows_private(&file)?;
        Ok(file)
    }
    pub fn read(&self, value: &str, limit: u64) -> Result<Vec<u8>, String> {
        let mut bytes = Vec::new();
        self.read_file(value)?
            .take(limit + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| fail("Cannot read managed file"))?;
        if bytes.len() as u64 > limit {
            return Err(fail("Managed file is too large"));
        }
        Ok(bytes)
    }
    pub fn executable(&self, value: &str) -> Result<bool, String> {
        let metadata = self
            .read_file(value)?
            .metadata()
            .map_err(|_| fail("Cannot inspect command mode"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            Ok(metadata.permissions().mode() & 0o100 != 0)
        }
        #[cfg(windows)]
        {
            let _ = metadata;
            Ok(true)
        }
    }
    pub fn lock(&self) -> Result<File, String> {
        let value = ".vaultwarden-commands.lock";
        #[cfg(unix)]
        let file = open_at(&self.handle, value, libc::O_RDWR | libc::O_CREAT, 0o600)?;
        #[cfg(windows)]
        let file = {
            if self.exists(value) {
                regular(&self.path.join(value))?;
            }
            OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .open(self.path.join(value))
                .map_err(|_| fail("Cannot open activation lock"))?
        };
        let metadata = file.metadata().map_err(|_| fail("Cannot inspect lock"))?;
        if !metadata.is_file() {
            return Err(fail("Invalid activation lock"));
        }
        owned(&metadata)?;
        fs4::FileExt::try_lock(&file).map_err(|_| fail("Another activation is in progress"))?;
        Ok(file)
    }
    pub fn stage(&self, data: &[u8], executable: bool, quarantine: bool) -> Result<String, String> {
        let mut nonce = [0u8; 16];
        getrandom::fill(&mut nonce).map_err(|_| fail("Cannot obtain staging identity"))?;
        let id: String = nonce.iter().map(|b| format!("{b:02x}")).collect();
        let value = format!(
            ".vaultwarden-{}-{id}",
            if quarantine { "quarantine" } else { "stage" }
        );
        #[cfg(unix)]
        let mut file = open_at(
            &self.handle,
            &value,
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
            0o600,
        )?;
        #[cfg(windows)]
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.path.join(&value))
            .map_err(|_| fail("Cannot stage command setup"))?;
        #[cfg(windows)]
        windows_private(&file)?;
        #[cfg(target_os = "macos")]
        macos_private(&file)?;
        file.write_all(data)
            .map_err(|_| fail("Cannot write command setup"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(if executable {
                0o755
            } else {
                0o600
            }))
            .map_err(|_| fail("Cannot set command permissions"))?;
        }
        #[cfg(windows)]
        let _ = executable;
        // Persist the payload and its final mode before any directory publication.
        file.sync_all()
            .map_err(|_| fail("Cannot persist staged command setup"))?;
        Ok(value)
    }
    pub fn remove(&self, value: &str) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let value = name(value)?;
            if unsafe { libc::unlinkat(self.handle.as_raw_fd(), value.as_ptr(), 0) } != 0 {
                return Err(fail("Cannot remove completed staging file"));
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            fs::remove_file(self.path.join(value))
                .map_err(|_| fail("Cannot remove completed staging file"))
        }
    }
    pub fn publish(&self, stage: &str, destination: &str) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let source = name(stage)?;
            let dest = name(destination)?;
            if unsafe {
                libc::linkat(
                    self.handle.as_raw_fd(),
                    source.as_ptr(),
                    self.handle.as_raw_fd(),
                    dest.as_ptr(),
                    0,
                )
            } != 0
            {
                return Err(fail(
                    "Cannot publish command without overwriting an existing file",
                ));
            }
        }
        #[cfg(windows)]
        super::replace(&self.path.join(stage), &self.path.join(destination), false)?;
        #[cfg(unix)]
        self.remove(stage)?;
        self.sync()
    }
    pub fn replace(&self, stage: &str, destination: &str) -> Result<(), String> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let source = name(stage)?;
            let dest = name(destination)?;
            if unsafe {
                libc::renameat(
                    self.handle.as_raw_fd(),
                    source.as_ptr(),
                    self.handle.as_raw_fd(),
                    dest.as_ptr(),
                )
            } != 0
            {
                return Err(fail("Activation failed before switching command setup"));
            }
            Ok(())
        }
        #[cfg(windows)]
        {
            super::replace(&self.path.join(stage), &self.path.join(destination), true)
        }
    }
    pub fn still_named(&self) -> Result<(), String> {
        let current = regular(&self.path)?;
        let original = self
            .handle
            .metadata()
            .map_err(|_| fail("Cannot inspect command directory"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if current.dev() != original.dev() || current.ino() != original.ino() {
                return Err(fail(
                    "Command directory moved during activation; no setup was switched",
                ));
            }
        }
        #[cfg(windows)]
        let _ = (current, original);
        Ok(())
    }
    pub fn sync(&self) -> Result<(), String> {
        #[cfg(unix)]
        self.handle
            .sync_all()
            .map_err(|_| fail("Cannot persist command directory metadata"))?;
        // Windows replacement uses MOVEFILE_WRITE_THROUGH; new files were flushed.
        Ok(())
    }
    pub fn sync_activation(&self) -> Result<(), String> {
        #[cfg(test)]
        if self.fail_final_sync {
            return Err(fail("injected final directory sync failure"));
        }
        self.sync()
    }
}

#[cfg(windows)]
fn windows_private(file: &File) -> Result<(), String> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
    use windows_sys::Win32::Foundation::LocalFree;
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::*;
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    let mut raw_token = std::ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut raw_token) } == 0 {
        return Err(fail("Cannot inspect account permissions"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw_token) };
    let mut length = 0;
    unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            std::ptr::null_mut(),
            0,
            &mut length,
        );
    }
    if length == 0 || length > 65536 {
        return Err(fail("Cannot inspect account identity"));
    }
    let mut storage = vec![
        0usize;
        (length as usize + std::mem::size_of::<usize>() - 1)
            / std::mem::size_of::<usize>()
    ];
    if unsafe {
        GetTokenInformation(
            token.as_raw_handle(),
            TokenUser,
            storage.as_mut_ptr().cast(),
            length,
            &mut length,
        )
    } == 0
    {
        return Err(fail("Cannot inspect account identity"));
    }
    let user = unsafe { (*(storage.as_ptr().cast::<TOKEN_USER>())).User.Sid };
    let mut system = [0u32; 17];
    let mut administrators = [0u32; 17];
    let mut creator_owner = [0u32; 17];
    for (kind, buffer) in [
        (WinLocalSystemSid, &mut system),
        (WinBuiltinAdministratorsSid, &mut administrators),
        (WinCreatorOwnerSid, &mut creator_owner),
    ] {
        let mut size = 68;
        if unsafe {
            CreateWellKnownSid(
                kind,
                std::ptr::null_mut(),
                buffer.as_mut_ptr().cast(),
                &mut size,
            )
        } == 0
        {
            return Err(fail("Cannot inspect trusted Windows principals"));
        }
    }
    let trusted = |sid: PSID| {
        !sid.is_null()
            && unsafe {
                EqualSid(sid, user) != 0
                    || EqualSid(sid, system.as_ptr().cast_mut().cast()) != 0
                    || EqualSid(sid, administrators.as_ptr().cast_mut().cast()) != 0
            }
    };
    let mut owner = std::ptr::null_mut();
    let mut acl = std::ptr::null_mut();
    let mut descriptor = std::ptr::null_mut();
    let status = unsafe {
        GetSecurityInfo(
            file.as_raw_handle(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut acl,
            std::ptr::null_mut(),
            &mut descriptor,
        )
    };
    if status != 0 {
        return Err(fail("Cannot inspect Windows directory permissions"));
    }
    let result = (|| {
        if !trusted(owner) || acl.is_null() {
            return Err(fail("Use a private user directory with an account, Administrators or SYSTEM owner and explicit access control"));
        }
        for index in 0..unsafe { (*acl).AceCount } {
            let mut raw = std::ptr::null_mut();
            if unsafe { GetAce(acl, u32::from(index), &mut raw) } == 0 || raw.is_null() {
                return Err(fail("Cannot inspect directory access rules"));
            }
            let header = unsafe { &*raw.cast::<ACE_HEADER>() };
            if header.AceType == 1 {
                continue;
            } // deny grants no mutation rights
            if header.AceFlags & 0x08 != 0 && header.AceFlags & 0x03 == 0 {
                continue;
            } // applies to neither this object nor descendants
            if header.AceType != 0 {
                return Err(fail("Complex directory access rules are not supported; choose a private user folder"));
            }
            let rule = unsafe { &*raw.cast::<ACCESS_ALLOWED_ACE>() };
            let sid = std::ptr::addr_of!(rule.SidStart).cast_mut().cast();
            const WRITE_ACCESS: u32 = 0x2
                | 0x4
                | 0x10
                | 0x40
                | 0x100
                | 0x10000
                | 0x40000
                | 0x80000
                | 0x10000000
                | 0x40000000;
            let owner_inheritance = header.AceFlags & 0x08 != 0
                && unsafe { EqualSid(sid, creator_owner.as_ptr().cast_mut().cast()) != 0 };
            if rule.Mask & WRITE_ACCESS != 0 && !trusted(sid) && !owner_inheritance {
                return Err(fail("Directory is writable by another Windows principal; choose a private user folder"));
            }
        }
        Ok(())
    })();
    unsafe {
        LocalFree(descriptor);
    }
    result
}

#[cfg(target_os = "macos")]
fn macos_private(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;
    type Opaque = *mut std::ffi::c_void;
    unsafe extern "C" {
        fn acl_get_fd_np(fd: i32, kind: i32) -> Opaque;
        fn acl_valid(acl: Opaque) -> i32;
        fn acl_get_entry(acl: Opaque, index: i32, entry: *mut Opaque) -> i32;
        fn acl_get_tag_type(entry: Opaque, tag: *mut i32) -> i32;
        fn acl_get_permset_mask_np(entry: Opaque, mask: *mut u64) -> i32;
        fn acl_get_qualifier(entry: Opaque) -> Opaque;
        fn acl_free(value: Opaque) -> i32;
        fn mbr_uid_to_uuid(uid: libc::uid_t, uuid: *mut u8) -> i32;
    }
    let acl = unsafe { acl_get_fd_np(file.as_raw_fd(), 0x100) };
    if acl.is_null() {
        // Darwin returns ENOENT for an absent extended ACL on an already-open
        // valid object. Other lookup failures are not interpreted as no ACL.
        if std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(fail("Cannot inspect macOS ACL permissions"));
    }
    let result = (|| {
        if unsafe { acl_valid(acl) } != 0 {
            return Err(fail("Invalid macOS ACL"));
        }
        let mut owner = [0u8; 16];
        let mut root = [0u8; 16];
        if unsafe { mbr_uid_to_uuid(libc::geteuid(), owner.as_mut_ptr()) } != 0
            || unsafe { mbr_uid_to_uuid(0, root.as_mut_ptr()) } != 0
        {
            return Err(fail("Cannot resolve macOS ACL identity"));
        }
        for index in 0..1024 {
            let mut entry = std::ptr::null_mut();
            if unsafe { acl_get_entry(acl, index, &mut entry) } != 0 {
                if std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                    return Ok(());
                }
                return Err(fail("Cannot inspect macOS ACL entries"));
            }
            let mut tag = 0;
            let mut permissions = 0u64;
            if unsafe { acl_get_tag_type(entry, &mut tag) } != 0
                || unsafe { acl_get_permset_mask_np(entry, &mut permissions) } != 0
            {
                return Err(fail("Cannot inspect macOS ACL permissions"));
            }
            if tag == 2 {
                continue;
            } // Includes the normal everyone-deny-delete rule.
            if tag != 1 {
                return Err(fail("Unknown macOS ACL permission kind"));
            }
            const MUTATION: u64 = (1 << 2)
                | (1 << 4)
                | (1 << 5)
                | (1 << 6)
                | (1 << 8)
                | (1 << 10)
                | (1 << 12)
                | (1 << 13);
            if permissions & MUTATION == 0 {
                continue;
            }
            let qualifier = unsafe { acl_get_qualifier(entry) };
            if qualifier.is_null() {
                return Err(fail("Cannot inspect macOS ACL principal"));
            }
            let uuid = unsafe { std::slice::from_raw_parts(qualifier.cast::<u8>(), 16) };
            let trusted = uuid == owner || uuid == root;
            unsafe {
                acl_free(qualifier);
            }
            // Inherit-only mutation grants matter too: they can make newly
            // created receipt or executable files writable by another user.
            if !trusted {
                return Err(fail("macOS ACL grants mutation rights to another principal; choose a private user folder"));
            }
        }
        Err(fail("macOS ACL contains too many entries"))
    })();
    unsafe {
        acl_free(acl);
    }
    result
}
