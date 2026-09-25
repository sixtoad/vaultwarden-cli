use super::*;
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};

fn image_bytes() -> Vec<u8> {
    // Machine code assembled from tests/fixtures/protected-exit.S; no toolchain at test time.
    let code: &[u8] = &[
        0x48, 0x83, 0x3c, 0x24, 0x02, 0x75, 0x2a, 0x48, 0x8b, 0x44, 0x24, 0x10, 0x81, 0x38, 0x6d,
        0x61, 0x72, 0x6b, 0x75, 0x1d, 0x80, 0x78, 0x04, 0x00, 0x75, 0x17, 0x48, 0x83, 0x7c, 0x24,
        0x18, 0x00, 0x75, 0x0f, 0x48, 0x83, 0x7c, 0x24, 0x20, 0x00, 0x75, 0x07, 0xbf, 0x2a, 0x00,
        0x00, 0x00, 0xeb, 0x05, 0xbf, 0x63, 0x00, 0x00, 0x00, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x0f,
        0x05,
    ];
    image_with_code(code)
}

#[cfg(target_arch = "x86_64")]
fn output_image_bytes() -> Vec<u8> {
    // This fixture forks two writers: one emits 128 KiB to stdout while the
    // other emits 128 KiB to stderr. It is preassembled so the test needs no
    // toolchain and exercises concurrent pipe draining.
    let code: &[u8] = &[
        0xb8, 0x39, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x48, 0x85, 0xc0, 0x74, 0x2c, 0x41, 0xbc, 0x00,
        0x20, 0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8d,
        0x35, 0x41, 0x00, 0x00, 0x00, 0xba, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x41, 0xff, 0xcc,
        0x75, 0xe3, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, 0x41, 0xbc, 0x00, 0x20,
        0x00, 0x00, 0xb8, 0x01, 0x00, 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x35,
        0x25, 0x00, 0x00, 0x00, 0xba, 0x10, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x41, 0xff, 0xcc, 0x75,
        0xe3, 0xb8, 0x3c, 0x00, 0x00, 0x00, 0x31, 0xff, 0x0f, 0x05, b's', b't', b'd', b'o', b'u',
        b't', b'-', b's', b'e', b'n', b't', b'i', b'n', b'e', b'l', b'\n', b's', b't', b'd', b'e',
        b'r', b'r', b'-', b's', b'e', b'n', b't', b'i', b'n', b'e', b'l', b'\n',
    ];
    image_with_code(code)
}

fn image_with_code(code: &[u8]) -> Vec<u8> {
    let mut b = vec![0u8; 4096];
    b[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    b[16..18].copy_from_slice(&2u16.to_le_bytes());
    let machine: u16 = if cfg!(target_arch = "aarch64") {
        183
    } else {
        62
    };
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b[20..24].copy_from_slice(&1u32.to_le_bytes());
    b[24..32].copy_from_slice(&0x400078u64.to_le_bytes());
    b[32..40].copy_from_slice(&64u64.to_le_bytes());
    b[52..54].copy_from_slice(&64u16.to_le_bytes());
    b[54..56].copy_from_slice(&56u16.to_le_bytes());
    b[56..58].copy_from_slice(&1u16.to_le_bytes());
    b[64..68].copy_from_slice(&1u32.to_le_bytes());
    b[68..72].copy_from_slice(&5u32.to_le_bytes());
    b[80..88].copy_from_slice(&0x400000u64.to_le_bytes());
    b[96..104].copy_from_slice(&4096u64.to_le_bytes());
    b[104..112].copy_from_slice(&4096u64.to_le_bytes());
    b[112..120].copy_from_slice(&4096u64.to_le_bytes());
    b[120..120 + code.len()].copy_from_slice(code);
    if cfg!(target_arch = "aarch64") {
        // Native exit(42); real argv/environment execution oracle is x86_64-only.
        b[120..132].copy_from_slice(&[
            0x40, 0x05, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        ]);
    }
    b
}
struct Fixture {
    root: tempfile::TempDir,
    path: std::path::PathBuf,
    bytes: Vec<u8>,
}
impl Fixture {
    fn new() -> Self {
        Self::from_bytes(image_bytes())
    }
    #[cfg(target_arch = "x86_64")]
    fn output() -> Self {
        Self::from_bytes(output_image_bytes())
    }
    fn from_bytes(bytes: Vec<u8>) -> Self {
        TEST_EXECUTION_ATTEMPTS.with(|calls| calls.set(0));
        TEST_LAUNCH_ATTEMPTS.with(|calls| calls.set(0));
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = root.path().join("image");
        std::fs::write(&path, &bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o500)).unwrap();
        Self { root, path, bytes }
    }
    fn digest(&self) -> String {
        Sha256::digest(&self.bytes)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
    fn source(&self) -> File {
        open_source(self.root.path(), &self.path).expect("tests need secure TMPDIR ancestry")
    }
    fn prepare(&self) -> Result<PreparedExecutable, ExecutionError> {
        let execution_before = TEST_EXECUTION_ATTEMPTS.with(|calls| calls.get());
        let launch_before = TEST_LAUNCH_ATTEMPTS.with(|calls| calls.get());
        let result = LinuxExecutablePreparer.prepare(
            ExecutionImage {
                root: self.root.path(),
                path: &self.path,
                sha256: &self.digest(),
                profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
            },
            vec!["fixture".into(), "mark".into()],
        );
        TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), execution_before));
        TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), launch_before));
        result
    }
    fn writable(&self) -> File {
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o700)).unwrap();
        let writer = std::fs::OpenOptions::new()
            .write(true)
            .open(&self.path)
            .unwrap();
        std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o500)).unwrap();
        writer
    }
}
fn argv() -> Vec<CString> {
    checked_arguments(vec!["fixture".into(), "mark".into()]).unwrap()
}

#[test]
fn valid_image_has_all_seals_and_redacted_debug() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    assert_eq!(
        unsafe { libc::fcntl(prepared.file.as_raw_fd(), libc::F_GET_SEALS) } & SEALS,
        SEALS
    );
    assert_eq!(prepared.file.metadata().unwrap().mode() & 0o7777, 0o500);
    assert_eq!(format!("{prepared:?}"), "PreparedExecutable([REDACTED])");
    assert!(prepared.file.set_len(1).is_err());
    assert!(prepared.file.set_len(8192).is_err());
    assert_eq!(
        unsafe { libc::pwrite(prepared.file.as_raw_fd(), b"X".as_ptr().cast(), 1, 120) },
        -1
    );
    assert_eq!(
        unsafe { libc::fchmod(prepared.file.as_raw_fd(), 0o400) },
        -1
    );
}

#[test]
fn fixture_supervision_uses_explicit_environment_and_reaps_the_child() {
    let fixture = Fixture::new();
    let prepared = fixture.prepare().unwrap();
    let environment = ChildEnvironment::from_mappings([(
        "LOGIN_TOKEN".to_owned(),
        crate::access::ports::SensitiveString::new("synthetic-sentinel".to_owned()),
    )])
    .unwrap();
    // The fixture accepts an empty environment and exits 42.  A nonzero
    // result therefore proves the exact explicit environment reached it; the
    // supervisor still reaped it and retained neither output nor the value.
    assert_eq!(
        prepared.run_fixture(environment).unwrap(),
        ExecutionOutcome::ExitedNonZero
    );
}

#[cfg(target_arch = "x86_64")]
#[test]
fn fixture_supervision_discards_large_secret_output_from_both_streams() {
    crate::adapters::execution::TEST_DISCARDED_BYTES.store(0, std::sync::atomic::Ordering::SeqCst);
    let fixture = Fixture::output();
    let prepared = fixture.prepare().unwrap();
    let environment = ChildEnvironment::from_mappings([(
        "LOGIN_TOKEN".to_owned(),
        crate::access::ports::SensitiveString::new("synthetic-secret-sentinel".to_owned()),
    )])
    .unwrap();
    assert_eq!(
        prepared.run_fixture(environment).unwrap(),
        ExecutionOutcome::ExitedZero
    );
    assert_eq!(
        crate::adapters::execution::TEST_DISCARDED_BYTES.load(std::sync::atomic::Ordering::SeqCst),
        256 * 1024,
    );
}

#[test]
fn independent_source_mode_guards() {
    for mode in [0o700, 0o520, 0o502, 0o4500, 0o2500, 0o1500, 0o400, 0o100] {
        let f = Fixture::new();
        std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            !source_ok(&std::fs::metadata(&f.path).unwrap(), unsafe {
                libc::geteuid()
            }),
            "mode {mode:o}"
        );
        let error = f.prepare().unwrap_err();
        if mode == 0o100 {
            // Kernel denies open before source metadata when owner-read is absent.
            assert!(matches!(
                error,
                ExecutionError::UnsafePath | ExecutionError::UnsafeSource
            ));
        } else {
            assert_eq!(error, ExecutionError::UnsafeSource, "mode {mode:o}");
        }
    }
}
#[test]
fn independent_root_and_descendant_mode_guards() {
    for mode in [0o750, 0o770, 0o707, 0o1700, 0o2700, 0o4700] {
        let f = Fixture::new();
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert_eq!(
            f.prepare().unwrap_err(),
            ExecutionError::UnsafePath,
            "root {mode:o}"
        );
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let child = f.root.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(mode)).unwrap();
        std::fs::rename(&f.path, child.join("image")).unwrap();
        assert!(
            open_source(f.root.path(), &child.join("image")).is_err(),
            "child {mode:o}"
        );
    }
}
#[test]
fn full_preparer_rejects_each_unsafe_execution_root_ancestor_permission() {
    let f = Fixture::new();
    let root = f.root.path().join("execution-root");
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.join("image");
    std::fs::rename(&f.path, &path).unwrap();
    let digest = f.digest();
    let prepare = || {
        LinuxExecutablePreparer.prepare(
            ExecutionImage {
                root: &root,
                path: &path,
                sha256: &digest,
                profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
            },
            vec!["fixture".into(), "mark".into()],
        )
    };
    assert!(prepare().is_ok());
    for bit in [0o020, 0o002, 0o4000, 0o2000, 0o1000] {
        // Change only an ancestor above the private execution root. Calling the
        // full preparer catches omission of the traversal's directory_ok call.
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(0o700 | bit))
            .unwrap();
        let observed_mode = std::fs::metadata(f.root.path()).unwrap().mode() & 0o7777;
        let result = prepare();
        // Restore before assertions so even a regression leaves cleanup private.
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert_eq!(observed_mode, 0o700 | bit);
        assert_eq!(
            result.unwrap_err(),
            ExecutionError::UnsafePath,
            "bit {bit:o}"
        );
        TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
        TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    }
    assert!(prepare().is_ok());
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
}

#[test]
fn directory_ownership_and_ancestor_permissions_are_independent() {
    let f = Fixture::new();
    let meta = std::fs::metadata(f.root.path()).unwrap();
    let uid = unsafe { libc::geteuid() };
    assert!(directory_ok(&meta, true, uid));
    assert!(!directory_ok(&meta, true, uid.wrapping_add(1)));
    let system_root = std::fs::metadata("/").unwrap();
    assert_eq!(system_root.uid(), 0);
    assert!(directory_ok(&system_root, false, 1));
    // A root-owned ancestor is valid for every provider; use a genuinely
    // foreign non-root owner for the negative oracle even when running as root.
    if uid == 0 {
        let name = CString::new(f.root.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 1, u32::MAX) }, 0);
    }
    let foreign = std::fs::metadata(f.root.path()).unwrap();
    assert_ne!(foreign.uid(), 0);
    assert!(!directory_ok(
        &foreign,
        false,
        foreign.uid().wrapping_add(1)
    ));
    if uid == 0 {
        let name = CString::new(f.root.path().as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::chown(name.as_ptr(), 0, u32::MAX) }, 0);
    }
    for mode in [0o777, 0o775, 0o757, 0o1755, 0o2755, 0o4755] {
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            !directory_ok(&std::fs::metadata(f.root.path()).unwrap(), false, uid),
            "{mode:o}"
        );
    }
}
#[test]
fn symlinks_at_leaf_root_descendant_and_ancestor_are_rejected() {
    let f = Fixture::new();
    symlink(&f.path, f.root.path().join("leaf")).unwrap();
    assert!(open_source(f.root.path(), &f.root.path().join("leaf")).is_err());
    symlink(f.root.path(), f.root.path().join("link")).unwrap();
    assert!(open_source(f.root.path(), &f.root.path().join("link/image")).is_err());
    assert!(
        open_source(
            &f.root.path().join("link"),
            &f.root.path().join("link/image")
        )
        .is_err()
    );
    let child = f.root.path().join("child");
    std::fs::create_dir(&child).unwrap();
    std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::copy(&f.path, child.join("image")).unwrap();
    std::fs::set_permissions(child.join("image"), std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(open_source(&child, &child.join("image")).is_ok());
    assert!(
        open_source(
            &f.root.path().join("link/child"),
            &f.root.path().join("link/child/image")
        )
        .is_err()
    );
}
#[test]
fn invalid_paths_and_special_sources_fail_without_blocking() {
    let f = Fixture::new();
    for path in [
        f.root.path().join("../image"),
        f.root.path().join("./image"),
        std::path::PathBuf::from("image"),
        f.root.path().to_path_buf(),
    ] {
        assert!(open_source(f.root.path(), &path).is_err());
    }
    assert!(open_source(std::path::Path::new("relative"), &f.path).is_err());
    std::fs::remove_file(&f.path).unwrap();
    std::fs::create_dir(&f.path).unwrap();
    // Empty tmpfs directories may be only 40 bytes; populate before hardening
    // so every source predicate except regular-file type is satisfied.
    for index in 0..8 {
        std::fs::write(f.path.join(format!("entry-{index}")), []).unwrap();
    }
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o500)).unwrap();
    let meta = std::fs::metadata(&f.path).unwrap();
    assert_eq!(meta.uid(), unsafe { libc::geteuid() });
    assert_eq!(meta.mode() & 0o7777, 0o500);
    assert!(meta.len() >= 64 && meta.len() <= MAX_IMAGE);
    assert!(!source_ok(&meta, unsafe { libc::geteuid() }));
    assert_eq!(f.prepare().unwrap_err(), ExecutionError::UnsafeSource);
    std::fs::set_permissions(&f.path, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(&f.path).unwrap();
    let name = CString::new(f.path.as_os_str().as_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o500) }, 0);
    assert_eq!(f.prepare().unwrap_err(), ExecutionError::UnsafeSource);
}
#[test]
fn wrong_digest_and_invalid_digest_are_distinct_closed_failures() {
    let f = Fixture::new();
    assert_eq!(
        snapshot(f.source(), &"0".repeat(64), argv(), |_| {}).unwrap_err(),
        ExecutionError::DigestMismatch
    );
    for digest in ["bad".to_owned(), "G".repeat(64), "A".repeat(64)] {
        assert_eq!(
            snapshot(f.source(), &digest, argv(), |_| {}).unwrap_err(),
            ExecutionError::InvalidImage
        );
    }
}
#[test]
fn arguments_are_bounded_and_nul_free() {
    for args in [
        vec![],
        vec!["".into()],
        vec!["x\0secret-sentinel".into()],
        vec!["x".repeat(MAX_ARG_BYTES)],
        vec!["x".into(); MAX_ARGS + 1],
    ] {
        assert_eq!(
            checked_arguments(args).unwrap_err(),
            ExecutionError::InvalidArguments
        );
    }
    assert!(checked_arguments(vec!["x".repeat(MAX_ARG_BYTES - 1)]).is_ok());
    assert!(checked_arguments(vec!["x".into(); MAX_ARGS]).is_ok());
}
#[test]
fn each_unsupported_or_malformed_elf_is_rejected_with_matching_hash() {
    let cases: &[(usize, &[u8])] = &[
        (0, b"#!xx"),
        (4, &[1]),
        (5, &[2]),
        (6, &[2]),
        (7, &[1]),
        (8, &[1]),
        (9, &[1]),
        (16, &[3, 0]),
        (18, &[0, 0]),
        (20, &[2, 0, 0, 0]),
        (24, &[0; 8]),
        (32, &[255; 8]),
        (48, &[1, 0, 0, 0]),
        (52, &[63, 0]),
        (54, &[55, 0]),
        (56, &[0, 0]),
        (56, &[1, 4]),
        (64, &[2, 0, 0, 0]),
        (64, &[3, 0, 0, 0]),
        (64, &[0x51, 0xe5, 0x74, 0x64]),
        (68, &[7, 0, 0, 0]),
        (68, &[4, 0, 0, 0]),
        (68, &[13, 0, 0, 0]),
        (72, &[255; 8]),
        (80, &[255; 8]),
        (96, &[255; 8]),
        (104, &[0; 8]),
        (112, &[3, 0, 0, 0, 0, 0, 0, 0]),
        (40, &[255; 8]),
        (60, &[1, 0]),
    ];
    for (index, (offset, value)) in cases.iter().enumerate() {
        let mut f = Fixture::new();
        f.bytes[*offset..*offset + value.len()].copy_from_slice(value);
        f.writable().write_all(&f.bytes).unwrap();
        assert_eq!(
            f.prepare().unwrap_err(),
            ExecutionError::UnsupportedImage,
            "case {index}"
        );
    }
}
#[test]
fn truncated_and_oversized_sources_fail() {
    for length in [0, 63, MAX_IMAGE + 1] {
        let f = Fixture::new();
        f.writable().set_len(length).unwrap();
        assert_eq!(f.prepare().unwrap_err(), ExecutionError::UnsafeSource);
    }
    let mut b = image_bytes();
    b.truncate(100);
    assert_eq!(validate_elf(&b), Err(ExecutionError::UnsupportedImage));
}
#[test]
fn source_changes_during_copy_reject_before_capability() {
    for size in [64, 8192, 4096] {
        let f = Fixture::new();
        let mut writer = f.writable();
        let result = snapshot(f.source(), &f.digest(), argv(), |boundary| {
            if matches!(boundary, Boundary::Opened) {
                writer.set_len(size).unwrap();
                writer.write_all(b"changed").unwrap();
            }
        });
        assert!(result.is_err());
    }
}
#[test]
fn pathname_replacement_and_source_write_after_copy_do_not_replace_verified_bytes() {
    for boundary_at in [Boundary::Copied, Boundary::Sealed, Boundary::Verified] {
        let f = Fixture::new();
        let mut writer = f.writable();
        let result = snapshot(f.source(), &f.digest(), argv(), |boundary| {
            if std::mem::discriminant(&boundary) == std::mem::discriminant(&boundary_at) {
                writer.write_all(b"changed").unwrap();
                std::fs::rename(&f.path, f.root.path().join("original")).unwrap();
                std::fs::write(&f.path, b"replacement").unwrap();
            }
        })
        .unwrap();
        let mut retained = result.file;
        retained.seek(SeekFrom::Start(0)).unwrap();
        let mut bytes = Vec::new();
        retained.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, f.bytes);
    }
}
#[test]
fn invalid_and_unsealable_descriptors_fail_closed() {
    TEST_LAUNCH_ATTEMPTS.with(|calls| calls.set(0));
    assert_eq!(seal_fd(-1), Err(ExecutionError::Unavailable));
    assert_eq!(
        execute_fd(-1, &argv()),
        Err(ExecutionError::ExecutionFailed)
    );
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    let f = Fixture::new();
    assert_eq!(
        seal_fd(f.source().as_raw_fd()),
        Err(ExecutionError::Unavailable)
    );
    assert_eq!(
        execute_fd(f.source().as_raw_fd(), &argv()),
        Err(ExecutionError::ExecutionFailed)
    );
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    // A non-sealable memfd also exercises kernel refusal with a valid owned descriptor.
    let fd = unsafe {
        libc::syscall(
            libc::SYS_memfd_create,
            c"unsealable".as_ptr(),
            libc::MFD_CLOEXEC | MFD_EXEC,
        )
    };
    assert!(fd >= 0);
    let file = unsafe { File::from_raw_fd(fd as RawFd) };
    assert_eq!(seal_fd(file.as_raw_fd()), Err(ExecutionError::Unavailable));
}

#[cfg(target_arch = "x86_64")]
#[test]
fn descriptor_execution_subprocess() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "adapters::execution::linux::tests::execution_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VW_EXECUTION_FIXTURE_CHILD", "1")
        .env("SENTINEL_MUST_NOT_REACH_EXEC", "secret-sentinel")
        .output()
        .unwrap();
    assert_eq!(
        child.status.code(),
        Some(42),
        "{}",
        String::from_utf8_lossy(&child.stderr)
    );
}
#[cfg(target_arch = "x86_64")]
#[test]
#[ignore = "only invoked by descriptor_execution_subprocess; replaces process"]
fn execution_child() {
    assert_eq!(std::env::var("VW_EXECUTION_FIXTURE_CHILD").unwrap(), "1");
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    let mut writer = f.writable();
    writer.write_all(b"source was replaced").unwrap();
    std::fs::remove_file(&f.path).unwrap();
    std::fs::write(&f.path, b"replacement must never execute").unwrap();
    drop(writer);
    drop(f);
    prepared.execute().unwrap();
}
#[test]
fn descriptor_cleanup_subprocess() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "adapters::execution::linux::tests::cleanup_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VW_EXECUTION_CLEANUP_CHILD", "1")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{}",
        String::from_utf8_lossy(&child.stdout)
    );
}
#[test]
#[ignore = "isolated FD-count and raw closed descriptor checks"]
fn cleanup_child() {
    assert_eq!(std::env::var("VW_EXECUTION_CLEANUP_CHILD").unwrap(), "1");
    let f = Fixture::new();
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count();
    for _ in 0..32 {
        assert!(snapshot(f.source(), &"0".repeat(64), argv(), |_| {}).is_err());
        drop(f.prepare().unwrap());
    }
    assert_eq!(count(), before);
    let fd = f.source().as_raw_fd(); // Owned File drops before using the raw, now-closed number.
    assert_eq!(
        execute_fd(fd, &argv()),
        Err(ExecutionError::ExecutionFailed)
    );
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    assert_eq!(seal_fd(fd), Err(ExecutionError::Unavailable));
    assert_eq!(count(), before);
}

#[test]
fn source_owner_check_is_independent_of_path_and_other_metadata() {
    let f = Fixture::new();
    let meta = f.source().metadata().unwrap();
    let uid = unsafe { libc::geteuid() };
    assert!(source_ok(&meta, uid));
    assert!(!source_ok(&meta, uid.wrapping_add(1)));
}

#[test]
fn channel_coordinated_writer_cannot_change_the_retained_object() {
    for mutate_after_copy in [false, true] {
        let f = Fixture::new();
        let mut writer = f.writable();
        let (go, start) = std::sync::mpsc::channel();
        let (finished, done) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            start
                .recv_timeout(std::time::Duration::from_secs(10))
                .expect("snapshot must reach the requested mutation boundary");
            writer.seek(SeekFrom::Start(120)).unwrap();
            writer.write_all(b"altered executable bytes").unwrap();
            finished.send(()).unwrap();
        });
        let result = snapshot(f.source(), &f.digest(), argv(), |boundary| {
            if matches!(
                (boundary, mutate_after_copy),
                (Boundary::Opened, false) | (Boundary::Copied, true)
            ) {
                go.send(()).unwrap();
                done.recv_timeout(std::time::Duration::from_secs(10))
                    .expect("coordinated writer must complete at the boundary");
            }
        });
        // Disconnect even when preparation rejects before reaching the hook.
        // Deadlines bound harness failures; channels determine race ordering.
        drop(go);
        worker.join().unwrap();
        if mutate_after_copy {
            let mut retained = result.unwrap().file;
            retained.rewind().unwrap();
            let mut bytes = Vec::new();
            retained.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, f.bytes);
        } else {
            assert!(result.is_err());
        }
    }
}

#[test]
fn unavailable_memfd_and_sealing_syscalls_close_resources() {
    for failure in ["memfd", "sealing", "execveat"] {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "adapters::execution::linux::tests::syscall_failure_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VW_EXECUTION_SYSCALL_FAILURE", failure)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{failure}: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

#[test]
#[ignore = "installs process-local seccomp fault injection; parent harness only"]
fn syscall_failure_child() {
    let failure = std::env::var("VW_EXECUTION_SYSCALL_FAILURE").unwrap();
    let f = Fixture::new();
    // Prove the same fixture prepares before injecting the one syscall failure.
    drop(f.prepare().unwrap());
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut filter = if failure == "memfd" || failure == "execveat" {
        let syscall = if failure == "memfd" {
            libc::SYS_memfd_create
        } else {
            libc::SYS_execveat
        };
        vec![
            instruction(0x20, 0, 0, 0),
            instruction(0x15, 0, 1, syscall as u32),
            instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
            instruction(0x06, 0, 0, 0x7fff0000),
        ]
    } else {
        assert!(matches!(failure.as_str(), "sealing" | "readback"));
        let command = if failure == "readback" {
            libc::F_GET_SEALS
        } else {
            libc::F_ADD_SEALS
        };
        vec![
            instruction(0x20, 0, 0, 0),
            instruction(0x15, 0, 3, libc::SYS_fcntl as u32),
            instruction(0x20, 0, 0, 24),
            instruction(0x15, 0, 1, command as u32),
            instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
            instruction(0x06, 0, 0, 0x7fff0000),
        ]
    };
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
    let count = || std::fs::read_dir("/proc/self/fd").unwrap().count();
    let before = count();
    for _ in 0..16 {
        if failure == "execveat" {
            assert_eq!(
                f.prepare().unwrap().execute(),
                Err(ExecutionError::ExecutionFailed)
            );
        } else {
            assert_eq!(f.prepare().unwrap_err(), ExecutionError::Unavailable);
        }
    }
    assert_eq!(count(), before);
    let expected_attempts = if failure == "execveat" { 16 } else { 0 };
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), expected_attempts));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), expected_attempts));
}

#[test]
fn malformed_section_contents_and_overlapping_loads_are_rejected() {
    let mut b = image_bytes();
    b[40..48].copy_from_slice(&512u64.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&1u16.to_le_bytes());
    assert!(validate_elf(&b).is_ok());
    for (field, value) in [(24, u64::MAX), (32, u64::MAX), (48, 3), (56, 3)] {
        let mut invalid = b.clone();
        // Entry size 3 must fail a non-multiple section size.
        invalid[512 + 32..512 + 40].copy_from_slice(&1u64.to_le_bytes());
        invalid[512 + field..512 + field + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            validate_elf(&invalid),
            Err(ExecutionError::UnsupportedImage)
        );
    }
    let mut b = image_bytes();
    b[56..58].copy_from_slice(&2u16.to_le_bytes());
    let program = b[64..120].to_vec();
    b[120..176].copy_from_slice(&program);
    assert_eq!(validate_elf(&b), Err(ExecutionError::UnsupportedImage));
    b[136..144].copy_from_slice(&0x300000u64.to_le_bytes());
    assert_eq!(validate_elf(&b), Err(ExecutionError::UnsupportedImage));
}

#[test]
fn dependency_and_executable_stack_headers_are_rejected_beside_a_valid_load() {
    for kind in [2u32, 3, 0x6474e551] {
        let mut f = Fixture::new();
        // Move the entry away from the new second header; the first executable
        // PT_LOAD still maps a valid file-backed entry throughout each case.
        f.bytes[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
        f.bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        f.bytes[120..176].fill(0);
        assert!(validate_elf(&f.bytes).is_ok());
        f.bytes[120..124].copy_from_slice(&kind.to_le_bytes());
        if kind == 0x6474e551 {
            f.bytes[124..128].copy_from_slice(&6u32.to_le_bytes());
            assert!(validate_elf(&f.bytes).is_ok());
            f.bytes[124..128].copy_from_slice(&7u32.to_le_bytes());
        }
        f.writable().write_all(&f.bytes).unwrap();
        assert_eq!(f.prepare().unwrap_err(), ExecutionError::UnsupportedImage);
        TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
        TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    }
}

#[test]
fn load_mapping_validation_uses_the_host_page_size() {
    let b = image_bytes();
    for page_size in [4096, 65536] {
        assert!(validate_elf_for_page_size(&b, page_size).is_ok());
    }
    for invalid in [0, 1, 2048, 8191] {
        assert_eq!(
            validate_elf_for_page_size(&b, invalid),
            Err(ExecutionError::Unavailable)
        );
    }
    let mut incongruent = b.clone();
    incongruent[80..88].copy_from_slice(&0x401000u64.to_le_bytes());
    incongruent[24..32].copy_from_slice(&0x401078u64.to_le_bytes());
    assert!(validate_elf_for_page_size(&incongruent, 4096).is_ok());
    assert_eq!(
        validate_elf_for_page_size(&incongruent, 65536),
        Err(ExecutionError::UnsupportedImage)
    );

    let mut pages_overlap = b;
    pages_overlap.resize(12288, 0);
    pages_overlap[56..58].copy_from_slice(&2u16.to_le_bytes());
    pages_overlap[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
    let first = pages_overlap[64..120].to_vec();
    pages_overlap[120..176].copy_from_slice(&first);
    pages_overlap[128..136].copy_from_slice(&8192u64.to_le_bytes());
    pages_overlap[136..144].copy_from_slice(&0x402000u64.to_le_bytes());
    assert!(validate_elf_for_page_size(&pages_overlap, 4096).is_ok());
    // Both loads individually have congruent offsets on 64KiB hosts; their
    // rounded mappings alias the same page only on that larger-page host.
    assert_eq!(
        validate_elf_for_page_size(&pages_overlap, 65536),
        Err(ExecutionError::UnsupportedImage)
    );
}

#[test]
fn literal_protocol_limits_are_independent_of_implementation_constants() {
    assert!(checked_arguments(vec!["x".into(); 128]).is_ok());
    assert_eq!(
        checked_arguments(vec!["x".into(); 129]).unwrap_err(),
        ExecutionError::InvalidArguments
    );
    assert!(checked_arguments(vec!["x".repeat(32_767)]).is_ok()); // includes one NUL byte
    assert_eq!(
        checked_arguments(vec!["x".repeat(32_768)]).unwrap_err(),
        ExecutionError::InvalidArguments
    );
    let f = Fixture::new();
    let writer = f.writable();
    for (length, accepted) in [(67_108_864, true), (67_108_865, false)] {
        writer.set_len(length).unwrap();
        let metadata = std::fs::metadata(&f.path).unwrap();
        assert_eq!(
            source_ok(&metadata, unsafe { libc::geteuid() }),
            accepted,
            "length {length}"
        );
    }
}

#[test]
fn each_private_directory_permission_bit_is_rejected_independently() {
    for mode in [
        0o740, 0o720, 0o710, 0o704, 0o702, 0o701, 0o4700, 0o2700, 0o1700, 0o300, 0o500, 0o600,
    ] {
        let f = Fixture::new();
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(mode)).unwrap();
        let metadata = std::fs::metadata(f.root.path()).unwrap();
        assert!(
            !directory_ok(&metadata, true, unsafe { libc::geteuid() }),
            "root {mode:o}"
        );
        assert_eq!(
            f.prepare().unwrap_err(),
            ExecutionError::UnsafePath,
            "root {mode:o}"
        );
        std::fs::set_permissions(f.root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let child = f.root.path().join("child");
        std::fs::create_dir(&child).unwrap();
        std::fs::rename(&f.path, child.join("image")).unwrap();
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(
            !directory_ok(&std::fs::metadata(&child).unwrap(), true, unsafe {
                libc::geteuid()
            }),
            "child {mode:o}"
        );
        assert!(
            open_source(f.root.path(), &child.join("image")).is_err(),
            "child {mode:o}"
        );
        std::fs::set_permissions(&child, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(open_source(f.root.path(), &child.join("image")).is_ok());
    }
}

#[test]
fn literal_seal_set_and_descriptor_flags_are_required() {
    let f = Fixture::new();
    let prepared = f.prepare().unwrap();
    let seals = unsafe { libc::fcntl(prepared.file.as_raw_fd(), libc::F_GET_SEALS) };
    assert!(seals >= 0);
    // Linux UAPI values; intentionally independent from the production SEALS constant.
    assert_eq!(seals & 0x2f, 0x2f);
    assert_eq!(
        unsafe {
            libc::fcntl(
                prepared.file.as_raw_fd(),
                libc::F_ADD_SEALS,
                libc::F_SEAL_FUTURE_WRITE,
            )
        },
        -1
    );
    let source = f.source();
    let root = open_at(libc::AT_FDCWD, std::ffi::OsStr::new("/"), true).unwrap();
    for descriptor in [&prepared.file, &source, &root] {
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
    }
    for descriptor in [&source, &root] {
        let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_eq!(flags & libc::O_NONBLOCK, libc::O_NONBLOCK);
    }
}

#[test]
fn seal_readback_failure_closes_resources_before_capability() {
    let child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "adapters::execution::linux::tests::syscall_failure_child",
            "--ignored",
            "--nocapture",
        ])
        .env("VW_EXECUTION_SYSCALL_FAILURE", "readback")
        .output()
        .unwrap();
    assert!(
        child.status.success(),
        "{} {}",
        String::from_utf8_lossy(&child.stdout),
        String::from_utf8_lossy(&child.stderr)
    );
}

#[test]
fn execution_error_labels_are_stable_and_redacted() {
    for (error, display, debug) in [
        (
            ExecutionError::InvalidImage,
            "invalid executable image",
            "InvalidImage",
        ),
        (
            ExecutionError::UnsafePath,
            "unsafe executable location",
            "UnsafePath",
        ),
        (
            ExecutionError::UnsafeSource,
            "unsafe executable source",
            "UnsafeSource",
        ),
        (
            ExecutionError::DigestMismatch,
            "executable digest mismatch",
            "DigestMismatch",
        ),
        (
            ExecutionError::UnsupportedImage,
            "unsupported executable image",
            "UnsupportedImage",
        ),
        (
            ExecutionError::Unavailable,
            "executable preparation unavailable",
            "Unavailable",
        ),
        (
            ExecutionError::InvalidArguments,
            "invalid executable arguments",
            "InvalidArguments",
        ),
        (
            ExecutionError::ExecutionFailed,
            "descriptor execution failed",
            "ExecutionFailed",
        ),
    ] {
        assert_eq!(error.to_string(), display);
        assert_eq!(format!("{error:?}"), debug);
    }
}

#[test]
fn preparation_explicitly_requests_executable_memfd_and_no_controlling_terminal() {
    for contract in ["memfd_exec", "open_noctty"] {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "adapters::execution::linux::tests::required_syscall_flag_child",
                "--ignored",
                "--nocapture",
            ])
            .env("VW_EXECUTION_REQUIRED_FLAG", contract)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{contract}: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

#[test]
#[ignore = "isolated syscall-flag contract; parent harness only"]
fn required_syscall_flag_child() {
    let contract = std::env::var("VW_EXECUTION_REQUIRED_FLAG").unwrap();
    let f = Fixture::new();
    drop(f.prepare().unwrap());
    let (syscall, argument_offset, required_bit) = match contract.as_str() {
        // seccomp_data.args starts at byte16, with 8-byte syscall arguments.
        // MFD_EXEC is the Linux6.3 UAPI bit0x10, independent of production constants.
        "memfd_exec" => (libc::SYS_memfd_create, 24, 0x10),
        "open_noctty" => (libc::SYS_openat, 32, libc::O_NOCTTY as u32),
        _ => panic!("unknown contract"),
    };
    let instruction = |code, jt, jf, k| libc::sock_filter { code, jt, jf, k };
    let mut filter = [
        instruction(0x20, 0, 0, 0),
        instruction(0x15, 0, 3, syscall as u32),
        instruction(0x20, 0, 0, argument_offset),
        instruction(0x45, 1, 0, required_bit),
        instruction(0x06, 0, 0, 0x00050000 | libc::EPERM as u32),
        instruction(0x06, 0, 0, 0x7fff0000),
    ];
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    assert_eq!(
        unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) },
        0
    );
    assert_eq!(unsafe { libc::prctl(libc::PR_SET_SECCOMP, 2, &program) }, 0);
    drop(f.prepare().unwrap());
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    // Remove through unlink operations, which do not need openat. Recursive
    // tempfile cleanup otherwise opens directories without our flag contract.
    std::fs::remove_file(&f.path).unwrap();
    std::fs::remove_dir(f.root.path()).unwrap();
}

#[test]
fn sealing_precedes_both_digest_and_format_rejection() {
    for malformed in [false, true] {
        let mut f = Fixture::new();
        if malformed {
            f.bytes[16..18].copy_from_slice(&3u16.to_le_bytes());
            f.writable().write_all(&f.bytes).unwrap();
        }
        let digest = if malformed {
            f.digest()
        } else {
            "0".repeat(64)
        };
        let mut saw_sealed = false;
        let result = snapshot(f.source(), &digest, argv(), |boundary| {
            if matches!(boundary, Boundary::Sealed) {
                saw_sealed = true;
            }
        });
        assert_eq!(
            result.unwrap_err(),
            if malformed {
                ExecutionError::UnsupportedImage
            } else {
                ExecutionError::DigestMismatch
            }
        );
        assert!(
            saw_sealed,
            "immutable seals must precede final byte verification"
        );
        TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
        TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    }
}

#[test]
fn descriptor_execution_rejects_each_independently_missing_seal_before_syscall() {
    // Executable memfds acquire size/write seals implicitly with F_SEAL_EXEC.
    // Mode0400 isolates each required seal without allowing any image to execute,
    // even if a weakened preflight were to reach execveat.
    for missing in [0x01, 0x02, 0x04, 0x08, 0x20] {
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                c"incomplete-seals".as_ptr(),
                libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x10u32,
            )
        };
        assert!(fd >= 0);
        let file = unsafe { File::from_raw_fd(fd as RawFd) };
        assert_eq!(unsafe { libc::fchmod(file.as_raw_fd(), 0o400) }, 0);
        let requested = 0x2f & !missing;
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, requested) },
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) },
            requested,
            "the kernel must leave exactly the intended seal missing"
        );
        TEST_EXECUTION_ATTEMPTS.with(|calls| calls.set(0));
        TEST_LAUNCH_ATTEMPTS.with(|calls| calls.set(0));
        assert_eq!(
            execute_fd(file.as_raw_fd(), &argv()).unwrap_err(),
            ExecutionError::ExecutionFailed
        );
        TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 1));
        TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0, "missing seal {missing:#x}"));
    }
}

#[test]
fn descriptor_zero_is_valid_for_open_and_snapshot_subprocess() {
    for operation in ["open", "snapshot"] {
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "adapters::execution::linux::tests::descriptor_zero_child",
                "--ignored",
                "--nocapture",
            ])
            .stdin(std::process::Stdio::null())
            .env("VW_EXECUTION_ZERO_DESCRIPTOR", operation)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "{operation}: {} {}",
            String::from_utf8_lossy(&child.stdout),
            String::from_utf8_lossy(&child.stderr)
        );
    }
}

#[test]
#[ignore = "isolated descriptor-zero contract; parent harness only"]
fn descriptor_zero_child() {
    let operation = std::env::var("VW_EXECUTION_ZERO_DESCRIPTOR").unwrap();
    let f = Fixture::new();
    let directory = File::open(f.root.path()).unwrap();
    let source = f.source();
    let digest = f.digest();
    let arguments = argv();
    assert!(directory.as_raw_fd() > 0);
    assert!(source.as_raw_fd() > 0);
    // Only this isolated child closes its inherited, unowned stdin descriptor.
    // No live Rust File owns descriptor0; the next open/memfd must acquire it.
    assert_eq!(unsafe { libc::close(0) }, 0);
    match operation.as_str() {
        "open" => {
            let mut opened =
                open_at(directory.as_raw_fd(), std::ffi::OsStr::new("image"), false).unwrap();
            assert_eq!(opened.as_raw_fd(), 0);
            let mut bytes = Vec::new();
            opened.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, f.bytes);
        }
        "snapshot" => {
            let prepared = snapshot(source, &digest, arguments, |_| {}).unwrap();
            assert_eq!(prepared.file.as_raw_fd(), 0);
            assert_eq!(
                unsafe { libc::fcntl(prepared.file.as_raw_fd(), libc::F_GET_SEALS) } & 0x2f,
                0x2f
            );
        }
        _ => panic!("unknown descriptor-zero operation"),
    }
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
}

#[test]
fn snapshot_contract_rejects_same_byte_rewrite_with_changed_timestamp() {
    let f = Fixture::new();
    let mut writer = f.writable();
    let before = writer.metadata().unwrap();
    let result = snapshot(f.source(), &f.digest(), argv(), |boundary| {
        if matches!(boundary, Boundary::Opened) {
            writer.rewind().unwrap();
            writer.write_all(&f.bytes).unwrap();
            let times = [
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
                libc::timespec {
                    tv_sec: before.mtime().checked_add(1).unwrap(),
                    tv_nsec: before.mtime_nsec(),
                },
            ];
            assert_eq!(
                unsafe { libc::futimens(writer.as_raw_fd(), times.as_ptr()) },
                0
            );
            assert_ne!(writer.metadata().unwrap().mtime(), before.mtime());
        }
    });
    // This proves conservative change rejection, not independence of each
    // timestamp comparison: the final approved bytes themselves are unchanged.
    assert_eq!(std::fs::read(&f.path).unwrap(), f.bytes);
    assert_eq!(result.unwrap_err(), ExecutionError::UnsafeSource);
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
}

#[test]
fn snapshot_contract_accepts_literal_64_mib_pinned_image() {
    let mut f = Fixture::new();
    // The protocol limit is literal and independent of the production bound.
    // ELF permits this zero padding beyond its valid load segment.
    f.bytes.resize(67_108_864, 0);
    f.writable().set_len(67_108_864).unwrap();
    let digest = f.digest();
    let prepared = snapshot(f.source(), &digest, argv(), |_| {}).unwrap();
    assert_eq!(prepared.file.metadata().unwrap().len(), 67_108_864);
    assert_eq!(
        unsafe { libc::fcntl(prepared.file.as_raw_fd(), libc::F_GET_SEALS) } & 0x2f,
        0x2f
    );
    TEST_EXECUTION_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
    TEST_LAUNCH_ATTEMPTS.with(|calls| assert_eq!(calls.get(), 0));
}

#[test]
fn elf_boundaries_reject_every_truncated_header_without_panicking() {
    let b = image_bytes();
    for length in 0..=64 {
        assert_eq!(
            validate_elf(&b[..length]),
            Err(ExecutionError::UnsupportedImage),
            "header length {length}"
        );
    }
}

#[test]
fn elf_boundaries_program_table_count_and_extent() {
    for (count, accepted) in [(1024u16, true), (1025, false)] {
        let mut b = image_bytes();
        b.resize(64 + usize::from(count) * 56, 0);
        // Only the first header maps executable bytes; all added headers are PT_NULL.
        b[120..].fill(0);
        b[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
        b[56..58].copy_from_slice(&count.to_le_bytes());
        assert_eq!(validate_elf(&b).is_ok(), accepted, "program count {count}");
    }
    let mut at_end = image_bytes();
    let program = at_end[64..120].to_vec();
    at_end[4040..4096].copy_from_slice(&program);
    at_end[32..40].copy_from_slice(&4040u64.to_le_bytes());
    assert!(validate_elf(&at_end).is_ok());
    at_end[32..40].copy_from_slice(&4041u64.to_le_bytes());
    assert_eq!(validate_elf(&at_end), Err(ExecutionError::UnsupportedImage));

    let mut truncated_second = image_bytes();
    truncated_second.truncate(128);
    truncated_second[24..32].copy_from_slice(&0x400040u64.to_le_bytes());
    truncated_second[96..104].copy_from_slice(&128u64.to_le_bytes());
    assert!(validate_elf(&truncated_second).is_ok());
    truncated_second[56..58].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        validate_elf(&truncated_second),
        Err(ExecutionError::UnsupportedImage)
    );
    // At offset24 the ELF entry/header fields can also parse as a harmless
    // non-load header. A real load follows at80; only the forbidden overlap
    // with the ELF header makes this table location invalid.
    let mut overlapping_header = image_bytes();
    let load = overlapping_header[64..120].to_vec();
    overlapping_header[64..80].fill(0);
    overlapping_header[80..136].copy_from_slice(&load);
    overlapping_header[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
    overlapping_header[32..40].copy_from_slice(&24u64.to_le_bytes());
    overlapping_header[56..58].copy_from_slice(&2u16.to_le_bytes());
    assert_eq!(
        validate_elf(&overlapping_header),
        Err(ExecutionError::UnsupportedImage)
    );
}

fn elf_with_two_sections() -> Vec<u8> {
    let mut b = image_bytes();
    b[40..48].copy_from_slice(&512u64.to_le_bytes());
    b[58..60].copy_from_slice(&64u16.to_le_bytes());
    b[60..62].copy_from_slice(&2u16.to_le_bytes());
    // Section0 is SHT_NULL. Section1 is nonempty SHT_PROGBITS with an
    // eight-byte entry size, giving the second iteration meaningful content.
    b[580..584].copy_from_slice(&1u32.to_le_bytes());
    b[600..608].copy_from_slice(&1024u64.to_le_bytes());
    b[608..616].copy_from_slice(&16u64.to_le_bytes());
    b[624..632].copy_from_slice(&8u64.to_le_bytes());
    b[632..640].copy_from_slice(&8u64.to_le_bytes());
    b
}

#[test]
fn elf_boundaries_section_table_metadata_and_extent() {
    let b = elf_with_two_sections();
    assert!(validate_elf(&b).is_ok());
    for (offset, value) in [(58, 63u16), (60, 0), (62, 2)] {
        let mut malformed = b.clone();
        malformed[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            validate_elf(&malformed),
            Err(ExecutionError::UnsupportedImage),
            "section header field {offset}"
        );
    }
    let mut missing_table = image_bytes();
    missing_table[62..64].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        validate_elf(&missing_table),
        Err(ExecutionError::UnsupportedImage)
    );

    let mut at_end = b.clone();
    at_end[3968..4096].copy_from_slice(&b[512..640]);
    at_end[40..48].copy_from_slice(&3968u64.to_le_bytes());
    assert!(validate_elf(&at_end).is_ok());
    for offset in [3969u64, 4032, u64::MAX - 63] {
        let mut beyond_end = at_end.clone();
        beyond_end[40..48].copy_from_slice(&offset.to_le_bytes());
        assert_eq!(
            validate_elf(&beyond_end),
            Err(ExecutionError::UnsupportedImage)
        );
    }
    // A section table may begin immediately after the ELF header when the
    // program table lives elsewhere; offset64 is an accepted exact boundary.
    let mut at_start = b.clone();
    at_start[768..824].copy_from_slice(&b[64..120]);
    at_start[32..40].copy_from_slice(&768u64.to_le_bytes());
    at_start[64..192].copy_from_slice(&b[512..640]);
    at_start[40..48].copy_from_slice(&64u64.to_le_bytes());
    at_start[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
    assert!(validate_elf(&at_start).is_ok());
    // Offset40 overlaps the ELF header but otherwise describes one empty
    // SHT_NULL section. Keep the executable program table separately at768.
    let mut overlapping_header = at_start;
    overlapping_header[64..128].fill(0);
    overlapping_header[40..48].copy_from_slice(&40u64.to_le_bytes());
    overlapping_header[60..62].copy_from_slice(&1u16.to_le_bytes());
    assert_eq!(
        validate_elf(&overlapping_header),
        Err(ExecutionError::UnsupportedImage)
    );
}

#[test]
fn elf_boundaries_second_section_fields_and_nobits_semantics() {
    let b = elf_with_two_sections();
    assert!(validate_elf(&b).is_ok());
    for (offset, value) in [
        (600, 4081u64), // sixteen bytes would extend one byte beyond EOF
        (600, u64::MAX),
        (608, u64::MAX),
        (624, 3), // invalid alignment
        (632, 3), // entry size does not divide the sixteen-byte section
    ] {
        let mut malformed = b.clone();
        malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        assert_eq!(
            validate_elf(&malformed),
            Err(ExecutionError::UnsupportedImage),
            "section field {offset} = {value}"
        );
    }
    let mut link = b.clone();
    link[616..620].copy_from_slice(&1u32.to_le_bytes());
    assert!(validate_elf(&link).is_ok());
    link[616..620].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(validate_elf(&link), Err(ExecutionError::UnsupportedImage));
    let mut at_end = b.clone();
    at_end[600..608].copy_from_slice(&4080u64.to_le_bytes());
    assert!(validate_elf(&at_end).is_ok());
    for alignment in [0u64, 1, 16] {
        let mut aligned = b.clone();
        aligned[624..632].copy_from_slice(&alignment.to_le_bytes());
        assert!(validate_elf(&aligned).is_ok());
    }
    let mut nobits = b;
    nobits[580..584].copy_from_slice(&8u32.to_le_bytes());
    nobits[600..608].copy_from_slice(&8192u64.to_le_bytes());
    assert!(validate_elf(&nobits).is_ok());
    nobits[580..584].copy_from_slice(&1u32.to_le_bytes());
    assert_eq!(validate_elf(&nobits), Err(ExecutionError::UnsupportedImage));
}

#[test]
fn elf_userspace_profiles_have_independent_literal_bounds_and_rounding() {
    // Literal architecture limits are independent of the production shifts.
    // Exercise AArch64 parsing arithmetic on x86_64 too, without accepting a
    // non-native executable in validate_elf or changing execution selection.
    for (machine, page, limit) in [
        (62, 4096, 0x7fff_ffff_f000u64),
        (62, 16384, 0x7fff_ffff_c000),
        (62, 65536, 0x7fff_ffff_0000),
        (183, 4096, 0x0010_0000_0000),
        (183, 16384, 0x0010_0000_0000),
        (183, 65536, 0x0010_0000_0000),
    ] {
        for end in [limit - page + 1, limit - 1, limit] {
            assert_eq!(checked_userspace_mapping_end(machine, page, end), Ok(limit));
        }
        assert_eq!(
            checked_userspace_mapping_end(machine, page, limit - page),
            Ok(limit - page)
        );
        for end in [limit + 1, limit + page, 0x8000_0000_0000_0000, u64::MAX] {
            assert_eq!(
                checked_userspace_mapping_end(machine, page, end),
                Err(ExecutionError::UnsupportedImage),
                "machine {machine}, page {page}, end {end:#x}"
            );
        }
    }
    assert_eq!(
        checked_userspace_mapping_end(0, 4096, 4096),
        Err(ExecutionError::UnsupportedImage)
    );
    assert_eq!(
        checked_userspace_mapping_end(62, 0x1_0000_0000_0000, 4096),
        Err(ExecutionError::Unavailable)
    );
}

#[test]
fn elf_userspace_high_load_is_rejected_with_matching_hash_and_valid_entry() {
    // Keep the entry in the original valid executable load. A separate read-only
    // load isolates address rejection from executable-entry validation.
    for address in [
        0x8000_0000_0000_0000u64,
        if cfg!(target_arch = "aarch64") {
            0x10_0000_0000
        } else {
            0x8000_0000_0000
        },
    ] {
        let mut f = Fixture::new();
        f.bytes[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
        f.bytes[56..58].copy_from_slice(&2u16.to_le_bytes());
        f.bytes[120..176].fill(0);
        f.bytes[120..124].copy_from_slice(&1u32.to_le_bytes());
        f.bytes[124..128].copy_from_slice(&4u32.to_le_bytes());
        f.bytes[136..144].copy_from_slice(&address.to_le_bytes());
        f.bytes[152..160].copy_from_slice(&4096u64.to_le_bytes());
        f.bytes[160..168].copy_from_slice(&4096u64.to_le_bytes());
        f.bytes[168..176].copy_from_slice(&4096u64.to_le_bytes());
        f.writable().write_all(&f.bytes).unwrap();
        assert_eq!(f.prepare().unwrap_err(), ExecutionError::UnsupportedImage);
        // Positive control differs only in the second load's address.
        f.bytes[136..144].copy_from_slice(&0x420000u64.to_le_bytes());
        f.writable().write_all(&f.bytes).unwrap();
        assert!(f.prepare().is_ok());
    }
}

#[test]
fn elf_userspace_end_and_entry_boundaries_have_matching_hashes() {
    let page = u64::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) }).unwrap();
    let limit = if cfg!(target_arch = "aarch64") {
        0x10_0000_0000u64
    } else {
        0x8000_0000_0000u64 - page
    };
    let address = limit - page;
    for (memory_size, entry_offset, accepted) in [
        (page - 1, 120, true), // Rounded mapping reaches the allowed end.
        (page, 120, true),
        (page + 1, 120, false), // One BSS byte crosses the allowed end.
        (page, 0, true),
        (page, 4095, true),
        (page, page, false), // Entry at the exclusive userspace end.
    ] {
        let mut f = Fixture::new();
        f.bytes[24..32].copy_from_slice(&(address + entry_offset).to_le_bytes());
        f.bytes[80..88].copy_from_slice(&address.to_le_bytes());
        // The 4 KiB fixture can have a larger native page, but filesz <= memsz
        // remains independent of the range guard for the just-below-end case.
        if memory_size < 4096 {
            f.bytes[96..104].copy_from_slice(&memory_size.to_le_bytes());
        }
        f.bytes[104..112].copy_from_slice(&memory_size.to_le_bytes());
        f.writable().write_all(&f.bytes).unwrap();
        let result = f.prepare();
        assert_eq!(
            result.is_ok(),
            accepted,
            "memory {memory_size}, entry {entry_offset}"
        );
        if !accepted {
            assert_eq!(result.unwrap_err(), ExecutionError::UnsupportedImage);
        }
    }
}

#[test]
fn elf_userspace_boundaries_account_for_supported_page_rounding() {
    for page in [4096u64, 16384, 65536] {
        let limit = if cfg!(target_arch = "aarch64") {
            0x10_0000_0000u64
        } else {
            0x8000_0000_0000u64 - page
        };
        let address = limit - page;
        let mut b = image_bytes();
        b[24..32].copy_from_slice(&(address + 120).to_le_bytes());
        b[80..88].copy_from_slice(&address.to_le_bytes());
        for (size, accepted) in [(page, true), (page + 1, false)] {
            b[104..112].copy_from_slice(&size.to_le_bytes());
            assert_eq!(validate_elf_for_page_size(&b, page).is_ok(), accepted);
        }
    }
}

#[test]
fn elf_boundaries_entry_and_independent_second_load() {
    let b = image_bytes();
    for (entry, accepted) in [
        (0x3fffffu64, false),
        (0x400000, true),
        (0x400fff, true),
        (0x401000, false),
    ] {
        let mut candidate = b.clone();
        candidate[24..32].copy_from_slice(&entry.to_le_bytes());
        assert_eq!(
            validate_elf(&candidate).is_ok(),
            accepted,
            "entry {entry:#x}"
        );
    }
    let mut two = b;
    two.resize(131_072, 0);
    two[24..32].copy_from_slice(&0x400200u64.to_le_bytes());
    two[56..58].copy_from_slice(&2u16.to_le_bytes());
    two[120..176].fill(0);
    two[120..124].copy_from_slice(&1u32.to_le_bytes());
    two[124..128].copy_from_slice(&4u32.to_le_bytes());
    two[128..136].copy_from_slice(&65_536u64.to_le_bytes());
    two[136..144].copy_from_slice(&0x420000u64.to_le_bytes());
    two[152..160].copy_from_slice(&64u64.to_le_bytes());
    two[160..168].copy_from_slice(&64u64.to_le_bytes());
    two[168..176].copy_from_slice(&65_536u64.to_le_bytes());
    assert!(validate_elf(&two).is_ok());
    for (offset, value) in [(152, 65u64), (168, 3), (168, 131_072)] {
        let mut malformed = two.clone();
        malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
        if offset == 168 && value == 3 {
            // Congruent modulo3 and both supported page sizes: only the
            // non-power-of-two alignment is invalid in this case.
            malformed[136..144].copy_from_slice(&0x430000u64.to_le_bytes());
        }
        assert_eq!(
            validate_elf(&malformed),
            Err(ExecutionError::UnsupportedImage)
        );
    }
    for flags in [3u32, 8] {
        let mut malformed = two.clone();
        malformed[124..128].copy_from_slice(&flags.to_le_bytes());
        assert_eq!(
            validate_elf(&malformed),
            Err(ExecutionError::UnsupportedImage)
        );
    }
    let mut empty = two.clone();
    empty[152..168].fill(0);
    assert_eq!(validate_elf(&empty), Err(ExecutionError::UnsupportedImage));
    let mut incongruent = two.clone();
    incongruent[136..144].copy_from_slice(&0x420001u64.to_le_bytes());
    incongruent[168..176].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        validate_elf(&incongruent),
        Err(ExecutionError::UnsupportedImage)
    );
    for size in [65_536u64, 65_537] {
        let mut end = two.clone();
        end[152..160].copy_from_slice(&size.to_le_bytes());
        end[160..168].copy_from_slice(&size.to_le_bytes());
        assert_eq!(validate_elf(&end).is_ok(), size == 65_536);
    }
    for alignment in [0u64, 1, 2] {
        let mut aligned = two.clone();
        aligned[168..176].copy_from_slice(&alignment.to_le_bytes());
        assert!(validate_elf(&aligned).is_ok());
    }
    for page_size in [4096, 65536] {
        let mut adjacent = two.clone();
        adjacent[104..112].copy_from_slice(&65_536u64.to_le_bytes());
        adjacent[136..144].copy_from_slice(&0x410000u64.to_le_bytes());
        assert!(validate_elf_for_page_size(&adjacent, page_size).is_ok());
        // One extra BSS byte makes the rounded first mapping overlap the
        // second. The file-backed entry and both segment congruences remain valid.
        adjacent[104..112].copy_from_slice(&65_537u64.to_le_bytes());
        assert_eq!(
            validate_elf_for_page_size(&adjacent, page_size),
            Err(ExecutionError::UnsupportedImage)
        );
    }
    let mut descending = two.clone();
    descending[136..144].copy_from_slice(&0x300000u64.to_le_bytes());
    assert_eq!(
        validate_elf(&descending),
        Err(ExecutionError::UnsupportedImage)
    );
    for size in [65_535u64, 65_536] {
        let mut overflow = two.clone();
        overflow[136..144].copy_from_slice(&0xffff_ffff_ffff_0000u64.to_le_bytes());
        overflow[160..168].copy_from_slice(&size.to_le_bytes());
        assert_eq!(
            validate_elf(&overflow),
            Err(ExecutionError::UnsupportedImage)
        );
    }
}
