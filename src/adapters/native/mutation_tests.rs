//! Boundary and binding tests added by the #49 native targeted mutation campaign.
//! Each test names the generated mutants it kills in
//! `docs/implementation/issue-49-native-mutations.md`.
use super::*;

#[test]
fn native_argument_vector_limits_are_inclusive_and_count_terminators() {
    let many = |count: usize| (0..count).map(|_| "a".to_string()).collect::<Vec<_>>();
    assert_eq!(arguments(many(128)).unwrap().len(), 128);
    assert!(arguments(many(129)).is_err());
    assert!(arguments(Vec::new()).is_err());
    assert!(arguments(vec![String::new()]).is_err());
    assert!(arguments(vec!["a".into(), "b\0c".into()]).is_err());
    // Each argument costs its bytes plus one NUL terminator; 32768 bytes is the cap.
    let sized = |total: usize| vec!["a".repeat(total - 2 - 1), "b".into()];
    let exact = arguments(sized(32768)).unwrap();
    assert_eq!(
        exact.iter().map(|s| s.as_bytes().len() + 1).sum::<usize>(),
        32768
    );
    assert!(arguments(sized(32769)).is_err());
    // Rejected only because of the terminators: 32767 payload bytes plus two NULs.
    assert!(arguments(vec!["a".repeat(32766), "b".into()]).is_err());
    // An empty non-initial argument is legal and still costs a terminator.
    assert_eq!(arguments(vec!["a".into(), String::new()]).unwrap().len(), 2);
}

fn reviewed_ssh() -> crate::access::policy::ImageRegistration {
    super::tests::image_registration()
}
fn image(reg: &crate::access::policy::ImageRegistration) -> ExecutionImage<'_> {
    ExecutionImage {
        root: Path::new(&reg.execution_root),
        path: Path::new(&reg.path),
        sha256: &reg.sha256,
        profile: reg.profile,
    }
}

#[test]
fn native_image_registration_verifier_rejects_what_preparation_rejects() {
    let reg = reviewed_ssh();
    assert!(NativeExecutablePreparer.verify(image(&reg)).is_ok());
    let mut wrong = image(&reg);
    wrong.sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    assert_eq!(
        NativeExecutablePreparer.verify(wrong).err(),
        Some(ExecutionError::DigestMismatch)
    );
}

#[test]
fn native_preparer_rejects_a_reviewed_image_outside_its_execution_root() {
    let reg = reviewed_ssh();
    let mut outside = image(&reg);
    outside.root = Path::new("/usr/lib");
    assert_eq!(
        NativeExecutablePreparer
            .prepare(outside, vec!["ssh".into()])
            .err(),
        Some(ExecutionError::UnsupportedImage)
    );
    assert!(
        NativeExecutablePreparer
            .prepare(image(&reg), vec!["ssh".into()])
            .is_ok()
    );
}

/// Installs synthetic identities for this thread and removes them on drop.
struct Identities(tempfile::TempDir);
impl Identities {
    fn install(provider_uid: u32) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let runtime = root.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        std::fs::set_permissions(&runtime, std::fs::Permissions::from_mode(0o700)).unwrap();
        identity::TEST_IDENTITIES.with(|v| {
            *v.borrow_mut() = Some(identity::Identities {
                provider_uid,
                provider_uuid: "synthetic-provider".into(),
                operator_uid: 42001,
                operator_uuid: "synthetic-operator".into(),
                human_gid: 20,
                agent_gid: 1,
                human_socket_dir: root.path().join("human"),
                ssh_runtime_dir: runtime,
            })
        });
        Self(root)
    }
    fn state(&self) -> PathBuf {
        let state = self.0.path().join("state");
        if !state.exists() {
            use std::os::unix::fs::PermissionsExt;
            std::fs::create_dir(&state).unwrap();
            std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        state
    }
    fn runtime(&self) -> PathBuf {
        self.0.path().join("runtime")
    }
}
impl Drop for Identities {
    fn drop(&mut self) {
        identity::TEST_IDENTITIES.with(|v| v.borrow_mut().take());
    }
}

#[test]
fn native_installed_supervisor_requires_provider_account_private_runtime_and_no_cores() {
    use std::os::unix::fs::PermissionsExt;
    let euid = unsafe { libc::geteuid() };
    {
        let ids = Identities::install(euid.wrapping_add(1));
        assert_eq!(
            NativeProcessSupervisor::installed(&ids.state()).err(),
            Some(ExecutionError::Unavailable)
        );
        assert!(!ids.state().join("ssh").exists());
    }
    {
        let ids = Identities::install(euid);
        std::fs::set_permissions(ids.runtime(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            NativeProcessSupervisor::installed(&ids.state()).err(),
            Some(ExecutionError::UnsafePath)
        );
    }
    let ids = Identities::install(euid);
    let supervisor = NativeProcessSupervisor::installed(&ids.state()).unwrap();
    assert_eq!(
        supervisor.ssh_material_root(),
        Some(ids.state().join("ssh").as_path())
    );
    assert!(ids.state().join("ssh/requests").is_dir());
    let mut limit = libc::rlimit {
        rlim_cur: 1,
        rlim_max: 1,
    };
    assert_eq!(unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) }, 0);
    assert_eq!((limit.rlim_cur, limit.rlim_max), (0, 0));
}

#[test]
fn native_recovery_removes_unused_request_material_and_preserves_in_use() {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let ids = Identities::install(unsafe { libc::geteuid() });
    let material = super::super::ssh_material::initialize(&ids.state()).unwrap();
    let request = |name: &str, markers: &[&str]| {
        let dir = material.join("requests").join(name);
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        for marker in markers {
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(dir.join(marker))
                .unwrap();
        }
        dir
    };
    let unused = request("req-0123456789abcdef0123456789abcdef", &["pending"]);
    let used = request(
        "req-fedcba9876543210fedcba9876543210",
        &["pending", "in_use"],
    );
    let supervisor = NativeProcessSupervisor {
        material: material.clone(),
    };
    assert_eq!(supervisor.recover(), Ok(()));
    assert!(
        !unused.exists(),
        "unused request material survived recovery"
    );
    assert!(used.join("in_use").exists());
}

#[test]
fn native_stopped_recovery_requires_the_provider_account_before_any_cleanup() {
    let ids = Identities::install(unsafe { libc::geteuid() }.wrapping_add(1));
    let mut cleared = false;
    let result = NativeProcessSupervisor::recover_stopped(&ids.state(), || {
        cleared = true;
        Ok(())
    });
    assert_eq!(result, Err(ExecutionError::Unavailable));
    assert!(!cleared);
    assert!(!ids.state().join("ssh").exists());
}

/// Independent oracle: Directory Services' UUID for `uid`, lower-case hex without dashes.
fn directory_uuid(uid: u32) -> String {
    let output = std::process::Command::new("/usr/bin/dsmemberutil")
        .args(["getuuid", "-u", &uid.to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .trim()
        .replace('-', "")
        .to_ascii_lowercase()
}

#[test]
fn native_account_uuid_matches_directory_services_and_unknown_accounts_fail() {
    let euid = unsafe { libc::geteuid() };
    assert_eq!(identity::uuid(euid).unwrap(), directory_uuid(euid));
    assert_eq!(identity::uuid(1).unwrap(), directory_uuid(1));
    assert_ne!(identity::uuid(euid).unwrap(), identity::uuid(1).unwrap());
    // Directory Services synthesizes UUIDs for unknown IDs; the account lookup must not.
    assert_eq!(
        identity::uuid(4_242_424).err(),
        Some(ExecutionError::Unavailable)
    );
    identity::TEST_ACCOUNT_UUID.with(|v| *v.borrow_mut() = Some((euid, None)));
    assert_eq!(
        identity::uuid(euid).err(),
        Some(ExecutionError::Unavailable)
    );
    assert_eq!(identity::uuid(1).unwrap(), directory_uuid(1));
    identity::TEST_ACCOUNT_UUID.with(|v| v.borrow_mut().take());
}

/// Points `identity::load` at a synthetic file for this thread.
struct IdentityFile(tempfile::TempDir);
impl IdentityFile {
    fn new() -> Self {
        Self(tempfile::tempdir().unwrap())
    }
    fn load(&self, bytes: &[u8]) -> Result<identity::Identities, ExecutionError> {
        use std::os::unix::fs::OpenOptionsExt;
        let path = self.0.path().join("native-identities.json");
        let _absent = std::fs::remove_file(&path);
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o644)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, bytes).unwrap();
        drop(file);
        identity::TEST_IDENTITY_FILE.with(|v| *v.borrow_mut() = Some(path));
        let result = identity::load();
        identity::TEST_IDENTITY_FILE.with(|v| v.borrow_mut().take());
        result
    }
}
type Edit = Box<dyn FnOnce(&mut serde_json::Value)>;
fn identity_json(edit: impl FnOnce(&mut serde_json::Value)) -> Vec<u8> {
    let euid = unsafe { libc::geteuid() };
    let mut value = serde_json::json!({
        "provider_uid": euid,
        "provider_uuid": directory_uuid(euid),
        "operator_uid": 1,
        "operator_uuid": directory_uuid(1),
        "human_gid": 20,
        "agent_gid": 12,
        "human_socket_dir": "/Library/VaultwardenAccess/human",
        "ssh_runtime_dir": "/Library/VaultwardenAccess/ssh",
    });
    edit(&mut value);
    serde_json::to_vec(&value).unwrap()
}

#[test]
fn native_installed_identities_reject_root_shared_or_unbound_accounts_and_relative_paths() {
    let file = IdentityFile::new();
    let valid = file.load(&identity_json(|_| {})).unwrap();
    assert_eq!(valid.operator_uid, 1);
    let cases: Vec<(&str, Edit)> = vec![
        (
            "root provider",
            Box::new(|v| {
                v["provider_uid"] = 0.into();
                v["provider_uuid"] = directory_uuid(0).into();
            }),
        ),
        (
            "root operator",
            Box::new(|v| {
                v["operator_uid"] = 0.into();
                v["operator_uuid"] = directory_uuid(0).into();
            }),
        ),
        (
            "shared account",
            Box::new(|v| {
                v["operator_uid"] = v["provider_uid"].clone();
                v["operator_uuid"] = v["provider_uuid"].clone();
            }),
        ),
        ("wheel human group", Box::new(|v| v["human_gid"] = 0.into())),
        ("wheel agent group", Box::new(|v| v["agent_gid"] = 0.into())),
        ("shared group", Box::new(|v| v["agent_gid"] = 20.into())),
        (
            "provider uuid",
            Box::new(|v| v["provider_uuid"] = directory_uuid(1).into()),
        ),
        (
            "operator uuid",
            Box::new(|v| v["operator_uuid"] = v["provider_uuid"].clone()),
        ),
        (
            "relative human socket",
            Box::new(|v| v["human_socket_dir"] = "human".into()),
        ),
        (
            "relative ssh runtime",
            Box::new(|v| v["ssh_runtime_dir"] = "ssh".into()),
        ),
        ("unknown field", Box::new(|v| v["extra"] = 1.into())),
    ];
    for (label, edit) in cases {
        assert_eq!(
            file.load(&identity_json(edit)).err(),
            Some(ExecutionError::UnsafePath),
            "{label}"
        );
    }
}

#[test]
fn native_installed_identities_are_bounded_single_link_files() {
    let file = IdentityFile::new();
    let pad = |total: usize| {
        let mut bytes = identity_json(|_| {});
        bytes.resize(total, b' ');
        bytes
    };
    assert!(file.load(&pad(4096)).is_ok());
    assert_eq!(
        file.load(&pad(4097)).err(),
        Some(ExecutionError::UnsafePath)
    );
    let path = file.0.path().join("native-identities.json");
    let link = file.0.path().join("second-link");
    assert!(file.load(&identity_json(|_| {})).is_ok());
    std::fs::hard_link(&path, &link).unwrap();
    identity::TEST_IDENTITY_FILE.with(|v| *v.borrow_mut() = Some(path.clone()));
    let linked = identity::load();
    identity::TEST_IDENTITY_FILE.with(|v| v.borrow_mut().take());
    assert_eq!(linked.err(), Some(ExecutionError::UnsafePath));
    identity::TEST_IDENTITY_FILE.with(|v| *v.borrow_mut() = Some(file.0.path().to_owned()));
    let directory = identity::load();
    identity::TEST_IDENTITY_FILE.with(|v| v.borrow_mut().take());
    assert_eq!(directory.err(), Some(ExecutionError::UnsafePath));
}

#[test]
fn native_no_writer_open_rejects_relative_dot_and_symlink_components() {
    assert!(platform::open_no_writers(Path::new("/usr/bin/ssh"), true).is_ok());
    for path in ["usr/bin/ssh", "/usr/./bin/ssh", "/usr/bin/../bin/ssh"] {
        assert_eq!(
            platform::open_no_writers(Path::new(path), true).err(),
            Some(ExecutionError::UnsafePath),
            "{path}"
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let link = dir.path().join("ssh");
    std::os::unix::fs::symlink("/usr/bin/ssh", &link).unwrap();
    assert!(platform::open_no_writers(dir.path(), false).is_ok());
    assert_eq!(
        platform::open_no_writers(&link, false).err(),
        Some(ExecutionError::UnsafePath)
    );
}

#[test]
fn native_no_writer_open_enforces_ownership_and_write_modes_per_component() {
    use std::os::unix::fs::PermissionsExt;
    // Root-owned but world-writable (sticky /tmp) never qualifies.
    assert_eq!(
        platform::open_no_writers(Path::new("/private/tmp"), true).err(),
        Some(ExecutionError::UnsafePath)
    );
    let dir = tempfile::tempdir().unwrap();
    // Own components need no identity lookup and are refused where root is required.
    identity::TEST_IDENTITIES.with(|v| v.borrow_mut().take());
    assert!(platform::open_no_writers(dir.path(), false).is_ok());
    assert_eq!(
        platform::open_no_writers(dir.path(), true).err(),
        Some(ExecutionError::UnsafePath)
    );
    let shared = dir.path().join("group-writable");
    std::fs::create_dir(&shared).unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o770)).unwrap();
    assert_eq!(
        platform::open_no_writers(&shared, false).err(),
        Some(ExecutionError::UnsafePath)
    );
    // A component owned by the enrolled provider account (here: daemon) is trusted
    // only when not root-required; any other non-root owner is refused.
    let provider_owned = Path::new("/private/var/at");
    let owner = std::fs::metadata(provider_owned).unwrap();
    assert_eq!(std::os::unix::fs::MetadataExt::uid(&owner), 1);
    let _ids = Identities::install(1);
    assert!(platform::open_no_writers(provider_owned, false).is_ok());
    assert!(platform::open_no_writers(provider_owned, true).is_err());
    drop(_ids);
    let _ids = Identities::install(42001);
    assert_eq!(
        platform::open_no_writers(provider_owned, false).err(),
        Some(ExecutionError::UnsafePath)
    );
}

#[test]
fn native_acl_check_reads_every_entry_and_allows_only_deny_entries() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("acl");
    std::fs::write(&path, b"x").unwrap();
    let chmod = |args: &[&str]| {
        assert!(
            std::process::Command::new("/bin/chmod")
                .args(args)
                .arg(&path)
                .status()
                .unwrap()
                .success()
        );
    };
    let check = || platform::no_acl(&std::fs::File::open(&path).unwrap());
    assert_eq!(check(), Ok(()));
    chmod(&["+a", "everyone deny delete"]);
    chmod(&["+a#", "1", "everyone deny write"]);
    assert_eq!(check(), Ok(()), "deny-only entries are permitted");
    chmod(&["+a#", "2", "everyone allow read"]);
    let mixed = check();
    // Remove the ACL (including "deny delete") so the fixture directory can be deleted.
    chmod(&["-N"]);
    assert_eq!(mixed, Err(ExecutionError::UnsafePath));
}

/// Records the supervisor's calls; `steal` reaps the new direct child itself on the
/// first liveness check, so the supervisor's own waitpid observes ECHILD.
struct Recording {
    before: Vec<libc::pid_t>,
    steal: bool,
    live_calls: std::cell::Cell<usize>,
    stolen: std::cell::Cell<bool>,
    started: std::cell::Cell<bool>,
}
fn children() -> Vec<libc::pid_t> {
    let mut pids: Vec<libc::pid_t> = vec![0; 4096];
    // <sys/proc_info.h> PROC_PPID_ONLY: direct children; the result is in bytes.
    let bytes = unsafe {
        libc::proc_listpids(
            6,
            libc::getpid() as u32,
            pids.as_mut_ptr().cast(),
            (pids.len() * std::mem::size_of::<libc::pid_t>()) as libc::c_int,
        )
    };
    assert!(bytes >= 0);
    pids.truncate(bytes as usize / std::mem::size_of::<libc::pid_t>());
    pids.retain(|pid| *pid > 0);
    pids
}
impl Recording {
    fn new(steal: bool) -> Self {
        Self {
            before: children(),
            steal,
            live_calls: 0.into(),
            stolen: false.into(),
            started: false.into(),
        }
    }
}
impl ExecutionControl for Recording {
    fn live(&self) -> bool {
        self.live_calls.set(self.live_calls.get() + 1);
        if self.steal && !self.stolen.get() {
            let new: Vec<_> = children()
                .into_iter()
                .filter(|pid| !self.before.contains(pid))
                .collect();
            assert_eq!(new.len(), 1, "exactly one new direct child");
            let mut status = 0;
            assert_eq!(unsafe { libc::waitpid(new[0], &mut status, 0) }, new[0]);
            self.stolen.set(true);
            return true;
        }
        // Bound a mutant that would keep polling after losing its child.
        !self.stolen.get()
    }
    fn remaining(&self) -> Duration {
        Duration::from_secs(5)
    }
    fn release(
        &self,
        action: &mut dyn FnMut() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        action()
    }
    fn started(&self) -> Result<(), ExecutionError> {
        self.started.set(true);
        Ok(())
    }
}
fn supervise(argv: &[&str], control: &Recording) -> Supervision {
    let reg = reviewed_ssh();
    let prepared = NativeExecutablePreparer
        .prepare(image(&reg), argv.iter().map(|s| s.to_string()).collect())
        .unwrap();
    let root = tempfile::tempdir().unwrap();
    NativeProcessSupervisor {
        material: root.path().into(),
    }
    .supervise_controlled(
        prepared,
        ChildEnvironment::from_mappings([]).unwrap(),
        control,
    )
}

#[test]
fn native_supervision_maps_natural_exit_status_and_reports_reaped_cleanup() {
    for (argv, outcome) in [
        (&["ssh", "-V"][..], ExecutionOutcome::ExitedZero),
        (&["ssh", "-Z"][..], ExecutionOutcome::ExitedNonZero),
    ] {
        let control = Recording::new(false);
        let result = supervise(argv, &control);
        assert_eq!(result.outcome, Ok(outcome), "{argv:?}");
        assert_eq!(result.cleanup, CleanupEvidence::Reaped, "{argv:?}");
        assert!(!result.helper_reaped);
        assert!(control.started.get());
        assert!(control.live_calls.get() >= 1);
        // The supervisor, not a later caller, reaped the child.
        assert!(
            children().iter().all(|pid| control.before.contains(pid)),
            "{argv:?}"
        );
    }
    // A consumer that is still running at the first polls must be waited for, not
    // reported lost: the fixture server closes the connection after 300 ms.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port().to_string();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        std::thread::sleep(Duration::from_millis(300));
        drop(stream);
    });
    let control = Recording::new(false);
    let result = supervise(
        &[
            "ssh",
            "-F",
            "/dev/null",
            "-oBatchMode=yes",
            "-oConnectTimeout=5",
            "-p",
            &port,
            "127.0.0.1",
        ],
        &control,
    );
    server.join().unwrap();
    assert_eq!(result.outcome, Ok(ExecutionOutcome::ExitedNonZero));
    assert_eq!(result.cleanup, CleanupEvidence::Reaped);
    assert!(
        control.live_calls.get() > 5,
        "the supervisor polled while it ran"
    );
}

#[test]
fn native_supervision_treats_a_child_reaped_elsewhere_as_lost_observation_at_once() {
    let control = Recording::new(true);
    let result = supervise(&["ssh", "-V"], &control);
    assert!(control.stolen.get());
    assert_eq!(result.outcome, Err(ExecutionError::ObservationLost));
    // The PID is no longer provably reaped by the supervisor: ownership is detached.
    assert_eq!(result.cleanup, CleanupEvidence::Detached);
    assert_eq!(
        control.live_calls.get(),
        1,
        "waitpid failure must end supervision without polling again"
    );
}

#[test]
fn native_execution_worker_runs_dispatched_requests_and_join_drains_the_queue() {
    let mut f = super::tests::Fixture::new();
    let id = f.request();
    f.approve(&id);
    let resolved = f.resolved.clone();
    let app = Arc::new(f.take_app());
    let material = tempfile::tempdir().unwrap();
    let worker = ExecutionWorker::start(
        app.clone(),
        Arc::new(NativeProcessSupervisor {
            material: material.path().into(),
        }),
    )
    .unwrap();
    assert!(!worker.is_finished());
    worker.dispatcher().dispatch(&id).unwrap();
    worker.join().unwrap();
    assert_eq!(resolved.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert!(matches!(
        app.direct_status(app.human_owner(), &id).unwrap(),
        crate::access::direct_request::DirectStatus::Completed { .. }
    ));
}
