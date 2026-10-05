//! External observers for real manager cleanup. Opt-in skips are missing evidence.
#![cfg(target_os = "linux")]
use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{Duration, Instant},
};
fn bounded(program: &str, args: &[&str]) -> std::io::Result<Output> {
    Command::new("timeout")
        .args(["--signal=KILL", "12s", program])
        .args(args)
        .output()
}
fn checked(output: Output) -> Result<String, String> {
    if !output.status.success() {
        return Err(format!("observer command failed: {}", output.status));
    }
    String::from_utf8(output.stdout).map_err(|_error| "observer output was not UTF-8".into())
}
fn run(args: &[&str]) -> String {
    let mut all = vec!["--user"];
    all.extend_from_slice(args);
    checked(bounded("systemctl", &all).unwrap()).unwrap()
}
// A visible marker synchronizes this provider's stream, not a privileged global disk flush.
fn synchronized_journal(
    mut invoke: impl FnMut(&[&str]) -> Output,
    provider: &str,
    unit: &str,
    phase: &str,
    budget: Duration,
) -> Result<String, String> {
    let marker = format!("VW18-JOURNAL-BARRIER:{provider}:{phase}");
    let deadline = Instant::now() + budget;
    loop {
        let text = checked(invoke(&["--user", "--unit", provider, "--no-pager"]))?;
        if ["stdout", "stderr"]
            .iter()
            .all(|stream| text.contains(&format!("{marker}:{stream}")))
        {
            break;
        }
        if Instant::now() >= deadline {
            return Err("journal synchronization marker missing".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    checked(invoke(&["--user", "--unit", unit, "--no-pager"]))
}
fn journal(unit: &str, provider: &str, phase: &str) {
    let text = synchronized_journal(
        |args| bounded("journalctl", args).unwrap(),
        provider,
        unit,
        phase,
        Duration::from_secs(10),
    )
    .unwrap();
    for sentinel in ["story18-synthetic-secret", "synthetic-password-sentinel"] {
        assert!(!text.contains(sentinel));
    }
}
#[test]
fn journal_failure_cannot_establish_secret_absence() {
    use std::os::unix::process::ExitStatusExt;
    for fail_at in [0, 1, 2, 3] {
        let mut calls = 0;
        let result = synchronized_journal(
            |_| {
                let status = if calls == fail_at { 1 << 8 } else { 0 };
                let stdout = match fail_at {
                    2 => vec![],
                    3 => b"VW18-JOURNAL-BARRIER:provider.service:finished:stdout".to_vec(),
                    _ => b"VW18-JOURNAL-BARRIER:provider.service:finished:stdout\nVW18-JOURNAL-BARRIER:provider.service:finished:stderr".to_vec(),
                };
                calls += 1;
                Output {
                    status: std::process::ExitStatus::from_raw(status),
                    stdout,
                    stderr: vec![],
                }
            },
            "provider.service",
            "synthetic.service",
            "finished",
            Duration::ZERO,
        );
        assert!(result.is_err());
        assert_eq!(calls, if fail_at == 1 { 2 } else { 1 });
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Identity {
    name: String,
    cgroup: String,
}
fn identities(root: &Path) -> Vec<Identity> {
    match std::fs::read_to_string(root.join("identities.jsonl")) {
        Ok(text) => text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
        Err(e) => panic!("cannot observe created request identities: {e}"),
    }
}
struct Cleanup {
    root: PathBuf,
    provider: String,
    complete: bool,
}
impl Cleanup {
    fn new(root: &Path, provider: &str) -> Self {
        Self {
            root: root.into(),
            provider: provider.into(),
            complete: false,
        }
    }
    fn finish(&mut self) -> Result<(), String> {
        // Stop creation before consuming the append-only identity ledger.
        stop_exact(&self.provider)?;
        let entries = std::fs::read_to_string(self.root.join("identities.jsonl"));
        let entries = match entries {
            Ok(text) => text
                .lines()
                .map(serde_json::from_str::<Identity>)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.to_string()),
        };
        for identity in &entries {
            stop_exact(&identity.name)?;
            let deadline = Instant::now() + Duration::from_secs(10);
            while !empty(&identity.cgroup) {
                if Instant::now() >= deadline {
                    return Err("cleanup did not independently observe reaping".into());
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        }
        if let Ok(runtime) = std::fs::read_to_string(self.root.join("runtime")) {
            let runtime = Path::new(&runtime);
            for identity in entries {
                // Only exact artifacts recorded by this harness, never namespace globs.
                let nonce = identity
                    .name
                    .strip_suffix(".service")
                    .and_then(|s| s.rsplit('-').next())
                    .ok_or("invalid identity")?;
                for path in [
                    runtime.join(format!("{}.json", identity.name)),
                    runtime.join(format!("{nonce}.sock")),
                ] {
                    match std::fs::remove_file(path) {
                        Ok(()) => {}
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
            }
            match std::fs::remove_dir(runtime) {
                Ok(()) => {}
                Err(e)
                    if matches!(
                        e.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::DirectoryNotEmpty
                    ) => {}
                Err(e) => return Err(e.to_string()),
            }
        }
        self.complete = true;
        Ok(())
    }
}
fn unit_absent(unit: &str) -> Result<bool, String> {
    let output = bounded(
        "systemctl",
        &["--user", "show", unit, "--property=LoadState", "--value"],
    )
    .map_err(|e| e.to_string())?;
    // systemctl show may fail for a unit which has already been garbage collected.
    if String::from_utf8_lossy(&output.stdout).trim() == "not-found" {
        return Ok(true);
    }
    checked(output).map(|_state| false)
}
fn stop_exact(unit: &str) -> Result<(), String> {
    let output = bounded("systemctl", &["--user", "stop", unit]).map_err(|e| e.to_string())?;
    if !output.status.success() && !unit_absent(unit)? {
        return Err(format!("could not stop exact test unit {unit}"));
    }
    // Release retained failure state only for this exact created name.
    let output =
        bounded("systemctl", &["--user", "reset-failed", unit]).map_err(|e| e.to_string())?;
    if !output.status.success() && !unit_absent(unit)? {
        return Err(format!("could not reset exact test unit {unit}"));
    }
    if !unit_absent(unit)? {
        let state = checked(
            bounded(
                "systemctl",
                &["--user", "show", unit, "--property=ActiveState", "--value"],
            )
            .map_err(|e| e.to_string())?,
        )?;
        if state.trim() != "inactive" {
            return Err(format!("exact test unit still active or failed: {unit}"));
        }
    }
    Ok(())
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        if !self.complete {
            // Never double-panic during assertion unwinding.
            match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| self.finish())) {
                Ok(Ok(())) => {}
                _ => eprintln!("bounded cleanup failed for exact harness {}", self.provider),
            }
        }
    }
}
fn until(root: &Path, mut ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(40);
    while !ready() {
        assert!(
            Instant::now() < deadline,
            "real-manager barrier deadline; stage={:?}",
            std::fs::read_to_string(root.join("stage"))
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}
fn empty(cgroup: &str) -> bool {
    for entry in std::fs::read_dir("/proc").unwrap() {
        let entry = entry.unwrap();
        if !entry
            .file_name()
            .to_string_lossy()
            .bytes()
            .all(|b| b.is_ascii_digit())
        {
            continue;
        }
        match std::fs::read_to_string(entry.path().join("cgroup")) {
            Ok(groups) => {
                for line in groups.lines() {
                    if let Some(path) = line.strip_prefix("0::") {
                        let path = path.strip_suffix(" (deleted)").unwrap_or(path);
                        if path == cgroup || path.starts_with(&format!("{cgroup}/")) {
                            return false;
                        }
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("incomplete independent proc observation: {e}"),
        }
    }
    true
}
fn start(root: &Path, unit: &str, mode: &str) {
    let binary = std::env::var("VW18_TEST_BINARY").expect("script supplies unit harness binary");
    let status = Command::new("timeout")
        .args(["--signal=KILL", "12s", "systemd-run"])
        .args([
            "--user",
            "--quiet",
            "--unit",
            unit,
            "--property=Type=exec",
            "--property=KillMode=control-group",
            "--property=TimeoutStopSec=5s",
            "--property=StandardOutput=journal",
            "--property=StandardError=journal",
        ])
        .arg(format!("--setenv=VW18_ROOT={}", root.display()))
        .arg(format!("--setenv=VW18_PROVIDER={unit}"))
        .arg(format!("--setenv=VW18_MODE={mode}"))
        .arg(format!("--setenv=TMPDIR={}", root.display()))
        .args([
            &binary,
            "--exact",
            "adapters::supervisor::real_tests::provider_harness",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
#[test]
#[ignore = "requires real user systemd; run scripts/test-systemd-supervisor.sh"]
fn independent_descendants_provider_crash_and_recovery() {
    use std::os::unix::fs::PermissionsExt;
    let selected = std::env::var("VW18_SCENARIO").ok();
    let mut ran = 0;
    for mode in [
        "exit",
        "orphan",
        "cancel",
        "crash",
        "collision",
        "helper-failure",
        "failed-launch-recovery",
        "helper-environment",
        "app-worker-exit",
        "app-worker-shutdown",
        "app-exit",
        "app-nonzero",
        "app-signal",
        "app-lock",
        "app-cancel",
        "app-revoke",
        "app-agent-revoke",
        "app-shutdown",
        "app-deadline",
        "app-persistence",
        "phase-job",
        "phase-helper",
        "phase-transfer",
        "phase-release",
        "phase-exit",
        "fault-missing",
        "fault-job",
        "fault-exec",
        "fault-monitor",
        "fault-stop",
    ] {
        if selected.as_ref().is_some_and(|selected| mode != selected) {
            continue;
        }
        ran += 1;
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        for (variable, name) in [("VW18_HELPER", "helper"), ("VW18_IMAGE", "image")] {
            std::fs::copy(std::env::var(variable).unwrap(), root.path().join(name)).unwrap();
            std::fs::set_permissions(
                root.path().join(name),
                std::fs::Permissions::from_mode(0o500),
            )
            .unwrap();
        }
        if mode == "helper-environment" {
            // Use the same production helper function with a pre-hardening pause.
            std::fs::set_permissions(
                root.path().join("helper"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            std::fs::copy(
                std::env::var("VW18_ENV_HELPER").unwrap(),
                root.path().join("helper"),
            )
            .unwrap();
            std::fs::set_permissions(
                root.path().join("helper"),
                std::fs::Permissions::from_mode(0o500),
            )
            .unwrap();
        }
        if matches!(mode, "helper-failure" | "failed-launch-recovery") {
            std::fs::set_permissions(
                root.path().join("helper"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            std::fs::write(root.path().join("helper"), b"not a helper executable").unwrap();
            std::fs::set_permissions(
                root.path().join("helper"),
                std::fs::Permissions::from_mode(0o500),
            )
            .unwrap();
        }
        let unit = format!(
            "vw18-harness-{}-{}-{mode}.service",
            std::process::id(),
            root.path().file_name().unwrap().to_string_lossy()
        );
        let mut cleanup = Cleanup::new(root.path(), &unit);
        start(root.path(), &unit, mode);
        eprintln!("real-manager scenario: {mode}; provider: {unit}");
        if mode == "app-agent-revoke" {
            until(root.path(), || root.path().join("agent-revoked").exists());
            let scoped: Vec<Identity> = serde_json::from_slice(
                &std::fs::read(root.path().join("scoped-identities.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(scoped.len(), 2);
            assert_ne!(scoped[0].name, scoped[1].name);
            assert!(
                empty(&scoped[0].cgroup),
                "revoked agent descendants survived acknowledgement"
            );
            assert!(
                !empty(&scoped[1].cgroup),
                "other agent was terminated by scoped revocation"
            );
            assert_eq!(run(&["is-active", &scoped[1].name]).trim(), "active");
            std::fs::write(root.path().join("scoped-observation-complete"), b"observed").unwrap();
            until(root.path(), || root.path().join("finished").exists());
        } else if mode.starts_with("app-")
            || mode.starts_with("fault-")
            || mode.starts_with("phase-")
            || matches!(
                mode,
                "exit"
                    | "orphan"
                    | "collision"
                    | "helper-failure"
                    | "helper-environment"
                    | "failed-launch-recovery"
            )
        {
            until(root.path(), || root.path().join("finished").exists());
        } else {
            until(root.path(), || {
                root.path().join("tree-ready").exists() && root.path().join("started").exists()
            });
            let runtime = std::fs::read_to_string(root.path().join("runtime")).unwrap();
            let lease_path = std::fs::read_dir(&runtime)
                .unwrap()
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.extension().is_some_and(|ext| ext == "json"))
                .unwrap();
            let lease: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&lease_path).unwrap()).unwrap();
            let cgroup = lease["cgroup"].as_str().unwrap();
            assert!(!empty(cgroup));
            let request_unit = lease["name"].as_str().unwrap();
            let properties = run(&["show", request_unit]);
            assert!(!properties.contains("story18-synthetic-secret"));
            assert!(properties.lines().any(|line| line == "StandardOutput=null"));
            assert!(properties.lines().any(|line| line == "StandardError=null"));
            journal(request_unit, &unit, "started");
            if mode == "crash" {
                run(&["kill", "--signal=SIGKILL", "--kill-whom=main", &unit]);
                // No callbacks in the killed provider participate in this proof.
                until(root.path(), || empty(cgroup));
                assert!(!root.path().join("finished").exists());
                assert!(
                    lease_path.exists(),
                    "recovery identity survives provider death"
                );
                let unrelated = format!(
                    "{}{}.service",
                    &request_unit[..request_unit.len() - 40],
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                );
                let mut unrelated_cleanup =
                    Cleanup::new(&root.path().join("unrelated-no-ledger"), &unrelated);
                assert!(
                    Command::new("timeout")
                        .args(["--signal=KILL", "12s", "systemd-run"])
                        .args([
                            "--user",
                            "--quiet",
                            "--unit",
                            &unrelated,
                            "/usr/bin/sleep",
                            "30"
                        ])
                        .status()
                        .unwrap()
                        .success()
                );
                std::fs::write(root.path().join("recover"), b"recover").unwrap();
                run(&["restart", &unit]);
                until(root.path(), || root.path().join("finished").exists());
                assert!(!lease_path.exists());
                assert_eq!(run(&["is-active", &unrelated]).trim(), "active");
                unrelated_cleanup.finish().unwrap();
            } else {
                std::fs::write(root.path().join("cancel"), b"cancel").unwrap();
                until(root.path(), || root.path().join("finished").exists());
                assert!(empty(cgroup));
            }
        }
        let created = identities(root.path());
        if mode == "fault-missing" {
            assert!(
                created.is_empty(),
                "missing manager must not publish an identity"
            );
        } else {
            assert_eq!(
                created.len(),
                if mode == "app-agent-revoke" { 2 } else { 1 },
                "every scenario must record its request identity: {mode}"
            );
        }
        for identity in created {
            assert!(
                empty(&identity.cgroup),
                "independent reaping failed: {mode}"
            );
            if mode == "fault-job" {
                let output = bounded(
                    "systemctl",
                    &[
                        "--user",
                        "show",
                        &identity.name,
                        "--property=LoadState",
                        "--value",
                    ],
                )
                .unwrap();
                assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "not-found");
            }
            if matches!(mode, "helper-failure" | "failed-launch-recovery") {
                until(root.path(), || {
                    let output = bounded(
                        "systemctl",
                        &[
                            "--user",
                            "show",
                            &identity.name,
                            "--property=LoadState",
                            "--value",
                        ],
                    )
                    .unwrap();
                    String::from_utf8_lossy(&output.stdout).trim() == "not-found"
                });
            }
            journal(&identity.name, &unit, "finished");
        }
        journal(&unit, &unit, "finished");
        cleanup.finish().unwrap();
        if let Ok(runtime) = std::fs::read_to_string(root.path().join("runtime")) {
            assert!(
                !Path::new(&runtime).exists(),
                "empty test namespace must be removed"
            );
        }
    }
    assert!(ran > 0, "VW18_SCENARIO did not match any scenario");
}

#[test]
#[ignore = "requires real user systemd; run scripts/test-systemd-supervisor.sh"]
fn assertion_unwind_reaps_exact_resources_and_preserves_unrelated() {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::tempdir().unwrap();
    for (variable, name) in [("VW18_HELPER", "helper"), ("VW18_IMAGE", "image")] {
        std::fs::copy(std::env::var(variable).unwrap(), root.path().join(name)).unwrap();
        std::fs::set_permissions(
            root.path().join(name),
            std::fs::Permissions::from_mode(0o500),
        )
        .unwrap();
    }
    let unit = format!(
        "vw18-panic-{}-{}.service",
        std::process::id(),
        root.path().file_name().unwrap().to_string_lossy()
    );
    let unrelated = format!(
        "vw18-unrelated-{}-{}.service",
        std::process::id(),
        root.path().file_name().unwrap().to_string_lossy()
    );
    let mut unrelated_cleanup = Cleanup::new(&root.path().join("unrelated-no-ledger"), &unrelated);
    assert!(
        bounded(
            "systemd-run",
            &[
                "--user",
                "--quiet",
                "--unit",
                &unrelated,
                "/usr/bin/sleep",
                "120"
            ]
        )
        .unwrap()
        .status
        .success()
    );
    let result = std::panic::catch_unwind(|| {
        let _cleanup = Cleanup::new(root.path(), &unit);
        start(root.path(), &unit, "cancel");
        until(root.path(), || {
            root.path().join("started").exists() && root.path().join("tree-ready").exists()
        });
        let runtime = std::fs::read_to_string(root.path().join("runtime")).unwrap();
        std::fs::write(Path::new(&runtime).join("unrelated.keep"), b"preserve me").unwrap();
        assert!(
            identities(root.path()).len() == 2,
            "injected scenario assertion failure"
        );
    });
    assert!(result.is_err());
    let created = identities(root.path());
    assert_eq!(created.len(), 1);
    assert!(empty(&created[0].cgroup));
    let runtime = std::fs::read_to_string(root.path().join("runtime")).unwrap();
    let files = std::fs::read_dir(&runtime)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(files, [std::ffi::OsString::from("unrelated.keep")]);
    assert_eq!(
        std::fs::read(Path::new(&runtime).join("unrelated.keep")).unwrap(),
        b"preserve me"
    );
    assert_eq!(run(&["is-active", &unrelated]).trim(), "active");
    journal(&created[0].name, &unit, "started");
    journal(&unit, &unit, "started");
    std::fs::remove_file(Path::new(&runtime).join("unrelated.keep")).unwrap();
    std::fs::remove_dir(&runtime).unwrap();
    unrelated_cleanup.finish().unwrap();
}
