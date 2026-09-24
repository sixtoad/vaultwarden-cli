//! Fixed desktop handoff. Only a private artifact path crosses the process boundary.
use crate::access::direct_request::DirectRequestError;
use std::{
    os::unix::fs::MetadataExt,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

pub(crate) trait DesktopOpener: Send + Sync {
    fn open(&self, artifact: &Path) -> Result<(), DirectRequestError>;
}
pub(crate) struct SystemDesktop;
impl DesktopOpener for SystemDesktop {
    fn open(&self, artifact: &Path) -> Result<(), DirectRequestError> {
        // No configuration or client field can replace this production executable.
        let launcher = Path::new("/usr/bin/xdg-open");
        let metadata = launcher.metadata().map_err(|_error| unavailable())?;
        if !trusted_launcher(metadata.is_file(), metadata.uid(), metadata.mode()) {
            return Err(unavailable());
        }
        run_bounded(desktop_command(launcher, artifact), Duration::from_secs(2))
    }
}
fn trusted_launcher(is_file: bool, uid: u32, mode: u32) -> bool {
    is_file && uid == 0 && mode & 0o022 == 0
}
fn desktop_command(launcher: &Path, artifact: &Path) -> Command {
    let mut command = Command::new(launcher);
    command
        .arg(artifact)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // Configuration is captured from the provider's own desktop, never a client.
    for name in [
        "HOME",
        "DISPLAY",
        "WAYLAND_DISPLAY",
        "XAUTHORITY",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_DESKTOP",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command
}
fn run_bounded(mut command: Command, timeout: Duration) -> Result<(), DirectRequestError> {
    let mut child = command.spawn().map_err(|_error| unavailable())?;
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return if status.success() {
                    Ok(())
                } else {
                    Err(unavailable())
                };
            }
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(10)),
            _ => {
                let _ignored = child.kill();
                let _ignored = child.wait();
                return Err(unavailable());
            }
        }
    }
}
fn unavailable() -> DirectRequestError {
    DirectRequestError::ReviewUnavailable
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn script(root: &Path, source: &str) -> std::path::PathBuf {
        let path = root.join("synthetic-opener");
        std::fs::write(&path, format!("#!/bin/sh\n{source}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }
    #[test]
    fn trust_requires_each_independent_launcher_metadata_condition() {
        assert!(trusted_launcher(true, 0, 0o100755));
        assert!(trusted_launcher(true, 0, 0o100744));
        assert!(!trusted_launcher(false, 0, 0o100755));
        assert!(!trusted_launcher(true, 1000, 0o100755));
        assert!(!trusted_launcher(true, 0, 0o100775));
        assert!(!trusted_launcher(true, 0, 0o100757));
    }
    #[test]
    fn child_receives_only_artifact_path_trusted_environment_and_null_streams() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = script(
            dir.path(),
            r#"
[ "$#" -eq 1 ] || exit 11
input=$(readlink /proc/$$/fd/0)
output=$(readlink /proc/$$/fd/1)
error=$(readlink /proc/$$/fd/2)
printf '%s\n' "$#" "$1" "$input" "$output" "$error" > "$1.report"
env > "$1.environment"
printf 'stdout-must-be-null'
printf 'stderr-must-be-null' >&2
"#,
        );
        let artifact = dir.path().join("private artifact;literal.html");
        let command = desktop_command(&launcher, &artifact);
        assert_eq!(command.get_program(), launcher.as_os_str());
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            vec![artifact.as_os_str()]
        );
        for name in [
            "HOME",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_CURRENT_DESKTOP",
            "XDG_SESSION_DESKTOP",
        ] {
            assert_eq!(
                command
                    .get_envs()
                    .find(|(key, _)| *key == name)
                    .and_then(|(_, value)| value),
                std::env::var_os(name).as_deref()
            );
        }
        // This checks child isolation, not scheduling latency under parallel builds.
        assert_eq!(run_bounded(command, Duration::from_secs(10)), Ok(()));
        let report = std::fs::read_to_string(format!("{}.report", artifact.display())).unwrap();
        let lines: Vec<_> = report.lines().collect();
        assert_eq!(
            lines,
            vec![
                "1",
                artifact.to_str().unwrap(),
                "/dev/null",
                "/dev/null",
                "/dev/null"
            ]
        );
        let environment =
            std::fs::read_to_string(format!("{}.environment", artifact.display())).unwrap();
        let allowed = [
            "PATH",
            "HOME",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
            "DBUS_SESSION_BUS_ADDRESS",
            "XDG_CURRENT_DESKTOP",
            "XDG_SESSION_DESKTOP",
            "PWD",
            "SHLVL",
            "_",
        ];
        for line in environment.lines() {
            assert!(
                allowed.contains(&line.split_once('=').unwrap().0),
                "unexpected inherited environment name"
            );
        }
        assert!(environment.lines().any(|line| line == "PATH=/usr/bin:/bin"));
    }
    #[test]
    fn nonzero_and_spawn_failure_are_closed_review_errors() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("artifact");
        let failed = script(dir.path(), "exit 7");
        assert_eq!(
            run_bounded(desktop_command(&failed, &artifact), Duration::from_secs(2)),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert_eq!(
            run_bounded(
                desktop_command(&dir.path().join("missing"), &artifact),
                Duration::from_secs(2)
            ),
            Err(DirectRequestError::ReviewUnavailable)
        );
    }
    #[test]
    fn timeout_kills_and_reaps_the_started_child() {
        let dir = tempfile::tempdir().unwrap();
        let launcher = script(dir.path(), "echo $$ > \"$1.pid\"\nexec /bin/sleep 30");
        let artifact = dir.path().join("artifact");
        let started = Instant::now();
        assert_eq!(
            run_bounded(
                desktop_command(&launcher, &artifact),
                Duration::from_millis(300)
            ),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert!(started.elapsed() >= Duration::from_millis(250));
        assert!(started.elapsed() < Duration::from_secs(5));
        let pid: libc::pid_t = std::fs::read_to_string(format!("{}.pid", artifact.display()))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert_eq!(
            unsafe { libc::waitpid(pid, std::ptr::null_mut(), libc::WNOHANG) },
            -1
        );
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ECHILD)
        );
    }
    #[test]
    fn fixed_system_launcher_uses_only_an_isolated_desktop_association() {
        if !Path::new("/usr/bin/xdg-open").exists() {
            assert_eq!(
                SystemDesktop.open(Path::new("/nonexistent-artifact")),
                Err(DirectRequestError::ReviewUnavailable)
            );
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".config")).unwrap();
        std::fs::create_dir_all(dir.path().join(".local/share/applications")).unwrap();
        let artifact = dir.path().join("artifact.html");
        std::fs::write(
            &artifact,
            "<!doctype html><html><title>Synthetic handoff</title></html>",
        )
        .unwrap();
        let handler = script(dir.path(), "printf '%s\\n' \"$1\" > \"$HOME/handoff\"");
        std::fs::write(dir.path().join(".local/share/applications/fixture.desktop"), format!("[Desktop Entry]\nType=Application\nName=Synthetic desktop handoff\nExec={} %f\nTerminal=false\nMimeType=text/html;\n", handler.display())).unwrap();
        std::fs::write(
            dir.path().join(".config/mimeapps.list"),
            "[Default Applications]\ntext/html=fixture.desktop;\ntext/plain=fixture.desktop;\n",
        )
        .unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "adapters::desktop_launch::tests::isolated_system_launcher_child",
                "--ignored",
            ])
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", dir.path())
            .env("DISPLAY", ":987")
            .env("XDG_CURRENT_DESKTOP", "X-Generic")
            .env("VW_DESKTOP_TEST_ARTIFACT", &artifact)
            .output()
            .unwrap();
        assert!(
            child.status.success(),
            "isolated production launcher test failed: {}",
            String::from_utf8_lossy(&child.stdout)
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("handoff"))
                .unwrap()
                .trim(),
            artifact.to_str().unwrap()
        );
    }
    #[test]
    #[ignore = "invoked only by the isolated desktop test subprocess"]
    fn isolated_system_launcher_child() {
        let artifact = std::path::PathBuf::from(
            std::env::var_os("VW_DESKTOP_TEST_ARTIFACT").expect("private artifact"),
        );
        assert_eq!(SystemDesktop.open(&artifact), Ok(()));
        assert_eq!(
            SystemDesktop.open(&artifact.with_extension("missing")),
            Err(DirectRequestError::ReviewUnavailable)
        );
    }
}
