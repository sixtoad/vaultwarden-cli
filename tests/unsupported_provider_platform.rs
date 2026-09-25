//! Unsupported hosts must reject provider use before parsing or touching state.
#![cfg(not(target_os = "linux"))]

use assert_cmd::Command;
use std::{ffi::OsString, path::Path, time::Duration};

fn snapshot(root: &Path) -> Vec<(std::path::PathBuf, Option<Vec<u8>>)> {
    fn collect(root: &Path, path: &Path, entries: &mut Vec<(std::path::PathBuf, Option<Vec<u8>>)>) {
        for entry in std::fs::read_dir(path).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            assert!(!kind.is_symlink(), "provider created a symlink");
            let path = entry.path();
            let relative = path.strip_prefix(root).unwrap().to_owned();
            if kind.is_dir() {
                entries.push((relative, None));
                collect(root, &path, entries);
            } else {
                assert!(kind.is_file(), "provider created a special file");
                entries.push((relative, Some(std::fs::read(path).unwrap())));
            }
        }
    }
    let mut entries = Vec::new();
    collect(root, root, &mut entries);
    entries.sort();
    entries
}

#[cfg(unix)]
fn non_unicode_argument() -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(b"private-caller-sentinel-\xff".to_vec())
}

#[cfg(windows)]
fn non_unicode_argument() -> OsString {
    use std::os::windows::ffi::OsStringExt;
    let mut value: Vec<u16> = "private-caller-sentinel-".encode_utf16().collect();
    value.push(0xd800); // An unpaired surrogate is valid in a native Windows argument.
    OsString::from_wide(&value)
}

#[test]
fn provider_binaries_reject_unsupported_platform_without_side_effects_or_disclosure() {
    for prepopulated in [false, true] {
        let parent = tempfile::tempdir().unwrap();
        let state = parent.path().join("private-caller-sentinel-state");
        let environment_state = parent.path().join("private-caller-sentinel-environment");
        let config = parent.path().join("private-caller-sentinel-config");
        if prepopulated {
            for root in [&state, &environment_state] {
                std::fs::create_dir(root).unwrap();
                std::fs::write(root.join("provider-state.json"), b"private-state-sentinel")
                    .unwrap();
                std::fs::write(
                    root.join("open-vaultwarden-access.html"),
                    b"private-launch-sentinel",
                )
                .unwrap();
            }
            std::fs::write(&config, b"private-config-sentinel").unwrap();
        }
        let before = snapshot(parent.path());
        for (binary, name) in [
            (
                assert_cmd::cargo::cargo_bin!("vaultwarden-accessd"),
                "vaultwarden-accessd",
            ),
            (assert_cmd::cargo::cargo_bin!("vw-access"), "vw-access"),
        ] {
            let mut cases: Vec<Vec<OsString>> = vec![
                vec![],
                vec!["--help".into()],
                vec!["--version".into()],
                vec!["--private-caller-sentinel-invalid".into()],
                vec!["--state-root".into(), state.as_os_str().to_owned()],
                vec!["--backend-config".into(), config.as_os_str().to_owned()],
                vec![
                    "--state-root".into(),
                    state.as_os_str().to_owned(),
                    "--backend-config".into(),
                    config.as_os_str().to_owned(),
                ],
                vec![
                    "--state-root".into(),
                    state.as_os_str().to_owned(),
                    "request".into(),
                    "private-caller-sentinel-operation".into(),
                    "--".into(),
                    "private-caller-sentinel-argument".into(),
                ],
                vec![
                    "request".into(),
                    "private-caller-sentinel-operation".into(),
                    "--".into(),
                    "private-caller-sentinel-argument".into(),
                ],
                vec!["status".into(), "private-caller-sentinel-receipt".into()],
            ];
            #[cfg(any(unix, windows))]
            cases.push(vec![non_unicode_argument()]);
            for arguments in cases {
                let output = Command::new(binary)
                    .args(arguments)
                    .env("VAULTWARDEN_ACCESS_STATE_ROOT", &environment_state)
                    .timeout(Duration::from_secs(10))
                    .output()
                    .unwrap();
                assert_eq!(output.status.code(), Some(1), "{name}");
                assert!(output.stdout.is_empty(), "{name}");
                assert_eq!(
                    output.stderr,
                    format!("{name}: unsupported platform; requires Linux\n").as_bytes(),
                    "{name}"
                );
                assert_eq!(
                    snapshot(parent.path()),
                    before,
                    "{name} created, removed or modified provider state/configuration"
                );
            }
        }
    }
}
