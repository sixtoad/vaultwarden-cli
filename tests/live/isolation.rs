//! Server-independent tests of the actual live CLI builder.
#[cfg(target_os = "linux")]
mod linux {
    use crate::live_env::{PrivateKeyring, isolate_command, isolated_cli};
    use assert_cmd::Command;
    use std::os::unix::net::UnixListener;

    #[test]
    fn inherited_environment_and_desktop_bus_are_isolated() {
        let root = tempfile::tempdir().unwrap();
        let bus_path = root.path().join("desktop-bus");
        let bus = UnixListener::bind(&bus_path).unwrap();
        bus.set_nonblocking(true).unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "isolation::linux::isolated_cli_probe",
                "--nocapture",
            ])
            .env("LIVE_ISOLATION_PROBE", "1")
            .env("PARENT_SECRET_SENTINEL", "synthetic-parent-secret")
            .env("VAULTWARDEN_PASSWORD", "synthetic-parent-password")
            .env(
                "DBUS_SESSION_BUS_ADDRESS",
                format!("unix:path={}", bus_path.display()),
            )
            .env("HTTP_PROXY", "http://127.0.0.1:9")
            .env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("DISPLAY", ":987")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(String::from_utf8_lossy(&output.stdout).contains("isolated actual CLI verified"));
        assert_eq!(
            bus.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
    }

    #[test]
    fn isolated_cli_probe() {
        if std::env::var("LIVE_ISOLATION_PROBE").as_deref() != Ok("1") {
            return;
        }
        assert_eq!(
            std::env::var("PARENT_SECRET_SENTINEL").unwrap(),
            "synthetic-parent-secret"
        );
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let config_root = root.path().join("config");
        let config = config_root.join("vaultwarden-cli");
        std::fs::create_dir_all(&home).unwrap();
        std::fs::create_dir_all(&config).unwrap();
        let _private_keyring = PrivateKeyring::start(&home, &config_root).unwrap();
        std::fs::write(config.join("config.json"), r#"{"server":"http://127.0.0.1:9","client_id":"synthetic-isolation-client","email":"synthetic@test.invalid"}"#).unwrap();
        std::fs::write(
            config.join("tokens.json"),
            r#"{"access_token":"synthetic-token","token_expiry":4102444800}"#,
        )
        .unwrap();
        let mut command = isolated_cli(&home, &config_root);
        let vars: Vec<_> = command
            .get_envs()
            .map(|(key, _)| key.to_string_lossy().into_owned())
            .collect();
        for forbidden in [
            "PARENT_SECRET_SENTINEL",
            "VAULTWARDEN_PASSWORD",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "DISPLAY",
        ] {
            assert!(!vars.iter().any(|key| key == forbidden));
        }
        // Lock loads and deletes native keyring entries against the private
        // service. The fake desktop listener must receive no connections.
        command.arg("lock").assert().success();
        let mut child_environment = Command::new("/usr/bin/env");
        isolate_command(&mut child_environment, &home, &config_root);
        let output = child_environment.output().unwrap();
        assert!(output.status.success());
        let environment = String::from_utf8(output.stdout).unwrap();
        for forbidden in [
            "synthetic-parent-secret",
            "synthetic-parent-password",
            "desktop-bus",
            "PROXY=",
            "DISPLAY=",
        ] {
            assert!(
                !environment.contains(forbidden),
                "inherited environment reached child"
            );
        }
        println!("isolated actual CLI verified");
    }
}
