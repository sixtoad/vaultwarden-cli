//! Real OpenSSH interoperability, separate from the production executable profile.
use super::*;
use crate::{access::ports::SshMaterial, adapters::ssh_material};
use std::process::{Child, Command, Stdio};

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

struct TestProcess(Child);
impl Drop for TestProcess {
    fn drop(&mut self) {
        // The test owns these disposable processes; production never signals consumers.
        let _terminated = self.0.kill();
        let _reaped = self.0.wait();
    }
}
struct Control;
impl ExecutionControl for Control {
    fn live(&self) -> bool {
        true
    }
    fn remaining(&self) -> Duration {
        Duration::from_secs(20)
    }
    fn release(
        &self,
        action: &mut dyn FnMut() -> Result<(), ExecutionError>,
    ) -> Result<(), ExecutionError> {
        action()
    }
    fn started(&self) -> Result<(), ExecutionError> {
        Ok(())
    }
}
fn private_file(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap()
        .write_all(bytes)
        .unwrap();
}

#[test]
#[ignore = "requires local OpenSSH ssh/sshd and loopback; run with secure temporary directory"]
fn real_openssh_authenticates_with_memory_only_client_key_and_survives_agent_close() {
    use ssh_key::EcdsaCurve;
    for (client_algorithm, host_algorithm, rsa_signature) in [
        (Algorithm::Ed25519, Algorithm::Ed25519, None),
        (
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            None,
        ),
        (
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP384,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP256,
            },
            None,
        ),
        (
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            Algorithm::Ecdsa {
                curve: EcdsaCurve::NistP521,
            },
            None,
        ),
        (
            Algorithm::Rsa { hash: None },
            Algorithm::Ed25519,
            Some("rsa-sha2-256"),
        ),
        (
            Algorithm::Rsa { hash: None },
            Algorithm::Rsa { hash: None },
            Some("rsa-sha2-512"),
        ),
    ] {
        run_interoperability(client_algorithm, host_algorithm, rsa_signature);
    }
}
fn run_interoperability(
    client_algorithm: Algorithm,
    host_algorithm: Algorithm,
    rsa_signature: Option<&str>,
) {
    let root = tempfile::tempdir().unwrap();
    let root = root.path();
    let (mut operation, _) = ssh_material::fixture(root);
    fn synthetic_key(algorithm: Algorithm) -> PrivateKey {
        if matches!(algorithm, Algorithm::Rsa { .. }) {
            PrivateKey::new(
                ssh_key::private::RsaKeypair::random(&mut rand::rng(), 2048)
                    .unwrap()
                    .into(),
                "synthetic RSA",
            )
            .unwrap()
        } else {
            PrivateKey::random(&mut rand::rng(), algorithm).unwrap()
        }
    }
    let host = synthetic_key(host_algorithm);
    let client = synthetic_key(client_algorithm);
    let username = String::from_utf8(Command::new("id").arg("-un").output().unwrap().stdout)
        .unwrap()
        .trim()
        .to_owned();
    let reserved = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
    let port = reserved.local_addr().unwrap().port();
    let host_path = root.join("server-host-key");
    private_file(
        &host_path,
        host.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    );
    let authorized = root.join("authorized_keys");
    private_file(
        &authorized,
        client.public_key().to_openssh().unwrap().as_bytes(),
    );
    let config = root.join("sshd_config");
    private_file(&config, format!("ListenAddress 127.0.0.1\nPort {port}\nHostKey {}\nPidFile {}\nAuthorizedKeysFile {}\nStrictModes yes\nUsePAM no\nPasswordAuthentication no\nKbdInteractiveAuthentication no\nAuthenticationMethods publickey\nAllowUsers {username}\nPermitUserEnvironment no\nPermitUserRC no\nAllowAgentForwarding no\nAllowTcpForwarding no\nX11Forwarding no\nLogLevel VERBOSE\n",host_path.display(),root.join("sshd.pid").display(),authorized.display()).as_bytes());
    let server_log = root.join("sshd.log");
    drop(reserved);
    let mut server = TestProcess(
        Command::new("/usr/sbin/sshd")
            .args(["-D", "-e", "-f"])
            .arg(&config)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&server_log).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "test sshd exited: {}",
            std::fs::read_to_string(&server_log).unwrap()
        );
        if std::net::TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "test sshd did not listen");
        std::thread::sleep(Duration::from_millis(10));
    }
    operation.destination.host = "127.0.0.1".into();
    operation.destination.port = port;
    operation.destination.user = username;
    #[cfg(target_os = "linux")]
    {
        operation.destination.resource_path = "/usr/bin/sleep 1".into();
    }
    #[cfg(target_os = "macos")]
    {
        operation.destination.resource_path = "/bin/sleep 1".into();
    }
    operation.destination.host_fingerprint =
        host.public_key().fingerprint(HashAlg::Sha256).to_string();
    std::fs::write(root.join("ssh/host_keys.json"), serde_json::to_vec(&serde_json::json!([{"host":"127.0.0.1","port":port,"key":host.public_key().to_openssh().unwrap().split_whitespace().take(2).collect::<Vec<_>>().join(" ")}])).unwrap()).unwrap();
    let (mut material, mut argv, _cwd) = ssh_material::with_test_runtime(root, || {
        ssh_material::prepare(&root.join("ssh"), &operation)
    })
    .unwrap();
    if let Some(algorithm) = rsa_signature {
        argv.splice(
            0..0,
            ["-o".into(), format!("PubkeyAcceptedAlgorithms={algorithm}")],
        );
    }
    material
        .install_key(SensitiveString::new(
            client
                .to_openssh(ssh_key::LineEnding::LF)
                .unwrap()
                .to_string(),
        ))
        .unwrap();
    material.mark_in_use().unwrap();
    let client_log = root.join("ssh.log");
    let mut ssh = TestProcess(
        Command::new("/usr/bin/ssh")
            .args(argv)
            .env_clear()
            .env("LANG", "C")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&client_log).unwrap())
            .spawn()
            .unwrap(),
    );
    #[cfg(target_os = "linux")]
    {
        let descriptor = unsafe { libc::syscall(libc::SYS_pidfd_open, ssh.0.id(), 0) };
        assert!(descriptor >= 0);
        material
            .agent
            .borrow_mut()
            .recipient((ssh.0.id(), unsafe {
                OwnedFd::from_raw_fd(descriptor as i32)
            }))
            .unwrap();
    }
    #[cfg(target_os = "macos")]
    material
        .agent
        .borrow_mut()
        .recipient(Recipient {
            pid: ssh.0.id(),
            requirement: crate::adapters::native::native_ssh_requirement().unwrap(),
        })
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut survived_agent_close = false;
    let outcome = loop {
        material.agent.borrow_mut().poll(&Control).unwrap();
        if let Some(status) = ssh.0.try_wait().unwrap() {
            break status;
        }
        let agent = material.agent.borrow();
        if agent.consumed && agent.key.is_none() && agent.listener.is_none() {
            survived_agent_close = true;
        }
        assert!(
            Instant::now() < deadline,
            "SSH timed out: {}",
            std::fs::read_to_string(&server_log).unwrap()
        );
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        outcome.success(),
        "SSH authentication failed; client: {}; server: {}",
        std::fs::read_to_string(&client_log).unwrap(),
        std::fs::read_to_string(&server_log).unwrap()
    );
    assert!(
        survived_agent_close,
        "established SSH continued after agent closed"
    );
    assert!(material.agent.borrow().key.is_none());
    for request in std::fs::read_dir(root.join("ssh/agents")).unwrap() {
        let request = request.unwrap().path();
        assert!(!request.join("identity").exists());
        assert!(!request.join("agent.sock").exists());
    }
    material
        .finalize(crate::access::ports::CleanupEvidence::Reaped)
        .unwrap();
}
