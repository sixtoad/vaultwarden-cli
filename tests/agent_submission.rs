//! Real distinct-UID/group and stdin-closed CLI evidence in an isolated user namespace.
#![cfg(target_os = "linux")]
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::SigningKey;
use std::{
    fs,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::Path,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use vaultwarden_cli::{
    access::{
        agent_binding::AgentPairing,
        application::ProviderApplication,
        direct_request::*,
        policy::*,
        ports::*,
        protocol::{AgentRejection, AgentResponse, SignedSubmission},
        provider::Provider,
    },
    adapters::{
        human_socket::{HumanCommand, HumanResponse, HumanSocket, exchange},
        session::MonotonicClock,
        unix_socket::AgentSocket,
    },
};
struct Backend(Arc<AtomicUsize>);
impl ProviderSession for Backend {
    fn probe_compatibility(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
    fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
        Ok(Duration::from_secs(900))
    }
    fn clear(&mut self) -> Result<(), SessionError> {
        Ok(())
    }
}
impl SecretBackend for Backend {
    fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
        Ok(true)
    }
    fn resolve(&mut self, _: &CredentialBinding<'_>) -> Result<Vec<SensitiveString>, SessionError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        panic!("submission must not resolve secrets")
    }
}
struct Launcher(AtomicUsize);
impl DirectReviewLauncher for Launcher {
    fn launch(&self, _: &str) -> Result<(), DirectRequestError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}
fn identity(command: &mut Command, uid: u32, gid: u32, groups: Vec<u32>) {
    unsafe {
        command.pre_exec(move || {
            if libc::setsid() < 0
                || libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.stdin(Stdio::null());
}
fn peer(
    path: &Path,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    bytes: &str,
    no_write: bool,
) -> AgentResponse {
    let mut command = Command::new("python3");
    command
        .args([
            "-c",
            r#"import os,socket,sys
s=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect(os.environ['SOCKET'])
if os.environ['NO_WRITE']=='0':
 s.sendall(os.environ['PAYLOAD'].encode());s.shutdown(socket.SHUT_WR)
data=b''
while True:
 chunk=s.recv(1024)
 if not chunk:break
 data+=chunk
 if len(data)>1024:raise Exception('oversized response')
sys.stdout.buffer.write(data)
"#,
        ])
        .env("SOCKET", path)
        .env("PAYLOAD", bytes)
        .env("NO_WRITE", if no_write { "1" } else { "0" });
    identity(&mut command, uid, gid, groups);
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    AgentResponse::parse(&output.stdout).unwrap()
}
fn count(root: &Path) -> usize {
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(root.join("provider-state.json")).unwrap()).unwrap();
    state["requests"].as_array().unwrap().len()
}
fn restricted_id_map(map: &str, required: &[u32]) -> bool {
    let mut ranges = Vec::new();
    for line in map.lines() {
        let Ok(fields) = line
            .split_whitespace()
            .map(str::parse::<u64>)
            .collect::<Result<Vec<_>, _>>()
        else {
            return false;
        };
        if fields.len() != 3
            || fields[1] == 0
            || fields[2] == 0
            || !fields[0]
                .checked_add(fields[2])
                .is_some_and(|end| end <= u64::from(u32::MAX) + 1)
            || !fields[1]
                .checked_add(fields[2])
                .is_some_and(|end| end <= u64::from(u32::MAX) + 1)
        {
            return false;
        }
        ranges.push(fields);
    }
    required.iter().all(|id| {
        ranges
            .iter()
            .any(|range| u64::from(*id) >= range[0] && u64::from(*id) - range[0] < range[2])
    })
}

#[test]
fn namespace_guard_rejects_initial_root_and_incomplete_maps() {
    assert!(restricted_id_map("0 1000 1\n1 100000 65536\n", &[0, 8, 10]));
    for map in [
        "0 0 4294967295\n",
        "0 1000 1\n",
        "0 1000 1\n8 0 1\n10 100010 1\n",
        "0 1000 9\n",
        "bad",
    ] {
        assert!(!restricted_id_map(map, &[0, 8, 10]), "{map}");
    }
}

fn set_owner(path: &Path, uid: u32, gid: u32) {
    let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(path.as_ptr(), uid, gid) }, 0);
}

#[test]
#[ignore = "requires VW_AGENT_NAMESPACE=1 in an isolated multi-UID user namespace; never run as host root"]
fn real_linux_peer_matrix_and_noninteractive_cli() {
    assert_eq!(std::env::var("VW_AGENT_NAMESPACE").as_deref(), Ok("1"));
    assert_eq!(unsafe { libc::geteuid() }, 0);
    // Kernel maps, not an environment marker or UID zero, prove this is a
    // restricted namespace. No mapped identity may reach outer UID/GID zero.
    assert!(
        restricted_id_map(
            &fs::read_to_string("/proc/self/uid_map").unwrap(),
            &[0, 8, 10]
        ),
        "requires restricted multi-UID namespace with non-root outer mappings"
    );
    assert!(
        restricted_id_map(
            &fs::read_to_string("/proc/self/gid_map").unwrap(),
            &[0, 7, 9, 10]
        ),
        "requires restricted multi-GID namespace with non-root outer mappings"
    );
    let dir = tempfile::tempdir().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o755)).unwrap();
    let root = dir.path().join("provider");
    let resolutions = Arc::new(AtomicUsize::new(0));
    let app = Arc::new(
        ProviderApplication::new(
            Provider::start(&root).unwrap(),
            Box::new(Backend(resolutions.clone())),
            Box::<MonotonicClock>::default(),
        )
        .unwrap(),
    );
    app.authenticate(SensitiveString::new("synthetic".into()))
        .unwrap();
    let image = dir.path().join("image");
    let bytes: &[u8] = b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x3e\x00\x01\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x38\x00\x01\x00\x40\x00\x00\x00\x00\x00\x01\x00\x00\x00\x05\x00\x00\x00\x78\x00\x00\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x78\x00\x40\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x0c\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\xb8\x3c\x00\x00\x00\xbf\x00\x00\x00\x00\x0f\x05";
    #[cfg(target_arch = "aarch64")]
    let native_bytes = {
        let mut native = bytes.to_vec();
        native[18..20].copy_from_slice(&183u16.to_le_bytes());
        // mov x0, #0; mov x8, #93; svc #0 (native Linux exit(0)).
        native[120..132].copy_from_slice(&[
            0x00, 0x00, 0x80, 0xd2, 0xa8, 0x0b, 0x80, 0xd2, 0x01, 0x00, 0x00, 0xd4,
        ]);
        native
    };
    #[cfg(target_arch = "aarch64")]
    let bytes = native_bytes.as_slice();
    std::fs::write(&image, bytes).unwrap();
    std::fs::set_permissions(&image, std::fs::Permissions::from_mode(0o500)).unwrap();
    use sha2::Digest;
    let digest: String = sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let state_path = root.join("provider-state.json");
    let mut state: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
    state["approved_images"] = serde_json::json!([{"id":"test-image","execution_root":dir.path(),"path":image,"sha256":digest,"profile":"reviewed_self_contained_elf64_v1"}]);
    std::fs::write(&state_path, serde_json::to_vec(&state).unwrap()).unwrap();
    let revision = app
        .activate_operation(OperationPolicyDraft {
            id: "deploy".into(),
            description: "Deploy <script>sentinel</script>".into(),
            image_id: "test-image".into(),
            targets: vec!["staging".into()],
            arguments: vec![
                ArgumentSpec::Target,
                ArgumentSpec::Integer {
                    minimum: 0,
                    maximum: 9,
                },
            ],
            credentials: vec![LoginCredentialDraft {
                item_id: "11111111-1111-1111-1111-111111111111".into(),
                label: "Deploy login".into(),
                use_type: CredentialUse::Login,
                field_mappings: vec![LoginFieldMapping {
                    field: LoginField::Password,
                    environment: "DEPLOY_PASSWORD".into(),
                }],
            }],
        })
        .unwrap();

    let traversal_only = dir.path().join("traversal-only");
    fs::create_dir(&traversal_only).unwrap();
    let socket_dir = traversal_only.join("agents");
    fs::create_dir(&socket_dir).unwrap();
    fs::set_permissions(&socket_dir, fs::Permissions::from_mode(0o750)).unwrap();
    let socket_dir_c = std::ffi::CString::new(socket_dir.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(socket_dir_c.as_ptr(), 0, 7) }, 0);
    let socket = AgentSocket::bind(&socket_dir, 7).unwrap();
    let path = socket_dir.join("agent.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let launcher = Arc::new(Launcher(AtomicUsize::new(0)));
    let human = HumanSocket::bind(&root).unwrap();
    let human_worker = {
        let (app, launcher, stop) = (app.clone(), launcher.clone(), stop.clone());
        std::thread::spawn(move || human.serve(app, launcher, stop))
    };
    let key = SigningKey::from_bytes(&[7; 32]);
    let HumanResponse::AgentPaired { agent } = exchange(
        &root,
        HumanCommand::AgentPair {
            pairing: AgentPairing {
                label: "namespace-agent".into(),
                public_key: URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes()),
                uid: 8,
                gid: 9,
            },
        },
    )
    .unwrap() else {
        panic!("pairing failed")
    };
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let worker = runtime.spawn(socket.serve(app.clone(), launcher.clone(), stop.clone()));
    let signed = |nonce: u8, signer: &SigningKey, revision: String, args: Vec<String>| {
        SignedSubmission::sign(
            agent.id.clone(),
            [nonce; 32],
            "deploy".into(),
            revision,
            args,
            signer,
        )
        .unwrap()
    };
    let valid = signed(
        1,
        &key,
        revision.clone(),
        vec!["staging".into(), "3".into()],
    );
    let encoded = format!("{}\n", serde_json::to_string(&valid).unwrap());
    // No write at all: rejection must precede any read or parser invocation.
    let start = std::time::Instant::now();
    assert!(matches!(
        peer(&path, 10, 9, vec![7], "", true),
        AgentResponse::Rejected {
            category: AgentRejection::Unauthorized,
            ..
        }
    ));
    assert!(start.elapsed() < Duration::from_secs(2));
    for (uid, gid, groups, input, expected) in [
        (
            10,
            9,
            vec![7],
            encoded.clone(),
            AgentRejection::Unauthorized,
        ),
        (
            8,
            10,
            vec![7],
            encoded.clone(),
            AgentRejection::Unauthorized,
        ),
        (0, 9, vec![7], encoded.clone(), AgentRejection::Unauthorized),
        (
            8,
            9,
            vec![7],
            format!(
                "{}\n",
                serde_json::to_string(&signed(
                    2,
                    &SigningKey::from_bytes(&[8; 32]),
                    revision.clone(),
                    vec!["staging".into(), "3".into()]
                ))
                .unwrap()
            ),
            AgentRejection::Unauthorized,
        ),
        (
            8,
            9,
            vec![7],
            "{not json}\n".into(),
            AgentRejection::Malformed,
        ),
        (
            8,
            9,
            vec![7],
            format!(
                "{}\n",
                serde_json::to_string(&signed(
                    3,
                    &key,
                    "a".repeat(64),
                    vec!["staging".into(), "3".into()]
                ))
                .unwrap()
            ),
            AgentRejection::StaleRevision,
        ),
        (
            8,
            9,
            vec![7],
            format!(
                "{}\n",
                serde_json::to_string(&signed(
                    4,
                    &key,
                    revision.clone(),
                    vec!["production".into(), "3".into()]
                ))
                .unwrap()
            ),
            AgentRejection::InvalidArguments,
        ),
    ] {
        assert!(
            matches!(peer(&path,uid,gid,groups,&input,false),AgentResponse::Rejected{category,..} if category==expected)
        );
        assert_eq!(count(&root), 0);
        assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
        assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    }
    // Thirty-two admitted partial frames hold capacity; the thirty-third is closed.
    let mut capacity = Command::new("python3");
    capacity.args(["-c", r#"import os,socket,fcntl,struct,time,json
held=[]
for i in range(32):
 s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(os.environ['SOCKET']);s.sendall(b'{')
 deadline=time.monotonic()+2
 while struct.unpack('i',fcntl.ioctl(s,0x5411,struct.pack('i',0)))[0]:
  assert time.monotonic()<deadline
  time.sleep(.001)
 held.append(s)
extra=socket.socket(socket.AF_UNIX);extra.settimeout(2);extra.connect(os.environ['SOCKET'])
try: assert extra.recv(1)==b''
except ConnectionResetError: pass
extra.close()
for s in held:s.shutdown(socket.SHUT_WR)
for s in held:
 data=b''
 while True:
  b=s.recv(1024)
  if not b:break
  data+=b
 assert json.loads(data)['category']=='malformed'
 s.close()
s=socket.socket(socket.AF_UNIX);s.settimeout(3);s.connect(os.environ['SOCKET']);s.sendall(b'{bad}\n');s.shutdown(socket.SHUT_WR)
data=b''
while True:
 b=s.recv(1024)
 if not b:break
 data+=b
assert json.loads(data)['category']=='malformed'
"#]).env("SOCKET",&path);
    identity(&mut capacity, 8, 9, vec![7]);
    let observed = capacity.output().unwrap();
    assert!(
        observed.status.success(),
        "{}",
        String::from_utf8_lossy(&observed.stderr)
    );
    assert_eq!(count(&root), 0);
    assert_eq!(launcher.0.load(Ordering::SeqCst), 0);
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    // Required membership is independently witnessed in primary and supplementary sets.
    assert!(matches!(
        peer(&path, 8, 9, vec![7], &encoded, false),
        AgentResponse::Pending { .. }
    ));
    assert!(matches!(
        peer(&path, 8, 9, vec![7], &encoded, false),
        AgentResponse::Rejected {
            category: AgentRejection::Replay,
            ..
        }
    ));
    let supplementary = format!(
        "{}\n",
        serde_json::to_string(&signed(
            5,
            &key,
            revision.clone(),
            vec!["staging".into(), "3".into()]
        ))
        .unwrap()
    );
    assert!(matches!(
        peer(&path, 8, 10, vec![7, 9], &supplementary, false),
        AgentResponse::Pending { .. }
    ));
    assert_eq!(count(&root), 2);
    assert_eq!(launcher.0.load(Ordering::SeqCst), 2);
    // Copy the executable outside private /home ancestors for the separate UID.
    let binary = dir.path().join("vw-access");
    fs::copy(assert_cmd::cargo::cargo_bin!("vw-access"), &binary).unwrap();
    fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
    let seed_directory = traversal_only.join("private-agent");
    fs::create_dir(&seed_directory).unwrap();
    set_owner(&seed_directory, 8, 9);
    let seed = seed_directory.join("agent-seed");
    fs::write(&seed, [7u8; 32]).unwrap();
    let seed_c = std::ffi::CString::new(seed.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::chown(seed_c.as_ptr(), 8, 9) }, 0);
    fs::set_permissions(&seed, fs::Permissions::from_mode(0o600)).unwrap();
    fs::set_permissions(&seed_directory, fs::Permissions::from_mode(0o100)).unwrap();
    fs::set_permissions(&traversal_only, fs::Permissions::from_mode(0o111)).unwrap();
    let mut traversal = Command::new("python3");
    traversal.args(["-c", "import os,sys\nfor path in sys.argv[1:]:\n try: os.listdir(path)\n except PermissionError: pass\n else: raise AssertionError('directory unexpectedly readable')"]).arg(&traversal_only).arg(&seed_directory);
    identity(&mut traversal, 8, 10, vec![7, 9]);
    assert!(traversal.status().unwrap().success());
    let mut client = Command::new(&binary);
    client
        .args(["submit", "deploy", "--socket"])
        .arg(&path)
        .arg("--key-file")
        .arg(&seed)
        .arg("--binding-id")
        .arg(&agent.id)
        .arg("--revision")
        .arg(&revision)
        .args(["--", "staging", "3"])
        .env_remove("VAULTWARDEN_ACCESS_STATE_ROOT");
    identity(&mut client, 8, 10, vec![7, 9]);
    let output = client.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(matches!(
        AgentResponse::parse(&output.stdout).unwrap(),
        AgentResponse::Pending { .. }
    ));
    assert_eq!(count(&root), 3);
    assert_eq!(launcher.0.load(Ordering::SeqCst), 3);
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    // Each client identity guard is independently invalid, with otherwise valid
    // directory modes, signing key, envelope and live listener.
    for socket_owner_mismatch in [true, false] {
        let endpoint = dir.path().join(if socket_owner_mismatch {
            "wrong-socket-owner"
        } else {
            "wrong-peer-uid"
        });
        fs::create_dir(&endpoint).unwrap();
        fs::set_permissions(&endpoint, fs::Permissions::from_mode(0o750)).unwrap();
        set_owner(&endpoint, if socket_owner_mismatch { 0 } else { 10 }, 7);
        let socket_path = endpoint.join("agent.sock");
        // The listener's captured kernel UID is zero in both cases.
        let listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o660)).unwrap();
        set_owner(&socket_path, 10, 7);
        let mut client = Command::new(&binary);
        client
            .args(["submit", "deploy", "--socket"])
            .arg(&socket_path)
            .arg("--key-file")
            .arg(&seed)
            .arg("--binding-id")
            .arg(&agent.id)
            .arg("--revision")
            .arg(&revision)
            .args(["--", "staging", "3"])
            .env_remove("VAULTWARDEN_ACCESS_STATE_ROOT");
        identity(&mut client, 8, 10, vec![7, 9]);
        let output = client.output().unwrap();
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.stderr, b"vw-access: agent transport unavailable\n");
        listener.set_nonblocking(true).unwrap();
        if socket_owner_mismatch {
            assert_eq!(
                listener.accept().unwrap_err().kind(),
                std::io::ErrorKind::WouldBlock
            );
        } else {
            let (mut stream, _) = listener.accept().unwrap();
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut payload = Vec::new();
            std::io::Read::read_to_end(&mut stream, &mut payload).unwrap();
            assert!(
                payload.is_empty(),
                "kernel UID mismatch must prevent signed payload"
            );
        }
    }
    stop.store(true, Ordering::Release);
    runtime.block_on(worker).unwrap().unwrap();
    human_worker.join().unwrap().unwrap();
    app.shutdown().unwrap();
    assert!(!path.exists());
}
