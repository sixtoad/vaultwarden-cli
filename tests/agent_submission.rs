//! Real distinct-UID/group and stdin-closed CLI evidence in an isolated user namespace.
#![cfg(target_os = "linux")]
#[path = "support/bounded_process.rs"]
#[allow(dead_code)]
mod bounded_process;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use bounded_process::BoundedChild;
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
        protocol::{
            AgentRejection, AgentResponse, AgentStatus, SignedStatusQuery, SignedSubmission,
        },
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
fn peer_bytes(
    path: &Path,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    bytes: &str,
    no_write: bool,
) -> Vec<u8> {
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
    let output = bounded_process::output(&mut command);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    output.stdout
}
fn peer(
    path: &Path,
    uid: u32,
    gid: u32,
    groups: Vec<u32>,
    bytes: &str,
    no_write: bool,
) -> AgentResponse {
    AgentResponse::parse(&peer_bytes(path, uid, gid, groups, bytes, no_write)).unwrap()
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
    let observed = bounded_process::output(&mut capacity);
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
    let output = bounded_process::output(&mut client);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let AgentResponse::Pending {
        request_id: cli_id, ..
    } = AgentResponse::parse(&output.stdout).unwrap()
    else {
        panic!("expected receipt")
    };
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
        let output = bounded_process::output(&mut client);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert_eq!(output.status.code(), Some(3));
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stderr).unwrap(),
            serde_json::json!({"event":"client_error","category":"transport_uncertain","request_id":null})
        );
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

    // Story 2.3: real kernel peers authenticate every observation, without
    // accessing provider state, stdin, a controlling TTY, or browser authority.
    let query = |nonce, id: &str| {
        SignedStatusQuery::sign(agent.id.clone(), [nonce; 32], id.into(), &key).unwrap()
    };
    let wire = |query: &SignedStatusQuery| format!("{}\n", serde_json::to_string(query).unwrap());
    let snapshot = || -> serde_json::Value {
        serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap()
    };
    let before = snapshot();
    for (nonce, gid, groups) in [(40, 9, vec![7]), (41, 10, vec![7, 9])] {
        let raw = peer_bytes(&path, 8, gid, groups, &wire(&query(nonce, &cli_id)), false);
        assert_eq!(
            AgentResponse::parse(&raw).unwrap(),
            AgentResponse::Status {
                protocol_version: 1,
                request_id: cli_id.clone(),
                state: AgentStatus::Pending
            }
        );
        for sentinel in [
            "namespace-agent",
            "Deploy login",
            "DEPLOY_PASSWORD",
            "http",
            "secret",
            "capability",
        ] {
            assert!(!String::from_utf8_lossy(&raw).contains(sentinel));
        }
    }
    assert_eq!(snapshot()["requests"], before["requests"]);
    assert_eq!(snapshot()["agent_audit"], before["agent_audit"]);
    assert_eq!(
        snapshot()["query_replay_markers"].as_array().unwrap().len(),
        2
    );
    for replay in [query(1, &cli_id), query(40, &cli_id)] {
        assert!(matches!(
            peer(&path, 8, 9, vec![7], &wire(&replay), false),
            AgentResponse::Rejected {
                category: AgentRejection::Replay,
                ..
            }
        ));
    }
    let replay_submit = signed(
        40,
        &key,
        revision.clone(),
        vec!["staging".into(), "3".into()],
    );
    assert!(matches!(
        peer(
            &path,
            8,
            9,
            vec![7],
            &format!("{}\n", serde_json::to_string(&replay_submit).unwrap()),
            false
        ),
        AgentResponse::Rejected {
            category: AgentRejection::Replay,
            ..
        }
    ));

    let other_key = SigningKey::from_bytes(&[8; 32]);
    let HumanResponse::AgentPaired { agent: other } = exchange(
        &root,
        HumanCommand::AgentPair {
            pairing: AgentPairing {
                label: "independently-eligible-other".into(),
                public_key: URL_SAFE_NO_PAD.encode(other_key.verifying_key().to_bytes()),
                uid: 10,
                gid: 9,
            },
        },
    )
    .unwrap() else {
        panic!("other pairing failed")
    };
    // Otherwise eligible UID/group evidence keeps selected-binding group checks independent.
    let decoy_key = SigningKey::from_bytes(&[9; 32]);
    assert!(matches!(
        exchange(
            &root,
            HumanCommand::AgentPair {
                pairing: AgentPairing {
                    label: "group-decoy".into(),
                    public_key: URL_SAFE_NO_PAD.encode(decoy_key.verifying_key().to_bytes()),
                    uid: 8,
                    gid: 10,
                }
            }
        )
        .unwrap(),
        HumanResponse::AgentPaired { .. }
    ));
    let unknown = URL_SAFE_NO_PAD.encode([231; 32]);
    let rejected =
        b"{\"status\":\"rejected\",\"protocol_version\":1,\"category\":\"unauthorized\"}\n";
    let before = snapshot();
    for id in [&cli_id, &unknown] {
        let q =
            SignedStatusQuery::sign(other.id.clone(), [42; 32], id.clone(), &other_key).unwrap();
        assert_eq!(
            peer_bytes(&path, 10, 9, vec![7], &wire(&q), false),
            rejected
        );
    }
    let mut tampered = query(43, &cli_id);
    tampered.request_id = unknown.clone();
    let bad_key =
        SignedStatusQuery::sign(agent.id.clone(), [43; 32], cli_id.clone(), &other_key).unwrap();
    let unpaired =
        SignedStatusQuery::sign(unknown.clone(), [43; 32], cli_id.clone(), &key).unwrap();
    for (uid, gid, groups, q) in [
        (10, 9, vec![7], query(43, &cli_id)),
        (8, 10, vec![7], query(43, &cli_id)),
        (0, 9, vec![7], query(43, &cli_id)),
        (8, 9, vec![7], tampered),
        (8, 9, vec![7], bad_key),
        (8, 9, vec![7], unpaired),
        (8, 9, vec![7], query(43, &unknown)),
    ] {
        assert_eq!(
            peer_bytes(&path, uid, gid, groups, &wire(&q), false),
            rejected
        );
    }
    assert_eq!(
        snapshot(),
        before,
        "rejected polling must not consume markers or alter audit"
    );

    let cli = |verb: &str, id: &str| {
        let mut command = Command::new(&binary);
        command
            .arg(verb)
            .arg(id)
            .arg("--socket")
            .arg(&path)
            .arg("--key-file")
            .arg(&seed)
            .arg("--binding-id")
            .arg(&agent.id)
            .env_remove("VAULTWARDEN_ACCESS_STATE_ROOT");
        identity(&mut command, 8, 10, vec![7, 9]);
        command
    };
    let before = snapshot();
    let poll = bounded_process::output(&mut cli("poll", &cli_id));
    assert!(poll.status.success());
    assert!(poll.stderr.is_empty());
    assert!(matches!(
        AgentResponse::parse(&poll.stdout).unwrap(),
        AgentResponse::Status {
            state: AgentStatus::Pending,
            ..
        }
    ));
    let wait = bounded_process::output(cli("wait", &cli_id).args(["--timeout-seconds", "1"]));
    assert_eq!(wait.status.code(), Some(4));
    assert_eq!(
        wait.stdout
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .count(),
        1,
        "unchanged state emitted once"
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&wait.stderr).unwrap(),
        serde_json::json!({"event":"client_error","category":"wait_timeout","request_id":cli_id})
    );
    let resumed = bounded_process::output(&mut cli("poll", &cli_id));
    assert!(resumed.status.success());
    assert_eq!(snapshot()["requests"], before["requests"]);
    assert_eq!(snapshot()["agent_audit"], before["agent_audit"]);
    assert_eq!(count(&root), 3);

    let mut submit_wait = Command::new(&binary);
    submit_wait
        .args([
            "submit",
            "deploy",
            "--wait",
            "--timeout-seconds",
            "1",
            "--socket",
        ])
        .arg(&path)
        .arg("--key-file")
        .arg(&seed)
        .arg("--binding-id")
        .arg(&agent.id)
        .arg("--revision")
        .arg(&revision)
        .args(["--", "staging", "3"]);
    identity(&mut submit_wait, 8, 10, vec![7, 9]);
    let observed = bounded_process::output(&mut submit_wait);
    assert_eq!(observed.status.code(), Some(4));
    let lines: Vec<_> = observed
        .stdout
        .split(|b| *b == b'\n')
        .filter(|line| !line.is_empty())
        .collect();
    assert_eq!(lines.len(), 2);
    let AgentResponse::Pending {
        request_id: waited_id,
        ..
    } = AgentResponse::parse(lines[0]).unwrap()
    else {
        panic!("receipt must precede observation")
    };
    assert!(matches!(
        AgentResponse::parse(lines[1]).unwrap(),
        AgentResponse::Status {
            state: AgentStatus::Pending,
            ..
        }
    ));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&observed.stderr).unwrap()["request_id"],
        waited_id
    );
    assert_eq!(count(&root), 4, "wait must never resubmit");
    assert_eq!(launcher.0.load(Ordering::SeqCst), 4);
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);

    // Kernel send-queue consumption proves admitted reading of a harmless JSON
    // whitespace prefix. Pipe synchronization withholds the signed query until
    // revocation completes; no competing waiter holds the authority gate.
    use std::io::{BufRead, Read, Write};
    let mut held = Command::new("python3");
    held.args([
        "-c",
        r#"import os,socket,sys,fcntl,struct,time
s=socket.socket(socket.AF_UNIX);s.settimeout(8);s.connect(os.environ['SOCKET'])
s.sendall(b' ')
deadline=time.monotonic()+3
while struct.unpack('i',fcntl.ioctl(s,0x5411,struct.pack('i',0)))[0]:
 assert time.monotonic()<deadline
s.setblocking(False)
try: s.recv(1,socket.MSG_PEEK)
except BlockingIOError: pass
else: raise AssertionError('preflight rejected before query')
s.settimeout(8)
print('admitted',flush=True)
assert sys.stdin.readline()=='go\n'
s.sendall(os.environ['PAYLOAD'].encode());s.shutdown(socket.SHUT_WR)
data=b''
while True:
 chunk=s.recv(1024)
 if not chunk:break
 data+=chunk
sys.stdout.buffer.write(data)
"#,
    ])
    .env("SOCKET", &path)
    .env("PAYLOAD", wire(&query(49, &cli_id)));
    identity(&mut held, 8, 9, vec![7]);
    let mut held = BoundedChild::spawn(
        held.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped()),
    );
    let mut held_stdout = std::io::BufReader::new(held.stdout());
    let (mut held_stdout, ready) = bounded_process::io(move || {
        let mut ready = String::new();
        held_stdout.read_line(&mut ready).unwrap();
        (held_stdout, ready)
    });
    assert_eq!(ready, "admitted\n");
    let revoked = exchange(
        &root,
        HumanCommand::AgentRevoke {
            id: agent.id.clone(),
        },
    )
    .unwrap();
    assert!(!matches!(revoked, HumanResponse::Rejected { .. }));
    held.stdin().write_all(b"go\n").unwrap();
    let held_raw = bounded_process::io(move || {
        let mut bytes = Vec::new();
        held_stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    assert_eq!(held_raw, rejected);
    assert!(held.wait_with_output().status.success());
    // A separate owner/phase tests active waiting, so its periodic gate access
    // cannot mask the held-connection authorization check with legitimate Busy.
    let other_submission = SignedSubmission::sign(
        other.id.clone(),
        [60; 32],
        "deploy".into(),
        revision.clone(),
        vec!["staging".into(), "3".into()],
        &other_key,
    )
    .unwrap();
    let AgentResponse::Pending {
        request_id: other_id,
        ..
    } = peer(
        &path,
        10,
        9,
        vec![7],
        &format!("{}\n", serde_json::to_string(&other_submission).unwrap()),
        false,
    )
    else {
        panic!("other request receipt")
    };
    let other_seed = dir.path().join("other-seed");
    fs::write(&other_seed, [8; 32]).unwrap();
    set_owner(&other_seed, 10, 9);
    fs::set_permissions(&other_seed, fs::Permissions::from_mode(0o600)).unwrap();
    let mut waiting = Command::new(&binary);
    waiting
        .arg("wait")
        .arg(&other_id)
        .arg("--socket")
        .arg(&path)
        .arg("--key-file")
        .arg(&other_seed)
        .arg("--binding-id")
        .arg(&other.id);
    identity(&mut waiting, 10, 9, vec![7]);
    let mut waiting = BoundedChild::spawn(waiting.stdout(Stdio::piped()).stderr(Stdio::piped()));
    let mut waiting_stdout = std::io::BufReader::new(waiting.stdout());
    let (mut waiting_stdout, first) = bounded_process::io(move || {
        let mut first = String::new();
        waiting_stdout.read_line(&mut first).unwrap();
        (waiting_stdout, first)
    });
    assert!(matches!(
        AgentResponse::parse(first.as_bytes()).unwrap(),
        AgentResponse::Status {
            state: AgentStatus::Pending,
            ..
        }
    ));
    assert!(matches!(
        exchange(
            &root,
            HumanCommand::AgentRevoke {
                id: other.id.clone()
            }
        )
        .unwrap(),
        HumanResponse::AgentRevoked { .. }
    ));
    let later = bounded_process::io(move || {
        let mut bytes = Vec::new();
        waiting_stdout.read_to_end(&mut bytes).unwrap();
        bytes
    });
    assert_eq!(later, rejected);
    assert_eq!(waiting.wait_with_output().status.code(), Some(1));
    let before = snapshot();
    assert_eq!(
        peer_bytes(&path, 8, 9, vec![7], &wire(&query(50, &unknown)), false),
        rejected
    );
    assert_eq!(
        peer_bytes(&path, 8, 9, vec![7], &wire(&query(50, &cli_id)), false),
        rejected
    );
    assert_eq!(snapshot(), before);
    assert_eq!(count(&root), 5);
    assert_eq!(launcher.0.load(Ordering::SeqCst), 5);
    assert_eq!(resolutions.load(Ordering::SeqCst), 0);
    stop.store(true, Ordering::Release);
    runtime.block_on(worker).unwrap().unwrap();
    bounded_process::join(human_worker).unwrap();
    app.shutdown().unwrap();
    assert!(!path.exists());
}
