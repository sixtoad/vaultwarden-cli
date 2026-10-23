//! Explicit real-backend pilot. No HTTP decision client or synthetic provider.
use super::*;
use std::net::{IpAddr, SocketAddr};

const PHASES: [&str; 5] = [
    "human-deny",
    "human-approve",
    "agent-deny",
    "agent-approve",
    "finish",
];
const OPERATION: &str = "rehearsal-check";

#[derive(serde::Serialize)]
#[serde(tag = "requester", content = "state", rename_all = "snake_case")]
enum ObservedStatus {
    Human(vaultwarden_cli::access::direct_request::DirectStatus),
    Agent(AgentStatus),
}

#[derive(serde::Serialize)]
#[serde(tag = "availability", rename_all = "snake_case")]
enum Historical<T> {
    Unavailable,
    Observed {
        observed_at_unix_ms: Option<u64>,
        freshness: &'static str,
        value: T,
    },
}

impl<T> Historical<T> {
    fn observed(value: T) -> Self {
        Self::Observed {
            observed_at_unix_ms: unix_ms(),
            freshness: "historical_may_be_stale",
            value,
        }
    }
}

#[derive(serde::Serialize)]
struct ObservedCounts {
    execution_starts: usize,
    successful_executions: usize,
    scope: &'static str,
}

#[derive(serde::Serialize)]
struct FailureObservation {
    phase: &'static str,
    phase_started_at_unix_ms: Option<u64>,
    request_id: Option<String>,
    last_observed_status: Historical<ObservedStatus>,
    exact_request_counts: Historical<ObservedCounts>,
}

fn unix_ms() -> Option<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|duration| duration.as_millis().try_into().ok())
}

impl FailureObservation {
    fn new(phase: &'static str) -> Self {
        Self {
            phase,
            phase_started_at_unix_ms: unix_ms(),
            request_id: None,
            last_observed_status: Historical::Unavailable,
            exact_request_counts: Historical::Unavailable,
        }
    }

    fn request(&mut self, id: &str) -> Result<()> {
        ensure!(
            id.len() == 43
                && URL_SAFE_NO_PAD
                    .decode(id)
                    .is_ok_and(|bytes| bytes.len() == 32),
            "pilot invalid request ID"
        );
        self.request_id = Some(id.to_owned());
        Ok(())
    }

    fn status(&mut self, state: &Value, agent: bool) -> Result<()> {
        let status = if agent {
            serde_json::from_value(state.clone()).map(ObservedStatus::Agent)
        } else {
            serde_json::from_value(state.clone()).map(ObservedStatus::Human)
        }
        .map_err(|_error| anyhow::anyhow!("pilot status observation invalid"))?;
        self.last_observed_status = Historical::observed(status);
        Ok(())
    }

    fn history(&mut self, history: &Value) -> Result<()> {
        use vaultwarden_cli::access::history::HistoryOutcome;
        let id = self
            .request_id
            .as_deref()
            .context("pilot invalid request ID")?;
        let events = history["events"]
            .as_array()
            .context("pilot history observation invalid")?;
        ensure!(
            events.len() <= 200
                && events
                    .iter()
                    .all(|event| event["request_id"].is_string() && event["outcome"].is_string()),
            "pilot history observation invalid"
        );
        let mut execution_starts = 0;
        let mut successful_executions = 0;
        for event in events {
            let outcome: HistoryOutcome = serde_json::from_value(event["outcome"].clone())
                .map_err(|_error| anyhow::anyhow!("pilot history observation invalid"))?;
            if event["request_id"] == id {
                execution_starts += usize::from(outcome == HistoryOutcome::ExecutionStarted);
                successful_executions += usize::from(outcome == HistoryOutcome::Succeeded);
            }
        }
        self.exact_request_counts = Historical::observed(ObservedCounts {
            execution_starts,
            successful_executions,
            scope: "observed_bounded_history_only_not_final_totals",
        });
        Ok(())
    }

    fn emit(&self, run: &Rehearsal, error: &anyhow::Error, writer: &mut impl Write) -> Result<()> {
        let record = json!({
            "kind":"pilot_failure_observation_v1",
            "failure_category":failure_category(error),
            "failure_observed_at_unix_ms":unix_ms(),
            "semantics":"historical_observations_not_final_outcome; null timestamps or request ID are unavailable",
            "observation":self,
        });
        let mut bytes = serde_json::to_vec(&record)?;
        ensure!(bytes.len() <= 4096, "pilot failure observation unavailable");
        bytes.push(b'\n');
        run.observe(&bytes)?;
        writer.write_all(&bytes)?;
        writer.flush()?;
        Ok(())
    }
}

fn finish_pilot(
    run: &mut Rehearsal,
    observation: &FailureObservation,
    result: Result<()>,
    writer: &mut impl Write,
) -> Result<()> {
    // Preserve the sanitized observation before cleanup erases private evidence.
    // Emission failure must not skip ownership-verified teardown. Redaction
    // failure still triggers the existing material-retention rule.
    let emitted = if let Err(error) = &result {
        observation.emit(run, error, writer) // mutation: failure evidence
    } else {
        Ok(())
    };
    let cleanup = CleanupObservation::capture(run);
    run.cleanup()?;
    confirm_cleanup(&cleanup)?;
    println!(
        "PASS: independent Linux cleanup verified; transferred Mac files and imported identity are NOT removed"
    );
    emitted.map_err(|_error| anyhow::anyhow!("pilot failure observation unavailable"))?;
    result
}

#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Ready {
    phase: String,
    nonce: String,
}

fn valid_phase(phase: &str) -> Result<()> {
    ensure!(PHASES.contains(&phase), "invalid pilot phase");
    Ok(())
}

fn control_directory(root: &Path) -> Result<PathBuf> {
    ensure!(
        root.file_name().is_some_and(|n| n
            .to_string_lossy()
            .starts_with(".vw-real-vaultwarden-pilot-")),
        "invalid pilot root"
    );
    ensure!(
        !root
            .as_os_str()
            .as_encoded_bytes()
            .split(|b| *b == b'/')
            .any(|p| p == b"." || p == b".."),
        "invalid pilot path"
    );
    safe_home(root)?;
    let directory = root.join("private/control");
    for path in [root.join("private"), directory.clone()] {
        let meta = fs::symlink_metadata(path)?;
        ensure!(
            meta.is_dir()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 == 0o700,
            "unsafe pilot control directory"
        );
    }
    Ok(directory)
}

fn read_control(path: &Path) -> Result<Ready> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.mode() & 0o7777 == 0o600
            && meta.nlink() == 1
            && meta.len() <= 512,
        "unsafe pilot control file"
    );
    let mut data = Vec::new();
    file.take(513).read_to_end(&mut data)?;
    ensure!(data.len() <= 512, "oversized pilot control");
    let value: Ready =
        serde_json::from_slice(&data).map_err(|_error| anyhow::anyhow!("invalid pilot control"))?;
    ensure!(
        value.nonce.len() == 32 && value.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid pilot control nonce"
    );
    Ok(value)
}

fn control(root: &Path, phase: Option<&str>) -> Result<()> {
    let directory = control_directory(root)?;
    let ready = read_control(&directory.join("ready.json"))?;
    if let Some(phase) = phase {
        valid_phase(phase)?;
        ensure!(ready.phase == phase, "pilot phase is not ready");
        // Atomic no-replace publication leaves consumed commands in place.
        // A running observer can never see a partially written control.
        publish_control(
            &directory.join(format!("advance-{phase}.json")),
            &serde_json::to_vec(&ready)?,
        )?;
    } else {
        publish_control(
            &directory.join("stop.json"),
            &serde_json::to_vec(&Ready {
                phase: "stop".into(),
                nonce: ready.nonce,
            })?,
        )?;
    }
    println!("PASS: pilot control accepted; no decision performed");
    Ok(())
}

fn publish_control(path: &Path, data: &[u8]) -> Result<()> {
    let mut temporary = tempfile::NamedTempFile::new_in(path.parent().context("control parent")?)?;
    temporary.write_all(data)?;
    temporary.as_file().sync_all()?;
    let source = std::ffi::CString::new(temporary.path().as_os_str().as_encoded_bytes())?;
    let destination = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())?;
    // Linux is required by this integration test. Fail closed if atomic
    // no-replace rename is unavailable; never emulate with an overwrite.
    ensure!(
        unsafe {
            libc::renameat2(
                libc::AT_FDCWD,
                source.as_ptr(),
                libc::AT_FDCWD,
                destination.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "pilot control already exists or publication failed"
    );
    fs::File::open(path.parent().context("control parent")?)?.sync_all()?;
    Ok(())
}

fn interrupted_or_stopped(root: &Path) -> Result<()> {
    ensure!(!INTERRUPTED.load(Ordering::Relaxed), "pilot interrupted");
    let path = root.join("private/control/stop.json");
    if path_present(&path)? {
        let stop = read_control(&path)?;
        ensure!(stop.phase == "stop", "invalid pilot stop");
        anyhow::bail!("pilot stopped by operator");
    }
    Ok(())
}

fn announce(run: &Rehearsal, phase: &str) -> Result<Ready> {
    valid_phase(phase)?;
    let directory = control_directory(&run.root)?;
    let mut nonce = [0; 16];
    getrandom::fill(&mut nonce).map_err(|_error| anyhow::anyhow!("random source"))?;
    let ready = Ready {
        phase: phase.into(),
        nonce: nonce.iter().map(|b| format!("{b:02x}")).collect(),
    };
    let staging = directory.join(format!("ready-{phase}.json"));
    private_file(&staging, &serde_json::to_vec(&ready)?)?;
    fs::rename(staging, directory.join("ready.json"))?;
    println!(
        "READY: {phase}; advance explicitly after Mac setup/unlock and operator readiness; root={}",
        run.root.display()
    );
    Ok(ready)
}

#[derive(Default)]
struct SubmissionGate {
    consumed: bool,
}
impl SubmissionGate {
    fn admit(&mut self, expected: &Ready, observed: Option<&Ready>) -> Result<bool> {
        if observed.is_none() {
            return Ok(false);
        } // mutation: readiness
        ensure!(
            observed == Some(expected),
            "stale or out-of-order pilot control"
        );
        ensure!(!self.consumed, "pilot submission already consumed"); // mutation: duplicate
        self.consumed = true;
        Ok(true)
    }
}

fn wait_ready(run: &Rehearsal, phase: &str) -> Result<()> {
    let ready = announce(run, phase)?;
    let mut gate = SubmissionGate::default();
    let deadline = Instant::now() + Duration::from_secs(1200);
    let path = run
        .root
        .join(format!("private/control/advance-{phase}.json"));
    loop {
        interrupted_or_stopped(&run.root)?;
        ensure!(
            Instant::now() < deadline,
            "pilot readiness deadline exceeded"
        );
        let observed = if path_present(&path)? {
            Some(read_control(&path)?)
        } else {
            None
        };
        if gate.admit(&ready, observed.as_ref())? {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn endpoint() -> Result<(String, SocketAddr)> {
    let host = std::env::var("VW_PILOT_HOSTNAME").context("VW_PILOT_HOSTNAME required")?;
    ensure!(
        !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|part| !part.is_empty()
                && part.len() <= 63
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')),
        "invalid pilot DNS hostname"
    );
    let address: SocketAddr = std::env::var("VW_PILOT_LISTEN")
        .context("VW_PILOT_LISTEN required")?
        .parse()
        .map_err(|_error| anyhow::anyhow!("invalid pilot listen address"))?;
    let private = match address.ip() {
        IpAddr::V4(ip) => ip.is_private(),
        IpAddr::V6(ip) => ip.is_unique_local(),
    };
    ensure!(
        private && address.port() != 0,
        "pilot requires explicit private LAN address and port"
    );
    Ok((host, address))
}

fn require_unoccupied(load_state: &str, runtime_present: bool) -> Result<()> {
    ensure!(load_state == "not-found", "provider unit collision");
    ensure!(!runtime_present, "supervisor runtime collision");
    Ok(())
}

fn preflight() -> Result<(PathBuf, u32, u32, u32, PathBuf)> {
    ensure!(
        cfg!(any(target_arch = "x86_64", target_arch = "aarch64")),
        "unsupported pilot architecture"
    );
    let home = PathBuf::from(std::env::var_os("HOME").context("home")?);
    safe_home(&home)?;
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    ensure!(uid != 0, "never run as host root");
    let load_state = property(UNIT, "LoadState")?;
    let namespace: String = Sha256::digest(format!("{uid}:{UNIT}").as_bytes())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    let runtime = PathBuf::from(format!("/run/user/{uid}/vw-access-{namespace}"));
    require_unoccupied(&load_state, path_present(&runtime)?)?;
    ensure!(
        Path::new("/sys/fs/cgroup/cgroup.controllers").exists(),
        "cgroup v2 required"
    );
    let user = text(checked(command("/usr/bin/id").arg("-un"))?)?;
    let agent_uid = subordinate_id(&fs::read_to_string("/etc/subuid")?, &user)
        .context("existing subordinate UID required")?;
    let map = text(checked(
        restricted().args(["/usr/bin/cat", "/proc/self/uid_map"]),
    )?)?;
    ensure!(
        map.lines()
            .any(|line| line.split_whitespace().take(2).collect::<Vec<_>>()
                == vec!["1", &agent_uid.to_string()]),
        "kernel restricted identity unavailable"
    );
    ensure!(
        !output(
            restricted().args(["/usr/bin/setpriv", "--reuid=0", "/usr/bin/true"]),
            None,
            5
        )?
        .status
        .success(),
        "agent can regain provider identity"
    );
    require_restricted_traversal(&home)?;
    check_fixture()?;
    Ok((home, uid, gid, agent_uid, runtime))
}

pub fn run() -> Result<()> {
    let action = std::env::var("VW_PILOT_ACTION").context("explicit pilot runner required")?;
    if action == "--advance" || action == "--stop" {
        let root = PathBuf::from(std::env::var_os("VW_PILOT_ROOT").context("pilot root required")?);
        let phase = std::env::var("VW_PILOT_PHASE").ok();
        ensure!(action == "--stop" || phase.is_some(), "phase required");
        return control(
            &root,
            if action == "--advance" {
                phase.as_deref()
            } else {
                None
            },
        );
    }
    ensure!(
        action == "--check" || action == "--run",
        "invalid pilot action"
    );
    let (home, uid, gid, agent_uid, runtime) = preflight()?;
    if action == "--check" {
        println!("PASS: pilot preflight; no resources provisioned");
        return Ok(());
    }
    let (hostname, address) = endpoint()?;
    // Check that the requested interface exists and the port is free before setup.
    drop(std::net::TcpListener::bind(address).context("pilot listen address unavailable")?);
    unsafe {
        libc::signal(libc::SIGINT, interrupted as *const () as libc::sighandler_t);
        libc::signal(
            libc::SIGTERM,
            interrupted as *const () as libc::sighandler_t,
        );
    }
    let root = tempfile::Builder::new()
        .prefix(".vw-real-vaultwarden-pilot-")
        .tempdir_in(home)?
        .keep();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o750))?;
    let mut run = Rehearsal {
        root,
        uid,
        gid,
        agent_uid,
        units: Vec::new(),
        container: None,
        driver: None,
        driver_lines: None,
        runtime,
        runtime_owned: false,
        cleaned: false,
        ownership_uncertain: false,
        secrets: initial_secrets(),
        evidence: RefCell::new(Vec::new()),
        fail_provider_stop: false,
        fail_provider_reap: false,
        fail_after_container_removal: false,
        human_display: None,
        human_mode: true,
        captures: Vec::new(),
        leaked: Cell::new(false),
    };
    run.ledger("owned-directory", "real Vaultwarden pilot root")?;
    println!("SETUP: owned pilot root={}", run.root.display());
    let mut observation = FailureObservation::new("setup");
    let result = execute(&mut run, &hostname, address, &mut observation);
    finish_pilot(&mut run, &observation, result, &mut std::io::stdout())
}

/// Only closed categories may reach the terminal. Never print the underlying
/// OS/upstream error, paths, entered values or response bodies.
pub fn failure_category(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "pilot listen address unavailable" => "listener_unavailable",
        "provider unit collision" => "provider_unit_collision",
        "supervisor runtime collision" => "supervisor_runtime_collision",
        "pilot stopped by operator" => "operator_stopped",
        "pilot interrupted" => "interrupted",
        "pilot private services failed" => "private_services_failed",
        "pilot certificates failed" => "certificates_failed",
        "pilot vault startup failed" => "vault_startup_failed",
        "pilot vault provisioning failed" => "vault_provisioning_failed",
        "pilot enrollment failed" => "enrollment_failed",
        "pilot provider bootstrap failed" => "provider_bootstrap_failed",
        "pilot provider startup failed" => "provider_startup_failed",
        "pilot provider readiness failed" => "provider_readiness_failed",
        "pilot decision deadline exceeded; never resubmit" => "decision_observation_timeout",
        "pilot readiness deadline exceeded" => "readiness_timeout",
        "pilot status poll failed" => "status_poll_failed",
        "pilot status observation invalid" => "invalid_status_observation",
        "pilot invalid request ID" => "invalid_request_id",
        "pilot history read failed" => "history_read_failed",
        "pilot history observation invalid" => "invalid_history_observation",
        "pilot history verification failed" => "history_verification_failed",
        "pilot terminal outcome mismatch; never resubmit" => "unexpected_terminal_status",
        "pilot terminal verification failed" => "unexpected_terminal_status",
        "pilot failure observation unavailable" => "failure_observation_unavailable",
        _ => "operation_failed",
    }
}

fn confirm_cleanup(observation: &CleanupObservation) -> Result<()> {
    observation.verify()?; // mutation: cleanup
    Ok(())
}

fn scan(run: &Rehearsal, bytes: &[u8]) -> Result<()> {
    run.observe(bytes)?; // mutation: redaction
    Ok(())
}

fn register_secret_file(run: &mut Rehearsal, path: &Path) -> Result<()> {
    let bytes = fs::read(path)?;
    run.secrets.push(
        base64::engine::general_purpose::STANDARD
            .encode(&bytes)
            .into_bytes(),
    );
    // Only PEM has meaningful textual secret lines. Splitting a binary PKCS#12
    // can register a single random punctuation byte and reject ordinary JSON.
    if bytes.starts_with(b"-----BEGIN ") {
        for line in bytes
            .split(|b| *b == b'\n')
            .filter(|l| !l.is_empty() && !l.starts_with(b"-----"))
        {
            run.secrets.push(line.to_vec());
        }
    }
    run.secrets.push(bytes);
    Ok(())
}

fn write_quick_setup_bundle(
    run: &mut Rehearsal,
    handoff: &Path,
    endpoint: &str,
    pin: &str,
    fingerprint: &str,
) -> Result<()> {
    fn bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        fs::File::open(path)?
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            !bytes.is_empty() && bytes.len() as u64 <= maximum,
            "invalid pilot bundle material"
        );
        Ok(bytes)
    }
    let ca = bounded(&handoff.join("ca.der"), 65_536)?;
    let identity = bounded(&handoff.join("client.p12"), 1_048_576)?;
    let passphrase = bounded(&handoff.join("identity-passphrase.txt"), 4097)?;
    let passphrase = std::str::from_utf8(&passphrase)?.trim_end_matches('\n');
    ensure!(
        !passphrase.is_empty() && passphrase.len() <= 4096,
        "invalid pilot bundle material"
    );
    ensure!(
        endpoint.len() <= 2048
            && endpoint.starts_with("https://")
            && [pin, fingerprint].iter().all(|value| value.len() == 64
                && value
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "invalid pilot bundle metadata"
    );
    let encoded_identity = base64::engine::general_purpose::STANDARD.encode(&identity);
    // Register both raw and encoded private material before the bundle exists.
    run.secrets.push(identity);
    run.secrets.push(encoded_identity.as_bytes().to_vec());
    run.secrets.push(passphrase.as_bytes().to_vec());
    run.secrets.push(PASSWORD.as_bytes().to_vec());
    let bundle = serde_json::to_vec(&json!({
        "version": 1,
        "kind": "disposable-companion-pilot",
        "endpoint": endpoint,
        "leaf_sha256": pin,
        "client_sha256": fingerprint,
        "ca_der": base64::engine::general_purpose::STANDARD.encode(ca),
        "pkcs12": encoded_identity,
        "import_passphrase": passphrase,
        "unlock_password": PASSWORD,
    }))?;
    ensure!(bundle.len() <= 1_600_000, "oversized pilot bundle");
    run.secrets.push(bundle.clone());
    private_file(&handoff.join("quick-setup.json"), &bundle)?;
    Ok(())
}

fn certificates(run: &mut Rehearsal, tls: &Path, host: &str) -> Result<PathBuf> {
    let handoff = run.root.join("private/mac-handoff");
    directory(&handoff, 0o700)?;
    for (name, purpose) in [
        ("companion-server", "serverAuth"),
        ("companion-client", "clientAuth"),
    ] {
        checked(
            command("/usr/bin/openssl")
                .args([
                    "req",
                    "-new",
                    "-newkey",
                    "rsa:2048",
                    "-nodes",
                    "-subj",
                    &format!("/CN=Disposable pilot {name}"),
                    "-keyout",
                ])
                .arg(tls.join(format!("{name}.key")))
                .arg("-out")
                .arg(tls.join(format!("{name}.csr"))),
        )?;
        let extensions = format!(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage={purpose}\n{}",
            if purpose == "serverAuth" {
                format!("subjectAltName=DNS:{host}\n")
            } else {
                String::new()
            }
        );
        private_file(&tls.join(format!("{name}.ext")), extensions.as_bytes())?;
        let mut serial = [0u8; 16];
        getrandom::fill(&mut serial).map_err(|_error| anyhow::anyhow!("random source"))?;
        let serial: String = serial.iter().map(|b| format!("{b:02x}")).collect();
        checked(
            command("/usr/bin/openssl")
                .args(["x509", "-req", "-days", "2", "-in"])
                .arg(tls.join(format!("{name}.csr")))
                .arg("-CA")
                .arg(tls.join("ca.pem"))
                .arg("-CAkey")
                .arg(tls.join("ca.key"))
                .args(["-set_serial", &format!("0x{serial}"), "-extfile"])
                .arg(tls.join(format!("{name}.ext")))
                .arg("-out")
                .arg(tls.join(format!("{name}.pem"))),
        )?;
    }
    // The shared setup's public certificate mode is made explicit for enrollment.
    for entry in fs::read_dir(tls)? {
        fs::set_permissions(entry?.path(), fs::Permissions::from_mode(0o600))?;
    }
    for name in ["companion-server.key", "companion-client.key"] {
        register_secret_file(run, &tls.join(name))?;
    }
    let mut password = [0; 32];
    getrandom::fill(&mut password).map_err(|_error| anyhow::anyhow!("random source"))?;
    let password = URL_SAFE_NO_PAD.encode(password); // secrets-ignore: encoding fresh random bytes, not a credential literal
    run.secrets.push(password.as_bytes().to_vec());
    private_file(
        &handoff.join("identity-passphrase.txt"),
        format!("{password}\n").as_bytes(),
    )?;
    private_file(
        &handoff.join("vault-password.txt"),
        format!("{PASSWORD}\n").as_bytes(),
    )?;
    checked(
        command("/usr/bin/openssl")
            .args([
                "pkcs12",
                "-export",
                "-keypbe",
                "PBE-SHA1-3DES",
                "-certpbe",
                "PBE-SHA1-3DES",
                "-macalg",
                "sha1",
                "-inkey",
            ])
            .arg(tls.join("companion-client.key"))
            .arg("-in")
            .arg(tls.join("companion-client.pem"))
            .arg("-certfile")
            .arg(tls.join("ca.pem"))
            .args(["-name", "Disposable Flutter real Vaultwarden pilot", "-out"])
            .arg(handoff.join("client.p12"))
            .arg("-passout")
            .arg(format!(
                "file:{}",
                handoff.join("identity-passphrase.txt").display()
            )),
    )?;
    checked(
        command("/usr/bin/openssl")
            .args(["x509", "-in"])
            .arg(tls.join("ca.pem"))
            .args(["-outform", "DER", "-out"])
            .arg(handoff.join("ca.der")),
    )?;
    for entry in fs::read_dir(&handoff)? {
        fs::set_permissions(entry?.path(), fs::Permissions::from_mode(0o600))?;
    }
    register_secret_file(run, &handoff.join("client.p12"))?;
    Ok(handoff)
}

fn start_vault(run: &mut Rehearsal, tls: &Path) -> Result<String> {
    run.ownership_uncertain = true;
    let id = text(checked(run.docker().args([
        "create",
        "--label",
        &format!(
            "vw.rehearsal={}",
            run.root.file_name().unwrap().to_string_lossy()
        ),
        "--publish",
        "127.0.0.1::80",
        "--tmpfs",
        "/data:rw,nosuid,nodev,noexec",
        "--mount",
        &format!(
            "type=bind,src={},dst=/rehearsal-tls/server.pem,readonly",
            tls.join("server.pem").display()
        ),
        "--mount",
        &format!(
            "type=bind,src={},dst=/rehearsal-tls/server.key,readonly",
            tls.join("server.key").display()
        ),
        "--env",
        "SIGNUPS_ALLOWED=true",
        "--env",
        "LOG_LEVEL=error",
        "--env",
        "ROCKET_TLS={certs=\"/rehearsal-tls/server.pem\",key=\"/rehearsal-tls/server.key\"}",
        "vaultwarden/server:1.36.0",
    ]))?)?;
    ensure!(
        id.len() == 64 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid owned container ID"
    );
    run.container = Some(id.clone());
    run.ledger("owned-container", &id)?;
    run.ownership_uncertain = false;
    checked(run.docker().args(["start", &id]))?;
    let address = text(checked(run.docker().args(["port", &id, "80/tcp"]))?)?;
    let parsed: SocketAddr = address
        .parse()
        .map_err(|_error| anyhow::anyhow!("invalid backend address"))?;
    ensure!(
        parsed.ip() == IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        "non-loopback backend"
    );
    let ids = setup_vault_items(
        run,
        &format!("https://{address}"),
        &tls.join("ca.pem"),
        &[(OPERATION, FIELD)],
    )
    .context("pilot vault provisioning failed")?;
    Ok(ids[0].clone())
}

fn execute(
    run: &mut Rehearsal,
    hostname: &str,
    address: SocketAddr,
    observation: &mut FailureObservation,
) -> Result<()> {
    let (checker, agent_public, tls) =
        setup_private_services(run).context("pilot private services failed")?;
    directory(&run.root.join("private/control"), 0o700)?;
    let handoff = certificates(run, &tls, hostname).context("pilot certificates failed")?;
    let item = start_vault(run, &tls).map_err(|error| {
        if failure_category(&error) == "vault_provisioning_failed" {
            error
        } else {
            error.context("pilot vault startup failed")
        }
    })?;
    let state = run.root.join("private/state");
    bootstrap_provider(run, &state).context("pilot provider bootstrap failed")?;
    let mut enroll = command(run.root.join("bin/vaultwarden-accessd"));
    run.env(&mut enroll);
    let enrolled = checked(
        enroll
            .arg("--state-root")
            .arg(&state)
            .arg("--companion-enroll-cert")
            .arg(tls.join("companion-client.pem"))
            .arg("--companion-client-ca")
            .arg(tls.join("ca.pem"))
            .args([
                "--companion-label",
                "Disposable Flutter real Vaultwarden pilot",
            ]),
    )
    .context("pilot enrollment failed")?;
    let fingerprint = text(enrolled)?;
    ensure!(
        fingerprint.len() == 64 && fingerprint.bytes().all(|b| b.is_ascii_hexdigit()),
        "invalid enrollment fingerprint"
    );
    let der = checked(
        command("/usr/bin/openssl")
            .args(["x509", "-in"])
            .arg(tls.join("companion-server.pem"))
            .args(["-outform", "DER"]),
    )?;
    let pin: String = Sha256::digest(der)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    write_quick_setup_bundle(
        run,
        &handoff,
        &format!("https://{hostname}:{}", address.port()),
        &pin,
        &fingerprint,
    )?;
    let public = json!({"endpoint":format!("https://{hostname}:{}", address.port()),"server_leaf_sha256":pin,"client_certificate_sha256":fingerprint,"mac_files":["ca.der","client.p12","identity-passphrase.txt","vault-password.txt"],"mac_cleanup":"Separate tracking required; imported identity retained until exact cleanup agreed"});
    private_file(
        &handoff.join("public.json"),
        &serde_json::to_vec_pretty(&public)?,
    )?;
    run.ledger_record(&json!({"event":"mac-handoff-source","resource":"private/mac-handoff","client_fingerprint":fingerprint,"transferred_copies":"operator records exact destinations separately","keychain_cleanup":"not performed by Linux"}))?;
    let mut provider = run.service_env();
    provider.extend([
        format!("SSL_CERT_FILE={}", tls.join("ca.pem").display()),
        run.root
            .join("bin/vaultwarden-accessd")
            .display()
            .to_string(),
        "--state-root".into(),
        state.display().to_string(),
        "--backend-config".into(),
        run.root.join("private/setup.json").display().to_string(),
        "--agent-socket-dir".into(),
        run.root.join("socket").display().to_string(),
        "--agent-socket-gid".into(),
        run.gid.to_string(),
        "--companion-listen".into(),
        address.to_string(),
        "--companion-tls-cert".into(),
        tls.join("companion-server.pem").display().to_string(),
        "--companion-tls-key".into(),
        tls.join("companion-server.key").display().to_string(),
        "--companion-client-ca".into(),
        tls.join("ca.pem").display().to_string(),
    ]);
    run.runtime_owned = true;
    run.start_unit(UNIT, &provider)
        .context("pilot provider startup failed")?;
    wait_for(|| {
        Ok(state.join("human.sock").exists() && run.root.join("socket/agent.sock").exists())
    })
    .context("pilot provider readiness failed")?;
    println!(
        "SETUP: real disposable Vaultwarden ready; private Mac handoff directory={}",
        handoff.display()
    );
    println!(
        "SETUP: endpoint=https://{hostname}:{}; server_leaf_sha256={pin}; client_certificate_sha256={fingerprint}",
        address.port()
    );
    for name in [
        "vaultwarden-accessd",
        "vaultwarden-access-exec",
        "vw-access",
    ] {
        let digest: String = Sha256::digest(fs::read(run.root.join("bin").join(name))?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        println!("BINARY: {name} sha256={digest}");
    }
    for private in [
        "private/state",
        "private/setup.json",
        "private/bus",
        "private/mac-handoff",
        "private/tls/companion-server.key",
    ] {
        ensure!(
            !output(
                restricted()
                    .args(["/usr/bin/test", "-r"])
                    .arg(run.root.join(private)),
                None,
                5
            )?
            .status
            .success(),
            "agent reached private material"
        );
    }
    // First readiness also confirms the operator has preserved prior Flutter
    // configuration, imported the dedicated identity and unlocked in Flutter.
    *observation = FailureObservation::new(PHASES[0]);
    wait_ready(run, PHASES[0])?;
    // Register the actual production unlock session in the private leak corpus.
    // This is never output or copied to the Mac/requester.
    let mut session = command("/usr/bin/secret-tool");
    run.env(&mut session);
    let session: Value = serde_json::from_slice(&checked(session.args([
        "lookup",
        "service",
        "vaultwarden-accessd",
        "username",
        "revocable-session",
    ]))?)?;
    for key in ["access_token", "enc_key", "mac_key"] {
        run.secrets.push(
            session[key]
                .as_str()
                .context("private provider session audit")?
                .as_bytes()
                .to_vec(),
        );
    }
    let registered = run.cli(&[
        "image",
        "register",
        "--id",
        "credential-check",
        "--execution-root",
        &run.root.join("private").display().to_string(),
        "--path",
        &checker.display().to_string(),
        "--sha256",
        &Sha256::digest(fs::read(&checker)?)
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>(),
        "--profile",
        "reviewed_self_contained_elf64_v1",
    ])?;
    scan(run, &serde_json::to_vec(&registered)?)?;
    let policy = run.root.join("private/pilot-operation.json");
    private_file(
        &policy,
        &serde_json::to_vec(
            &json!({"id":OPERATION,"description":"Validate disposable injected field","image_id":"credential-check","targets":[TARGET],"arguments":[{"type":"target"}],"credentials":[{"item_id":item,"label":"Disposable rehearsal Login","use_type":"login","field_mappings":[{"field":{"custom":{"name":"rehearsal-field"}},"environment":"REHEARSAL_CREDENTIAL"}]}]}),
        )?,
    )?;
    let created = run.cli(&[
        "operation",
        "create",
        "--file",
        &policy.display().to_string(),
    ])?;
    let revision = created["operation"]["revision"]
        .as_str()
        .context("policy revision")?;
    let paired = run.cli(&[
        "agent",
        "pair",
        "Disposable restricted pilot agent",
        "--public-key",
        &agent_public,
        "--uid",
        &run.agent_uid.to_string(),
        "--gid",
        &run.gid.to_string(),
    ])?;
    let binding = paired["agent"]["id"].as_str().context("paired binding")?;
    let socket = run.root.join("socket/agent.sock").display().to_string();
    let key = run.root.join("agent/key").display().to_string();
    let mut completed = Vec::new();
    for (index, phase) in PHASES[..4].iter().enumerate() {
        if index > 0 {
            *observation = FailureObservation::new(phase);
            wait_ready(run, phase)?;
        }
        let agent = phase.starts_with("agent");
        let approve = phase.ends_with("approve");
        let receipt = if agent {
            run.agent(
                AgentAction::Submit,
                &[
                    OPERATION,
                    "--socket",
                    &socket,
                    "--key-file",
                    &key,
                    "--binding-id",
                    binding,
                    "--revision",
                    revision,
                    "--",
                    TARGET,
                ],
            )?
        } else {
            run.cli(&[
                "request",
                OPERATION,
                "--revision",
                revision,
                "--no-wait",
                "--",
                TARGET,
            ])?
        };
        let id = receipt["request_id"]
            .as_str()
            .or_else(|| receipt["receipt"]["id"].as_str())
            .context("pilot receipt")?
            .to_owned();
        observation.request(&id)?;
        ensure!(
            if agent {
                receipt["status"] == "pending"
            } else {
                receipt["receipt"]["status"]["status"] == "pending"
            },
            "pilot request did not enter pending"
        );
        scan(run, &serde_json::to_vec(&receipt)?)?;
        observation.status(&json!({"status":"pending"}), agent)?;
        println!("PENDING: {phase}; request_id={id}; human must decide in foreground Flutter");
        let deadline = Instant::now() + Duration::from_secs(310);
        loop {
            interrupted_or_stopped(&run.root)?;
            ensure!(
                Instant::now() < deadline,
                "pilot decision deadline exceeded; never resubmit"
            );
            let response = if agent {
                run.agent(
                    AgentAction::Poll,
                    &[
                        &id,
                        "--socket",
                        &socket,
                        "--key-file",
                        &key,
                        "--binding-id",
                        binding,
                    ],
                )
                .context("pilot status poll failed")?
            } else {
                run.cli(&["status", &id])
                    .context("pilot status poll failed")?
            };
            scan(run, &serde_json::to_vec(&response)?)?;
            observation.status(&response["state"], agent)?;
            if terminal(&response["state"], agent, approve)
                .context("pilot terminal verification failed")?
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        completed.push((id.clone(), approve));
        let history = run
            .cli(&["history", "--limit", "200"])
            .context("pilot history read failed")?;
        observation.history(&history)?;
        check_history(&history, &completed).context("pilot history verification failed")?;
        println!(
            "PASS: {phase}; request_id={id}; terminal={}; execution_starts={}",
            if approve { "completed" } else { "denied" },
            usize::from(approve)
        );
    }
    // Keep the endpoint alive for human inspection/status recovery until an
    // explicit finish, then verify the whole history again before teardown.
    *observation = FailureObservation::new("finish");
    wait_ready(run, "finish")?;
    verify_final_history(run.cli(&["history", "--limit", "200"]), &completed)?;
    println!(
        "PASS: four human Flutter decisions; two successful credential checks; two denials without execution"
    );
    Ok(())
}

fn initialized_layout(state: &Path) -> Result<()> {
    let directory = fs::symlink_metadata(state)?;
    ensure!(
        directory.is_dir()
            && directory.uid() == unsafe { libc::geteuid() }
            && directory.mode() & 0o7777 == 0o700,
        "provider initialization incomplete"
    );
    for name in [".provider-state.lock", "provider-state.json"] {
        let meta = fs::symlink_metadata(state.join(name))?;
        ensure!(
            meta.is_file()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o7777 == 0o600
                && meta.nlink() == 1,
            "provider initialization incomplete"
        );
        if name == "provider-state.json" {
            ensure!(meta.len() > 0, "provider initialization incomplete");
        }
    }
    // File creation alone precedes composition cleanup. A positive lifecycle
    // generation proves the real daemon completed initialization, not merely
    // that it created a layout before failing during supervisor setup.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(state.join("provider-state.json"))?;
    let mut bytes = Vec::new();
    file.take(1024 * 1024 + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() <= 1024 * 1024,
        "provider initialization incomplete"
    );
    let record: Value = serde_json::from_slice(&bytes)
        .map_err(|_error| anyhow::anyhow!("provider initialization incomplete"))?;
    ensure!(
        record["lifecycle_epoch"]
            .as_u64()
            .is_some_and(|epoch| epoch > 0)
            && ["pairings", "operations", "requests", "approved_images"]
                .iter()
                .all(|key| record[key].as_array().is_some_and(Vec::is_empty)),
        "provider initialization incomplete"
    );
    Ok(())
}

fn bootstrap_provider(run: &mut Rehearsal, state: &Path) -> Result<()> {
    // The real daemon must create the complete state before offline enrollment.
    // Creating just a directory/lock is not initialization: existing incomplete
    // roots are deliberately rejected by the production store.
    ensure!(
        !path_present(state)?,
        "provider bootstrap root already exists"
    );
    let mut bootstrap = run.service_env();
    bootstrap.extend([
        run.root
            .join("bin/vaultwarden-accessd")
            .display()
            .to_string(),
        "--state-root".into(),
        state.display().to_string(),
    ]);
    run.runtime_owned = true;
    run.start_unit(UNIT, &bootstrap)?;
    wait_for(|| {
        ensure!(
            property(UNIT, "ActiveState")? == "active",
            "provider bootstrap exited"
        );
        Ok(initialized_layout(state).is_ok())
    })?;
    let unit = run
        .units
        .last()
        .context("missing bootstrap ownership")?
        .clone();
    ensure!(
        unit.name == UNIT && run.recorded_units()? == run.units,
        "bootstrap ownership mismatch"
    );
    ensure!(
        property(UNIT, "InvocationID")? == unit.invocation,
        "bootstrap invocation changed"
    );
    checked(manager().args(["stop", UNIT]))?;
    wait_for(|| Ok(property(UNIT, "LoadState")? == "not-found" && !path_present(&unit.cgroup)?))?;
    // Persist retirement only after independent stop/cgroup confirmation. The
    // ledger keeps both lifetimes; later cleanup acts on the new invocation only.
    run.ledger_record(&json!({"event":"retired-unit","resource":UNIT,"unit":unit}))?;
    run.units.pop();
    ensure!(
        run.recorded_units()? == run.units,
        "bootstrap retirement mismatch"
    );
    initialized_layout(state)?;
    println!(
        "PASS: real locked-only daemon initialized state; bootstrap invocation and cgroup retired before enrollment"
    );
    Ok(())
}

fn terminal(state: &Value, agent: bool, approve: bool) -> Result<bool> {
    if agent {
        return agent_terminal_status(
            state,
            &if approve {
                AgentStatus::Completed { exit_code: 0 }
            } else {
                AgentStatus::Denied
            },
        );
    }
    use vaultwarden_cli::access::direct_request::DirectStatus;
    let state: DirectStatus = serde_json::from_value(state.clone())
        .map_err(|_error| anyhow::anyhow!("invalid pilot human status"))?;
    match state {
        DirectStatus::Pending | DirectStatus::Approved | DirectStatus::Running => Ok(false),
        DirectStatus::Completed { exit_code: 0 } if approve => Ok(true),
        DirectStatus::Denied if !approve => Ok(true),
        _ => anyhow::bail!("pilot terminal outcome mismatch; never resubmit"),
    }
}

fn verify_final_history(history: Result<Value>, completed: &[(String, bool)]) -> Result<()> {
    let history = history.context("pilot history read failed")?;
    check_history(&history, completed).context("pilot history verification failed")
}

fn check_history(history: &Value, completed: &[(String, bool)]) -> Result<()> {
    let events = history["events"]
        .as_array()
        .context("pilot history unavailable")?;
    let expected_total = completed.iter().filter(|(_, approve)| *approve).count();
    ensure!(
        events
            .iter()
            .filter(|e| e["outcome"] == "execution_started")
            .count()
            == expected_total,
        "pilot total execution count mismatch"
    );
    for (id, approve) in completed {
        let starts = events
            .iter()
            .filter(|e| e["request_id"] == *id && e["outcome"] == "execution_started")
            .count();
        let successes = events
            .iter()
            .filter(|e| e["request_id"] == *id && e["outcome"] == "succeeded")
            .count();
        ensure!(
            starts == usize::from(*approve) && successes == usize::from(*approve),
            "pilot execution count mismatch"
        ); // mutation: counts
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pilot_binary_redaction_keeps_whole_material_without_short_fragments() {
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        run.cleaned = true;
        let path = temp.path().join("client.p12");
        let bytes = b"\x30\x82\xff\n{\n\"\n:\n}\nsynthetic-binary-material";
        fs::write(&path, bytes).unwrap();
        register_secret_file(&mut run, &path).unwrap();
        scan(
            &run,
            br#"{"events":[{"request_id":"public-id","outcome":"succeeded"}]}"#,
        )
        .unwrap();
        assert!(scan(&run, bytes).is_err());
        assert!(
            scan(
                &run,
                base64::engine::general_purpose::STANDARD
                    .encode(bytes)
                    .as_bytes()
            )
            .is_err()
        );
        let pem =
            b"-----BEGIN SYNTHETIC MATERIAL-----\nsynthetic-pem-secret-line\n-----END SYNTHETIC MATERIAL-----\n";
        fs::write(&path, pem).unwrap();
        register_secret_file(&mut run, &path).unwrap();
        assert!(scan(&run, b"synthetic-pem-secret-line").is_err());
        assert!(scan(&run, pem).is_err());
        assert!(
            scan(
                &run,
                base64::engine::general_purpose::STANDARD
                    .encode(pem)
                    .as_bytes()
            )
            .is_err()
        );
    }

    #[test]
    fn pilot_finish_history_failures_are_closed_without_invented_request_counts() {
        let observation = FailureObservation::new("finish");
        let read =
            verify_final_history(Err(anyhow::anyhow!("private upstream data")), &[]).unwrap_err();
        assert_eq!(failure_category(&read), "history_read_failed");
        let verify =
            verify_final_history(Ok(json!({"events":[{"outcome":"execution_started"}]})), &[])
                .unwrap_err();
        assert_eq!(failure_category(&verify), "history_verification_failed");
        verify_final_history(Ok(json!({"events":[]})), &[]).unwrap();
        let value = serde_json::to_value(&observation).unwrap();
        assert!(value["request_id"].is_null());
        assert_eq!(value["exact_request_counts"]["availability"], "unavailable");
    }

    #[test]
    fn pilot_quick_bundle_is_bounded_owner_only_and_encoded_secrets_are_redacted() {
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        run.cleaned = true;
        let handoff = temp.path().join("quick-handoff");
        directory(&handoff, 0o700).unwrap();
        // Deliberately not real private material; no services or key generation.
        private_file(&handoff.join("ca.der"), b"synthetic-ca").unwrap();
        private_file(&handoff.join("client.p12"), b"synthetic-identity").unwrap();
        private_file(
            &handoff.join("identity-passphrase.txt"),
            b"synthetic-passphrase\n",
        )
        .unwrap();
        write_quick_setup_bundle(
            &mut run,
            &handoff,
            "https://fixture.example:8443",
            &"a".repeat(64),
            &"b".repeat(64),
        )
        .unwrap();
        let path = handoff.join("quick-setup.json");
        let bytes = fs::read(&path).unwrap();
        let value: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(value.as_object().unwrap().len(), 9);
        assert_eq!(value["version"], 1);
        assert_eq!(value["kind"], "disposable-companion-pilot");
        assert_eq!(value["endpoint"], "https://fixture.example:8443");
        assert_eq!(value["leaf_sha256"], "a".repeat(64));
        assert_eq!(value["client_sha256"], "b".repeat(64));
        assert_eq!(value["import_passphrase"], "synthetic-passphrase");
        assert_eq!(value["unlock_password"], PASSWORD);
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(value["ca_der"].as_str().unwrap())
                .unwrap(),
            b"synthetic-ca"
        );
        assert_eq!(
            base64::engine::general_purpose::STANDARD
                .decode(value["pkcs12"].as_str().unwrap())
                .unwrap(),
            b"synthetic-identity"
        );
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(fs::metadata(&handoff).unwrap().mode() & 0o777, 0o700);
        assert!(scan(&run, value["pkcs12"].as_str().unwrap().as_bytes()).is_err());
        assert!(scan(&run, &bytes).is_err());
        assert!(
            write_quick_setup_bundle(
                &mut run,
                &handoff,
                "http://invalid",
                &"a".repeat(64),
                &"b".repeat(64)
            )
            .is_err()
        );
        fs::write(handoff.join("ca.der"), vec![1; 65_537]).unwrap();
        assert!(
            write_quick_setup_bundle(
                &mut run,
                &handoff,
                "https://fixture.example",
                &"a".repeat(64),
                &"b".repeat(64)
            )
            .is_err()
        );
        assert_eq!(fs::read(path).unwrap(), bytes);
    }

    struct BeforeCleanupWriter {
        root: PathBuf,
        bytes: Vec<u8>,
        flushed: bool,
    }
    impl Write for BeforeCleanupWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            assert!(self.root.exists(), "failure evidence emitted after cleanup");
            self.bytes.extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            assert!(self.root.exists(), "failure evidence flushed after cleanup");
            self.flushed = true;
            Ok(())
        }
    }

    #[test]
    fn pilot_failure_evidence_survives_actual_cleanup_without_invented_outcomes() {
        for status in [None, Some("pending"), Some("expired"), Some("denied")] {
            let temp = tempfile::tempdir().unwrap();
            let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
            let mut observation = FailureObservation::new("human-approve");
            observation
                .request(&URL_SAFE_NO_PAD.encode([7; 32]))
                .unwrap();
            if let Some(status) = status {
                observation
                    .status(&json!({"status":status}), false)
                    .unwrap();
            }
            let mut writer = BeforeCleanupWriter {
                root: temp.path().to_path_buf(),
                bytes: Vec::new(),
                flushed: false,
            };
            let error = anyhow::anyhow!("raw backend password response")
                .context("pilot status poll failed");
            assert!(finish_pilot(&mut run, &observation, Err(error), &mut writer).is_err());
            assert!(!temp.path().exists());
            assert!(writer.flushed);
            assert!(writer.bytes.len() <= 4097);
            assert!(!String::from_utf8_lossy(&writer.bytes).contains("raw backend"));
            let record: Value = serde_json::from_slice(&writer.bytes).unwrap();
            assert_eq!(record["failure_category"], "status_poll_failed");
            assert!(record["failure_observed_at_unix_ms"].is_u64());
            let observed = &record["observation"];
            assert_eq!(observed["phase"], "human-approve");
            assert_eq!(
                observed["exact_request_counts"]["availability"],
                "unavailable"
            );
            if let Some(status) = status {
                assert_eq!(
                    observed["last_observed_status"]["value"]["state"]["status"],
                    status
                );
                assert_eq!(
                    observed["last_observed_status"]["freshness"],
                    "historical_may_be_stale"
                );
            } else {
                assert_eq!(
                    observed["last_observed_status"]["availability"],
                    "unavailable"
                );
            }
        }
    }

    #[test]
    fn pilot_failure_evidence_is_typed_scanned_and_does_not_skip_cleanup() {
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        let mut observation = FailureObservation::new("agent-approve");
        for invalid in ["short", "password\n", &"!".repeat(43), &"x".repeat(4097)] {
            assert!(observation.request(invalid).is_err());
            assert!(observation.request_id.is_none());
        }
        observation
            .status(&json!({"status":"pending"}), true)
            .unwrap();
        for invalid in [
            json!({"status":"expired","password":"secret"}),
            json!({"status":"raw-error"}),
            json!(null),
        ] {
            assert!(observation.status(&invalid, true).is_err());
        }
        let id = URL_SAFE_NO_PAD.encode([9; 32]);
        observation.request(&id).unwrap();
        run.secrets.push(id.as_bytes().to_vec());
        let mut output = Vec::new();
        assert!(
            finish_pilot(
                &mut run,
                &observation,
                Err(anyhow::anyhow!("private error")),
                &mut output
            )
            .is_err()
        );
        assert!(output.is_empty());
        assert!(run.leaked.get());
        assert!(
            temp.path().exists(),
            "redaction uncertainty must retain material"
        );
        run.cleaned = true; // Synthetic fixture only; tempfile owns its removal.

        struct BrokenWriter;
        impl Write for BrokenWriter {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("private sink error"))
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        let error = finish_pilot(
            &mut run,
            &FailureObservation::new("setup"),
            Err(anyhow::anyhow!("private error")),
            &mut BrokenWriter,
        )
        .unwrap_err();
        assert_eq!(failure_category(&error), "failure_observation_unavailable");
        assert!(!temp.path().exists(), "sink failure must not skip teardown");
    }

    #[test]
    fn pilot_failure_counts_are_exact_request_historical_and_reset_per_phase() {
        let id = URL_SAFE_NO_PAD.encode([2; 32]);
        let mut observation = FailureObservation::new("human-approve");
        observation.request(&id).unwrap();
        observation
            .history(&json!({"events":[
                {"request_id":id,"outcome":"execution_started"},
                {"request_id":id,"outcome":"succeeded"},
                {"request_id":"other","outcome":"execution_started"}
            ]}))
            .unwrap();
        let value = serde_json::to_value(&observation).unwrap();
        assert_eq!(
            value["exact_request_counts"]["value"]["execution_starts"],
            1
        );
        assert_eq!(
            value["exact_request_counts"]["value"]["successful_executions"],
            1
        );
        assert_eq!(
            value["exact_request_counts"]["value"]["scope"],
            "observed_bounded_history_only_not_final_totals"
        );
        assert!(observation.history(&json!({"events":[{}]})).is_err());
        assert!(
            observation
                .history(&json!({"events":[{"request_id":id,"outcome":"secret upstream error"}]}))
                .is_err()
        );
        observation.history(&json!({"events":[]})).unwrap();
        let value = serde_json::to_value(&observation).unwrap();
        assert_eq!(
            value["exact_request_counts"]["value"]["execution_starts"],
            0
        );
        assert_eq!(
            value["exact_request_counts"]["freshness"],
            "historical_may_be_stale"
        );
        assert_eq!(value["last_observed_status"]["availability"], "unavailable");
        observation = FailureObservation::new("agent-deny");
        let value = serde_json::to_value(&observation).unwrap();
        assert!(value["request_id"].is_null());
        assert_eq!(value["last_observed_status"]["availability"], "unavailable");
        assert_eq!(value["exact_request_counts"]["availability"], "unavailable");
    }

    #[test]
    fn pilot_failure_categories_never_reflect_untrusted_error_details() {
        for (context, expected) in [
            (
                "pilot decision deadline exceeded; never resubmit",
                "decision_observation_timeout",
            ),
            ("pilot readiness deadline exceeded", "readiness_timeout"),
            ("pilot status poll failed", "status_poll_failed"),
            (
                "pilot status observation invalid",
                "invalid_status_observation",
            ),
            ("pilot invalid request ID", "invalid_request_id"),
            ("pilot history read failed", "history_read_failed"),
            (
                "pilot history observation invalid",
                "invalid_history_observation",
            ),
            (
                "pilot history verification failed",
                "history_verification_failed",
            ),
            (
                "pilot terminal verification failed",
                "unexpected_terminal_status",
            ),
            (
                "pilot failure observation unavailable",
                "failure_observation_unavailable",
            ),
        ] {
            assert_eq!(
                failure_category(&anyhow::anyhow!("private response password").context(context)),
                expected
            );
            assert_eq!(
                failure_category(&anyhow::anyhow!(format!("{context} private response"))),
                "operation_failed"
            );
        }
    }

    fn ready(phase: &str) -> Ready {
        Ready {
            phase: phase.into(),
            nonce: "1".repeat(32),
        }
    }

    #[test]
    fn pilot_listener_failure_is_closed_and_never_reflects_error_data() {
        let occupied = anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::AddrInUse,
            "secret endpoint password body",
        ))
        .context("pilot listen address unavailable");
        assert_eq!(failure_category(&occupied), "listener_unavailable");
        for payload in [
            "secret password",
            "pilot listen address unavailable secret",
            "https://private/#capability",
        ] {
            assert_eq!(
                failure_category(&anyhow::anyhow!(payload)),
                "operation_failed"
            );
        }
    }

    #[test]
    fn pilot_setup_stages_never_reflect_underlying_failure_data() {
        for (context, category) in [
            ("provider unit collision", "provider_unit_collision"),
            (
                "supervisor runtime collision",
                "supervisor_runtime_collision",
            ),
            ("pilot stopped by operator", "operator_stopped"),
            ("pilot interrupted", "interrupted"),
            ("pilot private services failed", "private_services_failed"),
            ("pilot certificates failed", "certificates_failed"),
            ("pilot vault startup failed", "vault_startup_failed"),
            (
                "pilot vault provisioning failed",
                "vault_provisioning_failed",
            ),
            ("pilot enrollment failed", "enrollment_failed"),
            (
                "pilot provider bootstrap failed",
                "provider_bootstrap_failed",
            ),
            ("pilot provider startup failed", "provider_startup_failed"),
            (
                "pilot provider readiness failed",
                "provider_readiness_failed",
            ),
        ] {
            let error = anyhow::anyhow!("password key URL response body").context(context);
            assert_eq!(failure_category(&error), category);
            assert_eq!(
                failure_category(&anyhow::anyhow!(format!("{context} secret"))),
                "operation_failed"
            );
        }
    }

    #[test]
    fn pilot_enrollment_requires_real_provider_initialization_not_directory_and_lock() {
        let temp = tempfile::tempdir().unwrap();
        let incomplete = temp.path().join("incomplete");
        directory(&incomplete, 0o700).unwrap();
        private_file(&incomplete.join(".provider-state.lock"), b"").unwrap();
        assert!(initialized_layout(&incomplete).is_err());
        assert!(vaultwarden_cli::access::provider::Provider::start(&incomplete).is_err());
        let complete = temp.path().join("complete");
        // The production lifecycle implementation authors this fixture; the
        // harness never writes provider-state.json or injects policy/pairings.
        let provider = vaultwarden_cli::access::provider::Provider::start(&complete).unwrap();
        initialized_layout(&complete).unwrap();
        assert!(vaultwarden_cli::access::provider::Provider::start(&complete).is_err());
        drop(provider);
        // Concurrently forked test children can retain the writer fd until
        // exec. Retain restart coverage without requiring instantaneous release;
        // a persistent failure still fails this bounded test.
        let deadline = Instant::now() + Duration::from_secs(2);
        let reopened = loop {
            match vaultwarden_cli::access::provider::Provider::start(&complete) {
                Ok(provider) => break provider,
                Err(error) if Instant::now() < deadline => {
                    assert_eq!(
                        error.diagnostic(),
                        vaultwarden_cli::access::provider::ProviderDiagnostic::PersistenceFailure
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("initialized provider did not reopen: {error:?}"),
            }
        };
        drop(reopened);
        initialized_layout(&complete).unwrap();
    }

    #[test]
    fn pilot_ledger_retirement_requires_exact_lifetime_before_same_name_restart() {
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        run.cleaned = true; // Synthetic ownership records must never stop units.
        let old = OwnedUnit {
            name: UNIT.into(),
            invocation: "a".repeat(32),
            cgroup: PathBuf::from(format!("/sys/fs/cgroup/user.slice/user-1000.slice/{UNIT}")),
        };
        run.record_unit(old.clone()).unwrap();
        let mut next = old.clone();
        next.invocation = "b".repeat(32);
        run.ledger_record(&json!({"event":"retired-unit","unit":old}))
            .unwrap();
        run.units.clear();
        assert!(run.recorded_units().unwrap().is_empty());
        run.record_unit(next.clone()).unwrap();
        assert_eq!(run.recorded_units().unwrap(), vec![next]);
        // A stale retirement must not remove the new same-name lifetime.
        run.ledger_record(&json!({"event":"retired-unit","unit":old}))
            .unwrap();
        assert!(run.recorded_units().is_err());
    }

    #[test]
    fn pilot_readiness_and_duplicates_are_fail_closed() {
        let mut gate = SubmissionGate::default();
        let expected = ready("human-deny");
        assert!(!gate.admit(&expected, None).unwrap());
        assert!(!gate.consumed);
        assert!(gate.admit(&expected, Some(&ready("agent-deny"))).is_err());
        assert!(
            gate.admit(
                &expected,
                Some(&Ready {
                    phase: expected.phase.clone(),
                    nonce: "2".repeat(32)
                })
            )
            .is_err()
        );
        assert!(gate.admit(&expected, Some(&expected)).unwrap());
        assert!(gate.admit(&expected, Some(&expected)).is_err());
        assert!(valid_phase("approve").is_err());
    }

    #[test]
    fn pilot_terminal_results_never_turn_expiry_failure_or_disconnect_into_success() {
        for agent in [false, true] {
            assert!(!terminal(&json!({"status":"pending"}), agent, true).unwrap());
            assert!(terminal(&json!({"status":"completed","exit_code":0}), agent, true).unwrap());
            assert!(terminal(&json!({"status":"denied"}), agent, false).unwrap());
            for state in [
                json!({"status":"expired"}),
                json!({"status":"denied"}),
                json!({"status":"completed","exit_code":1}),
                json!(null),
            ] {
                assert!(terminal(&state, agent, true).is_err());
            }
            assert!(terminal(&json!({"status":"completed","exit_code":0}), agent, false).is_err());
        }
    }

    #[test]
    fn pilot_history_requires_exact_per_request_and_global_counts() {
        let completed = vec![("deny".into(), false), ("approve".into(), true)];
        let good = json!({"events":[{"request_id":"approve","outcome":"execution_started"},{"request_id":"approve","outcome":"succeeded"}]});
        check_history(&good, &completed).unwrap();
        for bad in [
            json!({"events":[]}),
            json!({"events":[{"request_id":"approve","outcome":"execution_started"}]}),
            json!({"events":[{"request_id":"deny","outcome":"execution_started"},{"request_id":"approve","outcome":"succeeded"}]}),
            json!({"events":[{"request_id":"approve","outcome":"execution_started"},{"request_id":"approve","outcome":"execution_started"},{"request_id":"approve","outcome":"succeeded"}]}),
        ] {
            assert!(check_history(&bad, &completed).is_err());
        }
    }

    #[test]
    fn pilot_controls_reject_malformed_symlink_foreign_and_duplicate_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("control");
        private_file(&path, &serde_json::to_vec(&ready("human-deny")).unwrap()).unwrap();
        assert_eq!(read_control(&path).unwrap(), ready("human-deny"));
        assert!(private_file(&path, b"duplicate").is_err());
        let link = temp.path().join("link");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        assert!(read_control(&link).is_err());
        let hard = temp.path().join("hard");
        fs::hard_link(&path, &hard).unwrap();
        assert!(read_control(&path).is_err());
        fs::remove_file(&hard).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_control(&path).is_err());
        assert!(read_control(Path::new("/etc/passwd")).is_err());
        for bytes in [b"not-json".as_slice(), b"{\"phase\":\"human-deny\",\"nonce\":\"short\"}", b"{\"phase\":\"human-deny\",\"nonce\":\"11111111111111111111111111111111\",\"extra\":true}", &[b'x'; 513]] {
            fs::remove_file(&path).unwrap(); private_file(&path, bytes).unwrap(); assert!(read_control(&path).is_err());
        }
    }

    #[test]
    fn pilot_collision_guards_refuse_all_existing_service_states_and_runtime() {
        require_unoccupied("not-found", false).unwrap();
        for state in ["loaded", "error", "masked", "stub", "bad-setting", ""] {
            assert!(require_unoccupied(state, false).is_err());
        }
        assert!(require_unoccupied("not-found", true).is_err());
    }

    #[test]
    fn pilot_real_control_paths_require_current_phase_and_owner_only_ancestry() {
        let temp = tempfile::Builder::new()
            .prefix(".vw-real-vaultwarden-pilot-")
            .tempdir()
            .unwrap();
        directory(&temp.path().join("private"), 0o700).unwrap();
        let controls = temp.path().join("private/control");
        directory(&controls, 0o700).unwrap();
        private_file(
            &controls.join("ready.json"),
            &serde_json::to_vec(&ready("human-deny")).unwrap(),
        )
        .unwrap();
        assert!(control(temp.path(), Some("agent-approve")).is_err());
        control(temp.path(), Some("human-deny")).unwrap();
        assert!(control(temp.path(), Some("human-deny")).is_err());
        assert!(!controls.join("advance-agent-approve.json").exists());
        control(temp.path(), None).unwrap();
        assert!(interrupted_or_stopped(temp.path()).is_err());
        assert!(control(temp.path(), None).is_err());
        fs::set_permissions(&controls, fs::Permissions::from_mode(0o750)).unwrap();
        assert!(control_directory(temp.path()).is_err());
        fs::set_permissions(&controls, fs::Permissions::from_mode(0o700)).unwrap();
        let alias = temp.path().join("alias");
        std::os::unix::fs::symlink(&controls, &alias).unwrap();
        fs::rename(&controls, temp.path().join("saved-control")).unwrap();
        std::os::unix::fs::symlink(temp.path().join("saved-control"), &controls).unwrap();
        assert!(control_directory(temp.path()).is_err());
    }

    #[test]
    fn pilot_secret_output_and_missing_cleanup_confirmation_fail() {
        let temp = tempfile::tempdir().unwrap();
        let mut run = cleanup_regression_fixture(temp.path().to_path_buf()).unwrap();
        run.secrets.push(b"pilot-secret".to_vec());
        scan(&run, b"status only").unwrap();
        assert!(scan(&run, b"pilot-secret").is_err());
        let observation = CleanupObservation::capture(&run);
        assert!(confirm_cleanup(&observation).is_err());
        run.cleaned = true;
        temp.close().unwrap();
        confirm_cleanup(&observation).unwrap();
    }
}
