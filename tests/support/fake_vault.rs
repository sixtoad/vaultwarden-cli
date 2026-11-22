//! A stateful single-item fake of Vaultwarden 1.36's cipher routes, and a
//! pseudo-terminal driver for the human decision. Test-only; synthetic keys.
use serde_json::{Value, json};
use std::sync::{Arc, Mutex};
use vaultwarden_cli::crypto::CryptoKeys;
use vaultwarden_cli::secret_storage::{Destination, SecretImport, encrypt_create};
use wiremock::{
    Mock, MockServer, Request, Respond, ResponseTemplate,
    matchers::{method, path},
};

pub const ITEM: &str = "33333333-3333-3333-3333-333333333333";
pub const ACCOUNT: &str = "11111111-1111-1111-1111-111111111111";
pub const FOLDER_ID: &str = "22222222-2222-2222-2222-222222222222";
pub const FOLDER: &str = "homelab/production";
pub const REFERENCE: &str = "homelab/production/github/token";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PutMode {
    /// Apply like Vaultwarden, refusing a stale `lastKnownRevisionDate` with 400.
    Apply,
    /// Refuse with 400 without applying (a definite rejection).
    Reject,
    /// Apply, then lose the response (500): the client cannot know.
    ApplyThenLose,
    /// Fail with 500 without applying.
    LoseWithoutApplying,
    /// Apply, but store a different password ciphertext than requested.
    ApplyCorrupted,
}

pub struct State {
    pub item: Value,
    pub revision: u32,
    pub item_gets: usize,
    pub puts: Vec<Value>,
    pub put_mode: PutMode,
    /// Simulate another writer: bump the revision just before this item GET (1-based).
    pub edit_before_get: Option<usize>,
    keys: CryptoKeys,
}
impl State {
    fn revision_date(revision: u32) -> String {
        format!("2026-11-21T10:{revision:02}:00.000000Z")
    }
    pub fn current_revision(&self) -> String {
        Self::revision_date(self.revision)
    }
    fn bump(&mut self) {
        self.revision += 1;
        self.item["revisionDate"] = json!(Self::revision_date(self.revision));
    }
}

pub struct FakeVault {
    pub server: MockServer,
    pub state: Arc<Mutex<State>>,
}

/// The stored item: password, notes, two hidden fields and unselected login data.
pub fn initial_item(keys: &CryptoKeys) -> Value {
    let destination = Destination {
        account_id: ACCOUNT.into(),
        folder: FOLDER.into(),
        folder_id: FOLDER_ID.into(),
        reference: REFERENCE.into(),
    };
    let input = SecretImport::parse(
        br#"{"password":"old-password-private","notes":"old-notes-private","fields":[{"name":"api-key","value":"old-key-private"},{"name":"other","value":"kept-private"}]}"#,
    )
    .unwrap();
    let mut item =
        serde_json::to_value(encrypt_create(keys, &destination, &input, None).unwrap()).unwrap();
    item["id"] = json!(ITEM);
    item["revisionDate"] = json!(State::revision_date(1));
    item["object"] = json!("cipherDetails");
    item["login"]["username"] = json!(keys.encrypt(b"deploy").unwrap());
    item["login"]["totp"] = Value::Null;
    item["login"]["uris"] =
        json!([{"uri": keys.encrypt(b"https://example.invalid").unwrap(), "match": null}]);
    item["passwordHistory"] = Value::Null;
    item
}

struct ItemRoute(Arc<Mutex<State>>);
impl Respond for ItemRoute {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut state = self.0.lock().unwrap();
        if request.method.as_str() == "GET" {
            state.item_gets += 1;
            if state.edit_before_get == Some(state.item_gets) {
                state.bump();
            }
            return ResponseTemplate::new(200).set_body_json(&state.item);
        }
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        state.puts.push(body.clone());
        let stale = body["lastKnownRevisionDate"] != json!(state.current_revision());
        match state.put_mode {
            PutMode::Reject => return ResponseTemplate::new(400),
            PutMode::LoseWithoutApplying => return ResponseTemplate::new(500),
            _ if stale => return ResponseTemplate::new(400),
            _ => {}
        }
        let mut stored = body;
        let object = stored.as_object_mut().unwrap();
        object.remove("lastKnownRevisionDate");
        object.insert("id".into(), json!(ITEM));
        object.insert("object".into(), json!("cipherDetails"));
        if state.put_mode == PutMode::ApplyCorrupted {
            // Authentic under the item key: only an exact value comparison detects it.
            let item_keys = state.keys.item_keys(stored["key"].as_str()).unwrap();
            stored["login"]["password"] = json!(item_keys.encrypt(b"corrupted").unwrap());
        }
        state.item = stored;
        state.bump();
        if state.put_mode == PutMode::ApplyThenLose {
            return ResponseTemplate::new(500);
        }
        ResponseTemplate::new(200).set_body_json(&state.item)
    }
}

impl FakeVault {
    pub async fn start(keys: &CryptoKeys) -> Self {
        let server = MockServer::start().await;
        let state = Arc::new(Mutex::new(State {
            item: initial_item(keys),
            revision: 1,
            item_gets: 0,
            puts: Vec::new(),
            put_mode: PutMode::Apply,
            edit_before_get: None,
            keys: keys.clone(),
        }));
        let sync = json!({
            "profile": {"id": ACCOUNT, "email": "user@example.invalid"},
            "folders": [{"id": FOLDER_ID, "name": keys.encrypt(FOLDER.as_bytes()).unwrap()}],
            "ciphers": []
        });
        Mock::given(method("GET"))
            .and(path("/api/sync"))
            .respond_with(ResponseTemplate::new(200).set_body_json(sync))
            .mount(&server)
            .await;
        Mock::given(path(format!("/api/ciphers/{ITEM}")))
            .respond_with(ItemRoute(state.clone()))
            .mount(&server)
            .await;
        Self { server, state }
    }
    pub fn puts(&self) -> usize {
        self.state.lock().unwrap().puts.len()
    }
}

/// How the driver answers the terminal decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    Approve,
    Deny,
    /// Run with no controlling terminal at all.
    NoTerminal,
}

pub struct Run {
    pub output: std::process::Output,
    /// Everything the CLI wrote to the controlling terminal.
    pub terminal: String,
}

/// Run the CLI with `stdin` on a pipe and the decision on a fresh pseudo-terminal.
#[cfg(unix)]
pub fn run_cli(
    binary: std::process::Command,
    stdin: &[u8],
    password: Option<&str>,
    answer: Answer,
) -> Run {
    use std::{
        fs::File,
        io::{Read, Write},
        os::{
            fd::{AsRawFd, FromRawFd},
            unix::process::CommandExt,
        },
        process::Stdio,
        time::{Duration, Instant},
    };
    let mut command = binary;
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut terminal = None;
    if answer == Answer::NoTerminal {
        // A new session has no controlling terminal: /dev/tty cannot be opened.
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    } else {
        let (mut master, mut slave) = (-1, -1);
        let opened = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        };
        assert_eq!(opened, 0);
        let master = unsafe { File::from_raw_fd(master) };
        let slave = unsafe { File::from_raw_fd(slave) };
        assert_eq!(
            unsafe { libc::fcntl(master.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let terminal_fd = slave.as_raw_fd();
        unsafe {
            command.pre_exec(move || {
                if libc::setsid() < 0 || libc::ioctl(terminal_fd, libc::TIOCSCTTY as _, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        terminal = Some((master, slave));
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    // Keep the parent's slave handle open until the child exits so the master never sees EOF early.
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut transcript = Vec::new();
    let mut answered_secret = false;
    let mut answered_decision = false;
    loop {
        if let Some((master, _slave)) = terminal.as_mut() {
            let mut buffer = [0u8; 4096];
            match master.read(&mut buffer) {
                Ok(n) => transcript.extend_from_slice(&buffer[..n]),
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.raw_os_error() == Some(libc::EIO) => {}
                Err(error) => panic!("terminal read failed: {error}"),
            }
            let text = String::from_utf8_lossy(&transcript).into_owned();
            if let Some(secret) = password
                && !answered_secret
                && text.ends_with("Secret password: ")
            {
                master.write_all(format!("{secret}\n").as_bytes()).unwrap();
                answered_secret = true;
            }
            if !answered_decision
                && text.contains("Authorize this single attempt")
                && text.ends_with(": ")
            {
                let challenge = text.rsplit("typing '").next().unwrap();
                let challenge = challenge.split('\'').next().unwrap();
                let reply = if answer == Answer::Approve {
                    challenge.to_owned()
                } else {
                    "deny".to_owned()
                };
                master.write_all(format!("{reply}\n").as_bytes()).unwrap();
                answered_decision = true;
            }
        }
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("CLI run timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    if let Some((master, _slave)) = terminal.as_mut() {
        let mut buffer = [0u8; 4096];
        while let Ok(n) = master.read(&mut buffer) {
            if n == 0 {
                break;
            }
            transcript.extend_from_slice(&buffer[..n]);
        }
    }
    Run {
        output: child.wait_with_output().unwrap(),
        terminal: String::from_utf8_lossy(&transcript).into_owned(),
    }
}
