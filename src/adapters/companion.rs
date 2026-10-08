//! Bounded direct-LAN mTLS companion transport. The provider retains all authority.
use super::companion_identity as identity;
use crate::access::{
    application::{ProviderApplication, SessionStatus},
    direct_request::{DirectRequestError, DirectReview, DirectStatus, valid_request_id},
    ports::{
        ApprovalAuthenticator, DirectReviewLauncher, ExecutionDispatcher, SensitiveString,
        SessionError,
    },
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use serde::Deserialize;
use std::{
    collections::{HashMap, VecDeque},
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};
const MAX_BODY: usize = 16384;
const MAX_TICKETS: usize = 256;
const TICKET_LIFETIME: Duration = Duration::from_secs(60);

#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Session {
        version: u8,
    },
    List {
        version: u8,
    },
    Review {
        version: u8,
        request_id: String,
    },
    Status {
        version: u8,
        request_id: String,
    },
    Decision {
        version: u8,
        request_id: String,
        ticket: String,
        decision: Decision,
        #[serde(default, deserialize_with = "optional_password")]
        password: Option<SensitiveString>,
    },
    Unlock {
        version: u8,
        #[serde(deserialize_with = "password")]
        password: SensitiveString,
    },
}
#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Decision {
    Approve,
    Deny,
}
fn password<'de, D: serde::Deserializer<'de>>(de: D) -> Result<SensitiveString, D::Error> {
    String::deserialize(de).map(SensitiveString::new)
}
fn optional_password<'de, D: serde::Deserializer<'de>>(
    de: D,
) -> Result<Option<SensitiveString>, D::Error> {
    password(de).map(Some)
}
impl Command {
    fn valid(&self) -> bool {
        let (version, id) = match self {
            Self::Session { version } | Self::List { version } => (*version, None),
            Self::Review {
                version,
                request_id,
            }
            | Self::Status {
                version,
                request_id,
            } => (*version, Some(request_id)),
            Self::Unlock { version, password } => {
                if !valid_password(password) {
                    return false;
                }
                (*version, None)
            }
            Self::Decision {
                version,
                request_id,
                ticket,
                decision,
                password,
            } => {
                if !identity::valid_fingerprint(ticket)
                    || !match (decision, password) {
                        (Decision::Approve, Some(p)) => valid_password(p),
                        (Decision::Deny, None) => true,
                        _ => false,
                    }
                {
                    return false;
                }
                (*version, Some(request_id))
            }
        };
        version == 1 && id.is_none_or(|id| valid_request_id(id))
    }
}
fn valid_password(value: &SensitiveString) -> bool {
    !value.expose().is_empty() && value.expose().len() <= 4096
}
struct Ticket {
    token: String,
    device: String,
    review: DirectReview,
    generation: u64,
    deadline: Duration,
}
#[derive(Default)]
struct State {
    tickets: Vec<Ticket>,
    attempts: HashMap<String, VecDeque<Duration>>,
}
impl State {
    fn attempt(&mut self, device: &str, now: Duration) -> bool {
        let attempts = self.attempts.entry(device.into()).or_default();
        while attempts
            .front()
            .is_some_and(|at| now.saturating_sub(*at) >= Duration::from_secs(60))
        {
            attempts.pop_front();
        }
        if attempts.len() >= 5 {
            return false;
        }
        attempts.push_back(now);
        true
    }
    fn consume(
        &mut self,
        device: &str,
        request: &str,
        token: &str,
        now: Duration,
    ) -> Option<Ticket> {
        self.tickets.retain(|t| t.deadline > now);
        let position = self
            .tickets
            .iter()
            .position(|t| t.device == device && t.review.id == request && t.token == token)?;
        Some(self.tickets.swap_remove(position))
    }
}
struct PollLauncher;
impl DirectReviewLauncher for PollLauncher {
    fn launch(&self, request_id: &str) -> Result<(), DirectRequestError> {
        if valid_request_id(request_id) {
            Ok(())
        } else {
            Err(DirectRequestError::ReviewUnavailable)
        }
    }
}
// Test-only transport observation: never retains request bodies or credentials.
#[cfg(test)]
#[derive(Default, serde::Serialize)]
struct FixtureTrafficState {
    counts: HashMap<&'static str, u64>,
    decision_status_sequence: Vec<&'static str>,
    sequence_truncated: bool,
    dropped_approval_replies: u64,
    drop_next_successful_approval: bool,
}
#[cfg(test)]
struct FixtureTraffic(Mutex<FixtureTrafficState>);
#[cfg(test)]
impl FixtureTraffic {
    fn armed() -> Self {
        Self(Mutex::new(FixtureTrafficState {
            drop_next_successful_approval: true,
            ..FixtureTrafficState::default()
        }))
    }
    fn record(&self, command: &Command) {
        let name = match command {
            Command::Session { .. } => "session",
            Command::List { .. } => "list",
            Command::Review { .. } => "review",
            Command::Status { .. } => "status",
            Command::Decision { .. } => "decision",
            Command::Unlock { .. } => "unlock",
        };
        let mut state = self.0.lock().unwrap();
        let count = state.counts.entry(name).or_default();
        *count = count.saturating_add(1);
        if matches!(name, "decision" | "status") {
            if state.decision_status_sequence.len() < 128 {
                state.decision_status_sequence.push(name);
            } else {
                state.sequence_truncated = true;
            }
        }
    }
    fn drop_reply(&self, approval: bool, status: u16) -> bool {
        let mut state = self.0.lock().unwrap();
        if approval && status == 200 && state.drop_next_successful_approval {
            state.drop_next_successful_approval = false;
            state.dropped_approval_replies += 1;
            true
        } else {
            false
        }
    }
    fn snapshot(&self) -> serde_json::Value {
        serde_json::to_value(&*self.0.lock().unwrap()).unwrap()
    }
}
pub struct Companion {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    identity_store: PathBuf,
    state: Mutex<State>,
    authentication: Mutex<()>,
    approval_authenticator: Option<Arc<dyn ApprovalAuthenticator + Send + Sync>>,
    execution_dispatcher: Option<Arc<dyn ExecutionDispatcher>>,
    #[cfg(test)]
    fixture_traffic: Option<Arc<FixtureTraffic>>,
}
impl Companion {
    pub fn bind(
        address: SocketAddr,
        certificate: &Path,
        private_key: &Path,
        client_ca: &Path,
        identity_store: &Path,
    ) -> Result<Self, SessionError> {
        identity::enrolled(identity_store)?;
        crate::install_rustls_crypto_provider();
        let certificates = identity::private_file(certificate)?;
        let key = identity::private_file(private_key)?;
        let chain = CertificateDer::pem_slice_iter(&certificates)
            .collect::<Result<Vec<_>, _>>()
            .map_err(unavailable)?;
        let key = PrivateKeyDer::from_pem_slice(&key).map_err(unavailable)?;
        let mut config = rustls::ServerConfig::builder()
            .with_client_cert_verifier(identity::verifier(client_ca)?)
            .with_single_cert(chain, key)
            .map_err(unavailable)?;
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        // Every new connection must demonstrate its current certificate.
        config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        config.send_tls13_tickets = 0;
        let listener = TcpListener::bind(address).map_err(unavailable)?;
        listener.set_nonblocking(true).map_err(unavailable)?;
        Ok(Self {
            listener,
            tls: Arc::new(config),
            identity_store: identity_store.into(),
            state: Mutex::new(State::default()),
            authentication: Mutex::new(()),
            approval_authenticator: None,
            execution_dispatcher: None,
            #[cfg(test)]
            fixture_traffic: None,
        })
    }
    pub fn with_approval_authenticator(
        mut self,
        authenticator: Arc<dyn ApprovalAuthenticator + Send + Sync>,
    ) -> Self {
        self.approval_authenticator = Some(authenticator);
        self
    }
    pub fn with_execution_dispatcher(mut self, dispatcher: Arc<dyn ExecutionDispatcher>) -> Self {
        self.execution_dispatcher = Some(dispatcher);
        self
    }
    pub fn request_launcher(&self) -> Arc<dyn DirectReviewLauncher> {
        Arc::new(PollLauncher)
    }
    fn authorized(&self, device: &str) -> bool {
        identity::enrolled(&self.identity_store)
            .is_ok_and(|entries| entries.iter().any(|entry| entry.fingerprint == device))
    }
    fn session(app: &ProviderApplication) -> Response {
        match (app.status(), app.decision_generation()) {
            (Ok(state), Ok(generation)) => Response::ok(
                serde_json::json!({"version":1,"state":if state == SessionStatus::Locked { "locked" } else { "unlocked" },"generation":generation}),
            ),
            _ => Response::error(Error::Unavailable),
        }
    }
    fn dispatch(&self, device: &str, command: Command, app: &ProviderApplication) -> Response {
        if !self.authorized(device) {
            return Response::error(Error::Unauthorized);
        }
        if !command.valid() {
            return Response::error(Error::Invalid);
        }
        #[cfg(test)]
        if let Some(traffic) = &self.fixture_traffic {
            traffic.record(&command);
        }
        match command {
            Command::Session { .. } => Self::session(app),
            Command::List { .. } => match app.companion_pending() {
                Ok(requests) => Response::ok(serde_json::json!({"version":1,"requests":requests})),
                Err(_) => Response::error(Error::Unavailable),
            },
            Command::Status { request_id, .. } => {
                match app.direct_status(app.human_owner(), &request_id) {
                    Ok(status) => Response::ok(serde_json::json!({"version":1,"status":status})),
                    Err(_) => Response::error(Error::Unavailable),
                }
            }
            Command::Review { request_id, .. } => {
                let Ok((review, generation)) = app.companion_review(&request_id) else {
                    return Response::error(Error::Unavailable);
                };
                let mut token = None;
                if review.status == DirectStatus::Pending {
                    let Ok(mut state) = self.state.lock() else {
                        return Response::error(Error::Unavailable);
                    };
                    let now = app.companion_now();
                    state.tickets.retain(|t| {
                        t.deadline > now && !(t.device == device && t.review.id == request_id)
                    });
                    if state.tickets.len() >= MAX_TICKETS {
                        return Response::error(Error::Unavailable);
                    }
                    let mut bytes = [0u8; 32];
                    if getrandom::fill(&mut bytes).is_err() {
                        return Response::error(Error::Unavailable);
                    }
                    let Some(deadline) = now.checked_add(TICKET_LIFETIME) else {
                        return Response::error(Error::Unavailable);
                    };
                    let ticket = identity::fingerprint(&bytes);
                    state.tickets.push(Ticket {
                        token: ticket.clone(),
                        device: device.into(),
                        review: review.clone(),
                        generation,
                        deadline,
                    });
                    token = Some(ticket);
                }
                Response::ok(
                    serde_json::json!({"version":1,"review":review,"ticket":token,"generation":generation}),
                )
            }
            Command::Unlock { password, .. } => {
                let Ok(_authentication) = self.authentication.try_lock() else {
                    return Response::error(Error::RateLimited);
                };
                if !self.attempt(device, app.companion_now()) {
                    return Response::error(Error::RateLimited);
                }
                match app.authenticate(password) {
                    Ok(()) => Self::session(app),
                    Err(_) => Response::error(Error::Authentication),
                }
            }
            Command::Decision {
                request_id,
                ticket,
                decision,
                password,
                ..
            } => {
                let consumed = self.state.lock().ok().and_then(|mut state| {
                    state.consume(device, &request_id, &ticket, app.companion_now())
                });
                let Some(ticket) = consumed else {
                    return Response::error(Error::Stale);
                };
                let Ok(prepared) = app.companion_prepare(
                    &request_id,
                    &ticket.review,
                    ticket.generation,
                    ticket.deadline,
                ) else {
                    return Response::error(Error::Stale);
                };
                let status = match decision {
                    Decision::Deny => {
                        if !self.authorized(device) {
                            return Response::error(Error::Unauthorized);
                        }
                        app.companion_deny(prepared)
                    }
                    Decision::Approve => {
                        if self.execution_dispatcher.is_none() {
                            return Response::error(Error::Unavailable);
                        }
                        let Ok(_authentication) = self.authentication.try_lock() else {
                            return Response::error(Error::RateLimited);
                        };
                        if !self.attempt(device, app.companion_now()) {
                            return Response::error(Error::RateLimited);
                        }
                        let (Some(authenticator), Some(password)) =
                            (&self.approval_authenticator, password)
                        else {
                            return Response::error(Error::Unavailable);
                        };
                        let Ok(proof) = prepared.authenticate(password, authenticator.as_ref())
                        else {
                            return Response::error(Error::Authentication);
                        };
                        if !self.authorized(device) || app.companion_now() >= ticket.deadline {
                            return Response::error(Error::Stale);
                        }
                        app.commit_approval(proof)
                    }
                };
                match status {
                    Ok(status) => {
                        if status == DirectStatus::Approved
                            && let Some(dispatcher) = &self.execution_dispatcher
                            && dispatcher.dispatch(&request_id).is_err()
                        {
                            app.close_admission();
                            return Response::error(Error::Unavailable);
                        }
                        Response::ok(serde_json::json!({"version":1,"status":status}))
                    }
                    Err(_) => Response::error(Error::Stale),
                }
            }
        }
    }
    fn attempt(&self, device: &str, now: Duration) -> bool {
        self.state
            .lock()
            .is_ok_and(|mut state| state.attempt(device, now))
    }
    fn connection(&self, socket: TcpStream, app: &ProviderApplication, stop: &AtomicBool) {
        let Ok(connection) = rustls::ServerConnection::new(self.tls.clone()) else {
            return;
        };
        let mut stream = rustls::StreamOwned::new(
            connection,
            DeadlineStream {
                stream: socket,
                deadline: Instant::now() + Duration::from_secs(5),
            },
        );
        while stream.conn.is_handshaking() {
            if stream.conn.complete_io(&mut stream.sock).is_err() {
                return;
            }
        }
        let Some(leaf) = stream
            .conn
            .peer_certificates()
            .and_then(|certificates| certificates.first())
        else {
            return;
        };
        let device = identity::fingerprint(leaf);
        #[cfg(test)]
        let mut approval = false;
        let response = if !self.authorized(&device) {
            Response::error(Error::Unauthorized)
        } else {
            match read_command(&mut stream) {
                Ok(command) if !stop.load(Ordering::Acquire) => {
                    #[cfg(test)]
                    {
                        approval = matches!(
                            &command,
                            Command::Decision {
                                decision: Decision::Approve,
                                ..
                            }
                        );
                    }
                    // Do not accept a second already-buffered HTTP request. Later
                    // bytes also confer no authority: this connection always closes.
                    let mut extra = [0];
                    match stream.conn.reader().read(&mut extra) {
                        Ok(0) => self.dispatch(&device, command, app),
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            self.dispatch(&device, command, app)
                        }
                        _ => Response::error(Error::Invalid),
                    }
                }
                _ => Response::error(Error::Invalid),
            }
        };
        #[cfg(test)]
        if self
            .fixture_traffic
            .as_ref()
            .is_some_and(|traffic| traffic.drop_reply(approval, response.status))
        {
            // Dispatch has already committed and queued the real execution.
            return;
        }
        stream.sock.deadline = Instant::now() + Duration::from_secs(5);
        let _ignored = stream.write_all(response.encode().as_bytes());
        let _ignored = stream.flush();
    }
    pub fn serve(
        self,
        app: Arc<ProviderApplication>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), SessionError> {
        let service = Arc::new(self);
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::new();
        let mut result = Ok(());
        while !stop.load(Ordering::Acquire) {
            let mut index = 0;
            while index < workers.len() {
                if workers[index].is_finished() {
                    if workers.swap_remove(index).join().is_err() {
                        result = Err(SessionError::BackendUnavailable);
                        stop.store(true, Ordering::Release);
                    }
                } else {
                    index += 1;
                }
            }
            match service.listener.accept() {
                Ok((socket, _)) => {
                    if workers.len() >= 8 {
                        drop(socket);
                        continue;
                    }
                    let (service, app, stop) = (service.clone(), app.clone(), stop.clone());
                    workers.push(std::thread::spawn(move || {
                        service.connection(socket, &app, &stop)
                    }));
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25))
                }
                Err(_) => {
                    result = Err(SessionError::BackendUnavailable);
                    break;
                }
            }
        }
        stop.store(true, Ordering::Release);
        let initial = app.shutdown();
        for worker in workers {
            if worker.join().is_err() {
                result = Err(SessionError::BackendUnavailable);
            }
        }
        initial.and(app.shutdown()).and(result)
    }
}
fn unavailable<T>(_: T) -> SessionError {
    SessionError::BackendUnavailable
}
struct DeadlineStream {
    stream: TcpStream,
    deadline: Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(Instant::now())
            .filter(|time| !time.is_zero())
            .ok_or_else(|| std::io::ErrorKind::TimedOut.into())
    }
}
impl Read for DeadlineStream {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        self.stream.read(bytes)
    }
}
impl Write for DeadlineStream {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        self.stream.write(bytes)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.stream.flush()
    }
}
fn read_command(stream: &mut impl Read) -> Result<Command, SessionError> {
    let mut header = Zeroizing::new(Vec::new());
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() >= 8192 {
            return Err(SessionError::InvalidRequest);
        }
        let mut byte = [0];
        stream
            .read_exact(&mut byte)
            .map_err(|_error| SessionError::InvalidRequest)?;
        header.push(byte[0]);
    }
    let header = std::str::from_utf8(&header).map_err(|_error| SessionError::InvalidRequest)?;
    let mut lines = header.split("\r\n");
    if lines.next() != Some("POST /v1/companion HTTP/1.1") {
        return Err(SessionError::InvalidRequest);
    }
    let mut headers = HashMap::new();
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(SessionError::InvalidRequest)?;
        if name.is_empty()
            || !name.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
            || value.bytes().any(|c| c.is_ascii_control() && c != b'\t')
        {
            return Err(SessionError::InvalidRequest);
        }
        let name = name.to_ascii_lowercase();
        if matches!(
            name.as_str(),
            "transfer-encoding" | "content-encoding" | "upgrade" | "cookie" | "expect"
        ) || headers.insert(name, value.trim()).is_some()
        {
            return Err(SessionError::InvalidRequest);
        }
    }
    if headers.get("content-type") != Some(&"application/json")
        || headers.get("host").is_none_or(|value| value.is_empty())
        || headers
            .get("connection")
            .is_some_and(|value| value.to_ascii_lowercase().contains("upgrade"))
    {
        return Err(SessionError::InvalidRequest);
    }
    let length = headers
        .get("content-length")
        .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|n| *n <= MAX_BODY)
        .ok_or(SessionError::InvalidRequest)?;
    let mut body = Zeroizing::new(vec![0; length]);
    stream
        .read_exact(&mut body)
        .map_err(|_error| SessionError::InvalidRequest)?;
    let command: Command =
        serde_json::from_slice(&body).map_err(|_error| SessionError::InvalidRequest)?;
    body.zeroize();
    if !command.valid() {
        return Err(SessionError::InvalidRequest);
    }
    Ok(command)
}
#[derive(Clone, Copy)]
enum Error {
    Invalid,
    Unauthorized,
    Unavailable,
    Stale,
    Authentication,
    RateLimited,
}
struct Response {
    status: u16,
    body: String,
}
impl Response {
    fn error(error: Error) -> Self {
        let (status, error) = match error {
            Error::Invalid => (400, "invalid_request"),
            Error::Unauthorized => (403, "unauthorized"),
            Error::Unavailable => (503, "unavailable"),
            Error::Stale => (409, "stale"),
            // URLSession can interpret HTTP 403 on mTLS as client-certificate
            // rejection, hiding the body. Password rejection is application-level.
            Error::Authentication => (422, "authentication_failed"),
            Error::RateLimited => (429, "rate_limited"),
        };
        Self {
            status,
            body: serde_json::json!({"version":1,"error":error}).to_string(),
        }
    }
    fn ok(value: serde_json::Value) -> Self {
        let body = value.to_string();
        if body.len() > 1048576 {
            Self::error(Error::Unavailable)
        } else {
            Self { status: 200, body }
        }
    }
    fn encode(&self) -> String {
        format!(
            "HTTP/1.1 {} Response\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n{}",
            self.status,
            self.body.len(),
            self.body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::direct_request_tests::{Fixture, fixture, input};
    use std::{os::unix::fs::PermissionsExt, sync::atomic::AtomicUsize};
    const CLIENT: &[u8] = include_bytes!("../../tests/companion-tls/client.pem");
    const CLIENT_KEY: &[u8] = include_bytes!("../../tests/companion-tls/client-key.pem");
    const CLIENT_CA: &[u8] = include_bytes!("../../tests/companion-tls/ca.pem");
    struct Check {
        calls: AtomicUsize,
        action: Mutex<Option<Box<dyn FnOnce() + Send>>>,
    }
    impl ApprovalAuthenticator for Check {
        fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            if let Some(action) = self.action.lock().unwrap().take() {
                action();
            }
            if password.expose() == "synthetic-password" {
                Ok(())
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        }
    }
    struct Dispatch(AtomicUsize);
    impl ExecutionDispatcher for Dispatch {
        fn dispatch(&self, _: &str) -> Result<(), SessionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }
    fn write_private(root: &Path, name: &str, bytes: &[u8]) -> PathBuf {
        let path = root.join(name);
        std::fs::write(&path, bytes).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }
    fn leaf_fingerprint(bytes: &[u8]) -> String {
        identity::fingerprint(&CertificateDer::from_pem_slice(bytes).unwrap())
    }
    fn service(f: &Fixture) -> (Companion, Arc<Check>, Arc<Dispatch>) {
        let root = f.dir.path().join("provider");
        let server = write_private(
            &root,
            "server.pem",
            include_bytes!("../../tests/fixtures/provider-tls/server.pem"),
        );
        let key = write_private(
            &root,
            "server-key.pem",
            include_bytes!("../../tests/fixtures/provider-tls/server-key.pem"),
        );
        let ca = write_private(&root, "client-ca.pem", CLIENT_CA);
        let store = write_private(&root, identity::STORE_FILE, serde_json::json!({"version":1,"identities":[{"fingerprint":leaf_fingerprint(CLIENT),"label":"Synthetic Mac"},{"fingerprint":"b".repeat(64),"label":"Other Mac"}]}).to_string().as_bytes());
        let check = Arc::new(Check {
            calls: AtomicUsize::new(0),
            action: Mutex::new(None),
        });
        let dispatch = Arc::new(Dispatch(AtomicUsize::new(0)));
        let service = Companion::bind("127.0.0.1:0".parse().unwrap(), &server, &key, &ca, &store)
            .unwrap()
            .with_approval_authenticator(check.clone())
            .with_execution_dispatcher(dispatch.clone());
        (service, check, dispatch)
    }
    fn request(f: &Fixture, service: &Companion) -> String {
        f.app
            .submit_direct(
                f.app.human_owner(),
                input(),
                service.request_launcher().as_ref(),
            )
            .unwrap()
            .id
    }
    fn review(service: &Companion, f: &Fixture, id: &str) -> String {
        let response = service.dispatch(
            &leaf_fingerprint(CLIENT),
            Command::Review {
                version: 1,
                request_id: id.into(),
            },
            &f.app,
        );
        assert_eq!(response.status, 200);
        serde_json::from_str::<serde_json::Value>(&response.body).unwrap()["ticket"]
            .as_str()
            .unwrap()
            .into()
    }
    fn decision(id: &str, token: &str, password: &str) -> Command {
        Command::Decision {
            version: 1,
            request_id: id.into(),
            ticket: token.into(),
            decision: Decision::Approve,
            password: Some(SensitiveString::new(password.into())),
        }
    }
    #[test]
    fn companion_decision_is_device_bound_single_use_and_lost_reply_is_read_only() {
        let f = fixture();
        let (service, check, dispatch) = service(&f);
        let id = request(&f, &service);
        let token = review(&service, &f, &id);
        assert_eq!(
            service
                .dispatch(
                    &"b".repeat(64),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            409
        );
        assert_eq!(check.calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            200
        );
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            409
        );
        let response = service.dispatch(
            &leaf_fingerprint(CLIENT),
            Command::Status {
                version: 1,
                request_id: id.clone(),
            },
            &f.app,
        );
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response.body).unwrap()["status"]["status"],
            "approved"
        );
        assert_eq!(check.calls.load(Ordering::SeqCst), 1);
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 1);
        let response = service.dispatch(
            &leaf_fingerprint(CLIENT),
            Command::Review {
                version: 1,
                request_id: id,
            },
            &f.app,
        );
        assert!(
            serde_json::from_str::<serde_json::Value>(&response.body).unwrap()["ticket"].is_null()
        );
    }
    #[test]
    fn companion_wrong_password_consumes_ticket_and_rate_limits_per_device() {
        let f = fixture();
        let (service, check, dispatch) = service(&f);
        let id = request(&f, &service);
        for attempt in 0..6 {
            let token = review(&service, &f, &id);
            let response = service.dispatch(
                &leaf_fingerprint(CLIENT),
                decision(&id, &token, "wrong"),
                &f.app,
            );
            assert_eq!(response.status, if attempt < 5 { 422 } else { 429 });
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&response.body).unwrap(),
                serde_json::json!({"version":1,"error":if attempt < 5 {
                    "authentication_failed"
                } else {
                    "rate_limited"
                }})
            );
            assert_eq!(
                f.app.direct_status(f.app.human_owner(), &id).unwrap(),
                DirectStatus::Pending
            );
            assert_eq!(
                service
                    .dispatch(
                        &leaf_fingerprint(CLIENT),
                        decision(&id, &token, "synthetic-password"),
                        &f.app
                    )
                    .status,
                409
            );
        }
        assert_eq!(check.calls.load(Ordering::SeqCst), 5);
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 0);
        f.monotonic.store(70, Ordering::SeqCst);
        let token = review(&service, &f, &id);
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            200
        );
    }
    #[test]
    fn companion_rejects_changed_review_generation_expiry_and_revocation() {
        for case in [
            "review",
            "generation",
            "expiry",
            "revocation",
            "after_password_expiry",
            "after_password_lock",
            "after_password_revocation",
        ] {
            let f = fixture();
            let (service, check, dispatch) = service(&f);
            let id = request(&f, &service);
            let token = review(&service, &f, &id);
            match case {
                "review" => service.state.lock().unwrap().tickets[0]
                    .review
                    .effect
                    .push_str(" changed"),
                "generation" => service.state.lock().unwrap().tickets[0].generation += 1,
                "expiry" => {
                    f.monotonic.store(70, Ordering::SeqCst);
                }
                "revocation" => {
                    std::fs::write(
                        &service.identity_store,
                        b"{\"version\":1,\"identities\":[]}",
                    )
                    .unwrap();
                }
                "after_password_expiry" => {
                    let clock = f.monotonic.clone();
                    *check.action.lock().unwrap() = Some(Box::new(move || {
                        clock.store(70, Ordering::SeqCst);
                    }));
                }
                "after_password_revocation" => {
                    let path = service.identity_store.clone();
                    *check.action.lock().unwrap() = Some(Box::new(move || {
                        std::fs::write(path, b"{\"version\":1,\"identities\":[]}").unwrap();
                    }));
                }
                "after_password_lock" => {
                    let app = f.app.clone();
                    *check.action.lock().unwrap() = Some(Box::new(move || {
                        app.lock().unwrap();
                    }));
                }
                _ => panic!("unknown test case"),
            }
            assert_ne!(
                service
                    .dispatch(
                        &leaf_fingerprint(CLIENT),
                        decision(&id, &token, "synthetic-password"),
                        &f.app
                    )
                    .status,
                200,
                "{case}"
            );
            assert_eq!(dispatch.0.load(Ordering::SeqCst), 0, "{case}");
        }
    }
    #[test]
    fn companion_review_replaces_ticket_and_deny_needs_no_password() {
        let f = fixture();
        let (service, check, dispatch) = service(&f);
        let id = request(&f, &service);
        let old = review(&service, &f, &id);
        let new = review(&service, &f, &id);
        assert_eq!(service.state.lock().unwrap().tickets.len(), 1);
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &old, "synthetic-password"),
                    &f.app
                )
                .status,
            409
        );
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    Command::Decision {
                        version: 1,
                        request_id: id.clone(),
                        ticket: new,
                        decision: Decision::Deny,
                        password: None
                    },
                    &f.app
                )
                .status,
            200
        );
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &id),
            Ok(DirectStatus::Denied)
        );
        assert_eq!(check.calls.load(Ordering::SeqCst), 0);
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 0);
    }
    fn wire(body: &str) -> String {
        format!(
            "POST /v1/companion HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        )
    }
    #[test]
    fn companion_closed_json_http_and_password_limits() {
        let good = wire(r#"{"version":1,"command":"session"}"#);
        assert!(read_command(&mut good.as_bytes()).is_ok());
        for body in [
            r#"{"version":1,"version":1,"command":"session"}"#,
            r#"{"version":1,"command":"session","extra":1}"#,
            r#"{"version":1,"command":"session","password":"secret"}"#,
            r#"{"version":2,"command":"session"}"#,
            r#"{"version":1,"command":"session","command":"list"}"#,
            r#"{"version":1,"command":"unlock","password":""}"#,
            r#"{"version":1,"command":"unlock","password":null}"#,
            r#"{"version":1,"command":"unlock","password":"one","password":"two"}"#,
        ] {
            assert!(read_command(&mut wire(body).as_bytes()).is_err(), "{body}");
        }
        for bad in [
            good.replace("POST ", "GET "),
            good.replace("/v1/companion ", "/v1/companion?x "),
            good.replace(
                "Content-Length:",
                "Transfer-Encoding: chunked\r\nContent-Length:",
            ),
            good.replace(
                "Content-Length:",
                "Content-Encoding: gzip\r\nContent-Length:",
            ),
            good.replace("Content-Length:", "Cookie: a\r\nContent-Length:"),
            good.replace("Host: localhost\r\n", ""),
            good.replace("Content-Length:", "Content-Length: 1\r\nContent-Length:"),
            good.replace("application/json", "text/plain"),
        ] {
            assert!(read_command(&mut bad.as_bytes()).is_err());
        }
        let too_long =
            serde_json::json!({"version":1,"command":"unlock","password":"x".repeat(4097)})
                .to_string();
        assert!(read_command(&mut wire(&too_long).as_bytes()).is_err());
        assert!(read_command(&mut "X".repeat(8193).as_bytes()).is_err());
        assert!(
            read_command(
                &mut good
                    .replace("Content-Length: 33", "Content-Length: 16385")
                    .as_bytes()
            )
            .is_err()
        );
    }
    fn client_config(identity: Option<(&[u8], &[u8])>) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(
                CertificateDer::from_pem_slice(include_bytes!(
                    "../../tests/fixtures/provider-tls/ca.pem"
                ))
                .unwrap(),
            )
            .unwrap();
        let builder = rustls::ClientConfig::builder().with_root_certificates(roots);
        Arc::new(match identity {
            Some((cert, key)) => builder
                .with_client_auth_cert(
                    vec![CertificateDer::from_pem_slice(cert).unwrap()],
                    PrivateKeyDer::from_pem_slice(key).unwrap(),
                )
                .unwrap(),
            None => builder.with_no_client_auth(),
        })
    }
    fn exchange(
        service: &Companion,
        app: &ProviderApplication,
        config: Arc<rustls::ClientConfig>,
    ) -> String {
        exchange_body(service, app, config, r#"{"version":1,"command":"session"}"#)
    }
    fn exchange_body(
        service: &Companion,
        app: &ProviderApplication,
        config: Arc<rustls::ClientConfig>,
        body: &str,
    ) -> String {
        std::thread::scope(|scope| {
            let worker = scope.spawn(|| {
                loop {
                    match service.listener.accept() {
                        Ok((socket, _)) => {
                            service.connection(socket, app, &AtomicBool::new(false));
                            break;
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(5))
                        }
                        Err(error) => panic!("{error}"),
                    }
                }
            });
            let socket = TcpStream::connect(service.listener.local_addr().unwrap()).unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            socket
                .set_write_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let connection = rustls::ClientConnection::new(
                config,
                rustls::pki_types::ServerName::try_from("127.0.0.1").unwrap(),
            )
            .unwrap();
            let mut stream = rustls::StreamOwned::new(connection, socket);
            let mut response = String::new();
            if stream.write_all(wire(body).as_bytes()).is_ok() {
                let _ignored = stream.read_to_string(&mut response);
            }
            worker.join().unwrap();
            response
        })
    }
    #[test]
    fn companion_fixture_lost_reply_is_after_commit_and_only_once() {
        let f = fixture();
        let (mut service, check, dispatch) = service(&f);
        let traffic = Arc::new(FixtureTraffic::armed());
        service.fixture_traffic = Some(traffic.clone());
        let send = |id: &str, ticket: &str, decision: &str, password: &str| {
            let mut body = serde_json::json!({"version":1,"command":"decision","request_id":id,"ticket":ticket,"decision":decision});
            if decision == "approve" {
                body["password"] = serde_json::Value::String(password.into());
            }
            exchange_body(
                &service,
                &f.app,
                client_config(Some((CLIENT, CLIENT_KEY))),
                &body.to_string(),
            )
        };
        let denied = request(&f, &service);
        let ticket = review(&service, &f, &denied);
        assert!(send(&denied, &ticket, "approve", "wrong-password").starts_with("HTTP/1.1 422"));
        assert!(
            send(&denied, &ticket, "approve", "synthetic-password").starts_with("HTTP/1.1 409")
        );
        let ticket = review(&service, &f, &denied);
        assert!(send(&denied, &ticket, "deny", "").starts_with("HTTP/1.1 200"));
        assert_eq!(traffic.snapshot()["dropped_approval_replies"], 0);
        let first = request(&f, &service);
        let ticket = review(&service, &f, &first);
        assert!(send(&first, &ticket, "approve", "synthetic-password").is_empty());
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 1);
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &first).unwrap(),
            DirectStatus::Approved
        );
        let status = exchange_body(
            &service,
            &f.app,
            client_config(Some((CLIENT, CLIENT_KEY))),
            &serde_json::json!({"version":1,"command":"status","request_id":first}).to_string(),
        );
        assert!(status.starts_with("HTTP/1.1 200"));
        assert!(status.contains("approved"));
        let second = request(&f, &service);
        let ticket = review(&service, &f, &second);
        assert!(
            send(&second, &ticket, "approve", "synthetic-password").starts_with("HTTP/1.1 200")
        );
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 2);
        assert_eq!(check.calls.load(Ordering::SeqCst), 3);
        let snapshot = traffic.snapshot();
        assert_eq!(snapshot["dropped_approval_replies"], 1);
        assert_eq!(snapshot["counts"]["decision"], 5);
        assert_eq!(
            snapshot["decision_status_sequence"],
            serde_json::json!([
                "decision", "decision", "decision", "decision", "status", "decision"
            ])
        );
        assert_eq!(snapshot["sequence_truncated"], false);
    }
    #[test]
    fn companion_real_mtls_requires_ca_and_exact_enrolled_leaf() {
        let f = fixture();
        let (service, _, _) = service(&f);
        assert!(
            exchange(&service, &f.app, client_config(Some((CLIENT, CLIENT_KEY))))
                .starts_with("HTTP/1.1 200")
        );
        assert!(!exchange(&service, &f.app, client_config(None)).contains("200 Response"));
        let other = exchange(
            &service,
            &f.app,
            client_config(Some((
                include_bytes!("../../tests/companion-tls/other.pem"),
                include_bytes!("../../tests/companion-tls/other-key.pem"),
            ))),
        );
        assert!(other.starts_with("HTTP/1.1 403"));
        assert!(!other.contains("unlocked"));
        let wrong = exchange(
            &service,
            &f.app,
            client_config(Some((
                include_bytes!("../../tests/fixtures/provider-tls/replacement.pem"),
                include_bytes!("../../tests/fixtures/provider-tls/replacement-key.pem"),
            ))),
        );
        assert!(!wrong.contains("200 Response"));
    }
    #[test]
    fn companion_ticket_capacity_is_bounded_and_existing_review_reuses_slot() {
        let f = fixture();
        let (service, _, _) = service(&f);
        let id = request(&f, &service);
        review(&service, &f, &id);
        {
            let mut state = service.state.lock().unwrap();
            let base = state.tickets[0].review.clone();
            for index in 1..MAX_TICKETS {
                let mut review = base.clone();
                review.id = format!("synthetic-{index}");
                state.tickets.push(Ticket {
                    token: format!("{index:064x}"),
                    device: leaf_fingerprint(CLIENT),
                    review,
                    generation: 1,
                    deadline: Duration::from_secs(70),
                });
            }
        }
        review(&service, &f, &id);
        assert_eq!(service.state.lock().unwrap().tickets.len(), MAX_TICKETS);
        let response = service.dispatch(
            &"b".repeat(64),
            Command::Review {
                version: 1,
                request_id: id,
            },
            &f.app,
        );
        assert_eq!(response.status, 503);
    }
    #[test]
    fn companion_unlock_is_separate_and_authentication_is_serialized() {
        let f = fixture();
        let (service, check, dispatch) = service(&f);
        let old = request(&f, &service);
        let token = review(&service, &f, &old);
        f.app.lock().unwrap();
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    Command::Unlock {
                        version: 1,
                        password: SensitiveString::new("synthetic-password".into())
                    },
                    &f.app
                )
                .status,
            200
        );
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&old, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            409
        );
        let id = request(&f, &service);
        let token = review(&service, &f, &id);
        let guard = service.authentication.lock().unwrap();
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            429
        );
        drop(guard);
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            409
        );
        assert_eq!(check.calls.load(Ordering::SeqCst), 0);
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn companion_missing_dispatcher_never_commits_approval() {
        let f = fixture();
        let (mut service, check, dispatch) = service(&f);
        service.execution_dispatcher = None;
        let id = request(&f, &service);
        let token = review(&service, &f, &id);
        assert_eq!(
            service
                .dispatch(
                    &leaf_fingerprint(CLIENT),
                    decision(&id, &token, "synthetic-password"),
                    &f.app
                )
                .status,
            503
        );
        assert_eq!(check.calls.load(Ordering::SeqCst), 0);
        assert_eq!(dispatch.0.load(Ordering::SeqCst), 0);
        assert_eq!(
            f.app.direct_status(f.app.human_owner(), &id),
            Ok(DirectStatus::Pending)
        );
    }
}

#[cfg(test)]
#[path = "companion_acceptance_tests.rs"]
mod acceptance_tests;
