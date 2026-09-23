//! Small, bounded HTTPS surface for the human desktop. No agent transport.
use crate::access::{
    application::{ProviderApplication, SessionStatus},
    ports::{ApprovalAuthenticator, SensitiveString, SessionError},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::Zeroizing;

const MAX_PASSWORD_BYTES: usize = 4096;
// Every input byte can be encoded as a six-byte JSON Unicode escape.
const MAX_BODY_BYTES: usize = MAX_PASSWORD_BYTES * 6 + 15;

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordInput {
    #[serde(deserialize_with = "deserialize_password")]
    password: SensitiveString,
}
fn deserialize_password<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SensitiveString, D::Error> {
    <String as serde::Deserialize>::deserialize(deserializer).map(SensitiveString::new)
}

struct BrowserSession {
    cookie: SensitiveString,
    csrf: SensitiveString,
}
pub struct LoopbackUi {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    origin: String,
    host: String,
    launch: Option<SensitiveString>,
    session: Option<BrowserSession>,
}
fn random() -> Result<SensitiveString, SessionError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_| SessionError::BackendUnavailable)?;
    Ok(SensitiveString::new(URL_SAFE_NO_PAD.encode(bytes)))
}
impl LoopbackUi {
    /// Artifact must be in the provider-owned 0700 state directory. The human
    /// opens this file in their desktop browser; nothing is printed to clients.
    pub fn bind(
        artifact: &Path,
        certificate: &Path,
        private_key: &Path,
    ) -> Result<Self, SessionError> {
        let tls = load_identity(certificate, private_key)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_| SessionError::BackendUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| SessionError::BackendUnavailable)?;
        let host = listener
            .local_addr()
            .map_err(|_| SessionError::BackendUnavailable)?
            .to_string();
        let origin = format!("https://{host}");
        let launch = random()?;
        let html = Zeroizing::new(format!(
            "<!doctype html><meta name=referrer content=no-referrer><title>Vaultwarden Access</title><a rel=noreferrer href=\"{origin}/#{}\">Open Vaultwarden Access</a>",
            launch.expose()
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(artifact)
            .map_err(|_| SessionError::BackendUnavailable)?;
        file.write_all(html.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| SessionError::BackendUnavailable)?;
        Ok(Self {
            listener,
            tls,
            origin,
            host,
            launch: Some(launch),
            session: None,
        })
    }
    pub fn serve(
        self,
        app: Arc<ProviderApplication>,
        stop: Arc<AtomicBool>,
    ) -> Result<(), SessionError> {
        // Parsing/handshake workers never hold the authority gate or UI mutex.
        // Exhaustion closes admission irreversibly instead of starving Lock.
        const MAX_CONNECTIONS: usize = 8;
        let listener = self
            .listener
            .try_clone()
            .map_err(|_| SessionError::BackendUnavailable)?;
        let tls = self.tls.clone();
        let ui = Arc::new(Mutex::new(self));
        let mut workers: Vec<std::thread::JoinHandle<Result<(), SessionError>>> = Vec::new();
        let mut result = Ok(());
        while !stop.load(Ordering::Acquire) {
            let mut i = 0;
            while i < workers.len() {
                if workers[i].is_finished() {
                    if !matches!(workers.swap_remove(i).join(), Ok(Ok(()))) {
                        result = Err(SessionError::BackendUnavailable);
                        stop.store(true, Ordering::Release);
                    }
                } else {
                    i += 1;
                }
            }
            if stop.load(Ordering::Acquire) {
                break;
            }
            match listener.accept() {
                Ok((stream, peer)) if peer.ip().is_loopback() => {
                    if workers.len() >= MAX_CONNECTIONS {
                        stop.store(true, Ordering::Release);
                        let _ = app.shutdown();
                        result = Err(SessionError::BackendUnavailable);
                        break;
                    }
                    let (ui, app, stop, tls) = (ui.clone(), app.clone(), stop.clone(), tls.clone());
                    workers.push(std::thread::spawn(move || {
                        let socket = DeadlineStream {
                            stream,
                            deadline: std::time::Instant::now() + Duration::from_secs(2),
                        };
                        let connection = rustls::ServerConnection::new(tls)
                            .map_err(|_| SessionError::BackendUnavailable)?;
                        let mut stream = rustls::StreamOwned::new(connection, socket);
                        let response = match read_request(&mut stream) {
                            Ok(request) => {
                                let mut ui =
                                    ui.lock().map_err(|_| SessionError::BackendUnavailable)?;
                                if stop.load(Ordering::Acquire) {
                                    Response::denied()
                                } else {
                                    ui.handle(request, app.as_ref())
                                }
                            }
                            Err(_) => Response::denied(),
                        };
                        stream.sock.deadline = std::time::Instant::now() + Duration::from_secs(2);
                        let _ = stream.write_all(response.encode().as_bytes());
                        Ok(())
                    }));
                }
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25))
                }
                Err(_) => {
                    result = Err(SessionError::BackendUnavailable);
                    break;
                }
            }
        }
        stop.store(true, Ordering::Release);
        // Close admission before waiting; always join EVERY accepted worker,
        // even if one failed. A second clear after joining is mandatory.
        let early_cleanup = app.shutdown();
        for worker in workers {
            if !matches!(worker.join(), Ok(Ok(()))) {
                result = Err(SessionError::BackendUnavailable);
            }
        }
        let final_cleanup = app.shutdown();
        early_cleanup.and(final_cleanup).and(result)
    }
    fn handle(&mut self, request: Request, app: &ProviderApplication) -> Response {
        if request.header("host") != Some(self.host.as_str()) {
            return Response::denied();
        }
        if request.method == "GET" && request.path == "/" {
            // This page is public and NEVER contains cookie-recoverable proof.
            // Proof comes only from the one-use launch POST and remains origin-
            // scoped in sessionStorage (cookies themselves are not port-scoped).
            return Response::html(r#"<!doctype html><title>Vaultwarden Access</title><h1>Vaultwarden Access</h1><form id=unlock hidden><label for=password>Master password</label><input id=password type=password autocomplete=current-password required maxlength=4096><button>Unlock for up to 15 minutes</button></form><button id=lock hidden>Lock</button><p id=result role=status>Open the provider desktop launch file.</p><script>
(async()=>{
const result=document.getElementById('result'), input=document.getElementById('password');
let capability=location.hash.slice(1);history.replaceState(null,'','/');
if(location.protocol!=='https:')return;
if(capability){try{let r=await fetch('/launch',{method:'POST',headers:{'Content-Type':'text/plain'},body:capability});capability='';if(!r.ok)throw Error();sessionStorage.setItem('vw_proof',await r.text());}catch{result.textContent='Launch unavailable';return;}}
const csrf=sessionStorage.getItem('vw_proof');if(!csrf)return;
document.getElementById('unlock').hidden=false;document.getElementById('lock').hidden=false;result.textContent='Ready for an action';
let mutations=Promise.resolve();
function act(path,password){input.value='';const run=async()=>{try{const body=JSON.stringify({password});password='';let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body});result.textContent='Last action result: '+await r.text();}catch{password='';result.textContent='Last action result: Provider unavailable';}};mutations=mutations.then(run,run);}
document.getElementById('unlock').onsubmit=e=>{e.preventDefault();act('/unlock',input.value)};document.getElementById('lock').onclick=()=>act('/lock','');
})();</script>"#.into());
        }
        if request.method != "POST" || request.header("origin") != Some(self.origin.as_str()) {
            return Response::denied();
        }
        if request.path == "/launch" {
            if request.header("content-type") != Some("text/plain")
                || self
                    .launch
                    .as_ref()
                    .is_none_or(|launch| request.body.as_slice() != launch.expose().as_bytes())
            {
                return Response::denied();
            }
            self.launch = None;
            let (Ok(cookie), Ok(csrf)) = (random(), random()) else {
                return Response::denied();
            };
            let header = format!(
                "vw_session={}; Secure; HttpOnly; SameSite=Strict; Path=/",
                cookie.expose()
            );
            let proof = csrf.expose().to_owned();
            self.session = Some(BrowserSession { cookie, csrf });
            return Response {
                status: 200,
                body: proof,
                cookie: Some(header),
                html: false,
            };
        }
        if !self.authenticated(&request)
            || request.header("x-csrf-token") != self.session.as_ref().map(|s| s.csrf.expose())
            || request.header("content-type") != Some("application/json")
        {
            return Response::denied();
        }
        let result = match request.path.as_str() {
            "/unlock" => match serde_json::from_slice::<PasswordInput>(&request.body) {
                Ok(input) => {
                    let password = input.password;
                    if password.expose().is_empty() || password.expose().len() > MAX_PASSWORD_BYTES
                    {
                        Err(SessionError::InvalidRequest)
                    } else {
                        app.authenticate(password)
                    }
                }
                Err(_) => Err(SessionError::InvalidRequest),
            },
            "/lock" => app.lock(),
            _ => Err(SessionError::InvalidRequest),
        };
        match result {
            Ok(()) => Response::text(match app.status() {
                Ok(SessionStatus::Unlocked) => "Provider unlocked",
                _ => "Provider locked",
            }),
            Err(error) => Response {
                status: 403,
                body: error.to_string(),
                cookie: None,
                html: false,
            },
        }
    }
    fn authenticated(&self, request: &Request) -> bool {
        self.session.as_ref().is_some_and(|session| {
            let Some(cookies) = request.header("cookie") else {
                return false;
            };
            let mut found = None;
            for pair in cookies.split(';') {
                let Some((name, value)) = pair.trim().split_once('=') else {
                    return false;
                };
                if name == "vw_session" {
                    if found.is_some() {
                        return false;
                    }
                    found = Some(value);
                }
            }
            found == Some(session.cookie.expose())
        })
    }
}

// Both PEM files are provisioned by the human outside agent-writable storage.
fn identity_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| SessionError::BackendUnavailable)?;
    let meta = file
        .metadata()
        .map_err(|_| SessionError::BackendUnavailable)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o777 != 0o600
        || meta.nlink() != 1
    {
        return Err(SessionError::BackendUnavailable);
    }
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| SessionError::BackendUnavailable)?;
    if bytes.len() > 65536 {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(bytes)
}
fn load_identity(
    certificate: &Path,
    private_key: &Path,
) -> Result<Arc<rustls::ServerConfig>, SessionError> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
    crate::install_rustls_crypto_provider();
    let certificates = identity_file(certificate)?;
    let key = identity_file(private_key)?;
    let chain = CertificateDer::pem_slice_iter(&certificates)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| SessionError::BackendUnavailable)?;
    let key = PrivateKeyDer::from_pem_slice(&key).map_err(|_| SessionError::BackendUnavailable)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_| SessionError::BackendUnavailable)?;
    Ok(Arc::new(config))
}

struct DeadlineStream {
    stream: TcpStream,
    deadline: std::time::Instant,
}
impl DeadlineStream {
    fn remaining(&self) -> std::io::Result<Duration> {
        self.deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|d| !d.is_zero())
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

struct Request {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Zeroizing<Vec<u8>>,
}
impl Request {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    }
}
fn read_request(stream: &mut impl Read) -> Result<Request, SessionError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    let mut bytes = Zeroizing::new(Vec::new());
    let header_end = loop {
        if bytes.len() >= 8192 {
            return Err(SessionError::InvalidRequest);
        }
        let mut byte = [0];
        read_before(stream, &mut byte, deadline)?;
        bytes.push(byte[0]);
        if bytes.ends_with(b"\r\n\r\n") {
            break bytes.len();
        }
    };
    let header =
        std::str::from_utf8(&bytes[..header_end]).map_err(|_| SessionError::InvalidRequest)?;
    let mut lines = header.split("\r\n");
    let first: Vec<_> = lines
        .next()
        .ok_or(SessionError::InvalidRequest)?
        .split(' ')
        .collect();
    if first.len() != 3 || first[2] != "HTTP/1.1" {
        return Err(SessionError::InvalidRequest);
    }
    let mut request = Request {
        method: first[0].into(),
        path: first[1].into(),
        headers: Vec::new(),
        body: Zeroizing::new(Vec::new()),
    };
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(SessionError::InvalidRequest)?;
        let name = name.to_ascii_lowercase();
        if request.header(&name).is_some() || name == "transfer-encoding" {
            return Err(SessionError::InvalidRequest);
        }
        request.headers.push((name, value.trim().into()));
    }
    let length = request
        .header("content-length")
        .unwrap_or("0")
        .parse::<usize>()
        .map_err(|_| SessionError::InvalidRequest)?;
    if length > MAX_BODY_BYTES {
        return Err(SessionError::InvalidRequest);
    }
    request.body.resize(length, 0);
    read_before(stream, &mut request.body, deadline)?;
    Ok(request)
}
fn read_before(
    stream: &mut impl Read,
    mut buffer: &mut [u8],
    deadline: std::time::Instant,
) -> Result<(), SessionError> {
    while !buffer.is_empty() {
        let _remaining = deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|duration| !duration.is_zero())
            .ok_or(SessionError::InvalidRequest)?;
        let count = stream
            .read(buffer)
            .map_err(|_| SessionError::InvalidRequest)?;
        if count == 0 {
            return Err(SessionError::InvalidRequest);
        }
        buffer = &mut buffer[count..];
    }
    Ok(())
}
struct Response {
    status: u16,
    body: String,
    cookie: Option<String>,
    html: bool,
}
impl Response {
    fn denied() -> Self {
        Self {
            status: 403,
            body: "Invalid human request".into(),
            cookie: None,
            html: false,
        }
    }
    fn text(body: &str) -> Self {
        Self {
            status: 200,
            body: body.into(),
            cookie: None,
            html: false,
        }
    }
    fn html(body: String) -> Self {
        Self {
            status: 200,
            body,
            cookie: None,
            html: true,
        }
    }
    fn encode(&self) -> String {
        format!(
            "HTTP/1.1 {} Response\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\nConnection: close\r\n{}\r\n{}",
            self.status,
            if self.html { "text/html" } else { "text/plain" },
            self.body.len(),
            self.cookie
                .as_ref()
                .map(|cookie| format!("Set-Cookie: {cookie}\r\n"))
                .unwrap_or_default(),
            self.body
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::{
        ports::{CredentialBinding, ProviderSession, SecretBackend},
        provider::Provider,
    };
    use crate::adapters::session::MonotonicClock;
    use std::sync::atomic::AtomicUsize;
    struct Backend(Arc<AtomicUsize>);
    impl ProviderSession for Backend {
        fn probe_compatibility(&mut self) -> Result<(), SessionError> {
            Ok(())
        }
        fn unlock(&mut self, password: SensitiveString) -> Result<Duration, SessionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if password.expose() == "password-sentinel" {
                Ok(Duration::from_secs(900))
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        }
        fn clear(&mut self) -> Result<(), SessionError> {
            Ok(())
        }
    }
    impl SecretBackend for Backend {
        fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
            panic!("UI cannot read items")
        }
        fn resolve(
            &mut self,
            _: &CredentialBinding<'_>,
        ) -> Result<Vec<SensitiveString>, SessionError> {
            panic!("UI cannot resolve secrets")
        }
    }
    fn request(ui: &LoopbackUi, path: &str, body: &str) -> Request {
        let mut headers = vec![
            ("host".into(), ui.host.clone()),
            ("origin".into(), ui.origin.clone()),
            ("content-type".into(), "application/json".into()),
        ];
        if let Some(session) = &ui.session {
            headers.push((
                "cookie".into(),
                format!("vw_session={}", session.cookie.expose()),
            ));
            headers.push(("x-csrf-token".into(), session.csrf.expose().into()));
        }
        Request {
            method: "POST".into(),
            path: path.into(),
            headers,
            body: Zeroizing::new(body.as_bytes().to_vec()),
        }
    }
    fn identity(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::os::unix::fs::PermissionsExt;
        let certificate = dir.join("server.pem");
        let key = dir.join("server-key.pem");
        std::fs::write(
            &certificate,
            include_bytes!("../../tests/fixtures/provider-tls/server.pem"),
        )
        .unwrap();
        std::fs::write(
            &key,
            include_bytes!("../../tests/fixtures/provider-tls/server-key.pem"),
        )
        .unwrap();
        for path in [&certificate, &key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        (certificate, key)
    }
    fn fixture() -> (
        tempfile::TempDir,
        LoopbackUi,
        ProviderApplication,
        Arc<AtomicUsize>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let calls = Arc::new(AtomicUsize::new(0));
        let app = ProviderApplication::new(
            Provider::start(dir.path().join("provider")).unwrap(),
            Box::new(Backend(calls.clone())),
            Box::<MonotonicClock>::default(),
        )
        .unwrap();
        let (certificate, key) = identity(dir.path());
        let ui = LoopbackUi::bind(&dir.path().join("launch.html"), &certificate, &key).unwrap();
        (dir, ui, app, calls)
    }
    fn launch(ui: &mut LoopbackUi, app: &ProviderApplication) -> Response {
        let mut req = request(ui, "/launch", ui.launch.as_ref().unwrap().expose());
        req.headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        ui.handle(req, app)
    }
    #[test]
    fn launch_is_private_one_use_and_session_is_bound_to_csrf() {
        use std::os::unix::fs::PermissionsExt;
        let (dir, mut ui, app, calls) = fixture();
        assert_eq!(
            std::fs::metadata(dir.path().join("launch.html"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let old_launch = ui.launch.as_ref().unwrap().expose().to_owned();
        let response = launch(&mut ui, &app);
        assert_eq!(response.status, 200);
        let encoded = response.encode();
        for required in [
            "HttpOnly",
            "SameSite=Strict",
            "Cache-Control: no-store",
            "Referrer-Policy: no-referrer",
            "frame-ancestors 'none'",
        ] {
            assert!(encoded.contains(required));
        }
        assert!(!encoded.contains(&old_launch));
        assert!(ui.launch.is_none());
        let mut replay = request(&ui, "/launch", &old_launch);
        replay
            .headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(replay, &app).status, 403);
        let mut csrf_missing = request(&ui, "/unlock", r#"{"password":"password-sentinel"}"#);
        csrf_missing
            .headers
            .retain(|(key, _)| key != "x-csrf-token");
        assert_eq!(ui.handle(csrf_missing, &app).status, 403);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        let response = ui.handle(
            request(&ui, "/unlock", r#"{"password":"password-sentinel"}"#),
            &app,
        );
        assert_eq!(response.status, 200);
        assert_eq!(response.body, "Provider unlocked");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!response.encode().contains("password-sentinel"));
        assert_eq!(
            ui.handle(request(&ui, "/lock", "{}"), &app).body,
            "Provider locked"
        );
        assert_eq!(app.status(), Ok(SessionStatus::Locked));
    }

    #[test]
    fn tls_identity_rejects_owned_fifo_even_with_valid_certificate_contents() {
        let dir = tempfile::tempdir().unwrap();
        let (cert, _) = identity(dir.path());
        let contents = std::fs::read(&cert).unwrap();
        assert_eq!(identity_file(&cert).unwrap().as_slice(), contents);
        let fifo = dir.path().join("certificate.fifo");
        let _keeper = crate::adapters::buffered_fifo(&fifo, &contents);
        assert_eq!(
            crate::adapters::within_test_deadline(move || identity_file(&fifo).unwrap_err()),
            SessionError::BackendUnavailable
        );
    }

    #[test]
    fn tls_identity_requires_private_single_link_files_and_exact_size_bound() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (cert, key) = identity(dir.path());
        assert!(load_identity(&cert, &key).is_ok());
        for path in [&cert, &key] {
            for mode in [0o644, 0o640, 0o400] {
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
                assert!(load_identity(&cert, &key).is_err());
            }
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            let linked = dir.path().join("extra-link.pem");
            std::fs::hard_link(path, &linked).unwrap();
            assert!(load_identity(&cert, &key).is_err());
            std::fs::remove_file(linked).unwrap();
            assert!(load_identity(&cert, &key).is_ok());
            let symlink = dir.path().join("symlink.pem");
            std::os::unix::fs::symlink(path, &symlink).unwrap();
            assert!(identity_file(&symlink).is_err());
            std::fs::remove_file(symlink).unwrap();
        }
        let mut padded = std::fs::read(&cert).unwrap();
        padded.resize(65536, b'\n');
        std::fs::write(&cert, &padded).unwrap();
        assert_eq!(identity_file(&cert).unwrap().len(), 65536);
        assert!(load_identity(&cert, &key).is_ok());
        padded.push(b'\n');
        std::fs::write(&cert, &padded).unwrap();
        assert!(identity_file(&cert).is_err());
        assert!(load_identity(&cert, &key).is_err());
    }
    #[test]
    fn cookie_only_pages_never_recover_proof_and_cookie_pairs_are_unambiguous() {
        let (_dir, mut ui, app, calls) = fixture();
        let launch = launch(&mut ui, &app);
        let proof = launch.body;
        assert_eq!(proof.len(), 43);
        let mut get = request(&ui, "/", "");
        get.method = "GET".into();
        get.headers.retain(|(name, _)| name != "x-csrf-token");
        let page = ui.handle(get, &app);
        assert_eq!(page.status, 200);
        assert!(!page.body.contains(&proof));
        assert!(page.body.contains("sessionStorage.getItem('vw_proof')"));
        assert!(
            page.body
                .contains("function act(path,password){input.value='';")
        );
        assert!(page.body.contains("mutations=mutations.then(run,run)"));
        assert!(page.body.contains("Last action result: "));
        let mut request = request(&ui, "/unlock", r#"{"password":"password-sentinel"}"#);
        let cookie = request.header("cookie").unwrap().to_owned();
        for value in [
            format!("other=ok; {cookie}; preference=value"),
            format!("{cookie}; vw_session=bad"),
            format!("vw_session=bad; {cookie}"),
            "vw_session".into(),
        ] {
            request
                .headers
                .iter_mut()
                .find(|(name, _)| name == "cookie")
                .unwrap()
                .1 = value.clone();
            assert_eq!(ui.authenticated(&request), value.starts_with("other="));
        }
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn tls_identity_requires_owned_bounded_regular_private_files_and_matching_key() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let (certificate, key) = identity(dir.path());
        assert!(load_identity(&certificate, &key).is_ok());
        for path in [&certificate, &key] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
            assert!(load_identity(&certificate, &key).is_err());
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let link = dir.path().join("linked");
        std::fs::hard_link(&key, &link).unwrap();
        assert!(load_identity(&certificate, &key).is_err());
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(load_identity(&certificate, &link).is_err());
        std::fs::remove_file(&link).unwrap();
        std::fs::write(
            &key,
            include_bytes!("../../tests/fixtures/provider-tls/replacement-key.pem"),
        )
        .unwrap();
        assert!(load_identity(&certificate, &key).is_err());
        std::fs::write(&key, "key-sentinel").unwrap();
        assert!(load_identity(&certificate, &key).is_err());
        std::fs::write(&key, vec![b' '; 65536]).unwrap();
        assert_eq!(identity_file(&key).unwrap().len(), 65536);
        std::fs::write(&key, vec![b' '; 65537]).unwrap();
        assert!(identity_file(&key).is_err());
        std::fs::remove_file(&key).unwrap();
        assert!(load_identity(&certificate, &key).is_err());
        std::fs::create_dir(&key).unwrap();
        assert!(identity_file(&key).is_err());
    }

    #[test]
    fn hostile_requests_never_authenticate_or_reflect_passwords() {
        let (_dir, mut ui, app, calls) = fixture();
        launch(&mut ui, &app);
        for (key, value) in [
            ("host", "evil.test"),
            ("origin", "http://evil.test"),
            ("cookie", "vw_session=wrong"),
            ("x-csrf-token", "wrong"),
            ("content-type", "text/plain"),
        ] {
            let mut req = request(&ui, "/unlock", r#"{"password":"password-sentinel"}"#);
            req.headers
                .iter_mut()
                .find(|(name, _)| name == key)
                .unwrap()
                .1 = value.into();
            let response = ui.handle(req, &app);
            assert_eq!(response.status, 403);
            assert!(!response.encode().contains("password-sentinel"));
        }
        for path in ["/unlock?password=password-sentinel", "/status", "/resolve"] {
            assert_eq!(
                ui.handle(
                    request(&ui, path, r#"{"password":"password-sentinel"}"#),
                    &app
                )
                .status,
                403
            );
        }
        for body in [
            "secret-sentinel",
            r#"{"password":"password-sentinel","session":"session-sentinel"}"#,
            r#"{"password":""}"#,
            r#"{"password":"password-sentinel","password":"second-sentinel"}"#,
            r#"{"password":"password-sentinel", broken}"#,
            r#"{"password":"password-sentinel"} trailing"#,
        ] {
            let response = ui.handle(request(&ui, "/unlock", body), &app);
            assert_eq!(response.status, 403);
            assert!(!response.encode().contains("sentinel"));
        }
        let body = format!("{{\"password\":\"{}\"}}", "p".repeat(4097));
        assert_eq!(ui.handle(request(&ui, "/unlock", &body), &app).status, 403);
        let mut req = request(&ui, "/unlock", r#"{"password":"password-sentinel"}"#);
        req.method = "GET".into();
        assert_eq!(ui.handle(req, &app).status, 403);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn password_limit_allows_exactly_4096_bytes_without_reflecting_input() {
        let (_dir, mut ui, app, calls) = fixture();
        launch(&mut ui, &app);
        let password = "p".repeat(4096);
        let body = serde_json::json!({"password": password}).to_string();
        let response = ui.handle(request(&ui, "/unlock", &body), &app);
        assert_eq!(response.body, "authentication failed");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!response.encode().contains(&password));
        let body = serde_json::json!({"password": "p".repeat(4097)}).to_string();
        assert_eq!(
            ui.handle(request(&ui, "/unlock", &body), &app).body,
            "invalid human request"
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }
    #[test]
    fn restart_does_not_accept_old_launch_cookie_or_csrf() {
        let (_dir, mut first, app, _) = fixture();
        let old_capability = first.launch.as_ref().unwrap().expose().to_owned();
        launch(&mut first, &app);
        let old_request = request(&first, "/unlock", r#"{"password":"password-sentinel"}"#);
        let (_dir2, mut second, app2, calls) = fixture();
        launch(&mut second, &app2);
        let mut req = old_request;
        for (key, value) in &mut req.headers {
            if key == "host" {
                *value = second.host.clone();
            }
            if key == "origin" {
                *value = second.origin.clone();
            }
        }
        assert_eq!(second.handle(req, &app2).status, 403);
        let mut req = request(&second, "/launch", &old_capability);
        req.headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(second.handle(req, &app2).status, 403);
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }
    #[test]
    fn parser_bounds_body_and_rejects_ambiguous_framing() {
        fn parse(raw: &str) -> Result<Request, SessionError> {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
            let address = listener.local_addr().unwrap();
            let raw = raw.to_owned();
            let writer = std::thread::spawn(move || {
                let mut client = TcpStream::connect(address).unwrap();
                client.write_all(raw.as_bytes()).unwrap();
            });
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let result = read_request(&mut stream);
            writer.join().unwrap();
            result
        }
        for raw in [
            "POST /unlock HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "POST /unlock HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            "POST /unlock HTTP/1.1\r\nContent-Length: 24592\r\n\r\n",
            "GET / HTTP/1.0\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: 2\r\n\r\n",
            "POST / HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
        ] {
            assert!(parse(raw).is_err());
        }
        let request =
            parse("POST /unlock HTTP/1.1\r\nHost: 127.0.0.1:1\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        assert_eq!(request.method, "POST");
        assert_eq!(request.path, "/unlock");
        assert_eq!(request.header("host"), Some("127.0.0.1:1"));
        assert_eq!(request.body.as_slice(), b"{}");
        let largest = format!(
            "POST / HTTP/1.1\r\nContent-Length: 24591\r\n\r\n{}",
            "x".repeat(24591)
        );
        assert_eq!(parse(&largest).unwrap().body.len(), 24591);
        let complete_oversized = format!(
            "POST / HTTP/1.1\r\nContent-Length: 24592\r\n\r\n{}",
            "x".repeat(24592)
        );
        assert!(read_request(&mut complete_oversized.as_bytes()).is_err());
        let oversized = format!("GET / HTTP/1.1\r\nX-Large: {}\r\n\r\n", "x".repeat(8192));
        assert!(parse(&oversized).is_err());
        let prefix = "GET / HTTP/1.1\r\nX-Large: ";
        let suffix = "\r\n\r\n";
        let boundary = format!(
            "{prefix}{}{suffix}",
            "x".repeat(8192 - prefix.len() - suffix.len())
        );
        assert!(parse(&boundary).is_ok());
        let over = format!(
            "{prefix}{}{suffix}",
            "x".repeat(8193 - prefix.len() - suffix.len())
        );
        assert!(parse(&over).is_err());
    }
}
