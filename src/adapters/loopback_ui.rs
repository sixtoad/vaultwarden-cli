//! Small, bounded HTTPS surface for the human desktop. No agent transport.
use crate::access::{
    application::{ProviderApplication, SessionStatus},
    direct_request::{DirectRequestError, DirectStatus, valid_request_id},
    ports::{ApprovalAuthenticator, DirectReviewLauncher, SensitiveString, SessionError},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, Zeroizing};

const MAX_PASSWORD_BYTES: usize = 4096;
// Every input byte can be encoded as a six-byte JSON Unicode escape.
const MAX_BODY_BYTES: usize = MAX_PASSWORD_BYTES * 6 + 128;

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
    decision_generation: u64,
}
pub struct LoopbackUi {
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
    origin: String,
    host: String,
    launch: Option<SensitiveString>,
    sessions: Vec<BrowserSession>,
    broker: Arc<RequestLaunchBroker>,
    approval_authenticator: Option<Arc<dyn ApprovalAuthenticator + Send + Sync>>,
}
const MAX_BROWSER_SESSIONS: usize = 64;
const MAX_REQUEST_LAUNCHES: usize = 64;
struct RequestLaunch {
    capability: SensitiveString,
    request_id: String,
    artifact: PathBuf,
}
impl Drop for RequestLaunch {
    fn drop(&mut self) {
        let _ignored = std::fs::remove_file(&self.artifact);
    }
}
struct RequestLaunchBroker {
    origin: String,
    directory: PathBuf,
    pending: Mutex<Vec<RequestLaunch>>,
    desktop: Box<dyn super::desktop_launch::DesktopOpener>,
}
impl DirectReviewLauncher for RequestLaunchBroker {
    fn launch(&self, request_id: &str) -> Result<(), DirectRequestError> {
        if !valid_request_id(request_id) {
            return Err(DirectRequestError::ReviewUnavailable);
        }
        let mut pending = self
            .pending
            .lock()
            .map_err(|_error| DirectRequestError::ReviewUnavailable)?;
        if pending.len() >= MAX_REQUEST_LAUNCHES {
            return Err(DirectRequestError::ReviewUnavailable);
        }
        let capability = random().map_err(|_error| DirectRequestError::ReviewUnavailable)?;
        let artifact = self.directory.join(format!("review-{request_id}.html"));
        let html = Zeroizing::new(format!(
            "<!doctype html><html lang=en><meta name=referrer content=no-referrer><title>Review request</title><a rel=noreferrer href=\"{}/#{}:{}\">Review one-time request</a><script>location.replace(document.querySelector('a').href)</script></html>",
            self.origin,
            capability.expose(),
            request_id
        ));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&artifact)
            .map_err(|_error| DirectRequestError::ReviewUnavailable)?;
        let launch = RequestLaunch {
            capability,
            request_id: request_id.to_owned(),
            artifact,
        };
        file.write_all(html.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_error| DirectRequestError::ReviewUnavailable)?;
        self.desktop.open(&launch.artifact)?;
        pending.push(launch);
        Ok(())
    }
}
impl RequestLaunchBroker {
    fn take(&self, capability: &[u8]) -> Option<RequestLaunch> {
        let mut pending = self.pending.lock().ok()?;
        let index = pending
            .iter()
            .position(|item| item.capability.expose().as_bytes() == capability)?;
        Some(pending.swap_remove(index))
    }
    fn prune(&self, app: &ProviderApplication) {
        // Never call the application while holding this mutex: submission owns
        // the authority gate before entering the launch port.
        let ids: Vec<String> = match self.pending.lock() {
            Ok(pending) => pending.iter().map(|item| item.request_id.clone()).collect(),
            Err(_) => return,
        };
        for id in ids {
            if !matches!(
                app.direct_status(app.human_owner(), &id),
                Ok(DirectStatus::Pending)
            ) && let Ok(mut pending) = self.pending.lock()
            {
                pending.retain(|item| item.request_id != id);
            }
        }
    }
}
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ReviewInput {
    request_id: String,
}
fn random() -> Result<SensitiveString, SessionError> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(|_error| SessionError::BackendUnavailable)?;
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
        let directory = artifact.parent().ok_or(SessionError::BackendUnavailable)?;
        let metadata = std::fs::symlink_metadata(directory)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        require_private_directory(metadata.is_dir(), metadata.uid(), metadata.mode(), unsafe {
            libc::geteuid()
        })?;
        let directory = directory
            .canonicalize()
            .map_err(|_error| SessionError::BackendUnavailable)?;
        // A previous daemon cannot leave live authority; discard its private handoffs.
        for entry in
            std::fs::read_dir(&directory).map_err(|_error| SessionError::BackendUnavailable)?
        {
            let entry = entry.map_err(|_error| SessionError::BackendUnavailable)?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if name
                .strip_prefix("review-")
                .and_then(|s| s.strip_suffix(".html"))
                .is_some_and(valid_request_id)
            {
                std::fs::remove_file(entry.path())
                    .map_err(|_error| SessionError::BackendUnavailable)?;
            }
        }
        let tls = load_identity(certificate, private_key)?;
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .map_err(|_error| SessionError::BackendUnavailable)?;
        listener
            .set_nonblocking(true)
            .map_err(|_error| SessionError::BackendUnavailable)?;
        let host = listener
            .local_addr()
            .map_err(|_error| SessionError::BackendUnavailable)?
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
            .map_err(|_error| SessionError::BackendUnavailable)?;
        file.write_all(html.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_error| SessionError::BackendUnavailable)?;
        Ok(Self {
            listener,
            tls,
            broker: Arc::new(RequestLaunchBroker {
                origin: origin.clone(),
                directory,
                pending: Mutex::new(Vec::new()),
                desktop: Box::new(super::desktop_launch::SystemDesktop),
            }),
            origin,
            host,
            launch: Some(launch),
            sessions: Vec::new(),
            approval_authenticator: None,
        })
    }
    pub fn with_approval_authenticator(
        mut self,
        authenticator: Arc<dyn ApprovalAuthenticator + Send + Sync>,
    ) -> Self {
        self.approval_authenticator = Some(authenticator);
        self
    }
    fn dispatch(ui: &Mutex<Self>, mut request: Request, app: &ProviderApplication) -> Response {
        let mut locked = match ui.lock() {
            Ok(locked) => locked,
            Err(_) => return Response::denied(),
        };
        if request.path != "/approve" {
            return locked.handle(request, app);
        }
        if !locked.decision_authorized(&request, app) {
            return Response::denied();
        }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct ApprovalInput {
            request_id: String,
            #[serde(deserialize_with = "deserialize_password")]
            password: SensitiveString,
        }
        let Ok(input) = serde_json::from_slice::<ApprovalInput>(&request.body) else {
            return Response::denied();
        };
        request.body.zeroize();
        let Ok(prepared) = app.prepare_approval(app.human_owner(), &input.request_id) else {
            return Response::denied();
        };
        let Some(authenticator) = locked.approval_authenticator.clone() else {
            return Response::denied();
        };
        // Both UI and provider serialization are released during password verification.
        drop(locked);
        let authenticated = prepared.authenticate(input.password, authenticator.as_ref());
        let locked = match ui.lock() {
            Ok(locked) => locked,
            Err(_) => return Response::denied(),
        };
        if !locked.decision_authorized(&request, app) {
            return Response::denied();
        }
        match authenticated.and_then(|proof| app.commit_approval(proof)) {
            Ok(DirectStatus::Approved) => {
                Response::text("Request approved once. Execution has not started.")
            }
            _ => Response::denied(),
        }
    }
    fn decision_authorized(&self, request: &Request, app: &ProviderApplication) -> bool {
        request.method == "POST"
            && request.header("host") == Some(self.host.as_str())
            && request.header("origin") == Some(self.origin.as_str())
            && request.header("content-type") == Some("application/json")
            && self.browser_session(request).is_some_and(|session| {
                request.header("x-csrf-token") == Some(session.csrf.expose())
                    && app.decision_generation().ok() == Some(session.decision_generation)
            })
    }
    pub fn request_launcher(&self) -> Arc<dyn DirectReviewLauncher> {
        self.broker.clone()
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
            .map_err(|_error| SessionError::BackendUnavailable)?;
        let tls = self.tls.clone();
        let broker = self.broker.clone();
        let ui = Arc::new(Mutex::new(self));
        let mut prune_at = std::time::Instant::now();
        let mut workers: Vec<std::thread::JoinHandle<Result<(), SessionError>>> = Vec::new();
        let mut result = Ok(());
        while !stop.load(Ordering::Acquire) {
            if prune_due(std::time::Instant::now(), &mut prune_at) {
                broker.prune(&app);
            }
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
            match accepted_connection(listener.accept()) {
                Ok(AcceptedConnection::Loopback(stream)) => {
                    if workers.len() >= MAX_CONNECTIONS {
                        stop.store(true, Ordering::Release);
                        let _ignored = app.shutdown();
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
                            .map_err(|_error| SessionError::BackendUnavailable)?;
                        let mut stream = rustls::StreamOwned::new(connection, socket);
                        let response = match read_request(&mut stream) {
                            Ok(request) => {
                                if stop.load(Ordering::Acquire) {
                                    Response::denied()
                                } else {
                                    Self::dispatch(&ui, request, app.as_ref())
                                }
                            }
                            Err(_) => Response::denied(),
                        };
                        stream.sock.deadline = std::time::Instant::now() + Duration::from_secs(2);
                        let _ignored = stream.write_all(response.encode().as_bytes());
                        Ok(())
                    }));
                }
                Ok(AcceptedConnection::NonLoopback) => {}
                Ok(AcceptedConnection::Idle) => std::thread::sleep(Duration::from_millis(25)),
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
        if let Ok(mut pending) = broker.pending.lock() {
            pending.clear();
        }
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
            return Response::html(r#"<!doctype html><html lang=en><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>Vaultwarden Access</title><style>
body{font-family:system-ui,sans-serif;max-width:54rem;margin:2rem auto;padding:0 1rem;color:#142033;background:#fff}button,input{font:inherit;margin:.5rem;padding:.6rem}button:focus-visible,input:focus-visible,a:focus-visible{outline:3px solid #124ed0;outline-offset:3px}dt{font-weight:bold;margin-top:1rem}dd{margin:.25rem 0;overflow-wrap:anywhere}#result,#review-status{padding:.75rem;border:2px solid #64748b}[hidden]{display:none}
</style><main><h1>Vaultwarden Access</h1><section aria-labelledby=session-title><h2 id=session-title>Provider session</h2><form id=unlock hidden><label for=password>Master password</label><input id=password type=password autocomplete=current-password required maxlength=4096><button>Unlock for up to 15 minutes</button></form><button id=lock hidden>Lock</button><p id=result role=status aria-live=polite aria-atomic=true>Open the provider desktop launch file.</p></section><section id=review hidden aria-labelledby=review-title><h2 id=review-title>Review one-time request</h2><p>Decide this request once. Approval does not start execution at this stage.</p><dl id=details></dl><p id=review-status role=status aria-live=polite aria-atomic=true>Loading request status</p><p id=decision-feedback role=status aria-live=polite aria-atomic=true></p><div id=decisions hidden><button id=deny type=button>Deny request</button><button id=begin-approval type=button>Authenticate and approve once</button><form id=approval hidden><label for=approval-password>Master password for this approval</label><input id=approval-password type=password autocomplete=current-password required maxlength=4096><button id=approve type=submit>Approve once</button><button id=cancel-approval type=button>Cancel authentication</button></form></div><button id=refresh type=button>Refresh request status</button></section></main><script>
(async()=>{
const result=document.getElementById('result'), input=document.getElementById('password');
let [capability,requestId]=location.hash.slice(1).split(':');history.replaceState(null,'','/');
if(location.protocol!=='https:')return;
if(capability){try{await navigator.locks.request('vw-launch',async()=>{const r=await fetch('/launch',{method:'POST',headers:{'Content-Type':'text/plain'},body:capability});capability='';if(!r.ok)throw Error();sessionStorage.setItem('vw_proof',await r.text());if(requestId)sessionStorage.setItem('vw_request',requestId);});}catch{result.textContent='Launch unavailable';return;}}
const csrf=sessionStorage.getItem('vw_proof');if(!csrf)return;
requestId=sessionStorage.getItem('vw_request');
document.getElementById('unlock').hidden=false;document.getElementById('lock').hidden=false;result.textContent='Ready for an action';
let mutations=Promise.resolve();
function act(path,password){input.value='';const run=async()=>{try{const body=JSON.stringify({password});password='';let r=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body});result.textContent='Last action result: '+await r.text();if(requestId)await review();}catch{password='';result.textContent='Last action result: Provider unavailable';}};mutations=mutations.then(run,run);}
document.getElementById('unlock').onsubmit=e=>{e.preventDefault();act('/unlock',input.value)};document.getElementById('lock').onclick=()=>act('/lock','');
let reviewRequest=null,reviewEpoch=0,timer,detailsReady=false,retryDelay=1000,deciding=false,retired=false;
const decisions=document.getElementById('decisions'),approval=document.getElementById('approval'),approvalPassword=document.getElementById('approval-password'),beginApproval=document.getElementById('begin-approval'),refresh=document.getElementById('refresh'),feedback=document.getElementById('decision-feedback');
function showFeedback(text){if(!retired)feedback.textContent=text;}
function decisionControls(unavailable){if(unavailable&&decisions.contains(document.activeElement))refresh.focus();decisions.querySelectorAll('button,input').forEach(control=>control.disabled=unavailable);}
function invalidateReview(){reviewEpoch++;reviewRequest=null;clearTimeout(timer);}
function retireSession(){retired=true;approvalPassword.value='';decisionControls(true);approval.hidden=true;document.querySelectorAll('#unlock button,#unlock input,#lock').forEach(control=>control.disabled=true);feedback.textContent='Browser session retired. Reopen this request from a fresh launch to continue.';showStatus('Request status unavailable for this browser session.');}
beginApproval.onclick=()=>{approval.hidden=false;approvalPassword.focus();};
document.getElementById('cancel-approval').onclick=()=>{approvalPassword.value='';approval.hidden=true;showFeedback('Authentication form cancelled.');beginApproval.focus();review(true);};
async function decide(path,password){approvalPassword.value='';deciding=true;invalidateReview();decisionControls(true);showFeedback('Submitting decision.');try{const body=JSON.stringify(path==='/approve'?{request_id:requestId,password}:{request_id:requestId});password='';const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body});showFeedback(response.ok?'Decision submitted. See the current request status below.':'Decision rejected. Check the request status below.');}catch{password='';showFeedback('Decision response unavailable. Request status below is authoritative; do not resubmit.');}finally{approval.hidden=true;deciding=false;await review(true);refresh.focus();}}
approval.onsubmit=e=>{e.preventDefault();decide('/approve',approvalPassword.value);};document.getElementById('deny').onclick=()=>decide('/deny','');
function showStatus(text){const status=document.getElementById('review-status');if(status.textContent!==text)status.textContent=text;}
function renderDetails(value){const details=document.getElementById('details');for(const [name,text] of [['Request ID',value.id],['Requester',value.requester],['Operation',value.operation],['Effect',value.effect],['Target',value.target],['Permitted arguments',value.arguments],['Credentials and use types',value.credentials.map(c=>c.label+' ('+c.use_type+')').join(' · ')],['Executable digest',value.executable_digest],['Policy digest',value.policy_digest],['Arguments digest',value.arguments_digest],['Expires at',new Date(value.expires_at_unix_seconds*1000).toISOString()],['One-time meaning',value.one_time]]){const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=name;if(Array.isArray(text)){const values=document.createElement('ol');values.id='arguments';for(const [index,value] of text.entries()){const item=document.createElement('li');item.setAttribute('aria-label','Argument '+(index+1));item.textContent=value;values.append(item);}dd.append(values);}else{dd.textContent=text;}details.append(dt,dd);}detailsReady=true;}
async function review(force=false){if(force)invalidateReview();if(reviewRequest)return;const request={epoch:reviewEpoch};reviewRequest=request;clearTimeout(timer);let delay=0;const current=()=>reviewRequest===request&&request.epoch===reviewEpoch;try{const r=await fetch('/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify({request_id:requestId})});if(!current())return;if([400,401,403,404].includes(r.status)){retireSession();return;}if(!r.ok)throw Error();const value=await r.json();if(!current()||retired)return;if(!detailsReady)renderDetails(value);const state=value.status.status;decisions.hidden=false;decisionControls(deciding||state!=='pending');if(state!=='pending'){approvalPassword.value='';approval.hidden=true;}showStatus('Request status: '+state+(state==='completed'?'; exit code: '+value.status.exit_code:state==='failed'?'; reason: '+value.status.reason:state==='approved'?'; approved once; execution has not started':state==='denied'?'; no operation will run':''));retryDelay=1000;if(['pending','approved','running'].includes(state))delay=1000;}catch{if(current()&&!retired){showStatus('Request status unavailable; retrying');delay=retryDelay;retryDelay=Math.min(retryDelay*2,8000);}}finally{if(current()){reviewRequest=null;if(delay&&!retired)timer=setTimeout(review,delay);}}}
if(requestId){document.getElementById('review').hidden=false;refresh.onclick=()=>review();await review();}
})();</script></html>"#.into());
        }
        if request.method != "POST" || request.header("origin") != Some(self.origin.as_str()) {
            return Response::denied();
        }
        if request.path == "/launch" {
            if request.header("content-type") != Some("text/plain") {
                return Response::denied();
            }
            if self
                .launch
                .as_ref()
                .is_some_and(|launch| request.body.as_slice() == launch.expose().as_bytes())
            {
                self.launch = None;
            } else {
                let Some(launch) = self.broker.take(&request.body) else {
                    return Response::denied();
                };
                if !matches!(
                    app.direct_status(app.human_owner(), &launch.request_id),
                    Ok(DirectStatus::Pending)
                ) {
                    return Response::denied();
                }
            }
            let Ok(decision_generation) = app.decision_generation() else {
                return Response::denied();
            };
            let existing_session = self.browser_session_index(&request);
            if let Some(index) = existing_session
                && self.sessions[index].decision_generation == decision_generation
            {
                return Response::text(self.sessions[index].csrf.expose());
            }
            if existing_session.is_none() && self.sessions.len() >= MAX_BROWSER_SESSIONS {
                return Response::denied();
            }
            let (Ok(cookie), Ok(csrf)) = (random(), random()) else {
                return Response::denied();
            };
            let header = format!(
                "vw_session={}; Secure; HttpOnly; SameSite=Strict; Path=/",
                cookie.expose()
            );
            let proof = csrf.expose().to_owned();
            let session = BrowserSession {
                cookie,
                csrf,
                decision_generation,
            };
            if let Some(index) = existing_session {
                // A recognized browser rotates its proof without consuming another slot.
                self.sessions[index] = session;
            } else {
                self.sessions.push(session);
            }
            return Response {
                status: 200,
                body: proof,
                cookie: Some(header),
                html: false,
            };
        }
        if !self.authenticated(&request)
            || request.header("x-csrf-token")
                != self.browser_session(&request).map(|s| s.csrf.expose())
            || request.header("content-type") != Some("application/json")
        {
            return Response::denied();
        }
        if request.path == "/review" {
            let Ok(input) = serde_json::from_slice::<ReviewInput>(&request.body) else {
                return Response::denied();
            };
            return match app
                .review_direct(app.human_owner(), &input.request_id)
                .ok()
                .and_then(|review| serde_json::to_string(&review).ok())
            {
                Some(body) => Response::text(&body),
                None => Response::denied(),
            };
        }
        if request.path == "/deny" {
            if !self.decision_authorized(&request, app) {
                return Response::denied();
            }
            let Ok(input) = serde_json::from_slice::<ReviewInput>(&request.body) else {
                return Response::denied();
            };
            return match app.deny_direct(app.human_owner(), &input.request_id) {
                Ok(DirectStatus::Denied) => {
                    Response::text("Request denied. No operation will run.")
                }
                _ => Response::denied(),
            };
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
        self.browser_session(request).is_some()
    }
    fn browser_session(&self, request: &Request) -> Option<&BrowserSession> {
        self.browser_session_index(request)
            .map(|index| &self.sessions[index])
    }
    fn browser_session_index(&self, request: &Request) -> Option<usize> {
        let cookies = request.header("cookie")?;
        let mut found = None;
        for pair in cookies.split(';') {
            let (name, value) = pair.trim().split_once('=')?;
            if name == "vw_session" {
                if found.is_some() {
                    return None;
                }
                found = Some(value);
            }
        }
        self.sessions
            .iter()
            .position(|session| found == Some(session.cookie.expose()))
    }
}

fn require_private_directory(
    is_directory: bool,
    uid: u32,
    mode: u32,
    provider_uid: u32,
) -> Result<(), SessionError> {
    if !is_directory || uid != provider_uid || mode & 0o777 != 0o700 {
        return Err(SessionError::BackendUnavailable);
    }
    Ok(())
}

/// Reserve the next cleanup interval once due; idle polling must not reschedule it.
fn prune_due(now: std::time::Instant, next: &mut std::time::Instant) -> bool {
    if now >= *next {
        *next = now + Duration::from_secs(1);
        true
    } else {
        false
    }
}

enum AcceptedConnection {
    Loopback(TcpStream),
    NonLoopback,
    Idle,
}

/// Reject nonlocal peers before TLS or parsing; only an empty backlog retries.
fn accepted_connection(
    result: std::io::Result<(TcpStream, SocketAddr)>,
) -> Result<AcceptedConnection, SessionError> {
    match result {
        Ok((stream, peer)) if peer.ip().is_loopback() => Ok(AcceptedConnection::Loopback(stream)),
        Ok(_) => Ok(AcceptedConnection::NonLoopback),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
            Ok(AcceptedConnection::Idle)
        }
        Err(_) => Err(SessionError::BackendUnavailable),
    }
}

// Both PEM files are provisioned by the human outside agent-writable storage.
fn identity_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SessionError> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_error| SessionError::BackendUnavailable)?;
    let meta = file
        .metadata()
        .map_err(|_error| SessionError::BackendUnavailable)?;
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
        .map_err(|_error| SessionError::BackendUnavailable)?;
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
        .map_err(|_error| SessionError::BackendUnavailable)?;
    let key =
        PrivateKeyDer::from_pem_slice(&key).map_err(|_error| SessionError::BackendUnavailable)?;
    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .map_err(|_error| SessionError::BackendUnavailable)?;
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
        std::str::from_utf8(&bytes[..header_end]).map_err(|_error| SessionError::InvalidRequest)?;
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
        .map_err(|_error| SessionError::InvalidRequest)?;
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
            .map_err(|_error| SessionError::InvalidRequest)?;
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
            "HTTP/1.1 {} Response\r\nContent-Type: {}; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'\r\nConnection: close\r\n{}\r\n{}",
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
    #[test]
    fn accepted_connections_require_loopback_peers_before_handoff() {
        // Supply the address reported by accept independently of the listener's
        // bind address so a missing peer check cannot hide behind loopback bind.
        for address in ["127.0.0.1:1234", "127.1.2.3:1234", "[::1]:1234"] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let _client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (server, _) = listener.accept().unwrap();
            assert!(matches!(
                accepted_connection(Ok((server, address.parse().unwrap()))),
                Ok(AcceptedConnection::Loopback(_))
            ));
        }
        for address in [
            "192.0.2.1:1234",
            "0.0.0.0:1234",
            "[2001:db8::1]:1234",
            "[::]:1234",
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let (server, _) = listener.accept().unwrap();
            assert!(matches!(
                accepted_connection(Ok((server, address.parse().unwrap()))),
                Ok(AcceptedConnection::NonLoopback)
            ));
            // Rejection also closes the transport without reading client input.
            assert_eq!(client.read(&mut [0u8; 1]).unwrap(), 0);
        }
    }

    #[test]
    fn accept_retries_only_would_block_and_preserves_fatal_errors() {
        assert!(matches!(
            accepted_connection(Err(std::io::ErrorKind::WouldBlock.into())),
            Ok(AcceptedConnection::Idle)
        ));
        for kind in [
            std::io::ErrorKind::PermissionDenied,
            std::io::ErrorKind::InvalidInput,
            std::io::ErrorKind::ConnectionAborted,
            std::io::ErrorKind::Interrupted,
            std::io::ErrorKind::Other,
        ] {
            assert!(matches!(
                accepted_connection(Err(kind.into())),
                Err(SessionError::BackendUnavailable)
            ));
        }
    }

    #[test]
    fn launch_directory_requires_type_owner_and_mode_independently() {
        assert_eq!(require_private_directory(true, 1000, 0o40700, 1000), Ok(()));
        assert_eq!(
            require_private_directory(false, 1000, 0o700, 1000),
            Err(SessionError::BackendUnavailable)
        );
        assert_eq!(
            require_private_directory(true, 1001, 0o700, 1000),
            Err(SessionError::BackendUnavailable)
        );
        for mode in [0o600, 0o500, 0o750, 0o701, 0o777] {
            assert_eq!(
                require_private_directory(true, 1000, mode, 1000),
                Err(SessionError::BackendUnavailable)
            );
        }
    }

    #[test]
    fn cleanup_schedule_is_due_initially_then_at_exact_one_second_intervals() {
        let start = std::time::Instant::now();
        let mut next = start;
        assert!(prune_due(start, &mut next));
        assert_eq!(next, start + Duration::from_secs(1));
        assert!(!prune_due(start, &mut next));
        assert!(!prune_due(start + Duration::from_millis(999), &mut next));
        assert_eq!(next, start + Duration::from_secs(1));
        assert!(prune_due(start + Duration::from_secs(1), &mut next));
        assert_eq!(next, start + Duration::from_secs(2));
        assert!(prune_due(start + Duration::from_secs(10), &mut next));
        assert_eq!(next, start + Duration::from_secs(11));
    }

    #[test]
    fn server_removes_expired_launch_without_browser_traffic_before_shutdown() {
        use crate::access::direct_request_tests;
        let fixture = direct_request_tests::fixture();
        let root = fixture.dir.path().join("provider");
        let (cert, key) = identity(&root);
        let mut ui = LoopbackUi::bind(&root.join("launch.html"), &cert, &key).unwrap();
        Arc::get_mut(&mut ui.broker).unwrap().desktop = Box::new(FakeDesktop {
            fail: false,
            observed: Arc::new(Mutex::new(Vec::new())),
        });
        let receipt = fixture
            .app
            .submit_direct(
                fixture.app.human_owner(),
                direct_request_tests::input(),
                ui.request_launcher().as_ref(),
            )
            .unwrap();
        let artifact = root.join(format!("review-{}.html", receipt.id));
        assert!(artifact.exists());
        fixture.monotonic.store(310, Ordering::SeqCst);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let app = fixture.app.clone();
        let worker = std::thread::spawn(move || ui.serve(app, worker_stop));
        let deadline = std::time::Instant::now() + Duration::from_secs(4);
        while artifact.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        // Capture before shutdown: final cleanup must not mask missing pruning.
        let removed_before_shutdown = !artifact.exists();
        stop.store(true, Ordering::Release);
        let served = worker.join().unwrap();
        assert!(removed_before_shutdown);
        assert_eq!(served, Ok(()));
        assert_eq!(
            fixture
                .app
                .direct_status(fixture.app.human_owner(), &receipt.id),
            Ok(DirectStatus::Expired)
        );
    }

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
        if let Some(session) = ui.sessions.last() {
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
    struct FakeDesktop {
        fail: bool,
        observed: Arc<Mutex<Vec<PathBuf>>>,
    }
    impl super::super::desktop_launch::DesktopOpener for FakeDesktop {
        fn open(&self, artifact: &Path) -> Result<(), DirectRequestError> {
            self.observed.lock().unwrap().push(artifact.to_owned());
            if self.fail {
                Err(DirectRequestError::ReviewUnavailable)
            } else {
                Ok(())
            }
        }
    }
    fn broker_fixture(
        fail: bool,
    ) -> (
        tempfile::TempDir,
        RequestLaunchBroker,
        Arc<Mutex<Vec<PathBuf>>>,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let observed = Arc::new(Mutex::new(Vec::new()));
        let broker = RequestLaunchBroker {
            origin: "https://127.0.0.1:12345".into(),
            directory: dir.path().to_owned(),
            pending: Mutex::new(Vec::new()),
            desktop: Box::new(FakeDesktop {
                fail,
                observed: observed.clone(),
            }),
        };
        (dir, broker, observed)
    }
    #[test]
    fn request_handoff_is_private_one_use_and_launcher_gets_only_artifact() {
        let (_dir, broker, observed) = broker_fixture(false);
        let id = URL_SAFE_NO_PAD.encode([7; 32]);
        broker.launch(&id).unwrap();
        let paths = observed.lock().unwrap();
        assert_eq!(paths.len(), 1);
        let path = &paths[0];
        assert_eq!(
            path.file_name().unwrap(),
            format!("review-{id}.html").as_str()
        );
        assert_eq!(std::fs::metadata(path).unwrap().mode() & 0o777, 0o600);
        let capability = broker.pending.lock().unwrap()[0]
            .capability
            .expose()
            .to_owned();
        assert_eq!(URL_SAFE_NO_PAD.decode(&capability).unwrap().len(), 32);
        let html = std::fs::read_to_string(path).unwrap();
        assert!(html.contains(&format!("/#{}:{}", capability, id)));
        assert!(!path.to_string_lossy().contains(&capability));
        assert_eq!(
            broker.launch(&id),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert_eq!(std::fs::read_to_string(path).unwrap(), html);
        let taken = broker.take(capability.as_bytes()).unwrap();
        assert!(broker.take(capability.as_bytes()).is_none());
        drop(taken);
        assert!(!path.exists());
    }
    #[test]
    fn failed_launch_and_invalid_ids_leave_no_reusable_capability_or_artifact() {
        let (dir, broker, observed) = broker_fixture(true);
        assert_eq!(
            broker.launch("../client-path"),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert!(observed.lock().unwrap().is_empty());
        assert_eq!(
            broker.launch(&URL_SAFE_NO_PAD.encode([8; 32])),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert_eq!(observed.lock().unwrap().len(), 1);
        assert!(broker.pending.lock().unwrap().is_empty());
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }
    #[test]
    fn request_capabilities_are_bounded_and_never_replace_older_ones() {
        let (_dir, broker, observed) = broker_fixture(false);
        for byte in 0..64 {
            broker.launch(&URL_SAFE_NO_PAD.encode([byte; 32])).unwrap();
        }
        assert_eq!(
            broker.launch(&URL_SAFE_NO_PAD.encode([64; 32])),
            Err(DirectRequestError::ReviewUnavailable)
        );
        assert_eq!(observed.lock().unwrap().len(), 64);
        let capability = broker.pending.lock().unwrap()[0]
            .capability
            .expose()
            .to_owned();
        assert!(broker.take(capability.as_bytes()).is_some());
        broker.launch(&URL_SAFE_NO_PAD.encode([64; 32])).unwrap();
    }
    #[test]
    fn browser_sessions_survive_new_launches_and_proofs_cannot_cross_sessions() {
        let (_dir, mut ui, app, _) = fixture();
        launch(&mut ui, &app);
        let original = request(&ui, "/lock", "{}");
        let original_cookie = original.header("cookie").unwrap().to_owned();
        let original_proof = original.header("x-csrf-token").unwrap().to_owned();
        ui.launch = Some(random().unwrap());
        let mut new_launch = request(&ui, "/launch", ui.launch.as_ref().unwrap().expose());
        new_launch.headers.retain(|(key, _)| key != "cookie");
        new_launch
            .headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(new_launch, &app).status, 200);
        assert_eq!(ui.sessions.len(), 2);
        assert_eq!(ui.handle(original, &app).status, 200);
        let mut crossed = request(&ui, "/lock", "{}");
        crossed
            .headers
            .iter_mut()
            .find(|(key, _)| key == "x-csrf-token")
            .unwrap()
            .1 = original_proof;
        assert_eq!(ui.handle(crossed, &app).status, 403);
        let mut crossed = request(&ui, "/lock", "{}");
        crossed
            .headers
            .iter_mut()
            .find(|(key, _)| key == "cookie")
            .unwrap()
            .1 = original_cookie;
        assert_eq!(ui.handle(crossed, &app).status, 403);
    }
    #[test]
    fn sixty_four_browser_sessions_allow_existing_review_but_reject_new_sessions() {
        use crate::access::direct_request_tests;
        let fixture = direct_request_tests::fixture();
        let root = fixture.dir.path().join("provider");
        let (cert, key) = identity(&root);
        let mut ui = LoopbackUi::bind(&root.join("launch.html"), &cert, &key).unwrap();
        Arc::get_mut(&mut ui.broker).unwrap().desktop = Box::new(FakeDesktop {
            fail: false,
            observed: Arc::new(Mutex::new(Vec::new())),
        });
        let receipt = fixture
            .app
            .submit_direct(
                fixture.app.human_owner(),
                direct_request_tests::input(),
                ui.request_launcher().as_ref(),
            )
            .unwrap();
        let mut first_review = None;
        for index in 0..65 {
            if index != 0 {
                ui.broker.launch(&receipt.id).unwrap();
            }
            let capability = ui.broker.pending.lock().unwrap()[0]
                .capability
                .expose()
                .to_owned();
            let make_exchange = |ui: &LoopbackUi| {
                let mut exchange = request(ui, "/launch", &capability);
                exchange
                    .headers
                    .retain(|(name, _)| name != "cookie" && name != "x-csrf-token");
                exchange
                    .headers
                    .iter_mut()
                    .find(|(name, _)| name == "content-type")
                    .unwrap()
                    .1 = "text/plain".into();
                exchange
            };
            let response = ui.handle(make_exchange(&ui), &fixture.app);
            if index < 64 {
                assert_eq!(response.status, 200);
                assert!(response.cookie.is_some());
                if index == 0 {
                    first_review = Some(request(
                        &ui,
                        "/review",
                        &serde_json::json!({"request_id": receipt.id}).to_string(),
                    ));
                }
            } else {
                assert_eq!(response.status, 403);
                assert!(response.cookie.is_none());
                assert_eq!(
                    fixture
                        .app
                        .direct_status(fixture.app.human_owner(), &receipt.id)
                        .unwrap(),
                    DirectStatus::Pending
                );
            }
            assert!(ui.broker.pending.lock().unwrap().is_empty());
            assert_eq!(ui.handle(make_exchange(&ui), &fixture.app).status, 403);
        }
        assert_eq!(ui.sessions.len(), 64);
        let review = ui.handle(first_review.unwrap(), &fixture.app);
        assert_eq!(review.status, 200);
        let review: crate::access::direct_request::DirectReview =
            serde_json::from_str(&review.body).unwrap();
        assert_eq!(review.status, DirectStatus::Pending);
    }

    #[test]
    fn stale_request_launch_is_consumed_without_granting_a_browser_session() {
        let (_dir, mut ui, app, _) = fixture();
        let (_artifacts, broker, _) = broker_fixture(false);
        let id = URL_SAFE_NO_PAD.encode([9; 32]);
        broker.launch(&id).unwrap();
        let capability = broker.pending.lock().unwrap()[0]
            .capability
            .expose()
            .to_owned();
        ui.broker = Arc::new(broker);
        let mut attempt = request(&ui, "/launch", &capability);
        attempt
            .headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(attempt, &app).status, 403);
        assert!(ui.sessions.is_empty());
        assert!(ui.broker.pending.lock().unwrap().is_empty());
    }
    #[test]
    fn public_shell_is_accessible_and_decision_controls_never_inject_html() {
        let (_dir, mut ui, app, _) = fixture();
        let mut get = request(&ui, "/", "");
        get.method = "GET".into();
        let page = ui.handle(get, &app);
        for required in [
            "lang=en",
            "aria-atomic=true",
            "role=status",
            ":focus-visible",
            "Refresh request status",
            "dd.textContent=text",
            "Authenticate and approve once",
            "Cancel authentication",
            "Master password for this approval",
        ] {
            assert!(page.body.contains(required), "missing {required}");
        }
        for forbidden in ["innerHTML", "fetch('/approve'", "fetch('/deny'"] {
            assert!(!page.body.contains(forbidden));
        }
        launch(&mut ui, &app);
        for path in ["/approve", "/deny", "/review?id=sentinel"] {
            assert_eq!(ui.handle(request(&ui, path, "{}"), &app).status, 403);
        }
        for body in ["{}", r#"{"request_id":"sentinel","extra":true}"#] {
            let response = ui.handle(request(&ui, "/review", body), &app);
            assert_eq!(response.status, 403);
            assert!(!response.body.contains("sentinel"));
        }
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
        for path in [
            "/unlock?password=password-sentinel", // secrets-ignore: synthetic rejection-test sentinel
            "/status",
            "/resolve",
        ] {
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
            "POST /unlock HTTP/1.1\r\nContent-Length: 24705\r\n\r\n",
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
            "POST / HTTP/1.1\r\nContent-Length: 24704\r\n\r\n{}",
            "x".repeat(24704)
        );
        assert_eq!(parse(&largest).unwrap().body.len(), 24704);
        let complete_oversized = format!(
            "POST / HTTP/1.1\r\nContent-Length: 24705\r\n\r\n{}",
            "x".repeat(24705)
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

    #[test]
    fn pending_request_exchange_review_expiry_and_prune_are_authenticated() {
        use crate::access::{direct_request::DirectReview, direct_request_tests};
        let fixture = direct_request_tests::fixture();
        let root = fixture.dir.path().join("provider");
        let (cert, key) = identity(&root);
        let mut ui = LoopbackUi::bind(&root.join("launch.html"), &cert, &key).unwrap();
        Arc::get_mut(&mut ui.broker).unwrap().desktop = Box::new(FakeDesktop {
            fail: false,
            observed: Arc::new(Mutex::new(Vec::new())),
        });
        let owner = fixture.app.human_owner();
        let receipt = fixture
            .app
            .submit_direct(
                owner,
                direct_request_tests::input(),
                ui.request_launcher().as_ref(),
            )
            .unwrap();
        let (capability, artifact) = {
            let pending = ui.broker.pending.lock().unwrap();
            (
                pending[0].capability.expose().to_owned(),
                pending[0].artifact.clone(),
            )
        };
        ui.broker.prune(&fixture.app);
        assert!(artifact.exists());
        let mut exchange = request(&ui, "/launch", &capability);
        exchange
            .headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(exchange, &fixture.app).status, 200);
        assert!(!artifact.exists());
        let body = serde_json::json!({"request_id": receipt.id}).to_string();
        let review = ui.handle(request(&ui, "/review", &body), &fixture.app);
        assert_eq!(review.status, 200);
        assert_eq!(
            serde_json::from_str::<DirectReview>(&review.body)
                .unwrap()
                .status,
            DirectStatus::Pending
        );
        let mut cookie_only = request(&ui, "/review", &body);
        cookie_only.headers.retain(|(key, _)| key != "x-csrf-token");
        assert_eq!(ui.handle(cookie_only, &fixture.app).status, 403);
        let mut replay = request(&ui, "/launch", &capability);
        replay
            .headers
            .iter_mut()
            .find(|(key, _)| key == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(replay, &fixture.app).status, 403);
        let second = fixture
            .app
            .submit_direct(
                owner,
                direct_request_tests::input(),
                ui.request_launcher().as_ref(),
            )
            .unwrap();
        let second_artifact = root.join(format!("review-{}.html", second.id));
        fixture.monotonic.store(310, Ordering::SeqCst);
        ui.broker.prune(&fixture.app);
        assert!(!second_artifact.exists());
        assert!(ui.broker.pending.lock().unwrap().is_empty());
        fixture.app.lock().unwrap();
        let review = ui.handle(request(&ui, "/review", &body), &fixture.app);
        assert_eq!(review.status, 200);
        assert_eq!(
            serde_json::from_str::<DirectReview>(&review.body)
                .unwrap()
                .status,
            DirectStatus::Expired
        );
    }

    fn decision_fixture(
        authenticator: Arc<dyn ApprovalAuthenticator + Send + Sync>,
    ) -> (
        crate::access::direct_request_tests::Fixture,
        Arc<Mutex<LoopbackUi>>,
        String,
    ) {
        let f = crate::access::direct_request_tests::fixture();
        let root = f.dir.path().join("provider");
        let (cert, key) = identity(&root);
        let mut ui = LoopbackUi::bind(&root.join("launch.html"), &cert, &key)
            .unwrap()
            .with_approval_authenticator(authenticator);
        let id = f
            .app
            .submit_direct(
                f.app.human_owner(),
                crate::access::direct_request_tests::input(),
                &crate::access::direct_request_tests::Launcher::default(),
            )
            .unwrap()
            .id;
        let mut exchange = request(&ui, "/launch", ui.launch.as_ref().unwrap().expose());
        exchange
            .headers
            .iter_mut()
            .find(|(k, _)| k == "content-type")
            .unwrap()
            .1 = "text/plain".into();
        assert_eq!(ui.handle(exchange, &f.app).status, 200);
        (f, Arc::new(Mutex::new(ui)), id)
    }
    struct ApprovalCheck(AtomicUsize);
    impl ApprovalAuthenticator for ApprovalCheck {
        fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
            self.0.fetch_add(1, Ordering::SeqCst);
            if password.expose() == "approval-sentinel" {
                Ok(())
            } else {
                Err(SessionError::AuthenticationFailed)
            }
        }
    }
    #[test]
    fn decision_browser_guards_are_isolated_against_eligible_requests() {
        for endpoint in ["/approve", "/deny"] {
            for case in [
                "cookie_missing",
                "cookie_wrong",
                "csrf_missing",
                "csrf_wrong",
                "host",
                "origin",
                "content_type",
                "method",
                "cross_session",
                "cookie_stale",
                "csrf_stale",
                "pair_stale",
            ] {
                let check = Arc::new(ApprovalCheck(AtomicUsize::new(0)));
                let (f, ui, mut id) = decision_fixture(check.clone());
                let mut locked = ui.lock().unwrap();
                let old_cookie = locked.sessions[0].cookie.expose().to_owned();
                let old_csrf = locked.sessions[0].csrf.expose().to_owned();
                if case.ends_with("stale") {
                    f.app.lock().unwrap();
                    f.app
                        .authenticate(SensitiveString::new("synthetic".into()))
                        .unwrap();
                    id = f
                        .app
                        .submit_direct(
                            f.app.human_owner(),
                            crate::access::direct_request_tests::input(),
                            &crate::access::direct_request_tests::Launcher::default(),
                        )
                        .unwrap()
                        .id;
                    locked.sessions.push(BrowserSession {
                        cookie: random().unwrap(),
                        csrf: random().unwrap(),
                        decision_generation: f.app.decision_generation().unwrap(),
                    });
                }
                if case == "cross_session" {
                    locked.sessions.push(BrowserSession {
                        cookie: random().unwrap(),
                        csrf: random().unwrap(),
                        decision_generation: f.app.decision_generation().unwrap(),
                    });
                }
                let body = if endpoint == "/approve" {
                    serde_json::json!({"request_id":id,"password":"approval-sentinel"})
                } else {
                    serde_json::json!({"request_id":id})
                }
                .to_string();
                let mut req = request(&locked, endpoint, &body);
                match case {
                    "cookie_missing" => req.headers.retain(|(k, _)| k != "cookie"),
                    "csrf_missing" => req.headers.retain(|(k, _)| k != "x-csrf-token"),
                    "method" => req.method = "GET".into(),
                    "pair_stale" => {
                        req.headers
                            .iter_mut()
                            .find(|(k, _)| k == "cookie")
                            .unwrap()
                            .1 = format!("vw_session={old_cookie}");
                        req.headers
                            .iter_mut()
                            .find(|(k, _)| k == "x-csrf-token")
                            .unwrap()
                            .1 = old_csrf.clone();
                    }
                    _ => {
                        let (key, value) = match case {
                            "cookie_wrong" => ("cookie", "vw_session=wrong".into()),
                            "csrf_wrong" => ("x-csrf-token", "wrong".into()),
                            "host" => ("host", "attacker.invalid".into()),
                            "origin" => ("origin", "https://attacker.invalid".into()),
                            "content_type" => ("content-type", "text/plain".into()),
                            "cookie_stale" => ("cookie", format!("vw_session={old_cookie}")),
                            "csrf_stale" | "cross_session" => ("x-csrf-token", old_csrf.clone()),
                            _ => panic!("unknown test case"),
                        };
                        req.headers.iter_mut().find(|(k, _)| k == key).unwrap().1 = value;
                    }
                }
                drop(locked);
                assert_eq!(
                    LoopbackUi::dispatch(&ui, req, &f.app).status,
                    403,
                    "{endpoint} {case}"
                );
                assert_eq!(check.0.load(Ordering::SeqCst), 0);
                assert_eq!(
                    f.app.direct_status(f.app.human_owner(), &id),
                    Ok(DirectStatus::Pending)
                );
                let req = request(&ui.lock().unwrap(), endpoint, &body);
                assert_eq!(
                    LoopbackUi::dispatch(&ui, req, &f.app).status,
                    200,
                    "positive control {endpoint} {case}"
                );
                assert_eq!(
                    f.app.direct_status(f.app.human_owner(), &id),
                    Ok(if endpoint == "/approve" {
                        DirectStatus::Approved
                    } else {
                        DirectStatus::Denied
                    })
                );
            }
        }
    }
    #[test]
    fn decision_browser_authentication_input_is_closed_and_replay_does_not_authenticate() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"password":""}),
            serde_json::json!({"password":"wrong"}),
            serde_json::json!({"password":"x".repeat(4097)}),
            serde_json::json!({"password":"approval-sentinel","extra":"secret"}),
        ] {
            let check = Arc::new(ApprovalCheck(AtomicUsize::new(0)));
            let (f, ui, id) = decision_fixture(check.clone());
            let mut body = value;
            body["request_id"] = id.clone().into();
            let req = request(&ui.lock().unwrap(), "/approve", &body.to_string());
            assert_eq!(LoopbackUi::dispatch(&ui, req, &f.app).status, 403);
            assert_eq!(
                f.app.direct_status(f.app.human_owner(), &id),
                Ok(DirectStatus::Pending)
            );
            let good =
                serde_json::json!({"request_id":id,"password":"approval-sentinel"}).to_string();
            let req = request(&ui.lock().unwrap(), "/approve", &good);
            assert_eq!(LoopbackUi::dispatch(&ui, req, &f.app).status, 200);
            let before = check.0.load(Ordering::SeqCst);
            let req = request(&ui.lock().unwrap(), "/approve", &good);
            assert_eq!(LoopbackUi::dispatch(&ui, req, &f.app).status, 403);
            assert_eq!(check.0.load(Ordering::SeqCst), before);
        }
    }
    #[test]
    fn decision_browser_authentication_allows_lock_and_denial_to_finish() {
        use std::sync::mpsc;
        struct Blocked {
            entered: mpsc::Sender<()>,
            resume: Mutex<mpsc::Receiver<()>>,
        }
        impl ApprovalAuthenticator for Blocked {
            fn authenticate(&self, _: SensitiveString) -> Result<(), SessionError> {
                self.entered.send(()).unwrap();
                self.resume.lock().unwrap().recv().unwrap();
                Ok(())
            }
        }
        for action in [
            "/lock",
            "/deny",
            "rotate_cookie",
            "rotate_csrf",
            "generation",
        ] {
            let (entered_tx, entered_rx) = mpsc::channel();
            let (resume_tx, resume_rx) = mpsc::channel();
            let (f, ui, id) = decision_fixture(Arc::new(Blocked {
                entered: entered_tx,
                resume: Mutex::new(resume_rx),
            }));
            let approve = request(
                &ui.lock().unwrap(),
                "/approve",
                &serde_json::json!({"request_id":id,"password":"approval-sentinel"}).to_string(),
            );
            let worker = {
                let ui = ui.clone();
                let app = f.app.clone();
                std::thread::spawn(move || LoopbackUi::dispatch(&ui, approve, &app))
            };
            entered_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            if action.starts_with('/') {
                let req = request(
                    &ui.lock().unwrap(),
                    action,
                    &serde_json::json!({"request_id":id}).to_string(),
                );
                assert_eq!(LoopbackUi::dispatch(&ui, req, &f.app).status, 200);
            } else {
                let mut locked = ui.lock().unwrap();
                let session = locked.sessions.last_mut().unwrap();
                match action {
                    "rotate_cookie" => session.cookie = random().unwrap(),
                    "rotate_csrf" => session.csrf = random().unwrap(),
                    "generation" => session.decision_generation += 1,
                    _ => panic!("unknown test case"),
                }
                assert_eq!(
                    f.app.direct_status(f.app.human_owner(), &id),
                    Ok(DirectStatus::Pending)
                );
            }
            resume_tx.send(()).unwrap();
            assert_eq!(worker.join().unwrap().status, 403);
            assert_eq!(
                f.app.direct_status(f.app.human_owner(), &id),
                Ok(match action {
                    "/lock" => DirectStatus::Expired,
                    "/deny" => DirectStatus::Denied,
                    _ => DirectStatus::Pending,
                })
            );
        }
    }

    #[test]
    fn decision_browser_rotation_reuses_a_slot_and_preserves_terminal_review() {
        let (f, ui, old_id) = decision_fixture(Arc::new(ApprovalCheck(AtomicUsize::new(0))));
        let mut ui = ui.lock().unwrap();
        Arc::get_mut(&mut ui.broker).unwrap().desktop = Box::new(FakeDesktop {
            fail: false,
            observed: Arc::new(Mutex::new(Vec::new())),
        });
        let mut last_id = String::new();
        for _ in 0..65 {
            f.app.lock().unwrap();
            f.app
                .authenticate(SensitiveString::new("synthetic".into()))
                .unwrap();
            let receipt = f
                .app
                .submit_direct(
                    f.app.human_owner(),
                    crate::access::direct_request_tests::input(),
                    ui.request_launcher().as_ref(),
                )
                .unwrap();
            let capability = ui
                .broker
                .pending
                .lock()
                .unwrap()
                .last()
                .unwrap()
                .capability
                .expose()
                .to_owned();
            let mut exchange = request(&ui, "/launch", &capability);
            exchange
                .headers
                .iter_mut()
                .find(|(key, _)| key == "content-type")
                .unwrap()
                .1 = "text/plain".into();
            let response = ui.handle(exchange, &f.app);
            assert_eq!(response.status, 200);
            assert!(response.cookie.is_some());
            assert_eq!(ui.sessions.len(), 1);
            last_id = receipt.id;
        }
        let review_request = request(
            &ui,
            "/review",
            &serde_json::json!({"request_id":old_id}).to_string(),
        );
        let old_review = ui.handle(review_request, &f.app);
        assert_eq!(old_review.status, 200);
        assert_eq!(
            serde_json::from_str::<crate::access::direct_request::DirectReview>(&old_review.body)
                .unwrap()
                .status,
            DirectStatus::Expired
        );
        let deny_request = request(
            &ui,
            "/deny",
            &serde_json::json!({"request_id":last_id}).to_string(),
        );
        let denial = ui.handle(deny_request, &f.app);
        assert_eq!(denial.status, 200);
    }

    /// Test-only process fixture for the reproducible Firefox harness.
    #[test]
    #[ignore = "run with tests/ui/direct-request.mjs and a disposable trusted browser profile"]
    fn direct_request_browser_fixture() {
        use crate::{access::direct_request_tests, adapters::human_socket::HumanSocket};
        let control = std::path::PathBuf::from(
            std::env::var_os("VW_UI_TEST_CONTROL").expect("fixture control directory"),
        );
        let fixture = direct_request_tests::fixture();
        let root = fixture.dir.path().join("provider");
        let (cert, key) = identity(&root);
        let artifact = root.join("launch.html");
        struct Authenticator;
        impl ApprovalAuthenticator for Authenticator {
            fn authenticate(&self, password: SensitiveString) -> Result<(), SessionError> {
                if password.expose() == "synthetic-browser-password" {
                    Ok(())
                } else {
                    Err(SessionError::AuthenticationFailed)
                }
            }
        }
        let mut ui = LoopbackUi::bind(&artifact, &cert, &key)
            .unwrap()
            .with_approval_authenticator(Arc::new(Authenticator));
        struct Desktop;
        impl super::super::desktop_launch::DesktopOpener for Desktop {
            fn open(&self, _: &Path) -> Result<(), DirectRequestError> {
                Ok(())
            }
        }
        Arc::get_mut(&mut ui.broker).unwrap().desktop = Box::new(Desktop);
        let launcher = ui.request_launcher();
        let socket = HumanSocket::bind(&root).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let human = {
            let (app, stop) = (fixture.app.clone(), stop.clone());
            std::thread::spawn(move || socket.serve(app, launcher, stop))
        };
        let browser = {
            let (app, stop) = (fixture.app.clone(), stop.clone());
            std::thread::spawn(move || ui.serve(app, stop))
        };
        std::fs::write(
            control.join("ready.json"),
            serde_json::json!({"root":root,"artifact":artifact}).to_string(),
        )
        .unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(180);
        while !control.join("stop").exists() && std::time::Instant::now() < deadline {
            if let Ok(value) = std::fs::read_to_string(control.join("clock")) {
                fixture
                    .monotonic
                    .store(value.parse().unwrap(), Ordering::SeqCst);
            }
            fixture.app.status().unwrap();
            std::thread::sleep(Duration::from_millis(25));
        }
        stop.store(true, Ordering::Release);
        human.join().unwrap().unwrap();
        browser.join().unwrap().unwrap();
        assert!(control.join("stop").exists(), "browser fixture timed out");
    }
}
