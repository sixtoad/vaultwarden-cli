//! Versioned remote management. Every entry passes enrolled-certificate checks;
//! administrative commands additionally require an explicit owner-console grant.
use super::*;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::OpenOptionsExt;

const MAX_ACTIONS: usize = 128;
const MAX_PAGE: u32 = 64;
const JOURNAL: &str = "companion-management-actions.json";
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Kind {
    ApprovalClient,
    RequesterAgent,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Target {
    pub kind: Kind,
    pub id: String,
}
impl Target {
    fn valid(&self) -> bool {
        match self.kind {
            Kind::ApprovalClient => identity::valid_fingerprint(&self.id),
            Kind::RequesterAgent => valid_request_id(&self.id),
        }
    }
    fn key(&self) -> String {
        format!(
            "{}:{}",
            if self.kind == Kind::ApprovalClient {
                "approval_client"
            } else {
                "requester_agent"
            },
            self.id
        )
    }
}
#[derive(Clone, Serialize)]
struct Identity {
    kind: Kind,
    id: String,
    label: String,
    fingerprint: String,
    roles: Vec<&'static str>,
    trust: &'static str,
    this_client: bool,
}
impl Identity {
    fn target(&self) -> Target {
        Target {
            kind: self.kind.clone(),
            id: self.id.clone(),
        }
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Action {
    action_id: String,
    actor: String,
    target: Target,
    revocation: Revocation,
    cleanup: Cleanup,
    #[serde(default)]
    owner_reconciled: bool,
    #[serde(default)]
    reconciled_by_uid: Option<u32>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Revocation {
    NotRecorded,
    Pending,
    Recorded,
    Unknown,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Cleanup {
    Pending,
    Complete,
    Unknown,
    NotApplicable,
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u8,
    actions: Vec<Action>,
}
struct Ticket {
    token: String,
    action_id: String,
    actor: String,
    target: Target,
    generation: u64,
    epoch: u64,
    deadline: Duration,
}
#[derive(Default)]
pub(super) struct State {
    tickets: Vec<Ticket>,
    pub failed: bool,
    #[cfg(test)]
    pub(super) before_mutation: Option<Box<dyn FnOnce() + Send>>,
}
fn cursor_valid(value: &str) -> bool {
    value.split_once(':').is_some_and(|(kind, id)| match kind {
        "approval_client" => identity::valid_fingerprint(id),
        "requester_agent" => valid_request_id(id),
        _ => false,
    })
}
pub(super) fn valid(command: &Command) -> Option<bool> {
    Some(match command {
        Command::IdentityList {
            version,
            limit,
            after,
        } => {
            *version == 2
                && (1..=MAX_PAGE).contains(limit)
                && after.as_ref().is_none_or(|s| cursor_valid(s))
        }
        Command::IdentityDetail { version, target }
        | Command::IdentityPrepare { version, target } => *version == 2 && target.valid(),
        Command::IdentityRevoke {
            version,
            target,
            action_id,
            ticket,
            password,
        } => {
            *version == 2
                && target.valid()
                && valid_request_id(action_id)
                && identity::valid_fingerprint(ticket)
                && valid_password(password)
        }
        Command::IdentityStatus {
            version,
            target,
            action_id,
        } => *version == 2 && target.valid() && valid_request_id(action_id),
        Command::RequestOrigin {
            version,
            request_id,
        } => *version == 2 && valid_request_id(request_id),
        _ => return None,
    })
}
fn inventory(
    service: &Companion,
    actor: &str,
    app: &ProviderApplication,
) -> Result<Vec<Identity>, Error> {
    let mut rows = identity::management_records(&service.identity_store)
        .map_err(|_| Error::Unavailable)?
        .into_iter()
        .map(|(entry, revoked, admin)| Identity {
            kind: Kind::ApprovalClient,
            id: entry.fingerprint.clone(),
            label: entry.label,
            this_client: entry.fingerprint == actor,
            fingerprint: entry.fingerprint,
            roles: if revoked {
                vec![]
            } else if admin {
                vec!["approve", "admin"]
            } else {
                vec!["approve"]
            },
            trust: if revoked { "revoked" } else { "enabled" },
        })
        .collect::<Vec<_>>();
    for agent in app
        .list_agents(app.human_owner())
        .map_err(|_| Error::Unavailable)?
    {
        let revoked = agent.status == crate::access::agent_binding::AgentBindingStatus::Revoked;
        rows.push(Identity {
            kind: Kind::RequesterAgent,
            id: agent.id,
            label: agent.label,
            fingerprint: agent.fingerprint,
            roles: if revoked { vec![] } else { vec!["request"] },
            trust: if revoked { "revoked" } else { "enabled" },
            this_client: false,
        });
    }
    rows.sort_by_key(|row| row.target().key());
    Ok(rows)
}
fn read_journal(root: &Path) -> Result<Journal, Error> {
    identity::private_directory(root).map_err(|_| Error::Unavailable)?;
    let path = root.join(JOURNAL);
    match std::fs::symlink_metadata(&path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Journal {
            version: 2,
            actions: Vec::new(),
        }),
        _ => {
            let raw = identity::private_file(&path).map_err(|_| Error::Unavailable)?;
            let journal: Journal = serde_json::from_slice(&raw).map_err(|_| Error::Unavailable)?;
            let mut ids = std::collections::HashSet::new();
            if journal.version != 2
                || journal.actions.len() > MAX_ACTIONS
                || journal.actions.iter().any(|a| {
                    !valid_request_id(&a.action_id)
                        || !ids.insert(&a.action_id)
                        || !identity::valid_fingerprint(&a.actor)
                        || !a.target.valid()
                        || !matches!(
                            (&a.revocation, &a.cleanup),
                            (Revocation::NotRecorded, Cleanup::NotApplicable)
                                | (Revocation::Pending, Cleanup::Pending | Cleanup::Unknown)
                                | (Revocation::Recorded, Cleanup::Complete | Cleanup::Unknown)
                                | (Revocation::Unknown, Cleanup::Unknown)
                        )
                        || a.owner_reconciled != a.reconciled_by_uid.is_some()
                        || a.reconciled_by_uid
                            .is_some_and(|uid| uid != unsafe { libc::geteuid() })
                })
            {
                return Err(Error::Unavailable);
            }
            Ok(journal)
        }
    }
}
fn save_journal(root: &Path, journal: &Journal) -> Result<(), Error> {
    let bytes = serde_json::to_vec(journal).map_err(|_| Error::Unavailable)?;
    if bytes.len() > 65536 {
        return Err(Error::Unavailable);
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
    let path = root.join(format!(".management-{}.new", identity::fingerprint(&nonce)));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
            .map_err(|_| Error::Unavailable)?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|_| Error::Unavailable)?;
        std::fs::rename(&path, root.join(JOURNAL)).map_err(|_| Error::Unavailable)?;
        std::fs::File::open(root)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&path);
    }
    result
}
fn action_response(action: &Action) -> Response {
    Response::ok(
        serde_json::json!({"version":2,"target":action.target,"action_id":action.action_id,"revocation":action.revocation,"cleanup":action.cleanup,"owner_reconciled":action.owner_reconciled}),
    )
}
pub(super) fn dispatch(
    service: &Companion,
    actor: &str,
    command: Command,
    app: &ProviderApplication,
) -> Response {
    let result = (|| -> Result<Response, Error> {
        if let Command::RequestOrigin { request_id, .. } = command {
            let origin = app
                .companion_origin(&request_id)
                .map_err(|_| Error::Unavailable)?;
            return Ok(Response::ok(
                serde_json::json!({"version":2,"request_id":request_id,"origin":origin}),
            ));
        }
        let root = service.identity_store.parent().ok_or(Error::Unavailable)?;
        if matches!(&command, Command::IdentityStatus { .. })
            && !identity::administrator(&service.identity_store, actor)
            && !receipt_authorized(service, actor, &command)
        {
            return Err(Error::Unauthorized);
        }
        if let Command::IdentityStatus {
            target, action_id, ..
        } = command
        {
            let journal = read_journal(root)?;
            return match journal.actions.iter().find(|a| a.action_id == action_id) {
                Some(action) if action.actor == actor && action.target == target => {
                    Ok(action_response(action))
                }
                Some(_) => Err(Error::Unauthorized),
                None => Ok(action_response(&Action {
                    action_id,
                    actor: actor.into(),
                    target,
                    revocation: Revocation::Unknown,
                    cleanup: Cleanup::Unknown,
                    owner_reconciled: false,
                    reconciled_by_uid: None,
                })),
            };
        }
        if !identity::administrator(&service.identity_store, actor) {
            return Err(Error::Unauthorized);
        }
        let (generation, epoch) = app.management_authority().map_err(|_| Error::Unavailable)?;
        match command {
            Command::IdentityList { limit, after, .. } => {
                let mut rows = inventory(service, actor, app)?;
                rows.retain(|row| {
                    after
                        .as_ref()
                        .is_none_or(|cursor| row.target().key() > *cursor)
                });
                let more = rows.len() > limit as usize;
                rows.truncate(limit as usize);
                let next = if more {
                    rows.last().map(|r| r.target().key())
                } else {
                    None
                };
                let configured = service.execution_dispatcher.is_some();
                let available = app.status().is_ok_and(|s| s == SessionStatus::Unlocked)
                    && service
                        .execution_dispatcher
                        .as_ref()
                        .is_some_and(|dispatcher| dispatcher.available());
                Ok(Response::ok(
                    serde_json::json!({"version":2,"identities":rows,"next_cursor":next,"generation":generation,"provider":{"fingerprint":service.provider_fingerprint,"execution_configured":configured,"execution_available":available}}),
                ))
            }
            Command::IdentityDetail { target, .. } => {
                let row = inventory(service, actor, app)?
                    .into_iter()
                    .find(|row| row.target() == target)
                    .ok_or(Error::Unavailable)?;
                Ok(Response::ok(
                    serde_json::json!({"version":2,"identity":row,"generation":generation}),
                ))
            }
            Command::IdentityPrepare { target, .. } => {
                let mut state = service.management.lock().map_err(|_| Error::Unavailable)?;
                let row = inventory(service, actor, app)?
                    .into_iter()
                    .find(|row| row.target() == target)
                    .ok_or(Error::Unavailable)?;
                if row.trust == "revoked" {
                    return Err(Error::Stale);
                }
                let now = app.companion_now();
                state.tickets.retain(|t| t.deadline > now);
                if state.tickets.len() >= MAX_TICKETS {
                    return Err(Error::RateLimited);
                }
                let action_id = crate::access::RequestId::new_random()
                    .map_err(|_| Error::Unavailable)?
                    .as_str()
                    .to_owned();
                let mut nonce = [0; 32];
                getrandom::fill(&mut nonce).map_err(|_| Error::Unavailable)?;
                let ticket = identity::fingerprint(&nonce);
                let deadline = now
                    .checked_add(Duration::from_secs(55))
                    .ok_or(Error::Unavailable)?;
                state.tickets.push(Ticket {
                    token: ticket.clone(),
                    action_id: action_id.clone(),
                    actor: actor.into(),
                    target,
                    generation,
                    epoch,
                    deadline,
                });
                Ok(Response::ok(
                    serde_json::json!({"version":2,"identity":row,"action_id":action_id,"ticket":ticket,"generation":generation,"valid_for_seconds":55}),
                ))
            }
            Command::IdentityRevoke {
                target,
                action_id,
                ticket,
                password,
                ..
            } => {
                let mut state = service.management.lock().map_err(|_| Error::Unavailable)?;
                let position = state
                    .tickets
                    .iter()
                    .position(|t| {
                        t.actor == actor
                            && t.action_id == action_id
                            && t.target == target
                            && t.token == ticket
                    })
                    .ok_or(Error::Stale)?;
                let ticket = state.tickets.swap_remove(position);
                drop(state);
                if ticket.generation != generation || app.companion_now() >= ticket.deadline {
                    return Err(Error::Stale);
                }
                let _authentication = service
                    .authentication
                    .try_lock()
                    .map_err(|_| Error::RateLimited)?;
                if !service.attempt(actor, app.companion_now()) {
                    return Err(Error::RateLimited);
                }
                let authenticator = service
                    .approval_authenticator
                    .as_ref()
                    .ok_or(Error::Unavailable)?;
                authenticator
                    .authenticate(password)
                    .map_err(|_| Error::Authentication)?;
                let _commit = service
                    .identity_commit
                    .lock()
                    .map_err(|_| Error::Unavailable)?;
                if !service.authorized(actor)
                    || !identity::administrator(&service.identity_store, actor)
                    || app.companion_now() >= ticket.deadline
                    || app.management_authority().map_err(|_| Error::Unavailable)?
                        != (ticket.generation, ticket.epoch)
                {
                    return Err(Error::Stale);
                }
                if inventory(service, actor, app)?
                    .into_iter()
                    .find(|row| row.target() == target)
                    .is_none_or(|row| row.trust != "enabled")
                {
                    return Err(Error::Stale);
                }
                let mut journal = read_journal(root)?;
                if journal.actions.len() >= MAX_ACTIONS
                    || journal.actions.iter().any(|a| a.action_id == action_id)
                {
                    return Err(Error::Unavailable);
                }
                journal.actions.push(Action {
                    action_id: action_id.clone(),
                    actor: actor.into(),
                    target: target.clone(),
                    revocation: Revocation::Pending,
                    cleanup: Cleanup::Pending,
                    owner_reconciled: false,
                    reconciled_by_uid: None,
                });
                save_journal(root, &journal)?;
                let action = journal.actions.last_mut().ok_or(Error::Unavailable)?;
                #[cfg(test)]
                {
                    let hook = service
                        .management
                        .lock()
                        .map_err(|_| Error::Unavailable)?
                        .before_mutation
                        .take();
                    if let Some(hook) = hook {
                        hook();
                    }
                }
                use crate::access::application::ManagementMutationError;
                let outcome = match target.kind {
                    Kind::RequesterAgent => app
                        .revoke_agent_checked(
                            app.human_owner(),
                            &target.id,
                            Some((ticket.generation, ticket.epoch, ticket.deadline)),
                        )
                        .map(|(_, complete)| complete),
                    Kind::ApprovalClient => {
                        match app.management_retire(
                            ticket.generation,
                            ticket.epoch,
                            ticket.deadline,
                        ) {
                            Ok(complete) => {
                                match identity::revoke_online(root, &target.id, actor) {
                                    Ok(()) => Ok(complete),
                                    Err(_) => {
                                        service
                                            .management
                                            .lock()
                                            .map_err(|_| Error::Unavailable)?
                                            .failed = true;
                                        app.close_admission();
                                        Err(ManagementMutationError::Uncertain(
                                            DirectRequestError::Unavailable,
                                        ))
                                    }
                                }
                            }
                            Err(error) => Err(error),
                        }
                    }
                };
                match outcome {
                    Ok(complete) => {
                        action.revocation = Revocation::Recorded;
                        action.cleanup = if complete {
                            Cleanup::Complete
                        } else {
                            Cleanup::Unknown
                        };
                    }
                    Err(ManagementMutationError::NotStarted(_)) => {
                        action.revocation = Revocation::NotRecorded;
                        action.cleanup = Cleanup::NotApplicable;
                    }
                    Err(ManagementMutationError::Uncertain(_)) => {
                        action.revocation = Revocation::Unknown;
                        action.cleanup = Cleanup::Unknown;
                    }
                }
                let response = action_response(action);
                if save_journal(root, &journal).is_err() {
                    service
                        .management
                        .lock()
                        .map_err(|_| Error::Unavailable)?
                        .failed = true;
                    app.close_admission();
                    return Err(Error::Unavailable);
                }
                Ok(response)
            }
            _ => Err(Error::Invalid),
        }
    })();
    result.unwrap_or_else(Response::error)
}

/// Called before ANY transport/worker starts. An interrupted administrative
/// transaction must not restore a token denied only in the old process.
pub(super) fn enforce_recovery_fence(root: &Path, app: &ProviderApplication) {
    let safe = read_journal(root).is_ok_and(|journal| {
        journal.actions.iter().all(|action| {
            action.owner_reconciled
                || matches!(
                    (&action.revocation, &action.cleanup),
                    (Revocation::Recorded, Cleanup::Complete)
                        | (Revocation::NotRecorded, Cleanup::NotApplicable)
                )
        })
    });
    if !safe {
        app.close_admission();
    }
}

/// Explicit local-owner recovery. The provider writer lock is acquired before
/// cleanup or target mutation; the original remote outcome is never rewritten.
pub(super) fn reconcile_stopped(
    root: &Path,
    action_id: &str,
    kind: &str,
    id: &str,
    supplied_actor: Option<&str>,
    cleanup: impl FnOnce() -> Result<(), ()>,
) -> Result<serde_json::Value, SessionError> {
    use crate::access::{direct_request::AuthenticatedHuman, provider::Provider};
    let target = Target {
        kind: match kind {
            "approval_client" => Kind::ApprovalClient,
            "requester_agent" => Kind::RequesterAgent,
            _ => return Err(SessionError::InvalidRequest),
        },
        id: id.into(),
    };
    if !valid_request_id(action_id)
        || !target.valid()
        || supplied_actor.is_some_and(|actor| !identity::valid_fingerprint(actor))
    {
        return Err(SessionError::InvalidRequest);
    }
    let resolve_actor = |journal: &Journal| -> Result<String, SessionError> {
        match journal.actions.iter().find(|a| a.action_id == action_id) {
            Some(action)
                if action.target == target
                    && supplied_actor.is_none_or(|actor| actor == action.actor) =>
            {
                Ok(action.actor.clone())
            }
            Some(_) => Err(SessionError::InvalidRequest),
            None => {
                if journal.actions.len() >= MAX_ACTIONS {
                    return Err(SessionError::BackendUnavailable);
                }
                // No receipt means no attribution can be inferred. Only the
                // trusted owner may supply the original exact certificate.
                let actor = supplied_actor.ok_or(SessionError::InvalidRequest)?;
                if !identity::management_records(&root.join(identity::STORE_FILE))?
                    .iter()
                    .any(|(entry, _, _)| entry.fingerprint == actor)
                {
                    return Err(SessionError::InvalidRequest);
                }
                Ok(actor.into())
            }
        }
    };
    let before = read_journal(root).map_err(|_| SessionError::BackendUnavailable)?;
    resolve_actor(&before)?;
    // start_with_cleanup refuses a competing daemon before invoking cleanup.
    let mut provider = Provider::start_with_cleanup(root, cleanup)
        .map_err(|_| SessionError::BackendUnavailable)?;
    let mut journal = read_journal(root).map_err(|_| SessionError::BackendUnavailable)?;
    let actor = resolve_actor(&journal)?;
    if !journal.actions.iter().any(|a| a.action_id == action_id) {
        // Persist the owner's separate recovery intent before target mutation.
        // This is unknown history, never a claim the remote action was received.
        journal.actions.push(Action {
            action_id: action_id.into(),
            actor,
            target: target.clone(),
            revocation: Revocation::Unknown,
            cleanup: Cleanup::Unknown,
            owner_reconciled: false,
            reconciled_by_uid: None,
        });
        save_journal(root, &journal).map_err(|_| SessionError::BackendUnavailable)?;
    }
    let action = journal
        .actions
        .iter_mut()
        .find(|a| a.action_id == action_id && a.target == target)
        .ok_or(SessionError::InvalidRequest)?;
    let owner = AuthenticatedHuman::from_peer_uid(unsafe { libc::geteuid() });
    match target.kind {
        Kind::ApprovalClient => identity::revoke_online(root, &target.id, "local_owner")?,
        Kind::RequesterAgent => {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| SessionError::BackendUnavailable)?
                .as_secs();
            provider
                .revoke_agent(owner, &target.id, now)
                .map_err(|_| SessionError::BackendUnavailable)?;
        }
    }
    provider
        .shutdown()
        .map_err(|_| SessionError::BackendUnavailable)?;
    action.owner_reconciled = true;
    action.reconciled_by_uid = Some(unsafe { libc::geteuid() });
    let receipt = serde_json::from_str(&action_response(action).body)
        .map_err(|_| SessionError::BackendUnavailable)?;
    save_journal(root, &journal).map_err(|_| SessionError::BackendUnavailable)?;
    Ok(receipt)
}

/// Exception to enrollment: TLS still authenticates the exact certificate, and
/// only its own existing action receipt is readable. No general read authority.
pub(super) fn receipt_authorized(service: &Companion, actor: &str, command: &Command) -> bool {
    let Command::IdentityStatus {
        target, action_id, ..
    } = command
    else {
        return false;
    };
    let Some(root) = service.identity_store.parent() else {
        return false;
    };
    read_journal(root).is_ok_and(|journal| {
        journal
            .actions
            .iter()
            .any(|a| a.actor == actor && a.action_id == *action_id && a.target == *target)
    })
}
