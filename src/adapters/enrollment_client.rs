//! Agent-side guided enrollment driver (#59 phase 1): creates the agent key,
//! joins, asks the joining human, then confirms until the provider commits.
//! I/O is injected so the whole journey is testable without a terminal.

use crate::access::enrollment::{
    EnrolledIdentity, EnrollmentRejection, EnrollmentState, FailureReason, JoinerCancelReason,
    joiner::{InvitationCode, JoinAttempt, JoinedSession, JoinerError},
    wire::{EnrollmentReply, EnrollmentRequest},
};
use ed25519_dalek::SigningKey;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};
use zeroize::Zeroizing;

/// Identical join retransmissions after a transport failure.
const JOIN_ATTEMPTS: usize = 3;
/// Identical joins answered `unavailable` before giving up. A join refused
/// as `unavailable` changed nothing on the provider (the invitation stays
/// open, nothing was recorded), so resending it is safe; the bound keeps a
/// provider that is shutting down from holding the joiner until the deadline.
const UNAVAILABLE_ATTEMPTS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_secs(1);
/// Delay before resending after a lost reply or a `busy` provider; doubles
/// up to `BACKOFF_MAX`. Busy retries are bounded by the deadline.
const BACKOFF_FIRST: Duration = Duration::from_millis(250);
const BACKOFF_MAX: Duration = Duration::from_secs(2);
/// Slack past the session's own expiry before the joiner stops waiting, so
/// the provider's final `expired` state can still be observed.
const EXPIRY_GRACE: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JoinFailure {
    #[error("{0}")]
    Joiner(JoinerError),
    #[error("the provider is unreachable")]
    ProviderOffline,
    #[error("the provider stayed busy until the deadline; nothing was enrolled")]
    ProviderBusy,
    #[error("the comparison codes did not match; enrollment cancelled")]
    Declined,
    #[error("the provider rejected the request: {0}")]
    Rejected(EnrollmentRejection),
    /// `invalid_invitation`, which is also the agent socket's answer once
    /// nothing the provider retains names this account.
    #[error(
        "the provider does not recognise this invitation for this account (invalid_invitation): \
         the code may be mistyped, or the invitation cancelled, expired or ended and since \
         forgotten, or the provider restarted; ask the provider owner for a new invitation"
    )]
    InvitationUnknown,
    /// A confirmation's reply was lost, and the provider then no longer knew
    /// the session (restart, retention): it may have committed meanwhile.
    #[error("a confirmation reply was lost and the provider now answers {0}; outcome unknown")]
    OutcomeUnknown(EnrollmentRejection),
    /// `Failed{unavailable}`: the provider's store failed while committing.
    /// A store fault there is ambiguous (the binding may be durable while a
    /// later step failed), so only `identity_refused` is a definite "no".
    #[error(
        "the provider could not confirm that the enrollment was stored (failed: unavailable); \
         outcome unknown"
    )]
    CommitUncertain,
    #[error("enrollment ended without enrolling: {0:?}")]
    Ended(EnrollmentState),
    #[error("timed out waiting for the provider's approval")]
    TimedOut,
    #[error("local key file unavailable")]
    LocalKey,
    #[error("{0}")]
    KeyFile(KeyFileError),
}

/// Why the agent key file could not be created.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyFileError {
    #[error("the key file already exists; enrollment never replaces a key file")]
    Exists,
    #[error(
        "the key file's directory is refused: it must be a real directory (not a symlink) owned \
         by this account and not group- or world-writable"
    )]
    UnsafeDirectory,
    #[error("the key file's directory does not exist")]
    MissingDirectory,
    #[error("cannot create the key file")]
    Unavailable,
}

impl JoinFailure {
    /// Whether the provider may have enrolled the key despite this failure,
    /// so a key file must be kept rather than deleted.
    pub fn outcome_unknown(&self) -> bool {
        matches!(
            self,
            Self::TimedOut | Self::OutcomeUnknown(_) | Self::CommitUncertain
        )
    }
    fn rejected(reason: EnrollmentRejection) -> Self {
        match reason {
            EnrollmentRejection::InvalidInvitation => Self::InvitationUnknown,
            reason => Self::Rejected(reason),
        }
    }
}

/// 250 ms, 500 ms, 1 s, 2 s, 2 s, …
struct Backoff(Duration);

impl Backoff {
    fn new() -> Self {
        Self(BACKOFF_FIRST)
    }
    fn next(&mut self) -> Duration {
        let delay = self.0;
        self.0 = (self.0 * 2).min(BACKOFF_MAX);
        delay
    }
}

/// Sleep for `delay` unless that would pass `deadline`.
async fn pause(delay: Duration, deadline: tokio::time::Instant) -> bool {
    if tokio::time::Instant::now() + delay >= deadline {
        return false;
    }
    tokio::time::sleep(delay).await;
    true
}

/// One message to the provider; a transport error means the outcome is unknown.
pub trait EnrollmentTransport {
    fn send(
        &mut self,
        request: &EnrollmentRequest,
    ) -> impl std::future::Future<Output = Result<EnrollmentReply, ()>>;
}

/// The joining human. `confirm` shows the code and role and asks whether the
/// provider displays the same code; `waiting` reports progress.
pub trait JoinerPrompt {
    fn confirm(&mut self, session: &JoinedSession) -> bool;
    fn waiting(&mut self, state: &EnrollmentState);
}

/// Run the joiner protocol until enrolled, a final state, or the deadline:
/// `deadline` when given, else the session's own expiry (plus a short grace),
/// and never past that expiry plus grace either way.
pub async fn join_agent(
    transport: &mut impl EnrollmentTransport,
    prompt: &mut impl JoinerPrompt,
    code: InvitationCode,
    key: &SigningKey,
    deadline: Option<tokio::time::Instant>,
) -> Result<EnrolledIdentity, JoinFailure> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_error| JoinFailure::LocalKey)?;
    let attempt = JoinAttempt::agent(code, key, nonce);
    // Before the provider answers, the longest invitation bounds the wait.
    let join_deadline = tokio::time::Instant::now()
        + Duration::from_secs(crate::access::enrollment::MAX_TTL_SECONDS)
        + EXPIRY_GRACE;
    let join_deadline = deadline.map_or(join_deadline, |d| d.min(join_deadline));
    let mut backoff = Backoff::new();
    let (mut lost, mut unavailable) = (0, 0);
    let reply = loop {
        match transport.send(attempt.request()).await {
            // Contention, not a refusal: the identical join is resent.
            Ok(EnrollmentReply::Rejected {
                reason: EnrollmentRejection::Busy,
                ..
            }) => {}
            // A provider fault that burned nothing: resent a few times.
            Ok(EnrollmentReply::Rejected {
                reason: EnrollmentRejection::Unavailable,
                ..
            }) => {
                unavailable += 1;
                if unavailable >= UNAVAILABLE_ATTEMPTS {
                    return Err(JoinFailure::Rejected(EnrollmentRejection::Unavailable));
                }
            }
            Ok(EnrollmentReply::Rejected { reason, .. }) => {
                return Err(JoinFailure::rejected(reason));
            }
            Ok(reply) => break reply,
            Err(()) => {
                lost += 1;
                if lost >= JOIN_ATTEMPTS {
                    return Err(JoinFailure::ProviderOffline);
                }
            }
        }
        if !pause(backoff.next(), join_deadline).await {
            return Err(if lost > 0 {
                JoinFailure::ProviderOffline
            } else if unavailable > 0 {
                JoinFailure::Rejected(EnrollmentRejection::Unavailable)
            } else {
                JoinFailure::ProviderBusy
            });
        }
    };
    let session = attempt.accept(&reply).map_err(JoinFailure::Joiner)?;
    let expiry = tokio::time::Instant::now()
        + Duration::from_secs(session.expires_in_seconds)
        + EXPIRY_GRACE;
    let deadline = deadline.map_or(expiry, |d| d.min(expiry));
    if !prompt.confirm(&session) {
        let _ignored = transport
            .send(&session.cancel(JoinerCancelReason::CodeMismatch))
            .await;
        return Err(JoinFailure::Declined);
    }
    let confirm = session.confirm(Some(key));
    let mut last = None;
    let mut backoff = Backoff::new();
    // Set while a confirmation's reply is lost: that confirmation may have
    // committed, so a later "unknown session" is no proof of failure. A
    // later non-final state proves nothing had committed by then, and
    // clears it.
    let mut lost_reply = false;
    loop {
        let delay = match transport.send(&confirm).await {
            Ok(EnrollmentReply::State {
                state: EnrollmentState::Enrolled { identity },
                ..
            }) => return Ok(identity),
            Ok(EnrollmentReply::State {
                state:
                    EnrollmentState::Failed {
                        reason: FailureReason::Unavailable,
                    },
                ..
            }) => return Err(JoinFailure::CommitUncertain),
            Ok(EnrollmentReply::State { state, .. }) if state.is_final() => {
                return Err(JoinFailure::Ended(state));
            }
            Ok(EnrollmentReply::State { state, .. }) => {
                lost_reply = false;
                if last.as_ref() != Some(&state) {
                    prompt.waiting(&state);
                    last = Some(state);
                }
                backoff = Backoff::new();
                POLL_INTERVAL
            }
            Ok(EnrollmentReply::Rejected {
                reason: EnrollmentRejection::Busy,
                ..
            }) => backoff.next(),
            Ok(EnrollmentReply::Rejected { reason, .. }) if lost_reply => {
                return Err(JoinFailure::OutcomeUnknown(reason));
            }
            Ok(EnrollmentReply::Rejected { reason, .. }) => {
                return Err(JoinFailure::rejected(reason));
            }
            Ok(EnrollmentReply::Joined { .. }) => {
                return Err(JoinFailure::Joiner(JoinerError::UnexpectedReply));
            }
            // Offline provider: keep the same confirmation until the deadline.
            Err(()) => {
                lost_reply = true;
                backoff.next()
            }
        };
        if !pause(delay, deadline).await {
            return Err(JoinFailure::TimedOut);
        }
    }
}

/// The directory holding the key file, which only its owner may change: the
/// file is later removed by path after a definitive failure, and in a
/// directory others can write (even sticky) that path could be replaced.
fn key_directory(path: &Path) -> Result<std::fs::File, KeyFileError> {
    use std::os::unix::fs::MetadataExt;
    let parent = match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent,
        _ => Path::new("."),
    };
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|error| match error.raw_os_error() {
            // A symlinked or non-directory parent.
            Some(libc::ELOOP | libc::ENOTDIR) => KeyFileError::UnsafeDirectory,
            Some(libc::ENOENT) => KeyFileError::MissingDirectory,
            _ => KeyFileError::Unavailable,
        })?;
    let metadata = directory
        .metadata()
        .map_err(|_error| KeyFileError::Unavailable)?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
        return Err(KeyFileError::UnsafeDirectory);
    }
    Ok(directory)
}

/// A fresh Ed25519 seed in a new agent-owned `0600` file (never replaced),
/// in a directory only the agent account can change. This is the
/// `vw-access submit --key-file` format: exactly 32 raw bytes.
pub fn create_agent_key(path: &Path) -> Result<SigningKey, KeyFileError> {
    let directory = key_directory(path)?;
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_error| KeyFileError::Unavailable)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|error| match error.kind() {
            // Also a dangling symlink at the path: never followed.
            std::io::ErrorKind::AlreadyExists => KeyFileError::Exists,
            _ => KeyFileError::Unavailable,
        })?;
    if file
        .write_all(seed.as_ref())
        .and_then(|()| file.sync_all())
        .and_then(|()| directory.sync_all())
        .is_err()
    {
        remove_agent_key(path);
        return Err(KeyFileError::Unavailable);
    }
    Ok(SigningKey::from_bytes(&seed))
}

/// Remove a key file this run created after a definitive failure, only from
/// a directory that still only its owner can change, and make the removal
/// durable. Best effort: a refusal leaves the file in place.
pub fn remove_agent_key(path: &Path) {
    if let Ok(directory) = key_directory(path)
        && std::fs::remove_file(path).is_ok()
    {
        let _ignored = directory.sync_all();
    }
}

/// `enroll join` after the code is read: create a new key file at
/// `key_file`, run the protocol, and settle the file. It is kept when
/// enrolled and when the outcome is unknown (the provider may have bound
/// the key), and removed after a definitive failure.
pub async fn join_with_new_key(
    transport: &mut impl EnrollmentTransport,
    prompt: &mut impl JoinerPrompt,
    code: InvitationCode,
    key_file: &Path,
    deadline: Option<tokio::time::Instant>,
) -> Result<EnrolledIdentity, JoinFailure> {
    let key = create_agent_key(key_file).map_err(JoinFailure::KeyFile)?;
    let result = join_agent(transport, prompt, code, &key, deadline).await;
    if let Err(error) = &result
        && !error.outcome_unknown()
    {
        remove_agent_key(key_file);
    }
    result
}

/// The agent socket as an enrollment transport.
pub struct SocketTransport<'a> {
    pub socket: &'a Path,
}

impl EnrollmentTransport for SocketTransport<'_> {
    async fn send(&mut self, request: &EnrollmentRequest) -> Result<EnrollmentReply, ()> {
        super::unix_socket::enrollment_exchange(self.socket, request)
            .await
            .map_err(|_error| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::enrollment::{
        EnrolleeKind, FailureReason, InvitationRequest, Peer,
        book::{Book, EnrollmentHooks, Joiner},
    };
    use std::sync::{Arc, Mutex};

    /// The provider store; `fail` makes the commit fail with that reason.
    struct Commit {
        fail: Option<FailureReason>,
    }
    impl EnrollmentHooks for Commit {
        fn admissible(&mut self, _: &EnrolleeKind, _: &Joiner) -> Result<bool, FailureReason> {
            Ok(true)
        }
        fn commit(
            &mut self,
            _: &EnrolleeKind,
            joiner: &Joiner,
            _: u32,
        ) -> Result<EnrolledIdentity, FailureReason> {
            if let Some(reason) = self.fail {
                return Err(reason);
            }
            Ok(EnrolledIdentity::Agent {
                binding_id: "id".into(),
                fingerprint: joiner.fingerprint.clone(),
            })
        }
    }
    type ProviderAction = Box<dyn FnOnce(&mut Book)>;
    /// The provider in memory; `offline` drops that many messages first,
    /// `busy` answers that many with the provider's contention reply,
    /// `on_confirm` runs the provider human's action at the first confirm.
    /// `lose_commit_reply` processes the first confirm but loses its reply,
    /// then restarts the provider (every session forgotten).
    struct Fake {
        book: Arc<Mutex<Book>>,
        offline: usize,
        busy: usize,
        /// Messages answered normally before `busy` starts.
        busy_from: usize,
        /// Joins answered `unavailable` (nothing changes on the provider).
        unavailable: usize,
        lose_commit_reply: bool,
        on_confirm: Option<ProviderAction>,
        /// Run before the n-th message (1-based) is handled.
        before: std::collections::HashMap<usize, ProviderAction>,
        /// Messages (1-based) that are handled but whose reply is lost.
        lose_reply: Vec<usize>,
        commit_fails: Option<FailureReason>,
        sent: Vec<EnrollmentRequest>,
        at: Vec<tokio::time::Instant>,
    }
    impl EnrollmentTransport for Fake {
        async fn send(&mut self, request: &EnrollmentRequest) -> Result<EnrollmentReply, ()> {
            self.sent.push(request.clone());
            self.at.push(tokio::time::Instant::now());
            if self.offline > 0 {
                self.offline -= 1;
                return Err(());
            }
            if self.busy > 0 && self.sent.len() > self.busy_from {
                self.busy -= 1;
                return Ok(EnrollmentReply::rejected(EnrollmentRejection::Busy));
            }
            if self.unavailable > 0 && matches!(request, EnrollmentRequest::EnrollJoin { .. }) {
                self.unavailable -= 1;
                return Ok(EnrollmentReply::rejected(EnrollmentRejection::Unavailable));
            }
            let mut book = self.book.lock().unwrap();
            if let Some(action) = self.before.remove(&self.sent.len()) {
                action(&mut book);
            }
            let confirm = matches!(request, EnrollmentRequest::EnrollConfirm { .. });
            if confirm && let Some(action) = self.on_confirm.take() {
                action(&mut book);
            }
            let peer = Peer::Agent {
                uid: 4100,
                groups: vec![4200],
            };
            let reply = book.handle(
                &peer,
                &[],
                request,
                Duration::from_secs(5),
                [3; 32],
                &mut Commit {
                    fail: self.commit_fails,
                },
            );
            if confirm && self.lose_commit_reply {
                self.lose_commit_reply = false;
                *book = Book::default();
                return Err(());
            }
            if self.lose_reply.contains(&self.sent.len()) {
                return Err(());
            }
            Ok(reply)
        }
    }
    struct Human {
        answer: bool,
        seen: Arc<Mutex<Vec<String>>>,
    }
    impl JoinerPrompt for Human {
        fn confirm(&mut self, session: &JoinedSession) -> bool {
            self.seen
                .lock()
                .unwrap()
                .push(session.comparison_code.clone());
            self.answer
        }
        fn waiting(&mut self, _: &EnrollmentState) {}
    }
    fn setup(offline: usize) -> (Fake, String, String) {
        let book = Arc::new(Mutex::new(Book::default()));
        let issued = book
            .lock()
            .unwrap()
            .invite(
                InvitationRequest {
                    kind: EnrolleeKind::Agent {
                        label: "ci".into(),
                        uid: 4100,
                        gid: 4200,
                    },
                    ttl_seconds: None,
                },
                Duration::from_secs(1),
                &std::array::from_fn(|index| index as u8 + 1),
            )
            .unwrap();
        let id = issued.id.clone();
        (
            Fake {
                book,
                offline,
                busy: 0,
                busy_from: 0,
                unavailable: 0,
                lose_commit_reply: false,
                on_confirm: None,
                before: Default::default(),
                lose_reply: Vec::new(),
                commit_fails: None,
                sent: Vec::new(),
                at: Vec::new(),
            },
            issued.invitation_code.clone(),
            id,
        )
    }
    fn deadline() -> Option<tokio::time::Instant> {
        Some(tokio::time::Instant::now() + Duration::from_millis(1500))
    }

    #[tokio::test]
    async fn agent_enrolls_after_retrying_a_lost_join_and_approval_by_the_provider_human() {
        let (mut fake, code, id) = setup(1);
        let book = fake.book.clone();
        let mut human = Human {
            answer: true,
            seen: Default::default(),
        };
        // The provider owner types the code the joiner displays.
        let shown = human.seen.clone();
        fake.on_confirm = Some(Box::new(move |book: &mut Book| {
            let code = shown.lock().unwrap()[0].clone();
            book.approve(&id, &code, 501, Duration::from_secs(5))
                .unwrap();
        }));
        let key = SigningKey::from_bytes(&[4; 32]);
        let identity = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            deadline(),
        )
        .await
        .unwrap();
        assert!(matches!(identity, EnrolledIdentity::Agent { .. }));
        assert_eq!(
            fake.sent[0], fake.sent[1],
            "the lost join is resent byte-identically"
        );
        assert_eq!(human.seen.lock().unwrap().len(), 1);
        assert!(matches!(
            book.lock().unwrap().list(Duration::from_secs(5))[0].state,
            EnrollmentState::Enrolled { .. }
        ));
    }

    #[tokio::test]
    async fn declining_the_code_cancels_with_a_mismatch_and_never_confirms() {
        let (mut fake, code, _) = setup(0);
        let mut human = Human {
            answer: false,
            seen: Default::default(),
        };
        let key = SigningKey::from_bytes(&[4; 32]);
        let result = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            deadline(),
        )
        .await;
        assert_eq!(result, Err(JoinFailure::Declined));
        assert!(matches!(
            fake.sent.last(),
            Some(EnrollmentRequest::EnrollCancel {
                reason: JoinerCancelReason::CodeMismatch,
                ..
            })
        ));
        assert!(
            !fake
                .sent
                .iter()
                .any(|r| matches!(r, EnrollmentRequest::EnrollConfirm { .. }))
        );
    }

    #[tokio::test]
    async fn an_offline_provider_or_a_missing_approval_times_out_without_enrolling() {
        let (mut fake, code, _) = setup(JOIN_ATTEMPTS);
        let key = SigningKey::from_bytes(&[4; 32]);
        let mut human = Human {
            answer: true,
            seen: Default::default(),
        };
        let result = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            deadline(),
        )
        .await;
        assert_eq!(result, Err(JoinFailure::ProviderOffline));
        let (mut fake, code, _) = setup(0);
        let result = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            deadline(),
        )
        .await;
        assert_eq!(result, Err(JoinFailure::TimedOut), "no provider approval");
    }

    /// The provider owner types what the joiner shows, at the first confirm.
    fn approve_on_confirm(fake: &mut Fake, human: &Human, id: String) {
        let shown = human.seen.clone();
        fake.on_confirm = Some(Box::new(move |book: &mut Book| {
            let code = shown.lock().unwrap()[0].clone();
            book.approve(&id, &code, 501, Duration::from_secs(5))
                .unwrap();
        }));
    }

    #[tokio::test]
    async fn a_busy_provider_is_retried_with_backoff_and_is_not_a_failure() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let long = || Some(tokio::time::Instant::now() + Duration::from_secs(10));
        // Busy at the join: the identical join is resent after a growing delay.
        let (mut fake, code, id) = setup(0);
        fake.busy = 2;
        let mut human = Human {
            answer: true,
            seen: Default::default(),
        };
        approve_on_confirm(&mut fake, &human, id);
        let identity = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            long(),
        )
        .await;
        assert!(matches!(identity, Ok(EnrolledIdentity::Agent { .. })));
        assert!(fake.sent[0] == fake.sent[1] && fake.sent[1] == fake.sent[2]);
        assert!(fake.at[1] - fake.at[0] >= Duration::from_millis(250));
        assert!(fake.at[2] - fake.at[1] >= Duration::from_millis(500));
        // Busy while confirming: the confirmation keeps being resent.
        let (mut fake, code, id) = setup(0);
        (fake.busy, fake.busy_from) = (2, 1);
        let mut human = Human {
            answer: true,
            seen: Default::default(),
        };
        approve_on_confirm(&mut fake, &human, id);
        let identity = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            long(),
        )
        .await;
        assert!(matches!(identity, Ok(EnrolledIdentity::Agent { .. })));
        assert_eq!(fake.sent.len(), 4, "join, two busy confirms, the commit");
    }

    #[tokio::test]
    async fn a_lost_commit_reply_then_a_restart_is_an_unknown_outcome() {
        let (mut fake, code, id) = setup(0);
        fake.lose_commit_reply = true;
        let mut human = Human {
            answer: true,
            seen: Default::default(),
        };
        approve_on_confirm(&mut fake, &human, id);
        let key = SigningKey::from_bytes(&[4; 32]);
        let error = join_agent(
            &mut fake,
            &mut human,
            InvitationCode::parse(&code).unwrap(),
            &key,
            Some(tokio::time::Instant::now() + Duration::from_secs(10)),
        )
        .await
        .unwrap_err();
        // The binding exists although the provider no longer knows the
        // session: the key must be kept, not deleted as a definitive failure.
        assert!(error.to_string().contains("outcome unknown"), "{error}");
    }

    #[test]
    fn agent_socket_refusals_reach_the_joiner_as_enrollment_rejections() {
        use crate::adapters::unix_socket::enrollment_reply;
        for (category, reason) in [
            ("unauthorized", EnrollmentRejection::InvalidInvitation),
            ("busy", EnrollmentRejection::Busy),
            ("malformed", EnrollmentRejection::Malformed),
            ("unavailable", EnrollmentRejection::Unavailable),
            ("locked", EnrollmentRejection::Unavailable),
        ] {
            let bytes =
                format!(r#"{{"status":"rejected","protocol_version":1,"category":"{category}"}}"#);
            assert_eq!(
                enrollment_reply(bytes.as_bytes()).ok(),
                Some(EnrollmentReply::rejected(reason)),
                "{category}"
            );
        }
        assert!(enrollment_reply(br#"{"status":"pending"}"#).is_err());
    }

    #[test]
    fn agent_key_files_are_new_private_and_never_replaced() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.key");
        let key = create_agent_key(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), key.to_bytes());
        assert_eq!(create_agent_key(&path).err(), Some(KeyFileError::Exists));
        assert_eq!(std::fs::read(&path).unwrap(), key.to_bytes());
    }

    /// The key file is later removed by path after a definitive failure. In
    /// a directory others can write, that path could be swapped meanwhile,
    /// so such a directory is refused before any key exists.
    #[test]
    fn agent_keys_are_only_created_in_a_directory_only_the_owner_can_change() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        for mode in [0o777, 0o770, 0o1777] {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            let path = dir.path().join("agent.key");
            assert_eq!(
                create_agent_key(&path).err(),
                Some(KeyFileError::UnsafeDirectory),
                "{mode:o}"
            );
            assert!(!path.exists());
        }
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = dir.path().join("agent.key");
        create_agent_key(&path).unwrap();
        remove_agent_key(&path);
        assert!(!path.exists());
    }

    /// The key-file refusals the joiner can fix are told apart: an existing
    /// file, a directory others can change or reached through a symlink,
    /// and a missing directory.
    #[test]
    fn key_file_refusals_say_what_to_fix() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        std::fs::create_dir(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        assert_eq!(
            create_agent_key(&link.join("agent.key")).err(),
            Some(KeyFileError::UnsafeDirectory),
            "a symlinked parent"
        );
        assert!(!real.join("agent.key").exists());
        assert_eq!(
            create_agent_key(&dir.path().join("missing/agent.key")).err(),
            Some(KeyFileError::MissingDirectory)
        );
        std::os::unix::fs::symlink("/nonexistent", real.join("dangling.key")).unwrap();
        assert_eq!(
            create_agent_key(&real.join("dangling.key")).err(),
            Some(KeyFileError::Exists),
            "a dangling symlink is never followed"
        );
        let messages = [
            KeyFileError::Exists,
            KeyFileError::UnsafeDirectory,
            KeyFileError::MissingDirectory,
            KeyFileError::Unavailable,
        ]
        .map(|error| JoinFailure::KeyFile(error).to_string());
        for (index, message) in messages.iter().enumerate() {
            assert!(!messages[..index].contains(message), "{message}");
        }
    }

    fn human() -> Human {
        Human {
            answer: true,
            seen: Default::default(),
        }
    }
    async fn join_keyed(
        fake: &mut Fake,
        human: &mut Human,
        code: &str,
        key_file: &Path,
        deadline: Option<tokio::time::Instant>,
    ) -> Result<EnrolledIdentity, JoinFailure> {
        join_with_new_key(
            fake,
            human,
            InvitationCode::parse(code).unwrap(),
            key_file,
            deadline,
        )
        .await
    }
    fn far() -> Option<tokio::time::Instant> {
        Some(tokio::time::Instant::now() + Duration::from_secs(60))
    }

    /// A lost confirmation reply makes a later refusal ambiguous only until
    /// the provider answers a non-final state again: that state proves no
    /// commit had happened, so a later "unknown session" is definitive.
    #[tokio::test(start_paused = true)]
    async fn a_waiting_state_after_a_lost_reply_makes_a_later_refusal_definitive() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("agent.key");
        let (mut fake, code, id) = setup(0);
        // 1 join, 2 confirm (reply lost), 3 confirm (awaiting approvals),
        // then the owner cancels and the provider restarts before 4.
        fake.lose_reply = vec![2];
        fake.before.insert(
            4,
            Box::new(move |book: &mut Book| {
                book.cancel(&id, Duration::from_secs(5)).unwrap();
                *book = Book::default();
            }),
        );
        let result = join_keyed(&mut fake, &mut human(), &code, &key_file, far()).await;
        assert_eq!(result, Err(JoinFailure::InvitationUnknown));
        assert_eq!(fake.sent.len(), 4);
        assert!(!key_file.exists(), "a definitive failure removes the key");
    }

    /// `run_join`'s key handling: kept when the outcome is unknown (here a
    /// lost commit reply, then a restarted provider), removed otherwise.
    #[tokio::test(start_paused = true)]
    async fn the_key_file_is_kept_only_when_the_outcome_is_unknown() {
        let dir = tempfile::tempdir().unwrap();
        let key_file = dir.path().join("agent.key");
        let (mut fake, code, id) = setup(0);
        fake.lose_commit_reply = true;
        let mut joiner = human();
        approve_on_confirm(&mut fake, &joiner, id);
        let error = join_keyed(&mut fake, &mut joiner, &code, &key_file, far())
            .await
            .unwrap_err();
        assert!(error.outcome_unknown(), "{error}");
        assert_eq!(std::fs::metadata(&key_file).unwrap().len(), 32);

        let key_file = dir.path().join("declined.key");
        let (mut fake, code, _) = setup(0);
        let mut joiner = human();
        joiner.answer = false;
        let result = join_keyed(&mut fake, &mut joiner, &code, &key_file, far()).await;
        assert_eq!(result, Err(JoinFailure::Declined));
        assert!(!key_file.exists());

        let key_file = dir.path().join("timeout.key");
        let (mut fake, code, _) = setup(0);
        let result = join_keyed(&mut fake, &mut human(), &code, &key_file, far()).await;
        assert_eq!(result, Err(JoinFailure::TimedOut), "never approved");
        assert!(key_file.exists());
    }

    /// `Failed{unavailable}` at commit is ambiguous (the store may hold the
    /// binding), so the key is kept; `Failed{identity_refused}` is a
    /// definite "no" and removes it.
    #[tokio::test(start_paused = true)]
    async fn a_commit_store_fault_is_an_unknown_outcome_but_a_refusal_is_not() {
        let dir = tempfile::tempdir().unwrap();
        for (reason, kept) in [
            (FailureReason::Unavailable, true),
            (FailureReason::IdentityRefused, false),
        ] {
            let key_file = dir.path().join(format!("{reason:?}.key"));
            let (mut fake, code, id) = setup(0);
            fake.commit_fails = Some(reason);
            let mut joiner = human();
            approve_on_confirm(&mut fake, &joiner, id);
            let error = join_keyed(&mut fake, &mut joiner, &code, &key_file, far())
                .await
                .unwrap_err();
            assert_eq!(error.outcome_unknown(), kept, "{error}");
            assert_eq!(key_file.exists(), kept, "{reason:?}");
        }
    }

    /// `unavailable` at join burned nothing, so the identical join is resent
    /// a bounded number of times; the invitation stays open either way.
    #[tokio::test(start_paused = true)]
    async fn an_unavailable_join_is_retried_a_bounded_number_of_times() {
        let key = SigningKey::from_bytes(&[4; 32]);
        let (mut fake, code, id) = setup(0);
        fake.unavailable = UNAVAILABLE_ATTEMPTS - 1;
        let mut joiner = human();
        approve_on_confirm(&mut fake, &joiner, id);
        let identity = join_agent(
            &mut fake,
            &mut joiner,
            InvitationCode::parse(&code).unwrap(),
            &key,
            far(),
        )
        .await;
        assert!(matches!(identity, Ok(EnrolledIdentity::Agent { .. })));
        assert!((0..UNAVAILABLE_ATTEMPTS).all(|i| fake.sent[i] == fake.sent[0]));

        let (mut fake, code, _) = setup(0);
        fake.unavailable = UNAVAILABLE_ATTEMPTS;
        let result = join_agent(
            &mut fake,
            &mut human(),
            InvitationCode::parse(&code).unwrap(),
            &key,
            far(),
        )
        .await;
        assert_eq!(
            result,
            Err(JoinFailure::Rejected(EnrollmentRejection::Unavailable))
        );
        assert_eq!(fake.sent.len(), UNAVAILABLE_ATTEMPTS);
        assert_eq!(
            fake.book.lock().unwrap().list(Duration::from_secs(5))[0].state,
            EnrollmentState::AwaitingJoin {}
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_provider_busy_until_the_deadline_is_provider_busy() {
        let (mut fake, code, _) = setup(0);
        fake.busy = usize::MAX;
        let started = tokio::time::Instant::now();
        let result = join_agent(
            &mut fake,
            &mut human(),
            InvitationCode::parse(&code).unwrap(),
            &SigningKey::from_bytes(&[4; 32]),
            Some(started + Duration::from_secs(5)),
        )
        .await;
        assert_eq!(result, Err(JoinFailure::ProviderBusy));
        assert!(fake.sent.len() > 2);
        assert!(started.elapsed() <= Duration::from_secs(5));
    }

    /// Without `--timeout-seconds` the joiner waits for the session's own
    /// expiry plus the grace, not the longest possible invitation.
    #[tokio::test(start_paused = true)]
    async fn without_a_deadline_the_joiner_stops_at_the_session_expiry_and_grace() {
        let (mut fake, code, _) = setup(0);
        let started = tokio::time::Instant::now();
        let result = join_agent(
            &mut fake,
            &mut human(),
            InvitationCode::parse(&code).unwrap(),
            &SigningKey::from_bytes(&[4; 32]),
            None,
        )
        .await;
        assert_eq!(result, Err(JoinFailure::TimedOut), "never approved");
        // The fake provider answers at t=5 s for a 600 s invitation issued
        // at t=1 s: 596 s left, plus the 5 s grace.
        let limit = Duration::from_secs(596) + EXPIRY_GRACE;
        let waited = started.elapsed();
        assert!(
            waited <= limit && waited + POLL_INTERVAL >= limit,
            "{waited:?}"
        );
    }

    #[test]
    fn an_unknown_invitation_explains_the_possible_causes() {
        let message = JoinFailure::rejected(EnrollmentRejection::InvalidInvitation).to_string();
        for cause in ["cancelled", "expired", "restarted", "invalid_invitation"] {
            assert!(message.contains(cause), "{message}");
        }
    }
}
