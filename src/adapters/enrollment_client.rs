//! Agent-side guided enrollment driver (#59 phase 1): creates the agent key,
//! joins, asks the joining human, then confirms until the provider commits.
//! I/O is injected so the whole journey is testable without a terminal.

use crate::access::enrollment::{
    EnrolledIdentity, EnrollmentRejection, EnrollmentState, JoinerCancelReason,
    joiner::{InvitationCode, JoinAttempt, JoinedSession, JoinerError},
    wire::{EnrollmentReply, EnrollmentRequest},
};
use ed25519_dalek::SigningKey;
use std::{io::Write, os::unix::fs::OpenOptionsExt, path::Path, time::Duration};
use zeroize::Zeroizing;

/// Identical join retransmissions after a transport failure.
const JOIN_ATTEMPTS: usize = 3;
const POLL_INTERVAL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum JoinFailure {
    #[error("{0}")]
    Joiner(JoinerError),
    #[error("the provider is unreachable")]
    ProviderOffline,
    #[error("the comparison codes did not match; enrollment cancelled")]
    Declined,
    #[error("the provider rejected the request: {0}")]
    Rejected(EnrollmentRejection),
    #[error("enrollment ended without enrolling: {0:?}")]
    Ended(EnrollmentState),
    #[error("timed out waiting for the provider's approval")]
    TimedOut,
    #[error("local key file unavailable")]
    LocalKey,
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

/// Run the joiner protocol until enrolled, a final state, or `deadline`.
pub async fn join_agent(
    transport: &mut impl EnrollmentTransport,
    prompt: &mut impl JoinerPrompt,
    code: InvitationCode,
    key: &SigningKey,
    deadline: tokio::time::Instant,
) -> Result<EnrolledIdentity, JoinFailure> {
    let mut nonce = [0u8; 32];
    getrandom::fill(&mut nonce).map_err(|_error| JoinFailure::LocalKey)?;
    let attempt = JoinAttempt::agent(code, key, nonce);
    let mut reply = Err(());
    for _ in 0..JOIN_ATTEMPTS {
        reply = transport.send(attempt.request()).await;
        if reply.is_ok() {
            break;
        }
    }
    let reply = reply.map_err(|()| JoinFailure::ProviderOffline)?;
    let session = attempt.accept(&reply).map_err(JoinFailure::Joiner)?;
    if !prompt.confirm(&session) {
        let _ignored = transport
            .send(&session.cancel(JoinerCancelReason::CodeMismatch))
            .await;
        return Err(JoinFailure::Declined);
    }
    let confirm = session.confirm(Some(key));
    let mut last = None;
    loop {
        match transport.send(&confirm).await {
            Ok(EnrollmentReply::State {
                state: EnrollmentState::Enrolled { identity },
                ..
            }) => return Ok(identity),
            Ok(EnrollmentReply::State { state, .. }) if state.is_final() => {
                return Err(JoinFailure::Ended(state));
            }
            Ok(EnrollmentReply::State { state, .. }) => {
                if last.as_ref() != Some(&state) {
                    prompt.waiting(&state);
                    last = Some(state);
                }
            }
            Ok(EnrollmentReply::Rejected { reason, .. }) => {
                return Err(JoinFailure::Rejected(reason));
            }
            Ok(EnrollmentReply::Joined { .. }) => {
                return Err(JoinFailure::Joiner(JoinerError::UnexpectedReply));
            }
            // Offline provider: keep the same confirmation until the deadline.
            Err(()) => {}
        }
        if tokio::time::Instant::now() + POLL_INTERVAL >= deadline {
            return Err(JoinFailure::TimedOut);
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// A fresh Ed25519 seed in a new agent-owned `0600` file (never replaced).
/// This is the `vw-access submit --key-file` format: exactly 32 raw bytes.
pub fn create_agent_key(path: &Path) -> Result<SigningKey, JoinFailure> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_error| JoinFailure::LocalKey)?;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_error| JoinFailure::LocalKey)?;
    if file
        .write_all(seed.as_ref())
        .and_then(|()| file.sync_all())
        .is_err()
    {
        let _ignored = std::fs::remove_file(path);
        return Err(JoinFailure::LocalKey);
    }
    Ok(SigningKey::from_bytes(&seed))
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

    struct Commit;
    impl EnrollmentHooks for Commit {
        fn admissible(&mut self, _: &EnrolleeKind, _: &Joiner) -> bool {
            true
        }
        fn commit(
            &mut self,
            _: &EnrolleeKind,
            joiner: &Joiner,
            _: u32,
        ) -> Result<EnrolledIdentity, FailureReason> {
            Ok(EnrolledIdentity::Agent {
                binding_id: "id".into(),
                fingerprint: joiner.fingerprint.clone(),
            })
        }
    }
    type ProviderAction = Box<dyn FnOnce(&mut Book)>;
    /// The provider in memory; `offline` drops that many messages first,
    /// `on_confirm` runs the provider human's action at the first confirm.
    struct Fake {
        book: Arc<Mutex<Book>>,
        offline: usize,
        on_confirm: Option<ProviderAction>,
        sent: Vec<EnrollmentRequest>,
    }
    impl EnrollmentTransport for Fake {
        async fn send(&mut self, request: &EnrollmentRequest) -> Result<EnrollmentReply, ()> {
            self.sent.push(request.clone());
            if self.offline > 0 {
                self.offline -= 1;
                return Err(());
            }
            let mut book = self.book.lock().unwrap();
            if matches!(request, EnrollmentRequest::EnrollConfirm { .. })
                && let Some(action) = self.on_confirm.take()
            {
                action(&mut book);
            }
            let peer = Peer::Agent {
                uid: 4100,
                groups: vec![4200],
            };
            Ok(book.handle(
                &peer,
                &[],
                request,
                Duration::from_secs(5),
                [3; 32],
                &mut Commit,
            ))
        }
    }
    struct Human {
        answer: bool,
        seen: Vec<String>,
    }
    impl JoinerPrompt for Human {
        fn confirm(&mut self, session: &JoinedSession) -> bool {
            self.seen.push(session.comparison_code.clone());
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
                on_confirm: None,
                sent: Vec::new(),
            },
            issued.invitation_code.clone(),
            id,
        )
    }
    fn deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + Duration::from_millis(1500)
    }

    #[tokio::test]
    async fn agent_enrolls_after_retrying_a_lost_join_and_approval_by_the_provider_human() {
        let (mut fake, code, id) = setup(1);
        let book = fake.book.clone();
        fake.on_confirm = Some(Box::new(move |book: &mut Book| {
            let view = book.list(Duration::from_secs(5)).pop().unwrap();
            book.approve(
                &id,
                view.comparison_code.as_deref().unwrap(),
                501,
                Duration::from_secs(5),
            )
            .unwrap();
        }));
        let mut human = Human {
            answer: true,
            seen: Vec::new(),
        };
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
        assert_eq!(human.seen.len(), 1);
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
            seen: Vec::new(),
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
            seen: Vec::new(),
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

    #[test]
    fn agent_key_files_are_new_private_and_never_replaced() {
        use std::os::unix::fs::MetadataExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("agent.key");
        let key = create_agent_key(&path).unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.mode() & 0o7777, 0o600);
        assert_eq!(std::fs::read(&path).unwrap(), key.to_bytes());
        assert_eq!(create_agent_key(&path).err(), Some(JoinFailure::LocalKey));
        assert_eq!(std::fs::read(&path).unwrap(), key.to_bytes());
    }
}
