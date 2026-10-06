//! Client-only observation deadlines. These never change provider lifecycle.
use std::{future::Future, time::Duration};

use serde::Serialize;
use tokio::{
    signal::unix::{Signal, SignalKind, signal},
    time::Instant,
};

use crate::access::protocol::{AgentRejection, AgentResponse, AgentStatus};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientError {
    LocalFailure,
    TransportUncertain,
    WaitTimeout,
    Interrupted,
    Terminated,
}
impl ClientError {
    pub fn exit_code(self) -> u8 {
        match self {
            Self::LocalFailure => 1,
            Self::TransportUncertain => 3,
            Self::WaitTimeout => 4,
            Self::Interrupted => 130,
            Self::Terminated => 143,
        }
    }
}

/// Install before a wait-mode submission, so interruption cannot lose an already
/// printed receipt or fall through into the platform's default signal handler.
pub struct WaitSignals {
    interrupt: Signal,
    terminate: Signal,
}
impl WaitSignals {
    pub fn arm() -> Result<Self, ClientError> {
        Ok(Self {
            interrupt: signal(SignalKind::interrupt())
                .map_err(|_error| ClientError::LocalFailure)?,
            terminate: signal(SignalKind::terminate())
                .map_err(|_error| ClientError::LocalFailure)?,
        })
    }
    pub async fn cancelled(&mut self) -> ClientError {
        tokio::select! {
            _ = self.interrupt.recv() => ClientError::Interrupted,
            _ = self.terminate.recv() => ClientError::Terminated,
        }
    }
}

/// One absolute monotonic deadline bounds both network exchanges and sleeps.
/// Cancellation is polled first, even when an exchange is immediately ready.
pub async fn bounded<T>(
    deadline: Instant,
    cancellation: impl Future<Output = ClientError>,
    work: impl Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    tokio::select! {
        biased;
        error = cancellation => Err(error),
        _ = tokio::time::sleep_until(deadline) => Err(ClientError::WaitTimeout),
        result = work => result,
    }
}

/// Production composition boundary: a single budget includes submission,
/// flushed receipt, observations and backoff. Keep the receipt ID even if its
/// output is interrupted. A reconnect can only query that already accepted ID.
pub async fn observe<S, Q, F, E>(
    deadline: Option<Instant>,
    cancellation: impl Future<Output = ClientError>,
    submission: Option<S>,
    known_id: &mut Option<String>,
    mut query: Q,
    mut emit: impl FnMut(AgentResponse) -> E,
) -> Result<u8, ClientError>
where
    S: Future<Output = Result<AgentResponse, ClientError>>,
    Q: FnMut(String) -> F,
    F: Future<Output = Result<AgentResponse, ClientError>>,
    E: Future<Output = Result<(), ClientError>>,
{
    let work = async {
        if let Some(submission) = submission {
            let response = submission.await?;
            if let AgentResponse::Pending { request_id, .. } = &response {
                *known_id = Some(request_id.clone());
            }
            let accepted = matches!(response, AgentResponse::Pending { .. });
            emit(response).await?;
            if !accepted {
                return Ok(1);
            }
            if deadline.is_none() {
                return Ok(0);
            }
        }
        let id = known_id.as_ref().ok_or(ClientError::LocalFailure)?;
        if deadline.is_some() {
            wait(|| query(id.clone()), emit).await
        } else {
            let response = query(id.clone()).await?;
            let code = observation_exit(&response);
            emit(response).await?;
            Ok(code)
        }
    };
    match deadline {
        Some(deadline) => bounded(deadline, cancellation, work).await,
        None => work.await,
    }
}

/// Writes through an owned descriptor on a dedicated OS thread, without the
/// global stdout lock or Tokio's blocking pool. Dropping the awaiter detaches
/// this one outstanding write; runtime/process shutdown never joins it.
/// File descriptors are duplicated without changing their shared flags.
pub async fn output(response: AgentResponse) -> Result<(), ClientError> {
    use std::{fs::File, io::Write};
    let mut bytes = serde_json::to_vec(&response).map_err(|_error| ClientError::LocalFailure)?;
    bytes.push(b'\n');
    let descriptor = duplicate_descriptor(libc::STDOUT_FILENO)?;
    let (sent, received) = tokio::sync::oneshot::channel();
    std::thread::Builder::new()
        .name("agent-output".into())
        .spawn(move || {
            let mut file = File::from(descriptor);
            let result = file
                .write_all(&bytes)
                .and_then(|()| file.flush())
                .map_err(|_error| ClientError::LocalFailure);
            let _ignored = sent.send(result);
        })
        .map_err(|_error| ClientError::LocalFailure)?;
    received.await.map_err(|_error| ClientError::LocalFailure)?
}

/// A blocked diagnostic sink must not turn timeout or signal exit into a hang.
/// Give an ordinary stderr a short opportunity to receive the closed diagnostic.
pub fn diagnostic(bytes: Vec<u8>) {
    use std::{fs::File, io::Write};
    let Ok(descriptor) = duplicate_descriptor(libc::STDERR_FILENO) else {
        return;
    };
    let (sent, received) = std::sync::mpsc::sync_channel(1);
    if std::thread::Builder::new()
        .name("agent-diagnostic".into())
        .spawn(move || {
            let mut file = File::from(descriptor);
            let _ignored = file.write_all(&bytes).and_then(|()| file.flush());
            let _ignored = sent.send(());
        })
        .is_ok()
    {
        let _ignored = received.recv_timeout(Duration::from_millis(50));
    }
}

fn duplicate_descriptor(fd: libc::c_int) -> Result<std::os::fd::OwnedFd, ClientError> {
    use std::os::fd::FromRawFd;
    // SAFETY: fcntl validates even a closed descriptor; success returns a new,
    // exclusively owned descriptor, which OwnedFd closes exactly once.
    let duplicate = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if duplicate < 0 {
        return Err(ClientError::LocalFailure);
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(duplicate) })
}

pub fn observation_exit(response: &AgentResponse) -> u8 {
    match response {
        AgentResponse::Pending { .. } => 0,
        AgentResponse::Status { state, .. } => match state {
            AgentStatus::Denied | AgentStatus::Expired | AgentStatus::Failed { .. } => 1,
            _ => 0,
        },
        AgentResponse::Rejected { .. } => 1,
    }
}

/// The caller supplies a fresh authenticated observation for every call.
/// Busy is transient admission pressure, not a lifecycle transition.
pub async fn wait<Q, F, E>(
    mut query: Q,
    mut emit: impl FnMut(AgentResponse) -> E,
) -> Result<u8, ClientError>
where
    Q: FnMut() -> F,
    F: Future<Output = Result<AgentResponse, ClientError>>,
    E: Future<Output = Result<(), ClientError>>,
{
    let mut previous = None;
    let mut delay = Duration::from_millis(100);
    loop {
        let response = query().await?;
        match &response {
            AgentResponse::Status { state, .. } => {
                if previous.as_ref() != Some(state) {
                    emit(response.clone()).await?;
                    previous = Some(state.clone());
                }
                if state.is_terminal() {
                    return Ok(observation_exit(&response));
                }
            }
            AgentResponse::Rejected {
                category: AgentRejection::Busy,
                ..
            } => {}
            AgentResponse::Rejected { .. } => {
                emit(response.clone()).await?;
                return Ok(1);
            }
            AgentResponse::Pending { .. } => return Err(ClientError::TransportUncertain),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access::protocol::AgentFailure;
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    fn status(state: AgentStatus) -> AgentResponse {
        AgentResponse::Status {
            protocol_version: 1,
            request_id: "id".into(),
            state,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn busy_then_running_then_terminal_and_backoff_cap() {
        let states = Rc::new(RefCell::new(VecDeque::from([
            AgentResponse::rejected(AgentRejection::Busy),
            status(AgentStatus::Running),
            status(AgentStatus::Running),
            status(AgentStatus::Running),
            status(AgentStatus::Running),
            status(AgentStatus::Running),
            status(AgentStatus::Completed { exit_code: 17 }),
        ])));
        let start = Instant::now();
        let times = RefCell::new(Vec::new());
        let mut emitted = Vec::new();
        assert_eq!(
            wait(
                || {
                    times.borrow_mut().push(Instant::now() - start);
                    let value = states.borrow_mut().pop_front().unwrap();
                    async move { Ok(value) }
                },
                |response| {
                    emitted.push(response);
                    std::future::ready(Ok(()))
                }
            )
            .await,
            Ok(0)
        );
        assert_eq!(
            times.into_inner(),
            [0, 100, 300, 700, 1500, 2500, 3500].map(Duration::from_millis)
        );
        assert_eq!(
            emitted,
            [
                status(AgentStatus::Running),
                status(AgentStatus::Completed { exit_code: 17 })
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_clips_sleep_and_inflight_exchange() {
        for blocked_exchange in [false, true] {
            let start = Instant::now();
            let deadline = start + Duration::from_millis(50);
            let result = bounded(
                deadline,
                std::future::pending(),
                wait(
                    || async {
                        if blocked_exchange {
                            std::future::pending::<()>().await;
                        }
                        Ok(status(AgentStatus::Pending))
                    },
                    |_response| std::future::ready(Ok(())),
                ),
            )
            .await;
            assert_eq!(result, Err(ClientError::WaitTimeout));
            assert_eq!(Instant::now() - start, Duration::from_millis(50));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn every_terminal_and_rejection_stops_without_sleep_or_retry() {
        for state in [
            AgentStatus::Denied,
            AgentStatus::Expired,
            AgentStatus::Completed { exit_code: 0 },
            AgentStatus::Completed { exit_code: 255 },
            AgentStatus::Failed {
                category: AgentFailure::ReviewUnavailable,
            },
            AgentStatus::Failed {
                category: AgentFailure::ExecutionUnavailable,
            },
            AgentStatus::Failed {
                category: AgentFailure::ExecutionRejected,
            },
            AgentStatus::Failed {
                category: AgentFailure::ExecutionNonzero,
            },
            AgentStatus::Failed {
                category: AgentFailure::ExecutionSignaled,
            },
        ] {
            let expected = if matches!(state, AgentStatus::Completed { .. }) {
                0
            } else {
                1
            };
            let start = Instant::now();
            let mut calls = 0;
            assert_eq!(
                wait(
                    || {
                        calls += 1;
                        let response = status(state.clone());
                        async move { Ok(response) }
                    },
                    |_response| std::future::ready(Ok(()))
                )
                .await,
                Ok(expected)
            );
            assert_eq!(calls, 1);
            assert_eq!(Instant::now(), start);
        }
        let mut calls = 0;
        assert_eq!(
            wait(
                || {
                    calls += 1;
                    async { Ok(AgentResponse::rejected(AgentRejection::Unauthorized)) }
                },
                |_response| std::future::ready(Ok(()))
            )
            .await,
            Ok(1)
        );
        assert_eq!(calls, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn interruption_and_transport_uncertainty_never_become_lifecycle() {
        for error in [ClientError::Interrupted, ClientError::Terminated] {
            assert_eq!(
                bounded(
                    Instant::now() + Duration::from_secs(300),
                    async { error },
                    async { Ok(()) }
                )
                .await,
                Err(error)
            );
        }
        assert_eq!(
            wait(
                || async { Err(ClientError::TransportUncertain) },
                |_response| std::future::ready(Err(ClientError::LocalFailure))
            )
            .await,
            Err(ClientError::TransportUncertain)
        );
    }
    #[tokio::test(start_paused = true)]
    async fn submission_receipt_and_observation_share_one_deadline() {
        for blocked_receipt in [false, true] {
            let start = Instant::now();
            let mut known_id = None;
            let emitted = RefCell::new(Vec::new());
            let queries = std::cell::Cell::new(0);
            let result = observe(
                Some(start + Duration::from_secs(1)),
                std::future::pending(),
                Some(async {
                    tokio::time::sleep(Duration::from_millis(700)).await;
                    Ok(AgentResponse::Pending {
                        protocol_version: 1,
                        request_id: "accepted".into(),
                    })
                }),
                &mut known_id,
                |_id| {
                    queries.set(queries.get() + 1);
                    async { std::future::pending().await }
                },
                |response| {
                    emitted.borrow_mut().push(response);
                    async move {
                        if blocked_receipt {
                            std::future::pending::<()>().await;
                        }
                        Ok(())
                    }
                },
            )
            .await;
            assert_eq!(result, Err(ClientError::WaitTimeout));
            assert_eq!(Instant::now() - start, Duration::from_secs(1));
            assert_eq!(known_id.as_deref(), Some("accepted"));
            assert_eq!(emitted.borrow().len(), 1);
            assert_eq!(queries.get(), usize::from(!blocked_receipt));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_interrupts_pending_state_output() {
        for error in [ClientError::Interrupted, ClientError::Terminated] {
            let start = Instant::now();
            let result = bounded(
                start + Duration::from_secs(300),
                async {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    error
                },
                wait(
                    || async { Ok(status(AgentStatus::Running)) },
                    |_response| std::future::pending(),
                ),
            )
            .await;
            assert_eq!(result, Err(error));
            assert_eq!(Instant::now() - start, Duration::from_millis(20));
        }
    }
}
