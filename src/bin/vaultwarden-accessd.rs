use clap::Parser;
use std::{
    path::PathBuf,
    process::ExitCode,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use vaultwarden_cli::{
    access::{application::ProviderApplication, provider::Provider},
    adapters::{
        loopback_ui::LoopbackUi,
        session::{MonotonicClock, clear_persisted_session},
        vaultwarden::VaultwardenBackend,
    },
};

#[derive(Debug, Parser)]
#[command(name = "vaultwarden-accessd")]
struct Args {
    /// Provider-owned directory for lifecycle state.
    #[arg(long, env = "VAULTWARDEN_ACCESS_STATE_ROOT")]
    state_root: PathBuf,
    /// Provider-owned setup JSON; contains no reusable session or password.
    #[arg(long)]
    backend_config: Option<PathBuf>,
    /// Provider-owned PEM certificate chain trusted by the human's browser.
    #[arg(long, requires = "ui_tls_key", requires = "backend_config")]
    ui_tls_cert: Option<PathBuf>,
    /// Provider-owned, unencrypted PEM private key for the loopback HTTPS identity.
    #[arg(long, requires = "ui_tls_cert", requires = "backend_config")]
    ui_tls_key: Option<PathBuf>,
}
fn main() -> ExitCode {
    let args = Args::parse();
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(()) => {
            eprintln!("vaultwarden-accessd: provider unavailable");
            ExitCode::FAILURE
        }
    }
}
fn run(args: Args) -> Result<(), ()> {
    let runtime = tokio::runtime::Runtime::new().map_err(|_| ())?;
    let (mut interrupt, mut term) = runtime.block_on(async {
        use tokio::signal::unix::{SignalKind, signal};
        Ok::<_, ()>((
            signal(SignalKind::interrupt()).map_err(|_| ())?,
            signal(SignalKind::terminate()).map_err(|_| ())?,
        ))
    })?;
    let mut provider = initialize_provider(&args.state_root, clear_persisted_session)?;
    let Some(config) = args.backend_config else {
        // Preserve locked-only installations until human provisioning is complete.
        runtime.block_on(async {
            tokio::select! { _ = interrupt.recv() => {}, _ = term.recv() => {} }
        });
        return provider.shutdown().map_err(|_| ());
    };
    // Blocking HTTP construction and destruction stay outside the async runtime.
    let backend = VaultwardenBackend::from_setup(&config).map_err(|_| ())?;
    let app = Arc::new(
        ProviderApplication::new(
            provider,
            Box::new(backend),
            Box::<MonotonicClock>::default(),
        )
        .map_err(|_| ())?,
    );
    let artifact = args.state_root.join("open-vaultwarden-access.html");
    let ui = LoopbackUi::bind(
        &artifact,
        args.ui_tls_cert.as_deref().ok_or(())?,
        args.ui_tls_key.as_deref().ok_or(())?,
    )
    .map_err(|_| ())?;
    let stop = Arc::new(AtomicBool::new(false));
    let worker = {
        let app = app.clone();
        let stop = stop.clone();
        std::thread::spawn(move || ui.serve(app, stop))
    };
    runtime.block_on(monitor_shutdown(
        app.clone(),
        async {
            tokio::select! { _ = interrupt.recv() => {}, _ = term.recv() => {} }
        },
        || worker.is_finished(),
    ));
    stop.store(true, Ordering::Release);
    // Never short-circuit joining or final revocation on a worker error.
    let cleanup = join_then_revoke(worker, || {
        let memory = app.shutdown().map_err(|_| ());
        let persisted = clear_persisted_session().map_err(|_| ());
        memory.and(persisted)
    });
    let artifact_cleanup = std::fs::remove_file(artifact).map_err(|_| ());
    cleanup.and(artifact_cleanup)
}

/// Signal reception stays on the async driver; gate-taking status runs elsewhere.
async fn monitor_shutdown(
    app: Arc<ProviderApplication>,
    signal: impl std::future::Future<Output = ()>,
    worker_finished: impl Fn() -> bool,
) {
    tokio::pin!(signal);
    loop {
        tokio::select! {
            _ = &mut signal => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                if worker_finished() { break; }
                let status_app = app.clone();
                let status = tokio::task::spawn_blocking(move || status_app.status());
                tokio::select! {
                    _ = &mut signal => break,
                    result = status => if !matches!(result, Ok(Ok(_))) { break; },
                }
            }
        }
    }
    app.close_admission();
}

fn join_then_revoke(
    worker: std::thread::JoinHandle<Result<(), vaultwarden_cli::access::ports::SessionError>>,
    revoke: impl FnOnce() -> Result<(), ()>,
) -> Result<(), ()> {
    let serving = worker
        .join()
        .map_err(|_| ())
        .and_then(|result| result.map_err(|_| ()));
    let cleanup = revoke();
    cleanup.and(serving)
}

fn initialize_provider(
    root: &std::path::Path,
    clear: impl FnOnce() -> Result<(), vaultwarden_cli::access::ports::SessionError>,
) -> Result<Provider, ()> {
    Provider::start_with_cleanup(root, || {
        let keyring = clear().map_err(|_| ());
        let launch = clear_previous_launch(&root.join("open-vaultwarden-access.html"));
        keyring.and(launch)
    })
    .map_err(|_| ())
}

fn clear_previous_launch(path: &std::path::Path) -> Result<(), ()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn startup_cleans_before_corrupt_missing_or_unsafe_state_and_preserves_competing_owner() {
        use std::os::unix::fs::PermissionsExt;
        for problem in ["corrupt", "missing", "unsafe"] {
            let dir = tempfile::tempdir().unwrap();
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
            let root = dir.path().join("provider");
            let provider = initialize_provider(&root, || Ok(())).unwrap();
            let state = root.join("provider-state.json");
            let artifact = root.join("open-vaultwarden-access.html");
            std::fs::write(&artifact, "stale-launch-capability").unwrap();
            let cleared = AtomicBool::new(false);
            assert!(
                initialize_provider(&root, || {
                    cleared.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
            );
            assert!(!cleared.load(Ordering::Acquire));
            assert!(artifact.exists());
            drop(provider);
            match problem {
                "corrupt" => std::fs::write(&state, "malformed state").unwrap(),
                "missing" => std::fs::remove_file(&state).unwrap(),
                _ => std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o644))
                    .unwrap(),
            }
            assert!(
                initialize_provider(&root, || {
                    cleared.store(true, Ordering::Release);
                    Ok(())
                })
                .is_err()
            );
            assert!(cleared.load(Ordering::Acquire));
            assert!(!artifact.exists());
        }
    }

    #[test]
    fn no_config_startup_removes_stale_launch_even_when_keyring_cleanup_fails() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.path().join("provider");
        drop(Provider::start(&root).unwrap());
        let artifact = root.join("open-vaultwarden-access.html");
        for succeeds in [true, false] {
            std::fs::write(&artifact, "old launch").unwrap();
            let result = initialize_provider(&root, || {
                if succeeds {
                    Ok(())
                } else {
                    Err(vaultwarden_cli::access::ports::SessionError::CleanupFailed)
                }
            });
            assert_eq!(result.is_ok(), succeeds);
            assert!(!artifact.exists());
        }
    }

    #[test]
    fn signal_driver_closes_admission_while_status_waits_on_delayed_unlock() {
        use std::sync::mpsc;
        use vaultwarden_cli::access::ports::*;
        struct DelayedBackend(mpsc::Sender<()>, mpsc::Receiver<()>);
        impl ProviderSession for DelayedBackend {
            fn probe_compatibility(&mut self) -> Result<(), SessionError> {
                Ok(())
            }
            fn unlock(&mut self, _: SensitiveString) -> Result<Duration, SessionError> {
                self.0.send(()).unwrap();
                self.1
                    .recv_timeout(Duration::from_secs(5))
                    .map_err(|_| SessionError::BackendUnavailable)?;
                Ok(Duration::from_secs(900))
            }
            fn clear(&mut self) -> Result<(), SessionError> {
                Ok(())
            }
        }
        impl SecretBackend for DelayedBackend {
            fn eligible(&mut self, _: &CredentialBinding<'_>) -> Result<bool, SessionError> {
                panic!("unused")
            }
            fn resolve(
                &mut self,
                _: &CredentialBinding<'_>,
            ) -> Result<Vec<SensitiveString>, SessionError> {
                panic!("unused")
            }
        }
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let (entered_tx, entered_rx) = mpsc::channel();
        let (resume_tx, resume_rx) = mpsc::channel();
        let app = Arc::new(
            ProviderApplication::new(
                Provider::start(dir.path().join("provider")).unwrap(),
                Box::new(DelayedBackend(entered_tx, resume_rx)),
                Box::<MonotonicClock>::default(),
            )
            .unwrap(),
        );
        let pending = {
            let app = app.clone();
            std::thread::spawn(move || app.authenticate(SensitiveString::new("synthetic".into())))
        };
        entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let (signal_tx, signal_rx) = tokio::sync::oneshot::channel();
        let (poll_tx, poll_rx) = tokio::sync::oneshot::channel();
        let poll_tx = std::sync::Mutex::new(Some(poll_tx));
        let observed = runtime.block_on(async {
            let monitor = monitor_shutdown(
                app.clone(),
                async {
                    let _ = signal_rx.await;
                },
                || {
                    if let Some(tx) = poll_tx.lock().unwrap().take() {
                        let _ = tx.send(());
                    }
                    false
                },
            );
            let signal = async {
                poll_rx.await.unwrap();
                signal_tx.send(()).unwrap();
            };
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::join!(monitor, signal);
            })
            .await
        });
        // Always release the backend, even if a regression delayed the signal.
        resume_tx.send(()).unwrap();
        let outcome = pending.join().unwrap();
        assert!(observed.is_ok());
        assert_eq!(outcome, Err(SessionError::Locked));
        assert_eq!(
            app.authenticate(SensitiveString::new("later".into())),
            Err(SessionError::Locked)
        );
        app.shutdown().unwrap();
    }

    #[test]
    fn worker_success_error_and_panic_all_join_before_final_revocation() {
        for outcome in 0..3 {
            let usable = Arc::new(AtomicBool::new(false));
            let worker = {
                let usable = usable.clone();
                std::thread::spawn(move || {
                    // Represents an already-admitted unlock finishing at shutdown.
                    usable.store(true, Ordering::Release);
                    match outcome {
                        0 => Ok(()),
                        1 => Err(vaultwarden_cli::access::ports::SessionError::BackendUnavailable),
                        _ => panic!("synthetic worker failure"),
                    }
                })
            };
            let result = join_then_revoke(worker, || {
                assert!(usable.load(Ordering::Acquire));
                usable.store(false, Ordering::Release);
                Ok(())
            });
            assert_eq!(result.is_ok(), outcome == 0);
            assert!(!usable.load(Ordering::Acquire));
        }
        let worker = std::thread::spawn(|| Ok(()));
        assert_eq!(join_then_revoke(worker, || Err(())), Err(()));
    }

    #[test]
    fn no_config_startup_clears_injected_keyring_and_cleanup_error_blocks_start() {
        use vaultwarden_cli::adapters::session::{
            BOOTSTRAP_ACCOUNT, KEYRING_SERVICE, SESSION_ACCOUNT,
        };
        keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
        let session = keyring_core::Entry::new(KEYRING_SERVICE, SESSION_ACCOUNT).unwrap();
        let bootstrap = keyring_core::Entry::new(KEYRING_SERVICE, BOOTSTRAP_ACCOUNT).unwrap();
        session.set_password("stale-session-sentinel").unwrap();
        bootstrap.set_password("bootstrap-sentinel").unwrap();
        let dir = tempfile::tempdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let root = dir.path().join("provider");
        let args =
            Args::try_parse_from(["accessd", "--state-root", root.to_str().unwrap()]).unwrap();
        assert!(args.backend_config.is_none());
        let mut provider = initialize_provider(&args.state_root, clear_persisted_session).unwrap();
        assert!(matches!(
            session.get_password(),
            Err(keyring_core::Error::NoEntry)
        ));
        assert_eq!(bootstrap.get_password().unwrap(), "bootstrap-sentinel");
        assert_eq!(
            provider.lock_state(),
            vaultwarden_cli::access::provider::ProviderLockState::Locked
        );
        provider.shutdown().unwrap();
        drop(provider);
        assert!(
            initialize_provider(&dir.path().join("blocked"), || Err(
                vaultwarden_cli::access::ports::SessionError::CleanupFailed
            ))
            .is_err()
        );
        assert!(dir.path().join("blocked/provider-state.json").exists());
        let _active = initialize_provider(&args.state_root, clear_persisted_session).unwrap();
        let called = AtomicBool::new(false);
        assert!(
            initialize_provider(&args.state_root, || {
                called.store(true, Ordering::Release);
                Ok(())
            })
            .is_err()
        );
        assert!(!called.load(Ordering::Acquire));
        keyring_core::unset_default_store();
    }

    #[test]
    fn launch_cleanup_accepts_absence_removes_old_capability_and_rejects_failure() {
        let dir = tempfile::tempdir().unwrap();
        let artifact = dir.path().join("launch.html");
        assert_eq!(clear_previous_launch(&artifact), Ok(()));
        std::fs::write(&artifact, "stale-launch-capability").unwrap();
        assert_eq!(clear_previous_launch(&artifact), Ok(()));
        assert!(!artifact.exists());
        std::fs::create_dir(&artifact).unwrap();
        assert_eq!(clear_previous_launch(&artifact), Err(()));
        assert!(artifact.is_dir());
    }
}
