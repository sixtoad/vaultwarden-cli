//! Human terminal client. Outputs contain only provider-owned receipts and states.
#[cfg(target_os = "linux")]
use clap::{Parser, Subcommand, error::ErrorKind};
#[cfg(target_os = "linux")]
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
#[cfg(target_os = "linux")]
use vaultwarden_cli::{
    access::{
        agent_binding::AgentPairing,
        direct_request::DirectSubmission,
        policy::{ExecutionProfile, ImageRegistration, OperationPolicyDraft},
        provisioning::MAX_POLICY_BYTES,
    },
    adapters::human_socket::{HumanCommand, HumanResponse, exchange},
};

#[cfg(target_os = "linux")]
#[derive(Parser)]
#[command(
    name = "vw-access",
    version,
    about = "Submit a one-time human request for desktop review"
)]
struct Args {
    /// Private provider directory, also accepted from VAULTWARDEN_ACCESS_STATE_ROOT.
    #[arg(long, env = "VAULTWARDEN_ACCESS_STATE_ROOT")]
    state_root: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum Command {
    /// Register or inspect provider-owned executable images.
    Image {
        #[command(subcommand)]
        command: ImageCommand,
    },
    /// Create or inspect protected operation policies.
    Operation {
        #[command(subcommand)]
        command: OperationCommand,
    },
    /// Submit a signed agent request without a terminal or provider-state access.
    Submit {
        operation: String,
        #[arg(long)]
        socket: PathBuf,
        /// Agent-owned 0600 file containing exactly one raw 32-byte seed.
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        binding_id: String,
        #[arg(long)]
        revision: String,
        /// Observe the accepted request until terminal, without prompting.
        #[arg(long)]
        wait: bool,
        /// Monotonic client deadline in seconds (default 300; requires --wait).
        #[arg(long, requires = "wait", value_parser = parse_timeout_seconds)]
        timeout_seconds: Option<u64>,
        #[arg(last = true)]
        values: Vec<String>,
    },
    /// Observe a delegated request once using its immutable owner identity.
    Poll {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        binding_id: String,
    },
    /// Resume observing delegated work; never resubmits or cancels it.
    Wait {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        key_file: PathBuf,
        #[arg(long, allow_hyphen_values = true)]
        binding_id: String,
        /// Monotonic client deadline in seconds.
        #[arg(long, default_value_t = 300, value_parser = parse_timeout_seconds)]
        timeout_seconds: u64,
    },
    /// Submit and wait for a terminal status (approval is unavailable at this stage).
    Request {
        operation: String,
        /// Reject unless this digest is the currently active policy revision.
        #[arg(long)]
        revision: Option<String>,
        /// Print the receipt and return immediately after desktop handoff.
        #[arg(long)]
        no_wait: bool,
        /// Ordered policy values. Place these after --.
        #[arg(last = true)]
        values: Vec<String>,
    },
    /// Read a request's redacted status, including while the provider is locked.
    Status {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
    /// Read recent redacted lifecycle events, including while the provider is locked.
    History {
        /// Number of events (default 50; range 1–200).
        #[arg(long)]
        limit: Option<u32>,
    },
    /// Manage restricted agent identities, including while the vault is locked.
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
}
#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum AgentCommand {
    /// Pair a fresh Ed25519 public key with a restricted numeric OS identity.
    Pair {
        #[arg(allow_hyphen_values = true)]
        label: String,
        /// Canonical unpadded base64url Ed25519 public key (never a private key).
        #[arg(long, allow_hyphen_values = true)]
        public_key: String,
        /// Restricted UID, distinct from the provider UID.
        #[arg(long)]
        uid: u32,
        /// Required primary or supplementary group membership.
        #[arg(long)]
        gid: u32,
    },
    /// List immutable IDs, fingerprints, OS identities and enabled/revoked status.
    List,
    /// Revoke an immutable binding ID and wait for affected execution cleanup.
    Revoke {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
}
#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum ImageCommand {
    /// Declare behavioral review and verify an immutable executable without running it.
    Register {
        #[arg(long)]
        id: String,
        #[arg(long)]
        execution_root: String,
        #[arg(long)]
        path: String,
        #[arg(long)]
        sha256: String,
        #[arg(long, value_parser = ["reviewed_self_contained_elf64_v1"])]
        profile: String,
    },
    List,
    Show {
        id: String,
    },
}
#[cfg(target_os = "linux")]
#[derive(Subcommand)]
enum OperationCommand {
    /// Read a strict, bounded OperationPolicyDraft JSON file containing metadata only.
    Create {
        #[arg(long)]
        file: PathBuf,
    },
    List,
    Show {
        id: String,
    },
}

#[cfg(target_os = "linux")]
fn read_policy(path: &std::path::Path) -> Result<OperationPolicyDraft, String> {
    use std::{io::Read, os::unix::fs::OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_error| "invalid policy file")?;
    let metadata = file.metadata().map_err(|_error| "invalid policy file")?;
    if !metadata.is_file() || metadata.len() > MAX_POLICY_BYTES as u64 {
        return Err("invalid or oversized policy file".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_POLICY_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_error| "invalid policy file")?;
    if bytes.len() > MAX_POLICY_BYTES {
        return Err("invalid or oversized policy file".into());
    }
    serde_json::from_slice(&bytes).map_err(|_error| "invalid policy file".into())
}
#[cfg(target_os = "linux")]
fn main() -> ExitCode {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion
            ) =>
        {
            // DisplayHelp is the selected command's schema-generated help; all
            // actual parser diagnostics are redacted by the branch below.
            if error.kind() == ErrorKind::DisplayVersion {
                println!("vw-access {}", env!("CARGO_PKG_VERSION"));
            } else {
                let _ignored = error.print();
            }
            return ExitCode::SUCCESS;
        }
        Err(_) => {
            eprintln!("vw-access: invalid command; use --help");
            return ExitCode::from(2);
        }
    };
    if matches!(
        &args.command,
        Command::Submit { .. } | Command::Poll { .. } | Command::Wait { .. }
    ) {
        return ExitCode::from(run_agent(&args.command));
    }
    if args.state_root.is_none() {
        eprintln!("vw-access: invalid command; use --help");
        return ExitCode::from(2);
    }
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vw-access: {error}");
            ExitCode::FAILURE
        }
    }
}
#[cfg(target_os = "linux")]
fn parse_timeout_seconds(value: &str) -> Result<u64, &'static str> {
    let seconds = value.parse::<u64>().map_err(|_error| "invalid timeout")?;
    if seconds == 0
        || std::time::Instant::now()
            .checked_add(Duration::from_secs(seconds))
            .is_none()
    {
        return Err("invalid timeout");
    }
    Ok(seconds)
}
#[cfg(target_os = "linux")]
fn valid_agent_id(id: &str) -> bool {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD
        .decode(id)
        .is_ok_and(|bytes| bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == id)
}
#[cfg(target_os = "linux")]
fn run_agent(command: &Command) -> u8 {
    use vaultwarden_cli::{
        access::protocol::{SignedStatusQuery, SignedSubmission},
        adapters::{
            agent_wait::{self, ClientError, WaitSignals},
            unix_socket,
        },
    };
    let (socket, key_file, binding_id, timeout, mut known_id) = match command {
        Command::Submit {
            socket,
            key_file,
            binding_id,
            wait,
            timeout_seconds,
            ..
        } => (
            socket,
            key_file,
            binding_id,
            wait.then_some(timeout_seconds.unwrap_or(300)),
            None,
        ),
        Command::Poll {
            socket,
            key_file,
            binding_id,
            id,
        } => (socket, key_file, binding_id, None, Some(id.clone())),
        Command::Wait {
            socket,
            key_file,
            binding_id,
            id,
            timeout_seconds,
        } => (
            socket,
            key_file,
            binding_id,
            Some(*timeout_seconds),
            Some(id.clone()),
        ),
        _ => return 2,
    };
    // Only canonical IDs may be reflected in diagnostics, even on local failure.
    if !valid_agent_id(binding_id) || known_id.as_ref().is_some_and(|id| !valid_agent_id(id)) {
        eprintln!("vw-access: invalid command; use --help");
        return 2;
    }
    let result = (|| {
        let key =
            unix_socket::load_signing_key(key_file).map_err(|_error| ClientError::LocalFailure)?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_error| ClientError::LocalFailure)?;
        runtime.block_on(async {
            let mut signals = if timeout.is_some() {
                Some(WaitSignals::arm()?)
            } else {
                None
            };
            let deadline = timeout
                .map(|seconds| {
                    tokio::time::Instant::now()
                        .checked_add(Duration::from_secs(seconds))
                        .ok_or(ClientError::LocalFailure)
                })
                .transpose()?;
            let submission = if let Command::Submit {
                operation,
                revision,
                values,
                ..
            } = command
            {
                Some(async {
                    let mut nonce = [0; 32];
                    getrandom::fill(&mut nonce).map_err(|_error| ClientError::LocalFailure)?;
                    let input = SignedSubmission::sign(
                        binding_id.clone(),
                        nonce,
                        operation.clone(),
                        revision.clone(),
                        values.clone(),
                        &key,
                    )
                    .map_err(|_error| ClientError::LocalFailure)?;
                    unix_socket::exchange(socket, &input)
                        .await
                        .map_err(|_error| ClientError::TransportUncertain)
                })
            } else {
                None
            };
            let query = |id: String| {
                let key = &key;
                async move {
                    let mut nonce = [0; 32];
                    getrandom::fill(&mut nonce).map_err(|_error| ClientError::LocalFailure)?;
                    let input = SignedStatusQuery::sign(binding_id.clone(), nonce, id, key)
                        .map_err(|_error| ClientError::LocalFailure)?;
                    unix_socket::query_exchange(socket, &input)
                        .await
                        .map_err(|_error| ClientError::TransportUncertain)
                }
            };
            let cancellation = async {
                match signals.as_mut() {
                    Some(signals) => signals.cancelled().await,
                    None => std::future::pending().await,
                }
            };
            agent_wait::observe(
                deadline,
                cancellation,
                submission,
                &mut known_id,
                query,
                agent_wait::output,
            )
            .await
        })
    })();
    match result {
        Ok(code) => code,
        Err(error) => {
            #[derive(serde::Serialize)]
            struct Diagnostic<'a> {
                event: &'static str,
                category: ClientError,
                request_id: Option<&'a str>,
            }
            // All fields are closed values or validated opaque IDs.
            if let Ok(json) = serde_json::to_string(&Diagnostic {
                event: "client_error",
                category: error,
                request_id: known_id.as_deref(),
            }) {
                agent_wait::diagnostic(format!("{json}\n").into_bytes());
            }
            error.exit_code()
        }
    }
}
#[cfg(target_os = "linux")]
fn run(args: Args) -> Result<(), String> {
    let state_root = args.state_root.ok_or("provider state root required")?;
    let (command, wait) = match args.command {
        Command::Image { command } => (
            match command {
                ImageCommand::Register {
                    id,
                    execution_root,
                    path,
                    sha256,
                    profile: _,
                } => HumanCommand::ImageRegister {
                    image: ImageRegistration {
                        id,
                        execution_root,
                        path,
                        sha256,
                        profile: ExecutionProfile::ReviewedSelfContainedElf64V1,
                    },
                },
                ImageCommand::List => HumanCommand::ImageList {},
                ImageCommand::Show { id } => HumanCommand::ImageShow { id },
            },
            false,
        ),
        Command::Operation { command } => (
            match command {
                OperationCommand::Create { file } => HumanCommand::OperationCreate {
                    policy: Box::new(read_policy(&file)?),
                },
                OperationCommand::List => HumanCommand::OperationList {},
                OperationCommand::Show { id } => HumanCommand::OperationShow { id },
            },
            false,
        ),
        Command::Submit { .. } | Command::Poll { .. } | Command::Wait { .. } => {
            return Err("invalid command".into());
        }
        Command::Request {
            operation,
            revision,
            no_wait,
            values,
        } => (
            HumanCommand::Request {
                submission: DirectSubmission {
                    operation,
                    revision,
                    values,
                },
            },
            !no_wait,
        ),
        Command::Status { id } => (HumanCommand::Status { id }, false),
        Command::History { limit } => (HumanCommand::History { limit }, false),
        Command::Agent { command } => (
            match command {
                AgentCommand::Pair {
                    label,
                    public_key,
                    uid,
                    gid,
                } => HumanCommand::AgentPair {
                    pairing: AgentPairing {
                        label,
                        public_key,
                        uid,
                        gid,
                    },
                },
                AgentCommand::List => HumanCommand::AgentList {},
                AgentCommand::Revoke { id } => HumanCommand::AgentRevoke { id },
            },
            false,
        ),
    };
    let response = exchange(&state_root, command).map_err(|error| error.to_string())?;
    reject_error(&response)?;
    output(&response)?;
    if let HumanResponse::Submitted { receipt } = response
        && wait
        && !receipt.status.is_terminal()
    {
        let mut previous = receipt.status;
        loop {
            std::thread::sleep(Duration::from_millis(500));
            let response = exchange(
                &state_root,
                HumanCommand::Status {
                    id: receipt.id.clone(),
                },
            )
            .map_err(|error| error.to_string())?;
            reject_error(&response)?;
            let HumanResponse::Status { state } = &response else {
                return Err("invalid provider response".into());
            };
            if state != &previous {
                output(&response)?;
                previous = state.clone();
            }
            if state.is_terminal() {
                break;
            }
        }
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn reject_error(response: &HumanResponse) -> Result<(), String> {
    match response {
        HumanResponse::ProvisioningRejected { reason } => Err(reason.to_string()),
        HumanResponse::Rejected { reason } => Err(reason.to_string()),
        HumanResponse::InvalidRequest => Err("invalid request".into()),
        HumanResponse::Unauthorized => Err("unauthorized human".into()),
        HumanResponse::Unavailable => Err("provider unavailable".into()),
        _ => Ok(()),
    }
}
#[cfg(target_os = "linux")]
fn output(response: &impl serde::Serialize) -> Result<(), String> {
    let encoded = terminal_json(response)?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(encoded.as_bytes())
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_error| "output unavailable".into())
}
/// Preserve JSON semantics while making invisible terminal controls visible.
#[cfg(target_os = "linux")]
fn terminal_json(value: &impl serde::Serialize) -> Result<String, String> {
    use std::fmt::Write as _;
    const MAX_OUTPUT: usize = 2 * 1024 * 1024;
    let json = serde_json::to_string(value).map_err(|_error| "provider response unavailable")?;
    let mut safe = String::new();
    for character in json.chars() {
        if character.is_control()
            || matches!(character, '\u{061c}' | '\u{200b}' | '\u{2060}' | '\u{feff}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
        {
            write!(safe, "\\u{:04x}", character as u32)
                .map_err(|_error| "provider response unavailable")?;
        } else {
            safe.push(character);
        }
        if safe.len() >= MAX_OUTPUT {
            return Err("provider response unavailable".into());
        }
    }
    Ok(safe)
}
#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    #[test]
    fn history_arguments_and_terminal_json_preserve_data_without_controls() {
        for (arguments, limit) in [
            (vec!["history"], None),
            (vec!["history", "--limit", "200"], Some(200)),
        ] {
            let args = Args::try_parse_from(
                ["vw-access", "--state-root", "/private"]
                    .into_iter()
                    .chain(arguments),
            )
            .unwrap();
            assert!(matches!(args.command, Command::History { limit: actual } if actual == limit));
        }
        for value in ["4294967296", "-1", "private-sentinel"] {
            assert!(
                Args::try_parse_from([
                    "vw-access",
                    "--state-root",
                    "/private",
                    "history",
                    "--limit",
                    value
                ])
                .is_err()
            );
        }
        let value = "<img>\"\\n\r\t\x1b]2;title\x07\x7f\u{0085}\u{009b}\u{061c}\u{200e}\u{200f}\u{2028}\u{2029}\u{202a}\u{202b}\u{202c}\u{202d}\u{202e}\u{2066}\u{2067}\u{2068}\u{2069}";
        let encoded = terminal_json(&value).unwrap();
        assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), value);
        for character in value.chars().filter(|c| c.is_control() || matches!(c, '\u{061c}' | '\u{200b}' | '\u{2060}' | '\u{feff}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}')) {
            assert!(!encoded.contains(character));
        }
        assert!(
            encoded.contains(r"\u007f")
                && encoded.contains(r"\u0085")
                && encoded.contains(r"\u202e")
        );
        // The complete output includes JSON's two quotes and the final newline.
        let at_limit = terminal_json(&"x".repeat(2_097_149)).unwrap();
        assert_eq!(at_limit.len() + 1, 2_097_152);
        assert_eq!(
            terminal_json(&"x".repeat(2_097_150)),
            Err("provider response unavailable".into())
        );
        for character in ['\u{200b}', '\u{2060}', '\u{feff}'] {
            let label = format!("label{character}end");
            let encoded = terminal_json(&label).unwrap();
            assert!(!encoded.contains(character));
            assert!(encoded.contains(&format!("\\u{:04x}", character as u32)));
            assert_eq!(serde_json::from_str::<String>(&encoded).unwrap(), label);
        }
        assert_eq!(
            terminal_json(&"x".repeat(2_097_151)),
            Err("provider response unavailable".into())
        );
        assert_eq!(
            terminal_json(&"\u{0085}".repeat(400_000)),
            Err("provider response unavailable".into())
        );
    }
    #[test]
    fn request_defaults_to_wait_and_requires_separator_for_ordered_values() {
        let args = Args::try_parse_from([
            "vw-access",
            "--state-root",
            "/private",
            "request",
            "deploy",
            "--revision",
            "digest",
            "--",
            "-1",
            "target",
        ])
        .unwrap();
        let Command::Request {
            operation,
            revision,
            no_wait,
            values,
        } = args.command
        else {
            panic!("request expected");
        };
        assert_eq!(operation, "deploy");
        assert_eq!(revision.as_deref(), Some("digest"));
        assert!(!no_wait);
        assert_eq!(values, ["-1", "target"]);
        assert!(
            Args::try_parse_from([
                "vw-access",
                "--state-root",
                "/private",
                "request",
                "deploy",
                "target"
            ])
            .is_err()
        );
        assert!(
            Args::try_parse_from([
                "vw-access",
                "--state-root",
                "/private",
                "request",
                "deploy",
                "--expires",
                "10"
            ])
            .is_err()
        );
    }
    #[test]
    fn no_wait_and_status_parse_without_request_authority_fields() {
        let args = Args::try_parse_from([
            "vw-access",
            "--state-root",
            "/private",
            "request",
            "deploy",
            "--no-wait",
        ])
        .unwrap();
        assert!(matches!(
            args.command,
            Command::Request {
                no_wait: true,
                revision: None,
                ..
            }
        ));
        let args =
            Args::try_parse_from(["vw-access", "--state-root", "/private", "status", "opaque"])
                .unwrap();
        assert!(matches!(args.command, Command::Status { id } if id == "opaque"));
        assert!(
            Args::try_parse_from([
                "vw-access",
                "--state-root",
                "/private",
                "status",
                "opaque",
                "--uid",
                "0"
            ])
            .is_err()
        );
    }
    #[test]
    fn every_provider_rejection_is_an_error_and_never_success_output() {
        use vaultwarden_cli::access::direct_request::{DirectRequestError, DirectStatus};
        for (response, expected) in [
            (
                HumanResponse::Rejected {
                    reason: DirectRequestError::Locked,
                },
                "provider locked",
            ),
            (
                HumanResponse::Rejected {
                    reason: DirectRequestError::InvalidRequest,
                },
                "invalid request",
            ),
            (
                HumanResponse::Rejected {
                    reason: DirectRequestError::StaleRevision,
                },
                "stale policy revision",
            ),
            (HumanResponse::InvalidRequest, "invalid request"),
            (HumanResponse::Unauthorized, "unauthorized human"),
            (HumanResponse::Unavailable, "provider unavailable"),
        ] {
            assert_eq!(reject_error(&response), Err(expected.to_owned()));
        }
        assert_eq!(
            reject_error(&HumanResponse::Status {
                state: DirectStatus::Pending
            }),
            Ok(())
        );
    }
}

#[cfg(not(target_os = "linux"))]
fn main() -> std::process::ExitCode {
    eprintln!("vw-access: unsupported platform; requires Linux");
    std::process::ExitCode::FAILURE
}
