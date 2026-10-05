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
    access::{agent_binding::AgentPairing, direct_request::DirectSubmission},
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
        #[arg(last = true)]
        values: Vec<String>,
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
    if args.state_root.is_none() && !matches!(&args.command, Command::Submit { .. }) {
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
fn run(args: Args) -> Result<(), String> {
    if let Command::Submit {
        operation,
        socket,
        key_file,
        binding_id,
        revision,
        values,
    } = &args.command
    {
        use vaultwarden_cli::{
            access::protocol::{AgentResponse, SignedSubmission},
            adapters::unix_socket,
        };
        let key =
            unix_socket::load_signing_key(key_file).map_err(|_error| "agent key unavailable")?;
        let mut nonce = [0u8; 32];
        getrandom::fill(&mut nonce).map_err(|_error| "agent submission unavailable")?;
        let input = SignedSubmission::sign(
            binding_id.clone(),
            nonce,
            operation.clone(),
            revision.clone(),
            values.clone(),
            &key,
        )
        .map_err(|_error| "invalid agent submission")?;
        drop(key);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_error| "agent submission unavailable")?;
        let response = runtime
            .block_on(unix_socket::exchange(socket, &input))
            .map_err(|_error| "agent transport unavailable")?;
        output(&response)?;
        return if matches!(response, AgentResponse::Pending { .. }) {
            Ok(())
        } else {
            Err("agent submission rejected".into())
        };
    }
    let state_root = args.state_root.ok_or("provider state root required")?;
    let (command, wait) = match args.command {
        Command::Submit { .. } => return Err("invalid command".into()),
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
