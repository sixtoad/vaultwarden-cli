//! Human terminal client. Outputs contain only provider-owned receipts and states.
use clap::{Parser, Subcommand, error::ErrorKind};
use std::{
    io::{self, Write},
    path::PathBuf,
    process::ExitCode,
    time::Duration,
};
use vaultwarden_cli::{
    access::direct_request::DirectSubmission,
    adapters::human_socket::{HumanCommand, HumanResponse, exchange},
};

#[derive(Parser)]
#[command(
    name = "vw-access",
    version,
    about = "Submit a one-time human request for desktop review"
)]
struct Args {
    /// Private provider directory, also accepted from VAULTWARDEN_ACCESS_STATE_ROOT.
    #[arg(long, env = "VAULTWARDEN_ACCESS_STATE_ROOT")]
    state_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
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
    Status { id: String },
}
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
    match run(args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vw-access: {error}");
            ExitCode::FAILURE
        }
    }
}
fn run(args: Args) -> Result<(), String> {
    let (command, wait) = match args.command {
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
    };
    let response = exchange(&args.state_root, command).map_err(|error| error.to_string())?;
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
                &args.state_root,
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
fn reject_error(response: &HumanResponse) -> Result<(), String> {
    match response {
        HumanResponse::Rejected { reason } => Err(reason.to_string()),
        HumanResponse::InvalidRequest => Err("invalid request".into()),
        HumanResponse::Unauthorized => Err("unauthorized human".into()),
        HumanResponse::Unavailable => Err("provider unavailable".into()),
        _ => Ok(()),
    }
}
fn output(response: &HumanResponse) -> Result<(), String> {
    let encoded = serde_json::to_vec(response).map_err(|_error| "provider response unavailable")?;
    let mut stdout = io::stdout().lock();
    stdout
        .write_all(&encoded)
        .and_then(|()| stdout.write_all(b"\n"))
        .and_then(|()| stdout.flush())
        .map_err(|_error| "output unavailable".into())
}
#[cfg(test)]
mod tests {
    use super::*;
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
