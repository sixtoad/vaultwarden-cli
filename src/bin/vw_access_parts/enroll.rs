//! `vw-access enroll …`: guided enrollment (#59 phase 1). Provider-side verbs
//! use the owner's human socket; `join` runs in the invited agent account.
use clap::Subcommand;
use std::{
    io::{BufRead, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use vaultwarden_cli::{
    access::enrollment::{
        EnrolleeKind, EnrollmentState, InvitationRequest,
        joiner::{InvitationCode, JoinedSession},
    },
    adapters::{
        enrollment_client::{self, JoinFailure, JoinerPrompt, SocketTransport},
        human_socket::HumanCommand,
    },
};

#[derive(Subcommand)]
pub(crate) enum EnrollCommand {
    /// Invite a restricted agent account. Prints a single-use, expiring
    /// invitation code to hand to the person operating that account.
    InviteAgent {
        #[arg(allow_hyphen_values = true)]
        label: String,
        /// Restricted UID, distinct from the provider and operator UIDs.
        #[arg(long)]
        uid: u32,
        /// Required primary or supplementary group membership.
        #[arg(long)]
        gid: u32,
        /// Invitation lifetime (60–1800 seconds, default 600).
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// Invite a companion approval device. Enrollment never grants the
    /// administrator role.
    InviteCompanion {
        #[arg(allow_hyphen_values = true)]
        label: String,
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// Show invitations and their state. The comparison code is shown only on
    /// the joining endpoint: read it there and type it into `approve`.
    List,
    /// Approve after comparing: type the code the joining endpoint displays.
    /// A different code aborts the enrollment.
    Approve {
        #[arg(allow_hyphen_values = true)]
        id: String,
        #[arg(long)]
        code: String,
    },
    /// Cancel an open invitation or a pending enrollment.
    Cancel {
        #[arg(allow_hyphen_values = true)]
        id: String,
    },
    /// Run in the invited agent account. Reads the invitation code from the
    /// terminal, creates a new key file, shows the comparison code and asks
    /// the person at this terminal to confirm it.
    Join {
        #[arg(long)]
        socket: PathBuf,
        /// New agent-owned 0600 seed file; never replaces an existing file.
        #[arg(long)]
        key_file: PathBuf,
        /// How long to wait for the provider's approval. Default: until the
        /// invitation expires; never longer than that.
        #[arg(long, value_parser = super::parse_timeout_seconds)]
        timeout_seconds: Option<u64>,
    },
}

/// The provider-owner verbs as human-socket commands.
pub(crate) fn human_command(command: EnrollCommand) -> Result<HumanCommand, String> {
    Ok(match command {
        EnrollCommand::InviteAgent {
            label,
            uid,
            gid,
            ttl_seconds,
        } => HumanCommand::EnrollInvite {
            invitation: InvitationRequest {
                kind: EnrolleeKind::Agent { label, uid, gid },
                ttl_seconds,
            },
        },
        EnrollCommand::InviteCompanion { label, ttl_seconds } => HumanCommand::EnrollInvite {
            invitation: InvitationRequest {
                kind: EnrolleeKind::Companion { label },
                ttl_seconds,
            },
        },
        EnrollCommand::List => HumanCommand::EnrollList {},
        EnrollCommand::Approve { id, code } => HumanCommand::EnrollApprove { id, code },
        EnrollCommand::Cancel { id } => HumanCommand::EnrollCancel { id },
        EnrollCommand::Join { .. } => return Err("invalid command".into()),
    })
}

/// The joining human at the agent's terminal. Never auto-confirms.
struct Terminal {
    tty: std::fs::File,
}

impl Terminal {
    fn open() -> Result<Self, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map(|tty| Self { tty })
            .map_err(|_error| "enrollment requires an interactive terminal".into())
    }
    fn say(&mut self, text: &str) {
        let _ignored = self.tty.write_all(text.as_bytes());
        let _ignored = self.tty.flush();
    }
}

impl JoinerPrompt for Terminal {
    fn confirm(&mut self, session: &JoinedSession) -> bool {
        let role = match &session.kind {
            EnrolleeKind::Agent { label, uid, gid } => {
                format!("requester agent {label:?} (uid {uid}, gid {gid})")
            }
            EnrolleeKind::Companion { label } => format!("companion {label:?}"),
        };
        self.say(&format!(
            "Enrolling as {role}.\nComparison code: {}\nRead this code to the provider owner, who types it into `vw-access enroll approve`.\nThe provider never displays it. Type yes to enroll this account as shown: ",
            session.comparison_code
        ));
        let mut answer = String::new();
        let Ok(reader) = self.tty.try_clone() else {
            return false;
        };
        let read = std::io::BufReader::new(reader.take(16)).read_line(&mut answer);
        read.is_ok() && answer.trim() == "yes"
    }
    fn waiting(&mut self, state: &EnrollmentState) {
        if let EnrollmentState::AwaitingApprovals {
            provider_approved: false,
            ..
        } = state
        {
            self.say("Waiting for the provider owner to approve (vw-access enroll approve).\n");
        }
    }
}

/// `enroll join`: returns the process exit code.
pub(crate) fn join(socket: &Path, key_file: &Path, timeout_seconds: Option<u64>) -> u8 {
    match run_join(socket, key_file, timeout_seconds) {
        Ok(json) => match super::output(&json) {
            Ok(()) => 0,
            Err(_) => 1,
        },
        Err(error) => {
            eprintln!("vw-access: {error}");
            1
        }
    }
}

fn run_join(
    socket: &Path,
    key_file: &Path,
    timeout_seconds: Option<u64>,
) -> Result<serde_json::Value, String> {
    let mut terminal = Terminal::open()?;
    // The typed code holds the invitation secret: wiped once parsed.
    let code = zeroize::Zeroizing::new(
        rpassword::prompt_password("Invitation code (input hidden): ")
            .map_err(|_error| "enrollment requires an interactive terminal".to_string())?,
    );
    let code = InvitationCode::parse(&code).map_err(|error| error.to_string())?;
    let key = enrollment_client::create_agent_key(key_file)
        .map_err(|_error| "cannot create a new key file (it must not exist)".to_string())?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|_error| JoinFailure::LocalKey);
    let result = runtime.and_then(|runtime| {
        runtime.block_on(async {
            let deadline = timeout_seconds
                .map(|seconds| tokio::time::Instant::now() + Duration::from_secs(seconds));
            enrollment_client::join_agent(
                &mut SocketTransport { socket },
                &mut terminal,
                code,
                &key,
                deadline,
            )
            .await
        })
    });
    match result {
        Ok(identity) => Ok(serde_json::json!({
            "enrolled": identity,
            "key_file": key_file.display().to_string(),
        })),
        // The provider may have committed after the last reply we saw: keep
        // the key so a completed enrollment stays usable.
        Err(error) if error.outcome_unknown() => Err(format!(
            "{error}; key kept at {} (check `vw-access agent list` on the provider)",
            key_file.display()
        )),
        Err(error) => {
            // Definitively not enrolled: do not leave unused key material.
            enrollment_client::remove_agent_key(key_file);
            Err(error.to_string())
        }
    }
}
