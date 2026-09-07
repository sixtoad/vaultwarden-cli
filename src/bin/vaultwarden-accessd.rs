use clap::Parser;
use std::path::PathBuf;
use std::process::ExitCode;
use vaultwarden_cli::access::provider::Provider;

/// Locked foundation for the human-owned Vaultwarden Access provider.
#[derive(Debug, Parser)]
#[command(name = "vaultwarden-accessd")]
struct Args {
    /// Provider-owned directory for lifecycle state.
    #[arg(long, env = "VAULTWARDEN_ACCESS_STATE_ROOT")]
    state_root: PathBuf,
}

fn main() -> ExitCode {
    let args = Args::parse();
    let _provider = match Provider::start(args.state_root) {
        Ok(provider) => provider,
        Err(error) => {
            eprintln!("vaultwarden-accessd: {error}");
            return ExitCode::FAILURE;
        }
    };

    // There is intentionally no IPC, approval, or backend loop in this
    // foundation story. A later lifecycle adapter owns graceful signal
    // handling; restart recovery invalidates every unexecuted record.
    std::thread::park();
    unreachable!("the provider foundation waits for service termination")
}
