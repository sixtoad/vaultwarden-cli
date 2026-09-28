//! Internal systemd helper; its only arguments are a private socket and provider PID.
fn main() {
    #[cfg(target_os = "linux")]
    std::process::exit(vaultwarden_cli::adapters::protected_execution_helper());
    #[cfg(not(target_os = "linux"))]
    std::process::exit(1);
}
