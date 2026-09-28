//! Test-only entrypoint: pause before the production helper disables dumpability.
//! The manager/loader environment belongs to this same process; after inspection
//! it enters the unchanged production helper, including PR_SET_DUMPABLE=0.
unsafe extern "C" {
    fn raise(signal: i32) -> i32;
}
fn main() {
    // Linux SIGSTOP; this runner explicitly supports only x86_64 Linux fixtures.
    assert_eq!(unsafe { raise(19) }, 0);
    std::process::exit(vaultwarden_cli::adapters::protected_execution_helper());
}
