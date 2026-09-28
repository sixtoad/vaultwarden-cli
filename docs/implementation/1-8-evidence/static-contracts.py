"""Explicit source/composition contracts, complementary to behavioral tests."""
from pathlib import Path
import re
manager = Path('src/adapters/supervisor/manager.rs').read_text()
supervisor = Path('src/adapters/supervisor.rs').read_text()
bridge = Path('src/adapters/supervisor/bridge.rs').read_text()
helper = Path('src/bin/vaultwarden-access-exec.rs').read_text()
daemon = Path('src/bin/vaultwarden-accessd.rs').read_text()
unit = Path('systemd/user/vaultwarden-accessd.service').read_text()
for source in [manager, supervisor, bridge, helper]:
    for forbidden in ['Command::new', 'killpg(', 'systemd-run', 'systemctl']:
        assert forbidden not in source, forbidden
print('PASS: no subprocess/command-string or process-group cleanup fallback')
for forbidden in ['Environment', 'EnvironmentFile', 'EnvironmentFiles', 'SetEnvironment', 'SetCredential', 'LoadCredential']:
    assert not re.search(r'property\("'+forbidden+r'"', manager), forbidden
print('PASS: no credential-bearing manager property construction')
assert 'libc::SYS_execveat' in bridge and 'libc::AT_EMPTY_PATH' in bridge
assert 'libc::execve(' not in bridge and 'libc::execv(' not in bridge
assert 'libc::PR_SET_PDEATHSIG' in bridge and 'libc::PR_SET_CHILD_SUBREAPER' in bridge
assert 'libc::PTRACE_EVENT_EXEC' in bridge and 'libc::MSG_CMSG_CLOEXEC' in bridge
print('PASS: descriptor-only protected exec, kernel exec event, parent death, subreaper and CLOEXEC transfer')
for setting in ['Type=exec', 'KillMode=control-group', 'SendSIGKILL=yes', 'TimeoutStopSec=30s', 'LimitCORE=0', 'NoNewPrivileges=yes']:
    assert setting in unit, setting
assert '.with_execution_dispatcher(execution_worker.dispatcher())' in daemon
assert daemon.index('initialize_provider(&args.state_root') < daemon.index('SystemdProcessSupervisor::installed()') < daemon.index('HumanSocket::bind')
assert 'execution_worker.join()' in daemon
print('PASS: provider unit, writer-locked setup, recovery-before-admission and explicit worker joining')
