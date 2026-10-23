#!/usr/bin/env bash
# Explicit disposable real-backend pilot. Secret values are never shell arguments.
set -euo pipefail
umask 077
repo="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
action="${1:---check}"
case "$action" in
    --check|--run) [[ $# -le 1 ]] ;;
    --advance) [[ $# == 3 ]]; export VW_PILOT_ROOT="$2" VW_PILOT_PHASE="$3" ;;
    --stop) [[ $# == 2 ]]; export VW_PILOT_ROOT="$2" ;;
    *) echo 'usage: pilot-real-vaultwarden-companion.sh --check | --run | --advance ROOT PHASE | --stop ROOT' >&2; exit 2 ;;
esac
[[ "$(uname -s)" == Linux ]] || { echo 'FAIL: Linux required' >&2; exit 2; }
export VW_PILOT_ACTION="$action"
if [[ "$action" == --check || "$action" == --run ]]; then
    for dependency in /usr/bin/{cc,openssl,docker,systemctl,systemd-run,unshare,newuidmap,newgidmap,dbus-daemon,gnome-keyring-daemon,secret-tool,gdbus,setpriv,journalctl,timeout,id,cat,env,true,sleep,chown,dd,test} /bin/{sh,rm}; do
        [[ -f "$dependency" && -x "$dependency" ]] || { echo "FAIL: missing prerequisite $dependency" >&2; exit 2; }
    done
    [[ "${DOCKER_HOST:-unix:///var/run/docker.sock}" == unix:///var/run/docker.sock && "${DOCKER_CONTEXT:-default}" == default ]] || { echo 'FAIL: only local default Docker supported' >&2; exit 2; }
    [[ "$(timeout 5s docker context show)" == default ]] || exit 2
    timeout 5s docker info >/dev/null 2>&1 || { echo 'FAIL: local Docker unavailable' >&2; exit 2; }
fi
cd "$repo"
# Test executable path is obtained from Cargo metadata, never a glob picking an
# unrelated/stale test artifact. Control invocations do not launch services.
binary="$(cargo test --locked --test protected_rehearsal --no-run --message-format=json | python3 -c 'import json,sys; paths=[x["executable"] for line in sys.stdin for x in [json.loads(line)] if x.get("reason")=="compiler-artifact" and x.get("target",{}).get("name")=="protected_rehearsal" and x.get("executable")]; assert len(paths)==1; print(paths[0])')"
exec "$binary" real_vaultwarden_companion_pilot --ignored --exact --nocapture --test-threads=1
