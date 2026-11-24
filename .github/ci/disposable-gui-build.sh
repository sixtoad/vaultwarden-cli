# Sourced by the two GUI build steps. The guest identity is checked before setup.
if [[ ${RUNNER_OS:-} == macOS && ${RUNNER_ENVIRONMENT:-} == self-hosted ]]; then
  python3 scripts/disposable_macos_ci.py || return 1
  # Match Flutter's prebuilt framework symlinks during build and extraction.
  umask 022
  # Hold the guest display awake while this build shell exists. Renew the
  # user-activity assertion before the guest's idle screen saver can start.
  build_pid=$$
  (
    while kill -0 "$build_pid" 2>/dev/null; do
      /usr/bin/caffeinate -diu -w "$build_pid" -t 240 || exit 1
    done
  ) </dev/null >/dev/null 2>&1 &
fi
