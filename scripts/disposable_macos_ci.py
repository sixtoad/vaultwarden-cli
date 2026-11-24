"""Identify hosted Macs and operator-provisioned, single-job GUI guests."""
import os
from pathlib import Path
import stat
import subprocess
import sys


def disposable_macos_ci():
    if sys.platform != "darwin" or os.environ.get("CI") != "true" or os.environ.get("GITHUB_ACTIONS") != "true":
        return False
    environment = os.environ.get("RUNNER_ENVIRONMENT")
    if environment == "github-hosted":
        return True
    if environment != "self-hosted" or os.geteuid() == 0:
        return False
    name = os.environ.get("RUNNER_NAME", "")
    if not name.startswith("vw-ci-gui-"):
        return False
    # The provisioner writes the one-job registration name after cloning the
    # clean image. /private/var/run is root-owned and cleared on guest reboot.
    marker = Path("/private/var/run/vw-ci-gui-runner")
    try:
        info = marker.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            return False
        if marker.read_text() != name + "\n" or Path("/dev/console").stat().st_uid != os.geteuid():
            return False
        model = subprocess.check_output(["/usr/sbin/sysctl", "-n", "hw.model"], text=True)
        if not model.strip().startswith("VirtualMac"):
            return False
        sip = subprocess.check_output(["/usr/bin/csrutil", "status"], text=True, env={"LC_ALL": "C"})
        return sip.strip() == "System Integrity Protection status: enabled."
    except (OSError, UnicodeError, subprocess.CalledProcessError):
        return False


if __name__ == "__main__" and not disposable_macos_ci():
    raise SystemExit("A disposable macOS CI runner with a logged-in GUI session is required.")
