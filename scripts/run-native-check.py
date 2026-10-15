#!/usr/bin/env python3
"""Bound a native test command and preserve diagnostics on a hang."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys


def diagnose(pid, report):
    """Inspect only descendants of our child; never record command arguments."""
    try:
        table = subprocess.run(
            ["ps", "-axo", "pid=,ppid=,comm="], capture_output=True,
            text=True, timeout=5, check=True,
        )
        rows = [line.split(None, 2) for line in table.stdout.splitlines()]
        owned = {pid}
        while True:
            children = {int(row[0]) for row in rows
                        if len(row) == 3 and int(row[1]) in owned}
            if children <= owned:
                break
            owned |= children
        selected = [row for row in rows if len(row) == 3 and int(row[0]) in owned]
        (report / "processes.txt").write_text(
            "\n".join(" ".join(row) for row in selected) + "\n"
        )
        for row in selected:
            if Path(row[2]).name == "xctest":
                sample_path = report / f"xctest-{row[0]}.sample.txt"
                sample = subprocess.run(
                    ["/usr/bin/sample", row[0], "2", "-file",
                     str(sample_path)],
                    capture_output=True, text=True, timeout=10, check=False,
                )
                if sample.returncode != 0 or not sample_path.is_file():
                    (report / f"xctest-{row[0]}.sample-error.txt").write_text(
                        f"sample exit={sample.returncode}; file present={sample_path.is_file()}\n"
                        + sample.stdout + sample.stderr
                    )
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"Native diagnostics unavailable: {type(error).__name__}", file=sys.stderr, flush=True)


def stop_group(pid):
    try:
        os.killpg(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def run(command, report, timeout):
    report.mkdir(parents=True, exist_ok=True)
    # A private process group limits cleanup to this synthetic test invocation.
    process = subprocess.Popen(command, start_new_session=True)
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"Native test exceeded {timeout:g}s; capturing diagnostics.", file=sys.stderr, flush=True)
        diagnose(process.pid, report)
        return 124
    finally:
        # Also close inherited pipes held by descendants after their leader exits.
        stop_group(process.pid)
        process.wait()


def terminate(signum, _frame):
    # Raising through run() ensures cleanup also happens on CI cancellation.
    raise SystemExit(128 + signum)


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--timeout", type=float, default=120)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command or not 0 < args.timeout <= 600:
        parser.error("a command and a finite timeout in (0, 600] are required")
    result = run(command, args.report, args.timeout)
    sys.exit(result if result >= 0 else 128 - result)
