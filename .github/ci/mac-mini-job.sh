#!/bin/bash
# Installed by the operator outside the checkout as both runner job hooks.
set -eu
umask 077
[[ $(/usr/bin/id -un) == vwci && "$HOME" == /Users/vwci ]]
[[ $(/usr/bin/uname -m) == arm64 ]]
[[ "$GITHUB_REPOSITORY" == sixtoad/vaultwarden-cli ]]
[[ "$GITHUB_WORKFLOW_REF" == sixtoad/vaultwarden-cli/.github/workflows/ci.yml@* ]]

/usr/bin/python3 -I - <<'PY'
import json
import os
from pathlib import Path
import shutil

env = os.environ
with open(env["GITHUB_EVENT_PATH"]) as source:
    event = json.load(source)
repo = "sixtoad/vaultwarden-cli"
if event.get("repository", {}).get("full_name") != repo:
    raise SystemExit("Unexpected repository")
if env["GITHUB_EVENT_NAME"] == "pull_request":
    pr = event["pull_request"]
    if (pr["head"]["repo"]["full_name"] != repo or pr["base"]["repo"]["full_name"] != repo
            or pr["user"]["login"] == "dependabot[bot]"):
        raise SystemExit("This pull request requires a hosted runner")
elif env["GITHUB_EVENT_NAME"] != "push" or event.get("ref") not in ("refs/heads/main", "refs/heads/master"):
    raise SystemExit("Unexpected CI event or branch")

workspace = Path("/Users/vwci/actions-runner/_work/vaultwarden-cli/vaultwarden-cli")
if Path(env["GITHUB_WORKSPACE"]) != workspace or workspace.resolve() != workspace:
    raise SystemExit("Unexpected runner workspace")
# Leave the workspace itself in place. Run before checkout as well as after
# artifact upload so a previous failed or interrupted job cannot seed this one.
for entry in workspace.iterdir():
    if entry.is_symlink() or not entry.is_dir():
        entry.unlink()
    else:
        shutil.rmtree(entry)
PY
