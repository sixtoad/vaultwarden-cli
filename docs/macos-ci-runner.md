# macOS CI runner

`ci.yml` uses the repository variable `VW_MACOS_CI` to route seven Apple Silicon jobs. Set it to `self-hosted` to select the repo-only label `vw-ci-macos-arm64` for the native provider, Swift companion, stable and beta tests, macOS CLI build, and both iOS Rust targets. Matrix display names retain their original OS and target strings. GitHub's job page shows the runner that actually took the job.

The Flutter desktop job launches a packaged app, changes the Keychain search list and uses an app container. The disposable pilot also changes the default Keychain and explicitly checks for a GitHub-hosted image. Both use hosted ARM64 machines. Release signing and the separate manual mutation campaign use their existing runners.

## Before registration

1. In repository Settings → Actions → General, select **Require approval for all external contributors**. Verify `gh api repos/sixtoad/vaultwarden-cli/actions/permissions/fork-pr-contributor-approval --jq .approval_policy` returns `all_external_contributors`. A fork can edit workflow YAML and request a runner label. Review the full proposed workflows and their invoked code before approving an external run. The normal CI expression routes fork and Dependabot PRs to hosted workers.
2. Inspect queued and in-progress runs and their requested labels before bringing a new listener online. Review workflow triggers when adding new jobs. The installed hook accepts this repository's CI workflow on main/master pushes and same-repository PRs. CI has read-only contents access. Only hosted jobs that need to write comments or checks have those permissions. The release workflow receives separate permissions.
3. Use a dedicated standard macOS account named `vwci` with a private, ownership-enforcing home at `/Users/vwci`. Verify the account has no admin membership, sudo grants, personal Keychain items, Git credentials, or access to other runners' private data. Keep the runner home and work tree on storage with enough free space for the largest Rust build. A volume mounted with `noowners` is unsuitable for private runner files. Check whether the runner account can access other tenants' data there, too.
4. In the runner account, check `uname -m` (arm64), `xcodebuild -version`, `xcrun --sdk iphoneos --show-sdk-path`, `xcrun --sdk iphonesimulator --show-sdk-path`, `swift --version`, Python 3, OpenSSL and a user-owned rustup installation. Use full Xcode with its license and first-launch setup already completed. The Swift tests need working user Keychain services. Keep the other runner's service, toolchains, caches, build trees and login session separate.
5. Allow outbound HTTPS (TCP 443) to the GitHub runner, action, artifact and tool download endpoints. The runner polls for jobs. Test fixtures bind to loopback. Setup requires no forwarding, tunnel or inbound listener. [GitHub connectivity requirements](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#communication)

## Install

In the dedicated account, set `umask 077`, create `~/actions-runner`, download the official macOS ARM64 package listed in repository Settings → Actions → Runners → New self-hosted runner, and verify its published SHA-256 before unpacking it there. Keep the runner's automatic updates enabled.

Copy the reviewed [job hook](../.github/ci/mac-mini-job.sh) outside the checkout to `/Users/vwci/ci-hooks/mac-mini-job.sh` and make it executable. In the fresh `~/actions-runner/.env`, set:

```dotenv
ACTIONS_RUNNER_HOOK_JOB_STARTED=/Users/vwci/ci-hooks/mac-mini-job.sh
ACTIONS_RUNNER_HOOK_JOB_COMPLETED=/Users/vwci/ci-hooks/mac-mini-job.sh
CARGO_INCREMENTAL=0
```

Register exactly one listener. From the administrator's terminal, the following pipeline passes a short-lived registration token to the separate account via stdin. Authenticate sudo locally first so its prompt cannot consume the pipe. The administrator's GitHub CLI credentials stay in the administrator's account.

```bash
sudo -v
gh api --method POST repos/sixtoad/vaultwarden-cli/actions/runners/registration-token --jq .token |
  sudo -n -H -u vwci /bin/bash -c '
    set -eu
    umask 077
    cd /Users/vwci/actions-runner
    IFS= read -r ACTIONS_RUNNER_INPUT_TOKEN
    export ACTIONS_RUNNER_INPUT_TOKEN
    export PATH="/Users/vwci/.cargo/bin:/usr/bin:/bin:/usr/sbin:/sbin"
    ./config.sh --unattended --url https://github.com/sixtoad/vaultwarden-cli \
      --name vw-ci-mac-mini --no-default-labels --labels vw-ci-macos-arm64 --work _work
  '
```

In the dedicated account's login session, run `./svc.sh install`, `./svc.sh start` and `./svc.sh status` from `~/actions-runner`. The macOS service is a per-user LaunchAgent. Keep that session logged in while jobs are eligible. Before switching user sessions, check with the owner of the active desktop. Protect the runner's registration files, service logs and tool paths from access by other users.

## Operation and rollback

- Check registration and workload with `gh api repos/sixtoad/vaultwarden-cli/actions/runners --jq '.runners[] | {name,status,busy,labels:[.labels[].name]}'`. Check CPU load, memory pressure and disk space on the host. Each runner accepts one job at a time, so GitHub and Gitea can each start a job simultaneously. CI limits Cargo to two build jobs. A label does not serialize the two services.
- The hook cleans the dedicated repository workspace before checkout and after artifact upload, including hidden and untracked files. The runner manages its temporary directory. Toolchains and per-account caches persist. After a crash, inspect free space, runner diagnostics, abandoned scratch directories and test Keychains under the dedicated account before starting more jobs. Perform maintenance while idle and coordinate service interruptions.
- For a real PR run, compare the PR head SHA to the run's head SHA, inspect the checkout step for the tested merge SHA and its PR head parent, and verify the runner name, job conclusions, uploaded artifacts and Merge Ready in GitHub. A queued job has not executed.
- To send **future** jobs back to hosted ARM64 machines, set `gh variable set VW_MACOS_CI --repo sixtoad/vaultwarden-cli --body hosted`. An unset variable also selects hosted. Existing jobs retain their assigned labels. Coordinate any cancellation or rerun separately.
