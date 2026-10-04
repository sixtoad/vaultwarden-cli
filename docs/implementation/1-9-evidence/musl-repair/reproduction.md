# Local musl repair reproduction

Run from the repository root on x86_64 Ubuntu with `apt-get`, `dpkg-deb`, Python 3,
`x86_64-linux-gnu-gcc` and rustup available. The recorded run used the active
`stable-x86_64-unknown-linux-gnu` toolchain, `rustc 1.98.1 (48a229cea 2026-09-01)`.
Use that Rust version when reproducing this snapshot. Cargo dependencies must
already be cached; `cargo fetch --locked` prepares them if necessary.

The original `apt-get download musl musl-dev musl-tools` resolved all three
packages to `1.2.4-2`. The commands below pin those exact versions and extract
them without installing system packages. Re-extraction restores the original
specs before rewriting, so paths are not prefixed twice on a repeat run.

```bash
rustup target add x86_64-unknown-linux-musl
mkdir -p /tmp/story19-musl-toolchain
(
  cd /tmp/story19-musl-toolchain
  apt-get download musl:amd64=1.2.4-2 musl-dev:amd64=1.2.4-2 musl-tools:amd64=1.2.4-2
  for package in musl_1.2.4-2_amd64.deb musl-dev_1.2.4-2_amd64.deb musl-tools_1.2.4-2_amd64.deb; do
    dpkg-deb -x "$package" /tmp/story19-musl-toolchain/root
  done
)
python3 - <<'PY'
from pathlib import Path

toolchain = Path('/tmp/story19-musl-toolchain')
specs = toolchain / 'root/usr/lib/x86_64-linux-musl/musl-gcc.specs'
specs.write_text(specs.read_text().replace('/usr/', str(toolchain / 'root/usr') + '/'))
wrapper = toolchain / 'musl-gcc'
wrapper.write_text('#!/bin/sh\nexec x86_64-linux-gnu-gcc "$@" -specs ' + str(specs) + '\n')
wrapper.chmod(0o755)
PY
```

Exact build and runtime test invocations, including the compiler environment:

```bash
env CARGO_BUILD_JOBS=2 \
  CC_x86_64_unknown_linux_musl=/tmp/story19-musl-toolchain/musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/story19-musl-toolchain/musl-gcc \
  cargo build --offline --locked --target x86_64-unknown-linux-musl \
  > /tmp/story19-musl-build.log 2>&1

env CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=1 \
  CC_x86_64_unknown_linux_musl=/tmp/story19-musl-toolchain/musl-gcc \
  CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=/tmp/story19-musl-toolchain/musl-gcc \
  ./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked \
  --target x86_64-unknown-linux-musl --lib adapters::supervisor::bridge::tests \
  > /tmp/story19-musl-bridge-tests.log 2>&1

./scripts/with-secure-test-tmpdir.sh cargo test --offline --locked \
  --lib adapters::supervisor::bridge::tests
```

The final command is the recorded native bridge regression invocation. Run the
tests where Unix socket binding and ptrace fixtures are permitted. The wrapper
requires safe, provider-owned home-directory ancestry and creates its private
temporary directory there. The recorded successful tests ran outside the agent
sandbox; the initial sandboxed attempt could not execute two fixtures.

Both musl commands exited successfully; the musl and native bridge runs each
passed all nine tests. See [source provenance](provenance.md),
[musl build output](musl-build.log.gz) and [musl test output](musl-bridge-tests.log.gz).
