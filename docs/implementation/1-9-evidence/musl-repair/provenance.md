# Musl repair evidence provenance

The musl build, bridge runtime tests, native all-targets suite, strict Clippy and
real-systemd checks in this directory tested repository baseline
`73d9f64fb9996380a558eb34eec418e2f53f88e7` plus the uncommitted repair to
`src/adapters/supervisor/bridge.rs`. That file is the sole production source
delta. The report and evidence files are documentation additions and do not
change the tested program. `Cargo.lock` is unchanged from the baseline.

[bridge.patch](bridge.patch) preserves the exact output of this repository-root
command at the tested snapshot:

```bash
git diff 73d9f64fb9996380a558eb34eec418e2f53f88e7 -- src/adapters/supervisor/bridge.rs
```

Apply that patch to a clean checkout of the baseline to reconstruct the tested
production sources. The existing [source.sha256](source.sha256) continues to
hash only the repaired bridge source. The separate
[provenance.sha256](provenance.sha256) records `Cargo.lock`, the archived source
patch and the diagnostic excerpt. Both manifests use paths relative to the
repository root and can be checked there with `sha256sum -c`.

[Original compiler diagnostics](original-compiler-diagnostics.txt) were extracted
from `/tmp/story19-musl.log`, the downloaded output of
[Actions run 37121572620, job 111198543089](https://github.com/sixtoad/vaultwarden-cli/actions/runs/37121572620/job/111198543089).
The excerpt starts at the first `error[E0308]` and ends at the compiler's
`due to 10 previous errors` summary. Only ANSI terminal escapes and leading
Actions timestamps were removed; all ten diagnostics, locations, notes and
suggestions within that span remain verbatim.

[reproduction.md](reproduction.md) records the isolated musl compiler setup and
exact build/test commands. These are local results; they do not establish a
successful hosted musl rerun.
