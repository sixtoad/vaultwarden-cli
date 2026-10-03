# Story 1.9 evidence artifacts

Read the adjacent `1-9-test-evidence.md` and `1-9-mutation-classifications.md`
for results and acceptance mapping. `post-review/` is the completed reviewed snapshot. `review-semantic/` and
`review-generated/` hold its complete 44-fault rerun; `review-fix/` holds targeted
agent checks. `final/`, `parent/` and `baseline-adapters/` retain earlier verification
provenance.

`semantic/` retains the first 19-fault campaign. `semantic-final/` contains two
survivor retries and terminal escaping; `semantic-browser-final/` contains HTML
and control escaping. Read later results as superseding the same earlier fault,
not as additional unique mutants. The browser failed baseline under
`semantic-final/` is not a caught fault.

`generated-initial/` contains the 16 selected cargo-mutants transformations;
`generated-final/` reruns the two initial survivors. Generated inventory records
unselected transformations as inventory only, not as executed checks.

Captured logs and larger machine-generated JSON/manifests are compressed
losslessly with a `.gz` suffix; read with `gzip -cd`.
A patch containing significant blank context lines is retained as `.diff.gz`.
Machine-generated JSON retains original log filenames: append `.gz` where the
uncompressed log is absent. Compression changes no captured output. The runners
write uncompressed logs when rerun. JSON records exact commands, exit codes and
durations; source manifests and per-mutant hashes establish the tested/restored
source snapshots.

Runners require the toolchain/browser dependencies described in the report.
They use only synthetic fixtures and the project's secure temporary-directory
wrapper. Semantic mutations run sequentially and restore files unconditionally;
do not edit source or run another mutation campaign concurrently.
