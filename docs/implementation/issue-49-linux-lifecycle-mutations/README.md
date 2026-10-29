# Linux lifecycle mutation receipts

The four mutations ran in a private source/build copy, after their unmodified
targeted tests passed. Each `.log` includes the actual failed test and assertion;
an exit code alone is not counted as a caught mutation. The working tree was not
mutated. Synthetic test inputs contain no production credentials.

`report.json` identifies the tested source bytes, patch hashes and receipt hashes.
The exact patches were reconstructed from the retained `run_mutations.py` and
the source identified by the original report; both original source hashes were
verified before patch generation. Later review fixes are separately tested and
do not rewrite these historical receipts.

To repeat against the current source, run from the repository root:

```sh
scripts/with-secure-test-tmpdir.sh python3 docs/implementation/issue-49-linux-lifecycle-mutations/run_mutations.py
```

The script makes an isolated source and target copy and writes a new receipt
directory under `/tmp`. It does not overwrite these records.

The [review-fix mutations](review-fixes/report.json) separately remove the final
producer write gate and the application's SSH lifetime marker. Their baseline
tests pass; the mutants fail the synchronized ordering assertion and the actual
missing-material assertion after recovery. This directory retains the exact
source snapshot, hashes, patches and both outer and provider assertion receipts.
