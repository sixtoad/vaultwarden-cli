# Story 1.6 mutation survivor classifications

All 42 surviving distinct mutations are listed below. Equivalence is scoped to
the enforced input domain and approved preparation/race contract described in each
entry. This does not claim identical timing, internal bookkeeping or conservative
rejection behavior. Disjoint-bit OR/XOR cases are exact mathematical equivalences.

The 23 compiler-rejected mutants are separate from these survivors and from the
520 named-test failures. They are not counted as security checks caught by tests.
Historical line positions identify retained raw results; current production ranges
are recorded in the provenance JSON. Changed functions were freshly mutated.

Raw patches, logs, commands and per-mutant classifications are in
[verification-raw.tar.gz](1-6-evidence/verification-raw.tar.gz).

## 1. equivalent

Provider::expire_direct runs first using the same now and deadline map and persists terminal Expired before retain runs. At equality only terminal deadline bookkeeping persists one tick; approved_execution requires Approved and execution_authority independently rejects now >= deadline. No approved authority is retained; existing Story 1.5 reached the same classification. Deadline equality tests passed under the mutant.

- `src/access/application.rs:135:39: replace < with <= in ProviderApplication::expire_requests`

## 2. equivalent

The loaded Approved state has matching epoch by ProviderState::validate. DirectRecord::validate requires a matching Some approval for current ONE_TIME. A legacy record may have None only with legacy one_time, which the unchanged final OR rejects. Therefore (A || B || C) and ((A && B) || C) reject the same validated-state set and return the same category.

- `src/access/provider.rs:299:13: replace || with && in Provider::approved_execution`

## 3. equivalent

OR and XOR yield identical values because every involved Linux flag bit is disjoint (including conditional O_DIRECTORY); no shared bits can cancel. Exact flag constants and mutated patch are retained.

- `src/adapters/execution.rs:118:9: replace | with ^`
- `src/adapters/execution.rs:117:9: replace | with ^`
- `src/adapters/execution.rs:116:9: replace | with ^`
- `src/adapters/execution.rs:115:9: replace | with ^`
- `src/adapters/execution.rs:131:13: replace | with ^ in linux::open_at`
- `src/adapters/execution.rs:130:13: replace | with ^ in linux::open_at`
- `src/adapters/execution.rs:129:13: replace | with ^ in linux::open_at`
- `src/adapters/execution.rs:128:13: replace | with ^ in linux::open_at`
- `src/adapters/execution.rs:127:13: replace | with ^ in linux::open_at`
- `src/access/policy.rs:437:40: replace | with ^ in executable_identity_matches`

## 4. equivalent

Equivalent on the reachable input domain: the preceding path.is_absolute() != absolute check already rejects a RootDir component when absolute is false.

- `src/adapters/execution.rs:164:39: replace match guard absolute with true in linux::components`

## 5. equivalent

The first root walk now checks the final root with ancestor rules, but open_relative immediately rechecks that same retained root descriptor with private=true before opening any image component. Both original and mutant require provider-owned mode0700 root.

- `src/adapters/execution.rs:200:23: replace + with * in linux::open_source`

## 6. equivalent

MFD_CLOEXEC=0x1, MFD_ALLOW_SEALING=0x2 and MFD_EXEC=0x10 have disjoint bits; OR and XOR produce the same flags.

- `src/adapters/execution.rs:289:61: replace | with ^ in linux::snapshot`
- `src/adapters/execution.rs:289:35: replace | with ^ in linux::snapshot`

## 7. equivalent-to-approved-race-contract

Changes copy take(MAX+1) to take(MAX). Both descriptor metadata checks reject length>MAX; unchanged copied/before/after length comparisons reject truncation/growth; final sealed SHA-256 still requires exactly pinned bytes. At MAX, both copy all valid bytes. Any source race either rejects or yields the approved immutable bytes, as required by the frozen matrix.

- `src/adapters/execution.rs:299:70: replace + with * in linux::snapshot`

## 8. equivalent-to-approved-race-contract

The modified conservative metadata-comparison chain can change which in-flight source edits are rejected. Both source_metadata checks independently enforce file type, fixed provider UID, safe mode and size; copy remains bounded; all seals are required before the final SHA-256/ELF checks. Every successful capability therefore still contains exactly the declared pinned immutable bytes. The approved matrix expressly allows rejection OR unchanged pinned sealed bytes during source mutation. This is security-contract equivalence, not identical error/timing behavior. Aggregate deletion of stability checks is caught by the forced same-byte rewrite/timestamp test; any individual rerun actually caught by that test takes precedence over this classification.

- `src/adapters/execution.rs:310:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:309:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:308:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:307:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:306:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:305:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:304:13: replace || with && in linux::snapshot`
- `src/adapters/execution.rs:303:13: replace || with && in linux::snapshot`

## 9. equivalent

F_ADD_SEALS success returns0; a negative failure is ignored by this mutant, but the unchanged F_GET_SEALS bitmask readback requires every seal before yielding the prepared descriptor. A fresh memfd with failed installation cannot pass. This is equivalent for snapshot preparation; arbitrary already-sealed descriptors can differ in redundant installation-error behavior.

- `src/adapters/execution.rs:341:65: replace < with > in linux::seal_fd`

## 10. equivalent

An observed seal value0 already fails observed & SEALS != SEALS; adding zero to the explicit negative-value guard cannot change the result.

- `src/adapters/execution.rs:345:21: replace < with <= in linux::seal_fd`
- `src/adapters/execution.rs:358:21: replace < with <= in linux::execute_fd`

## 11. equivalent-to-protected-execution-contract

Preliminary pathname metadata and opened metadata duplicate regular-file/execute checks. The untouched counterpart rejects stable invalid input; adapter source_ok independently requires regular/provider-owned/readable/executable/nonwritable bytes before capability creation. In a pathname/mode race preliminary rejection timing can differ, so this is not claimed as observational equivalence of provisioning. The combined removal of both preliminary execute-mode guards is caught; every adapter ownership/type/mode omission is independently caught. These preliminary checks never certify execution.

- `src/access/policy.rs:431:40: replace || with && in executable_identity_matches`
- `src/access/policy.rs:431:59: replace & with | in executable_identity_matches`
- `src/access/policy.rs:431:59: replace & with ^ in executable_identity_matches`
- `src/access/policy.rs:446:9: replace || with && in executable_identity_matches`
- `src/access/policy.rs:445:9: replace || with && in executable_identity_matches`
- `src/access/policy.rs:445:26: replace & with | in executable_identity_matches`
- `src/access/policy.rs:445:26: replace & with ^ in executable_identity_matches`

## 12. equivalent-to-protected-execution-contract

Changes take(MAX+1) to take(MAX). The opened length guard rejects an already oversized source; the running total guard rejects excessive reads with the original bound. For a source that grows during preliminary hashing, the mutant can hash a MAX-sized prefix; protected preparation independently enforces source size and hashes the final sealed bytes. No oversized or different executable capability results. Observable preliminary race behavior can differ. Combined removal of all preliminary size bounds is caught using an oversized source with its correct digest.

- `src/access/policy.rs:450:58: replace + with * in executable_identity_matches`

## 13. equivalent

The only extra rejected input has length64. The unchanged positive program-count and phoff>=64/table-end bounds require at least120bytes, so no accepted ELF64 input has length64.

- `src/adapters/execution.rs:459:20: replace < with <= in linux::validate_elf_for_page_size`

## 14. equivalent

The added alignment1 case is a power of two, so !align.is_power_of_two() is false. Alignment0 remains excluded. The boolean result is identical.

- `src/adapters/execution.rs:514:27: replace > with >= in linux::validate_elf_for_page_size`

## 15. equivalent

Adding align1 to the guarded branch is equivalent:1 is a power of two and address%1 equals offset%1 (=0), so both rejection terms stay false.

- `src/adapters/execution.rs:548:31: replace > with >= in linux::validate_elf_for_page_size`

## 16. equivalent

The only additional overlap detected has a prior mapping start equal to the current mapping end. That is a descending adjacent mapping; the unchanged loads.last() order check already rejects its current page_start <= previous start. Ascending adjacent mappings still have page_start == previous stop and fail the unchanged first strict overlap predicate. All previously accepted sorted mappings remain accepted.

- `src/adapters/execution.rs:560:71: replace < with <= in linux::validate_elf_for_page_size`

## 17. equivalent-to-preparation-authority-contract

Only owned immutable policy/marker/iterator/boolean work under the authority gate separates this live check from the immediately preceding post-I/O check. Removing it changes when an asynchronous closure/deadline can be observed, not whether successful preparation requires live authority. The following post-I/O check always runs, including on errors, and the final durable binding revalidation remains. No secret resolution, dispatch or approval consumption occurs. This is preparation-contract redundancy, not identical timing or backend-call counts under asynchronous revocation; all nonredundant post-I/O/expiry/durable guards are independently caught. Story 1.7 must revalidate/consume dispatch authority.

- `auth_before_each_credential`
- `auth_before_probe`
