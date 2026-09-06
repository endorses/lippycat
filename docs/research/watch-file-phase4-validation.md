# Completed compact query and production-cutover verification

Date: 2026-09-06. Scope: Phase 4, milestone A of the compact source index plan.
Completed packet publication still follows analyzer EOF and finalization.

## Implementation and correctness

Compact queries scan authenticated row directories and compressed blocks in
bounded sequential batches. They materialize selected columns for structured
expressions, with complete bounded summary fallback for opaque predicates.
Every completed match contributes to full-match statistics. An implicit matching
prefix avoids writing any ID vector for all-match queries; other match IDs use
bounded buffered ordered u64 output. Query ownership, cancellation and pinned
export continue to use the completed dataset generation.

The filter compiler translates constructed immutable TUI filters, preserving
aliases and parser behavior instead of reparsing their display strings. Typed
related-flow matching normalizes IPv4-mapped addresses, compares both directions,
and preserves unknown-transport and empty-node wildcards while rejecting invalid
endpoints and zero ports. Dense bitsets and lazy related postings remain optional,
subject to measured benefit over this implementation.

## Measurement method

The acceptance runner compiles once per condition, warms the complete original
input before each fresh process, and runs three unprofiled measurements. Compiler
and profile costs are excluded. The legacy condition uses existing opaque filter
constructors; the compact condition compiles those same filters to expressions.
Controlled sparse/dense/all-match callbacks separately exercise fallback scans.
Readiness-only allocations are reported separately from allocations for the full
query/detail/export workload. Exact admitted ledger disk and memory high-water
marks supplement process RSS and sampled physical coexistence estimates.

No controlled cold-cache, persistent-reuse or Wireshark endpoint was available.
The first useful render measures PacketList.View at 120 by 40, excluding terminal
I/O. Base, application and full-analysis readiness still coincide in milestone A.

## Reproduction

```sh
python3 scripts/benchmark-offline-acceptance.py /path/to/capture.pcap \
  /tmp/phase4-legacy --backend legacy
python3 scripts/benchmark-offline-acceptance.py /path/to/capture.pcap \
  /tmp/phase4-compact --backend compact
```

The private capture and raw measurement/profile artifacts remain local. The final
results and production selection decision are recorded below.

## Initial matrix and profile-driven correction

The first six-process matrix preserved exact packet/event counts and the 89.46 MB
completed index. Compact readiness was 9.468 s versus 9.011 s legacy (+5.1%),
but the complete workload allocated 31.690 GB versus 18.733 GB. Related lookup
medians regressed 12.5–14.7%, and effective-byte export throughput was 71.12 MB/s
versus 129.10 MB/s. These results failed the predeclared tolerances, so production
cutover remained blocked while the measured costs were corrected.

A separate profile attributed 20.67 GiB cumulative allocations to compact query
scans, including 13.07 GiB in block reading and 7.47 GiB in inflation; raw export
allocated 3.10 GiB. Query scan CPU was 18.97 s cumulative, inflation 9.32 s,
and raw export 4.40 s. These overlapping CPU values are not wall times and must
not be summed. The initial raw artifacts are in local
`/tmp/lippycat-compact-phase4-{legacy,compact}/`.

The correction gives each scan reusable bounded input/output buffers and a
resettable inflater, retains only the current row block and two header slots,
and reuses the addressable row decoder scratch. Header reuse still validates
each directory entry checksum and original authenticated block header. Raw export
now decodes only source locators and capture fields, reads bounded groups of up to
64 effective records through owned backing leases, and buffers match-ID and
directory reads. It avoids stateless presentation decoding, complete row
materialization and repeated cache-copy allocation.

## Result representation decisions

The controlled 0.1%-density query writes 6,575 bytes, the 90%-density query
4,186,595 bytes, and the all-match query zero bytes. Counts are 580, 521,991 and
579,990 respectively. Sparse vectors preserve simple constant-memory random
page access and pinned export. The dense vector is about 2.1% of measured
compact admitted peak disk, so a second rank-indexed bitset representation was
not added in this phase. Repeated related queries use the same bounded scan;
postings remain deferred because this matrix does not establish sufficient
repeated interactive demand to justify another retained index and ownership path.

## Final acceptance measurements

All runs used the same private classic PCAP: 323,454,505 bytes, SHA-256
`53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`.
Host: Linux amd64, Intel Core i9-13900HX, 32 logical CPUs,
`go1.26.3-X:nodwarf5`, `all` tags, frozen default analysis, 10,000 retained
events, source backing, 64 MiB cache, 8 MiB record and 4 GiB disk limits.
Runs were grouped by condition on a shared host, without CPU affinity.

The final matrix used three fresh unprofiled processes for each backend. Every
run completed 579,990 logical packets and 44,873 arrived events; all filter and
related match counts matched. Raw artifacts and per-process resource records
are in `/tmp/lippycat-compact-phase4-final-legacy/` and
`/tmp/lippycat-compact-phase4-production-fixed-compact/`. The compact samples follow
final low-budget compatibility and replay-allocation fixes; the unchanged legacy branch uses its prior
three-run baseline.
[Sanitized measurements](watch-file-phase4-measurements.json) preserve every
per-run metric/resource sample and aggregate without private capture paths.

| Backend | Ready seconds, runs 1 / 2 / 3    | Median seconds | Peak RSS KiB, runs 1 / 2 / 3 |
| ------- | -------------------------------- | -------------- | ---------------------------- |
| legacy  | 8.959507 / 9.105576 / 8.978829   | 8.978829       | 217976 / 219748 / 224152     |
| compact | 10.120556 / 10.226828 / 9.939211 | 10.120556      | 134900 / 134460 / 127496     |

| Metric, median                                    |              Legacy |             Compact |
| ------------------------------------------------- | ------------------: | ------------------: |
| Completed storage bytes                           |         683,436,932 |          89,456,432 |
| Admitted peak disk bytes                          |       1,034,722,489 |         200,987,759 |
| Peak temporary/query excess above completed bytes |         351,285,557 |         111,531,327 |
| Combined disk lower bound including export bytes  |       1,034,722,489 |         412,910,851 |
| Admitted peak memory bytes                        |          67,108,864 |          53,473,716 |
| Accounted retained storage memory bytes           |          58,716,489 |           1,979,571 |
| Retained heap bytes                               |          79,765,256 |          14,123,448 |
| Readiness allocated bytes                         |       5,572,362,032 |       6,097,495,032 |
| Complete workload allocated bytes                 |      18,733,159,960 |       8,311,659,688 |
| Export effective MB/s                             |          128.771119 |          163.417203 |
| First page ms                                     |            0.245555 |            0.581260 |
| First rendered packet pane ms                     |            0.822095 |            0.636017 |
| First useful page from open seconds               |            8.979749 |           10.121899 |
| Random page within-run p50 / p95 ms               | 0.004315 / 0.005668 | 0.170725 / 0.184301 |
| Random detail within-run p50 / p95 ms             | 0.004251 / 0.008565 | 0.009232 / 0.013827 |

Query timings below are seconds. Each cell is fresh-process median / across-process
nearest-rank p95. With three processes, that p95 is the largest sample; random
page/detail p95 above instead measures the distribution inside each process.

| Query                     |        Legacy first |       Compact first |       Legacy repeat |      Compact repeat |
| ------------------------- | ------------------: | ------------------: | ------------------: | ------------------: |
| base-source               | 1.236205 / 1.400711 | 1.049540 / 1.099173 | 1.345886 / 1.439262 | 1.027464 / 1.037102 |
| application-protocol      | 1.121065 / 1.221064 | 0.973465 / 1.007978 | 1.143185 / 1.174053 | 0.956598 / 1.039954 |
| application-info          | 1.168578 / 1.179973 | 1.001355 / 1.048261 | 1.091071 / 1.247176 | 1.006894 / 1.015158 |
| application-http-metadata | 1.093227 / 1.094334 | 1.006377 / 1.012181 | 1.061953 / 1.084862 | 1.005992 / 1.011167 |
| related                   | 1.034562 / 1.092095 | 1.035362 / 1.113264 | 1.024658 / 1.061706 | 1.064873 / 1.167088 |
| controlled-density-sparse | 1.082631 / 1.116756 | 1.159188 / 1.162761 | 1.063784 / 1.108471 | 1.179381 / 1.191369 |
| controlled-density-dense  | 1.346557 / 1.367190 | 1.197175 / 1.203564 | 1.310042 / 1.392169 | 1.178853 / 1.181007 |
| controlled-density-all    | 1.269890 / 1.310748 | 1.189618 / 1.191955 | 1.300499 / 1.305878 | 1.171763 / 1.236867 |

Base/application filters, related lookup, random pages/details, export, RSS and
both allocation measurements pass their regression gates. Configured resource
limits pass, and completed storage is below 100 MB. The controlled opaque sparse
repeat timing exception is reported below.
The ledger peak includes buffered admissions and all owned index/scratch/query
files; it is not a physical filesystem allocation measure. Export output remains
outside the session disk budget. Combined peak is a lower bound, while admitted
session disk/memory high-water marks are exact.

Readiness misses the unchanged 10% tolerance: compact median 10.120556 s versus
8.978829 s (+12.716%); its limit is 9.876712 s, a 0.243844 s miss. The first useful
page from open inherits this delay. First-render median passes; across-process
p95 is 1.423719 ms versus 1.423995 ms legacy, with a 2.566394 ms limit.
The final render endpoint passes.
Timing misses are recorded failures, not relabeled passes. The independent
three-second engineering readiness target also remains unmet. No reruns were
selected to conceal these misses. The prior post-optimization matrix had
10.209354 s compact readiness and a 0.043293 ms render-p95 tolerance miss; all its
samples remain in the measurement JSON. The final remeasurement was required by
post-cutover low-budget fixes, and replaces the entire compact sample set.

The controlled opaque sparse repeat median is 1.179381 s versus 1.063784 s
legacy (+10.864%), exceeding its 10% + 1 ms comparison by 0.008219 s. Its first
query, across-process p95, and dense/all-match endpoints pass. This small fallback
timing gap is retained alongside the readiness gap; no query result or resource
limit differs. Construction allocations are back within tolerance at
6,097,495,032 bytes versus 5,572,362,032 bytes (+9.424%), and complete-workload
allocations are 8,311,659,688 bytes versus 18,733,159,960 bytes.

Engineering disposition: accept milestone-A cutover after exact parity and hard
resource/ownership gates pass, retaining these timing gaps for phase 6. The
storage, allocation, RSS and export gains justify completed-dataset adoption;
readiness still includes serialization, compression and ordered protocol analysis.
This does not change the predeclared thresholds or claim three-second readiness.

Measurement identities (full working-tree patch and untracked hashes retained locally):

- legacy: revision `4c869de86aaa84377519ffc5338855d54f42eb6d`, tracked patch SHA-256 `945319884938349325f3afc87fdd0bca66f1a70524423e504a055cf8a663a9c3`, binary SHA-256 `25d72ba6d673443463c7967f730fc7ea254bcd89d06b1abe9ddfebc35d50dc9f`.
- compact: revision `4c869de86aaa84377519ffc5338855d54f42eb6d`, tracked patch SHA-256 `3f2f97d376c8de08441e44f1f53d28c16b2b5b10ab2a593f6e50bdd6bc185d5e`, binary SHA-256 `db49594bc7184d13db50493285bb794a2b02e42c243a8d10d14170215dde62f4`.

The original working-tree baseline was revision
`4c869de86aaa84377519ffc5338855d54f42eb6d`, with preexisting tracked patch SHA-256
`08493f5079ae66f028c4da0a07a7896cdfa7246dd82e2a272869fe73fe247f59`.
The unrelated tracked and untracked baseline changes were preserved separately
from the phase implementation; measured patch identities above include this work.

A separate final readiness profile reported 9.755 s readiness and the same
89,456,432 completed bytes, and is excluded from the three-run medians. Its
cumulative CPU attributed 3.52 s to `AppendCompact`, 1.87 s to `flushCompact`,
2.28 s to event-analysis `ObservePacket`, and 2.99 s to GC scanning. These
consistent serialization/compression and ordered-analysis costs identify remaining
work without attributing query acceleration to faster analyzer completion.

## Production selection and validation

The production entry point unconditionally selects locator ordering and compact
storage. Migration flags were removed from the frozen analysis configuration;
legacy and locator-stage wrappers now live only in test files. Differential tests
name the legacy builder explicitly, so changing production selection cannot turn
the oracle into a comparison of two compact builds.

A new production test verifies schema-2 complete manifests with both completion
flags, explicit source-change errors after truncation, and snapshot independence
from later original-file truncation. The compact, locator, phase-timing and
production-backing tests passed after cutover. The exhaustive private-capture
oracle passed with all 579,990 logical records, complete order/source/raw-byte
identity, summaries/accessors, filters/statistics, detail metadata, deterministic
events, calls and exports. It compared 10,000 retained events, 44,873 arrived
events and one retained call under the existing capped-history policy. Its
production-default test binary SHA-256 was
`05c1846f8a1b8b710b01704d35d1dacce556a86e140cf2c25af889f7882eb0bd`.
The private test log remains `/tmp/lippycat-compact-phase4-private-parity.log`.

Full verification caught two additional cutover issues. The cleanup regression
assumed the builder directory already existed during initial opening progress;
it now waits for that directory before testing permission-denied cleanup and
retry. Its failure/retry assertions remain intact. A valid 128 KiB cache with
16 KiB record budget could not fit compact writer/read-ahead reservations.

For caches below 16 MiB, construction now releases completed stateless decoder
scratch before flushing, flushes buffered rows earlier, and relies on the block
writer's existing transposition reservation rather than charging the same output
scratch twice. Uncompressed readers avoid reserving an unused inflater; if a
compressed block is encountered, inflater memory is admitted before allocation.
Locator replay scales optional read-ahead to the shared budget. The default
64 MiB path retains the original block thresholds, five-record writer scratch,
eager inflater reservation, 16 KiB readers, 64-key batch and 1 MiB prefetch.
Independent review checked admission before allocation and balanced release.
The 128 KiB lifecycle regression now exercises build/query/page/detail/raw export.

After these corrections, the required full package suite, offline/capture/TUI
race suite, watch command (`tui` tags) and `make build` passed. Build exited zero
with a nonfatal sandbox Go stat-cache write warning. Parent verification logs
remain in `/tmp/phase4-final-{packages,race,watch,build}.log`. The default-budget
private oracle predates these low-budget-only branches; their default-path
behavior is unchanged and the final package/race suites cover the new branches.
A final three-process compact remeasurement followed the corrections, preserving
all prior samples and reusing the unchanged legacy baseline; it is not selection
of the fastest earlier runs.

The required post-fix remeasurement revealed a second allocation issue: dynamically
sized replay key/locator slices were allocated inside every batch. This added
about 150 MB during construction despite unchanged default batch sizes, reaching
6.246 GB versus 5.572 GB baseline (+12.09%) and missing the construction
allocation tolerance. Replay now allocates the already-admitted capacities once and resets them only after
the previous batch lease and independent packet handoff complete. Focused capture
race and production/TUI release tests passed after this correction. A full
three-process corrected compact condition replaces the preceding condition;
the intervening samples remain under `budget_fix_matrix` in the measurement JSON.

## Follow-up assessment (2026-09-06)

Three independent sub-agents reviewed filter compilation, block queries and
resource/ownership behavior, and production cutover/documentation. Parent review
verified their findings against the implementation and tests. One compatibility
defect was confirmed: a filter accepted by the existing parser could exceed the
structured-expression representation limits, causing the TUI to reject it before
starting a query instead of using its existing opaque predicate fallback.

The reproduction uses 65 `NOT` operators followed by `impossible`. Parsing and
the legacy predicate succeed, but the new TUI regression failed because no
offline query started. Both the parent and a second reviewer reproduced that
failure before the fix. Expression representation limits now have a dedicated
error sentinel; the filter-chain adapter maps only that error to opaque fallback.
Invalid-expression errors and backend resource limits remain enforced.

Regression coverage includes expression depth, a 257-filter stack, oversized
text, invalid numeric comparison errors, and end-to-end TUI query completion,
match statistics and installed filter state. The formerly failing reproduction
passes after the fix. No other phase-4 defect was substantiated.

The parent ran the plan's full package gate, offline/capture/TUI race gate and
complete build before the fix. After the fix, the full offline and TUI package
trees, affected expression/filter/TUI race tests and complete build passed.
A second reviewer independently reran the focused regressions and reviewed the
final diff. Builds exited successfully with a nonfatal sandbox Go stat-cache
write warning. Go files were formatted and the diff passed whitespace checks.

This assessment did not rerun the private-capture oracle or performance matrix.
Their recorded results and the explicitly deferred readiness/sparse-fallback
timing gaps above remain unchanged. Preexisting unrelated working-tree changes
were preserved.
