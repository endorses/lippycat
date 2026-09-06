# Compact source-backed offline index implementation plan

Status: Phases 0–4 complete; phase 5 and the remaining phase-6 gates are pending.
Scope: `lc watch file`.

Phase 0 establishes the baseline, injectable differential oracle, measurement
runner, v2 schema, field inventory and source/resource contracts. Verification
includes the private capture, three fresh unprofiled matrix runs, a separate
profile run, package/race gates and build. The oracle exposed a source-ordering
defect, corrected in `52456e0e` after explicit authorization. See
[baseline, measurements and verification](../research/watch-file-phase0-baseline.md)
for exact results and unavailable endpoints. Compact-backend parity and
production cutover remain later-phase gates.

## Objective and evidence

Replace the eager serialized packet database with a compact index that references
unchanged source bytes, retains exceptional bytes and finalized stateful metadata,
and reconstructs stateless presentation details on demand. Preserve normalized
packet identity, ordering, filters, statistics, event identities and export bytes.

Read these documents before implementation:

| Document                                                                                     | Role                                                                                |
| -------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------- |
| [Compact index investigation](../research/watch-file-compact-index-design.md)                | Primary design, feasibility measurements, source lifetime and readiness constraints |
| [Real-capture performance investigation](../research/watch-file-real-capture-performance.md) | Production baseline, profiling and reproduction command                             |
| [Offline contracts](../design/watch-file-offline-contracts.md)                               | Field/filter semantics, ownership, budgets and publication behavior                 |
| [Current storage format](../design/offline-storage-format.md)                                | Existing codec and integrity contract to replace explicitly                         |

The reported capture is 323,454,505 bytes. The current normalizer emits 579,990
logical packets and 44,873 events; the measured warm full-index median is 10.26 s
and completed storage is 683,436,932 bytes. The research prototype scans physical
frames in approximately 0.25 s but omits normalization and application analysis.
Its 579,991 physical frames are not the logical dataset. Do not use prototype
latency or row size as a production acceptance result.

The existing uncommitted performance fixes, tests and research are the comparison
baseline. Preserve them. Record the commit plus working-tree patch identity used
for measurements; do not reset, stage or commit unrelated changes with this work.

## Scope and implementation decisions

The first deliverable replaces storage and query costs while retaining publication
only after analyzer EOF. A second deliverable introduces complete-base browsing
with an atomic analysis overlay. Persistent reuse and further parallelism are
conditional follow-up work, not prerequisites for the storage replacement.

| Area              | Decision                                                                                                                                                                                                                                            |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Backend migration | Evolve `diskDataset`/`diskQuery` in place, retaining the legacy builder/codec as a test oracle during migration. Select the new path internally for tests until the replacement passes its gate; do not add a temporary user-facing backend switch. |
| Source bytes      | Dataset-owned open handles with bounded read leases; never reopen a source path to satisfy an existing locator. Derived and decompressed backing belongs to the same lifetime.                                                                      |
| Normalization     | Preserve BPF on original frames, then existing normalization. Explicit provenance determines whether output is source-backed; transformed output defaults to derived backing.                                                                       |
| Order             | Validate the entire normalized stream before stateful analysis. Ordered single input needs no sort; ordered multiple inputs use a bounded merge; regressions use external locator-key sorting.                                                      |
| Persistence       | New versioned typed blocks, bounded variable arenas and sparse metadata. No full `PacketDisplay` records, unsafe struct dumps or unbounded string dictionaries in the final production path.                                                        |
| Details           | Frozen configuration plus stateless decoding and finalized metadata; selection never advances a detector, tracker or reassembly engine.                                                                                                             |
| Queries           | Structured expressions for the TUI fast path, with compatible opaque `QuerySpec.Match` fallback. Keep existing accepted syntax and quirks.                                                                                                          |
| Readiness         | Completed-only behavior through milestone A; complete ordered base plus immutable analysis revision in milestone B. No provisional packet IDs before the base scan finishes.                                                                        |
| Format support    | Preserve current classic PCAP, supported PCAPNG and gzip classic PCAP boundaries. Multiple PCAPNG sections/interfaces and gzip PCAPNG remain separate work.                                                                                         |

Source-backed storage intentionally changes independence from source files. Detect
mutation/truncation and return explicit errors. Renamed/unlinked files may remain
readable through owned handles where the platform permits. A snapshot backing
policy must be specified before enabling source-backed production reads; if a
copy is required, create and validate it before indexing and charge its full cost.
Do not silently switch to a fresh copy after detecting mutation.

## Milestones and dependencies

| Phase | Deliverable                                                | Prerequisite | Completion gate                                                   |
| ----- | ---------------------------------------------------------- | ------------ | ----------------------------------------------------------------- |
| 0     | Baseline, differential oracle and format/lifetime contract | None         | Reproducible comparisons and reviewed schema                      |
| 1     | Validated source and derived locators                      | 0            | Reader, provenance, mutation and ownership parity                 |
| 2     | Locator-only ordering and scan-integrated identity         | 1            | Stable normalized replay without all-packet raw spool             |
| 3     | Compact completed dataset, lazy details and raw export     | 2            | Full semantic parity and bounded resource accounting              |
| 4     | Block queries and production cutover: milestone A          | 3            | Correctness suite and measured completed-ready performance        |
| 5     | Complete-base browsing: milestone B                        | 4            | Revision-safe operations and failure/cancellation lifecycle       |
| 6     | Profile-driven follow-ups and final acceptance             | 5            | Documented measurements and explicit disposition of optional work |

Each phase is a reviewable implementation unit; split it into smaller commits as
needed. Keep the completed-dataset gate intact until phase 5. A missed performance
target requires profiling and a documented gap; a correctness or resource-budget
failure blocks production cutover.

## Phase 0 — Establish the oracle and contracts

Touchpoints: `internal/pkg/tui/offline_file_benchmark_test.go`, existing
`offline_release_*` tests, `internal/pkg/offline/phase6_benchmark_test.go`,
`docs/design/watch-file-offline-contracts.md`, and
`docs/design/offline-storage-format.md`.

- [x] Record baseline revision/patch identity, Go version, build tags, host, capture identity, frozen configuration, cache conditions and resource limits. Preserve the real-capture benchmark command from the performance investigation.
- [x] Extend the end-to-end harness to measure the acceptance matrix below, with phase timings around identity/scan, ordering, analysis, finalization and first page. Use fresh processes and at least three unprofiled runs per condition; profile separately.
- [x] Add a legacy-versus-compact comparison harness using synthetic fixtures and the local private capture when available. Compare every logical record's order, source argument/sequence, timestamp, lengths, effective link type and raw-byte digest; compare field accessors, filter IDs, detail metadata, statistics, events/calls and export records separately.
- [x] Specify schema v2: source/backing/context IDs, physical ordinal versus logical sequence, locator bounds, timestamp precision, original/effective lengths and link types, typed columns, presence flags, text/metadata references, checksums, manifest versions and completion markers. Reserve explicit version handling; reject incompatible data rather than interpreting v1 as v2.
- [x] Inventory each `PacketDisplay` field as source-decodable, finalized stateful metadata, derived content or presentation-only. Record its list/filter/detail consumers and readiness dependency. Preserve the distinction between packet-local metadata and normalized event metadata.
- [x] Specify memory and disk accounting for block buffers, arenas, dictionaries, sort runs, prefetch, derived/spool bytes, queries, pins and retained replacement sessions. Charge buffered bytes on admission, before flush; validate lengths and arithmetic before allocation or I/O.
- [x] Specify the source-change error contract and explicit source/snapshot backing policy, including settings plumbing, ownership, compressed-input identity and failed-copy cleanup. Record numeric benchmark regression tolerances before evaluating new results.

Gate: the oracle reproduces current behavior, and the schema accounts for all
observable fields and all storage, not merely the illustrative 112-byte core.

Phase-0 review (2026-09-06) confirmed the oracle and contracts and corrected two
measurement-runner issues: accept Go's unsuffixed benchmark name for
`GOMAXPROCS=1`, and include across-process nearest-rank p95 in `summary.json`,
excluding profiled runs. The recorded baseline samples remain unchanged. Focused
Python regression checks and the Go oracle/release tests, including the race
detector, passed.

## Phase 1 — Add owned backings and normalization provenance

Touchpoints: `internal/pkg/capture/pcaptypes/offline.go`,
`internal/pkg/capture/offline_cursor.go`, `internal/pkg/capture/offline_ng.go`,
`internal/pkg/capture/capture.go` (`PacketInfo`) and normalization producers, `internal/pkg/pipeline/captureadapter/`,
and `internal/pkg/offline/{contracts,storage,scratch}.go`. Add focused backing and
locator files in the existing packages rather than moving capture into the TUI.

- [x] Add parser-consumed classic-PCAP payload offsets and physical ordinals. Preserve byte order, micro/nanosecond precision, capture metadata and malformed/truncated-input errors. Never derive offsets from a buffered file descriptor's current seek position.
- [x] Add checked PCAPNG block/payload locators with existing interface, timestamp-resolution/time-offset and missing-timestamp semantics. Validate padding and block bounds; retain current unsupported-format errors.
- [x] Introduce a backing registry and bounded `ReadAt`-style reads with owned handles, source identity checks, per-record integrity verification and explicit close/lease behavior. Transfer ownership before `offlineCursor.Close` would close inputs at scan EOF. Validate indexes and referenced bytes before exposing them to detail/export readers.
- [x] Implement one seekable decompressed backing spool for gzip classic PCAP. Hash original compressed input, validate decompression completion, and account for both spool and temporary peak disk.
- [x] Propagate provenance through filtering, fragment completion, VXLAN extraction and ESP transformations. Unchanged output retains its source locator; changed/reassembled output receives derived backing. A subslice of derived data must remain derived through nested transformations.
- [x] Preserve original source context separately from effective decoding context and logical emission sequence. Repeated input arguments remain distinct even when their paths or underlying files are equal.
- [x] Implement the phase-0 backing policy and tests for rename, replacement, unlink where supported, truncation, same-size in-place mutation, snapshot failures, cancellation and pinned-reader shutdown. Preserve cleanup errors and retry ownership.

Gate: every emitted normalized packet can be reread byte-for-byte with its exact
capture metadata, and no reader obtains bytes from a replacement path.

Phase-1 implementation and review: see [verification](../research/watch-file-phase1-validation.md).
The locator path is internally opt-in; legacy sorting and completed production
datasets retain their existing behavior until the later migration gates.

Phase-1 follow-up review (2026-09-06) used three independent agents for readers,
backing ownership and normalization provenance, with parent verification. It
found and fixed one reader defect: nested gzip was decompressed twice in the
locator path, producing offsets into the wrong backing. Nested gzip now retains
the legacy unsupported-format rejection. Regression coverage for legacy, source
and snapshot modes failed before the fix and passed afterward. No other Phase-1
defects were found. Package and race gates, the watch command check and the
complete build passed; unrelated working-tree changes were preserved.

## Phase 2 — Replace raw sorting spools with locator ordering

Touchpoints: `internal/pkg/capture/offline_sort.go`, `offline_cursor.go`,
`internal/pkg/events` offline identity helpers, and
`internal/pkg/tui/offline_indexer.go` (`indexOfflineDataset`).

- [x] Fuse original-byte SHA256 calculation into each mandatory source scan while preserving the existing per-file aggregation and input-argument ordering. Preserve caller-supplied input identity behavior. Split scan/order preparation from replay and move producer/runtime initialization after the hashes finalize; adding a hashing reader alone is insufficient. Complete identity before constructing deterministic event production.
- [x] Replace raw-spool offsets in sort keys with validated backing references and source context. Retain timestamp, argument index and logical sequence as the stable comparator.
- [x] Track monotonicity after normalization. Implement direct iteration for one ordered input, bounded heap merge for individually ordered inputs, and external compact-key sort when any input regresses, including at EOF.
- [x] Finalize packet IDs only after global ordering is known. Replay through the existing analysis envelope without changing BPF ordering, timestamps, reassembly domains or source attribution.
- [x] Add byte-bounded read coalescing/prefetch with explicit buffer ownership. Account for merge buffers, sort runs and temporary coexistence; propagate read, write, flush and cancellation failures.
- [x] Compare all three ordering paths against the legacy sorter for equal timestamps, duplicate arguments, interleaved inputs, late regressions, fragments and nested transformations. Compare TCP/SIP outcomes and deterministic event identities as well as packet order.

Gate: ordinary packets are no longer copied into an all-packet sorting spool;
full-ready publication and analysis order still match the baseline.

Phase-2 implementation and independent review: see [verification](../research/watch-file-phase2-validation.md).
The prepared locator stream is internally opt-in; completed production datasets
continue to use the legacy oracle until the later storage and cutover gates.

## Phase 3 — Store compact records and materialize details lazily

Touchpoints: `internal/pkg/offline/{storage,codec,summary,amendment,cache,contracts}.go`,
`internal/pkg/tui/{offline_indexer,offline_sip,offline_export}.go` and packet-local
decoding helpers used by the indexer.

- [x] Implement schema-v2 buffered typed blocks, direct row/block lookup and checksums with bounded text arenas and sparse protocol metadata. Deduplicate low-cardinality source/interface/node data; spill high-cardinality text rather than retaining a dataset-sized map.
- [x] Persist the exact searchable projection, including Info text, address rendering, missing-versus-zero ports, metadata-presence bits and protocol-specific field quirks. Keep `Summary` accessors free of I/O after page/query materialization.
- [x] Replace `Builder.UpdateDetail` full-record rewrites with narrow packet-ID metadata amendments. Finalize late SIP/EOF updates before publication; retain reassembled messages, RTP attribution and TLS decryption results that cannot be decoded from one packet.
- [x] Define an injected stateless decoder contract in `offline`, configured by the TUI adapter. `capture` already imports `offline`, so the backend must not import capture or TUI helpers. Extract a stateless detail materializer using owned effective bytes, frozen settings and finalized metadata. Do not retain live protocol detectors or mutate stream state. Preserve owned `Detail.Packet` bytes and exact visible field semantics.
- [x] Adapt cache keys, `DetailPin`, page leases and transient accounting to compact blocks and materialized details. Bound cache, decode scratch, in-flight reads and pins together; fail explicitly on an oversized first row/record.
- [x] Introduce a raw-record iterator carrying packet ID, effective bytes, timestamp, lengths and link type. Route `exportOfflinePCAP`/`writeOfflinePCAP` through it while preserving query order, cancellation, mixed-link-type behavior and existing output-file failure handling.
- [x] Update `AllPackets`, `PinQuery`, query iteration and concrete backend helpers for the new storage. Preserve implicit identity queries and acquire export ownership before scheduling asynchronous work.
- [x] Preserve builder poisoning after write failure and the `Finish` flush/sync/close/read-only reopen/atomic manifest sequence. Rebuild finalized statistics after metadata amendments before publishing the completed dataset.
- [x] Validate malformed block headers/references, overflow, checksum failure, short reads/writes, flush/finalization failure, disk exhaustion and cleanup retry. A failed build must never publish a completed manifest.
- [x] Run the differential corpus, including random/repeated detail requests under changing live settings, EOF amendments, concurrent pinned export and session replacement. Measure complete index/sidecar size and full-ready time before changing readiness.

Gate: compact completed datasets match the oracle for all existing operations;
unchanged packet bytes and full presentation records are absent from persisted
production storage. All exceptional retained content is included in accounting.

Phase-3 implementation, independent review, full differential verification and
measurements: see [verification](../research/watch-file-phase3-validation.md).
The unshipped v2 layout was refined to combined typed columns, block-local arenas
and an authenticated direct row directory; the storage specification describes
the actual format. The compact candidate remains internal and completed-only.
Private-capture parity passed, but readiness/allocation tolerances and the
100 MB storage target were missed. The measured serialization/representation
gaps must be addressed before phase-4 production cutover.

Phase-3 follow-up assessment (2026-09-06) found and corrected invalid-input
publication and allocation-before-admission gaps. Three independent reviewers
and parent verification found no additional substantiated phase-3 defect. See
the [follow-up assessment](../research/watch-file-phase3-validation.md#follow-up-assessment-2026-09-06)
for reproductions, fixes and verification; the completed checklist remains valid.

A second phase-3 assessment confirmed a combined-detail budget defect in narrow
VoIP amendments. Finalization now validates the materialized amended range before
publication, rejecting rows whose combined raw bytes and metadata exceed the
record budget. The range uses constant memory; sparse amendments may validate
intervening rows. See the verification document for regression evidence.

The [performance follow-up](../research/watch-file-compact-performance.md)
reduced measured compact readiness from 21.94 s to 10.56 s, completed storage
from 301.8 MB to 89.5 MB and allocations from 9.24 GB to 6.10 GB. Full private
parity passed after correcting nondeterministic SDP endpoint presentation.
The three-second engineering target remains unmet; these results do not complete
the remaining Phase 4 query and production-cutover gates.

## Phase 4 — Accelerate complete-file queries and cut over

Touchpoints: `internal/pkg/offline/{query,query_pin,statistics,summary,contracts}.go`,
`internal/pkg/tui/filters/`, and the TUI offline filter/query adapters.

- [x] Add sequential block scanning and buffered ordered match output. Keep all-match queries implicit. Start with bounded sparse ID vectors; implement dense bitsets with block rank counts only if measured density/storage benefits justify the additional page-lookup path.
- [x] Define a validated filter expression in a package usable by offline storage without importing the TUI. Compile immutable TUI filter snapshots to it, preserving aliases, boolean/stack behavior, numeric epsilon, metadata presence, text matching and current BPF-subset quirks; retain opaque predicate fallback.
- [x] Select only required columns/arenas for supported expressions. Keep fallback materialization bounded and compare both paths against existing filter constructors, including missing/empty values and unsupported syntax.
- [x] Implement typed bidirectional related-flow comparison with mapped-IPv4 normalization, missing-node/unknown-transport wildcards and invalid-endpoint/zero-port rejection. Add lazy postings only after repeated-lookup benchmarks justify them.
- [x] Preserve completed full-match statistics, cancellation/progress semantics and the prior query on failed or cancelled filtering. Verify random result pages and concurrent pinned export for every chosen result representation.
- [x] Run milestone-A correctness, race and performance checks. Make the compact backend the production path only after parity and resource gates pass; remove migration-only production switches and keep a test oracle or frozen fixtures for regression coverage.
- [x] Update offline contracts, storage-format documentation and source-lifetime/operator documentation to describe actual completed-dataset behavior. Record measured gains and any remaining target gap.

Gate: completed-ready production behavior remains equivalent, with end-to-end
query/detail/export performance evaluated against the predeclared tolerances.

Phase-4 implementation and independent sub-agent reviews were verified by the
parent, including full package/race/build gates and exact private-capture parity.
See [measurements and verification](../research/watch-file-phase4-validation.md).
Production now uses completed compact datasets with structured block queries and
bounded opaque fallback. Sparse vectors and implicit all-match results are the
measured representations; dense bitsets and related postings remain deferred.
Source and snapshot behavior is documented. Configured resource limits pass;
remaining readiness and sparse-fallback timing gaps are explicitly recorded,
without changing the tolerances or claiming the three-second target. Publication still
waits for analyzer EOF; phase 5 has not begun.

Phase-4 follow-up assessment (2026-09-06) used three independent sub-agents and
parent verification. It found one compatibility defect: accepted filters that
exceeded structured-expression limits aborted instead of using the opaque
predicate fallback. The adapter now falls back only for representation-limit
errors, preserving other compiler errors and backend budgets. See the
[follow-up verification](../research/watch-file-phase4-validation.md#follow-up-assessment-2026-09-06).
No additional phase-4 defect was substantiated.

## Phase 5 — Publish a complete base before analysis finishes

Touchpoints: `internal/pkg/offline/contracts.go`, manifest/cache/query ownership,
`internal/pkg/tui/{offline_indexer,offline_lifecycle,offline_export,offline_event}.go`,
offline page/detail/filter message handlers and watch-file user documentation.

- [ ] Refactor construction into complete scan/order/base finalization followed by bounded ordered analysis. Publish only the immutable complete base; never expose provisional logical IDs during scanning.
- [ ] Introduce analysis revision in request/result tokens, query/detail/export pins, cache keys and stale-result checks. Define the base-only revision and first completed revision explicitly; publish the completed overlay, protocol statistics and bounded event/call views atomically.
- [ ] Apply the phase-0 field dependency inventory to navigation, detail, filtering, statistics and export. Offer complete base-field operations while analysis runs; show dependent operations/fields as pending. Treat Protocol and Info as dependent unless their base equivalence is proven.
- [ ] Keep raw unfiltered export available from the base. Pin analysis-dependent filtered export to a completed revision; never silently change matches or metadata during iteration. Reissue active UI queries explicitly on revision transition while preserving valid selection IDs.
- [ ] Define lifecycle behavior for base success followed by analysis failure/cancellation: retain the valid base with an explicit status, release failed overlay resources, and preserve previously pinned revisions until their owners close.
- [ ] Extend session transfer/close ownership so cancellation, rapid reopen, stale completion, mode switch and quit cancel and join analysis/readers before closing backing handles. Keep blocking cleanup outside Bubble Tea Update and retain retryable cleanup failures.
- [ ] Add lifecycle/race tests for stale revision errors and successes, filter requests while pending, late overlay publication, pinned export across revision change, analyzer EOF failure and replacement during background analysis.
- [ ] Document and measure complete-base time, first useful page and completed-analysis time separately. Do not relabel faster browsing as faster full analysis.

Gate: no partial query is presented as complete, no unfinished metadata is treated
as absent, and a pinned operation sees one immutable generation/revision pair.

## Phase 6 — Validate remaining costs and optional follow-ups

- [x] Profile the new completed-analysis path and remove duplicated protocol work only where measurements identify a worthwhile cost. Compare event/detail semantics after each change.
- [x] Evaluate bounded stateless parallel work with deterministic ordered output. Keep stateful analysis serial unless a separate design proves per-flow ownership, deterministic event admission and merge behavior.
- [ ] Decide whether persistent reuse is justified by repeat-open measurements. If deferred, record the reason; if implemented, key it by exact ordered input identity, schema/normalization/analyzer versions, BPF and frozen settings/key-material identity without persisting secrets.
- [ ] For an implemented cache, require verified sources, atomic complete manifests, independent base/analysis completeness, bounded eviction and leases. Test stale/corrupt entries, source mutation, settings changes and concurrent readers. Report verification cost as part of repeat-open latency.
- [ ] Run the final acceptance matrix, publish measurements and explicitly report unmet targets plus the next measured bottleneck. Update documentation and remove obsolete migration code once its oracle coverage is retained.
- [ ] Format changed files before staging. Check off only verified tasks, and commit the implementation and updated plan in scoped commits as required by repository instructions; exclude unrelated baseline changes.

## Validation corpus and acceptance matrix

The profile-driven completed-open follow-up was brought forward at the user's
request, without implementing phase 5. Ordered stateful analysis remains serial;
bounded analysis/storage workers and allocation reductions lower warm completion
to a 3.622 s median. The 3.0 s target remains unmet. See
[implementation and verification](../research/watch-file-three-second-open.md)
and the [scoped plan](watch-file-three-second-open.md). This does not complete
phase 6 or its phase-5-dependent acceptance gates.

Synthetic fixtures must be distributable; keep the private capture and profile
artifacts local. If the reported capture is unavailable, complete synthetic
validation and record real-capture acceptance as unverified.

| Coverage            | Required cases/results                                                                                                                                                                                                        |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Readers             | Both classic byte orders and precisions; existing PCAPNG packet types/timestamp rules; gzip classic; empty/BPF-empty/truncated/malformed input; unchanged unsupported-format rejection                                        |
| Normalization/order | BPF before transforms; IPv4/IPv6 fragments; VXLAN; ESP; nested derived transforms; equal timestamps; late regressions; multi-input merge; duplicate arguments; exact effective export bytes                                   |
| Protocol semantics  | Missing and empty metadata; all documented filter families; nonstandard ports; SIP TCP segmentation/retransmission/idle expiry/EOF amendment; RTP attribution; TLS keys/decryption; HTTP/DNS/email details and event identity |
| Ownership/integrity | Source mutation/replacement/truncation; corrupt blocks/locators; short I/O/flush failure; budget exhaustion; cancelled/stale queries; pinned detail/export; rapid reopen; failed cleanup retry; race detector                 |
| Scaling             | Increasing packet counts, ordered and disordered inputs, sparse/dense/all-match queries, long unique text and derived-heavy inputs; bounded retained memory and explicitly measured analyzer overhead                         |

| Measurement          | Acceptance/reporting rule                                                                                                                                                                                       |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Semantic parity      | Exact normalized identity/order/bytes, filter matches, field presence, statistics and deterministic event results; explain any intentional existing capped-history behavior                                     |
| Full readiness       | Engineering target near 3 s on the reported capture and comparable host/settings; median of at least three warm fresh-process runs; report every run and any missed target                                      |
| Complete storage     | Target below 100 MB decimal on that capture, including manifests, columns, text, order maps, metadata and exceptional sidecars; report query files and temporary peak disk separately, plus their combined peak |
| Query/detail/export  | First and repeated base/application filters, related lookup, random detail/page latency and export throughput against baseline tolerances; completed match counts/statistics required                           |
| Readiness            | Complete base, first useful rendered page, analysis-dependent filter readiness and full analysis completion measured separately                                                                                 |
| Resources            | Peak RSS, cumulative allocations, retained/accounted memory, completed disk and temporary peak disk; no dataset-sized heap indexes or unbounded arenas                                                          |
| Cold/repeat opens    | Record reproducible cache preparation and filesystem conditions; label unavailable cold measurements honestly; include content verification in persistent-cache timing                                          |
| Wireshark comparison | Record version, settings/dissectors/name resolution, same input and readiness endpoint; user-observed 3 s remains unverified until a controlled comparison exists                                               |

Run focused tests while implementing each phase, then this package-level gate
from the repository root (request sandbox escalation if required):

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/pipeline/... \
  ./internal/pkg/events/... ./internal/pkg/eventanalysis ./internal/pkg/tui/...

GOCACHE=/tmp/lippycat-go-cache go test -race -tags all \
  ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/tui

make build
```

Add affected command/build-tag checks if shared capture or adapter contracts
change. These commands are future verification steps, not checks already run.
For production timing use the reproduction command in the performance research;
exclude compilation and profiling overhead, and add a separate first-render
measurement rather than inferring it from worker completion.
