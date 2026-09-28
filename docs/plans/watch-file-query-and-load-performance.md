# Watch File Query and Load Performance Plan

**Date:** 2026-09-28

**Status:** Implemented and verified

**Code baseline:** `5dc86651`

## Goal and scope

Reduce demonstrated overhead when `lc watch file` indexes a capture and applies a display filter. Preserve packet order, complete analysis, integrity validation, cancellation, atomic publication, and configured memory and disk limits. Measure elapsed time and resource use, but do not treat any particular speedup, throughput, RSS value, or comparison with another tool as an acceptance gate.

The first implementation is deliberately bounded: establish a reproducible filter benchmark, avoid unnecessary RADIUS decoding, evaluate a compact-block header cache against the integrity contract, and parallelize compact query scans where the storage budget admits it. Re-profile once after these changes. Progressive display, a new index format, a single-pass indexer, and shared packet dispatch are separate design decisions described under [Later work](#later-work); they are not prerequisites for this implementation.

Do not add packet contents, capture paths, host addresses, user identities, credentials, machine-identifying profile output, or raw benchmark artifacts to the repository. Use synthetic fixtures in committed tests. Local capture benchmarks may use `LIPPYCAT_BENCH_PCAP`; report only aggregate timing, counts, allocation, and resource usage.

## Existing contracts to preserve

- `internal/pkg/offline/query.go` publishes a completed, immutable query or an error. The previous filter remains visible until replacement succeeds. A cancelled or failed scan must not expose partial results.
- The authenticated row directory is authoritative. Amendments can redirect individual rows to replacement blocks and can cause a scan to revisit a prior block.
- An all-match compact query uses an identity representation without a match-ID file; a later first miss materializes the matching prefix. Query IDs and statistics remain in packet-ID order.
- `QuerySpec.Match` uses the immutable, concurrency-safe `Predicate` contract; `QuerySpec.Progress` runs synchronously and must receive cumulative, monotonic updates. It must not run concurrently from scan workers.
- Reads and query scratch space must stay within configured memory and disk accounting. Integrity and length checks must remain active on every scan; no checksum algorithm or verification frequency changes in this plan.
- `radius.DecodePacket` returns an owned observation even when it rejects a packet. Positive detection on configured RADIUS ports and existing malformed, fragmented, and truncated packet behavior must remain intact.

## Implementation

### 1. Reproducible baseline

- [x] Add a committed `BenchmarkOfflineFilter` beside `BenchmarkOfflineFileIndex` in `internal/pkg/tui/`, or an equivalent benchmark that executes the same TUI filter compilation, `Dataset.Query`, and first `Page` path against a local capture supplied by environment variable. Skip cleanly when no capture is supplied. Include a small set of selective, dense, and all-match expressions. Keep capture data and its path out of logs committed to the repository.
- [x] Record separate indexing, query, and first-page timings; allocations; and peak or sampled resource-accounting values where available. Distinguish warm and cold filesystem-cache runs and avoid comparing them as equivalent. Keep methodology in the benchmark comments or a short repository note, without embedding a private capture description.
- [x] Run the existing synthetic query tests and benchmark once before optimization. Use the baseline to locate costs, not to establish a mandatory performance target.

### 2. Cheap RADIUS rejection

- [x] In `internal/pkg/detector/radius.go`, `internal/pkg/capture/radius.go`, and the `internal/pkg/eventanalysis/runtime.go` fallback, use already-decoded transport information where available to skip `radius.DecodePacket` only when the packet is certainly outside the configured RADIUS scope. Where no decoded packet exists yet, move the existing decode earlier or use a bounded header check; do not add another full decode. Check how each caller receives additional service ports before applying a port-based rejection. Do not remove content-based or custom-port detection.
- [x] Keep `radius.DecodePacket`'s ownership and outcome contract for actual decoder calls. If a direct decoder fast path is needed, avoid changing its rejection observation or errors as a side effect of this optimization.
- [x] Verify positive and negative cases with synthetic Ethernet/raw IPv4 and IPv6 packets, default and configured ports, malformed candidate datagrams, fragmentation, and truncation. Extend `internal/pkg/radius/packet_test.go`, `internal/pkg/detector/radius_test.go`, and caller tests only where behavior could change. Re-run the index benchmark and allocation profile to confirm whether this removes meaningful work.

### 3. Bounded details-header cache

- [x] Establish whether the current integrity contract requires detecting a details-header mutation between two row reads in the same scan. A cached header would miss such a mutation even while recomputing `IndexChecksum`; if that detection is required, retain rereads and close this item without changing verification behavior.
- [x] If compatible with that contract, extend `internal/pkg/offline/compact_scan_reader.go` with a small, fixed-capacity cache keyed by details block offset and size. Keep the existing summary-header handling and compute `IndexChecksum` for every row. Account for the cache under the scan reader's memory reservation. Reject stale or inconsistent references as before; do not add a dataset-wide verified bitmap or skip block payload validation.
- [x] If the cache is added, test alternating and amended details-block references, corruption before first read, cancellation, and budget exhaustion using `internal/pkg/offline/compact_scan_reader_test.go` and `query_scan_test.go`. Compare results and resource release to the existing scan.

### 4. Bounded parallel compact query scan

- [x] Split `scanCompactSummaries` into bounded ranges of **row-directory entries**, not a walk over physical blocks. Give each worker its own scan reader, decoder scratch, and ordered result segment. Preserve the sequential path for noncompact datasets and for budgets that cannot admit multiple workers.
- [x] Admit worker buffers, inflater memory, decoded summaries, and pending result segments through the existing storage budget before allocation. Cap in-flight segments and apply backpressure so a slow early segment cannot cause unbounded retention. Do not introduce waiting for resources that the same query holds until completion.
- [x] Merge segments in packet-ID order before updating statistics, invoking the predicate if needed, writing match IDs, and reporting progress. If predicate execution on workers is used, first prove that all supported predicates and expression evaluation meet the concurrency contract and that errors/cancellation remain deterministic. Otherwise keep predicate calls in the ordered merge; measure whether parallel read, verification, and decode alone help.
- [x] Keep a single owner for query scratch-file creation, disk admission, prefix materialization, all-match identity selection, sync/manifest completion, and cleanup. Stop all workers on the first error or cancellation, join them, and release reservations before returning. Progress callbacks remain ordered, synchronous, and monotonic.
- [x] Extend `internal/pkg/offline/query_scan_test.go`, `query_progress_test.go`, and amendment/corruption tests to compare parallel output with the sequential oracle: sparse/dense/all-match queries, late first miss, amended rows, related-flow queries, row order, statistics, paging/pins, cancellation, injected I/O failure, corruption, and tight memory/disk budgets. Include a race-enabled targeted test for shared scan state.

### 5. Verification and decision

- [x] Format edited Go files with `gofmt`. Run targeted RADIUS, detector, capture, event-analysis, offline, and TUI tests plus relevant build-tag variants. Run `go test -race` on the parallel scan tests where feasible and `go vet` on changed packages. Run the repository's required checks.
- [x] Re-run the same benchmark cases and capture conditions once. Report query and load time, first-page time, allocation, and accounted resource use with the same methodology. Describe regressions and correctness findings without declaring an unsourced performance threshold.
- [x] If a change adds complexity without a meaningful measured benefit, simplify or revert that change while preserving independent correctness fixes. Close this plan after correctness checks pass and the measured results are recorded; a benchmark miss alone does not require another optimization cycle.
- [x] When implementing this markdown plan, check off only verified tasks and commit the code and updated plan together, as required by the repository work style.

## Verification record

The comparison used one deterministic, synthetic 100,000-packet UDP capture (about 8.8 MB). The same committed benchmark harness was run against the code baseline and the implementation, in separate processes. Query measurements were taken after indexing, with warmed filesystem caches; they do not represent a cold-cache run or a VoIP-heavy production capture. Values below are medians of three one-query runs except indexing, which used one baseline run and three current runs.

| Measure | Baseline | Implemented |
| --- | ---: | ---: |
| Index elapsed | 0.55 s | 0.36–0.39 s |
| Index allocations | 566 MB/op | 95 MB/op |
| Selective filter query | 115 ms | 92 ms |
| Dense filter query | 123 ms | 95 ms |
| Filter-query allocations | 33 MB/op | 44 MB/op |
| Accounted peak memory during benchmark | about 62.7 MB | about 62.7 MB |

The first page of a completed dense query remained sub-millisecond in the repeated runs. Query allocations increased despite the lower elapsed times, so a representative capture should be measured before drawing broader conclusions. An allocation profile was captured for the final index run; this Go toolchain does not include `go tool pprof`, so hotspot inspection was limited to the benchmark's allocation totals. No profile or capture artifact was committed.

The integrity review found that the storage format treats completed blocks as immutable during a scan; the previous reader already cached the most recent header. The new scan-local cache keeps per-row directory checksums and fresh payload validation. If the contract changes to require detection of an external mutation between reads in the same scan, that requires a separate design.

Validation: `make test` (`all` and LI partitions), `make vet`, targeted parallel-scan race tests, focused package tests, and `git diff --check` passed. These checks cover correctness and build variants; the synthetic benchmark is exploratory performance evidence, not an acceptance gate.

## Later work

These candidates require separate evidence and design before implementation. They are not acceptance criteria for the bounded work above.

- **Progressive filter results:** Design a provisional, generation-tagged view separate from the completed `Query` interface. Specify how cancellation, stale messages, scrolling, exports, provisional counts, and final statistics behave. A selective expression may find its first match late or not at all; do not promise a fixed first-result time. Assess removal of scratch-file `fsync` separately against the publication and durability contract.
- **Progressive indexing:** Specify sealed-block publication, stable packet IDs, late `UpdateDetail` amendments, EOF analysis, failure cleanup, and replacement-session behavior before showing packets from an unfinished dataset.
- **Single-pass ordered input:** A timestamp regression may appear at the end of a file. Any optimistic analysis path needs a bounded rollback/rebuild plan that discards provisional analyzer state and output. First reconcile measured sorting time with the existing monotonic-file path, which already skips external sorting.
- **Index format or codec changes:** Measure whole-block inflation cost after the bounded fixes. If it remains material, design a versioned column-grouped format and compare end-to-end write, scan, random-page, disk, and memory behavior. Keep structural validation and configured limits.
- **Per-packet analysis and shared dispatch:** Treat this as an independent architecture project. A packet-ID reorder stage must also order SIP handler mutations to call and SDP state; it must own factory attribution, global resource caps, expiry, flush barriers, and error propagation. Removing worker-0 TCP pinning alone does not create parallel assembly with a one-shard default. Do not turn an earlier agent-written benchmark target into a required gate for this work.
- **Checksum policy:** Decide separately whether session-local files require collision resistance, detection of post-verification modification, or only accidental-corruption detection. Map each existing digest to that requirement before changing algorithms, stored digest widths, or verification frequency. Preserve source identity and cryptographic bounds that have independent requirements.
