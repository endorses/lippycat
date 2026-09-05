# Scalable Offline Dataset Implementation Plan

**Date:** 2026-09-05

**Status:** Phases 0–2 implemented and verified; phases 3–6 pending

**Code baseline:** `fff6c68f`

**Research:** [Scalable complete-file analysis](../research/watch-file-scalable-offline-dataset.md)

## Objective and scope

Make every logical packet accepted from `lc watch file` inputs navigable,
filterable, and exportable without retaining the entire capture in RAM. Global
statistics must cover the complete logical dataset. Startup arguments, settings,
and file dialogs must use one cancellable model-owned open workflow.

The first release uses normalized temporary disk storage, deterministic streaming
merge, asynchronous queries, and a byte-bounded display cache. Live and remote
capture retain their existing packet and event rings. `watch.buffer_size` must
no longer limit offline packet completeness.

Packet completeness does not imply unlimited event or call history. Initially,
the Events and Calls views retain their existing bounded-history semantics,
clearly labelled separately from the packet dataset. Stateful analysis still
consumes the entire ordered stream. Complete disk-backed event history is an
explicit follow-up below, not a prerequisite for packet completeness.

## Current implementation and changes since the research

| Area                 | Current evidence                                                                                                                                         | Plan consequence                                                                                                 |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| Ordered input        | `internal/pkg/capture/snifferstarter.go`: `RunOfflineOrderedContext` still collects and stable-sorts all packets; cancellation-aware sends already exist | Replace collection with cursors and a heap; extend existing cancellation rather than introducing it from scratch |
| Input errors         | The same reader logs and continues after source errors; BPF setup failure currently warns                                                                | Dataset construction must return errors and refuse to publish incomplete or incorrectly filtered input           |
| Offline presentation | `internal/pkg/tui/bridge.go` retains an unbounded offline pending packet slice                                                                           | Write records and statistics outside the presentation queue; UI receives progress and bounded pages              |
| Retention/filtering  | `store/packet_store.go`, `filter_helpers.go`, and `filter_operations.go` operate on retained records                                                     | Route offline packet queries to the dataset without changing live ring semantics                                 |
| Opening files        | `cmd/watch/file.go` and `tui/capture_lifecycle.go` start separate replay paths; restart clears current state first                                       | Share a session controller and replace state atomically after successful indexing                                |
| Export/navigation    | `save_operations.go`, `helpers.go`, keyboard and mouse handlers consume slices                                                                           | Audit all consumers; changing only `PacketList.View` cannot establish complete-file behavior                     |
| Event delivery       | `local_event_sink.go` blocks at the offline sink queue, but `pendingLocalEventBuffer` can drop after 4,096 batches                                       | Do not use the UI delivery queue as authoritative offline analysis storage                                       |

The [event performance plan](tui-event-view-performance-optimization.md) records
phases 1–7 as implemented and verified, with final mixed-mode acceptance separate.
The current implementation already provides:

| Existing optimization                                                                                  | Files                                                            | Required preservation                                                                   |
| ------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| Dirty flags, adaptive refresh cadence, hidden-view deferral, immediate interaction refresh             | `event_refresh.go`, `event_view.go`, `capture_events.go`         | No per-packet full event refresh during indexing or page loading                        |
| Batched ingestion, constant-time ring eviction, cached visibility, incremental cursor/delta projection | `store/event_store.go`                                           | Keep the typed live/event ring; do not redo this work or enlarge it to file size        |
| Incremental append/trim and stable selection including repeated event IDs                              | `components/eventsview.go`                                       | Preserve duplicate-ID and detail-scroll behavior across publication/reset               |
| Viewport-only presentation cache, Unicode-aware formatting, pure rendering                             | `components/eventtimelinecache.go`, `components/eventsview.go`   | Reuse the presentation principles; never perform disk I/O or model mutation in `View()` |
| Shared pane style cache and cached flow-to-packet availability                                         | Packet/event components, `store/packet_flow.go`, `event_view.go` | Preserve live lookup performance; provide a dataset lookup for offline relationships    |

These optimizations reduce retained-event processing and rendering costs. They
do not remove the full-input sort, packet retention limit, or incomplete-file
filtering. This plan builds on them rather than repeating their implementation.

## Architecture decisions

### Dataset and ownership

Use a proposed `internal/pkg/offline` package for storage, cursors, queries, and
statistics snapshots, with a TUI session adapter for existing analyzers. Keep
storage independent of Bubble Tea and `tui/components`; do not introduce a
dependency from general capture code into the TUI. Pass a predicate/adapter to
storage query scans if importing the build-tagged TUI filter package would
violate that boundary.

The dataset API should expose count, global statistics, summary pages, details
by stable `PacketID`, cancellable filter queries, query count/statistics,
streaming iteration for export, related-flow lookup, and close. Use `uint64`
logical IDs/row counts; convert only bounded page-local indices to `int`.
Dataset generation, query generation, and request ID must accompany asynchronous
results. IDs are meaningful only within their dataset generation.

Persist summary, details/raw bytes, and fixed-width offset streams separately.
Offset tables and match-ID vectors must also live on disk; an O(N) Go slice of
offsets would defeat bounded memory. Version and frame records, validate lengths
before allocation, and store effective link type, timestamps, captured/original
lengths, source identity, and protocol metadata needed to reproduce details.
Use a completed manifest only after successful analyzer drain and storage flush.

Build complete statistics during indexing, once per accepted logical packet.
Retain existing explicitly bounded cardinality counters where appropriate;
document their approximation independently of packet completeness. Do not
re-run stateful analysis on page reads. Flush EOF-generated events before
publishing the session, and freeze or persist deferred metadata updates needed
for correct final packet details.

### Resource and ordering policy

Expose validated settings for session directory, maximum session disk bytes,
and cache bytes using normal flag/Viper precedence. Choose and document defaults
after baseline measurements. Account for details pins, prefetch, in-flight reads,
query files, and concurrent replacement datasets. Include all streams and query
results in disk accounting. Refuse oversized records explicitly if they cannot
fit the configured allocation limit.

A heap retains one logical packet per open source, ordered by timestamp, source
argument index, then source sequence. Use source/interface-local reassembly and
globally ordered TCP/application analysis. Preserve completion-packet timestamp
semantics for reassembled packets and effective link type after decapsulation.

For the initial release, fail indexing on a source timestamp regression, with
source and sequence context. Warning and continuing would falsely claim global
ordering after earlier packets had already been analyzed. External sorting or a
bounded reorder policy is a later extension. Equal timestamps are supported;
clock correction and deduplication are never implicit. Bound simultaneous readers
with an explicit supported-source limit and actionable errors.

The cache budget is not a hard process RSS limit. Separately bound and measure
reader/reassembly state, analyzer state, retained events/calls, serializers, and
Go/runtime overhead. Packet count must not produce hidden unbounded allocations.

### Lifecycle and presentation

Use `Opening -> Indexing -> Ready`, with cancellation/failure cleanup branches.
Filtering is a separate operation on a ready dataset. The model owns contexts
and sessions; workers own reader/writer resources. Cancellation and worker joins
run outside `Update()` so the UI can continue displaying cleanup progress.

Keep the previous completed dataset, statistics, retained events/calls, and
configuration installed until replacement succeeds. New analysis must use
isolated session state rather than clearing shared trackers/decryptors first.
Late results from obsolete workers must be ignored and their resources closed.
The first implementation blocks browsing the new dataset until Ready; partial
index browsing is deferred.

Use `components.RenderModal()` for indexing progress and Cancel. Show phase,
source count, bytes scanned where measurable, logical packet count, elapsed
time, and temporary disk usage. Do not invent exact percentages where the
reader cannot provide physical byte progress. Keep the modal active while
cancellation cleans up. Throttle/coalesce progress delivery.

## Implementation phases

Each phase should be a reviewable commit or series. Verify tasks before checking
them off, format changed files before staging, and commit implementation changes
together with updates to this plan. Dependency order is 0, then 1/2, then 3, 4,
5, and 6; phases 1 and 2 can proceed independently after the contracts in phase 0.

### Phase 0 — Establish contracts and baselines

- [x] Inventory packet filter fields in `types/packet.go` and `tui/filters`,
      including field presence, aliases, text search, numeric comparisons,
      negation, and stacked filters; define a summary adapter with exact parity.
- [x] Define dataset/query/session interfaces, record schema, resource accounting,
      and timestamp-regression behavior described above.
- [x] Audit all packet-slice consumers, including details, mouse/keyboard jumps,
      related-event navigation, statistics, filter removal, and save operations.
- [x] Record current indexing RSS/time, event replay and rendering benchmarks,
      dataset-sized packet behavior, and event/call retention/loss semantics.
- [x] Add transitional UI/documentation distinguishing processed versus retained
      packets and retained-only interactive filters until the dataset path ships.

Phase 0 artifacts:

- [Filter parity, schema, ownership and resource contracts](../design/watch-file-offline-contracts.md),
  with executable interfaces and immutable summary adapter in `internal/pkg/offline`.
- [Packet consumer and retained-history audit](../research/watch-file-offline-consumer-audit.md).
- [Measured reader/RSS, event replay/rendering and retention baseline](../research/watch-file-offline-baseline.md),
  including reproducible commands and provisional comparison gates.
- Transitional offline processed/retained labels and filter scope, with updated
  watch README and local-capture manual.

Verification: TUI, components, store, filters and watch packages pass under `all`
and `tui`; focused ordered-reader tests and reader benchmarks pass. Summary field
and filter-family parity, metadata isolation, resource validation and source-error
contracts are tested. Focused offline notice/render-purity tests pass with the
race detector. Storage, streaming merge and complete-file queries remain later
phases; phase 0 does not claim that those behaviors have shipped.

### Phase 1 — Stream ordered input

- [x] Extract sequential, error-returning file cursors from
      `readAllPacketsFromDeviceContext`; distinguish EOF from malformed input and
      propagate open, read, and BPF errors. Check reader/PCAPNG interface support.
- [x] Implement deterministic k-way merge with context-aware reads/sends and
      explicit timestamp-regression errors; remove full-input collection/sort.
- [x] Preserve IPv4/IPv6 reassembly, ESP/VXLAN handling, raw byte ownership,
      exact source paths, BPF placement, and logical packet metadata.
- [x] Bound fragment state and reader concurrency; ensure downstream failure
      cancels the producer and every owned reader is closed.
- [x] Extend `snifferstarter_test.go`, `defrag_offline_test.go`, and
      `offline_flow_test.go` for interleaved SIP/RTP, equal timestamps, empty
      sources, duplicate basenames, mixed formats, regression errors, malformed
      input, and cancellation of blocked consumers. No later-SIP prioritization.

Phase 1 implementation notes:

- Sequential PCAP/PCAPNG cursors and a deterministic one-packet-per-source heap
  replace collection/sorting in production replay. Error-returning stream APIs
  join consumers, close readers, and propagate source and downstream failures.
- The supported limit is 64 regular-file sources. PCAPNG currently supports one
  section and one interface per file; additional domains fail with instructions
  to split the input, preventing accidental cross-interface reassembly.
- Reader records/PCAPNG blocks are capped at 16 MiB. Per-source pending IP state
  is bounded to 4,096 flows and 16 MiB with capture-time expiry; source-local ESP
  caches are separately capped at 4,096 combined entries. Limit failures are
  explicit. PCAPNG framing/options are validated before decoder allocation.
- Startup and in-TUI replay surface failures as partial replay errors. Atomic
  dataset publication and isolated analyzer lifecycle remain Phase 3 work.
- The [reader baseline comparison](../research/watch-file-offline-baseline.md#phase-1-streaming-reader-comparison-2026-09-05)
  records about 38 MiB peak RSS for both 100,000 and 1,000,000 packets. This does
  not claim bounded analyzer or TUI presentation-queue memory.

Verification: full capture, PCAP type, offline, TUI and watch checks pass under
`all`; capture, TUI and watch checks also pass under `tui`. Focused ordered-reader,
normalization, cancellation and failure-toast tests pass with the race detector.
Hunter, processor, tap and CLI specialized builds pass. Tests cover bounded
lookahead before later corruption, deterministic ties/SIP/RTP, empty sources,
exact paths, mixed formats, malformed framing/BPF, regressions, fragment budgets,
source-local IPv4/IPv6 and ESP state, VXLAN metadata, and blocked/failed consumers.
Private capture fixtures were replaced with portable generated ordered inputs.

Phase 1 review corrections (2026-09-05): independent reviews confirmed the
streaming merge, cancellation, ownership, and source bounds. Two malformed-input
gaps were reproduced and corrected: PCAPNG EOF immediately after a block header
now reports truncation instead of successful partial replay, and truncated IPv6
fragments are rejected before reassembly, matching IPv4 validation. Regression
tests cover both failures, including IPv6 hop-by-hop headers. Capture, PCAP type,
offline, TUI, and watch checks pass under `all` and `tui`; focused reader and
reassembly race tests and hunter, processor, tap, and CLI builds also pass.

Additional Phase 1 review (2026-09-05) reproduced two reader compatibility bugs:
PCAPNG explicit seconds and binary timestamp resolutions were decoded inaccurately
by the underlying reader, and native link types above 255 could silently wrap to
a different decoder. The reader now converts PCAPNG ticks directly with integer
precision and validates native PCAP/PCAPNG link types before narrowing them.
Regression coverage includes cross-source merge ordering, timestamp offsets,
multiple packets, and compressed PCAP header validation.
Capture, PCAP type, offline, TUI, and watch checks pass under `all` and `tui`;
focused reader/reassembly race checks and hunter, processor, tap, and CLI builds
also pass. Independent review found no further Phase 1 defects.

Further Phase 1 review (2026-09-05) reproduced a BPF compatibility regression:
raw-IP PCAP and PCAPNG sources passed portable file link types to libpcap's
native-DLT filter compiler, causing valid filters to fail. Filter compilation
now translates RAW, ATM RFC1483, and LOOP through libpcap's platform mapping,
while decoding and packet metadata retain the file link type. Regression tests
verify matching and rejected packets, raw bytes, timestamps, and supported UDP
decoding in both formats, including raw IPv4 and IPv6. Independent review
verified the correction and found no additional Phase 1 defects. Capture, PCAP
type, offline, TUI, and watch checks pass under `all` and `tui`; focused reader
and reassembly race checks and hunter, processor, tap, and CLI builds also pass.

### Phase 2 — Implement session storage and complete queries

- [x] Implement private temporary session directories, versioned framed streams,
      on-disk offsets, completion manifests, corruption checks, and safe cleanup.
- [x] Persist summary/detail records with schema round-trip coverage, including
      reassembled and decapsulated packets and all supported protocol metadata.
- [x] Implement byte-bounded summary/detail caching, bounded serialization, and
      selected-detail pinning; cap prefetch/in-flight reads under the same policy.
- [x] Add global statistics accumulation independent of display ingestion and
      filtered statistics accumulated over complete query matches.
- [x] Implement cancellable sequential summary filtering with immutable filter
      snapshots and disk-backed ordered match IDs; atomically publish only
      completed queries. Empty/all-match queries must remain memory-bounded.
- [x] Add paged query iteration and dataset-wide related-flow lookup using the
      existing bidirectional transport/node matching semantics. Use a bounded
      disk scan initially if needed; do not rebuild a full in-memory flow map.
- [x] Enforce disk limits for datasets and queries, propagate write/flush/close
      errors, remove superseded query files, and test failure injection.

Phase 2 implementation notes:

- `internal/pkg/offline` now provides a shared-budget storage owner, private
  dataset builders, complete packet queries, related-flow scans, and streaming
  detail iteration. TUI session/analyzer integration remains Phase 3.
- Normalized summaries and full details use checksummed binary frames, with
  disk-backed offsets. This refines the provisional JSON codec contract to
  validate decoded container allocations before allocation. A recursive schema
  fingerprint prevents silent metadata layout changes; see the
  [storage format](../design/offline-storage-format.md).
- Read-only datasets and queries publish only after writer flush/close and
  atomic completion-manifest publication. Disk charges include unfinished and
  replacement datasets, queries, and manifests; failed cleanup remains charged
  and dataset cleanup can be retried.
- A shared byte-bounded frame cache returns independently decoded records.
  Pages and selected details retain explicit leases; serialization and in-flight
  reads reserve working space under the same budget. Storage schedules no
  background prefetch; any prefetched page uses the same bounded API.
- Global/query totals remain independent of display reads. Protocol/address
  counters cap cardinality and retained key bytes, with explicit approximation
  markers. All-match and empty queries keep match IDs on disk.
- The [storage benchmark](../research/watch-file-offline-baseline.md#phase-2-storagequery-comparison-2026-09-05)
  records bounded live heap at a fixed cache budget for 1k, 10k, and 100k packets;
  full analyzer/UI performance acceptance remains Phase 6.

Verification: offline and all TUI packages (including components, stores and
filters), plus watch, pass under `all` and `tui`. The complete offline package
passes the race detector under `all`. Coverage includes all metadata and
nil/empty round-trips, transformed raw/link-type/source identity, schema drift,
corruption and preallocation limits, a 12,017-packet public-API completeness
check, all/empty/sparse queries, exact totals, related-flow parity, cancellation,
writer/manifest failure, cache eviction and mutation isolation, retained page and
detail leases, concurrent readers, close joins, and retryable cleanup.

### Phase 3 — Unify indexing and analysis lifecycle

- [ ] Introduce `OpenOfflineDatasetMsg` (or one equivalent shared controller)
      carrying inputs and frozen analysis configuration. Route startup,
      settings, file dialog, and offline restart through it.
- [ ] Move the startup-specific replay ownership out of `cmd/watch/file.go`;
      retain CLI validation and configuration plumbing.
- [ ] Extract/reuse bridge normalization and analyzer stages to write directly
      into the dataset. Eliminate authoritative offline packet delivery through
      the unbounded pending packet slice and per-packet UI statistics updates.
- [ ] Make retained events/calls session-owned during indexing. Feed their
      bounded stores directly through a synchronized adapter or context-aware
      bounded worker queue, bypassing `pendingLocalEventBuffer` drops. Preserve
      declared ring eviction, event IDs/order, compatibility/loss accounting,
      and analyzer EOF flush semantics; do not run presentation work per event.
- [ ] Isolate call tracking, local aggregators, event analysis, and TLS decryptor
      state for replacement sessions; audit current global capture/bridge state
      to prevent old and new generations contaminating each other.
- [ ] Add indexing modal, throttled progress, cancel/cleanup messages, worker
      completion ownership, and atomic publication of all session state.
- [ ] Cancel/join prior work asynchronously on reopen, mode switch, or quit;
      dispose of stale successful results and preserve the previous ready
      dataset on failure/cancel. Release storage only after readers/export stop.
- [ ] Test startup/in-TUI equivalence, replacement failure, rapid repeated open,
      cancellation in every stage, stale messages, and quit during cleanup.

### Phase 4 — Virtual packet browsing and event integration

- [ ] Adapt `components/packetlist.go` to logical row counts and bounded page
      input, keeping existing slice-backed behavior for live/remote modes.
- [ ] Implement asynchronous viewport/prefetch loading, top/bottom/page jumps,
      selected packet details, and stable selection by dataset/query/packet ID.
      Show loading states without displaying details from an old selection.
- [ ] Replace offline slice assumptions in helpers and keyboard/mouse handlers;
      cancel obsolete requests and reject responses from old generations.
- [ ] Preserve shared pane styling and event viewport-cache/pure-render behavior;
      neither View nor PrepareLayout may read files or scan the complete dataset.
- [ ] Route event-related availability and packet navigation to the offline
      dataset, preserving `Local`/remote identity translation and TCP/UDP rules.
      Cache eviction must not produce a false “related packets unavailable”.
      Verify an event can reach a packet far outside the current page cache;
      page eviction must not increment capture or event loss counters.
- [ ] Install the session's bounded event projection once at Ready; invalidate
      its delta cursor on store replacement and preserve existing subsequent
      incremental updates, filter behavior, selection, and detail-scroll rules.
- [ ] Show total dataset packets, matching packets, cached rows/bytes, and index
      bytes separately. Label retained event/call history and counters accurately.

### Phase 5 — Complete filtering, statistics, and export

- [ ] Route all offline packet filter apply/remove/clear paths through dataset
      queries, preserving the previous completed query while a new scan runs.
- [ ] Display cancellable scan/match progress; publish filter state, row count,
      selection, and filtered statistics together. Failed/cancelled filters leave
      the previous query and its visible filter description consistent.
- [ ] Keep global and filtered statistics clearly distinguished; never recompute
      dataset totals from a page or count page reloads as new packets.
- [ ] Stream offline saves over a pinned dataset/query snapshot instead of
      `getPacketsToSave()` slices. Export every matching logical packet with
      bounded memory, cancellation, and surfaced errors. Define mixed-link-type
      output using a capable format or explicit rejection rather than silently
      using the first packet's link type for all records.
- [ ] Test filters matching beginning/middle/end beyond the former ring capacity,
      exact filter-adapter parity, atomic publication under rapid edits, empty
      results, full-match memory bounds, and complete filtered/unfiltered export.

### Phase 6 — Acceptance, documentation, and release

- [ ] Compare global/filtered statistics and selected details/raw bytes against
      independent full-scan references, including reload after cache eviction.
- [ ] Test disk-full, permission errors, truncated records, incompatible schema,
      failed replacement, analyzer finalization errors, and cleanup failures.
      A failed source must never produce a successful partial dataset.
- [ ] Run focused capture/offline/TUI/store/component/watch tests under `all`
      and `tui` tags, race tests for session/query/cache concurrency, and relevant
      specialized-build checks if shared capture/types code changed. Request
      sandbox escalation when tests require it.
- [ ] Re-run existing event incremental, rendering-equivalence/purity, related-
      packet, and replay benchmarks; include final mixed-mode event acceptance
      that the earlier performance plan leaves separate. Preserve live/remote
      throughput, retention, pause, loss, and refresh behavior.
- [ ] Benchmark increasing capture sizes at fixed budgets, multiple source counts,
      mixed protocols, and all-match filters. Record indexing throughput, peak
      RSS/heap, disk amplification, first-page/random-scroll/detail latency,
      filter throughput, cancellation latency, and active-event-view CPU.
- [ ] Demonstrate no O(packet-count) RAM growth in dataset infrastructure and
      document measured analyzer/runtime overhead separately. Establish numeric
      latency/regression acceptance thresholds from phase 0 measurements.
- [ ] Update `cmd/watch/README.md`, offline settings/help, relevant config
      reference, and `docs/manual/src/part2-local-capture/watch-local.md` with
      packet completeness, retained event/call scope, resource settings,
      regression rejection, export semantics, and disk exhaustion behavior.
- [ ] Remove transitional retained-packet warnings from the completed offline
      path; retain appropriate live/remote retention descriptions. Format,
      verify, check off actual completed work, and commit code plus this plan.

## Deferred optimizations and extensions

These are follow-up work, not release blockers for phases 0–6.

- [ ] Add a small-file in-memory dataset with byte-based spill into the same
      normalized format; benchmark before enabling it by default.
- [ ] Cache canonical filter queries with schema-aware invalidation and bounded
      disk eviction; compare compressed bitmaps with on-disk packet-ID vectors.
- [ ] Add reusable indexes identified by source fingerprint, ordering, schema/
      analyzer version, BPF/decode configuration, and TLS key-log identity.
      Validate ownership before abandoned-session cleanup; never delete active
      sessions or broad temporary/cache roots.
- [ ] Evaluate classic-PCAP source offsets behind the dataset API, retaining
      normalized records for PCAPNG/context-dependent or transformed packets.
- [ ] Add complete disk-backed event history and asynchronous event filters via
      an event-specific dataset projection. Reuse existing viewport formatting
      and selection invariants; do not append the whole history to EventsView
      or treat duplicate event IDs as unique row positions. Assess call-history
      persistence separately and update completeness labels only when delivered.
- [ ] Consider bounded external merge passes for very large source counts or
      non-monotonic sources; research explicit clock offsets, reorder windows,
      and optional deduplication as separate user-visible policies.
