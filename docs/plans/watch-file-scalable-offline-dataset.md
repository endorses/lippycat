# Scalable Offline Dataset Implementation Plan

**Date:** 2026-09-05

**Status:** Phases 0–6 implemented and verified; real-capture corrections completed
in [ordering and navigation](watch-file-ordering-and-navigation.md).

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
phases 1–7 as implemented and verified; final mixed-mode presentation acceptance
is recorded with Phase 6 below.
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

The original implementation used a strict heap merge and rejected source timestamp
regressions. The [ordering and navigation follow-up](watch-file-ordering-and-navigation.md)
supersedes that policy for watch datasets: normalize sources in original record
order, then externally sort logical packets by timestamp, source argument index
and original logical sequence before stateful analysis. Scratch storage shares
the session disk budget, with bounded-memory runs and merge passes. Preserve
completion-packet timestamps, source/interface-local reassembly and effective link
type. No clock correction or deduplication is implicit. Strict streaming remains
available to existing non-dataset callers; the source count limit still applies.

The cache budget is not a hard process RSS limit. Separately bound and measure
reader/reassembly state, analyzer state, retained events/calls, serializers, and
Go/runtime overhead. Packet count must not produce hidden unbounded allocations.

### Lifecycle and presentation

Use `Opening -> Reading -> Sorting -> Indexing -> Finalizing -> Ready`, with cancellation/failure cleanup branches.
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

Phase 2 review correction (2026-09-05): independent storage, query, and cache
reviews identified one lifecycle defect, reproduced before correction. Closing
a superseded query waited for unrelated selected-detail pins because it acquired
the exclusive dataset lock. Query cleanup now holds a shared dataset lock and
joins its own readers through the query lock; dataset cleanup still waits for
all readers and pins. A regression test covers query closure while a detail is
pinned, and existing coverage verifies closure waits for its own active iterator.
Independent review verified the fix and found no further Phase 2 defects.
Offline and TUI/watch checks pass under `all` and `tui`; the complete offline
race suite and repeated focused query lifecycle race checks pass.

### Phase 3 — Unify indexing and analysis lifecycle

- [x] Introduce `OpenOfflineDatasetMsg` (or one equivalent shared controller)
      carrying inputs and frozen analysis configuration. Route startup,
      settings, file dialog, and offline restart through it.
- [x] Move the startup-specific replay ownership out of `cmd/watch/file.go`;
      retain CLI validation and configuration plumbing.
- [x] Extract/reuse bridge normalization and analyzer stages to write directly
      into the dataset. Eliminate authoritative offline packet delivery through
      the unbounded pending packet slice and per-packet UI statistics updates.
- [x] Make retained events/calls session-owned during indexing. Feed their
      bounded stores directly through a synchronized adapter or context-aware
      bounded worker queue, bypassing `pendingLocalEventBuffer` drops. Preserve
      declared ring eviction, event IDs/order, compatibility/loss accounting,
      and analyzer EOF flush semantics; do not run presentation work per event.
- [x] Isolate call tracking, local aggregators, event analysis, and TLS decryptor
      state for replacement sessions; audit current global capture/bridge state
      to prevent old and new generations contaminating each other.
- [x] Add indexing modal, throttled progress, cancel/cleanup messages, worker
      completion ownership, and atomic publication of all session state.
- [x] Cancel/join prior work asynchronously on reopen, mode switch, or quit;
      dispose of stale successful results and preserve the previous ready
      dataset on failure/cancel. Release storage only after readers/export stop.
- [x] Test startup/in-TUI equivalence, replacement failure, rapid repeated open,
      cancellation in every stage, stale messages, and quit during cleanup.

Phase 3 implementation notes:

- Startup, settings, file dialogs, and restart now dispatch the same frozen
  `OpenOfflineDatasetMsg`. A shared model-owned controller retains workers and
  completed results even when Bubble Tea stops before consuming their messages.
  Reopen, cancel, mode switches, and quit join and dispose outside `Update`.
- Indexing writes packet records and complete statistics directly to storage.
  Session-owned bounded event stores bypass presentation queues; call tracking,
  detector/flow caches, ESP policy, and TLS key/decryption state are isolated.
  Input identity hashing is cancellable and rejects non-regular sources.
- Synchronous bounded SIP framing preserves ordered SIP/RTP analysis. Queued
  reassembly pages carry packet identity through EOF, including equal timestamps
  and retransmissions. Deferred metadata amendments append replacement disk
  frames and update disk offsets before publication; amended datasets rebuild
  final statistics once from summaries without rerunning stateful analysis.
- The modal reports opening/indexing/cleanup progress without claiming physical
  byte percentages. Failed/cancelled replacement keeps the prior ready packet,
  statistics, event/call, details, and installed settings state. Obsolete legacy
  packet/event/background results cannot enter the ready session.
- Watch exposes the resource defaults documented in the
  [offline contracts](../design/watch-file-offline-contracts.md). Ready and
  replacement datasets share budgets. SIP frame buffers additionally cap at
  16 MiB, 4,096 streams, and 64 KiB per message, with tighter frozen SIP limits
  honored. TLS key logs use bounded, unwatched session snapshots.
- Until phases 4–5 implement virtual browsing and complete interactive queries,
  the UI explicitly labels its preview of up to 32 pinned packet details.
  Preview retention uses at most one quarter of the configured cache budget;
  packet navigation/filtering/saving still uses that preview. Dataset totals
  and bounded retained events/calls are installed at Ready. This phase does
  not claim complete-file browsing, interactive filtering, or export.

Verification: capture, offline, events, detector, pipeline, all TUI packages,
components/stores/filters, and watch pass under `all` and `tui`. Full capture,
offline, events, detector, pipeline, and TUI suites pass with the race detector.
Hunter, processor, tap, and CLI specialized builds pass. Tests cover startup and
file-dialog equivalence, failed replacement/settings preservation, rapid reopen,
stale and duplicate completion, abandoned command results, cancellation and
cleanup errors, mode changes and quit during cleanup, bounded preview with
complete totals, direct event retention/EOF drain, TLS snapshots, frozen ESP,
cancellable identity hashing, deferred amendment failure/disk accounting, and
SIP completion ownership across segments, queued EOF bytes, equal timestamps,
and retransmissions. Independent sub-agent reviews and root review reproduced
and corrected lifecycle, global-state, and EOF metadata issues before checking
these tasks off.

Phase 3 review corrections (2026-09-05): independent reviews reproduced two
defects. Failed mode-switch or quit cleanup could expose an already
closed dataset and silently reject subsequent opens. Cleanup failures now keep
the modal active, retain ownership, and support asynchronous retry while
preserving restart, queued-open, and quit intent. Offline SIP reassembly also
failed to expire idle connections, allowing fragments an hour apart to produce
a false completed call. Indexing now expires streams on a deterministic
capture-time cadence and preserves original packet identity for queued messages
released during expiry. Regression tests cover cleanup recovery, stale SIP
framing, expired stream capacity, and deferred metadata provenance.

Verification: root review confirmed both reproductions and reviewed the fixes;
a separate reviewer verified cleanup recovery. Offline, pipeline, all TUI
packages, and watch pass under `all` and `tui`. Full TUI and pipeline race suites
pass, as do repeated focused cleanup race checks. Capture, events, and detector
checks and hunter, processor, tap, and CLI builds pass. No further Phase 3
defects were found; phases 4–6 remain pending.

Additional Phase 3 review (2026-09-05): three independent sub-agent reviews and
root verification reproduced cleanup and settings defects. Failed removal of an
unfinished builder discarded its ownership, preventing subsequent cleanup from
releasing the disk budget. The indexer now returns a cleanup-only session when
removal fails. Cancellation now surfaces joined worker errors and keeps failed
candidate cleanup retryable in the modal without closing the previous ready
dataset. Reopens queue behind that cleanup. A buffer-size edit also updates the
installed configuration snapshot, preserving the edited setting after failed
replacement.

Regression tests reproduce directory-permission cleanup failure, cancellation
error reporting and retry, preservation of the ready dataset, and buffer-setting
restoration. Offline, all TUI packages, and watch checks pass under `all` and
`tui`; the full TUI race suite and repeated focused cancellation/lifecycle race
checks pass. Independent review verified cleanup retries and rapid queued
reopens. Phases 4–6 remain pending.

Further Phase 3 review (2026-09-05): three sub-agent reviews and root
verification reproduced two presentation-state isolation defects. Successful
offline publication retained live capture drop counters and bridge health
telemetry. It now clears both at publication, preserving them during indexing
and failed/cancelled opens. Remote call correlations also survived publication
or arrived through late remote messages, attaching foreign call legs to offline
calls with matching Call-IDs. Publication now clears correlations and their
detail cache, and indexing/ready sessions reject remote correlation updates.

Regression coverage checks prior-state preservation, stale bridge refresh,
same-ID call details, and late correlation delivery. Root reproduced the
failures before fixing them and verified the sub-agent changes; independent
review also verified the telemetry correction. Offline, all TUI packages, and
watch checks pass under `all` and `tui`; TUI and component race checks pass.
No further Phase 3 defects were confirmed. Phases 4–6 remain pending.

Further Phase 3 protocol and mode-switch review (2026-09-05): three sub-agent
reviews and root verification confirmed two defects. Valid ARP, unknown Ethernet,
ICMP, and IGMP packets failed indexing because the local event adapter requires
decoded IP TCP/UDP flows. Indexing now retains and counts packets outside that
adapter's supported protocols while continuing to propagate errors from supported
analysis. Mixed-capture regression tests verify raw bytes, link types, complete
totals, and supported UDP EOF events without transport loss.

Leaving offline mode also retained the session's TLS details callback and cached
plaintext. Live/remote restart now clears the selected details and restores the
normal global TLS callback after successful cleanup. Regression tests reproduce
the old plaintext appearing across both mode switches and verify that subsequent
details use the current global decryptor. Independent review verified the fix;
root reproduced both defects before accepting the corrections. Phases 4–6 remain
pending.

Verification: offline, all TUI packages, watch, and pipeline checks pass under
`all` and `tui`. Full TUI and component race suites pass, along with repeated
focused protocol-preservation and TLS mode-switch race checks. No further
Phase 3 defects were confirmed.

Further Phase 3 failure-cleanup review (2026-09-05): three sub-agent reviews
and root verification confirmed one remaining cleanup-routing defect. A normal
indexing failure with candidate resources dismissed the modal before cleanup
succeeded; cleanup errors then showed only a toast without an explicit retry.
Failed candidates now use the generation-aware cleanup modal and retry workflow,
preserving the prior ready session. Failed disposal of an obsolete result during
reopen also returns the owned candidate to that workflow.

Root reproduced the regression before accepting the fix. Two regression tests
cover failed-open cleanup retry and obsolete-result ownership. Offline, all TUI
packages, and watch pass uncached under `all` and `tui`; independent review and
repeated focused lifecycle race tests pass. No other Phase 3 defects were
confirmed. Phases 4–6 remain pending.

Further Phase 3 TLS retention review (2026-09-05): independent analyzer review
and root reproduction confirmed that a single decrypted TLS connection retained
plaintext proportional to capture length. Offline sessions now enforce a 16 MiB
aggregate plaintext budget across all connections and directions. Exhaustion
fails indexing before publication, including failures while pending records drain;
eviction and expiry release the retained-byte charge. This analyzer budget is
separate from the display cache and does not include allocation overhead.
Other decryption callers retain their existing configuration defaults.

Verification: root reproduced the unbounded behavior with encrypted-record and
full-indexing regressions before accepting the correction; independent review
verified the fix. Tests cover cross-flow/direction accounting, eviction/expiry,
pending-record errors, and failed-index cleanup. Offline, TLS, all TUI packages,
and watch checks pass under `all` and `tui`; full TUI and TLS decryption race
checks and hunter, processor, tap, and CLI builds pass. No other Phase 3 defects
were confirmed. Phases 4–6 remain pending.

Further Phase 3 TLS lookup review (2026-09-05): three independent sub-agent
reviews and root verification confirmed that repeated ClientHello messages on a
reused flow retained obsolete client-random reverse lookups, allowing analyzer
memory to grow despite the session limit. Replacing a handshake now removes its
old lookup. Replacement, expiry, and eviction preserve lookups owned by another
flow when client randoms coincide.

Root reproduced the regression before accepting the correction, and independent
review verified the fix. Regression coverage checks 1,000 handshake identities
with a one-session limit and lookup ownership during replacement, expiry, and
eviction. TLS, offline, all TUI packages, and watch checks pass under `all` and
`tui`; full TUI and TLS decryption race checks and hunter, processor, tap, and CLI
builds pass. No other Phase 3 defects were confirmed. Phases 4–6 remain pending.

### Phase 4 — Virtual packet browsing and event integration

- [x] Adapt `components/packetlist.go` to logical row counts and bounded page
      input, keeping existing slice-backed behavior for live/remote modes.
- [x] Implement asynchronous viewport/prefetch loading, top/bottom/page jumps,
      selected packet details, and stable selection by dataset/query/packet ID.
      Show loading states without displaying details from an old selection.
- [x] Replace offline slice assumptions in helpers and keyboard/mouse handlers;
      cancel obsolete requests and reject responses from old generations.
- [x] Preserve shared pane styling and event viewport-cache/pure-render behavior;
      neither View nor PrepareLayout may read files or scan the complete dataset.
- [x] Route event-related availability and packet navigation to the offline
      dataset, preserving `Local`/remote identity translation and TCP/UDP rules.
      Cache eviction must not produce a false “related packets unavailable”.
      Verify an event can reach a packet far outside the current page cache;
      page eviction must not increment capture or event loss counters.
- [x] Install the session's bounded event projection once at Ready; invalidate
      its delta cursor on store replacement and preserve existing subsequent
      incremental updates, filter behavior, selection, and detail-scroll rules.
- [x] Show total dataset packets, matching packets, cached rows/bytes, and index
      bytes separately. Label retained event/call history and counters accurately.

Phase 4 implementation notes:

- Packet browsing uses logical `uint64` row counts and bounded summary pages.
  An implicit unfiltered query maps rows to packet IDs without a full scan or
  another match-vector file. Live and remote packet rings retain their existing
  slice-backed behavior.
- Session-owned workers load viewport/prefetch summaries and selected details
  asynchronously. Navigation clears stale details, cancels obsolete requests,
  rejects old generations, reuses prefetched summaries, and releases abandoned
  results during replacement or shutdown. Relative timestamps use dataset start
  time across page changes. Hidden packet views release their leases before
  event scans; returning reloads the preserved logical selection.
- Offline event availability uses a cancellable dataset scan and bounded
  selected-flow cache, independently of page residency. Enter jumps to the first
  related packet. Node translation and bidirectional TCP/UDP matching retain the
  existing semantics; lookup completion preserves same-event detail scrolling.
- Ready publication installs the bounded event projection and invalidates its
  delta cursor. Packet page reads and evictions do not change global statistics
  or capture/event loss counters. The header and status distinguish logical
  totals, matching rows, resident rows, cache bytes, and temporary index bytes.
- Cache reads borrow validated frame payloads during decoding, eliminating a
  duplicate allocation while retaining checksum, schema, and decoded-allocation
  bounds. Large-summary and large-detail regressions verify tight-cache browsing
  and event lookup; page limits leave decoding headroom.
- Complete interactive packet filtering and export remain Phase 5. Those legacy
  operations are explicitly unavailable for ready datasets so they cannot
  silently operate on only the resident page. Event/call filters remain usable,
  and their history remains explicitly bounded.

Verification: offline, all TUI packages, components/stores/filters, and watch
pass under `all` and `tui`; the full offline and TUI race suites pass. Root
review and independent sub-agent reviews verified logical navigation, stale and
abandoned results, distant event-to-detail jumps, hidden-view cleanup, selected
row recovery from byte-limited pages, identity/transport parity, event projection
replacement/deltas, detail scrolling, pure component rendering, and low-cache
large-record behavior. Temporary Go build-cache exhaustion during verification
was resolved by clearing the rebuildable cache and running checks sequentially.
Phase 4 is complete; complete packet filtering/export and release acceptance
remain phases 5–6.

Phase 4 review corrections (2026-09-05): three sub-agent reviews and root
verification confirmed two protocol-scope defects. Opening or replacing an
offline dataset retained the selected event protocol but installed an unfiltered
event projection. Publication now reapplies that protocol scope before the first
projection, preserving it through subsequent incremental updates. Protocol
selection also claimed to filter offline packets while leaving all rows visible;
its notification now identifies the selected views and explicitly states that
offline packet filtering is unavailable.

Regression coverage checks initial and replacement publication, incremental
event updates, accurate notifications, complete virtual packet counts, selected
row preservation, and event filtering after protocol selection. Root reproduced
the publication failure before accepting the fix and verified both corrections;
independent review also verified the notification correction. Offline, all TUI
packages, and watch checks pass under `all` and `tui`; full offline/TUI race
checks and repeated focused regression race checks pass. No further phase 4
defects were confirmed. Phases 5–6 remain pending.

Further Phase 4 review (2026-09-05): three sub-agent reviews and root
verification confirmed one loading-state defect. Repeating End while the
selected packet's details were pending cleared the loading message without
starting a replacement request. Unchanged selections now preserve the browser's
detail state until completion or failure. Root reproduced the failing regression
before fixing it, and independent review verified the correction. The regression
also checks that completion installs the selected packet and ends loading.

Verification: offline, all TUI packages, and watch checks pass under `all` and
`tui`; full TUI race checks pass. No other Phase 4 defects were confirmed.
Complete packet filtering/export and release acceptance remain phases 5–6.

### Phase 5 — Complete filtering, statistics, and export

- [x] Route all offline packet filter apply/remove/clear paths through dataset
      queries, preserving the previous completed query while a new scan runs.
- [x] Display cancellable scan/match progress; publish filter state, row count,
      selection, and filtered statistics together. Failed/cancelled filters leave
      the previous query and its visible filter description consistent.
- [x] Keep global and filtered statistics clearly distinguished; never recompute
      dataset totals from a page or count page reloads as new packets.
- [x] Stream offline saves over a pinned dataset/query snapshot instead of
      `getPacketsToSave()` slices. Export every matching logical packet with
      bounded memory, cancellation, and surfaced errors. Define mixed-link-type
      output using a capable format or explicit rejection rather than silently
      using the first packet's link type for all records.
- [x] Test filters matching beginning/middle/end beyond the former ring capacity,
      exact filter-adapter parity, atomic publication under rapid edits, empty
      results, full-match memory bounds, and complete filtered/unfiltered export.

Phase 5 implementation notes:

- Packet filter input, stacking, removal, clearing, statistics shortcuts, and
  protocol selection use immutable asynchronous dataset queries. A cancellable
  modal reports scanned and matching packets. Completed rows, filter description,
  selection, and matching statistics publish together; failed, cancelled, and
  obsolete scans preserve the previous completed query. Session ownership joins
  workers and reclaims abandoned query results outside the update loop.
- Filtered browsing resolves logical query rows to stable packet IDs, including
  details beyond the former packet ring. Related-event navigation clears a packet
  filter through the same query workflow before jumping to the related ID.
  Replacement datasets clear packet filters while preserving event protocol scope.
- Statistics explicitly separate global dataset and completed matching-query
  counts, bytes, sizes, endpoints, capture intervals, and protocol counts. Bounded
  cardinality estimates remain labelled separately. Page reads do not accumulate
  statistics, and returning to live capture immediately clears offline labels.
- Offline saves pin the installed dataset/query before starting a worker and
  stream one record at a time. Nanosecond PCAP output preserves effective link
  type, raw bytes, timestamps, and captured/original lengths. Mixed link types
  are explicitly rejected; export those inputs separately. Empty queries report
  no packets to save. Cancellation and write/read/flush/close errors remove the
  temporary output and preserve an existing destination; only successful saves
  atomically replace it. Escape cancels export, and session cleanup joins it.

Verification: offline, all TUI packages, and watch pass under `all` and `tui`;
the full offline and TUI race suites pass. Root review and independent sub-agent
review verified snapshot ownership, query retirement, cancellation, stale and
abandoned results, filtered row/detail identity, retained event scope, and
immediate statistics reset on mode changes. Tests cover complete filter-adapter
parity, beginning/middle/end matches in the 12,017-packet storage acceptance
fixture, empty/all-match scans with bounded resource accounting, and exact
4,097-packet filtered/unfiltered export roundtrips. Export failures preserve the
destination and clean up temporary files. Phase 5 is complete; phase 6 remains
pending for release acceptance, benchmarks, and operator documentation.

Phase 5 review correction (2026-09-05): three sub-agent reviews and root code
verification confirmed one input regression: the offline filter branch bypassed
the existing history update and persistence. It now records entered filters
using the same behavior as the live input path. The regression failed before
the fix and verifies in-memory history, temporary YAML persistence, and Up-arrow
recall. Independent review verified the correction. No additional filtering,
statistics, or export defects were confirmed.

Verification: offline, all TUI packages, and watch checks pass under `all` and
`tui`; the new regression also passes under both tags. Offline and component race
checks pass. An initial full TUI race run failed with truncated diagnostics; a
rerun with captured output passed, so the initial failure remains unexplained.
Phase 6 release acceptance remains pending.

Further Phase 5 review corrections (2026-09-05): three sub-agent reviews and
root verification confirmed two export defects. The save key still returned a
Phase 4 unavailable notice, preventing normal access to the implemented exporter.
It now opens the save dialog and reaches the dataset export workflow. PCAP output
also silently replaced missing timestamps with the current time and wrapped
timestamps outside unsigned 32-bit Unix seconds. Export now explicitly rejects
those values while preserving the destination and removing temporary output.

Both regressions failed before correction. Coverage exercises the actual save
key and file-selection dispatch, reads back the complete exported dataset,
checks timestamp rejection after an earlier valid record, and verifies exact
roundtrips at both supported timestamp boundaries. Independent review verified
both fixes. No additional filtering, statistics, or export defects were confirmed.

Verification: offline, all TUI packages, and watch pass uncached under `all` and
`tui`; full offline and TUI race suites pass uncached under `all`. Phase 6 remains
pending.

### Phase 6 — Acceptance, documentation, and release

- [x] Compare global/filtered statistics and selected details/raw bytes against
      independent full-scan references, including reload after cache eviction.
- [x] Test disk-full, permission errors, truncated records, incompatible schema,
      failed replacement, analyzer finalization errors, and cleanup failures.
      A failed source must never produce a successful partial dataset.
- [x] Run focused capture/offline/TUI/store/component/watch tests under `all`
      and `tui` tags, race tests for session/query/cache concurrency, and relevant
      specialized-build checks if shared capture/types code changed. Request
      sandbox escalation when tests require it.
- [x] Re-run existing event incremental, rendering-equivalence/purity, related-
      packet, and replay benchmarks; include final mixed-mode event acceptance
      that the earlier performance plan leaves separate. Preserve live/remote
      throughput, retention, pause, loss, and refresh behavior.
- [x] Benchmark increasing capture sizes at fixed budgets, multiple source counts,
      mixed protocols, and all-match filters. Record indexing throughput, peak
      RSS/heap, disk amplification, first-page/random-scroll/detail latency,
      filter throughput, cancellation latency, and active-event-view CPU.
- [x] Demonstrate no O(packet-count) RAM growth in dataset infrastructure and
      document measured analyzer/runtime overhead separately. Establish numeric
      latency/regression acceptance thresholds from phase 0 measurements.
- [x] Update `cmd/watch/README.md`, offline settings/help, relevant config
      reference, and `docs/manual/src/part2-local-capture/watch-local.md` with
      packet completeness, retained event/call scope, resource settings,
      regression rejection, export semantics, and disk exhaustion behavior.
- [x] Remove transitional retained-packet warnings from the completed offline
      path; retain appropriate live/remote retention descriptions. Format,
      verify, check off actual completed work, and commit code plus this plan.

Phase 6 implementation and acceptance (2026-09-05):

- Independent full-scan references now compare every global/matching statistics
  field and selected details against generated records and separately read PCAP
  inputs. Beginning/middle/end reloads survive demonstrated cache eviction.
- Failure acceptance includes real ENOSPC and permission denial, incompatible or
  truncated storage, late source corruption, EOF-only analyzer errors, failed
  replacement, and cleanup retry. No failed source publishes a partial dataset.
- New fixed-budget storage and full-indexer benchmarks cover 100,000/1,000,000
  packets, one/eight sources, DNS/ordinary UDP, complete all-match scans,
  page/detail latency, cancellation cleanup, sampled peak/live heap and peak RSS.
  Root independently repeated representative runs and inspected heap profiles.
  All memory/latency/throughput investigation gates pass. See the
  [measurement report](../research/watch-file-offline-phase6-benchmarks.md).
- Five one-second event samples pass the Phase 0 replay/rendering time and
  allocation gates. Incremental/related-packet costs remain bounded. Active
  live/remote view and idle offline view measurements, CPU profiling, mixed-mode
  interaction tests and real PTY checks are recorded in the
  [acceptance report](../research/watch-file-offline-phase6-acceptance.md).
- Operator README, manual, configuration reference, embedded help and offline
  settings now describe complete packet scope and separately bounded event/call
  history. Transitional retained-only/preview claims were removed. Export,
  ordering, disk exhaustion and replacement/cancellation behavior are explicit.

Verification: uncached capture/offline/all TUI packages/watch tests pass under
`all` and `tui`; uncached full offline/TUI race suites pass under `all`. Both
`all` and `tui` binaries build. Real offline terminal runs with an eight-packet
buffer export every one of 86 matches from 257 input records, with exact independent
readback. Connected remote terminal lifecycle and controlled live terminal
delivery/navigation/pause/resize pass. Raw live capture requires OS privileges
unavailable in this environment; the live terminal check is explicitly at the
unchanged delivery/presentation boundary, not a NIC throughput claim. Independent
sub-agent reviews and root verification covered code, tests, benchmark methodology
and numerical results. Phase 6 is complete; only the deferred extensions below
remain outside this release scope.

Phase 6 review correction (2026-09-05): three sub-agent reviews and root
verification confirmed one CLI-help omission. The inherited `--buffer-size`
description still described only a packet memory limit. It now identifies the
live/remote packet ring and retained event capacity and explicitly states that
offline packets are not limited. Root reproduced the old `watch file --help`
output and verified the corrected output under `all` and `tui`.

Uncached capture/offline/all TUI packages/watch tests pass under both tags;
the full offline/TUI race suites pass under `all`. Reviews verified independent
statistics and raw-byte references, actual cache eviction, failure/publication
and cleanup coverage, mixed-mode event behavior, documentation, and benchmark
methodology. Fresh-process 100,000/1,000,000-packet storage runs used
41,472/44,576 KiB peak RSS (+3.03 MiB) and passed the documented latency and
throughput gates. No runtime defects or other Phase 6 implementation gaps were
confirmed.

## Indexing performance follow-up

- [x] Measure and remove redundant per-packet event flush barriers while preserving
      lossless event admission and final EOF drain.
- [x] Reduce per-record storage I/O overhead with bounded resource accounting;
      benchmark and verify amendments, failures, queries, and cleanup.
- [x] Narrow the opening modal while keeping content left aligned and the box
      centered in the terminal.
- [x] Record measurements, run relevant checks, format, and commit this follow-up.

Implementation (2026-09-05): the indexer relies on the analyzer's lossless
pre-admission drain and final dispatcher close, eliminating a redundant barrier
after every packet. A 2,049-flow regression verifies EOF delivery beyond queue
capacity with no transport loss. Storage maintains append offsets across both
new records and deferred amendments, and writes each frame header and payload
together. This reduces each packet append from five writes and two seeks to
three writes and no seeks, without persistent buffering or a schema change.
Frame-prefix allocation remains charged to the memory budget. The opening modal
uses a stable 48-column content width, retaining left alignment and centering.

Measurements on Linux/amd64, Intel i9-13900HX, five isolated one-iteration runs
per version, comparing the prior committed implementation with this follow-up:

| Benchmark (100,000 packets) | Before median | After median | Throughput gain |
| -------------------------- | ------------- | ------------ | --------------- |
| Storage indexing           | 170,217 pkt/s  | 213,199 pkt/s | 25.3%           |
| Full indexer, one source    | 47,430 pkt/s   | 56,518 pkt/s  | 19.2%           |

The full-indexer fixture mixes DNS and ordinary UDP. Before samples were
48,025 / 46,974 / 48,149 / 44,206 / 47,430 pkt/s; after samples were
59,505 / 56,169 / 58,266 / 56,518 / 56,447 pkt/s. Live heap stayed near 10 MB,
sampled peak heap within 45–49 MB, and cancellation cleanup below 1.2 ms.
Full-indexer disk amplification was 8.966 before and 8.955–8.966 after;
storage-only amplification remained 2.773. These generated-fixture results do
not predict an exact speedup for the screenshot's capture or reduce normalized
storage amplification materially.

Reproduce with `go test -tags all ./internal/pkg/tui -run '^$'
-bench '^BenchmarkPhase6OfflineIndex/packets_100000$/sources_1$'
-benchtime=1x -count=5`; the storage benchmark is `BenchmarkPhase6Dataset` in
`internal/pkg/offline/phase6_benchmark_test.go`. Benchmark versions sequentially
without concurrent tests or other benchmark processes.

Verification: offline, all TUI packages, and watch tests pass under `all` and
`tui`; full offline and TUI race suites pass under `all`. Existing amendment,
corruption, allocation-limit, short-write, query, export, and cleanup coverage
passes. Independent code review found no regressions in event drain,
cancellation, offset maintenance, or frame accounting. Go files are formatted
and the diff passes whitespace checks.

## Progress bars and query performance follow-up

- [x] Show phase-specific percentage bars when indexing/filter totals are known,
      and an activity indicator for opening/reading/sorting with unknown totals.
- [x] Use the compact opening-modal width for filter progress and cancellation.
- [x] Measure and reduce query scan overhead without weakening corruption checks,
      memory bounds, cancellation, or deferred-amendment support.
- [x] Verify, record measurements, format, and commit the follow-up.

Implementation (2026-09-05): the sorter already knows the complete logical
packet count before replay. The indexer now carries that total into progress
messages, enabling an indexing-phase percentage bar. Reading and sorting show
activity without claiming a percentage; filter scans use their existing exact
scanned/total counts. Bars describe the current scan, not overall readiness:
a finalizing phase shows activity during analyzer EOF drain and storage
finalization before publication. Both modals share the stable 48-column width
and suppress percentage bars during
cancellation/cleanup. Tests cover known and unknown totals, near-completion
rounding, empty datasets, indexer total propagation, and compact filter rendering.

Queries now validate immutable stream headers and snapshot summary-stream size
once per scan while holding the dataset read lock. Every record still validates
its offset, length, frame identity/schema, checksum and allocation budget.
There are no new scan buffers. Regression coverage rejects corrupt headers,
offsets, lengths and frame IDs, cleans up failed partial match vectors, and
filters the latest amended summary.

Three isolated 100,000-packet `BenchmarkPhase6Dataset/100000$` runs measured
filter throughput of 297,061 / 304,986 / 312,567 pkt/s before and
467,257 / 429,699 / 438,975 pkt/s after. The median improved from 304,986 to
438,975 pkt/s: **43.9% more throughput, 30.5% less scan time**. This generated
all-match fixture measures query scanning, not full capture opening; capture
contents and storage hardware affect the result. Reproduce with
`go test ./internal/pkg/offline -run '^$' -bench 'BenchmarkPhase6Dataset/100000$'
-benchtime=1x -count=3`, running versions sequentially.

Verification: offline, all TUI packages, and watch pass under `all` and `tui`.
Full offline/TUI race suites pass, with finalizing-phase changes additionally
verified by focused indexer, progress, and ordering race tests. Independent
review checked total propagation, phase semantics, and modal fit. Go files are
formatted and whitespace checks pass.

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
- [ ] Extend the supported source count beyond 64; research explicit clock
      offsets, reorder windows and optional deduplication as separate user-visible
      policies. Non-monotonic watch sources are handled by the ordering follow-up.
