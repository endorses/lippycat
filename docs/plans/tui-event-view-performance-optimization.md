# TUI Event View Performance Optimization Plan

**Date:** 2026-09-04
**Status:** Phases 1–7 and final mixed-mode presentation acceptance verified
**Scope:** Normalized event ingestion, retention, projection, synchronization,
and rendering in `internal/pkg/tui`

## 1. Objective

Reduce TUI CPU usage while the Capture tab's event timeline is active, without
losing events beyond the existing bounded-buffer and pressure policies or
changing event filtering, ordering, selection, pause, navigation, or related-
packet behavior.

The event timeline should receive the same class of hot-path protections as the
packet list: batched ingestion, bounded update frequency, incremental state
transfer, and work proportional to the visible change rather than the complete
retained buffer.

## 2. Current Performance Problem

The current implementation multiplies several linear operations:

- `handleEventBatchMsg` synchronizes the event view immediately for every
  accepted batch while the event view is active.
- Local analysis emits singleton event batches, and one TUI tick can drain up
  to 50 of those batches independently.
- `renderCaptureTab` synchronizes the event view again whenever Bubble Tea
  renders the Capture tab.
- A synchronization filters and copies the complete retained event set,
  performs repeated linear selection lookups, and scans the complete packet
  buffer to determine related-packet availability.
- `EventStore.AddBatch` calls the per-event insertion path, including one lock
  and selection validation per event.
- At capacity, each insertion shifts the retained event slice by one element.

Because the event store uses the packet buffer size, the default steady-state
cost can involve repeated scans and copies of approximately 10,000 events and
10,000 packets for each arriving event. Switching away from the event view
removes the active-view synchronization work, explaining the observed CPU
drop.

### 2.1 Reuse strategy

Use the packet path as the reference implementation rather than designing a
second, unrelated performance architecture:

- [ ] Reuse the algorithms and control flow from `PacketStore.AddPacketBatch`,
      `PacketStore.GetNewPackets`, `updatePacketListIncremental`,
      `PacketList.AppendPackets`, and `PacketList.TrimOldPackets`.
- [ ] Prefer a shared refresh/throttling helper when packet and event refresh
      semantics are identical, so cadence and pressure behavior cannot drift.
- [ ] Keep event filtering, stable-ID selection, follow-latest behavior, loss
      accounting, and detail state event-specific.
- [ ] Do not make `EventStore` wrap `PacketStore` or represent events as
      packets; their filtering and identity contracts differ.
- [ ] Initially port the proven ring-buffer algorithm into `EventStore` rather
      than refactoring the working packet store in the same performance change.
- [ ] Consider extracting a small generic `boundedRing[T]` only after both
      typed implementations and their equivalence tests demonstrate a stable
      common API. Treat that extraction as an optional follow-up, not a
      prerequisite for fixing event-view CPU usage.

## 3. Required Invariants

- [ ] Preserve arrival ordering for retained events.
- [ ] Preserve the configured retention capacity and exact eviction accounting.
- [ ] Preserve capture-mode gating for local and remote event batches.
- [ ] Preserve pause accounting and transport-loss reporting.
- [ ] Preserve protocol, source, and stacked user-filter semantics.
- [ ] Preserve stable selection while navigating history and follow-latest
      behavior at the live edge.
- [ ] Preserve detail-pane scroll caching until selection or relevant detail
      state changes.
- [ ] Preserve the warning when packets related to the selected event have
      actually left the packet buffer.
- [ ] Keep Bubble Tea `View()` functions free of data synchronization and
      model mutation.
- [ ] Do not make event ingestion wait on terminal rendering.

## 4. Performance Targets

Establish the exact baseline before setting a hard regression threshold. The
implementation is complete only when all of the following are demonstrated on
the same machine and workload:

- [ ] Active event-view CPU is materially lower than the baseline under a
      sustained high-rate event stream.
- [ ] Event-view synchronization occurs no more frequently than the configured
      UI refresh cadence, except for direct user interactions that require an
      immediate refresh.
- [ ] Ingestion and eviction benchmarks remain approximately constant-time as
      retained capacity grows from 1,000 to 10,000 events; no per-event slice
      shift remains at capacity.
- [ ] Allocation volume per refresh is proportional to new/visible event data,
      not the complete retained event capacity.
- [ ] Packet ingestion throughput and Statistics-tab CPU do not regress.
- [ ] Race-enabled tests show no new data races.

Record the baseline and final benchmark results in the pull request or commit
description. Do not encode timing thresholds that are too noisy for routine CI;
use allocation assertions and operation-count test seams where deterministic
guards are possible.

## 5. Phase 1 — Add Measurements and Regression Coverage

Create repeatable measurements before changing the hot path.

- [x] Add `EventStore` benchmarks covering:
  - [x] single-event insertion below capacity;
  - [x] batch insertion below capacity;
  - [x] batch insertion and eviction at capacities 1,000 and 10,000;
  - [x] unfiltered and filtered visible projections;
  - [x] selection maintenance while following latest and while pinned in
        history.
- [x] Add `EventsView` benchmarks for appending events and rendering a fixed
      terminal viewport with 1,000 and 10,000 retained events.
- [x] Add a model-level benchmark or deterministic test that feeds 50 local
      singleton batches in one tick and counts event-view synchronizations.
- [x] Add a model-level benchmark for remote batches of sizes 1 and 128.
- [x] Capture CPU and allocation profiles for the active event view using a
      representative live or replayed capture.
- [x] Confirm profiles expose the expected costs in `syncEventsView`, visible
      projection, selection lookup, packet relationship lookup, and front
      eviction.
- [x] Add correctness tests that freeze the invariants in Section 3 before
      structural changes begin.

### Phase 1 baseline

The Phase 1 review corrected repeated event IDs in the ingestion benchmarks.
Those fixtures let selection lookups stop at an earlier retained event and
understated live-edge selection costs. Prebuilt fixture cycles now exceed
retention, so an ID leaves the buffer before reuse; below-capacity batches and
selection-maintenance fixtures also use distinct retained IDs. These results
supersede the original ingestion baseline.

On an Intel Core i9-13900HX, corrected one-second benchmark runs measured:

| Workload                                             |  Time/op | Allocated bytes/op |
| ---------------------------------------------------- | -------: | -----------------: |
| Remote batch, 1 event, 10,000 retained               |  1.57 ms |            484,736 |
| Remote batch, 128 events, 10,000 retained            | 30.31 ms |            512,221 |
| Local tick, 50 singleton batches, 10,000 retained    | 67.54 ms |         24,232,643 |
| Batch eviction, 128 events, capacity 1,000           |  2.90 ms |                184 |
| Batch eviction, 128 events, capacity 10,000          | 31.87 ms |             18,618 |
| Synchronization, 10,000 events and unrelated packets |  1.96 ms |          2,809,861 |
| Related-packet miss, 10,000 retained packets         |  0.58 ms |          2,326,918 |

Eviction allocation figures amortize the initial backing-slice expansion over
the measured iterations; they are not steady-state allocations per insertion.
The local tick still performs exactly 50 synchronizations. Timings are
observational baselines, not CI thresholds.

`BenchmarkModelEventDNSReplay` supplies the previously missing capture replay
measurement. It decodes checksum-valid generated Ethernet/IPv4/UDP DNS query
frames and exercises the production analyzer, event identity assignment,
dispatcher, local sink, packet/event tick delivery, and `Model.View()` at
160×40 with details open. It retains 10,000 events and packets, rotates across
10,001 flows, and replays 50 queries per operation. Assertions verify packet
retention, exact event arrivals/evictions, latest selection, and zero loss.
This controlled DNS workload excludes PCAP disk I/O and terminal-driver costs;
it does not represent a mixed-protocol production capture.

A 15-second profiled run measured 126.19 ms/op, 149,964,780 bytes/op, and 70,199
allocations/op. Profiles include setup (roughly 1.5 seconds of 19.65 seconds
elapsed), while benchmark timing excludes it. CPU attribution confirms
`syncEventsView` at 49.53% cumulative, view ID lookup at 25.92% flat, store
selection maintenance at 11.07% flat, and related-packet lookup at 10.30%
cumulative. Source-line attribution identifies 370 ms in the front-eviction
`copy`. Allocation attribution identifies packet-buffer materialization at
78.45% and visible event projection at 16.21%. Cumulative percentages overlap.

Reproduce measurements and inspect profiles with:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all -run '^$' \
  -bench 'Benchmark(EventStore|EventsView|ModelEventBatch|SyncEventsView|HasRelated)' \
  -benchtime=1s -benchmem ./internal/pkg/tui ./internal/pkg/tui/store ./internal/pkg/tui/components
GOCACHE=/tmp/lippycat-go-cache go test -tags all -run '^$' \
  -bench '^BenchmarkModelEventDNSReplay$' -benchtime=15s -benchmem \
  -cpuprofile=/tmp/tui-event-dns-replay.cpu.pprof \
  -memprofile=/tmp/tui-event-dns-replay.allocs.pprof \
  -o /tmp/tui-event-dns-replay.test ./internal/pkg/tui
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -cum /tmp/tui-event-dns-replay.cpu.pprof
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -alloc_space /tmp/tui-event-dns-replay.allocs.pprof
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -list 'EventStore.*AddEvent' /tmp/tui-event-dns-replay.cpu.pprof
```

The installed toolchain lacks the `go tool pprof` binary, but its local
`cmd/pprof` source works without installing a dependency. The workload, commands,
and attribution above preserve reproducibility.
The TUI correctness suite and race suite pass. Rendering purity and bounded
refresh cadence remain explicit later-phase changes, not passing Phase 1
baseline invariants.

### Phase 1 append-workload review

- [x] Correct the `EventsView` append benchmark to introduce one new retained
      event on every iteration, including across fixture-cycle boundaries.
- [x] Independently review the cyclic fixture and rerun the affected benchmark,
      component correctness tests, and race-enabled checks.

The previous `BenchmarkEventsViewAppendViaSetEvents` appended only on its first
iteration, then repeatedly supplied the same projection. It now slides a fixed
1,000- or 10,000-event window over a pool one event larger than retention and
selects the newest event after each refresh. Every operation adds one event and
evicts one, with no duplicate retained IDs. A one-second review run measured
132 µs/op and 1.21 ms/op respectively, both with zero steady-state allocations.
These are observational measurements of the corrected workload, which includes
updating selection; they are not a performance comparison with the old fixture.

The review also passed the TUI correctness and race suites, reran the Phase 1
benchmarks, and reproduced the DNS replay CPU/allocation profiles. The replay
measured 137.78 ms/op and 150,051,905 bytes/op; profiles again exposed full
synchronization, selection lookup, packet materialization, visible projection,
and front eviction. No Phase 1 production-code defect was found.

Likely files:

- `internal/pkg/tui/store/event_store_test.go`
- `internal/pkg/tui/components/eventsview_test.go`
- `internal/pkg/tui/event_view_test.go`
- optional focused benchmark files beside those tests

## 6. Phase 2 — Coalesce Delivery and Bound Refresh Frequency

Remove the largest multiplicative cost before redesigning storage.

- [x] Change local pending-event draining so all batches selected for one tick
      are combined into one ordered `EventBatchMsg`, including loss records and
      compatibility omissions.
- [x] Verify coalescing does not reorder events or associate loss metadata with
      the wrong delivery boundary.
- [x] Introduce event-view dirty state and timestamps in `Model`.
- [x] Store every accepted event batch immediately, but synchronize presentation
      state at a bounded cadence comparable to the packet list.
- [x] Extract or reuse the packet list's refresh-cadence and pressure decision
      logic where its semantics are identical; do not duplicate its threshold
      calculation for events.
- [x] Start with the normal TUI refresh interval and the shared packet/event
      pressure policy rather than introducing event-specific magic intervals.
- [x] Permit user actions—view entry, filter changes, selection/navigation,
      resize, pause/resume, and clear—to request an immediate synchronization.
- [x] Ensure remote singleton or small batches cannot drive an unbounded render
      rate through direct `program.Send` calls.
- [x] Add deterministic tests proving that many arrivals inside one refresh
      window produce one presentation synchronization while all accepted events
      reach the store.

Likely files:

- `internal/pkg/tui/local_event_sink.go`
- `internal/pkg/tui/update_handlers.go`
- `internal/pkg/tui/eventhandler.go`
- `internal/pkg/tui/event_view.go`
- `internal/pkg/tui/model.go`

### Phase 2 implementation and verification

Local ticks submit one `EventBatchMsg` containing the ordered original
deliveries in `Batches`. Keeping those boundaries preserves event order,
transport-loss records, compatibility omissions, and stream cursor metadata.
Queue overflow reports follow the preceding accepted deliveries, including
across partial drains, and precede later accepted deliveries.

Remote callbacks now enqueue in a bounded model-owned queue rather than calling
`Program.Send` for each event batch. Normal active ticks drain at most 50
deliveries; paused and inactive remote ticks drain the final backlog completely.
The model ingests each drained batch synchronously and marks presentation dirty
only when retention changes. One recurring tick chain continues at a slow
cadence while inactive/paused, preventing stranded deliveries across disconnect,
reconnect, and mode changes without creating duplicate polling loops.

Event refresh uses the normal 50 ms `TUITickInterval` and the same extracted
pressure policy as the packet paths: double the base interval above 1% recent
bridge drops, 250 ms above 10%, and 500 ms above 30%. Only the active Capture
event view synchronizes on dirty ticks. Explicit view/tab entry, filters,
selection, resize, pause/resume, clear, and capture completion can refresh
immediately. Packet arrivals and retention changes mark the event view dirty
so related-packet notices remain current. Pause transitions account for queued
remote events under the preceding pause state; clear and restart clear queued
remote data with the retained state.

The unconditional `renderCaptureTab` synchronization was removed as a Phase 2
dependency: retaining it would bypass the cadence limit on every render. The
remaining component rendering mutations and full Phase 3 purity audit are still
deferred. Full projection, linear selection maintenance, and packet scans remain
later-phase work.

Three sub-agents implemented/reviewed delivery, cadence, and interaction paths.
Independent cross-review caught and verified fixes for disconnected backlogs,
duplicate tick chains, and queued data reappearing after clear. Deterministic
tests cover ordered coalescing/loss boundaries, 50 accepted arrivals with one
refresh, idle ticks without synchronization, render calls inside a refresh
window, pause/mode gating, immediate user actions, and packet-only eviction.

On the same Intel Core i9-13900HX, one-second benchmark runs measured:

| Workload                                          | Phase 1 time/op | Phase 2 time/op | Phase 2 allocated bytes/op |
| ------------------------------------------------- | --------------: | --------------: | -------------------------: |
| Local tick, 50 singleton batches, 10,000 retained |        67.54 ms |        12.26 ms |                    499,379 |
| Remote batch, 1 event, 10,000 retained            |         1.57 ms |         1.38 ms |                    485,049 |
| Remote batch, 128 events, 10,000 retained         |        30.31 ms |        31.75 ms |                    511,147 |

Remote benchmarks now include queue admission and tick processing; Phase 1
called the batch handler directly. Both local and remote benchmarks advance
`TickMsg.Time` by the normal refresh interval and assert exactly one sync per
operation. This prevents fast benchmark iterations from accidentally measuring
ingestion alone. Timings remain observational, not CI thresholds. The remaining
128-event ingestion cost is consistent with the unchanged per-event store
selection scans, which Phase 4 addresses.

The 15-second DNS replay profile measured 21.63 ms/op, 5,016,548 bytes/op, and
36,356 allocations/op, versus the recorded Phase 1 126.19 ms/op and 149,964,780
bytes/op. It uses the same generated frames, retention, packet/event delivery,
viewport, and loss assertions, with deterministic tick timestamps. Event
synchronization now follows packet ingestion once per tick. CPU attribution
shows synchronization at 14.10% cumulative and store selection maintenance at
55.76% flat. Packet materialization and visible projection account for 44.63%
and 9.03% of allocation volume respectively. Profiles still include setup;
cumulative CPU percentages overlap. The workload still excludes terminal-driver
and disk-I/O costs and is not a mixed-protocol capture.

Verification passed: the full TUI correctness and race suites under `-tags all`,
all Phase 1 benchmark workloads, the profiled replay, and builds with `tui` and
`all` tags. Go files were formatted and the TUI architecture notes updated.
Reproduce the profiles with the Phase 1 replay command.

### Phase 2 navigation review

Review found that deferred presentation could leave the store's live-edge
selection ahead of the displayed selection. With event 3 displayed and selected,
accepting events 4–5 before a refresh made Up select event 4 instead of event 2.
Arrow keys, page navigation, and mouse-wheel navigation shared this problem.

- [x] Anchor relative event navigation to the displayed stable ID when it is
      still retained, then move and synchronize once. Preserve the store's
      selection fallback when the displayed event has been evicted.
- [x] Verify regression coverage for all relative navigation paths, history
      pinning, live-edge following, and eviction; run TUI correctness and race
      checks and build the `tui` and `all` variants.

Three sub-agents reviewed delivery, cadence, and interactions. The navigation
regression was independently reproduced in all six relative input paths before
the fix, and the correction received independent cross-review. Focused tests
and the uncached full TUI race suite passed; both build variants passed. The
local/remote synchronization benchmark smoke run also preserved its one-sync
assertions. No further Phase 2 defect was confirmed; later-phase storage,
projection, and rendering work remains deferred as planned.

## 7. Phase 3 — Make Rendering Pure

Eliminate redundant full synchronization and make update ownership explicit.

- [x] Remove `syncEventsView()` from `renderCaptureTab` (required by Phase 2 cadence).
- [x] Audit the complete TUI render path for other event-store reads or state
      mutations that belong in `Update` handlers.
- [x] Synchronize on entry to the event view and on explicit dirty refreshes.
- [x] Ensure tab switches and unrelated Bubble Tea messages do not rebuild the
      event projection.
- [x] Add a test that repeatedly calls `View()` without model updates and
      verifies that event projection and selection state do not change.
- [x] Add an operation-count regression test showing that an event update causes
      at most one synchronization/render projection.

Likely files:

- `internal/pkg/tui/view_renderer.go`
- `internal/pkg/tui/event_view.go`
- `internal/pkg/tui/event_view_test.go`

### Phase 3 implementation and verification

The render-path audit found event-store filter reads and shared header/footer
mutation in `Model.View`, timeline offset updates in `RenderTimeline`, and
detail viewport initialization, sizing, and content projection in `RenderDetails`.
Initialization and the public `Update` wrapper now prepare header/footer state;
settings-dialog sizing also moved out of rendering. Event synchronization applies
items, stable selection, and related-packet availability before `PrepareLayout`
prepares the timeline geometry and detail viewport. Event rendering performs no
store reads, synchronization, or persistent state mutation.

Component setters maintain the timeline offset before rendering, including for
mouse hit testing, eviction, and resizing. Detail scrolling survives unchanged
refreshes and hiding/reopening the pane. Selection, related-packet availability,
theme, width, and clear invalidate detail content; height changes clamp scrolling.
Clean tab returns reuse the existing event projection, while dirty or uninitialized
returns refresh immediately. Explicit event-view entry and dirty cadence refreshes
retain their existing synchronization ownership.

Two sub-agents implemented the component and model changes; a third independently
audited the render and update paths. Root review and suite verification caught a
partial-model fixture panic in chrome preparation and unnecessary repeated selection
scans; both were corrected. Regression tests exercise the public `Update`/`View`
path, snapshot event projection/selection/scroll and chrome before the first render,
and confirm rendering works with the event store detached. Operation-count checks
verify one synchronization per due event refresh, none on renders or clean tab
round trips, and one detail projection per relevant invalidation.

Full TUI correctness and race suites under `-tags all` passed, as did `tui` and
`all` builds. The existing store/component/model benchmarks and generated DNS replay
were rerun. Storage, full projection, and related-packet scan optimizations remain
Phases 4–6; unrelated specialized views were audited for event access but their
own component rendering behavior is outside this phase's event-state scope.

Final one-second runs on the same Intel Core i9-13900HX measured:

| Workload                                          | Phase 2 time/op | Phase 3 time/op | Phase 3 allocated bytes/op |
| ------------------------------------------------- | --------------: | --------------: | -------------------------: |
| Local tick, 50 singleton batches, 10,000 retained |        12.26 ms |        11.67 ms |                    499,206 |
| Remote batch, 1 event, 10,000 retained            |         1.38 ms |         1.28 ms |                    484,759 |
| Remote batch, 128 events, 10,000 retained         |        31.75 ms |        29.41 ms |                    509,840 |

The final one-second DNS replay smoke measurement was 20.65 ms/op and
5,127,473 bytes/op (50 packets/op), compared with the recorded Phase 2
15-second profile run's 21.63 ms/op and 5,016,548 bytes/op. These observational
runs have different durations and do not establish a new CPU-performance claim.
The replay retains its arrival, eviction, selection, and zero-loss assertions.
Append-via-SetEvents measured 81.60 µs/op and 940.23 µs/op at 1,000 and 10,000
retained events, respectively, with zero steady-state allocations. Use the Phase 1
commands to reproduce the benchmark workloads. No timing threshold was added to CI.

### Phase 3 double-click review

- [x] Prepare event presentation after the mouse double-click details toggle,
      so opening the pane immediately displays the selected event.
- [x] Independently reproduce the blank pane through public `Update` calls
      and verify the fix preserves exactly one synchronization per click.

The mouse handler synchronized while details were still hidden, then toggled
the pane open. With rendering now read-only, the pane stayed blank until a
later synchronization. Moving the existing synchronization after the toggle
prepares the final layout without adding another projection. Two sub-agents
audited component and model ownership; root independently reproduced the
regression before applying the fix. No other Phase 3 defect was confirmed.
The new regression passed independent cross-review. Full TUI correctness and
race suites, `tui` and `all` builds, and the local/remote synchronization
benchmark smoke checks passed after the fix. Go files were formatted.

## 8. Phase 4 — Implement True Bulk EventStore Ingestion

Make batch cost depend on the batch and final retained state, not capacity per
event. Use `PacketStore`'s existing circular-buffer implementation as the
algorithmic reference.

- [x] Document the packet ring invariants used by `AddPacketBatch`, ordered
      materialization, and `GetNewPackets` before porting them.
- [x] Rewrite `EventStore.AddBatch` to acquire the mutex once.
- [x] Validate and account for nil and file-content events inside the bulk
      operation without changing statistics semantics.
- [x] Append accepted events and update arrival sequences in one pass.
- [x] Apply capacity truncation once per batch and account for every evicted
      event exactly.
- [x] Replace front-of-slice shifting with the same preallocated backing slice,
      head index, count, and overwrite mechanics used by `PacketStore` so
      steady-state append/evict is O(1).
- [x] Validate or repair selection once after the batch is applied.
- [x] Keep `AddEvent` as a thin wrapper around the bulk implementation so the
      two paths cannot diverge.
- [x] Add wraparound, oversized-batch, exact-capacity, pause, selection-eviction,
      and race tests.
- [x] Confirm benchmarks no longer show capacity-sized copies per insertion.
- [x] Add table-driven equivalence tests that run the packet and event ring
      algorithms through empty, partial, full, wraparound, and oversized-batch
      cases and compare their ordered retention behavior.
- [x] Do not modify `PacketStore` merely to create a generic container during
      this phase.

Likely files:

- `internal/pkg/tui/store/event_store.go`
- `internal/pkg/tui/store/event_store_test.go`

### Phase 4 packet-ring reference

Before porting, the reference `PacketStore` invariants are:

- The backing slice has fixed length equal to capacity. The head identifies the
  next write slot; count is bounded by capacity. Each append overwrites that slot,
  advances head modulo capacity, and increments count only while below capacity.
- Ordered retention starts at `(head - count + capacity) % capacity` and visits
  exactly count slots. Before filling, this starts at zero; at capacity, head is
  the oldest retained item. Oversized batches retain their newest capacity items.
- `AddPacketBatch` holds one mutex across all writes and trims its separate
  filtered projection once after insertion. Event storage will retain its own
  filtering and selection contracts rather than copying that projection cache.
- `GetNewPackets` uses the monotonic total-arrival counter, never the bounded
  count, as its cursor. A positive delta below capacity reads the newest delta
  slots ending immediately before head; a delta at least capacity requests full
  refresh. The event delta API remains Phase 5 work.

### Phase 4 implementation and verification

`EventStore` now uses preallocated event and visibility slices, a next-write head,
and a bounded count. All reads traverse live slots in arrival order. `AddBatch`
holds one mutex, rejects nil/file-content entries without counting them, accounts
for supported paused arrivals without consuming retention sequences, and writes
accepted events directly into the ring. Eviction accounting is applied once per
batch, including events overwritten within an oversized batch. `AddEvent` is a
thin wrapper; `PacketStore` was not changed.

Cached visibility and the first/last visible slots preserve selection transitions
through intermediate evictions without per-event retained-buffer scans. Advancing
the first visible slot visits each intervening retained slot at most once, making
ingestion and selection maintenance amortized O(1) per event. The selected ID is
committed once after the batch. This preserves the existing physical-oldest
fallback followed by visible-boundary repair, including after filter broadening.
Filter changes rebuild visibility. Reset releases retained event references and
preserves pause/filter state. Events remain immutable normalized snapshots;
repeated delivery of the same stable ID has the same filter metadata.

Two sub-agents implemented production code and tests, and a third independently
reviewed both. Root reviewed the diff and compared the new store against the
previous implementation using 60,000 seeded operations with unique IDs and another
60,000 with repeated immutable events. Both comparisons passed across oversized
batches, filters, navigation, pause, and reset. Temporary legacy-comparison files
were removed after verification; permanent regressions cover eight packet/event
ring equivalence scenarios, exact accounting, filtered selection eviction,
concurrent access, randomized batch/singleton equivalence, repeated identities,
zero-allocation steady-state ingestion, and reset reference release.

Full TUI correctness and race suites under `-tags all` passed, as did `make tui all`.
The existing store/component/model benchmark suite and generated DNS capture replay
passed their assertions. Full projection and packet relationship scans remain
Phases 5–6; no claim is made here about completing those optimizations or the
plan's final mixed-mode manual/CPU acceptance gates.

Final one-second runs on the same Intel Core i9-13900HX, without concurrent test
workloads, measured:

| Workload                                             | Before Phase 4 time/op | Phase 4 time/op | Phase 4 allocated bytes/op |
| ---------------------------------------------------- | ---------------------: | --------------: | -------------------------: |
| Batch eviction, 128 events, capacity 1,000           |               2.616 ms |         9.03 µs |                          0 |
| Batch eviction, 128 events, capacity 10,000          |              28.023 ms |         9.41 µs |                          0 |
| Single-event selection maintenance, following latest |               20.01 µs |        95.93 ns |                          0 |
| Single-event selection maintenance, pinned history   |                6.26 µs |        88.95 ns |                          0 |
| Local tick, 50 singleton batches, 10,000 retained    |               11.67 ms |         1.03 ms |                    488,408 |
| Remote batch, 1 event, 10,000 retained               |                1.28 ms |         0.97 ms |                    484,122 |
| Remote batch, 128 events, 10,000 retained            |               29.41 ms |         0.98 ms |                    484,099 |

Store baselines were measured immediately before this implementation; model
baselines are the recorded Phase 3 runs. The new pinned-selection-eviction
benchmark measured 9.39–10.77 µs per 128-event batch across both capacities and
filtered/unfiltered cases, with zero allocations. These results and source review
confirm that capacity-sized copies and scans no longer occur per insertion.
Timings are observational, not CI thresholds; allocation assertions are deterministic.

The one-second generated DNS replay measured 5.66 ms/op and 5,243,130 bytes/op
for 50 packets, versus Phase 3's 20.65 ms/op and 5,127,473 bytes/op. Arrival,
eviction, selection, and zero-loss assertions passed. This phase primarily reduces
ingestion CPU; full-projection and packet-scan allocations remain. Reproduce with
the Phase 1 commands,
adding `BenchmarkEventStorePinnedSelectionEviction` and the DNS replay workload.

## 9. Phase 5 — Introduce Incremental Event Projection

Avoid rebuilding and copying the entire visible event collection for ordinary
append-only updates. Mirror the established packet-list incremental flow:
detect a projection change, use a full refresh only when required, otherwise
retrieve a sequence delta, trim the view, and append new rows.

- [x] Add an event equivalent of `PacketStore.GetNewPackets`, keyed by the
      existing monotonic arrival sequence and a projection/filter revision.
- [x] Return the same essential outcome as the packet API: new visible items,
      the new synchronization cursor, and whether a full refresh is required.
- [x] Define any additional event-view delta fields narrowly—for example the
      number of visible items trimmed, selection ID, and projection generation.
- [x] Have `EventStore.AddBatch` expose or retain enough change information to
      build the delta without scanning the full store.
- [x] Add typed `EventsView.AppendEvents` and `EventsView.TrimOldEvents`
      operations modeled on `PacketList.AppendPackets` and
      `PacketList.TrimOldPackets`, plus reset and stable-ID selection updates.
- [x] Maintain an ID-to-logical-index map, or equivalent stable index, so
      selection operations do not repeatedly scan the full projection.
- [x] Reserve full projection rebuilds for protocol/source/user-filter changes,
      resets, or recovery from a generation mismatch.
- [x] Ensure filtering new arrivals evaluates only the new events; filter
      changes may intentionally perform one full rebuild.
- [x] Keep viewport offset and follow-latest behavior correct across circular
      buffer wraparound and filtered evictions.
- [x] Add equivalence tests that compare incremental results with a reference
      full projection across randomized batches, filters, selections, and
      evictions.
- [x] Add parallel packet/event incremental-sync scenarios proving both paths
      make the same full-refresh versus delta decisions for equivalent ring
      states.

Likely files:

- `internal/pkg/tui/store/event_store.go`
- `internal/pkg/tui/components/eventsview.go`
- `internal/pkg/tui/event_view.go`
- corresponding test files

### Phase 5 implementation and verification

`EventStore.GetNewEvents` returns an atomic cursor, selection, visible eviction
count, and new visible rows. Arrival sequences address the newest ring slots;
cached per-slot visibility avoids re-evaluating predicates during synchronization.
Filter revisions and reset invalidate the cursor. Missing at least capacity
arrivals requests a recovery snapshot, matching `PacketStore.GetNewPackets`.
Unchanged protocol/source filters preserve the revision. Explicit navigation
uses cached ring visibility without allocating a complete projection; ordinary
refresh selection uses the component's constant-time stable-ID index.

The model uses full snapshots only for initialization, invalidation, or recovery,
and detects store replacement even if its cursor values match the prior store.
`EventsView` maintains absolute ID positions, including linked repeated-ID
occurrences, across trims and amortized backing-slice compaction. Evicted event
references are cleared immediately. The model appends before trimming so an ID
evicted and reintroduced in one delta retains its original viewport anchor.
Selection and layout are prepared after the complete update; rendering stays
read-only. Full reset still clears detail state.

Two sub-agents implemented store and component changes, while root integrated
the model and a third agent independently reviewed the result. Review reproduced
and verified fixes for repeated-ID detail-scroll reset and viewport drift.
Permanent tests compare 9,000 randomized store operations with an independently
filtered full projection and 5,000 atomic component deltas with full `SetEvents`
updates, alongside 3,000 individual component-operation comparisons. Parallel
packet/event scenarios verify recovery decisions; deterministic tests cover
cached predicate work, idle/invisible zero-allocation deltas, bounded index work,
reference release, unchanged filters, reset, store replacement, and model full-
refresh counts. Independent exhaustive viewport comparisons also passed.

Full TUI correctness and race suites under `-tags all` and `make tui all` passed.
Go files were formatted. The same generated DNS replay passed arrival, eviction,
selection, and zero-loss assertions. No Phase 6 packet index or final mixed-mode
manual/CPU acceptance claim is included in this phase.

One-second runs on the same Intel Core i9-13900HX measured:

| Workload                                          | Phase 4 time/op | Phase 5 time/op | Phase 5 allocated bytes/op |
| ------------------------------------------------- | --------------: | --------------: | -------------------------: |
| Local tick, 50 singleton batches, 10,000 retained |         1.03 ms |        16.20 µs |                     12,218 |
| Remote batch, 1 event, 10,000 retained            |         0.97 ms |         1.13 µs |                        423 |
| Remote batch, 128 events, 10,000 retained         |         0.98 ms |        34.75 µs |                     16,141 |
| Generated DNS replay, 50 packets                  |         5.66 ms |         3.61 ms |                  4,669,859 |

Incremental component append/trim/selection measured 134.1 ns and 134.7 ns at
1,000 and 10,000 retained events, with zero steady-state allocations. Store
append plus unfiltered delta measured 138.0 ns and 140.9 ns, respectively, with
48 bytes per operation. The filtered alternating-kind workload measured
125.1–141.5 ns and 24 amortized bytes per operation. Model synchronization
benchmarks retain their exactly-one-sync-per-tick assertions. These timings are
observations rather than CI thresholds; retained-capacity-independent work is
also guarded by deterministic operation-count tests. Replay allocations still
include full packet-buffer relationship scans, which Phase 6 addresses.

Reproduce using the Phase 1 benchmark command with
`Benchmark(EventStoreIncrementalProjection|EventsViewAppendIncremental|ModelEventBatchSynchronization|ModelEventDNSReplay)$`.

## 10. Phase 6 — Remove Full Packet-Buffer Scans

Make related-packet availability an indexed lookup that follows packet-buffer
retention.

- [x] Define a canonical bidirectional flow key using node identity, transport,
      source/destination addresses, and ports.
- [x] Maintain reference counts or newest retained packet sequence per flow key
      as packets enter and leave the packet ring.
- [x] Query the index for the selected event rather than copying/scanning the
      complete packet buffer.
- [x] Recompute related-packet availability only when selection changes or when
      packet eviction/addition affects the selected flow.
- [x] Handle incomplete event flow identity conservatively and preserve current
      behavior for node IDs that are absent.
- [x] Add tests for forward/reverse flow matching, node separation, port reuse,
      circular-buffer eviction, filtered packet views, and empty flow fields.
- [x] Verify packet-only ingestion stays close to baseline with lazy activation,
      and quantify active-index ingestion overhead alongside end-to-end gains.
      See the measured tradeoff below; active maintenance is not cost-free.

Likely files:

- `internal/pkg/tui/store/packet_store.go`
- `internal/pkg/tui/event_view.go`
- related store and event-view tests

### Phase 6 implementation and verification

`PacketStore.HasRelatedPacket` replaces routine packet-buffer materialization
and scanning with a canonical bidirectional endpoint key. TCP and UDP remain
separate even when application labels are identical. `PacketDisplay.Transport`
preserves the decoded transport through shared capture, local fast/full, and
remote conversion; remote processor metadata supplies a fallback when raw bytes
cannot provide it. Absent node IDs preserve the previous wildcard behavior.
Unknown legacy transport also matches conservatively; missing/invalid addresses,
missing/zero ports, and unsupported transports do not establish a relationship.
IPv4-mapped addresses normalize to IPv4.

The first valid relationship query activates the index with one traversal of
retained ring slots, without allocating an ordered packet copy. Packet-only
sessions skip index maintenance. Once activated, exact-node and all-node counts
follow insertion and eviction, and empty entries are deleted. A single selected-
flow cache is invalidated by matching membership changes, selection of another
flow, or retention replacement. Unrelated packets, display filters, and statistics
counter resets do not invalidate it. Activation persists across buffer resets;
resize/replacement rebuild active indexes. Clear and capture restart now use the
store's reset APIs, releasing retained references and invalidating availability.

Two sub-agents implemented store/model changes, and a third independently
reviewed them. Root reviewed the final code, integrated transport propagation,
verified the tests and benchmarks, and avoided inactive-path packet copies before
index helper calls. Permanent coverage includes forward/reverse matching, node
and transport separation, port reuse, incomplete identity, IPv6 normalization,
filtered display versus raw retention, selection-specific invalidation, lazy
activation after wraparound, resize/replacement, clear/restart, and concurrent
retention/query access. An independent reference test checks 10,000 randomized
mutations and 400,000 cached/uncached queries. Cached store queries have a
zero-allocation assertion.

On the same Intel Core i9-13900HX, one-second runs measured:

| Workload                                   | Before Phase 6 |  Phase 6 | Phase 6 allocated bytes/op |
| ------------------------------------------ | -------------: | -------: | -------------------------: |
| Related-packet miss, 1,000 retained        |       39.05 µs | 141.9 ns |                        384 |
| Related-packet miss, 10,000 retained       |      502.27 µs | 135.1 ns |                        384 |
| Unchanged synchronization, 10,000 retained |              — | 125.9 ns |                          0 |
| Generated DNS replay, 50 packets           |       2.631 ms | 1.457 ms |                  1,099,345 |

The replay's arrival, eviction, selection, and zero-loss assertions pass. Replay
allocation volume fell from 4,542,155 bytes/op by approximately 76%. The helper
miss benchmark still includes one event-interface allocation; the store lookup
and unchanged synchronization allocate nothing. These are observational timings,
not CI thresholds or a mixed-protocol production performance claim.

Same-binary controls preserve the previous `AddPacketBatch` implementation for
comparison. At 1,000 retained packets, a 64-packet batch measured 9.84 µs for the
control, 9.82 µs with the index inactive, and 35.30 µs with it active. At 10,000
retained packets the measurements were 14.70, 15.65, and 38.78 µs respectively.
A separate 20,000-flow churn workload into a 10,000-packet ring measured
15.15 µs control versus 51.24 µs indexed per batch. Active maintenance therefore
has measurable primitive-ingestion overhead, approximately 0.3–0.6 µs per packet;
it is not a zero-cost operation. Lazy activation keeps packet-only overhead
small, while the measured active event replay improves overall. Packet-buffer
allocation volume remains comparable to the control; reported integer
allocations/op round fractional backing-slice allocations and do not imply that
packet ingestion allocates nothing.

Reproduce the lookup/replay and ingestion measurements with:

```bash
go test -tags all -run '^$' -benchtime=1s -benchmem \
  -bench 'Benchmark(HasRelatedPacketMiss|SyncEventsView|ModelEventDNSReplay)' \
  ./internal/pkg/tui
go test -tags all -run '^$' -benchtime=1s -benchmem \
  -bench 'BenchmarkPacketFlow(Ingestion|IngestionChurn|InactiveIngestion)$' \
  ./internal/pkg/tui/store
```

Full TUI, capture, and remote-capture correctness/race suites and `make tui all`
passed. Go files were formatted and TUI architecture documentation updated.
Phase 7 rendering work and the plan's final mixed-mode manual/CPU acceptance
remain separate; this phase does not claim those gates are complete.

### Phase 6 source-identity review

Independent review found a preexisting integration defect that the original
Phase 6 tests missed: local events use producer ID `watch-local`, but retained
packets use display ID `Local`. Remote tap/processor-local events similarly use
the processor ID while their packets use `<processor>-local`. Exact-node lookup
therefore displayed a false missing-packet warning despite retaining the packet.

- [x] Reproduce the local mismatch using the production bridge's generated
      event and converted packet through normal model packet delivery.
- [x] Normalize only the relationship query's node identity for local capture
      and the exact remote processor-local source alias; preserve stored event
      identity, ordinary remote node separation, and absent-node semantics.
- [x] Cover live/offline, custom local producers, tap, unrelated remote nodes,
      source provenance, and clear invalidation; independently review the fix.
- [x] Correct the replay fixture to use production node identities and decoded
      transport, and assert selected-event related-packet availability.
- [x] Format changed Go files, run uncached race checks across TUI, capture,
      and remote-capture packages, and build both `tui` and `all` variants.

Root independently reproduced the failing bridge regression before applying the
fix and verified both sub-agent reviews. Store reference counts, canonical keys,
lazy activation, and selected-flow cache invalidation required no changes.

One-second review benchmarks on the same i9-13900HX passed. The corrected DNS
replay measured 1.575 ms and 1,112,688 bytes per 50 packets, with arrival,
eviction, selection, loss, and relationship assertions passing. Unchanged
synchronization measured 146–157 ns with zero allocations; related-packet misses
measured 164–177 ns at 1,000/10,000 retained packets. The fixture correction
changes node identity and transport metadata, so these replay timings are not
an exact comparison with the original fixture.

The ingestion controls again confirmed the documented tradeoff. At 1,000
retained packets, a 64-packet batch measured 9.43 µs control, 9.18 µs inactive,
and 37.61 µs active; at 10,000, results were 16.82, 18.47, and 44.23 µs.
Churn measured 17.83 µs control versus 58.93 µs active. No timing thresholds or
claims about Phase 7/manual acceptance were added.

## 11. Phase 7 — Optimize Visible-Row Rendering

Only pursue this phase after profiling the preceding changes; storage and
synchronization are expected to dominate current CPU usage.

- [x] Re-profile the active event view and confirm timeline formatting remains
      a material hotspot before changing it.
- [x] Reuse or extract the packet list's style-cache invalidation pattern for
      theme, width, and focus changes instead of creating a second cache
      lifecycle.
- [x] Cache reusable Lip Gloss styles and column-width calculations using that
      shared lifecycle.
- [x] Cache immutable row presentation fields or rendered rows when doing so
      reduces measured allocations without complicating invalidation.
- [x] Continue rendering only viewport-visible rows.
- [x] Preserve sanitization, Unicode width correctness, protocol colors, and
      fixed column alignment.
- [x] Add allocation benchmarks and visual-output equivalence tests.

Likely files:

- `internal/pkg/tui/components/eventsview.go`
- `internal/pkg/tui/components/eventsview_test.go`

### Phase 7 implementation and verification

The post-Phase 6 generated DNS replay profile confirmed the prerequisite:
`RenderTimeline` consumed 14.14% cumulative sampled CPU and 11.73% of allocation
volume. The 15-second run measured 1.616 ms per 50-packet operation, 1,083,855
bytes/op, and 6,359 allocations/op. Profiles include setup; cumulative CPU
attribution overlaps. The original unprepared fixed DNS viewport measured
498–512 µs/op and 1,732 allocations/op at 1,000/10,000 retained events.

`PrepareLayout` now caches column widths, header/protocol/selection styles, and
only viewport-visible row strings. Overlapping rows reuse absolute projection
positions across append/trim, including repeated stable IDs. Full snapshots,
theme changes, and width changes invalidate row formatting; height changes reuse
overlap and release the old row slice. Selection styles reuse prepared plain
text. Unchanged preparation and focus changes do no row formatting. Cached rows
hold no event references. A shared `paneStyleCache` handles theme/dimension
invalidation and both focus border variants for packet and event panes.

`RenderTimeline` remains read-only, including when called between setters and
layout preparation or with alternate dimensions. Those calls build a temporary
local cache. Sanitization and field bounds remain in place. Timeline fitting now
uses terminal cells, correcting the previous rune-count alignment for CJK,
emoji, and combining sequences; ASCII has a fast path. Detail formatting is
unchanged.

Two sub-agents implemented production changes and independent legacy-output
controls; a third reviewed the implementation and added 350 randomized lifecycle
comparisons. Root reviewed their code and tests. Review caught and fixed a
duplicate-ID navigation case where recomputing an offset differed from the
committed viewport offset. Frozen pre-cache renderers verify event and packet
output across theme/focus/size transitions, navigation, delta updates, full
replacement, empty/reset state, sanitization, and widths through 1,000 columns.
Wide Unicode uses explicit cell-alignment assertions instead of preserving the
old alignment bug. Deterministic tests verify bounded cache size, release on
shrink, visible-only formatting, reuse on selection/focus, and pure fallback
rendering. The existing detail-projection counter test isolates its timeline
to zero data rows so its unchanged assertions measure only detail preparation.

One-second runs on the same Intel Core i9-13900HX measured:

| Workload                          | Retained | Time/op | Bytes/op | Allocations/op |
| --------------------------------- | -------: | ------: | -------: | -------------: |
| Prepared DNS timeline             |    1,000 |  241 µs |  258,041 |            648 |
| Prepared DNS timeline             |   10,000 |  225 µs |  250,021 |            648 |
| Mixed-kind legacy control         |    1,000 |  720 µs |  439,852 |          1,880 |
| Mixed-kind cached timeline        |    1,000 |  330 µs |  273,287 |            649 |
| Mixed-kind legacy control         |   10,000 |  747 µs |  398,812 |          1,880 |
| Mixed-kind cached timeline        |   10,000 |  313 µs |  243,728 |            649 |
| Append/trim/select/prepare/render |    1,000 |  368 µs |  277,254 |            701 |
| Append/trim/select/prepare/render |   10,000 |  365 µs |  258,125 |            701 |

The mixed-kind control is frozen Phase 6 code in the same test binary. The final
two rows include cache preparation in timed work. The DNS benchmark now labels
prepared and unprepared calls separately; unprepared fallback measured
481–503 µs and 1,726 allocations/op. A relative allocation assertion compares
cached rendering with its same-binary legacy control; no timing threshold is
encoded in tests.

Three isolated five-second DNS replay runs of saved before/after binaries had
median times of 1.645 ms and 1.684 ms per 50 packets respectively, with ranges of
1.640–1.749 ms and 1.670–1.883 ms. Allocations fell from 6,359 to 6,319 per
operation; bytes varied across runs at approximately 1.03–1.09 MB/op. This
workload replaces the complete visible viewport each tick and does not show a
clear end-to-end speedup from row reuse. Arrival, eviction, latest-selection,
related-packet availability, and zero-loss assertions pass. The substantial
measured Phase 7 gain is repeated/incremental timeline rendering, not a claim
about mixed-protocol production CPU or terminal-driver overhead.

A final isolated 15-second profile measured 1.659 ms/op, 1,070,154 bytes/op,
and 6,319 allocations/op. `RenderTimeline` accounted for 5.57% cumulative CPU;
update-side `buildTimelineCache` accounted for 9.89%. Reporting both avoids
mistaking moved formatting work for eliminated work when every row is new.

Reproduce the component measurements with:

```bash
GOCACHE=/tmp/lippycat-go-cache go test -tags all -run '^$' -benchtime=1s -benchmem \
  -bench '^BenchmarkEventsView(TimelineControl|TimelineAppendRender|RenderTimeline)$' \
  ./internal/pkg/tui/components
```

Use the Phase 1 replay/profile command for end-to-end measurements. The plan's
final manual live/offline/remote and Events/Packets/Statistics CPU acceptance
gates remain unchecked; automated rendering and replay tests do not substitute
for those checks.

Verification passed: full TUI correctness tests under `-tags all`, uncached
`go test -count=1 -race -tags all ./internal/pkg/tui/...`, both `make tui all`
builds, component benchmarks, and generated DNS replay/profiles. All changed Go
files were formatted and the TUI architecture notes updated.

## 12. Verification

After each phase (checked below for Phases 1–7):

- [x] Format all modified Go files with `gofmt` before staging.
- [x] Run focused event-store, event-view, and TUI tests with the appropriate
      `tui`/`all` build tag.
- [x] Run the new benchmarks and compare with the recorded baseline.
- [x] Run race-enabled tests for the touched TUI/store packages.

Before completion:

- [x] Run the repository's relevant full test suite.
- [x] Build at least the `tui` and `all` variants.
- [x] Replay the same representative capture used for the baseline.
- [x] Compare active Events, Packets, and Statistics tab CPU and memory usage.
- [x] Exercise live, offline, and remote capture modes.
- [x] Exercise protocol/source/user filters, pause/resume, clear, selection,
      mouse navigation, keyboard navigation, resizing, and details scrolling.
- [x] Confirm event arrival, retention, eviction, paused, and transport-loss
      counters remain correct.
- [x] Confirm no accepted event is omitted except through an existing,
      observable bounded-buffer or pressure policy.
- [x] Update relevant TUI architecture documentation if synchronization or
      store APIs change materially.
- [x] Check off only tasks verified as complete.
- [x] Commit the code, tests, documentation, and this updated plan together as
      required by the repository workflow.

Suggested commands:

```bash
gofmt -w <modified-go-files>
go test -tags all ./internal/pkg/tui/...
go test -race -tags all ./internal/pkg/tui/...
go test -tags all -bench 'Event(Store|sView)' -benchmem ./internal/pkg/tui/...
make tui
make all
```

## 13. Completion Criteria

- [x] The active event view has a bounded refresh rate under local and remote
      event streams.
- [x] Ordinary event arrival does not trigger a full retained-event projection.
- [x] Bubble Tea rendering does not synchronize or mutate event state.
- [x] Steady-state event insertion and eviction do not shift the retained
      buffer.
- [x] Selection and related-packet checks avoid full-buffer scans on routine
      refreshes.
- [x] Benchmarks and profiles demonstrate the targets in Section 4.
- [x] Existing and new correctness, race, build, and manual verification gates
      pass.

Final mixed-mode acceptance (2026-09-05) passed. Measurements are retained in the
[offline Phase 6 benchmark report](../research/watch-file-offline-phase6-benchmarks.md#repeated-event-performance).
The same DNS replay and prepared-render workloads pass the original time and
allocation gates over five one-second samples. Incremental/related-packet
benchmarks and a CPU profile preserve the optimized behavior. Separate active
live/remote and idle offline measurements compare Events/Packets/Statistics.
Full TUI suites under `all`/`tui`, full race checks, both builds, controlled
mixed-mode delivery/interaction tests and actual terminal checks pass. Offline
terminal export and connected remote lifecycle were exercised with real binaries.
Live terminal presentation used controlled delivery because raw loopback capture
lacked OS permissions; no privileged NIC/transport throughput is claimed.
No synchronization/store API changes were needed for this acceptance step.

## 14. Risks and Mitigations

- **Event/loss ordering:** Coalescing can obscure delivery boundaries. Preserve
  source order and aggregate only fields whose semantics are additive; retain
  ordered loss controls if their placement matters.
- **Selection drift:** Circular storage and deltas can invalidate physical
  indices. Store logical sequence/ID identities and test wraparound heavily.
- **Stale filters:** Incremental projection requires explicit invalidation.
  Filter changes must advance a generation and force one full rebuild.
- **Stale related-packet state:** Tie cache invalidation to selected flow and
  packet-ring membership changes, not only event arrival.
- **Over-throttling:** Ingestion must remain immediate; only presentation is
  throttled. Direct navigation and filter actions should refresh immediately.
- **Premature render caching:** Do not add complex row caches unless post-Phase
  6 profiles demonstrate that rendering is still significant.

## 15. Non-Goals

- Changing normalized event schemas or analyzer behavior.
- Changing remote event transport compatibility or delivery guarantees.
- Increasing the default event retention capacity.
- Coupling TUI subscriber pressure to hunter or processor flow control.
- Optimizing unrelated Calls, Queries, Email, HTTP, or Statistics views.
