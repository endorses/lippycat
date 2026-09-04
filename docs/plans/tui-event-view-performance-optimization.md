# TUI Event View Performance Optimization Plan

**Date:** 2026-09-04
**Status:** Phase 1 verified; Phases 2–7 planned
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

| Workload | Time/op | Allocated bytes/op |
| --- | ---: | ---: |
| Remote batch, 1 event, 10,000 retained | 1.57 ms | 484,736 |
| Remote batch, 128 events, 10,000 retained | 30.31 ms | 512,221 |
| Local tick, 50 singleton batches, 10,000 retained | 67.54 ms | 24,232,643 |
| Batch eviction, 128 events, capacity 1,000 | 2.90 ms | 184 |
| Batch eviction, 128 events, capacity 10,000 | 31.87 ms | 18,618 |
| Synchronization, 10,000 events and unrelated packets | 1.96 ms | 2,809,861 |
| Related-packet miss, 10,000 retained packets | 0.58 ms | 2,326,918 |

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
`cmd/pprof` source works without installing a dependency. Profile binaries live
in `/tmp`; the workload, commands, and attribution above preserve reproducibility.
The TUI correctness suite and race suite pass. Rendering purity and bounded
refresh cadence remain explicit later-phase changes, not passing Phase 1
baseline invariants.

Likely files:

- `internal/pkg/tui/store/event_store_test.go`
- `internal/pkg/tui/components/eventsview_test.go`
- `internal/pkg/tui/event_view_test.go`
- optional focused benchmark files beside those tests

## 6. Phase 2 — Coalesce Delivery and Bound Refresh Frequency

Remove the largest multiplicative cost before redesigning storage.

- [ ] Change local pending-event draining so all batches selected for one tick
      are combined into one ordered `EventBatchMsg`, including loss records and
      compatibility omissions.
- [ ] Verify coalescing does not reorder events or associate loss metadata with
      the wrong delivery boundary.
- [ ] Introduce event-view dirty state and timestamps in `Model`.
- [ ] Store every accepted event batch immediately, but synchronize presentation
      state at a bounded cadence comparable to the packet list.
- [ ] Extract or reuse the packet list's refresh-cadence and pressure decision
      logic where its semantics are identical; do not duplicate its threshold
      calculation for events.
- [ ] Start with the normal TUI refresh interval and the shared packet/event
      pressure policy rather than introducing event-specific magic intervals.
- [ ] Permit user actions—view entry, filter changes, selection/navigation,
      resize, pause/resume, and clear—to request an immediate synchronization.
- [ ] Ensure remote singleton or small batches cannot drive an unbounded render
      rate through direct `program.Send` calls.
- [ ] Add deterministic tests proving that many arrivals inside one refresh
      window produce one presentation synchronization while all accepted events
      reach the store.

Likely files:

- `internal/pkg/tui/local_event_sink.go`
- `internal/pkg/tui/update_handlers.go`
- `internal/pkg/tui/eventhandler.go`
- `internal/pkg/tui/event_view.go`
- `internal/pkg/tui/model.go`

## 7. Phase 3 — Make Rendering Pure

Eliminate redundant full synchronization and make update ownership explicit.

- [ ] Remove `syncEventsView()` from `renderCaptureTab`.
- [ ] Audit the complete TUI render path for other event-store reads or state
      mutations that belong in `Update` handlers.
- [ ] Synchronize on entry to the event view and on explicit dirty refreshes.
- [ ] Ensure tab switches and unrelated Bubble Tea messages do not rebuild the
      event projection.
- [ ] Add a test that repeatedly calls `View()` without model updates and
      verifies that event projection and selection state do not change.
- [ ] Add an operation-count regression test showing that an event update causes
      at most one synchronization/render projection.

Likely files:

- `internal/pkg/tui/view_renderer.go`
- `internal/pkg/tui/event_view.go`
- `internal/pkg/tui/event_view_test.go`

## 8. Phase 4 — Implement True Bulk EventStore Ingestion

Make batch cost depend on the batch and final retained state, not capacity per
event. Use `PacketStore`'s existing circular-buffer implementation as the
algorithmic reference.

- [ ] Document the packet ring invariants used by `AddPacketBatch`, ordered
      materialization, and `GetNewPackets` before porting them.
- [ ] Rewrite `EventStore.AddBatch` to acquire the mutex once.
- [ ] Validate and account for nil and file-content events inside the bulk
      operation without changing statistics semantics.
- [ ] Append accepted events and update arrival sequences in one pass.
- [ ] Apply capacity truncation once per batch and account for every evicted
      event exactly.
- [ ] Replace front-of-slice shifting with the same preallocated backing slice,
      head index, count, and overwrite mechanics used by `PacketStore` so
      steady-state append/evict is O(1).
- [ ] Validate or repair selection once after the batch is applied.
- [ ] Keep `AddEvent` as a thin wrapper around the bulk implementation so the
      two paths cannot diverge.
- [ ] Add wraparound, oversized-batch, exact-capacity, pause, selection-eviction,
      and race tests.
- [ ] Confirm benchmarks no longer show capacity-sized copies per insertion.
- [ ] Add table-driven equivalence tests that run the packet and event ring
      algorithms through empty, partial, full, wraparound, and oversized-batch
      cases and compare their ordered retention behavior.
- [ ] Do not modify `PacketStore` merely to create a generic container during
      this phase.

Likely files:

- `internal/pkg/tui/store/event_store.go`
- `internal/pkg/tui/store/event_store_test.go`

## 9. Phase 5 — Introduce Incremental Event Projection

Avoid rebuilding and copying the entire visible event collection for ordinary
append-only updates. Mirror the established packet-list incremental flow:
detect a projection change, use a full refresh only when required, otherwise
retrieve a sequence delta, trim the view, and append new rows.

- [ ] Add an event equivalent of `PacketStore.GetNewPackets`, keyed by the
      existing monotonic arrival sequence and a projection/filter revision.
- [ ] Return the same essential outcome as the packet API: new visible items,
      the new synchronization cursor, and whether a full refresh is required.
- [ ] Define any additional event-view delta fields narrowly—for example the
      number of visible items trimmed, selection ID, and projection generation.
- [ ] Have `EventStore.AddBatch` expose or retain enough change information to
      build the delta without scanning the full store.
- [ ] Add typed `EventsView.AppendEvents` and `EventsView.TrimOldEvents`
      operations modeled on `PacketList.AppendPackets` and
      `PacketList.TrimOldPackets`, plus reset and stable-ID selection updates.
- [ ] Maintain an ID-to-logical-index map, or equivalent stable index, so
      selection operations do not repeatedly scan the full projection.
- [ ] Reserve full projection rebuilds for protocol/source/user-filter changes,
      resets, or recovery from a generation mismatch.
- [ ] Ensure filtering new arrivals evaluates only the new events; filter
      changes may intentionally perform one full rebuild.
- [ ] Keep viewport offset and follow-latest behavior correct across circular
      buffer wraparound and filtered evictions.
- [ ] Add equivalence tests that compare incremental results with a reference
      full projection across randomized batches, filters, selections, and
      evictions.
- [ ] Add parallel packet/event incremental-sync scenarios proving both paths
      make the same full-refresh versus delta decisions for equivalent ring
      states.

Likely files:

- `internal/pkg/tui/store/event_store.go`
- `internal/pkg/tui/components/eventsview.go`
- `internal/pkg/tui/event_view.go`
- corresponding test files

## 10. Phase 6 — Remove Full Packet-Buffer Scans

Make related-packet availability an indexed lookup that follows packet-buffer
retention.

- [ ] Define a canonical bidirectional flow key using node identity, transport,
      source/destination addresses, and ports.
- [ ] Maintain reference counts or newest retained packet sequence per flow key
      as packets enter and leave the packet ring.
- [ ] Query the index for the selected event rather than copying/scanning the
      complete packet buffer.
- [ ] Recompute related-packet availability only when selection changes or when
      packet eviction/addition affects the selected flow.
- [ ] Handle incomplete event flow identity conservatively and preserve current
      behavior for node IDs that are absent.
- [ ] Add tests for forward/reverse flow matching, node separation, port reuse,
      circular-buffer eviction, filtered packet views, and empty flow fields.
- [ ] Verify the index adds negligible cost to packet ingestion benchmarks.

Likely files:

- `internal/pkg/tui/store/packet_store.go`
- `internal/pkg/tui/event_view.go`
- related store and event-view tests

## 11. Phase 7 — Optimize Visible-Row Rendering

Only pursue this phase after profiling the preceding changes; storage and
synchronization are expected to dominate current CPU usage.

- [ ] Re-profile the active event view and confirm timeline formatting remains
      a material hotspot before changing it.
- [ ] Reuse or extract the packet list's style-cache invalidation pattern for
      theme, width, and focus changes instead of creating a second cache
      lifecycle.
- [ ] Cache reusable Lip Gloss styles and column-width calculations using that
      shared lifecycle.
- [ ] Cache immutable row presentation fields or rendered rows when doing so
      reduces measured allocations without complicating invalidation.
- [ ] Continue rendering only viewport-visible rows.
- [ ] Preserve sanitization, Unicode width correctness, protocol colors, and
      fixed column alignment.
- [ ] Add allocation benchmarks and visual-output equivalence tests.

Likely files:

- `internal/pkg/tui/components/eventsview.go`
- `internal/pkg/tui/components/eventsview_test.go`

## 12. Verification

After each phase (checked below for Phase 1):

- [x] Format all modified Go files with `gofmt` before staging.
- [x] Run focused event-store, event-view, and TUI tests with the appropriate
      `tui`/`all` build tag.
- [x] Run the new benchmarks and compare with the recorded baseline.
- [x] Run race-enabled tests for the touched TUI/store packages.

Before completion:

- [ ] Run the repository's relevant full test suite.
- [ ] Build at least the `tui` and `all` variants.
- [ ] Replay the same representative capture used for the baseline.
- [ ] Compare active Events, Packets, and Statistics tab CPU and memory usage.
- [ ] Exercise live, offline, and remote capture modes.
- [ ] Exercise protocol/source/user filters, pause/resume, clear, selection,
      mouse navigation, keyboard navigation, resizing, and details scrolling.
- [ ] Confirm event arrival, retention, eviction, paused, and transport-loss
      counters remain correct.
- [ ] Confirm no accepted event is omitted except through an existing,
      observable bounded-buffer or pressure policy.
- [ ] Update relevant TUI architecture documentation if synchronization or
      store APIs change materially.
- [ ] Check off only tasks verified as complete.
- [ ] Commit the code, tests, documentation, and this updated plan together as
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

- [ ] The active event view has a bounded refresh rate under local and remote
      event streams.
- [ ] Ordinary event arrival does not trigger a full retained-event projection.
- [ ] Bubble Tea rendering does not synchronize or mutate event state.
- [ ] Steady-state event insertion and eviction do not shift the retained
      buffer.
- [ ] Selection and related-packet checks avoid full-buffer scans on routine
      refreshes.
- [ ] Benchmarks and profiles demonstrate the targets in Section 4.
- [ ] Existing and new correctness, race, build, and manual verification gates
      pass.

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
