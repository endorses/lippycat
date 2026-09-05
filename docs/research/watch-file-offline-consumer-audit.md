# Offline packet consumer and retained history audit

Date: 2026-09-05. Baseline: `fff6c68f`. This is the phase 0 inventory for
[the scalable offline dataset plan](../plans/watch-file-scalable-offline-dataset.md).
It describes existing behavior and obligations for later phases; it does not
claim that disk-backed browsing or complete export has shipped.

## Audit coverage

The audit searched non-test Go sources in `cmd/watch` and `internal/pkg/tui` for
`packetStore`, `PacketList`, `GetPackets`, `GetPacketsInOrder`,
`GetFilteredPackets`, `getPacketsToSave`, `[]components.PacketDisplay`, and
`[]types.PacketDisplay`, then inspected their callers, count mutations, filter
paths, event relationships, and store implementations. Tests and benchmarks are
validation references rather than production consumers. `components.PacketDisplay`
is an alias of the shared packet type, so both spellings matter.

| Consumer                                                                                                                           | Current slice/count dependency                                                                                                                                                    | Offline migration obligation                                                                                                                                                                                                                                      |
| ---------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `store/packet_store.go`: `AddPacket`, `AddPacketBatch`, ordered/filtered getters, incremental getters, resize/reset/filter methods | Raw ring and separate bounded last-matching slice; getters copy retained data. Public counters/fields are also read and mutated directly.                                         | Keep live/remote implementation; offline count, pages, filters and resets must use session/query state. A page cache cannot become a ring that deletes logical packets.                                                                                           |
| `components/packetlist.go`: `SetPackets`, append/trim, `Len`, cursor/page methods, `SetCursor`, `View`, row formatting             | `int` positions and `len(p.packets)` define the entire dataset. Selection is repaired using timestamps/endpoints and scans. Relative-time fallback uses the slice's first packet. | Logical `uint64` row positions and stable dataset/query/packet identity, bounded page-local indexing, dataset time origin, loading rows and async requests. Preserve live selection/scroll behavior. No disk reads or complete-dataset scans in rendering/layout. |
| `helpers.go`: `updateDetailsPanel`                                                                                                 | Reads `GetPackets()[GetCursor()]` and passes a copied packet to DetailsPanel.                                                                                                     | Resolve selection by stable ID, asynchronously load/pin full details, clear stale details during selection changes, reject stale generations. DetailsPanel itself consumes one packet and can remain a presentation component.                                    |
| `keyboard_navigation.go`: `handleMoveUp/Down`, `handleJumpToTop/Bottom`, `handlePageUp/Down`                                       | Bottom jump explicitly uses `len(GetPackets())-1`; remaining operations delegate to slice-bound component methods.                                                                | Navigate complete query count and request destination pages even outside cache; empty results and out-of-order completions must be safe.                                                                                                                          |
| `mouse_handler.go`: wheel handlers and both packet click paths                                                                     | Click index is `GetOffset()+visibleRow`, bounded against the whole slice, then `SetCursor`; wheel delegates cursor motion.                                                        | Hit-test logical visible rows independently of loaded page indices; request details only for current selection. Both split-details and full-width layouts need coverage.                                                                                          |
| `helpers.go`: `updatePacketListIncremental`, unfiltered/filtered helpers, `doFullPacketListRefresh`                                | Total/matched arrival counters drive full copies or append/trim to `MaxPackets`.                                                                                                  | Retain these for live rings; offline page publication must not count rows as arrivals or trim logical history.                                                                                                                                                    |
| `filter_helpers.go`: `parseAndApplyFilter`                                                                                         | Offline/paused apply synchronously calls `ReapplyFilters`, then copies filtered retained packets.                                                                                 | Snapshot compiled predicates and scan dataset summaries asynchronously; publish description, count, selection and query stats atomically.                                                                                                                         |
| `filter_operations.go`: empty `handleFilterInput` submission                                                                       | Clears filter and directly resets `FilteredPackets`, `MatchedPackets`, PacketList and sync counters.                                                                              | Empty input must publish an all-record query through the same cancellable workflow as apply.                                                                                                                                                                      |
| `keyboard_handler.go`: `handleClearAllFilters`, `handleRemoveLastFilter`                                                           | Direct chain mutation, retained reapplication or full retained copy; different live/paused branches.                                                                              | Route every offline remove/clear through query generations, preserving previous completed query on cancellation/failure. Do not broaden only the current page.                                                                                                    |
| `update_handlers.go`: `handleProtocolSelectedMsg`                                                                                  | Clears/replaces packet filter with protocol BPF or restores retained packets; updates sync counters.                                                                              | Protocol selection is also an offline query transition, including returning to All.                                                                                                                                                                               |
| `event_view.go`: `setCaptureView`                                                                                                  | Returning to packets copies raw ring or reads public `FilteredPackets`.                                                                                                           | Restore current dataset query/page rather than materializing the dataset or resetting its selection.                                                                                                                                                              |
| `event_view.go`: `hasRelatedPacket`, `syncEventsViewAt`; `store/packet_flow.go`: `HasRelatedPacket`                                | Lazy flow-count index covers retained raw ring independently of display filters; single-selection availability cache.                                                             | Dataset-wide lookup independent of viewport/cache. Preserve endpoint direction equivalence, node wildcard and TCP/UDP/unknown transport matching. Translate local event node to `Local`, and processor-local provenance to capture-source node as today.          |
| Related-event navigation                                                                                                           | Existing event code displays packet availability; the audit found no event-to-packet jump handler.                                                                                | Phase 4 must add dataset-backed navigation as well as replacing availability. Test reaching an old packet outside the page cache; absence from cache must never mean unavailable or lost.                                                                         |
| `helpers.go`: `processPendingPackets`, `updateStatistics`; `capture_events.go`: packet/batch handlers                              | Adds delivered packets to ring; accumulates statistics and drives calls from deliveries. Some paths write active streaming save.                                                  | Indexing owns once-per-logical-packet normalization, stats and ordered analyzer input. UI pages must never rerun analysis or increment totals. Keep live pre-sampling ingress snapshots.                                                                          |
| `components/statistics*.go`, `model.go` statistics initialization                                                                  | Global counters passed from model, not recomputed from selected packets; no complete filtered-statistics scan exists. Protocol/source/destination counters have cardinality caps. | Separate global dataset snapshot from complete-query snapshot and document bounded cardinality approximation.                                                                                                                                                     |
| `view_renderer.go`: shared header/footer setup                                                                                     | Header uses retained `PacketsCount/MaxPackets`; footer reads chain/count. Capture-complete handler reads total arrivals.                                                          | Distinguish processed/dataset/matching/cached counts, disk/cache bytes and bounded histories. Changing header count alone cannot fix completeness.                                                                                                                |
| `save_operations.go`: `getPacketsToSave`, `startOneShotSave`, `determineSaveMode`                                                  | Offline always one-shot; worker reads model store to obtain entire retained raw/filtered slice and picks first packet's link type.                                                | Pin immutable session/query before worker starts; stream every matching packet with cancellation, bounded memory, close errors and mixed-link-type handling. Do not silently encode all records with the first link type.                                         |
| `save_operations.go`: `startStreamingSave`, `getFilterFunction`                                                                    | Live/remote seed save with retained slice and retain mutable filter chain reference.                                                                                              | Preserve existing mode scope; offline exports must not use this API or its snapshot assumptions.                                                                                                                                                                  |
| `keyboard_handler.go`: `handleClearPackets`; `capture_lifecycle.go`: restart; `update_handlers.go`: buffer resize                  | Clears/resizes ring and presentation; clear also resets statistics. Restart clears old capture state before new replay.                                                           | Define offline clear as closing/resetting the session, never deleting only loaded rows while claiming an intact dataset. Replacement must preserve old completed state until new session is ready. Buffer resizing must not cap offline logical count.            |
| `model.go`, `store/ui_state.go`                                                                                                    | Construct PacketStore and slice-backed PacketList; model owns statistics, trackers and lifecycle state.                                                                           | Introduce session ownership and mode adapter without coupling general storage to components/Bubble Tea.                                                                                                                                                           |
| `bridge.go`, `eventhandler.go`, `background_processor.go`                                                                          | Offline pending packet slice grows without bound; event handler routes packet batches; background batch submission consumes slices.                                               | Write authoritative offline records outside UI queues. Preserve bounded live delivery and avoid offline background drops; session adapter must own analyzer drain.                                                                                                |
| `cmd/watch/file.go`, `capture_lifecycle.go`, `update_handlers.go`: file selection/settings                                         | Startup and in-TUI replay have separate ownership and restart routes.                                                                                                             | One model-owned cancellable open workflow with frozen inputs/configuration and atomic session installation.                                                                                                                                                       |

## Processed versus retained packet semantics

`watch.buffer_size` defaults to 10,000. Each delivered packet increments
`PacketStore.TotalPackets`, while `PacketsCount` is capped at `MaxPackets`.
`FilteredPackets` independently retains up to the last `MaxPackets` matches and
can contain a match older than the raw ring. On interactive offline reapplication,
`reapplyFilters` discards that list and scans only the current raw ring; removing
or broadening a filter therefore cannot recover earlier packets. `MatchedPackets`
counts matches since the current filter's last reset/reapplication, not an
immutable full-file count. An active match list and raw ring must not be described
as necessarily identical retained sets.

Current offline statistics accumulate delivered packets even after ring eviction,
so normal fully drained replay can show processed totals larger than browsable or
exportable history. This is not proof of source completeness: the existing ordered
reader collects and sorts all input, and source failures can log-and-continue.
The UI bridge's offline pending slice is unbounded, so the bounded final ring is
not a bound on indexing/replay RSS.

Protocol counts retain at most 1,000 keys; source and destination counts retain
10,000 each (`model.go`). The current `Increment` implementation ignores new keys once capacity is reached
(despite stale eviction comments); existing tracked keys continue to increment. Packet/byte totals
and min/max sizes are separate from these approximate cardinality summaries.

## Events and Calls are bounded histories

`NewModel` creates EventStore at packet `bufferSize`, default 10,000. `AddBatch`
skips nil and file-content events, increments `Arrived` for accepted metadata
inputs, and either increments `Paused` without retaining during pause or writes
the FIFO ring. Ring overwrite increments `Evicted`; `Retained` is current ring
occupancy, not number matching event filters. Kind/user filters project retained
history and do not expand it. Duplicate event IDs remain distinct arrival rows;
selection/projection behavior must preserve existing arrival sequence semantics.

`TransportLost` is separate from ring eviction and pause. `handleEventBatchMsg`
records explicit losses by kind and compatibility omissions under
`compatibility_omission`. Count-less loss ranges use inclusive sequence lengths;
a control without a usable count/range still counts as one observable gap.

The local offline sink blocks on its own queue (`preserveAll`) and supports flush
barriers, but its downstream `pendingLocalEventBuffer` caps at 4,096 batches.
`localEventSink.run` normally emits one event per batch. A full pending buffer
rejects incoming batches and accumulates their event/loss/compatibility counts;
a later ordered buffer-loss control reports them. Offline draining takes all
pending batches, while normal draining takes at most 50. Thus a completed analyzer
or sink flush does not establish lossless retained-history delivery. Phase 3 must
feed the isolated session's bounded event store directly or through a bounded,
cancellable backpressured worker; ring eviction remains legitimate retention,
and must stay distinct from delivery loss. Preserve EOF flush and final loss
visibility before publishing Ready.

CallStore uses update-recency LRU, sized by `watch.max_calls` (default 5,000),
with chronological display sorting by StartTime and CallID. Repeated updates
refresh recency. Evicted calls lose retained filter visibility; a later update
can reinsert the same ID and increment `totalCalls` again. `totalCalls` therefore
is not a globally deduplicated complete-file call count; `Clear` does not reset
that cumulative field. There is no equivalent CallStore transport-loss counter.

The upstream `voip.CallAggregator` has its own default 1,000-call LRU;
`NewLocalCallAggregator` uses that default. The bridge CallTracker separately
caps at 5,000 calls with bounded media-endpoint associations. Offline
`processPendingPackets` processes calls synchronously, avoiding background queue
drops at that stage, but does not remove those analyzer/history caps. Live calls
may use the dropping BackgroundProcessor. Packet completeness must not promise
complete call history or erase bounded analyzer-state caveats. Replacement
sessions need isolated aggregators/trackers and their resulting retained Calls
projection installed together with Events and dataset statistics.
