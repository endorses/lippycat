# Research: Scalable Complete-File Analysis for `lc watch file`

## Objective

Make `lc watch file` behave like a file analyzer rather than a live capture:

- Every packet in the selected PCAP files belongs to the browsable dataset.
- Aggregate statistics cover the complete dataset.
- Interactive filters evaluate the complete dataset, including packets that are
  not currently visible.
- Very large captures do not require all packet payloads and decoded metadata to
  remain in memory.
- Multiple concurrently captured files remain ordered by capture timestamp.

The `--buffer-size` setting should continue to describe live and remote capture
retention. It should not silently truncate an offline file.

## Executive Summary

The current offline path processes the complete input, but the TUI retains only
the newest `buffer-size` packet records. Statistics are accumulated while all
packets pass through the model, whereas later interactive filtering scans only
the retained ring. The result is an inconsistent user model: the TUI has
analyzed the file, but the packet list and filters cannot address all of it.

Increasing the packet buffer to the PCAP packet count is not a safe general
solution. A `PacketDisplay` includes raw bytes, strings, and potentially large
protocol metadata, and several pipeline stages hold overlapping packet slices.
Packet count therefore does not provide a useful upper bound on memory.

The recommended design is an offline-specific, disk-backed `PacketDataset`:

1. Scan or merge the input files sequentially.
2. Run complete-stream statistics and stateful protocol analysis during that
   pass.
3. Persist compact display and filter records in logical timestamp order.
4. Keep only a byte-bounded window/page cache in memory.
5. Load raw packet bytes and detailed decoding on demand.
6. Evaluate interactive filters asynchronously across the complete dataset and
   store their ordered matching packet IDs.

This design deliberately separates offline storage from the live
`PacketStore` ring rather than adding more mode-dependent behavior to it.

## Current Architecture

### Offline ingestion

`cmd/watch/file.go` creates the normal TUI model using
`watch.buffer_size`, then starts timestamp-ordered replay through:

```text
capture.StartOfflineSnifferOrdered
    -> capture.RunOfflineOrdered
    -> NormalizeCaptureStream
    -> StartEnvelopeBridge(preserveAll=true)
    -> TUI Model
```

`RunOfflineOrdered` currently:

- Reads every packet from every input file.
- Copies its raw bytes.
- Retains the decoded `gopacket.Packet`.
- Appends all packets to one `[]PacketInfo`.
- Stable-sorts the complete slice by timestamp.
- Sends the sorted packets through a blocking channel.

The blocking channel makes the main replay boundary lossless, but reading and
sorting the complete input makes peak memory proportional to capture size.

### Offline bridge

The TUI bridge treats replay as lossless. Its offline pending queue is an
unbounded slice, unlike the bounded live ring. If ingestion outruns Bubble Tea
processing, a substantial part of the capture can accumulate there as another
in-memory representation.

### Packet retention

`internal/pkg/tui/store.PacketStore` is a circular buffer sized by
`watch.buffer_size`. It tracks:

- `TotalPackets`: all packets accepted by the model.
- `Packets`: at most `MaxPackets` recent packet records.
- `FilteredPackets`: at most `MaxPackets` recent matching records.
- `MatchedPackets`: matches observed while packets entered the store.

Once the ring wraps, older records cannot be retrieved.

### Statistics semantics

Offline statistics are updated while every delivered packet passes through
`Model.processPendingPackets`. Consequently, unfiltered aggregate statistics
can cover the full replay even though the detail list contains only its tail.

This is useful behavior and should be retained, but the statistics must become
an explicit product of the complete dataset scan rather than an incidental
side effect of feeding the display ring.

### Interactive filter semantics

Changing a TUI filter calls `PacketStore.ReapplyFilters()`, which scans only the
records still present in the circular buffer. Therefore:

- Initial CLI BPF filtering applies while reading the PCAP and covers the input.
- Interactive filters added after loading cover only the retained tail.
- `MatchedPackets` is reset to the number of retained records matching the new
  filter.

This violates the expectation that opening a file makes the complete file
searchable.

## Requirements and Semantics

### Completeness

For a successfully loaded dataset:

- Logical packet count equals the number of packets accepted after the initial
  capture-time BPF filter and reassembly policy.
- Packet navigation can reach any logical packet.
- Interactive filters evaluate all logical packets.
- Global statistics describe all logical packets.
- Filtered statistics, when shown, describe all matches rather than the cached
  viewport.

### Bounded memory

Memory should be controlled in bytes, not packet count. The limit should cover
decoded pages, raw packet payloads, and filter result working state where
practical. Large inputs may consume disk and take longer, but should not cause
unbounded RAM growth.

### Stateful analysis

VoIP correlation, TCP reassembly, DNS/HTTP tracking, TLS processing, and similar
analysis cannot be reconstructed reliably by decoding arbitrary display pages
in isolation. The initial scan must feed stateful analyzers in logical timestamp
order. Lazy loading applies to browsing and details, not to whether the packet
is analyzed.

### Responsiveness

The TUI should remain usable while indexing or filtering:

- Show indexing/filtering progress.
- Allow cancellation.
- Avoid replacing a valid result set with a partially computed one.
- Permit browsing already indexed ranges if doing so does not complicate the
  first implementation excessively.

### Entry-point independence

Opening an offline dataset is a TUI model operation, not a responsibility of
the `lc watch file` command alone. The same lifecycle and guarantees must apply
when files are supplied by:

- `lc watch file file1.pcap file2.pcap` at startup.
- The offline settings view.
- The reusable file dialog inside the TUI.
- A capture-mode restart that selects one or more PCAP files.
- Any future recent-file or reopen action.

All entry points should produce the same model-level request, such as
`OpenOfflineDatasetMsg`, containing the file list and analysis configuration.
No entry point should construct, index, or install a dataset directly.

## Options Considered

### Option A: Resize the packet ring to the packet count

This preserves the existing model but requires either a preliminary counting
pass or dynamic growth.

Advantages:

- Small implementation change.
- Existing packet list and filtering continue to work.

Disadvantages:

- Packet count does not predict memory consumption.
- Raw data and protocol metadata can be much larger than the PCAP itself once
  represented as Go objects.
- `RunOfflineOrdered`, the bridge, `PacketStore`, `FilteredPackets`, and
  `PacketList` can hold overlapping representations.
- Allocation of a huge ring may fail before useful work begins.
- Filtering remains an O(N) in-memory operation that blocks or burdens the UI.

Conclusion: reject as the default architecture. It may be retained as an
internal small-file optimization selected by an estimated byte budget.

### Option B: Keep only a moving PCAP window and rescan on demand

The TUI could discard old packets and reopen/rescan the PCAP whenever the user
scrolls outside the retained window.

Advantages:

- Minimal persistent storage.
- Straightforward for a single classic PCAP.

Disadvantages:

- Backward scrolling can become very slow.
- Filters require repeated full scans.
- Stateful protocol analysis is difficult to reproduce for arbitrary windows.
- Multiple files require repeating timestamp merge work.
- PCAPNG access depends on preceding interface and block context.

Conclusion: unsuitable as the primary design.

### Option C: Direct offsets into original files

Build an index containing packet metadata and original file offsets, then seek
back to the source for details.

Advantages:

- Avoids duplicating raw packet bytes on disk.
- Efficient for classic PCAP with simple record offsets.

Disadvantages:

- PCAPNG packets depend on section/interface metadata and block structure.
- Reassembled or decapsulated logical packets may not correspond to one source
  record.
- Source files must remain unchanged and available for the session/index life.
- Cross-format readers need different locator implementations.

Conclusion: useful as a later optimization, but it should sit behind a dataset
interface rather than define the first implementation.

### Option D: Normalized disk-backed dataset

During the initial scan, write normalized records to an append-only session
file and maintain an index of logical packet IDs to record offsets.

Advantages:

- Works consistently for PCAP and PCAPNG.
- Can represent reassembled/decapsulated logical packets.
- Supports efficient sequential scans and random page reads.
- Makes the original files irrelevant after successful indexing.
- Provides a clean boundary between analysis and presentation.

Disadvantages:

- Requires temporary disk space.
- Introduces serialization and lifecycle management.
- May duplicate packet bytes already present in the source.

Conclusion: recommended initial architecture. Direct source-file locators can
later reduce disk use without changing TUI consumers.

## Recommended Architecture

### Offline `PacketDataset`

Introduce an interface owned by the offline analysis subsystem rather than the
live packet store. A conceptual API is:

```go
type PacketID uint64

type PacketDataset interface {
    Count() uint64
    GlobalStatistics() StatisticsSnapshot
    Page(ctx context.Context, query QueryID, start, count uint64) ([]PacketSummary, error)
    Details(ctx context.Context, id PacketID) (*PacketDisplay, error)
    ApplyFilter(ctx context.Context, chain *filters.FilterChain, progress func(FilterProgress)) (QueryID, error)
    FilteredStatistics(query QueryID) (StatisticsSnapshot, bool)
    Close() error
}
```

The exact types can change, but callers should address logical rows and pages,
not the backing slices.

### Record separation

Separate cheap list/filter data from expensive details:

```text
PacketSummary
  packet ID, timestamp, source file/interface
  addresses, ports, protocol, length, info
  compact metadata presence/type fields
  selected filterable protocol fields

PacketDetails
  raw packet bytes
  complete decoded protocol metadata
  hex/details-panel representation inputs
```

The summary schema must cover every currently supported interactive packet
filter. Otherwise applying a filter would require decoding every full packet
again. Schema ownership should be centralized so new filter fields explicitly
declare their indexed representation.

### Disk layout

A simple first implementation can use:

- An append-only data file containing length-delimited normalized records.
- A fixed-width offset table indexed by `PacketID`.
- A summary stream suitable for sequential filtering.
- A small manifest containing schema version, source identities, counts, and
  completion state.

Only a completed manifest should make a dataset reusable. Interrupted or
failed session datasets should be removed safely.

An embedded database is not required initially. A purpose-built sequential
format matches the dominant operations and avoids adding a large or CGo-backed
dependency.

### Page cache

Replace full-list ownership in `PacketList` with a virtual row provider:

- Maintain a stable logical cursor/index.
- Request the visible page plus prefetch pages before and after it.
- Cache pages with an LRU governed by a byte budget.
- Pin the selected packet while its details panel uses it.
- Cancel stale page requests after large cursor jumps or filter changes.

The cache size and the UI page size are independent of total dataset size.

### Complete statistics

Global statistics should be accumulated during indexing and finalized when the
dataset scan completes. This includes protocol, address, byte, packet-size, and
other current statistics.

If a counter is intentionally bounded, such as top-N or bounded-cardinality
address counts, that limitation should remain explicit and independent of
packet retention.

### Complete filtering

Applying an interactive filter should start a background sequential scan of the
summary records:

1. Compile/validate the filter chain.
2. Allocate a new unpublished query result.
3. Evaluate each summary in logical order.
4. Append matching `PacketID` values.
5. Accumulate filtered statistics if required.
6. Report scanned/matched counts periodically.
7. Publish the query atomically only after successful completion.

The first representation can be a disk-backed or memory-bounded chunked vector
of `uint64` packet IDs. A compressed bitmap is worthwhile only after profiling;
it is not required to establish correct semantics.

Repeated filter chains can be cached by a canonical filter hash. Cache entries
must be invalidated when the dataset or filter schema version changes.

## Multi-File Timestamp Merge

### K-way merge

Reading all files and globally sorting N packets costs O(N) packet memory and
O(N log N) sorting time. Since packets inside each capture are normally already
timestamp ordered, use a min-heap containing the next logical packet from each
file:

```text
open K sequential readers
read one packet from each reader into a min-heap

while heap is not empty:
    pop earliest packet
    analyze and append it to the dataset
    read the next packet from the same source
    push that packet into the heap
```

This costs O(K) packet memory and O(N log K) heap operations.

### Simultaneously captured SIP and RTP files

The merge works when a SIP PCAP and RTP PCAP cover the same call at the same
time. It orders their packets using capture timestamps without requiring either
file to be designated as signaling or media.

Required caveats:

- Each input should be internally monotonic. Timestamp regressions should be
  detected and reported; a bounded reorder window can be considered later.
- Equal timestamps need a deterministic key, for example timestamp, source
  argument index, then per-source packet sequence.
- Captures from different hosts may have clock skew. The merge cannot infer
  true causal order from unsynchronized timestamps.
- Existing orphan-RTP buffering/correlation must remain available when media
  precedes its SIP/SDP due to clock skew or capture boundaries.
- Overlapping captures can contain duplicate packets. Deduplication is a
  separate optional policy and must not happen silently.

A future explicit per-file time-offset option is safer than automatic clock
correction. Automatic alignment may be researched using shared flow signatures,
but should expose confidence and never rewrite timestamps invisibly.

### Reassembly interaction

Fragment reassembly state is naturally per input file/interface. A file cursor
may consume multiple physical records before yielding one logical packet into
the heap. TCP and application analyzers then consume the globally merged logical
stream.

## Loading Lifecycle and User Experience

Suggested states:

```text
Opening -> Indexing -> Ready
              |          |
              v          v
          Cancelled    Filtering -> Ready
              |
              v
            Failed
```

### Indexing modal

Indexing should use the existing unified modal rendering in
`internal/pkg/tui/components/modal.go`. A dedicated indexing-modal component can
own presentation and keyboard/mouse handling while dataset construction remains
outside the component.

The modal should show:

- Current phase, such as opening, scanning, merging, analyzing, finalizing, or
  cleaning up.
- Current file or source count.
- Bytes scanned versus total source bytes where available.
- Logical packets indexed.
- Elapsed time and estimated completion when the estimate is meaningful.
- Temporary disk use and configured limit.
- A progress bar and a clear Cancel action.

The modal should prevent interaction with stale packet-list state while a new
dataset is being constructed. Whether the previous dataset remains visible
behind it is a presentation choice, but it should remain installed until the
new dataset reaches `Ready`. A failed or cancelled replacement must not leave a
half-built dataset active.

The modal is not merely decorative. Its active state should correspond to one
owned indexing session, including its context, session ID, progress channel,
and completion result. Progress and completion messages must carry the session
ID so delayed messages from a cancelled or superseded operation cannot update
the new session's modal or install the wrong dataset.

### Context-driven cancellation

Use a session-scoped `context.WithCancel` for indexing. The model owns the
cancel function; the modal's Cancel button and cancellation key send a Bubble
Tea message that asks the model to invoke it.

```text
OpenOfflineDatasetMsg
    -> cancel and join any prior indexing session
    -> context.WithCancel(model/session context)
    -> show indexing modal
    -> start dataset builder with session ID and context

CancelOfflineIndexMsg(session ID)
    -> invoke session cancel function
    -> show "Cancelling..."
    -> wait for worker cleanup/completion message
    -> close modal or restore prior dataset
```

Cancellation is cooperative rather than an unsafe goroutine termination. To
make it feel immediate, every potentially long or blocking stage must observe
the context frequently:

- PCAP/PCAPNG reader loops.
- K-way merge iteration.
- Sends into analyzers and dataset writers.
- Stateful analyzer processing where it can run for a long time.
- Serialization and periodic flush loops.
- Filter scans and page loads.

Blocking channel operations should select on `ctx.Done()`. File reads cannot
always be interrupted mid-system-call, but regular local-file reads return
quickly; the loop must check cancellation before decoding or reading the next
record. Final cleanup should close readers, writers, and incomplete dataset
files before reporting cancellation complete.

The first Cancel requests graceful cancellation. A forced second-cancel path is
not recommended initially because Go cannot safely kill a goroutine and the
temporary index may still be flushing. If shutdown latency is excessive, fix
the non-cooperative stage and surface `Cancelling...` rather than abandoning
resources silently.

### Shared open workflow

`cmd/watch/file.go` should only validate startup arguments, create the TUI, and
submit the same offline-open request used by the in-TUI settings/file-dialog
path. Dataset lifecycle belongs in the model or a session controller shared by
both flows.

The current in-TUI path already converges on `RestartCaptureMsg` with
`PCAPFiles`, handled by `Model.handleRestartCaptureMsg`. The implementation can
either evolve that message into a more explicit offline-dataset request or have
its offline branch delegate immediately to a shared `beginOfflineIndex` method.
The important constraint is that startup must not retain a parallel capture
goroutine implementation with different progress, cancellation, or cleanup
behavior.

During indexing, show:

- Files and bytes scanned.
- Logical packets indexed.
- Elapsed time and, when file sizes make it meaningful, estimated completion.
- Temporary disk use.
- A cancellation hint.

After loading, the header should describe dataset and cache separately, for
example:

```text
Packets: 8,412,779 | Cached: 2,048 | Index: 3.1 GiB
```

It should not display `10,000 / 10,000` in a way that suggests the file itself
contains only 10,000 packets.

While a filter is running, preserve the previous completed list until the new
result is ready, or clearly display a dedicated progress view. Do not expose a
partial list as though it were the final result.

## Cache and Index Lifecycle

### Session datasets

The first implementation should create a private temporary directory and remove
it on orderly exit. Startup may clean abandoned datasets that are clearly owned
by lippycat and older than a conservative threshold.

Temporary cleanup must use validated, narrowly scoped paths. Never recursively
remove a broad cache or temporary root.

### Reusable indexes

Reusable sidecars can be added later. Their identity should include at least:

- Canonical source path or stable source identifier.
- File size.
- Modification time.
- A content fingerprint covering enough data to avoid stale reuse.
- Dataset schema and analyzer version.
- Initial BPF filter and relevant decode configuration.
- TLS key-log identity when decrypted metadata affects summaries.

Reusing an index created under different analysis settings would produce
incorrect filtering and statistics, so configuration is part of the cache key.

### Disk limits

Configuration should support:

- Maximum session index bytes.
- Maximum reusable cache bytes.
- Cache directory.
- Eviction policy for completed reusable indexes.
- Behavior when disk space is insufficient.

Insufficient disk space should fail explicitly or offer a clearly labelled
truncated mode. It must not silently fall back to retaining only the newest
packets.

## Small-File Fast Path

An in-memory dataset remains useful for small captures. Selection should use an
estimated byte budget rather than packet count:

1. Estimate decoded summary/detail cost while sampling or scanning.
2. Keep the dataset in memory only while it stays below the configured budget.
3. Spill to the same disk-backed representation when the threshold is crossed.

Both implementations should satisfy the same `PacketDataset` interface so the
TUI does not care which backing was selected.

## Error Handling and Integrity

- Every read, serialization, flush, seek, and close error must be surfaced with
  file and operation context.
- A dataset becomes `Ready` only after all files, analyzers, statistics, index
  tables, and manifests complete successfully.
- Cancellation is not corruption; it should stop readers and background work,
  close resources, and remove the incomplete session dataset.
- A source timestamp regression should be observable even if processing can
  continue.
- Checksums or record framing should detect truncated/corrupt cached datasets.
- Dataset format changes require an explicit version and clean rejection of
  incompatible caches.

## Testing Strategy

### Correctness

- [ ] A capture larger than the former TUI buffer is fully navigable.
- [ ] An interactive filter can match packets near the beginning, middle, and
      end of that capture.
- [ ] Global statistics match a reference full sequential scan.
- [ ] Filtered statistics match an independent reference scan.
- [ ] Details and raw bytes belong to the selected logical packet after page
      eviction and reload.
- [ ] Filter result publication is atomic.

### Multi-file ordering

- [ ] Interleaved SIP and RTP files are emitted in timestamp order.
- [ ] Equal timestamps use deterministic source/sequence tie-breaking.
- [ ] Empty files and files with disjoint time ranges work.
- [ ] Timestamp regressions are reported.
- [ ] Fragment reassembly remains source-local while application analysis sees
      merged order.

### Resource bounds

- [ ] Peak memory remains within the configured cache budget within documented
      overhead.
- [ ] The heap retains O(file count) input packets.
- [ ] Filtering a result that matches every packet does not require an
      unbounded in-memory ID slice.
- [ ] Insufficient disk space produces an explicit error without publishing a
      partial dataset.

### Lifecycle

- [ ] Cancellation during indexing terminates promptly and removes incomplete
      session files.
- [ ] The indexing modal reflects real progress and remains active through
      cancellation cleanup.
- [ ] Delayed progress/completion messages from a cancelled session are ignored.
- [ ] Cancel stops readers, merge work, analysis, and dataset writes through the
      same session context.
- [ ] Cancellation during filtering leaves the previous completed query usable.
- [ ] Normal exit closes and removes session storage.
- [ ] Reusable indexes reject modified sources and incompatible schema or
      analysis configuration.
- [ ] Startup file arguments and files opened through settings/file dialogs use
      the same indexing controller and produce equivalent datasets.
- [ ] Replacing an open dataset keeps the previous completed dataset usable if
      indexing the replacement fails or is cancelled.

### Performance

Benchmark representative captures by bytes, packets, protocols, and source-file
count. Measure:

- Indexing throughput.
- Peak resident memory.
- Temporary disk amplification.
- First-page latency.
- Sequential and random scrolling latency.
- Full-filter throughput.
- Selected-packet detail latency.

## Proposed Delivery Phases

### Phase 0: Make current limitations explicit

- [ ] Show retained packet count separately from total processed packets.
- [ ] Warn that current interactive filters cover retained packets only.
- [ ] Document that `--buffer-size` is retention, not file completeness.

This is a short-term correctness/UX measure, not the final solution.

### Phase 1: Streaming ordered input

- [ ] Introduce sequential per-file cursors.
- [ ] Implement deterministic k-way timestamp merge.
- [ ] Preserve fragmentation, decapsulation, and stateful analyzer behavior.
- [ ] Add cancellation and timestamp-regression reporting.
- [ ] Remove the full-capture `[]PacketInfo` and global sort.

### Phase 1.5: Unified open lifecycle and indexing modal

- [ ] Introduce one model-level offline-open request for startup and in-TUI
      actions.
- [ ] Add a session controller with context, cancel function, session ID, and
      completion ownership.
- [ ] Build an indexing screen with the existing unified modal renderer.
- [ ] Define throttled Bubble Tea progress messages and cancellation messages.
- [ ] Keep the previous completed dataset installed until replacement succeeds.
- [ ] Ensure all indexing stages cooperate with context cancellation.

### Phase 2: Disk-backed dataset construction

- [ ] Define versioned summary/detail record schemas.
- [ ] Implement append-only session storage and offset index.
- [ ] Accumulate and persist complete statistics.
- [ ] Add safe incomplete-dataset cleanup and disk-limit handling.

### Phase 3: Virtual packet list

- [ ] Add logical row count and cursor semantics to `PacketList`.
- [ ] Implement asynchronous page loading and byte-bounded LRU caching.
- [ ] Load selected packet details on demand.
- [ ] Update the header to distinguish dataset size from cache size.

### Phase 4: Complete interactive filtering

- [ ] Evaluate filters against persisted summaries in a cancellable worker.
- [ ] Store match IDs in a bounded/chunked result representation.
- [ ] Publish completed filter results atomically.
- [ ] Add progress and filtered statistics.

### Phase 5: Optimization and reusable indexes

- [ ] Add the small-file in-memory implementation behind `PacketDataset`.
- [ ] Profile compact bitmaps versus chunked packet-ID vectors.
- [ ] Add reusable indexes with robust source/configuration identity.
- [ ] Evaluate direct classic-PCAP offsets as a storage optimization.
- [ ] Research explicit clock offsets and optional deduplication separately.

## Architectural Decisions

The following decisions are recommended:

1. Offline file completeness is independent of `watch.buffer_size`.
2. Live/remote retention continues to use a bounded ring.
3. Offline browsing uses a `PacketDataset` abstraction with a byte-bounded
   cache.
4. Complete statistics and stateful analysis happen during sequential indexing.
5. Interactive filters scan the complete persisted summary dataset.
6. Multiple inputs use deterministic k-way timestamp merge.
7. The first disk-backed implementation stores normalized records; direct
   source offsets are an optimization behind the same interface.
8. Truncation, corruption, cancellation, and resource exhaustion are explicit
   states and never silent packet eviction.
9. Startup and in-TUI file opening use one model-owned dataset lifecycle.
10. Indexing progress and cancellation use the reusable modal system and a
    session-scoped Go context.

## Related Documents

- [Implementation plan](../plans/watch-file-scalable-offline-dataset.md)
- [Consumer and retained-history audit](watch-file-offline-consumer-audit.md)
- [Phase 0 baseline and Phase 1–2 comparisons](watch-file-offline-baseline.md)
- [Phase 6 acceptance measurements](watch-file-offline-phase6-benchmarks.md)
- `docs/research/multi-file-pcap-support.md`
- `docs/research/tui-generic-filtering.md`
- `docs/research/tui-packet-freeze-analysis.md`
- `docs/plans/multi-file-pcap.md`
- `docs/plans/tui-generic-filtering.md`
- `docs/manual/src/part2-local-capture/watch-local.md`
