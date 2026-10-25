# Offline dataset storage

This package supplies normalized temporary storage and complete packet queries.
It is independent of Bubble Tea and packet analyzers. The TUI session adapter implements indexing and atomic replacement as part of the
[offline dataset plan](../../../docs/plans/watch-file-scalable-offline-dataset.md).

Create one `Storage` with validated `ResourceLimits` and share it between the
current dataset and replacement builders. This keeps their disk and display
memory use under one budget. `NewBuilder` creates a private child directory;
only that owned child is eligible for cleanup.
A constructor error may return a nonnil cleanup-only `Builder` when removal
fails. Retain that owner before checking the error and retry `Close`; it cannot
append or publish. Successful failure-path cleanup returns a nil builder.

Append finalized logical `Detail` records in order. The builder assigns
zero-based packet IDs and ignores caller tokens/IDs.
The caller supplies exact source identity, effective link type, raw bytes, and
captured/original lengths after reassembly or decapsulation. Complete analyzer
EOF processing before `Finish`. Use `Builder.UpdateDetail` for metadata released
after its packet was appended; the callback updates one bounded detail, preserves
its ID, and persists replacement summary/detail frames. Superseded frames remain
charged to the disk budget. Final statistics are rebuilt once from the final
summaries when amendments occurred. Storage does not run analysis or update
packet metadata on reads.

`Finish` publishes a dataset only after writing its completion manifest. On a
failed build, close the builder to clean up its temporary files. A completed
dataset owns its storage until `Close`. Close the shared storage owner when all
sessions are finished. Cleanup and publication errors must be surfaced to the
caller.

`Query` scans all summaries and writes ordered match IDs to disk. A nil predicate
matches every packet; no dataset-sized ID slice is allocated. Predicates must be
immutable, concurrency-safe snapshots supplied by the adapter. Keep the previous
query installed until its replacement completes, then close the superseded
query to reclaim its files. A failed or cancelled query cannot publish partial
matches. `Related` uses the same query mechanism across the full dataset,
independently of any display filter.

Use `Page` with both row and byte limits, `Detail` for an individual packet, and
`Iterate` for cancellable streaming export. Use `PinDetail` for the selected
detail retained by the UI, then close its pin before closing the dataset.
Prefetch uses the same bounded read path; no background prefetch is scheduled
by storage. Cached summary/detail frames are immutable encoded bytes, and each
read returns an independently decoded value. Close each returned page when its
rows leave the viewport; its lease keeps retained row memory charged to the
shared budget. A copied page shares the same idempotent lease. Tokens carry dataset, query, and
request identities; the model must also reject obsolete asynchronous responses.
Run closing operations outside the UI update loop, since they wait for active
readers. Do not call close from an iteration callback that still owns a reader.

Statistics count each accepted logical packet once. Global and query totals are
separate snapshots; paging never increments either. Address/protocol frequency
maps have explicit cardinality limits, with approximation indicated in
`TruncatedCardinality`. Display memory budgets are not hard process RSS limits:
Go runtime overhead, caller-owned results, analyzer state, and separately bounded
statistics must also be considered when selecting deployment limits.

Reads reserve up to three maximum-sized record buffers plus framing before
shrinking to the decoded result size. Leave room for that working space in
addition to pages and pins. Exhaustion returns an explicit allocation error;
workers never wait indefinitely for a pin held by the caller.

The provisional deployment limits remain 64 MiB cache, 4 GiB disk, 8 MiB maximum
record, and 64 sources. The watch command exposes `--offline-session-dir`, `--offline-max-disk-bytes`,
`--offline-cache-bytes`, `--offline-max-record-bytes`, and
`--offline-max-sources`, also configurable through `watch.offline` in Viper. The precise framing,
metadata projection, and ownership contract is documented in
[offline contracts](../../../docs/design/watch-file-offline-contracts.md).

Production progressive opens use `NewCompactBaseBuilder` for complete ordered
base revision 0, followed by `NewCompactRevisionBuilder` for independent completed
analysis revision 1. The base contains only B-ready fields; a base read never
runs the application metadata decoder. Protocol, Info and application fields
remain pending until completed analysis. No published dataset is amended.
`Dataset.Revision()` and `Token.Revision` must match exactly on requests and pins;
zero identifies the base and never aliases the current revision. Query, cache,
manifest and typed-block identities include the revision.

`CheckQueryReadiness` rejects base operations requiring application fields with
`ErrAnalysisPending` before scanning or admitting query files. Expressions proven
to use base fields and raw iteration remain available; opaque predicates are
analysis-dependent. `Query.Position` performs bounded ordered lookup of a stable
PacketID when refreshing a query after publication. The caller preserves the last
installed query if a refresh fails or is cancelled.

Revisions share an explicit lease on originally validated source handles and
owned snapshot/decompressed/derived backings. Metadata directories are independent;
retiring the base cannot invalidate a completed revision or a pinned base export.
Both metadata revisions and replacement sessions count toward shared resource
limits. The session adapter retains the base after analysis failure/cancellation,
publishes completed packets/statistics/events atomically, and cancels workers and
exports before joining query owners during whole-session cleanup. Failed cleanup
ownership remains retryable. Persistent reuse is not implemented.

`NewEventBuilder` adds complete metadata event history under the same storage
budgets. Append immutable arrivals in analysis order; `EventRowID` starts at one
and is independent of the envelope's delivery ID. Repeated IDs and amendments
remain separate snapshots. File-content events are excluded. `Finish` writes a
checksummed completion manifest; any append failure poisons the builder, so a
prefix cannot be published. Retain failed cleanup owners and retry `Abort`.

Event queries write match row IDs to disk; all-events queries use implicit IDs.
Close each borrowed `EventPage` and `EventDetail` lease after presentation releases
it. They account for decoded data and a bounded presentation record. Do not retain
deep clones without a separate reservation. `PinEventQuery` keeps a fixed query
and dataset alive for asynchronous consumers. Join readers and close pins/queries
before closing the event dataset. Packet and event datasets are separate storage
objects, published together by the offline session adapter after both finalize.
