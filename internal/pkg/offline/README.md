# Offline dataset storage

This package supplies normalized temporary storage and complete packet queries.
It is independent of Bubble Tea and packet analyzers. The TUI session adapter and
command integration are separate phases of the
[offline dataset plan](../../../docs/plans/watch-file-scalable-offline-dataset.md).

Create one `Storage` with validated `ResourceLimits` and share it between the
current dataset and replacement builders. This keeps their disk and display
memory use under one budget. `NewBuilder` creates a private child directory;
only that owned child is eligible for cleanup.

Append finalized logical `Detail` records in order. The builder assigns
zero-based packet IDs and ignores caller tokens/IDs.
The caller supplies exact source identity, effective link type, raw bytes, and
captured/original lengths after reassembly or decapsulation. Complete analyzer
EOF processing and freeze deferred metadata before appending affected records.
Storage does not run analysis or update packet metadata on reads.

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
record, and 64 sources. They are explicit construction parameters here; flags
will be exposed when the session workflow consumes them. The precise framing,
metadata projection, and ownership contract is documented in
[offline contracts](../../../docs/design/watch-file-offline-contracts.md).
