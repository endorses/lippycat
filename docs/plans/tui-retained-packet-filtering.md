# Concurrent retained packet filtering

Live and remote display filter changes must filter a snapshot of retained packets
in the background while newly arriving packets continue through the active filter.
Snapshot results must merge in arrival order without duplicates, stale results,
or restoration of evicted historical packets. Offline dataset queries retain
their existing path.

- [x] Add cancellable packet-store snapshots and guarded result merging.
- [x] Route filter additions, removals, and buffer resizing through background scans.
- [x] Verify concurrent ingestion, ordering, eviction, supersession, and lifecycle resets with deterministic regression tests.
- [x] Run focused TUI tests and race checks, and format changes.

The UI loop copies the bounded snapshot and publishes completed results; predicate
evaluation runs in a Bubble Tea command without holding the packet-store lock.
Performance observations are exploratory, with no new acceptance thresholds.

Validation passed:

```sh
go test -tags all ./internal/pkg/tui/...
go test -race -tags all ./internal/pkg/tui ./internal/pkg/tui/store -run 'TestPacketFilter' -count=1
```

Commit the implementation and this completed plan together.
