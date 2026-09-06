# Three-second usable capture opening

Target: open the reported 323,454,505-byte capture and provide complete usable
packet browsing, filtering and navigation in approximately three seconds.
Storage savings alone do not satisfy this target. Preserve normalized identity,
protocol semantics, source integrity, bounded resources and cancellation.

- [x] Establish current fresh-process completed-ready measurements and profile on the private capture.
- [x] Remove measured construction and analysis overhead without weakening correctness or resource limits.
- [x] Independently review changes and run synthetic and private-capture differential verification.
- [x] Measure at least three fresh unprofiled runs and usable-page/query endpoints; report any remaining gap honestly.
- [x] Update verification documentation, format changed files and commit only scoped changes.

Use the existing compact completed benchmark and acceptance runner. Preserve the
preexisting working-tree changes. Do not relabel base-only or partial results as
completed analysis. The existing compact-index plan's phase 5 remains separate
unless a revision-safe early-publication implementation is required and verified.

Verified outcome: three warm fresh-process completed-ready samples of 3.603,
3.622 and 3.723 seconds; median 3.622 seconds. The three-second target remains
unmet. Full private-capture differential verification, the affected package race
suite and the complete build passed. See [measurements and remaining gap](../research/watch-file-three-second-open.md).
