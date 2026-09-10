# Compact writer construction and compression follow-up

Improve completed capture opening while preserving schema bytes, source integrity,
ordered analysis, bounded resources, and existing small-budget behavior. Keep the
preexisting working-tree changes separate. Phase 5 remains a separate feature.

- [x] Establish a fresh comparison binary and capture measurements before editing.
- [x] Record column boundaries during encoding to avoid reparsing completed rows; verify exact block/schema and budget parity.
- [x] Prototype bounded overlap of block compression with construction, preserving FIFO output, amendments, failure cleanup and finalization.
- [x] Compare candidates in interleaved fresh-process runs; discard changes without a worthwhile measured benefit.
- [x] Independently review retained changes and run affected package/race tests plus the private capture differential oracle.
- [x] Run the complete acceptance matrix, document results and remaining limitations, and format the scoped implementation and plan files.

Use temporary overlays for experiments that cannot yet meet ownership or resource
requirements. Retain existing compression and integrity checks in production.

Commit the verified implementation, plan and supporting measurements together.

Outcome: final paired completed-ready median 3.178 s versus 3.712 s (14.4% faster);
complete acceptance median 3.171 s. The index remains 89,246,448 bytes. Full private
record/query/export parity, affected race suites, isolated integration and build
checks passed. Preexisting tracked edits retain their original patch hash.
See the [measured results](../research/watch-file-compact-writer-results.md).
