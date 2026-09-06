# Compact offline index: phase 1 verification

Phase 1 adds owned, validated source and derived locators. It does not enable the
compact production dataset or replace the legacy sorting spool. The internal
`capture.WithOfflineBackings` context opts a cursor or ordered stream into locator
emission. Its caller owns the registry; cursor close releases a scan lease while
the registry keeps the handles available for later reads. Phase 2 will preserve
these locators through ordering, and phase 3 will attach them to compact datasets.

`--offline-backing-policy` binds to `watch.offline.backing_policy`, defaults to
`source`, accepts `snapshot`, and is frozen and validated before opening a
session. Production continues to use its existing completed dataset behavior.
The policy controls backing construction when the internal locator path is used.

## Ownership and integrity

Classic PCAP offsets count parser-consumed bytes. PCAPNG offsets come from checked
block framing, including packet padding and interface references. Both readers
preserve original format, byte order, snaplen and timestamp context independently
of effective packet metadata. Physical ordinals precede BPF filtering; logical
sequence counts emitted normalized packets. Repeated input arguments remain
distinct sources. Every successful transformation marks the result derived,
including extraction of a subslice after reassembly.

The registry owns initially opened handles and never reopens paths for reads.
Reads validate bounds and source metadata, verify SHA-256, then validate metadata
again before returning a byte-accounted lease. Source changes poison subsequent
reads and expose `ErrSourceChanged`; invalid bounds and private backing integrity
failures expose `ErrInvalidLocator`. Rename, unlink and replacement retain the
old opened object on platforms that support it. Source identity checking detects
changes to accessed bytes even when modification time is restored; it does not
claim protection from concurrent hostile changes with restored metadata.

Snapshot copies are independently hashed and synced before parsing. Gzip keeps
the compressed identity, validates decompression through its checksum, and uses
one seekable decompressed spool. Copy/spool coexistence is charged to the shared
disk budget. Failed cleanup remains owned for retry. Registry and storage close
wait for scan/read leases before closing backings. Gzip PCAPNG and additional
PCAPNG sections/interfaces remain unsupported.

## Verification

The implementation was reviewed across the parser, backing and cursor agents,
then independently reviewed and tested by the parent agent. Review fixes included
scan leases, preserving gzip PCAPNG rejection after decompression, original parser
context, addressability checks and cleanup ownership.

| Coverage                                                                                              | Result                                                            |
| ----------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| Classic byte orders, micro/nanosecond precision, buffered offsets, empty records and truncation       | Passed                                                            |
| PCAPNG packet block types, timestamp context/absence, interfaces, padding and bounds                  | Passed                                                            |
| 18 format/normalization combinations, including IPv4/IPv6 fragments, VXLAN, ESP and nested transforms | Passed; exact legacy bytes and metadata reread after cursor close |
| Duplicate arguments, BPF physical/logical sequence, empty filtered stream and adapter round trip      | Passed                                                            |
| Rename/replacement/unlink, truncation, same-size mutation and restored modification time              | Passed                                                            |
| Snapshot/gzip identity, checksum failure, budgets, cancellation, cleanup retry and pinned shutdown    | Passed                                                            |
| Required package and race gates                                                                       | Passed                                                            |
| Complete build and hunter, processor, tap, cli and tui builds                                         | Passed                                                            |

Commands run with `GOCACHE=/tmp/lippycat-go-cache`:

```sh
go test -tags all ./internal/pkg/offline ./internal/pkg/capture \
  ./internal/pkg/pipeline/... ./internal/pkg/events/... \
  ./internal/pkg/eventanalysis ./internal/pkg/tui/...
go test -race -tags all ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/tui
go test -tags all ./cmd/watch
make build
for variant in hunter processor tap cli tui; do
  go build -tags "$variant" -o "/tmp/lippycat-phase1-$variant" .
done
```

Verification used base commit `43e42d03772205e940e845f5f7595d1a4172777e` with the
preexisting tracked working-tree patch SHA-256
`6a8f24a22adf641ac607268f8c79475a40d6005acbfcd992ea9f213c5fa95e23`.
Those baseline changes and preexisting untracked research/tests were preserved
and excluded from the phase 1 commit. No new performance claim or private-capture
acceptance measurement is made at this phase.
