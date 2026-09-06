# Compact offline index: phase 2 verification

Phase 2 introduces a prepared locator stream for internal migration consumers.
The production completed dataset and legacy raw-spool sorter remain the oracle
until the later compact-storage and production-cutover gates. This phase makes
no claim that completed storage already meets the 100 MB target or full readiness
meets the three-second target.

## Review baseline

Work started at commit `32ab1577348a1c3ea3bb483c6922289ae799e85d`.
The preexisting tracked working-tree patch SHA-256 was
`d4910bae26f0269b80ae0809a4f91dea71592c1de69415db452bced152801d1d`.
Existing event-analysis, storage-codec and reassembly changes, and untracked
research and benchmark files, are outside this phase's commit.

## Implementation and ownership

`PrepareOfflineLocatorStream` finishes normalization and original-byte hashes
before returning a replayable stream. The internal TUI candidate constructs its
deterministic event producer and runtime only after preparation. Caller-supplied
input identity still overrides the derived aggregate. Original compressed bytes
are hashed during gzip decompression; snapshot mode retains its mandatory copy
and independent validation. Repeated arguments remain separate inputs.

The normalized stream determines ordering: one ordered input iterates directly,
individually ordered inputs use a bounded heap, and any regression selects
external sorting. All paths compare signed timestamp seconds, nanoseconds,
argument index and logical sequence. Stateful analysis and packet-ID assignment
occur during globally ordered replay, including when the last input frame
regresses.

Ordering scratch stores versioned, checksummed fixed-size locator records with
source context. Ordinary payloads stay in owned source handles. Transformed
bytes, decompressed input and requested snapshots remain charged exceptional
backings. Keys are written directly to budgeted scratch, so there are no
uncharged buffered writes. External passes charge input and output coexistence
and remove obsolete runs before replay.

The temporary ordering format has a 16-byte `LCLORDER` header (version 1,
192-byte record width, reserved zeros). Each record encodes the comparator,
backing locator and SHA-256, effective and original capture metadata, physical
ordinal, decoding context, and CRC32 explicitly in little endian. This private
intermediate format is separate from both the legacy 64-byte raw-spool keys and
the later schema-v2 dataset blocks. Replay rejects incompatible headers,
checksums, invalid contexts, source mismatches and backward key order.

Replay reads at most 64 locators and normally at most 1 MiB of payload per batch;
a single larger packet must fit the configured record and allocation limits.
Nearby ascending payloads on one backing share reads, with gaps charged to the
same byte cap. Source checks and per-packet digests precede exposure. Packet
copies passed through the existing analysis envelope own their bytes independently
of the read lease. Analyzer retention remains under the existing independent
analysis limits, rather than becoming an unbounded ordering cache.

## Verification record

Three implementation agents covered ordering, identity/backings and TUI
integration. Parent review inspected their changes, requested corrections and
added independent ownership, mutation, storage-budget and PCAPNG regressions.
Review corrections included replay progress reporting, exact prefetch gap
accounting, retained-buffer reservations, arithmetic/context validation and
cleanup ownership on failed preparation.

| Coverage                                                                                                                                   | Result                                                      |
| ------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------- |
| Direct, heap and external ordering against legacy; 10,013-row late regression, multiple merge passes, duplicates and interleaving          | Passed                                                      |
| IPv4/IPv6 fragments, VXLAN, ESP and nested derived transforms through every ordering path                                                  | Passed                                                      |
| PCAPNG byte orders, supported packet blocks, binary resolution, negative time offset and missing timestamps                                | Passed                                                      |
| Scan-derived and caller-supplied identities; source/snapshot/gzip; empty and BPF-empty inputs                                              | Passed                                                      |
| Full TUI oracle: packet identity, details, field accessors, filters, statistics, exports, TCP/SIP calls and deterministic event identities | Passed                                                      |
| Retained bytes across replay batches and stream close, renamed/replaced paths, source mutation with restored modification time             | Passed                                                      |
| Disk exhaustion, scan/sort cancellation, consumer error/early stop, corrupt key/header, truncated scan before analysis                     | Passed                                                      |
| Private capture differential oracle                                                                                                        | Passed; test duration 112.721 s, not a full-ready benchmark |
| Required package and race gates, watch command check, complete and specialized builds                                                      | Passed                                                      |

The parent reran the package and race gates after the final implementation
changes. The additional parent PCAPNG tests also passed under the race detector.
The private fixture was `capture_20251020_082236.pcap`, using the existing frozen
open configuration and full differential oracle. No private packet data or test
artifacts are included in the commit. Full performance acceptance remains a
later milestone.

Commands run with `GOCACHE=/tmp/lippycat-go-cache`:

```sh
go test -tags all ./internal/pkg/offline ./internal/pkg/capture \
  ./internal/pkg/pipeline/... ./internal/pkg/events/... \
  ./internal/pkg/eventanalysis ./internal/pkg/tui/...
go test -race -tags all ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/tui
go test -race -tags all ./internal/pkg/capture -run '^TestOfflineLocatorReview' -count=1
LIPPYCAT_BENCH_PCAP=/path/to/capture_20251020_082236.pcap \
  go test -tags all ./internal/pkg/tui \
  -run '^TestOfflineLocatorIndexerPrivateOracle$' -count=1 -timeout=30m
go test -tags all ./cmd/watch
make build
for variant in hunter processor tap cli tui; do
  go build -tags "$variant" -o "/tmp/lippycat-phase2-$variant" .
done
```

The complete build was also run with sandbox escalation for Go's module metadata
cache. Specialized builds exited successfully with nonfatal read-only metadata
cache warnings. All preexisting tracked changes were verified byte-for-byte
against the starting working tree and excluded from staging.
