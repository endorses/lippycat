# Compact offline index: phase 3 verification

Phase 3 implements completed compact datasets through the internal
`indexOfflineCompactDataset` candidate. Production `watch file` continues using
the legacy backend. Publication still waits for analyzer EOF, amendments,
backing finalization and the atomic completion manifest.

## Baseline and review

Work started at `db5b37236297c3d08bccc2b02ce2d0d1878bb078`. The preexisting
tracked working-tree patch SHA-256 was
`d4910bae26f0269b80ae0809a4f91dea71592c1de69415db452bced152801d1d`.
Existing event-analysis, storage-codec and reassembly optimizations, and untracked
research and benchmark files, remain outside this phase's commit. The scoped
implementation was also compiled and its synthetic compact corpus tested in a
temporary checkout without those changes. Review removed a dependency on the
legacy codec's uncommitted pointer wrappers by giving compact records their own
identical bounded memory traversal; focused race tests passed afterward.

Three implementation agents covered storage, TUI materialization and raw export.
The parent reviewed their code, coordinated ownership and schema changes, and
added independent manifest, corruption, source-mutation, resource-admission,
registry-bound and cleanup tests. Review corrections included source-handle
transfer, buffered disk admission, overlapping decode reservations, sparse empty
metadata elision, source/backing validation, read-only backing sealing, directory
authentication and immutable block-cache reuse.

## Follow-up assessment (2026-09-06)

Three independent reviewers compared the phase-3 plan with storage validation,
resource accounting, backing/query/export ownership and TUI materialization.
The parent reproduced the findings and a separate reviewer checked the fixes.
Two categories of defect were confirmed:

- Invalid capture contexts could be accepted and published although later reads
  rejected them. Generic amendments also accepted invalid lengths or source
  references. Initial append and generic amendment now share validation, and
  failure poisons the builder before a completed manifest can be published.
- Summary projection objects and generic amendment callback growth could allocate
  before budget admission. Projection objects now reserve their fixed footprint
  before construction; callback growth stays charged through serialization.
  The narrow VoIP amendment also admits its scratch before creating a projection.

The new invalid-input and callback-accounting regressions fail against the
original implementation using a Go source overlay and pass with the fixes.
Projection tests cover every metadata-presence combination, exhausted budgets,
cancellation and balanced release. The complete relevant package suite, race
checks for offline/capture/TUI and `make build` passed. The exhaustive private
capture comparison passed both before the fixes (215.606 seconds) and afterward
(204.313 seconds), covering all 579,990 logical records and the same oracle
operations described below. These are test durations, not readiness benchmarks.
No additional substantiated TUI, lifecycle, format or export defect was found.
The performance gaps below
remain phase-4 cutover work; this assessment does not change readiness or enable
the compact backend in production.

## Additional amendment-budget assessment (2026-09-06)

Three independent reviewers checked storage, resource ownership and TUI parity;
the parent verified their findings. One additional defect was reproduced: with
a 65,536-byte record limit, a 30,000-byte Info field and a late 40,000-byte VoIP
body each passed separate row/metadata validation. Completion succeeded, but
reading the combined detail failed its allocation limit.

Completion now materializes the range of narrowly amended packet IDs before
publishing the manifest. This includes raw bytes and other decoded protocol
metadata in validation. Range tracking uses constant memory; widely separated
amendments may also validate intervening records. Amendment writes still avoid
source reads, and failed finalization poisons the builder.

The new regression fails against the prior implementation through a Go source
overlay and passes with the fix. It covers valid and oversized combined details,
reverse-order amendments, absent manifests after failure, poisoned retries and
balanced resource cleanup. An independent reviewer reproduced the defect and
verified the fix. No other substantiated phase-3 defect was found.

Fresh complete package and offline/capture/TUI race suites passed, as did the
watch command check and `make build`. The private-capture oracle was not rerun
in this assessment; it requires `LIPPYCAT_BENCH_PCAP`. Performance was not
remeasured, so the earlier timing results do not quantify the new validation cost.

## Implemented contract

The [storage specification](../design/offline-storage-format.md) documents the
actual v2 format. The unshipped phase-0 layout was refined to combine completed
base and analysis columns in typed blocks, keep text/compound values in bounded
block-local arenas, and use a 64-byte authenticated direct row directory. Bounded
source/label/context registries live in the completion manifest. This avoids a
dataset-sized arena directory and supports compact row replacement within the
existing completed-dataset lifecycle. It does not implement the earlier proposed
split-stream layout or imply readiness for persistent reuse.

Rows retain source argument and logical sequence, physical ordinal, original
parser context, original/effective capture metadata, locator and effective-byte
digest. Address/port rendering, Protocol, Info and the exact searchable projection
remain persisted. Summaries require no I/O after materialization. There are no
persisted full `PacketDisplay` records or ordinary effective-payload copies.

The injected TUI decoder reconstructs packet-local DNS, HTTP and TLS details
without a live detector, tracker or settings lookup. Sparse whole-protocol
overrides retain metadata that differs from stateless decoding, including VoIP
and email results. SIP/EOF amendments write sparse metadata and a replacement
compact row; superseded bytes stay charged. They do not rewrite raw bytes or full
presentation records. Statistics are rebuilt after amendments.

TLS plaintext remains in the stopped session decryptor under its existing 16 MiB
session plaintext cap, separately from storage cache accounting; no second
plaintext copy is added to index files. Tests decrypt actual TLS 1.3 traffic,
remove the key file and verify that both backends retain the same plaintext.

Raw iteration follows query order and bypasses the detail decoder. Query pins
are acquired before asynchronous export scheduling, and keep the old dataset
alive across query/session replacement. Cache, row/detail scratch, page leases,
pins and registries share the configured storage memory budget. Owned source,
snapshot, decompressed and derived backings remain valid until their owner closes.
Source reads validate the initially opened handle and packet digest on every
read; cached index blocks do not bypass source-change detection.

Completion flushes rows, validates sources, seals owned backings with
sync/close/read-only reopen and identity checks, rebuilds amended statistics,
syncs/closes/reopens index streams, and publishes a synced atomic manifest.
The manifest includes index-file hashes and full hashes of owned backings.
Construction failures poison the builder, and failed cleanup remains retryable.

## Verification results

| Coverage | Result |
| --- | --- |
| Synthetic differential order, summaries/accessors, filters, statistics, details and exports | Passed |
| Direct/merge/external ordering, duplicate inputs and 1,614-row multi-block oracle | Passed |
| SIP segmentation, retransmission, idle expiry and EOF amendments | Passed |
| DNS, nonstandard-port HTTP, TLS, SMTP/email and RTP metadata | Passed |
| IPv4/IPv6 fragmentation, VXLAN, nested fragment/tunnel normalization, PCAPNG and BPF before transforms | Passed |
| Snapshot/gzip, empty/BPF-empty inputs, cancellation and truncated input cleanup | Passed |
| Random/repeated details after live-setting changes and caller mutation | Passed |
| Pinned raw/PCAP export during replacement and concurrent dataset close; decoder bypass | Passed, including race checks |
| Source mutation after a cached detail; previous owned bytes remain valid | Passed |
| Invalid versions/headers, checksums, directory references and overflow/short reads | Passed |
| Recomputed-checksum malformed column/arena descriptors, duplicate maps, nil/empty values and codec shape | Passed |
| Disk admission/exhaustion, `/dev/full`, flush/sync/reopen/manifest publication failures and cleanup retry | Passed |
| Owned backing sealing, read-only writes, active leases and poisoned cleanup | Passed |
| Required package and race suites, watch command check and complete build | Passed |

The final private-capture differential oracle passed in 213.09 seconds. This is
the duration of two builds plus exhaustive comparisons, not a readiness
measurement. It compared all 579,990 logical records, all configured filter
cases and export records, 10,000 retained events, 44,873 arrived events and one
retained call. The oracle preserves deterministic event identities and compares
intentionally random flow/file identifiers through the existing bijection.

Two earlier private-oracle attempts were interrupted while reviewing older cache
implementations; they are not counted as passing runs. The final passing run
used the completed immutable-block cache path.

## Completed readiness and storage measurements

Host: Linux amd64, Intel Core i9-13900HX, 32 logical CPUs;
`go1.26.3-X:nodwarf5`, `all` tags. Input: 323,454,505-byte
`capture_20251020_082236.pcap`, SHA-256
`53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`.
The private capture and profiling artifacts remain local.

The measured binary SHA-256 was
`988813fbec516cf76f0d98360aadc375437f998c9405927f3f1f1b46536c6972`.
`BenchmarkOfflineCompactCompleted` used `FreezeOfflineOpen` with 10,000 retained
events, default settings and source backing; limits were 64 MiB cache, 8 MiB
record, 4 GiB disk and 64 sources. Each backend ran in three fresh processes,
alternating legacy/compact, with an untimed full input read to warm filesystem
cache. Compilation, warming, inspection and cleanup are excluded from the ready
metric. The host was shared; there was no CPU affinity or controlled cold-cache
claim. Profiles were separate from the three timed samples.

| Backend | Ready seconds, runs 1 / 2 / 3 | Median | Completed bytes | Median cumulative allocation |
| --- | --- | --- | --- | --- |
| Legacy | 8.905 / 8.765 / 8.950 | 8.905 s | 683,436,932 | 5,571,180,728 B |
| Compact | 21.537 / 21.626 / 20.344 | 21.537 s | 301,790,134 | 9,241,122,664 B |

An earlier pre-isolation series recorded legacy 9.188 / 9.984 / 9.091 seconds
and compact 22.496 / 21.729 / 21.731 seconds. These were remeasured after the
accounting-wrapper isolation change and are excluded from the final medians.
Additional development/breakdown observations of 22.023 and 20.357 seconds are
also excluded. All samples consistently miss the production readiness target.

Every timed run produced 579,990 packets and 44,873 arrived events. The benchmark
walked all owned files and asserted that their exact total equalled the disk
ledger. Each final run also recorded the same component sizes:

| Completed artifact | Bytes |
| --- | --- |
| Combined typed row columns and arenas | 264,219,498 |
| Direct authenticated row directory | 37,119,392 |
| Sparse metadata | 440,149 |
| Completion manifest | 9,581 |
| Exceptional derived backing | 1,514 |
| **Total** | **301,790,134** |

Completed storage is about 55.8% smaller, but misses the 100 MB engineering
target. Full readiness is about 2.42 times the comparison legacy median, missing
both the 10% regression tolerance and three-second target. Cumulative allocations
also exceed the predeclared tolerance. Accounted retained storage memory at
completion was 15,844 bytes (registries/backing bookkeeping); this is **not**
process RSS or total retained analyzer/event/TLS memory. This runner does not
measure peak RSS, exact temporary peak disk, first render or query/detail latency
percentiles; those remain phase-4 acceptance-matrix work. No acceptance claim is
made for these unmeasured endpoints.

The separate CPU profile attributed 14.62 cumulative CPU seconds to
`AppendCompact`, 8.44 to `reflect.Value.FieldByName`, 7.17 to
`writeCompactBlock`, and 6.72 to `compactSplitRow`. These nested totals overlap
and must not be added. The allocation profile attributed roughly 1,233 MiB of
flat allocations to `compactSplitRow`; repeated row encoding, decoding and
column transposition are the measured next storage bottleneck. Combined row
columns and their reference/arena representation dominate completed disk size.

Disposition: phase 3's semantic, ownership and bounded-resource gates are met;
the completed candidate remains internal. Production cutover is **not accepted**.
Phase 4 must address the measured serialization and representation costs and run
its full performance/query gates before selecting this backend for users.

## Reproduction

From the repository root, with the private path supplied locally:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/pipeline/... \
  ./internal/pkg/events/... ./internal/pkg/eventanalysis ./internal/pkg/tui/...
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all \
  ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/tui
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./cmd/watch
make build

GOCACHE=/tmp/lippycat-go-cache go test -c -tags all ./internal/pkg/tui \
  -o /tmp/lippycat-phase3.test
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-phase3.test -test.run '^TestOfflineCompactIndexerPrivateOracle$' \
  -test.count=1 -test.timeout=30m

# Run each backend three times in separate processes, without profiling.
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-phase3.test -test.run '^$' \
  -test.bench '^BenchmarkOfflineCompactCompleted/compact$' \
  -test.benchtime=1x -test.benchmem -test.timeout=10m
# Substitute /legacy$ for the comparison runs.

# Profile separately; exclude this run from timing samples.
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-phase3.test -test.run '^$' \
  -test.bench '^BenchmarkOfflineCompactCompleted/compact$' -test.benchtime=1x \
  -test.cpuprofile=/tmp/lippycat-phase3.cpu \
  -test.memprofile=/tmp/lippycat-phase3.mem
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -cum \
  /tmp/lippycat-phase3.test /tmp/lippycat-phase3.cpu
```
