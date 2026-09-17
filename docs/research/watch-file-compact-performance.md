# Watch-file compact-index performance record

This is the canonical measurement ledger for the compact source-backed offline
index. It consolidates the production baseline, compact-storage optimization,
completed-open work, rejected experiments, writer overlap, and VoIP-heavy
follow-ups. Phase references are to the
[compact source-backed index plan](../plans/watch-file-compact-source-index.md).
Private captures and profile artifacts are not committed.

## Legacy production baseline

The first real-capture investigation ran on 2026-09-05 using Linux amd64, an
Intel Core i9-13900HX with 32 logical CPUs, Go 1.26.3, and `all` build tags. The
323,454,505-byte private mixed-traffic capture contained 579,990 packets and
produced 44,873 events. Measurements covered input identity, normalization,
sorting, protocol analysis, dataset writing, EOF drain, and cleanup; compilation,
terminal rendering, and interactive search were excluded.

| Implementation                                      | Median ready | Allocated bytes | Allocations    |
| --------------------------------------------------- | -----------: | --------------: | -------------: |
| Range-traversal baseline                            |     11.46 s  |         7.59 GB | 48.81 million  |
| Borrowed fields, decoded reuse, lazy SMTP, TCP reuse |     10.26 s  |         5.57 GB | 42.00 million  |

The changes reduced median latency by about 10% and allocation volume by 27%.
The legacy completed index was 683,436,932 bytes. Profiles identified redundant
capture-metadata traversal, repeated storage validation, interface conversions,
duplicate packet decoding, eager SMTP parser construction, and discarded TCP
buffer capacity. After those fixes, storage serialization, allocations, and
ordered analysis remained shared critical-path costs; no evidence supported a
claim that one remaining change would reach three seconds.

Historical reproduction used the production offline-index benchmark:

```sh
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui \
  -run '^$' -bench '^BenchmarkOfflineFileIndex$' -benchtime=1x -benchmem \
  -cpuprofile=/tmp/lippycat-open.cpu -memprofile=/tmp/lippycat-open.mem \
  -o /tmp/lippycat-open.test -timeout 3m
```

Regression coverage verified record-schema bytes, exact budget boundaries,
protocol-event parity, nonstandard HTTP ports, and fragmented/repeated TLS data.
Offline storage, analysis, reassembly, capture, pipeline, TUI, processor and
sniff-command checks passed, including the relevant race suites and full build.

## Phase 3 compact-storage optimization

Measured 2026-09-06 on the internal completed compact candidate. Production
selection and the rest of compact-plan Phase 4 were unchanged at this point.

### Changes

Schema field indexes and column shapes are resolved once. The hot row encoder
writes the frozen typed schema directly, including the metadata-reference prefix,
avoiding reflection, row boxing and a second encoded-row copy. Tests compare its
bytes and memory-limit behavior with the generic codec for all projection masks.
Empty override records are no longer encoded just to be discarded.

Block assembly validates and slices existing row bytes instead of decoding and
re-encoding every field. It retains uint32 field ends rather than a tree of slice
headers. Payload and compressor output buffers are reused under retained capacity
admission. High-cardinality values remain in bounded block-local arenas.

Schema 2.1 adds independently compressed DEFLATE blocks using the standard Go
BestSpeed encoder. The row codec and directory structure are unchanged. The
directory authenticates physical lengths and the block header; the header gives
the bounded expanded length and SHA-256 of the expanded typed payload. Expanded
cache entries also retain the original physical length. Unknown versions/flags,
truncation, excess expansion, trailing compressed bytes and checksum errors are
rejected. See [the storage format](../design/offline-storage-format.md).

The compressor has a 2 MiB retained reservation and the inflater a conservative
256 KiB scratch reservation. Reused buffers are admitted before growth and
released at completion or failed-build cleanup. Small blocks, incompressible
blocks and configurations with less than 16 MiB cache retain raw encoding.

### Measurement identity and method

Baseline commit: `052aa35bc4754400762fdee04bb078845da13e29`. The preexisting
tracked working-tree patch SHA-256 was
`08493f5079ae66f028c4da0a07a7896cdfa7246dd82e2a272869fe73fe247f59`.
Those event-analysis, legacy-codec and reassembly edits remain outside this work.
The existing untracked research and benchmark files were preserved.

Host: Linux amd64, Intel Core i9-13900HX, 32 logical CPUs,
`go1.26.3-X:nodwarf5`, build tags `all`. Private capture: 323,454,505 bytes,
SHA-256 `53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`.
The capture and raw artifacts stay local.

Binary SHA-256 values:

- Before: `69ba9ad1f99d046caae15c9fd0836753fa00d930a31c02e773f489bb8f7bbc95`.
- Measured optimized candidate: `d3d63b4bd9c5676eb1791dddf090b7b628c91031cedf73cba5785e506798a81e`.

`BenchmarkOfflineCompactCompleted` used three fresh processes per condition,
an untimed source read to warm filesystem caches, frozen default settings,
10,000 retained events, source backing, 64 MiB cache, 8 MiB record budget,
4 GiB disk budget and 64 sources. Compilation, warming, inspection and cleanup
are excluded from readiness and allocation metrics. Runs were grouped by
condition, on a shared host without CPU affinity; no controlled cold-cache claim
is made. Development and profiled runs are excluded from these medians.

### Results

| Backend           | Ready seconds, runs 1 / 2 / 3 | Median   | Completed bytes | Median allocated bytes |
| ----------------- | ----------------------------- | -------- | --------------- | ---------------------- |
| Previous compact  | 21.497 / 21.937 / 22.319      | 21.937 s | 301,790,134     | 9,244,082,304          |
| Legacy            | 9.681 / 9.955 / 9.803         | 9.803 s  | 683,436,932     | 5,572,983,992          |
| Optimized compact | 10.559 / 11.977 / 10.084      | 10.559 s | 89,456,432      | 6,096,776,520          |

Compared with the previous compact candidate, median readiness improves 51.9%,
completed storage shrinks 70.4%, and cumulative allocated bytes fall 34.0%.
The 100 MB decimal storage target is met. Readiness is 7.7% above the current
legacy median and allocations 9.4% above it, within the predeclared 10% regression
tolerances in this sample. The variable second run and narrow allocation margin
argue for repeating the complete acceptance matrix before production cutover.

Every run produced 579,990 logical packets and 44,873 arrived events. Each run
walked the complete owned directory and asserted exact equality with the disk
ledger. The optimized completed artifacts were:

| Artifact                    | Bytes      |
| --------------------------- | ---------- |
| Typed row blocks            | 51,885,797 |
| Authenticated row directory | 37,119,392 |
| Sparse metadata             | 440,149    |
| Manifest                    | 9,580      |
| Exceptional backing         | 1,514      |
| Total                       | 89,456,432 |

Accounted retained storage memory at completion remained 15,844 bytes. This is
not peak RSS, peak temporary disk or retained analyzer memory. Those endpoints,
query/detail latency distributions and first render remain unmeasured here.

The three-second engineering target remains unmet. The intermediate separate
profile, after removing reflection-name lookup and decode/re-encode but before
the final typed encoder and buffer reuse, reduced `AppendCompact` cumulative CPU
from the earlier 14.62 s to 5.20 s. It showed row encoding, compression and event
analysis as remaining costs. Those overlapping CPU totals are not wall time and
must not be summed. The separate final profile attributed 3.61 cumulative CPU
seconds to `AppendCompact`, 1.80 to `flushCompact`, 2.03 to event-analysis
`ObservePacket`, and 2.88 to GC scanning (`gcDrain`). Storage serialization,
compression and ordered protocol analysis still account for substantial work;
further readiness gains require profiling these paths alongside the remaining
Phase 4 query work. The profiled run reported 9.629 s readiness and the same
89,456,432 completed bytes; it is excluded from the timing medians.

### Verification and disposition

Independent agents implemented the codec and splitter, reviewed buffer and
compression ownership, and added corruption/resource tests. Parent verification
caught and corrected physical-size/header handling in the expanded block cache.
Focused tests compare typed row bytes against the generic codec and cover all
projection masks, absent strings, truncated rows, malformed booleans/timestamps,
compressed random detail/raw reads and failed admission.

The full relevant package suite, offline/capture/TUI race suite and `make build`
passed. The exhaustive private-capture oracle failed after 163.84 s at its final
call-summary comparison; preceding packet/detail/filter/statistics/event/export
comparisons passed. A temporary diagnostic reproduced the difference between two
legacy builds: identical `SDPEndpoints` appeared in different slice orders.
`callregistry.Core.EndpointsForCall` iterates a map, while the oracle compares
those slices positionally. This is an unrelated baseline/oracle nondeterminism.
Implementation initially stopped per repository instructions. After explicit
user authorization, the registry was changed to return an owned, lexically
sorted endpoint snapshot. The regression test failed before the fix and passed
afterward, covering insertion/iteration order and caller mutation. The strict
oracle comparison was preserved.

The exhaustive oracle then passed in 154.63 s, comparing all 579,990 packets,
10,000 retained events, 44,873 arrived events and one retained call. That is test
duration, not readiness. Call-registry/VoIP/TUI race checks and the complete build
also passed after the fix. The verified binary SHA-256 is
`41c982aa230b8665bba584c5f172e72c10b0504a0d4195af74c1289c4dab1124`.
The timing matrix above predates this endpoint-order fix; it is not a remeasurement
of the final binary.
This performance work does not mark the remaining Phase 4 tasks complete or
enable the compact candidate for production.

### Phase 3 reproduction

From the repository root, set `LIPPYCAT_BENCH_PCAP` to the private capture.
Compile once, then run each backend three times in separate fresh processes with
an untimed full input read to warm filesystem caches. Run profiling separately
and exclude it from the timing medians. Local raw outputs for this historical
assessment were in `/tmp/lippycat-compact-performance/`. Reproducing the recorded
numbers requires the code and measurement identities above; current code may
produce different results.

```sh
GOCACHE=/tmp/lippycat-go-cache go test -c -tags all ./internal/pkg/tui \
  -o /tmp/lippycat-compact.test
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-compact.test -test.run '^TestOfflineCompactIndexerPrivateOracle$' \
  -test.count=1 -test.timeout=30m

# Run each backend three times in separate processes, without profiling.
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-compact.test -test.run '^$' \
  -test.bench '^BenchmarkOfflineCompactCompleted/compact$' \
  -test.benchtime=1x -test.benchmem -test.timeout=10m
# Substitute /legacy$ for the comparison runs.

# Profile separately; exclude this run from timing samples.
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  /tmp/lippycat-compact.test -test.run '^$' \
  -test.bench '^BenchmarkOfflineCompactCompleted/compact$' -test.benchtime=1x \
  -test.cpuprofile=/tmp/lippycat-compact.cpu \
  -test.memprofile=/tmp/lippycat-compact.mem
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -cum \
  /tmp/lippycat-compact.test /tmp/lippycat-compact.cpu
```

The subsequent production-cutover matrix used the complete acceptance runner,
including query/detail/export and resource measurements:

```sh
python3 scripts/benchmark-offline-acceptance.py /path/to/capture.pcap \
  /tmp/compact-acceptance-legacy --backend legacy
python3 scripts/benchmark-offline-acceptance.py /path/to/capture.pcap \
  /tmp/compact-acceptance-compact --backend compact
```

## Completed-open optimization

After the Phase 4 production cutover, the same 323,454,505-byte capture reached
completed analysis in a 3.622-second median, compared with the 10.121-second
Phase 4 acceptance baseline. Publication remained completed-only; this did not
implement Phase 5's progressive base publication.

| Endpoint                      | Phase 4 baseline | Optimized |
| ----------------------------- | ---------------: | --------: |
| Completed analysis            |         10.121 s |   3.622 s |
| First useful rendered page    |         10.122 s |   3.624 s |
| First source filter           |          1.050 s |   0.966 s |
| First HTTP-metadata filter    |          1.006 s |   0.917 s |
| Related-flow lookup           |          1.035 s |   0.978 s |
| Effective export throughput   |        163.4 MB/s | 172.6 MB/s |
| Acceptance allocations        |          8.312 GB |  3.823 GB |
| Whole-process peak RSS        |         131.3 MiB | 126.3 MiB |

Completed-ready samples were 3.603, 3.622, and 3.723 seconds. The completed
index occupied 89,246,448 bytes. The exact ledger peak was 200,777,808 disk
bytes and at most 54,232,679 memory bytes; retained heap after the full
acceptance workload was about 14.14 MB. All query/detail/page, export,
allocation, RSS, filter-count, and exported-byte gates passed.

The implementation batched compact-directory writes; reused bounded
transposition, row, replay, and packet-layer storage; used a compatible reusable
DEFLATE writer; separated serial ordered analysis from compact writing with
bounded workers; removed discarded packet-local HTTP/TLS metadata; and replaced
per-event flushes with bounded lossless admission. Stateful analyzers still saw
one deterministic stream, and workers drained before EOF publication.

Independent review found and corrected a TCP DNS mismatch and two small-budget
admission regressions. The full 579,991-frame decoder comparison, private
differential oracle, package race suite, isolated-checkout validation, and build
passed. Historical identity:

```json
{
  "baseline_revision": "6f73ac5254d6722f0bcd3d1aa8472ecc542e59f6",
  "working_tree_patch_sha256": "b4f65113bc04588fa3054f80d51292b84d550e188e0aa389f96898986ed8ab2d",
  "benchmark_binary_sha256": "04a3dead68e631af8be0c152be87a2c9eec657df6d319f019329396bb123b55a"
}
```

The median still missed the three-second target by 0.622 seconds. Scan/order
took 0.690 seconds, analysis/storage 2.877 seconds, and finalization 0.052
seconds. Larger blocks and specialized integer encoding were measured and
reverted. Persistent reuse was deferred because it would not improve the
required fresh-index endpoint and needs separate invalidation and lifecycle
work.

Reproduction and verification:

```sh
python3 scripts/benchmark-offline-acceptance.py CAPTURE.pcap \
  /tmp/lippycat-final-acceptance --backend compact
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all \
  ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/pipeline/... \
  ./internal/pkg/events/... ./internal/pkg/eventanalysis \
  ./internal/pkg/protocolmeta ./internal/pkg/http ./internal/pkg/tls \
  ./internal/pkg/tui/...
LIPPYCAT_BENCH_PCAP=CAPTURE.pcap GOCACHE=/tmp/lippycat-go-cache \
  go test -tags all ./internal/pkg/tui \
  -run '^TestOfflineCompactIndexerPrivateOracle$' -timeout 10m
```

## Writer construction and compression overlap

The next follow-up retained two changes: recording column boundaries during row
encoding, and overlapping one block's compression with construction of the next
batch. The compact schema and integrity checks were unchanged.

The encoder records boundaries in admitted reusable storage. Compression owns
at most one pending block and fixed buffers; the builder alone writes files and
transfers disk accounting. Pending work drains before amendments, finalization,
failure cleanup, or disk-pressure reads. Overlap requires at least a 32 MiB
cache and a 4–256 KiB payload; admission charges buffers, compressor allowance,
worker bookkeeping, and construction headroom. Pressure retires the optional
worker and safely falls back to the serial path.

| Five-run comparison                                 | Baseline | Candidate |
| --------------------------------------------------- | -------: | --------: |
| Recorded boundaries and single-pass encoding       |  3.716 s |   3.575 s |
| Add bounded compression overlap                     |  3.602 s |   3.127 s |
| Final combined change versus original baseline      |  3.712 s |   3.178 s |

The final candidate won every paired run and reduced the median by 14.4% while
retaining the 89,246,448-byte index. A separate complete acceptance matrix
measured 3.171 seconds ready, 3.173 seconds to the first page, 178 MB/s export,
62.92 MB peak accounted memory, and 134.4 MiB median whole-process peak RSS.
Private differential, resource-success, failure, cleanup, race, isolated-build,
and complete-build checks passed.

Historical identity:

```json
{
  "baseline_revision": "3a80772de4e66b2b8acf351692e5cc25fcab7ab2",
  "working_tree_patch_sha256": "d022938ebc2b5104f48a2caaf7cda76444e2fe80fbff89b2e95e2bb05ea01170",
  "final_binary_sha256": "f08ace39f3490ad5a66dda4e95ef9b83ccff52df962239b5ea15c4382483b796"
}
```

## Rejected experiments and Phase 5 feasibility

Temporary overlays screened alternatives after the first completed-open work.
They made no production-code or runtime-default changes.

| Variant                               | Median ready | Complete index |
| ------------------------------------- | -----------: | -------------: |
| Current implementation                |      3.702 s |       89.25 MB |
| Single-pass row encoding              |      3.683 s |       89.25 MB |
| Profile-guided compilation            |      3.754 s |       89.25 MB |
| Compression disabled, diagnostic only |      3.314 s |      301.79 MB |

The single-pass microbenchmark improved, but full-file timing did not establish
a reliable win. The workload-specific PGO profile regressed both time and
allocations. Disabling compression demonstrated material cost but violated the
100 MB storage target. `GOGC=200` and `GOGC=400` raised peak RSS without a
reliable opening-time improvement, so runtime defaults remained unchanged.

A local TShark 4.6.6 comparison measured a 2.601-second median and 664.6 MiB
median peak RSS versus lippycat's 3.684 seconds and 116.3 MiB. This supported
the plausibility of the user's observation but was not a controlled GUI or
equivalent-work comparison.

Phase 5 requires more than publishing the existing locator scan. A correct base
must persist globally ordered random access and base scalar fields, assign
revision identity to tokens/caches/queries/details/exports, publish completed
analysis atomically, and preserve a valid base after analysis failure. Protocol,
Info, and application metadata remain pending until that completed revision.
No subsecond early-publication claim was supported by the measurements.

The deleted screening JSON contained no additional conclusion beyond the tables
above. Its reproducibility identity was revision `3a80772d`, mixed-capture
SHA-256 `53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`,
and working-tree patch SHA-256
`d022938ebc2b5104f48a2caaf7cda76444e2fe80fbff89b2e95e2bb05ea01170`.

## VoIP-heavy capture

The 158,436,032-byte private `gtest6.pcap` capture, SHA-256
`ff79696784871fe6b8f6bd2b44fbb9758c95f65d3a78eebbbc502ef5543486a3`,
exposed a call-tracking cost absent from the mixed-traffic capture. Its original
completed-open profile took 55.06 seconds and allocated about 61.1 GB for
316,382 logical packets; `touchCallLocked` accounted for 48.26 CPU seconds.

Every newly tracked call copied and rescanned up to 5,000 registry entries to
discover eviction. `Core.UpsertWithEviction` now reports the evicted ID directly,
allowing the TUI to remove only that call's auxiliary state. The registry also
stops at the first unpinned least-recently-used entry when no custom priority is
configured. A second change passes already-validated sparse-metadata boundaries
to the writer instead of decoding and re-encoding solely to rediscover them.

| Measurement                        | Original | Candidate |
| ---------------------------------- | -------: | --------: |
| Clean completed-open comparison    | 55.04 s  |   7.616 s |
| Cumulative allocation              | 61.1 GB  |    5.96 GB |
| Earlier mixed-traffic median       |  3.238 s |    3.169 s |

The completed VoIP index remained 314,252,031 bytes and every run retained
316,382 packets and 2,500 events. The full private oracle, seeded eviction
reference tests, exact metadata parity, broad race suites, isolated build, and
complete build passed. The raw JSON was redundant with this record; historical
identity was baseline revision `099ba6ca`, baseline binary SHA-256
`f08ace39f3490ad5a66dda4e95ef9b83ccff52df962239b5ea15c4382483b796`,
and candidate binary SHA-256
`f7ec22535320e9d8ddd1154d841a2d9515fa53eb0d03bbf85318f42aa06fba89`.

## Remaining VoIP costs

The final follow-up targeted SIP decoding, generic metadata encoding, and
external-sort writes. Locator preparation now skips terminal SIP decoding for
supported plain Ethernet/IP/TCP-or-UDP frames after a cheap protocol/port
precheck. VoIP-only metadata uses the frozen typed schema, and sort output uses
an optional accounted 16 KiB buffer with flush-before-read and low-memory
fallback.

Before the non-SIP precheck, the combined candidate reduced a 7.500-second
baseline to 5.573 seconds and allocations from about 5.96 GB to 4.26 GB. A
mixed-traffic regression then led to the precheck. Final paired results were:

| Capture       | Baseline samples (seconds) | Final samples (seconds) | Median change          |
| ------------- | -------------------------- | ----------------------- | ----------------------: |
| VoIP          | 7.683, 7.643, 7.609        | 5.398, 5.538, 5.313     | 7.643 → 5.398 (29.4%) |
| Mixed traffic | 3.060, 3.139, 3.106        | 3.124, 3.144, 3.156     | 3.106 → 3.144 (1.2%) |

The small 38 ms mixed-traffic median regression was retained and reported. Both
private captures passed the complete differential oracle; capture, offline,
TUI, call-registry, and VoIP race suites, isolated validation, and the full build
passed. The few-second VoIP target remains unmet. The deleted raw JSON added no
conclusion beyond these samples and identities: baseline revision `7015120f`,
VoIP SHA-256 `ff79696784871fe6b8f6bd2b44fbb9758c95f65d3a78eebbbc502ef5543486a3`,
mixed-capture SHA-256 `53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`,
and tracked-patch SHA-256
`d022938ebc2b5104f48a2caaf7cda76444e2fe80fbff89b2e95e2bb05ea01170`.
