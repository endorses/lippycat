# Offline dataset phase 6 measurements

Measured 2026-09-05 on the phase 0 host: Linux amd64, Intel Core i9-13900HX,
32 logical CPUs, Go 1.26.3, default GOMAXPROCS 32, `all` tags, no race
instrumentation. These are warm-filesystem observations on a shared development
host, without CPU pinning. Each table row is one iteration in a fresh compiled
test process. Compilation is outside the RSS measurement. CPU-heavy benchmark
runs were serialized. These results demonstrate the tested fixed-cardinality
workloads; they are not a hard RSS guarantee for arbitrary protocol state.

## Workloads and measurement boundaries

`BenchmarkPhase6Dataset` isolates normalized storage from readers, analyzers,
event retention, and terminal rendering. It streams 256-byte records in one fixed
UDP flow, finishes the dataset, and creates an explicit all-match query, including
its disk-backed match vector. Budgets remain 2 MiB cache, 64 KiB maximum record,
4 GiB disk and eight sources at both sizes. It checks complete match counts and
random-page identity. Disk amplification includes the dataset and all-match query
and divides by raw packet bytes.

`BenchmarkPhase6OfflineIndex` generates chronological classic PCAP sources,
round-robin interleaved across one or eight sources. Half the packets are valid
DNS questions; half are ordinary UDP payloads, in two fixed flows. The full
production indexer performs capture merge, protocol detection, analysis, event
retention, storage, and EOF drain. Events are capped at 10,000 and calls at 1,000;
storage budgets match the isolated benchmark. Fixture generation is outside the
benchmark timer but inside process RSS. Disk amplification divides normalized
index bytes by complete input PCAP bytes. Short DNS/UDP packets have higher
metadata amplification than the storage fixture's 256-byte records.

Live heap is `HeapAlloc` after a forced GC while the completed dataset and query
(or indexed session) remain owned. Heap reservation is `HeapSys`, not resident
memory. Sampled peak heap reads `HeapAlloc` every 1,024 storage appends and at
query/index progress callbacks; it can miss peaks between samples. Peak RSS is
`resource.getrusage(RUSAGE_CHILDREN).ru_maxrss` from a fresh Python parent for each
compiled binary invocation. Cumulative allocation volume is not retained memory.

First-page latency measures the first 64-row read following filtering. Random
page/detail latency averages 100 deterministic requests, releasing each page
lease before the next. These are warm means, not cold-disk or p95 measurements.
Query cancellation starts inside its first matching predicate and measures until
error return and query-file cleanup. Index cancellation starts in a progress
callback after at least 1,024 records and measures until all index resources have
joined and been cleaned up; the benchmark verifies no candidate and zero disk
charge. Neither includes a human keypress or terminal scheduler latency.

## Reproduction

Compile first:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -c -tags all \
  -o /tmp/lippycat-phase6-offline.test ./internal/pkg/offline
GOCACHE=/tmp/lippycat-go-cache go test -c -tags all \
  -o /tmp/lippycat-phase6-tui.test ./internal/pkg/tui
```

Run this script separately for every kind/count/source combination. Use
`offline 100000 1`, `offline 1000000 1`, and `tui` with each count and source
count `1`/`8`. Anchors on every slash-separated benchmark component prevent
100,000 also matching 1,000,000.

```python
import os
import resource
import subprocess
import sys

kind, count, sources = sys.argv[1:]
benchmark = (
    f"^BenchmarkPhase6Dataset$/{count}$"
    if kind == "offline"
    else f"^BenchmarkPhase6OfflineIndex$/^packets_{count}$/^sources_{sources}$"
)
env = dict(os.environ,
           LIPPYCAT_PHASE6_HEAP_PROFILE=f"/tmp/phase6-{kind}-{count}-{sources}.heap")
subprocess.run([
    f"/tmp/lippycat-phase6-{kind}.test", "-test.run", "^$",
    "-test.bench", benchmark, "-test.benchtime=1x", "-test.count=1",
], env=env, check=True)
print("peak_rss_kib=", resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
```

The optional `LIPPYCAT_PHASE6_HEAP_PROFILE` writes a heap snapshot before session
cleanup. `LIPPYCAT_PHASE6_FIXTURE_DIR` selects an existing directory for persistent
mixed PCAP fixtures, useful for interactive terminal acceptance. Without it,
fixtures and normalized datasets are private test temporary files and are removed.

## Storage, complete filtering, and browsing results

| Packets   | Index packets/s | All-match filter packets/s | Peak RSS KiB | Live heap bytes | Sampled peak heap bytes | Heap reservation bytes | Disk/raw |
| --------- | --------------- | -------------------------- | ------------ | --------------- | ----------------------- | ---------------------- | -------- |
| 100,000   | 163,098         | 290,265                    | 43,608       | 3,757,000       | 13,768,320              | 19,824,640             | 2.773    |
| 1,000,000 | 166,503         | 288,857                    | 41,192       | 4,422,976       | 14,527,696              | 23,986,176             | 2.773    |

| Packets   | First page ms | Random page mean ms | Detail mean µs | Query cancel/cleanup µs |
| --------- | ------------- | ------------------- | -------------- | ----------------------- |
| 100,000   | 0.183         | 0.204               | 3.626          | 28.978                  |
| 1,000,000 | 0.320         | 0.266               | 4.012          | 30.999                  |

The tenfold packet increase added about 650 KiB live heap and 742 KiB sampled
peak heap. Peak RSS decreased by about 2.4 MiB; ordinary allocator/scheduler
variation makes the sign unimportant. Both remain well inside the phase 0
maximum additional 64 MiB RSS gate. There is no packet-count-sized offset or
match-ID array: storage/query inspection and retained heap profiles attribute
storage memory to the bounded frame cache and its LRU entries. The million-row
sample attributes approximately 2 MiB cumulatively to cached-record reads; the
rest is largely runtime threads and initialization/test overhead. Heap profiles
are statistically sampled and do not exactly equal `MemStats.HeapAlloc`.

## Full indexer and analyzer overhead

| Packets   | Sources | Index packets/s | Peak RSS KiB | Live heap bytes | Sampled peak heap bytes | Heap reservation bytes | Disk/PCAP | Index cancel/cleanup ms |
| --------- | ------- | --------------- | ------------ | --------------- | ----------------------- | ---------------------- | --------- | ----------------------- |
| 100,000   | 1       | 48,925          | 90,880       | 9,966,648       | 48,506,664              | 61,734,912             | 8.966     | 0.240                   |
| 100,000   | 8       | 49,638          | 90,080       | 9,981,080       | 48,154,520              | 61,603,840             | 8.966     | 0.329                   |
| 1,000,000 | 1       | 49,727          | 93,668       | 10,052,168      | 48,686,336              | 61,571,072             | 8.977     | 0.558                   |
| 1,000,000 | 8       | 49,995          | 96,848       | 10,056,208      | 48,532,288              | 65,699,840             | 8.977     | 0.570                   |

Every run verified the full packet count and at least two detected protocols;
each retained exactly 10,000 events. Eight sources at one million packets used
only about 74 KiB more live heap than eight sources at 100,000 packets, with
6.6 MiB additional peak RSS. The full indexer's roughly 10 MB live heap and
48 MB sampled peak heap are separate from the storage cache budget. The retained
million-packet analyzer profile includes about 3.5 MiB of sampled event production
allocations plus protocol tables, regular expressions, application initialization,
and runtime threads. This measures two bounded flows, without fragmented traffic,
VoIP calls or TLS decryption; those independently enforced budgets and failure
paths require their own correctness tests, not extrapolation from these values.

The installed Go distribution lacks the prebuilt `go tool pprof` executable.
Its available source was built without downloading tools:

```sh
GOCACHE=/tmp/lippycat-go-cache go build -o /tmp/lippycat-phase6-pprof cmd/pprof
/tmp/lippycat-phase6-pprof -top -sample_index=inuse_space \
  /tmp/phase6-offline-1000000-1.heap
/tmp/lippycat-phase6-pprof -top -sample_index=inuse_space \
  /tmp/phase6-tui-1000000-8.heap
```

## Acceptance thresholds

The phase 0 regression gates remain unchanged: at least five 1-second samples,
median DNS replay at most 1.79 ms per 50 packets and 6,952 allocations; prepared
10,000-event rendering at most 0.280 ms and 713 allocations. Event replay,
rendering, and active-view CPU results are recorded with mixed-mode acceptance
in the [event performance results below](#repeated-event-performance).

The fixed-budget 100,000→1,000,000 infrastructure RSS gate is at most +64 MiB;
these observations pass. Because phase 0 had no dataset implementation, the
following are new local investigation thresholds, not retroactive phase 0
measurements or flaky test timeouts: first/random 64-row page mean below 10 ms,
detail mean below 1 ms, cooperative query/index cancellation including cleanup
below 100 ms, storage indexing and all-match scan throughput at one million rows
at least 70% of the 100,000-row rate, and eight-source indexing at least 70% of
the one-source rate for equal packet counts. All measured cases pass. Future
regression assessment should repeat at least five fresh runs; these single
full-dataset acceptance runs establish a reproducible reference without claiming
percentile latency, cold-disk behavior, or cross-host guarantees.

Root independently reran the 100,000/1,000,000 storage pair and the million-packet,
eight-source indexer after reviewing the harness. Storage peak RSS was
42,440 / 45,300 KiB (+2.8 MiB), with 3,762,944 / 4,429,672 bytes live heap and
188,319 / 186,153 indexing packets/s. The full indexer retained 10,000 events,
used 94,844 KiB peak RSS and 10,043,544 bytes live heap, indexed at 55,323
packets/s, and cancelled with cleanup in 0.505 ms. These independent observations
also pass the gates. Root inspected both retained heap profiles and confirmed
bounded frame-cache/LRU and retained-event allocations rather than count-sized
offset or match vectors.

## Repeated event performance

Same host and workload as the [phase 0 baseline](watch-file-offline-baseline.md):
Linux amd64, Core i9-13900HX, Go 1.26.3, GOMAXPROCS 32, `all`, no race
instrumentation, 160×40 viewport. Five one-second samples per benchmark; reported
values are medians. These timings exclude a physical terminal driver and network
transport. DNS replay includes decoding, the production analyzer and bounded
delivery, 50 packets per iteration. Component benchmarks isolate their named
operation.

| Workload                                                  |           Median | Allocations/op | Acceptance                                      |
| --------------------------------------------------------- | ---------------: | -------------: | ----------------------------------------------- |
| DNS analysis/delivery, tick and Events render, 50 packets |         1.618 ms |          6,319 | Pass: ≤1.79 ms and ≤6,952 allocations           |
| Prepared timeline, 1,000 retained                         |         0.225 ms |            648 | Comparable to 10,000-row viewport cost          |
| Prepared timeline, 10,000 retained                        |         0.223 ms |            648 | Pass: ≤0.280 ms and ≤713 allocations            |
| Unprepared timeline, 10,000 retained                      |         0.466 ms |          1,726 | Control; prepared rendering is about 52% faster |
| Incremental append, 1,000 / 10,000 retained               |   137 / 169.5 ns |          0 / 0 | No full retained-history rebuild                |
| Unfiltered store delta, 1,000 / 10,000 capacity           | 140.4 / 144.0 ns |          1 / 1 | Approximately constant per delta                |
| Filtered store delta, 1,000 / 10,000 capacity             | 124.2 / 124.4 ns |          0 / 0 | Approximately constant per delta                |
| Cached related-packet miss, 1,000 / 10,000 retained       |   207 / 206.1 ns |          1 / 1 | Independent of retained packet count            |

Run the repeated comparison with:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/tui ./internal/pkg/tui/components ./internal/pkg/tui/store \
  -run '^$' -bench 'BenchmarkModelEventDNSReplay$|BenchmarkEventsViewRenderTimeline$|BenchmarkEventStoreIncrementalProjection$|BenchmarkEventsViewAppendIncremental$|BenchmarkHasRelatedPacketMiss$|BenchmarkEventPhase6' \
  -benchtime=1s -count=5 -benchmem
```

A separate five-second DNS replay CPU profile measured 1.466 ms/op and 6,319
allocations. `RenderTimeline` accounted for 6.09% cumulative CPU and update-side
`buildTimelineCache` for 9.88%; reporting both includes formatting work moved out
of rendering. The prior event-plan profile reported 5.57% and 9.89%, respectively.
This is consistent with preserving the optimized path, not a claim of another
Phase 6 rendering speedup. Reproduce with the same replay selector,
`-benchtime=5s -cpuprofile=/tmp/lippycat-phase6-events.cpu`, then
`/tmp/lippycat-phase6-pprof -top -cum /tmp/lippycat-phase6-events.cpu` (tool build
instructions are in the dataset report).

## Per-view CPU and allocations

`BenchmarkEventPhase6ModeViews` feeds the same 50-packet/50-event batch into
10,000-entry live/remote stores, ticks and renders each active view. Live mode
also receives its separate exact ingress-telemetry snapshot. Assertions verify
packet/event arrivals, retained counts, and that only the Events view projects
the stream. This measures delivery/model/presentation work, not NIC or gRPC
throughput. Fixed-flow fixtures intentionally isolate presentation costs.

| Mode   | Active view | Median per 50-packet cycle | Allocated bytes/op | Allocations/op |
| ------ | ----------- | -------------------------: | -----------------: | -------------: |
| Live   | Events      |                   0.787 ms |            499,459 |          2,051 |
| Live   | Packets     |                   0.464 ms |            306,839 |          1,391 |
| Live   | Statistics  |                   0.284 ms |            209,793 |            692 |
| Remote | Events      |                   0.732 ms |            505,786 |          2,031 |
| Remote | Packets     |                   0.462 ms |            312,468 |          1,431 |
| Remote | Statistics  |                   0.295 ms |            209,458 |            672 |

Both modes keep exactly 10,000 events/packets and account for every supplied
batch. Statistics and Packets do not spend CPU projecting hidden event history.
The benchmark passes synthetic packets without raw bytes to the existing
background processor; full background protocol analysis and transport throughput
are outside this measurement. Every model is shut down after its sample.
Initial development samples with the remote model still on its default Nodes tab
or missing the remote packet identity were discarded. Final assertions prevent
either setup error from silently producing reassuring timings.

`BenchmarkEventPhase6OfflineReadyViews` indexes 20,000 DNS/ordinary-UDP packets,
publishes the actual session and loads the selected page/detail/relationship
before timing idle ticks and rendering. It asserts that idle ticks never
reproject event history. Each ready-mode iteration costs 0.751 ms / 0.436 ms /
0.243 ms for Events / Packets / Statistics, respectively, with 1,600 / 1,410 /
657 allocations. Median allocated bytes are 322,711 / 146,688 / 48,126 per
iteration, not retained memory. At the idle one-second tick interval the Events
measurement represents about 0.075% of one CPU core for this work alone; terminal,
runtime and input activity are additional. Storage/analyzer retained and sampled
peak memory are reported separately in the dataset measurements.

## Interactive terminal reproduction

The historical live terminal check exercised controlled delivery, not privileged
NIC capture. Reproduce the opt-in presentation test in an interactive terminal:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -c -tags tui \
  -o /tmp/lippycat-phase6-terminal.test ./internal/pkg/tui
LIPPYCAT_PHASE6_TERMINAL_SMOKE=1 /tmp/lippycat-phase6-terminal.test \
  -test.run '^TestPhase6LiveTerminalSmoke$' -test.v
```

Use `v`, arrows, `d`, Space twice, resize, switch tabs and `q`. Normal suites skip
this opt-in test. Controlled live/remote/offline interaction coverage also lives
in `TestEventPhase6MixedModeAcceptance`.
