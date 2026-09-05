# Offline dataset phase 0 baseline

Measured 2026-09-05 against the existing reader and event implementation at
`fff6c68f`, with the phase 0 benchmark harness added. These measurements establish
comparison workloads, not a claim that a disk-backed index already exists.

## Environment and method

Linux 6.18.32-2-lts, amd64, Intel Core i9-13900HX, 32 logical CPUs;
`go1.26.3-X:nodwarf5`, default GOMAXPROCS 32, `-tags all`, no race instrumentation.
Shared development host, warm filesystem cache, no CPU pinning. The event runs
were completed before the reader measurements. Times are local observations, not
portable throughput guarantees.

`BenchmarkOfflineOrderedBaseline` generates one chronological classic PCAP with
256-byte Ethernet/IPv4/UDP frames in one fixed flow. Generation is streaming and
outside the Go benchmark timer. The measured operation opens the input, runs
`RunOfflineOrderedContext`, consumes every logical packet, and closes the source.
The first-packet metric measures the delay until the consumer receives its first
packet. No application analyzer, TUI bridge backlog, display store, or terminal
is included. This is the current read/sort/replay baseline for future indexing,
not full watch startup or an on-disk storage benchmark. Checksums are zero and
there are no fragments, tunnels, or application messages in this fixture.

Each size runs once in a fresh compiled test process. Peak RSS includes runtime,
test setup and fixture generation, but excludes the compiler. Captured bytes and
cumulative allocated bytes are distinct from peak resident memory. RSS was read
with Python `resource.getrusage(RUSAGE_CHILDREN)` after each successive process;
that value is the maximum across completed children. Sizes were run in increasing
order and each peak exceeded its predecessor. For isolated reproduction use a
fresh Python parent per size, as below.

| Logical packets | PCAP bytes  | Replay seconds | First packet seconds | Peak RSS KiB | Allocated bytes/op | Allocs/op  |
| --------------- | ----------- | -------------- | -------------------- | ------------ | ------------------ | ---------- |
| 10,000          | 2,720,024   | 0.010566       | 0.008574             | 46,376       | 26,515,064         | 150,124    |
| 100,000         | 27,200,024  | 0.099714       | 0.084603             | 199,544      | 270,364,440        | 1,500,195  |
| 1,000,000       | 272,000,024 | 1.089309       | 0.922335             | 1,684,640    | 2,693,358,672      | 15,000,260 |

Every run consumed exactly the requested count. Peak RSS rose roughly 1.4 GiB
between 100,000 and 1,000,000 packets. The full collection and stable sort precede
first delivery. A fixed display ring cannot bound this reader allocation; the
unbounded offline pending bridge slice can add further memory in real use.

Reproduce without compiling inside the RSS measurement:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -c -tags all \
  -o /tmp/lippycat-capture-baseline.test ./internal/pkg/capture
python3 - 1000000 <<'PY'
import resource
import subprocess
import sys
n = int(sys.argv[1])
subprocess.run([
    '/tmp/lippycat-capture-baseline.test', '-test.run', '^$',
    '-test.bench', f'BenchmarkOfflineOrderedBaseline/packets_{n}$',
    '-test.benchtime=1x', '-test.count=1',
], check=True)
print('peak_rss_kib=', resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss)
PY
```

## Dataset-sized packet behavior

`store.TestOfflineRetentionBaseline` ingests 100,000 display records in batches
of 100 with a fixed 10,000-packet capacity, then applies filters for exact info
strings at the beginning, middle and end. It verifies:

| Observation                                         | Current result                                     |
| --------------------------------------------------- | -------------------------------------------------- |
| Processed counter                                   | 100,000                                            |
| Raw ring and unfiltered display                     | 10,000 each                                        |
| Filter for packet 0 / 50,000 / 99,999               | 0 / 0 / 1 matches                                  |
| Clear filter                                        | 10,000 visible; earlier packets remain unavailable |
| Matched counter before / after filter reapplication | 100,000 / 10,000                                   |

This is a store-level regression fixture, not a complete file-open integration
test. The [consumer audit](watch-file-offline-consumer-audit.md) traces how the
same slices determine navigation and export and records the separate filtered
arrival history. The transitional notice deliberately calls the cumulative
packet-store count “processed”, without implying verified source completeness.

## Event replay and rendering

Command (three samples, 200 ms target per benchmark):

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all \
  ./internal/pkg/tui ./internal/pkg/tui/components -run '^$' \
  -bench 'BenchmarkModelEventDNSReplay$|BenchmarkEventsViewRenderTimeline$' \
  -benchtime=200ms -count=3
```

| Workload                                                          | Median ns/op | Observed ns/op range | Allocs/op   |
| ----------------------------------------------------------------- | ------------ | -------------------- | ----------- |
| DNS analysis/delivery + model tick + Events render, 50 packets/op | 1,377,880    | 1,301,743–1,506,241  | 6,319–6,320 |
| Timeline 1,000 retained, unprepared                               | 463,717      | 444,142–471,724      | 1,726       |
| Timeline 1,000 retained, prepared                                 | 210,262      | 204,920–210,940      | 648         |
| Timeline 10,000 retained, unprepared                              | 434,681      | 427,777–495,654      | 1,726       |
| Timeline 10,000 retained, prepared                                | 215,387      | 203,100–221,284      | 648         |

Replay uses generated DNS requests over 10,001 rotating UDP flows, 10,000 retained
packets/events, batches of 50, a 160×40 viewport with details, production event
analysis and the local bounded sink. Its assertions check exact arrivals and ring
evictions, zero transport loss and analyzer drops, selection and related-packet
availability. It flushes delivery every batch, so it does not demonstrate absence
of loss with a stalled UI. Median replay throughput is about 36,288 packets/s.
Replay allocated 1,045,904–1,225,175 bytes/op; prepared rendering allocated
248,657–267,271 bytes/op. Short-run allocator variation warrants longer repeated
measurements before treating small differences as regressions.

## Retention and loss scope

The [consumer audit](watch-file-offline-consumer-audit.md) is the authoritative
function-level inventory. In particular, offline event sink backpressure does
not make end-to-end delivery lossless: the pending model queue caps at 4,096
batches and can drop. The typed event ring then evicts old events independently;
transport loss, pause suppression, compatibility omissions and ring eviction have
separate counters. Calls have separately capped tracking/display history and
aging; they do not promise one retained record for every call in the file.
Stateful analyzers can consume packets whose display rows are subsequently
evicted. Neither packet completeness nor complete event/call history follows
from a processed counter.

## Comparison gates for later phases

Use the same host/workload and at least five 1-second samples when assessing a
regression. A median above 1.79 ms per 50-packet DNS replay batch or 0.280 ms per
prepared 10,000-event timeline (30% over this baseline) requires investigation
before acceptance. Keep allocation counts within 10% (6,952 replay; 713 prepared
render) unless an explicitly reviewed change explains the increase. These are
initial investigation gates, not unit-test timeouts.

At fixed storage/cache/source budgets, the future 100,000→1,000,000 fixed-flow
run should add no more than 64 MiB of peak RSS after warm-up, with infrastructure
heap profiles checked for count-proportional offsets/match arrays. This is a
provisional acceptance target, not an observed storage result or a hard process
RSS cap. Separately profile analyzer, reassembly, retained event/call and runtime
state. Disk amplification, page/detail/filter/export latency, cancellation and
multi-source throughput have no current dataset implementation to measure; record
those in phases 2–6. The current replay throughput is a comparison point, not a
requirement that indexing plus durable writes cost no additional time.
