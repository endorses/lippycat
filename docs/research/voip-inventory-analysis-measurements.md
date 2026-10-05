# VoIP and inventory analysis measurements

Date: 2026-10-05. These are exploratory synthetic measurements, with no
performance acceptance threshold or deployment capacity claim.

## Workload and revision identity

The checked-in `BenchmarkInventoryAnalysis` reconstructs a reproducible workload;
it does not reproduce the review's unavailable temporary harness. The baseline is
an isolated checkout of `0c8fd186`, with only this benchmark file copied into it.
The after run uses the scope-cache change in this remediation. The accompanying
[raw results](voip-inventory-analysis-measurements.json) identify the exact baseline
and hash the measured after-source files. The SHA-256 input concatenates each
listed relative filename, a NUL byte, its file contents, and another NUL byte,
in the recorded order. Each trial runs the baseline followed by the changed
runtime, and each invocation contains inventory off/on cases.

The workload has 2,048 bidirectional IPv4 UDP flows, two documentation addresses,
172 payload bytes, 214-byte Ethernet frames, one synthetic capture source, fixed
capture timestamps, and no protocol service evidence. It calls `ObservePacket`
with predecoded synthetic packets; metadata enrichment and runtime observation
are timed, while packet construction is excluded. Defaults are explicit through
`eventconfig.Default()` with only inventory enablement varied. Inventory CIDRs
are omitted; subject policy therefore permits both observed unicast addresses.
The runtime uses fixed producer/capture epochs, a discard event sink, queues of
8,192 items, and lossless dispatcher delivery to avoid treating dropped events
as completed work. This measures analysis with a consumer; consumerless sniff now
skips the optional runtime entirely.

Discovery observes the first request/response for each flow, resetting runtime
state after every 4,096 packets. Reset/setup time and its allocations are excluded
from benchmark statistics. Steady state first observes the full bidirectional
set outside timing, then repeatedly observes established flows without expiry.
The separate correctness tests exercise scope separation, bounds, expiry and
re-emission after eviction; this workload does not characterize those costs.

Runs used Go `go1.27.1-X:nodwarf5`, Linux/amd64, `GOMAXPROCS=32`, five paired
trials, `-benchtime=300ms`, and `-benchmem` on a shared machine. CPU scheduling,
GC, and asynchronous dispatch can vary between runs. No confidence interval or
whole-application inference is supplied. A pre-inventory revision is not compared:
its analysis pipeline and available policy differ, and the original harness and
configuration needed to isolate that historical claim are unavailable.

## Paired results

One operation is one observed packet. Time is minimum / median / maximum across
five trials; allocation columns show the observed range.

| Revision | Flow state | Inventory | ns/packet (min / median / max) | B/packet | allocations/packet |
| --- | --- | --- | --- | --- | --- |
| baseline | discovery | off | 1728 / 2062 / 2294 | 1155–1156 | 17–17 |
| baseline | discovery | on | 2138 / 2344 / 3161 | 1975–1979 | 19–19 |
| baseline | steady | off | 1201 / 1362 / 1529 | 480–480 | 12–12 |
| baseline | steady | on | 1776 / 1785 / 1888 | 1088–1088 | 14–14 |
| after | discovery | off | 1079 / 1166 / 1319 | 951–951 | 10–10 |
| after | discovery | on | 1463 / 1610 / 1686 | 1719–1719 | 11–11 |
| after | steady | off | 659.8 / 684.6 / 715.8 | 288–288 | 5–5 |
| after | steady | on | 953.9 / 1079 / 1170 | 800–800 | 6–6 |

The stable allocation difference is consistent with eliminating repeated scope
formatting and hashing. Incremental inventory work remains: established-flow
inventory adds 512 B and one allocation per packet in this workload. The runtime
still offers evidence to the bounded inventory tracker on every qualifying
observation, allowing re-emission after eviction or expiry. It does not cache a
per-flow decision to suppress future inventory work permanently.

## One profiling pass and resulting change

Before editing the runtime, one inventory-off/on steady-state profiling pass
collected CPU, allocation, and mutex profiles. The profiles include benchmark
calibration, fixture/setup and cleanup, unlike the timed benchmark columns.
They are useful for locating work, not for assigning precise application costs.
The text below preserves the original profile summaries without binary profile
files or personal source paths.

The inventory-disabled profile identified quoted scope formatting on every
packet: `associationScope` accounted for about 38% of allocated space cumulatively.
With inventory on, connection inventory snapshots accounted for about 44% of
allocated space; scope formatting and the inventory tracker's scope hashing were
also visible. CPU profiles showed quoted formatting, flow/tracker lookups,
normalization and metadata enrichment. The serial observation workload's mutex
profile was dominated by runtime synchronization and does not establish behavior
under multiple concurrent packet producers.

The single implementation batch caches the most recent complete scope key and
its SHA-256 digest. It retains one entry, including node identity, analysis epoch,
capture epoch, capture source, interface name/index, input file and runtime
generation. A changed component recomputes the same quoted encoding. TCP or other
attribution using a different scope falls back to hashing that scope. A cheap DNS
port check now precedes unicast evidence checks for non-DNS UDP. Snapshot ownership,
tracker lookups and event contents remain unchanged; no further optimization cycle
is required by these observations.

## Reproduction

Run from the repository root with the checked-in benchmark present. This creates
and removes only its own temporary checkout/results directory:

```bash
repo_dir=$(pwd)
measurement_dir=$(mktemp -d)
trap 'rm -rf -- "$measurement_dir"' EXIT
mkdir -p "$measurement_dir/baseline"
git archive 0c8fd186 | tar -x -C "$measurement_dir/baseline"
cp internal/pkg/eventanalysis/inventory_benchmark_test.go \
  "$measurement_dir/baseline/internal/pkg/eventanalysis/"
for trial in 1 2 3 4 5; do
  (
    cd "$measurement_dir/baseline"
    GOMAXPROCS=32 go test -tags all ./internal/pkg/eventanalysis -run '^$' \
      -bench '^BenchmarkInventoryAnalysis$' -benchtime=300ms -count=1 -benchmem
  ) > "$measurement_dir/baseline-$trial.txt"
  (
    cd "$repo_dir"
    GOMAXPROCS=32 go test -tags all ./internal/pkg/eventanalysis -run '^$' \
      -bench '^BenchmarkInventoryAnalysis$' -benchtime=300ms -count=1 -benchmem
  ) > "$measurement_dir/after-$trial.txt"
done
cat "$measurement_dir"/*.txt
```

The profiling invocation was the following, once per `enabled=false` and
`enabled=true`, against the baseline checkout carrying the reconstructed harness:

```bash
go test -tags all ./internal/pkg/eventanalysis -run '^$' \
  -bench '^BenchmarkInventoryAnalysis/inventory=false/steady$' -benchtime=2s \
  -cpuprofile=off.cpu -memprofile=off.mem -mutexprofile=off.mutex -o analysis.test
# Repeat once with inventory=true and distinct on.* output filenames.
go run cmd/pprof -top analysis.test off.cpu
go run cmd/pprof -top -alloc_space analysis.test off.mem
go run cmd/pprof -top analysis.test off.mutex
```

The actual profiling source was the unchanged pre-cache runtime at `0c8fd186`
in the working tree; running it in the isolated baseline checkout is equivalent
for these runtime files. Profiling is already complete for this plan. Temporary
profiles and caches are removed after recording the sanitized results.

Whole-process CPU/RSS, live offered traffic, capture/queue loss, contention and
mixed-protocol scaling were not measured. Such evidence is needed before making
corresponding application-level claims; it is optional characterization under
this remediation plan.

## Preserved profile summaries

### Inventory off: CPU

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: cpu
Time: 2026-10-05 08:43:55 CEST
Duration: 4.04s, Total samples = 4590ms (113.61%)
Showing nodes accounting for 2400ms, 52.29% of 4590ms total
Dropped 87 nodes (cum <= 22.95ms)
Showing top 15 nodes out of 101
      flat  flat%   sum%        cum   cum%
     310ms  6.75%  6.75%      910ms 19.83%  strconv.appendQuotedWith
     280ms  6.10% 12.85%      540ms 11.76%  strconv.appendEscapedRune
     210ms  4.58% 17.43%      210ms  4.58%  strconv.IsPrint
     200ms  4.36% 21.79%      780ms 16.99%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).envelope
     200ms  4.36% 26.14%      250ms  5.45%  runtime.scanObject
     140ms  3.05% 29.19%      140ms  3.05%  internal/runtime/maps.memHashAES
     140ms  3.05% 32.24%      140ms  3.05%  runtime.memmove
     140ms  3.05% 35.29%      150ms  3.27%  runtime.tryDeferToSpanScan
     130ms  2.83% 38.13%     1340ms 29.19%  fmt.(*pp).doPrintf
     130ms  2.83% 40.96%     3380ms 73.64%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).observeDecodedCaptured
     120ms  2.61% 43.57%      120ms  2.61%  internal/runtime/maps.ctrlGroup.matchH2 (inline)
     110ms  2.40% 45.97%      330ms  7.19%  github.com/endorses/lippycat/internal/pkg/flowid.(*Cache).Lookup
     100ms  2.18% 48.15%      490ms 10.68%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).observe
     100ms  2.18% 50.33%      180ms  3.92%  runtime.mallocgcSmallScanNoHeaderSC2
      90ms  1.96% 52.29%       90ms  1.96%  net/netip.parseIPv4Fields
```

### Inventory off: allocation

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: alloc_space
Time: 2026-10-05 08:43:59 CEST
Showing nodes accounting for 1348.22MB, 97.11% of 1388.36MB total
Dropped 94 nodes (cum <= 6.94MB)
Showing top 15 nodes out of 31
      flat  flat%   sum%        cum   cum%
  496.59MB 35.77% 35.77%   746.10MB 53.74%  github.com/endorses/lippycat/internal/pkg/protocolmeta.EnrichForReassembly
  265.50MB 19.12% 54.89%   525.53MB 37.85%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).associationScope
  259.02MB 18.66% 73.55%   260.53MB 18.77%  fmt.Sprintf
  165.01MB 11.88% 85.43%   249.51MB 17.97%  github.com/google/gopacket.Endpoint.String
   84.50MB  6.09% 91.52%    84.50MB  6.09%  net.IP.String
   44.83MB  3.23% 94.75%    44.83MB  3.23%  github.com/endorses/lippycat/internal/pkg/flowid.NewCache
   16.72MB  1.20% 95.95%    16.72MB  1.20%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).Close
   10.04MB  0.72% 96.68%    10.04MB  0.72%  github.com/endorses/lippycat/internal/pkg/reassembly.(*pageCache).grow
    3.50MB  0.25% 96.93%    11.50MB  0.83%  github.com/endorses/lippycat/internal/pkg/eventanalysis.BenchmarkInventoryAnalysis
    2.50MB  0.18% 97.11%     8.50MB  0.61%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).observe
         0     0% 97.11%    11.73MB  0.85%  github.com/endorses/lippycat/internal/pkg/capture.NewTCPAssembler
         0     0% 97.11%    11.73MB  0.85%  github.com/endorses/lippycat/internal/pkg/capture.NewTCPAssemblerWithLimits
         0     0% 97.11%     8.50MB  0.61%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).ObserveWithInventory (inline)
         0     0% 97.11%    22.23MB  1.60%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).EOF
         0     0% 97.11%  1284.13MB 92.49%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).ObservePacket
```

### Inventory on: CPU

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: cpu
Time: 2026-10-05 08:44:12 CEST
Duration: 4.21s, Total samples = 5160ms (122.71%)
Showing nodes accounting for 2030ms, 39.34% of 5160ms total
Dropped 133 nodes (cum <= 25.80ms)
Showing top 15 nodes out of 148
      flat  flat%   sum%        cum   cum%
     280ms  5.43%  5.43%      720ms 13.95%  strconv.appendQuotedWith
     210ms  4.07%  9.50%      370ms  7.17%  strconv.appendEscapedRune
     170ms  3.29% 12.79%      260ms  5.04%  runtime.scanObject
     160ms  3.10% 15.89%      160ms  3.10%  crypto/internal/fips140/sha256.blockSHANI
     140ms  2.71% 18.60%      140ms  2.71%  runtime.memmove
     120ms  2.33% 20.93%      120ms  2.33%  internal/runtime/maps.memHashAES
     120ms  2.33% 23.26%      240ms  4.65%  runtime.scanObjectsSmall
     120ms  2.33% 25.58%      180ms  3.49%  runtime.scanblock
     120ms  2.33% 27.91%      170ms  3.29%  runtime.tryDeferToSpanScan
     110ms  2.13% 30.04%      130ms  2.52%  github.com/endorses/lippycat/internal/pkg/conntrack.(*flow).event
     110ms  2.13% 32.17%      110ms  2.13%  strconv.IsPrint
     100ms  1.94% 34.11%     3580ms 69.38%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).observeDecodedCaptured
     100ms  1.94% 36.05%      120ms  2.33%  github.com/google/gopacket.(*eagerPacket).Layer
      90ms  1.74% 37.79%      140ms  2.71%  runtime.mallocgcSmallScanNoHeaderSC2
      80ms  1.55% 39.34%     1130ms 21.90%  fmt.(*pp).doPrintf
```

### Inventory on: allocation

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: alloc_space
Time: 2026-10-05 08:44:17 CEST
Showing nodes accounting for 2481.66MB, 97.84% of 2536.37MB total
Dropped 97 nodes (cum <= 12.68MB)
Showing top 15 nodes out of 28
      flat  flat%   sum%        cum   cum%
 1108.54MB 43.71% 43.71%  1108.54MB 43.71%  github.com/endorses/lippycat/internal/pkg/conntrack.(*flow).inventoryObservation
  432.08MB 17.04% 60.74%   656.08MB 25.87%  github.com/endorses/lippycat/internal/pkg/protocolmeta.EnrichForReassembly
  212.50MB  8.38% 69.12%   423.52MB 16.70%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).associationScope
  211.52MB  8.34% 77.46%   211.52MB  8.34%  github.com/endorses/lippycat/internal/pkg/inventory.(*Tracker).Observe
  210.02MB  8.28% 85.74%   211.02MB  8.32%  fmt.Sprintf
  151.50MB  5.97% 91.71%   224.01MB  8.83%  github.com/google/gopacket.Endpoint.String
   72.50MB  2.86% 94.57%    72.50MB  2.86%  net.IP.String
   55.09MB  2.17% 96.74%    55.09MB  2.17%  github.com/endorses/lippycat/internal/pkg/flowid.NewCache
   19.40MB  0.76% 97.51%    19.90MB  0.78%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).Close
    6.50MB  0.26% 97.76%    16.51MB  0.65%  github.com/endorses/lippycat/internal/pkg/conntrack.newFlow
       2MB 0.079% 97.84%  1127.06MB 44.44%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).observe
         0     0% 97.84%  1127.06MB 44.44%  github.com/endorses/lippycat/internal/pkg/conntrack.(*Tracker).ObserveWithInventory (inline)
         0     0% 97.84%    27.40MB  1.08%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).EOF
         0     0% 97.84%  2419.69MB 95.40%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).ObservePacket
         0     0% 97.84%   211.52MB  8.34%  github.com/endorses/lippycat/internal/pkg/eventanalysis.(*Runtime).emitInventory
```

### Inventory off: mutex delay

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: delay
Time: 2026-10-05 08:43:59 CEST
Showing nodes accounting for 17003us, 100% of 17003us total
Dropped 70 nodes (cum <= 85.02us)
Showing top 12 nodes out of 47
      flat  flat%   sum%        cum   cum%
16484.83us 96.95% 96.95% 16484.83us 96.95%  runtime.unlock (inline)
  518.17us  3.05%   100%   518.17us  3.05%  runtime._LostContendedRuntimeLock
         0     0%   100%   206.12us  1.21%  runtime.(*gcWork).init
         0     0%   100%   206.12us  1.21%  runtime.(*gcWork).tryGetObj
         0     0%   100%   680.62us  4.00%  runtime.(*mheap).allocManual
         0     0%   100%   738.68us  4.34%  runtime.(*mheap).allocSpan
         0     0%   100%   382.48us  2.25%  runtime.(*stackScanState).addObject
         0     0%   100%  2963.11us 17.43%  runtime.allocm
         0     0%   100%   990.72us  5.83%  runtime.checkIdleGCNoP
         0     0%   100% 10770.94us 63.35%  runtime.findRunnable
         0     0%   100%   849.16us  4.99%  runtime.forEachP
         0     0%   100%   849.16us  4.99%  runtime.forEachP.func1
```

### Inventory on: mutex delay

```text
File: eventanalysis.test
Build ID: 4abce216a8f80e61c8ff53b0a5a207495097b002
Type: delay
Time: 2026-10-05 08:44:17 CEST
Showing nodes accounting for 26.61ms, 99.81% of 26.66ms total
Dropped 66 nodes (cum <= 0.13ms)
Showing top 12 nodes out of 46
      flat  flat%   sum%        cum   cum%
   26.61ms 99.81% 99.81%    26.61ms 99.81%  runtime.unlock (inline)
         0     0% 99.81%     0.65ms  2.42%  runtime.(*gcWork).init
         0     0% 99.81%     0.16ms   0.6%  runtime.(*gcWork).putObj
         0     0% 99.81%     0.49ms  1.82%  runtime.(*gcWork).tryGetObj
         0     0% 99.81%     2.33ms  8.72%  runtime.(*mheap).allocManual
         0     0% 99.81%     2.39ms  8.98%  runtime.(*mheap).allocSpan
         0     0% 99.81%     0.70ms  2.62%  runtime.(*stackScanState).addObject
         0     0% 99.81%     0.92ms  3.44%  runtime.(*stackScanState).putPtr
         0     0% 99.81%     4.52ms 16.94%  runtime.allocm
         0     0% 99.81%    14.39ms 53.99%  runtime.findRunnable
         0     0% 99.81%     3.10ms 11.62%  runtime.forEachP
         0     0% 99.81%     3.10ms 11.62%  runtime.forEachP.func1
```
