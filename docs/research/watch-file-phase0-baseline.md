# Compact index Phase 0 baseline and verification

Recorded 2026-09-06. This establishes the legacy comparison point and the
measurement/oracle machinery; it does not implement or certify a compact backend.

## Deterministic event ordering correction

The new oracle exposed a pre-existing production defect in
`internal/pkg/conntrack/tracker.go`: EOF/expiry sorting used node and flow tuple
without source provenance. Different input files with identical tuples tied, so
map iteration changed which payload received each deterministic EventID. The
initial 15-run synthetic check reproduced approximately five failures.

After explicit authorization, the fix adds capture source, interface name,
numeric interface index and input file as tie breakers, preserving node/flow
precedence. Equal-time capacity eviction now uses the same source distinctions.
The correction is commit `52456e0e665f06fad42f309553089a6eabed744b`.
Regression tests check both insertion permutations for every source field and
actual Close, Expire and eviction outputs. Independent review approved the fix;
twenty repeated runs of the previously failing legacy sanity oracle passed.

The comparator remains strict. Intentionally random flow UIDs are compared
bijectively, preserving presence/reuse/distinctness; all deterministic event IDs,
producer/session IDs, sequence numbers, Community IDs and payloads remain exact.
File observations also contain a randomly generated analyzer prefix: the oracle
maps only that prefix bijectively and checks the exact 16-hex-digit observation
counter, parent/content relationships and every remaining file-event field.
Neither random identifier normalization changes production behavior.
UI wall-clock arrival time is excluded, while arrival sequence and all history
counters are compared. Retained events use the existing configured history cap.

## Baseline identity and environment

The baseline is commit `370761c7174064c694413371c233c16d185e270d` plus the
pre-existing performance working tree. The binary `git diff --binary HEAD`
over its ten modified tracked files has SHA-256
`6a8f24a22adf641ac607268f8c79475a40d6005acbfcd992ea9f213c5fa95e23`.
[The baseline identity manifest](watch-file-phase0-baseline-identity.json)
records every modified and untracked baseline file separately, including the
original benchmark and research. Its original canonical JSON bytes have SHA-256
`483502ed7c04ebd17f0b593a94075d8550b0d718a6049c5b2bb00b9a045e8210` (before
documentation formatting). These pre-existing files are preserved and excluded
from the Phase 0 implementation commit, except the explicitly requested plan.
Local recovery copies and the exact patch are in `/tmp/lippycat-phase0-baseline`;
hashes identify the baseline but do not make an uncommitted patch retrievable
from Git alone. Preserve that patch alongside results when moving hosts.

| Setting                     | Recorded value                                                                                                                                              |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Go                          | `go1.26.3-X:nodwarf5 linux/amd64`                                                                                                                           |
| Build                       | `-tags all`, default compiler optimization, no race/profiling for timing                                                                                    |
| Host                        | Linux `6.18.32-2-lts`, Intel Core i9-13900HX, 32 logical CPUs                                                                                               |
| Memory                      | 67,129,327,616 bytes physical; swap enabled; no CPU pinning                                                                                                 |
| Current process cgroup      | `memory.max=max`, `cpu.max=max 100000`                                                                                                                      |
| Source filesystem           | ext4, local home volume                                                                                                                                     |
| Session filesystem          | `/tmp`, tmpfs; its pages contribute to host memory pressure                                                                                                 |
| Cache                       | Warm: full capture SHA-256 read before first run; no cache drop                                                                                             |
| Host load                   | Shared developer host; timing is observational, not an isolated performance experiment                                                                      |
| Capture                     | Private `capture_20251020_082236.pcap`, 323,454,505 bytes                                                                                                   |
| Capture SHA-256             | `53fad981f7092d229c1e6232df3707f69f4ce58af23b408d370864c143cd7450`                                                                                          |
| Input order / BPF           | One argument, no BPF, original content identity computed by worker                                                                                          |
| Frozen legacy configuration | Fresh process, no user configuration loaded; VoIP mode off, TLS decryption off, ESP defaults; node `watch-local`, profile `watch-eventanalysis-v1\|filter=` |
| Histories                   | 10,000 retained events, 5,000 maximum calls; normalized event arrival count is separate from retained history                                               |
| Dataset limits              | 4 GiB disk, 64 MiB cache, 8 MiB maximum record, 64 sources; fresh private session per run                                                                   |

The identity JSON intentionally contains repository file hashes only. Private
traffic, key material, profiles and raw operation output remain local.

## Original benchmark reproduction and fresh baseline

Preserve the production-worker reproduction from the performance investigation:

```sh
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui \
  -run '^$' -bench '^BenchmarkOfflineFileIndex$' -benchtime=1x -benchmem \
  -cpuprofile=/tmp/lippycat-open.cpu -memprofile=/tmp/lippycat-open.mem \
  -o /tmp/lippycat-open.test -timeout 3m

GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -cum \
  /tmp/lippycat-open.test /tmp/lippycat-open.cpu
GOCACHE=/tmp/lippycat-go-cache go run cmd/pprof -top -alloc_space \
  /tmp/lippycat-open.test /tmp/lippycat-open.mem
```

Profiling runs are separate and must never enter unprofiled timing medians.
The original benchmark remains an existing local baseline file, not part of the
Phase 0 commit. For the following measurements it was compiled once using
`go test -c -tags all ./internal/pkg/tui`, then executed three times in fresh
processes with `-test.run=^$ -test.bench=^BenchmarkOfflineFileIndex$`
`-test.benchtime=1x -test.benchmem -test.timeout=3m` and the environment above.

| Run | Worker Ready (s) | Whole benchmark (s, includes cleanup) | Allocated bytes | Allocations |
| --- | ---------------: | ------------------------------------: | --------------: | ----------: |
| 1   |      8.743451430 |                           8.777613674 |   5,563,927,592 |  41,995,085 |
| 2   |      9.133123271 |                           9.166111949 |   5,562,679,592 |  41,994,739 |
| 3   |      9.540503838 |                           9.576477701 |   5,563,495,912 |  41,994,978 |

The worker median is 9.133123271 s. Every run has 579,990 logical packets,
44,873 arrived normalized events, and 683,436,932 completed index bytes:
526,285,829 details, 138,583,049 summaries, 18,559,696 offsets and 8,358 other.
This reproduces the earlier exact counts/storage. The earlier 10.26 s median
remains historical evidence; a faster host run is not a compact-index result.
The current backend has no separately published base-ready endpoint.

## Acceptance harness and oracle

Phase 0 extends these measurements with explicit phase boundaries, operations,
resource reporting and a candidate-injection comparison harness. Numeric
regression tolerances are fixed in the
[offline contracts](../design/watch-file-offline-contracts.md) before evaluation
of a replacement. Cold-cache and controlled Wireshark measurements remain
unverified; the user's approximately 3 s Wireshark observation is not a measured
comparison. Future source/snapshot runs must report copy/decompression cost and
filesystem conditions as distinct conditions.

The end-to-end oracle completed on the private capture: all 579,990 logical
records, nine query cases (all, text, numeric, metadata, node, SIP, BPF, boolean,
stack), complete dataset/query statistics, raw digests and exported records
matched. The retained event comparison matched 10,000 entries, with 44,873 total
arrivals and one retained call. The comparison is two independently built legacy
sessions, not a compact-backend result. The candidate argument is mandatory;
future migration tests must supply their real implementation and retain the
legacy implementation as the reference. The independent pcapgo synthetic
reference additionally checks every untransformed logical record, including
repeated source arguments and equal timestamps. Synthetic SIP EOF and nil/empty
metadata cases exercise finalized detail amendments and stored projections.

Run the distributable suite and optional private comparison with:

```sh
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui \
  -run '^TestOfflineCompactOracle' -count=1
GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui \
  -run '^TestOfflineCompactOracleLegacySanity$' -count=20
LOG_LEVEL=ERROR LIPPYCAT_BENCH_PCAP=/path/to/capture.pcap \
  GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui \
  -run '^TestOfflineCompactOraclePrivateLegacySanity$' -count=1 -v -timeout 15m
```

The fresh-process acceptance runner compiles once, hashes the original capture
before each process, writes per-run logs and per-child RSS, and computes medians
from unprofiled runs only. Python uses `wait4` on supported Unix hosts; Linux RSS
is KiB. All profiles, original capture paths, query descriptions, binaries and
raw output remain local. A locally generated 100-packet UDP fixture passed
three fresh-process smoke runs with exactly 100 packets, one arrived event,
sparse/dense/all counts 1/90/100, and identical first/repeated field-filter counts.
Those smoke timings ran alongside correctness checks and are not a performance
comparison. The private timing processes run sequentially after correctness work.

```sh
python3 scripts/benchmark-offline-acceptance.py /path/to/capture.pcap \
  /tmp/lippycat-phase0-results --runs 3 --profile
```

Use a new output directory for each condition. `--profile` adds a separate fourth
process; omit it for timing-only comparisons. No privileged cache eviction is
performed. `LIPPYCAT_BENCH_BPF` selects a capture filter and therefore a different
condition; configuration is frozen and logged without key material. The checked-in
runner preserves the original worker-only benchmark command above.

## Verification

The following passed with the ordering fix: the plan's package-level gate
(offline, capture, pipeline, events, eventanalysis, TUI and subpackages), plus
conntrack; the race gate for conntrack/offline/capture/TUI; the focused updated
oracle race suite; and `make build` with `GOCACHE=/tmp/lippycat-go-cache`.
The build required sandbox escalation for Go module-cache metadata writes.
Twenty repeats reproduce stable synthetic event identities, and the full private
oracle passes. Independent reviews checked the ordering fix, test coverage,
168-field inventory, v2 framing sizes, differential comparisons and measurement
runner. The 18 unrelated baseline files still match their original SHA-256s.

## Final Phase-0 measurement matrix

All three warm, unprofiled processes completed successfully, followed by one
separate CPU/heap-profiled process. The table below retains the timing samples;
profiling is excluded from its statistics. These historical measurements include
the authorized ordering correction (`52456e0e`), recorded performance patch and
Phase-0 observer/harness. Measurement identity:

```json
{
  "revision": "52456e0e665f06fad42f309553089a6eabed744b",
  "patch_sha256": "fdb801261cc87b629f0e3889aa7689d8ab41a462148dd48dc72b92bc205cccc7",
  "benchmark_binary_sha256": "edd5264f8f65ed3721d1b59dd3dcb563d4281df23692c72f4ec8a21de59ed32b",
  "runner_sha256": "f432a4dff1194ed5a9383e97d0b0279dac0fddf5778cb06f84edd1a380732ed0"
}
```

Exact patches and raw logs were recorded under
`/tmp/lippycat-phase0-private-final` on the measurement host.

| Endpoint                              |   Run 1 |   Run 2 |   Run 3 |  Median |
| ------------------------------------- | ------: | ------: | ------: | ------: |
| Identity (ms)                         | 164.074 | 162.743 | 161.479 | 162.743 |
| Scan/normalization (ms)               | 759.255 | 683.034 | 804.479 | 759.255 |
| Ordering (ms)                         | 210.446 | 205.227 | 236.160 | 210.446 |
| Analysis + storage (s)                |   7.234 |   7.560 |   8.043 |   7.560 |
| Finalization including EOF (ms)       |   0.556 |   0.414 |   0.435 |   0.435 |
| Full ready (s)                        |   8.371 |   8.614 |   9.248 |   8.614 |
| First page read (ms)                  |   0.335 |   0.228 |   0.215 |   0.228 |
| First packet-pane render (ms)         |   0.965 |   0.566 |   0.982 |   0.965 |
| First useful pane from open (s)       |   8.372 |   8.615 |   9.249 |   8.615 |
| Base source filter, first (s)         |   1.069 |   1.191 |   1.228 |   1.191 |
| Base source filter, repeated (s)      |   1.098 |   1.270 |   1.168 |   1.168 |
| Application protocol, first (s)       |   0.980 |   1.083 |   1.050 |   1.050 |
| Application protocol, repeated (s)    |   0.981 |   1.094 |   1.020 |   1.020 |
| Related lookup, first (s)             |   0.982 |   1.026 |   1.079 |   1.026 |
| Related lookup, repeated (s)          |   0.911 |   1.040 |   0.964 |   0.964 |
| Random page p95 (microseconds)        |   9.356 |   5.799 |   5.049 |   5.799 |
| Random detail p95 (microseconds)      |   4.992 |  14.056 |   6.115 |   6.115 |
| Export effective bytes (MB/s decimal) | 144.194 | 130.411 | 133.296 | 133.296 |

Median first/repeated Info queries were 1.058/1.041 s; HTTP-presence queries were
1.014/1.008 s. Counts were stable in every process: base-source 215,024;
application-protocol 17; Info 3,916; HTTP presence 262; related flow 17.
Controlled sparse/dense/all predicates completed with 580/521,991/579,990 matches;
their query files used 6,575/4,186,595/4,650,587 bytes respectively. Every query
checked complete match/statistics packet counts. Predicate construction and
first/repeated operation order are fixed in the benchmark source; results are
compared with the same sequence and frozen configuration in future runs.

Completed storage remains exactly 683,436,932 bytes. Export has 323,454,419 bytes
including PCAP framing, and throughput excludes those headers. Sampled accounted
and combined peak disk lower bounds were 1,033,529,293 / 1,031,911,764 /
1,033,093,227 bytes; completed-index-relative transient excess was
350,092,361 / 348,474,832 / 349,656,295 bytes. Query disk is reported separately
above. Sampling may miss the exact sort/index coexistence peak; the ledger's
4 GiB limit is enforced independently. Exact disk high-water instrumentation
remains required for the production cutover peak gate.

Whole-matrix peak RSS was 220,528 / 222,312 / 221,232 KiB. Median cumulative
allocation was 18,722,787,120 bytes, retained Go heap 79,738,680 bytes, and final
accounted cache/pin/prefetch/in-flight memory 58,716,489 bytes. These include
query/detail/export work and must not be compared directly with the worker-only
allocation figures above. Heap and RSS include analyzer/history/runtime overhead
outside the logical cache; their difference from cache accounting is not an
isolated analyzer allocation measurement.

Phase 0 is a baseline and oracle gate, not a compact production cutover. The
legacy path still misses the future 3 s and 100 MB engineering targets. Its base
and application readiness coincide at full completion; there is no separately
published base. Full model/event-loop/terminal rendering, controlled cold-cache
runs, persistent reuse and a controlled Wireshark comparison remain unverified.
The first-render metric measures actual packet-pane rendering, not terminal
presentation. These limits are explicit in the measurement contract and must
not be interpreted as passed cutover gates.
