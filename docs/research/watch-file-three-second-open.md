# Completed capture opening: performance verification

The reported capture now reaches completed analysis in a median **3.622 s**,
compared with **10.121 s** for the phase-4 production acceptance baseline.
The first useful packet-list render completes in **3.624 s**. This is a 64.2%
reduction, but the independent **3.0 s target remains unmet by 0.622 s**.
The completed-only publication contract is unchanged.

## Measurements

Three fresh, unprofiled processes, with an untimed complete input read before
each process. Same 323,454,505-byte capture, 579,990 normalized packets and
44,873 arrived events; no persistent dataset reuse. Intel Core i9-13900HX,
Go 1.26.3-X:nodwarf5, `all` tags, default GOMAXPROCS/GOGC, 64 MiB storage cache,
8 MiB record limit and 4 GiB disk limit. Event history retains 10,000 events.

| Endpoint                      | Phase-4 baseline median | Optimized median |
| ----------------------------- | ----------------------: | ---------------: |
| Completed analysis            |                10.121 s |          3.622 s |
| First useful page from open   |                10.122 s |          3.624 s |
| First source filter           |                 1.050 s |          0.966 s |
| First protocol filter         |                 0.973 s |          0.938 s |
| First HTTP-metadata filter    |                 1.006 s |          0.917 s |
| Related-flow lookup           |                 1.035 s |          0.978 s |
| Random page, within-run p95   |                0.184 ms |         0.270 ms |
| Random detail, within-run p95 |                0.014 ms |         0.049 ms |
| Effective export throughput   |              163.4 MB/s |       172.6 MB/s |
| Whole acceptance allocations  |                8.312 GB |         3.823 GB |
| Whole-process peak RSS        |               131.3 MiB |        126.3 MiB |

Completed-ready samples: **3.603, 3.622, 3.723 s**. Useful-page samples:
**3.604, 3.624, 3.724 s**. The three-sample nearest-rank p95 is 3.723 s
for completion. Opening allocates 1.595 GB cumulatively, versus approximately
6.10 GB before these changes; this is allocation traffic, not retained memory.

Completed owned storage is 89,246,448 bytes, below the 100 MB target. The exact
ledger peak is 200,777,808 disk bytes and at most 54,232,679 memory bytes.
The sampled combined disk lower bound, including export, is 412,700,867 bytes.
Retained heap after the acceptance workload is approximately 14.14 MB.

All measured query/detail/page latency, export, allocation and RSS regression
gates pass the predeclared tolerances. Random operations are slightly slower in
absolute microseconds but remain within the fixed 1 ms allowance. Exact filter
counts agree across repetitions. These measurements do not establish cold-cache
performance, terminal I/O latency or a controlled Wireshark comparison. The page
endpoint includes `PacketList.View` at 120 by 40, as in the existing harness.

Historical measurement identity:

```json
{
  "baseline_revision": "6f73ac5254d6722f0bcd3d1aa8472ecc542e59f6",
  "measured_working_tree_patch_sha256": "b4f65113bc04588fa3054f80d51292b84d550e188e0aa389f96898986ed8ab2d",
  "benchmark_binary_sha256": "04a3dead68e631af8be0c152be87a2c9eec657df6d319f019329396bb123b55a"
}
```

Existing
uncommitted baseline changes were retained for both measurements and verification;
they are excluded from this implementation's commit. Private input paths,
exported captures and profiles remain local.

## Changes and correctness boundaries

- Batched compact-directory writes and reused bounded transposition/row buffers;
  retained exact row checksums and the existing schema.
- Reused a compatible faster DEFLATE writer. Existing standard-library readers
  still validate both old and new compressed blocks.
- Used synchronous borrowed replay and reusable packet layers for supported
  frames. Fragments, tunnels and unsupported decoding paths retain the original
  decoder and owned bytes wherever normalization can retain them.
- Reused admitted scan, replay and worker slabs. Public readers and observers
  keep their owned-buffer contracts; oversized records use independent storage.
- Separated ordered event analysis and compact writing into bounded workers.
  Each stateful analyzer still receives one serial, deterministic packet stream;
  workers are joined before EOF publication and amendments drain preceding writes.
- Removed packet-local HTTP/TLS metadata construction that reassembly discarded,
  reused consumed TCP-buffer space, and preserved TLS fingerprint strings with
  frozen-oracle tests.
- Replaced per-event dispatcher flushes with bounded lossless queue admission.
  Live delivery retains its existing nonblocking policy; EOF still drains sinks.

Independent reviews found and corrected a TCP DNS decoding mismatch and two
small-budget admission regressions while developing the optimizations. Targeted
regressions cover those cases, borrowed-buffer poisoning, fragment retention,
FIFO ordering, canceled/failed workers, source changes and cleanup. The private
physical-frame decoder comparison checked all 579,991 frames, including concrete
layer fields and decoding failures.

## Remaining gap

The acceptance median spends 0.690 s scanning and establishing normalized order,
2.877 s in analysis/storage, and 0.052 s finalizing. The separate final CPU profile
attributes 2.22 CPU seconds to the compact writer, including 1.15 seconds in block
construction, and 1.41 CPU seconds to the event-analysis worker. These overlap;
they must not be added as wall-clock time.

The remaining critical cost is ordered compact construction and analysis after
the complete scan. Raising blocks from 128 to 512 rows worsened opening to
3.965 s and was reverted. Specializing integer encoding showed no measurable
benefit and was also reverted. Integrity hashes authenticate distinct sources,
records and blocks and remain enabled.

This change fixes the performance regression and substantially reduces startup
work; it does **not** declare the three-second objective achieved. Further work
must target block construction or the separately planned revision-safe base
publication. Phase 5 is not implemented by these changes. Persistent reuse is
deferred because it would not improve the required fresh-index endpoint and
would require separate identity, invalidation and lifecycle verification.

## Reproduction and verification

Keep the private input and output directory local:

```sh
python3 scripts/benchmark-offline-acceptance.py CAPTURE.pcap /tmp/lippycat-final-acceptance --backend compact
GOCACHE=/tmp/lippycat-go-cache go test -race -tags all ./internal/pkg/offline ./internal/pkg/capture ./internal/pkg/pipeline/... ./internal/pkg/events/... ./internal/pkg/eventanalysis ./internal/pkg/protocolmeta ./internal/pkg/http ./internal/pkg/tls ./internal/pkg/tui/...
LIPPYCAT_BENCH_PCAP=CAPTURE.pcap GOCACHE=/tmp/lippycat-go-cache go test -tags all ./internal/pkg/tui -run '^TestOfflineCompactIndexerPrivateOracle$' -timeout 10m
GOCACHE=/tmp/lippycat-go-cache make build
```

An initial private export run exhausted the temporary-directory quota. After
removing obsolete lippycat caches and compiled test binaries, the all-record
export comparison passed. That environmental failure is not treated as a
successful correctness run.

Final verification passed: the complete private-capture differential oracle
(including all/numeric/BPF/boolean filtered export comparisons), the affected
package race suite above, and `make build`. The three unprofiled acceptance
processes also completed successfully.

An isolated checkout of the staged files also passed the affected non-race
package suite, verifying that the scoped commit builds and tests independently
of the preserved uncommitted baseline edits.
