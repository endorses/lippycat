# Progressive offline readiness observation

Measured 2026-10-25 during
[operational visibility workstream 5](../plans/operational-visibility-and-offline-investigation.md#workstream-5--compact-index-milestone-b),
from implementation based on `e966aefb`. This is one generated-fixture observation,
without a numerical performance acceptance gate.

Reproduce from the repository root:

```sh
go test -tags all ./internal/pkg/tui \
  -run '^(TestOfflineProgressiveCandidateQuotaFailurePreservesBase|TestOfflineProgressiveReadinessAndAbandonedCompletedOwnership)$' \
  -count=1 -v -timeout=90s
```

`writeOfflineEventFlows(t, 513)` creates a nanosecond classic Ethernet PCAP with
513 distinct UDP flows, source ports 20000–20512, destination port 32001, payload
`offline EOF event`, and timestamps beginning at Unix 1700000000 with 1 µs
increments. The test recreates and removes its own input and session files.
There is one source, source backing, no BPF, VoIP or TLS key log, and a one-event
compatibility ring. Limits are 64 MiB disk, 16 MiB cache, 1 MiB record and 64
sources. The complete event dataset contains all 513 EOF connection events.

| Endpoint from start of open       | Observed elapsed |
| --------------------------------- | ---------------- |
| Complete ordered base ready       | 4.506040 ms      |
| First useful base page and render | 5.280490 ms      |
| Complete ordered analysis         | 17.143590 ms     |

The useful-page endpoint creates an all-packets base query, materializes at most
64 rows, and renders `PacketList.View` at 120×40 with pending-analysis
presentation. Its components were query 4.729 µs, page 447.741 µs and render
312.312 µs. It executes synchronously in the base-ready callback before analysis
starts. It excludes Tea scheduling and terminal I/O; it is not a measurement of
the user's first displayed terminal frame.

The shared ledger reported 410,870 current disk bytes, 427,104 peak disk bytes and
9,611,504 peak charged memory bytes. Charged memory is not process RSS. This small
fixture does not establish scaling or real-world throughput.

Environment: Linux/amd64, Go `go1.27.1-X:nodwarf5`, 32 CPUs, GOMAXPROCS 32,
`all` build tag without race instrumentation. The input was freshly written;
filesystem cache state was warm/uncontrolled, and persistent index reuse was not
used. The shared task Go build cache affects compilation, outside measured open
boundaries. OS-cold observations were not collected. `LIPPYCAT_BENCH_PCAP` was
unset, so private capture evidence is unavailable.

Separate correctness checks cover 1,086 mixed-source/protocol packets with
external sorting, exact completed packet/metadata/event parity, immutable base
fields, pending-query admission, source/backing lifetime, pinned exports,
analysis/EOF/quota failures, cancellation, replacement and concurrent cleanup.
