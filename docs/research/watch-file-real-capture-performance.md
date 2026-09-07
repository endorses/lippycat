# Real-capture file-open performance investigation

Measured 2026-09-05 on Linux amd64, Intel Core i9-13900HX, 32 logical CPUs,
Go 1.26.3, `all` build tags. The input is the locally supplied 309 MiB capture
`capture_20251020_082236.pcap`: 579,990 packets and 44,873 generated events.
The private capture and profile artifacts are not committed.

These measurements exercise the production offline indexing worker, including
input identity, normalization, sorting, protocol analysis, dataset writing,
EOF draining, and cleanup. They exclude compilation, terminal rendering, and
interactive search. Runs use a warm filesystem on a shared development machine;
no CPU pinning or cold-cache guarantee is implied. The reported three-second
Wireshark opening time is a user observation, not an independently measured
comparison of identical work. This investigation does not establish a feature
or search-speed advantage for lippycat.

## Measurements

Single CPU-profiled full-file runs:

| Implementation | Elapsed | Cumulative allocated bytes | Allocations |
|---|---:|---:|---:|
| Before capture-metadata range traversal | 32.95 s | Not measured | Not measured |
| Range traversal, prior investigation | 11.82 s | Not measured | Not measured |
| Range traversal, fresh baseline | 10.91 s | 7.585 GB | 48.812 million |
| Borrowed record fields, decoded-packet reuse, lazy SMTP parser | 10.24 s | 5.638 GB | 42.075 million |
| Also reuse fully drained TCP buffer capacity | 9.92 s | 5.565 GB | 41.995 million |

Repeated runs without CPU/memory profiling, each in a fresh test process:

| Implementation | Elapsed runs | Median | Typical cumulative allocation |
|---|---|---:|---:|
| Range traversal baseline | 11.34, 11.46, 11.62 s | 11.46 s | 7.59 GB / 48.81 million allocations |
| All current changes | 10.67, 10.26, 10.15 s | 10.26 s | 5.57 GB / 42.00 million allocations |

This is approximately a 10% median latency reduction and a 27% allocation-volume
reduction beyond the earlier range-traversal fix. It does not close the reported
Wireshark gap. Baseline runs preceded changed runs; filesystem state and shared
host load were not controlled sufficiently for a formal statistical comparison.

GB means decimal gigabytes of cumulative allocation, not peak or retained RAM.
Every full-file run produced the same packet and event counts. The completed
index occupies 683,436,932 bytes, about 652 MiB. It includes stored summaries,
details, packet bytes, and an offset table.

The final profiled run reached indexing at 1.28 seconds and readiness at 9.88
seconds. Source reading and external sorting are a small portion of this case;
most elapsed time remains in the per-packet indexing worker.

## Confirmed causes

The initial dominant issue was repeated capture metadata lookup for every TCP
payload byte. Range traversal removed that bottleneck while retaining capture
provenance and frame-completion timestamps.

After that fix, the fresh baseline profile attributed 3.80 CPU seconds to
`offline.Builder.Append`, 2.87 CPU seconds to event analysis, and 3.63 CPU
seconds to background garbage collection. These cumulative CPU measurements
include overlapping goroutines and nested functions; they must not be added
as elapsed-time phases.

Storage performed recursive object-memory validation twice for each summary
and twice for each detail. Interface conversion and temporary wire structs
also copied large packet-display structures onto the heap. Record encoding
still needs a sizing traversal and an encoding traversal to preserve bounded
allocation; the redundant object validation did not serve that purpose.

Local event analysis decoded an already-decoded packet a second time. Every
new TCP stream also constructed an SMTP parser and compiled its regular
expressions, including streams that never carried SMTP. Fully consuming a TCP
buffer discarded its reusable slice capacity.

The final fixes remove these redundant operations. The checked record writer
remains available to independent callers; builders use the prevalidated path
only after accounting for the record. Encoding borrows fields in the existing
schema order. Stream writes, failure handling, publication, and memory budgets
retain their existing behavior.

## Remaining opportunities

The current storage path issues three separate writes per packet: summary,
detail, and offsets. This capture therefore needs roughly 1.74 million such
writes in addition to sorting scratch I/O. Bounded buffering could reduce those
calls, but must charge disk bytes at admission, charge retained buffer memory,
flush before amendment reads and offset updates, and propagate flush failures
before publication. Buffering also changes when backing-file errors become
visible; that needs explicit tests rather than merely replacing writers.

Per-record reflection, frame allocation, and duplicated packet storage remain.
Reusable serialization buffers or a more direct codec merit measurement, with
schema compatibility and transient-memory accounting preserved. The index is
more than twice the input size for this capture. That is an implementation cost,
not evidence that search requires this much startup work.

Analysis still formats reassembly identity keys and hashes source identity per
packet. Packet-local enrichment can parse application metadata that the TCP
path then discards in favor of reassembly. Avoiding that parsing must preserve
protocol recognition on nonstandard ports, so it is a separate correctness-sensitive
change. The current fixes do not bypass analysis or discard events to improve time.

There is no measured basis for claiming that any one remaining change will
reach three seconds. Storage costs, repeated allocations, and analysis now
share the critical path; further work should be evaluated end to end.

## Reproduction

Set the capture path locally, then run:

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

`go run cmd/pprof` uses the installed Go source in this environment, whose
packaged tool directory does not include the `pprof` executable. On other
installations, `go tool pprof` provides the same analysis.

Regression coverage checks byte-for-byte record-schema compatibility, exact
memory-budget boundaries, decoded versus transported protocol-event parity,
nonstandard HTTP ports, and repeated/fragmented TLS records after buffer reuse.
The real-capture benchmark records packet/event counts, which were compared
across the runs above.

Validation passed for the offline storage, event analysis, reassembly, capture,
pipeline, TUI, processor, and sniff-command packages with `all` tags. Storage
and event-analysis race tests also passed. Processor tests required permission
to open local sockets outside the sandbox. The complete `make build` binary
was rebuilt successfully.
