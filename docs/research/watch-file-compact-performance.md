# Compact completed-index performance follow-up

Date: 2026-09-06. Scope: the internal completed compact candidate. Production
selection and the rest of Phase 4 remain unchanged.

## Changes

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

## Measurement identity and method

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

## Results

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

## Verification and disposition

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

## Reproduction

Use the existing reproduction commands in
[Phase 3 verification](watch-file-phase3-validation.md#reproduction), setting
`LIPPYCAT_BENCH_PCAP` to the private capture. Compile once, then run
`BenchmarkOfflineCompactCompleted/compact` and `/legacy` in separate fresh
processes with `-test.benchtime=1x -test.benchmem`, three times each. Run profiling
separately and exclude it from the timing medians. Local raw outputs for this
assessment are in `/tmp/lippycat-compact-performance/`.
