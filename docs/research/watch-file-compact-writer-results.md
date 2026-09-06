# Compact writer construction and compression results

This follow-up retains two measured improvements: recording column boundaries
during row encoding, and overlapping one block's compression with construction
of the next batch. Neither changes the compact schema or removes integrity checks.

The final five-run comparison measured **3.178 seconds versus 3.712 seconds**
completed-ready median, a **14.4% reduction**. The candidate was faster in every
paired run. The completed index remains 89,246,448 bytes.

## Implementation

The typed encoder records field boundaries in admitted reusable storage. Block
construction consumes those boundaries instead of reparsing every encoded row.
The encoder also skips its sizing traversal when a conservative bound proves
that the row fits the caller's buffer. Larger rows and generic callers retain
the validated fallback. Pooling starts only at an empty batch, so earlier rows
cannot lack the boundaries expected by the block writer.

Compression has one pending summary block at most. Its worker owns fixed input
and output buffers and a compressor; the builder alone writes files, creates
directory entries and transfers disk accounting. Pending disk reservations stay
charged until writing. The worker computes SHA-256 over the uncompressed payload
and uses the same compression format and level as the serial path.

Overlap requires at least a 32 MiB cache and a payload between 4 and 256 KiB.
Admission charges two 256 KiB buffers, a conservative 2 MiB compressor allowance,
and worker bookkeeping, while proving additional construction headroom. Larger
blocks use the serial path. Writer memory pressure drains and retires optional
state before retrying admission; pending work also drains before sparse metadata
writes and when disk pressure requires it. Strong flushes retire the worker before
amendment reads or finalization. Retirement disables further overlap for that
builder. Close joins outstanding compression before releasing memory or files.

## Measurements

All measurements use the same 323,454,505-byte private capture on the same
i9-13900HX host, default Go runtime settings and the existing completed-ready
endpoint. Runs use fresh processes and datasets, with an untimed complete input
read beforehand. Agent tests and builds are paused during timing.

| Five-run comparison | Baseline median | Candidate median |
| --- | ---: | ---: |
| Recorded column boundaries and single-pass encoding | 3.716 s | 3.575 s |
| Add bounded compression overlap | 3.602 s | 3.127 s |
| Final combined change versus original baseline | 3.712 s | 3.178 s |

The second comparison alternates the recorded-boundary candidate and the combined
candidate. Separate rounds have different baselines; their deltas should not be
added as exact independent savings. Compression overlap wins in all five paired
runs. Its allocation traffic is approximately 1.56 GB versus 1.59 GB: the worker
also reuses its directory batch. Process RSS remains approximately 120 MiB.

All successful runs retain exactly 579,990 logical packets, 44,873 arrived events,
and 89,246,448 bytes of completed index files. This is warm-cache completed-index
timing, not a controlled Wireshark GUI comparison or a cold-cache guarantee.

The separate three-run complete acceptance matrix measured 3.171 seconds to
completed-ready and 3.173 seconds to the first rendered page. Export throughput
was 178 MB/s; filter result counts and exported byte counts match the previous
acceptance run. The median accounted peak memory was 62.92 MB (60.0 MiB), versus
54.22 MB previously, within the 64 MiB limit. Overlapping work keeps more transient
reservations alive simultaneously. Whole-process peak RSS for the complete
query/export exercise was 134.4 MiB median; completed-opening-only RSS was about
122.8 MiB in the final paired comparison. The acceptance matrix includes sparse,
dense and all-match queries, application filters, related packets, random reads,
and export.

## Validation and limits

The private capture differential oracle compares every normalized record,
metadata, events and calls, plus query and export behavior. It passed on the final
implementation. The affected capture, pipeline, events, analysis, protocol,
offline-storage and TUI packages passed race testing, and the complete build
passed. An isolated HEAD archive containing only the eight changed writer and test
files also passed offline race tests and an all-tag build. Focused tests cover exact serial file bytes, pool reuse under changing
memory pressure, oversized and incompressible data, amendments, metadata changes,
pending-block finalization, cancellation, write failures, and resource cleanup.
Independent agents reviewed ownership, accounting and ordering; the parent
checked their findings against the code and measurements.

A separate real-capture success sweep uses an unchanged 8 MiB maximum record
budget. Both the original and candidate reject a 48 MiB cache and complete with
52, 56, 60 and 64 MiB caches. All successful runs match counts, sidecar sizes and
final accounting. These are resource-success checks, not timing samples or a proof
of success for every possible concurrent workload. Existing hard limits remain
enforced, and overlapping buffers consume a bounded additional allowance while
active.

Phase 5 early base publication remains separate. This change reduces completed
analysis time; performance on other traffic mixes and machines still requires
measurement. In particular, early amendments or memory pressure may retire the
optional worker and leave the serial path in use for the rest of that builder.

[Sanitized measurements](watch-file-compact-writer-measurements.json) include raw
paired samples and the memory-budget sweep. The earlier
[performance investigation](watch-file-next-performance-investigation.md)
documents the rejected PGO, GC and uncompressed-storage experiments.
