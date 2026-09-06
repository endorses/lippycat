# Further offline-opening performance investigation

Investigated after `3a80772d`, retaining the same preexisting uncommitted baseline
changes. This investigation used temporary compiler overlays and binaries; it
makes no production-code or runtime-default changes.

The evidence supports further work on compact-index construction. It does not
establish a language-imposed limit, and it does not establish that the remaining
gap can be closed with compiler flags, GC tuning or a small encoder change.

## Local TShark comparison

TShark 4.6.6 is installed locally. Three sequential, interleaved fresh-process
runs used the same 323,454,505-byte input, with an untimed complete read before
each process. TShark used a fresh personal configuration directory, installed
global configuration/plugins, disabled name resolution, and ordinary packet
summary output redirected to `/dev/null`:

```sh
WIRESHARK_CONFIG_DIR=EMPTY_CONFIG_DIR tshark -n -r CAPTURE.pcap > /dev/null
```

| Whole-process measurement          | Samples, seconds    |  Median | Peak RSS median |
| ---------------------------------- | ------------------- | ------: | --------------: |
| TShark                             | 2.813, 2.601, 2.560 | 2.601 s |       664.6 MiB |
| Lippycat completed-index benchmark | 3.679, 3.684, 3.693 | 3.684 s |       116.3 MiB |

This supports the plausibility of the user's roughly three-second stopwatch
observation. It is **not a controlled Wireshark GUI opening measurement** or an
isolation of C versus Go. TShark dissects packets and prints summaries; lippycat
builds a bounded, source-backed compact dataset, query structures, normalized
events and call state. Their work and retained state differ. Whole-process
measurements include startup and shutdown; the lippycat optimization experiments
below instead report its existing internal completed-ready endpoint.

## Three-run optimization screening

All variants used the same input, default resource limits and alternating run
order. These short runs on a shared host are screening evidence. Differences of
a few hundredths of a second are not reliable wins.

| Variant                               | Completed-ready samples, seconds |  Median | Complete index |
| ------------------------------------- | -------------------------------- | ------: | -------------: |
| Current implementation                | 3.612, 3.768, 3.702              | 3.702 s |       89.25 MB |
| Single-pass row encoding              | 3.617, 3.782, 3.683              | 3.683 s |       89.25 MB |
| Profile-guided compilation            | 3.754, 3.752, 3.797              | 3.754 s |       89.25 MB |
| Compression disabled, diagnostic only | 3.307, 3.314, 3.394              | 3.314 s |      301.79 MB |

The single-pass encoder proves that a row fits its admitted slot before encoding,
retaining the existing two-pass path for larger rows. Five same-process microbench
repetitions improved ordinary rows from 516 to 325 ns and full projections from
891 to 569 ns, with zero allocations in both paths. Ten thousand randomized rows
compared original/candidate bytes and exact errors across presence flags, budgets,
capacities and prefixes; all compact tests passed under the overlay. The full-file
screening nevertheless showed no clear improvement, so this was not adopted.

PGO was trained on the same capture's final CPU profile, using
`go test -c -tags all -pgo=PROFILE`. It produced no win even on that workload and
increased opening allocations from approximately 1.59 to 1.98 GB. This does not
rule out better representative profiles, but it provides no justification for
enabling this one. The [Go PGO documentation](https://go.dev/doc/pgo) explains the
importance of representative profiles; a release profile should cover more than
one capture and command mode.

Disabling compression confirms a material cost, but increases storage more than
threefold and violates the current 100 MB target. It is a diagnostic, not a
recommended change. Its 0.388-second median improvement does not directly predict
the benefit of parallel compression: output size and I/O also changed. Every
variant completed with 579,990 logical packets and 44,873 arrived events; these
screening runs are not substitutes for the full export/metadata differential gate.

## GC trade-off

A separate three-run interleaved experiment kept the existing binary and varied
runtime settings. Higher GOGC trades collection frequency for memory; the
[Go GC guide](https://go.dev/doc/gc-guide) describes this relationship.

| Runtime settings            | Completed-ready samples, seconds |  Median | Peak RSS median |
| --------------------------- | -------------------------------- | ------: | --------------: |
| Defaults                    | 3.712, 3.563, 3.599              | 3.599 s |       119.8 MiB |
| GOGC=200, GOMEMLIMIT=256MiB | 3.660, 3.558, 3.541              | 3.558 s |       164.6 MiB |
| GOGC=400, GOMEMLIMIT=256MiB | 3.654, 3.640, 3.502              | 3.640 s |       245.0 MiB |

There is no reliable opening-time win here to justify changing defaults.
GOMEMLIMIT is a Go runtime soft limit, not a process-RSS cap. The results suggest
that GC tuning is not the strongest route to shortening this critical path.
They do not imply that Go has no runtime overhead.

## Remaining measured costs

The final CPU profile attributes 2.22 CPU seconds to the storage worker. Block
construction takes 1.15 seconds, including compression within the surrounding
flush path; compression totals about 0.78 seconds. Row encoding takes about
0.35 seconds, including a 0.11-second sizing traversal. Splitting/reparsing the
encoded rows costs about 0.18 seconds. These are nested CPU costs, not additive
wall-clock savings. Stateless reconstruction and metadata comparison cost only
about 0.06 and 0.05 CPU seconds, so removing them is a weak priority.

A fresh sampled allocation profile identifies approximately 274 MiB beneath the
application-only standard-decoder fallback, largely partial/invalid TLS records.
The fallback preserves concrete standard error layers, error text and truncation
behavior. Other large sources include TCP stream/context handling and reassembly
buffer growth. These are concrete investigation targets, not demonstrated bugs.

The most useful next writer prototype should eliminate intermediate work:
record column boundaries while encoding, or encode directly into bounded column
buffers instead of reparsing every serialized row. Exact schema and budget parity
must remain the gate. A separate compression worker is another candidate, provided
it owns admitted immutable block buffers, preserves ordered writes and directory
references, and drains before amendments, finalization and failure cleanup.
Its benefit must be measured alongside the existing analysis/storage workers.

The source, packet, directory and block hashes protect different integrity
boundaries. The approximately 0.81 CPU seconds attributed to SHA operations cannot
be treated as uniformly redundant. Reusing directory buffers would save roughly
37 MB of allocation traffic, but its direct CPU cost is only about 0.01 seconds.

## Phase 5 feasibility

The current 0.690-second normalized scan is not a publishable base dataset.
Locator records retain timestamps, lengths, link types, source/order/provenance
and authenticated byte locations. Addresses, ports and transport columns exist
transiently during decoding but are not persisted there. For multiple individually
ordered inputs, the final global heap merge also happens during replay.

A correct base-publication implementation needs to persist the base scalar fields
and finish a globally ordered random-access index before publication. It can then
expose navigation, base-field filtering/statistics, raw inspection and raw export
while ordered analysis continues. Protocol, Info and all application metadata
remain pending until the completed revision is published atomically.

The existing contracts explicitly describe finalized datasets. Revision identity
must reach tokens, cache keys, queries, detail/export pins and stale-result checks.
`PinQuery` currently requires a concrete `*diskQuery`, so adding a new Dataset
implementation alone is insufficient. The TUI lifecycle currently transfers one
final session; it needs distinct base and completed-analysis publication, with
shared backing ownership and retention of a valid base after analysis failure.

Validation must cover pending filters, exports pinned to old revisions, late
successes and errors after replacement, source mutation, and cancellation while
readers or workers retain either revision. Additional base-writing, merge,
publication and rendering time has not been measured, so no subsecond readiness
claim is justified.

For reducing **completed-analysis** time, writer/block-construction work is the
best next step. Phase 5 is a larger, separate responsiveness feature. Neither
requires a language rewrite; neither yet guarantees beating Wireshark.

## Evidence

[Sanitized raw samples and build identity](watch-file-next-performance-measurements.json)
record the screening conditions. Local artifacts are under
`/tmp/lippycat-next-performance`; the single-pass experiment is available through
`/tmp/lippycat-singlepass-overlay.json`. Private capture paths, packet output and
profile contents are omitted from repository evidence. Independent agents reviewed
the storage and phase-5 paths; the parent checked the findings against current
code, profiles and fresh measurements.
