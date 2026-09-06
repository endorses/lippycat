# Offline dataset contracts

Phase 2 implements storage, codecs, resource accounting, and complete queries in
`internal/pkg/offline`, without a production dependency on Bubble Tea or TUI
filters. Installing the dataset path and analyzer lifecycle remains phase 3. The authoritative parity source is `types.PacketDisplay` and the
existing filter constructors, including their current quirks.

## Filter inventory and parity

Field names are case-sensitive at the record interface. Unknown strings return
`""`; unknown/missing numeric values return zero. `RecordType()` is `packet`.

| Kind    | Names / aliases                                                                                                               | Source                                                     |
| ------- | ----------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| String  | `src`, `srcip`; `dst`, `dstip`                                                                                                | source/destination IP                                      |
| String  | `srcport`, `dstport`, `protocol`, `info`, `interface`                                                                         | corresponding display field                                |
| String  | `node`, `nodeid`                                                                                                              | NodeID, including literal `Local`                          |
| String  | `sip.user`, `sip.from`, `sip.to`, `sip.callid`, `sip.method`, `sip.codec`, `sip.fromtag`, `sip.totag`, `sip.imsi`, `sip.imei` | VoIP metadata                                              |
| String  | `dns.query`, `dns.name`; `dns.type`                                                                                           | query name/type                                            |
| String  | `tls.sni`, `tls.ja3`                                                                                                          | SNI / JA3 fingerprint                                      |
| String  | `http.host`, `http.path`, `http.method`                                                                                       | HTTP metadata                                              |
| Numeric | `length`, `len`                                                                                                               | display length                                             |
| Numeric | `sip.status`                                                                                                                  | SIP status, zero without VoIP metadata                     |
| Numeric | `rtp.seq`, `rtp.sequence`; `rtp.ssrc`                                                                                         | SequenceNum / SSRC, only when IsRTP; SeqNumber is not read |
| Numeric | `dns.ttl`; `dns.latency`                                                                                                      | first answer TTL only / QueryResponseTimeMs                |
| Numeric | `http.status`; `http.contentlength`                                                                                           | status code / content length                               |

Base field presence is always true, even for empty strings/zero length.
`voip`, `sip`, and `rtp` presence all mean non-nil VoIP metadata, even non-RTP.
Presence of `dns`, `tls`, `http`, `email` means non-nil corresponding metadata.
Any nonempty `sip.*`, `dns.*`, `tls.*`, `http.*` suffix reports metadata presence,
including unknown names. `rtp.*` additionally requires IsRTP. `email.*` is never
present. No timestamp, raw bytes, transport, or arbitrary headers are filter
fields today, though timestamp/transport/link type remain in the row projection
for browsing and flow matching. Email content is not searchable today.

| Filter          | Current behavior to preserve                                                                                                                                                                                                                                                                     |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Text            | Case-insensitive substring; default/all searches only src, dst, srcport, dstport, protocol, info, node. Explicit src/dst also search the corresponding port; srcip/dstip do not. Explicit generic fields use GetStringField. Empty search matches empty fields.                                  |
| Numeric         | `>`, `<`, `>=`, `<=`, `=`, `==`; equality epsilon 0.0001. Does not test presence, so missing values can match zero. Duration syntax exists in the generic constructor, principally for calls.                                                                                                    |
| Metadata        | has:voip also accepts literal SIP/RTP Protocol without metadata; other supported has types require presence. Unknown metadata types reject.                                                                                                                                                      |
| VoIP            | Requires Protocol exactly SIP. user/from prefer sip.user then sip.from; selected missing fields fall back to existing Info parser. Case-insensitive substring and existing prefix/suffix/contains wildcard rules. No correction of fallback parsing during migration.                            |
| Node            | Case-sensitive exact/prefix/suffix/middle wildcard; `*` excludes empty and Local.                                                                                                                                                                                                                |
| Interactive BPF | Field-based subset, not compiled BPF: protocol compares display Protocol, ports compare strings, host uses substring, net uses CIDR when parsed otherwise substring. Unsupported expressions match all packets. Capture BPF is separate and must fail dataset construction if compilation fails. |
| Boolean/stack   | Reuse existing parser/AND/OR/NOT behavior; stacked filters are AND, reordered by selectivity; remove-last follows insertion order. Call-state filters never match packets.                                                                                                                       |

The packet UI parser currently accepts sip filters, has, node, protocol/src/dst/
info text, BPF-shaped input and plain text, with existing case/fallback behavior.
It does **not** expose every record field or generic numeric constructor:
`length:>100` currently falls back to plain text, and `sip.status:>100` is routed
to the VoIP constructor. The dataset migration must preserve this distinction;
expanding filter syntax is a separate change.

`NewSummary` copies exactly the observable metadata into a private PacketDisplay
projection and delegates all three field accessors to PacketDisplay. Metadata
presence survives even when every value is empty. It drops payloads, maps, body
previews, and all DNS answer data except the first TTL. Later metadata changes
cannot mutate the snapshot. Tests compare all fields, missing/empty metadata,
all filter families, boolean combinations, stacking/removal, and mutation
isolation. A future PacketDisplay field addition must extend both projection
and inventory/parity cases. The summary is not a full detail record.

## Dataset, query and session ownership

Packet IDs and row counts are uint64, zero-based within one dataset generation.
Query rows refer to a completed ordered match set, never cache positions. Every
async envelope, including errors, carries dataset generation, query generation
and request ID (`Token`). Generation/request zero is reserved for synchronous
construction; model-owned requests use monotonically increasing nonzero values.
Page requests bound both rows and decoded bytes; only bounded page indices may
be converted to int. An oversized first row fails explicitly rather than making
pagination stall with an empty page. Summary field access never performs I/O. Returned pages retain a shared memory
lease until `Page.Close`; selected details use `PinDetail` and its explicit close.

A Dataset exposes count/global statistics, completed Query creation, related-flow
queries, details, accounting and Close. A nil predicate is all-match; an empty
result is a valid completed query. Predicate closures must capture an immutable
snapshot (not the mutable FilterChain). Query exposes count/filtered statistics,
pages and cancellable streaming iteration for export. Match IDs and record
offsets stay on disk even for all-match queries. Statistics snapshots own their
bounded maps (initially 1,000 protocols and 10,000 entries per address counter,
matching the current UI), plus 1 MiB of owned key bytes per map; packet/byte totals and min/max packet sizes are exact,
capped source/destination frequency and cardinality metrics are identified
separately. No page read updates statistics or reruns analysis.

Related-flow lookup initially scans summaries with bounded memory. Preserve
`store/packet_flow.go`: normalize mapped IPv4, canonicalize both endpoint
directions, reject invalid endpoints and zero ports, allow TCP/UDP and legacy
unknown transport only, infer TCP/UDP from Protocol only for unknown transport,
and match either unknown transport as a wildcard. Empty node is a wildcard;
otherwise node identity must agree. The session adapter translates local event
identity to Local. Lookup operates over the dataset independently of display
filters/cache contents. A returned related query supports pagination and export.

Session transitions are Opening → Reading → Sorting → Indexing → Ready, or
Cancelling → Cancelled /
Failed. Cancel signals promptly; workers join and clean up outside Update.
Close reports cleanup errors. Wait succeeds exactly once after analyzer EOF
flush, deferred detail metadata finalization, storage flush and completed manifest.
Wait-context cancellation alone must not leak the worker: the caller still owns
Session and must Cancel/Close. A completed dataset is transferred to the caller;
Session.Close must not delete transferred storage.

The model keeps the previous dataset, configuration, statistics and bounded
call/event histories until replacement succeeds. The TUI session adapter owns
isolated analyzer state and these histories and publishes them atomically with
the Dataset. Obsolete successes are closed. Query/export/detail reads pin their
snapshot; close waits for readers before deleting its private directory. Filter
failure/cancellation leaves the prior completed query and filter description
installed. Progress is coalesced, never an authoritative packet/event channel;
physical byte percentages appear only when measurable.

## Record and disk schema v1

Phase 2 refines the provisional JSON record proposal into the bounded binary
[storage format](offline-storage-format.md). Binary decoding validates decoded
container allocation before allocating; checksummed 32-byte frames replace the
provisional 20-byte JSON frames. The schema layout is pinned by a recursive
fingerprint test, so changing protocol metadata cannot silently change storage.

Private session directories contain separate `summaries`, `details`, `offsets`,
query match vectors and completion manifests. Summary/detail streams use the
16-byte `LCODATA` header, and offsets use kind 3 followed by fixed 32-byte
entries: summary offset/length and detail offset/length, all little-endian uint64.
The offsets stay on disk and frame reads validate stream headers, lengths,
record IDs, checksums and allocation budgets before exposing decoded records.

The completed JSON dataset manifest records schema/analysis versions,
generation, source identities, count, statistics, stream lengths and
`Complete=true`. Timestamps use seconds/nanoseconds DTOs. Data writers are
synced, closed and reopened read-only before the manifest is flushed, closed and
atomically renamed into place. This package does not reopen abandoned sessions;
only a successfully completed builder returns a dataset. Any construction error
makes the builder terminal, and its owner must close it to reclaim storage.

Query vectors use a 24-byte header: seven bytes `LCQUERY`, version byte 1,
dataset generation and query generation as little-endian uint64. Ordered uint64
match IDs follow; reads validate size, bounds and increasing IDs. A separate
streamed binary completion manifest includes token, count, complete statistics
and frozen descriptions, published by rename after flush and close. Empty and
all-match queries never allocate a dataset-sized ID slice. Closing a superseded
query removes its files; failed deletion remains charged to the dataset until
its private directory is removed.

Summary projections retain filter parity, while details preserve all finalized
metadata, nil/empty containers, effective raw bytes, timestamps and source
identity. The codec strips monotonic clock state and normalizes times to UTC.
Analysis and deferred metadata finalization remain the caller's responsibility.

## Resource and ordering policy

Provisional first-release configuration defaults are 64 MiB total display cache,
4 GiB total session disk, 8 MiB maximum encoded record/allocation, and 64 open
sources. The default parent is the OS temporary directory; create a private owned
child and never clean the parent. Configuration follows normal flag/Viper precedence. Watch exposes
`--offline-session-dir`, `--offline-max-disk-bytes`, `--offline-cache-bytes`,
`--offline-max-record-bytes`, and `--offline-max-sources`, bound respectively to
`watch.offline.session_dir`, `max_disk_bytes`, `cache_bytes`,
`max_record_bytes`, and `max_sources`. Budgets are shared across replacements;
changing them while a dataset is installed requires leaving offline mode first.

These are conservative starting limits, not measured storage amplification
claims. Baseline ordered replay of 256-byte UDP fixtures grows from roughly
45 MiB RSS at 10k packets to 195 MiB at 100k and 1.61 GiB at 1m; a fixed 64 MiB
cache forces a meaningful break from packet-count growth. The 4 GiB disk budget
allows testing the 256 MiB raw million-packet fixture with normalization overhead,
but acceptance measurements must determine whether it actually fits. Revise
these provisional defaults using phase 2 disk/cache measurements.

Disk accounting includes every stream, header, manifest, offset, query match and
unfinished file, including concurrent old/replacement datasets and exports when
written inside the session directory. Reserve bytes before writes and release
only after deletion; reject exhaustion without installing a partial result.
The cache includes disjoint cached, pinned, prefetch and in-flight decoded bytes.
Encoded buffers and decoded record allocations must also fit the allocation
budget; concurrent serializers require explicit bounded reservations. Record
limits apply before allocation, not after decoding. Refuse records that cannot
fit rather than truncating packet details. ResourceLimits.Validate rejects zero
budgets and records larger than cache/disk budgets. Cache bytes are not a process
RSS bound: reader/reassembly, analyzers, bounded event/call histories, cardinality
maps, serializers and Go runtime overhead need separate limits/measurements.

Offline watch datasets normalize each source in original record order, then sort
logical packets on disk by timestamp, source argument index and original logical
sequence before application/TCP analysis. Reassembly stays source/interface-local
and preserves completion-frame timestamps and effective link type. Backward and
equal timestamps are supported without clock correction, deduplication or SIP
prioritization. Fixed-size key runs and pairwise disk merge passes bound memory;
raw and index scratch files share the session disk budget and remain owned until
cleanup succeeds. Reading, sorting and replay are cancellable. The existing
strict heap-streaming API still rejects regressions for non-dataset callers.
Reject more than the supported source limit before opening readers.

See [ordering and navigation corrections](../plans/watch-file-ordering-and-navigation.md)
for the change superseding the initial strict-rejection policy.

## Compact migration contracts

The following is the implementation contract for phases 1–5 of the compact
source-index plan. Phase 3 implements an internally selected completed compact
dataset; the existing v1 production behavior and completed-only publication
remain unchanged until the phase-4 cutover gate. See the
[full field inventory](watch-file-packet-field-inventory.md) and
[implemented v2 wire specification](offline-storage-format.md).
The baseline environment and immutable revision/working-tree identity are recorded
in [baseline identity](../research/watch-file-phase0-baseline-identity.json).

The unshipped v2 layout was refined during implementation: finalized base and
analysis columns share typed blocks, text uses block-local arenas, and a
checksummed fixed-width row directory supports direct lookup and replacement
rows. Bounded label/context registries live in the completion manifest. This
preserves exact projections and source provenance without a dataset-sized arena
map. The storage specification documents the actual fields and integrity checks.

The injected decoder reconstructs DNS, HTTP and TLS packet-local metadata from
owned effective bytes and the finalized projection. Whole-protocol overrides
retain results that differ from that reconstruction, including VoIP and email
metadata. SIP amendments replace sparse protocol metadata and a compact row;
they never rewrite effective packet bytes or full presentation records. TLS
plaintext remains in the separately bounded, stopped session analyzer (16 MiB
session plaintext limit), as in the oracle; it is not copied into the index.
Queries and raw export preserve their completed-generation ownership, with raw
export bypassing the decoder. No progressive readiness or persistent reuse is
introduced by phase 3.

### Predeclared regression tolerances

Declared 2026-09-06, before evaluating the new acceptance-matrix measurements.
Compare the same fixture, configuration, budget, host, operation and cache
condition, using at least three unprofiled fresh processes per condition. Report
all samples and median; for random operations report within-run p95 as well.
Profiles are separate runs. Do not change these tolerances to fit observations.

| Metric                                                                     | Regression gate                                                                                              |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| Logical records, fields/presence, bytes, filters, statistics, events/calls | Exact equality, zero tolerance; bounded history policy compared separately                                   |
| First/repeated base/application filters and related lookup                 | Each median and p95 <= baseline × 1.10 + 1 ms                                                                |
| Random pages/details, first useful rendered page                           | Each median and p95 <= baseline × 1.10 + 1 ms                                                                |
| Export throughput (effective bytes/second)                                 | >= 90% of baseline, exact records/order                                                                      |
| Full completed readiness                                                   | Median <= baseline × 1.10; engineering target <= 3.0 s independently                                         |
| Peak RSS and cumulative allocations                                        | Each <= baseline × 1.10; configured accounted limits remain hard                                             |
| Completed storage                                                          | Engineering target < 100,000,000 decimal bytes on reported capture, including every owned completed artifact |
| Temporary/query/combined peak disk and retained memory                     | Report every component and peak; never exceed configured accounting limits                                   |
| Cold/repeat opens, base readiness                                          | Same 10% + 1 ms rule only with equivalent measured endpoints; missing baseline is unverified, not zero       |

A missed timing/storage target requires a measured explanation and a recorded
acceptance decision; correctness, explicit budget or ownership failures block
cutover. Warm filesystem means an untimed full input read before each process,
not reuse of an in-process Dataset. OS-cold runs require recorded eviction or a
fresh controlled environment; otherwise label them unavailable. Record filesystem,
storage medium, CPU/load/affinity, Go/build tags, capture SHA-256/size, limits,
frozen flags/Viper values (without secrets), analyzer/history settings and process
start/stop boundaries. Keep the original production benchmark reproduction command
in the performance investigation unchanged. First worker page is not first render.
The Phase-0 first-render endpoint materializes the page and renders the actual
packet pane with `PacketList.View` at 120×40. It includes pane construction and
layout; full model rendering, event-loop delivery and terminal I/O are unverified.
Compare this same endpoint across backends until a full-UI measurement is added.
For single-operation endpoints, median and nearest-rank p95 are calculated across
fresh processes (with only three samples p95 is the maximum, not a population
estimate). Random page/detail p95 additionally uses 32 observations within each
process. Disk high-water samples are explicitly lower bounds; they cannot certify
an exact peak-disk gate without ledger high-water instrumentation at cutover.
Three-process medians are an engineering comparison, not statistical confidence.

### Explicit backing policy and source errors

Phase 1 will add `--offline-backing-policy` bound to
`watch.offline.backing_policy`, with exactly `source` and `snapshot`; default
`source`. This policy takes effect only when the compact path is enabled after
its gate, not in Phase 0. Snapshot is the explicit option for independence from
later source edits; no implicit fallback or automatic copy after a source error.
Use ordinary flag/Viper precedence and pass the validated value through watch
configuration, the frozen offline session config and backend source construction.
Validate before opening input. Freeze per session; replacement sessions can use
a different policy but share the same model-wide resource budget. Display/report
the chosen policy; never persist TLS secrets in manifest/config output.

For `source`, the Dataset owns the initially opened handle. A read lease keeps it
open through validation and ReadAt; never reopen the argument path. Before every
lease read validate owned-handle identity, size and modification metadata,
then bound the read, read into owned memory, verify its recorded SHA-256, and
repeat the metadata check before exposing bytes. Size/modification-time changes fail even if
the particular packet digest is unchanged. Change time is recorded for diagnostics
but cannot alone invalidate an owned source: rename/unlink can change it. Per-read
digests still detect changed referenced bytes if modification time is restored. A same-size mutation is detected by
the digest when referenced bytes are read; unchanged unrelated bytes do not prove
whole-file immutability. This is detection on accessed data, not an OS lock or
continuous watcher. Hash the full original source during construction and require
stable pre/post-scan metadata; reject inconsistent scans. Concurrent hostile
writes with restored metadata are outside the immutable-source guarantee.

On supported platforms rename/unlink/replacement of a path preserves access to
the owned old file; path metadata is not used to switch identities. In-place
truncation, changes to the owned file or short reads return a typed source-change
error with source argument index, source/backing IDs, operation, reason
(`identity`, `size`, `metadata`, `digest`, `short_read`) and wrapped underlying
I/O error when present. The Phase-1 implementation should expose a stable
`ErrSourceChanged` sentinel and errors.Is support. Error output includes the
original display path but no captured content or secrets. An invalid locator or
corrupt private index is a distinct corruption error, not silently a source change.

A failed detail/page request publishes no partial bytes; a failed query leaves
the previous query installed. Export reports failure and follows existing output
cleanup rules, never claims success with mixed content. Source failure prevents
new source reads from succeeding under the invalid dataset; previously returned
owned/pinned bytes remain valid until release. Opening a replacement is an
explicit new session, with a new generation and independent identity.

For `snapshot`, create a private owned copy/reflink before indexing. Open the
source once; capture its identity/size/times before and after copying, hash bytes
while copying, then independently hash/validate the snapshot and require equal
sizes/digests and stable source metadata. A reflink is acceptable only with
copy-on-write snapshot semantics and the same validation. Charge its full logical
size even if physical extents are shared. Never index a partially copied snapshot.
Cancellation, space exhaustion, write/flush/sync/hash/close errors poison the
attempt; remove incomplete copies, preserve cleanup errors and retry ownership,
and release disk reservations only after deletion succeeds. Copies live inside
the same private session lifetime as the index.

For gzip classic PCAP, identity always hashes the original compressed bytes.
Validate gzip completion/checksum and use one seekable owned decompressed spool;
locators reference decompressed offsets, not compressed offsets. `snapshot`
charges the compressed copy plus decompressed spool while both exist. Source
identity refers to the compressed input even when source-policy detail reads use
an owned decompressed spool. Future source mutation cannot alter an already
validated owned spool. Do not add gzip PCAPNG or extra PCAPNG section/interface
support under this policy. All handles/backings transfer ownership before cursor
EOF closes inputs. Dataset Close cancels/joins workers and waits for read leases,
detail/query/export pins, then closes files and removes owned storage; failed
close/deletion remains owned and retryable. Source files are never deleted.

### Complete resource ledger

Keep the existing defaults (64 MiB cache/read allocation, 4 GiB session disk,
8 MiB record, 64 open sources). A model-wide ledger covers the old installed
session, replacement under construction, stale completed results awaiting cleanup
and pinned exports. A limit applies to their sum, not separately per Dataset.

| Allocation/storage                          | Memory charge                                                                              | Disk charge and release                                                                                       |
| ------------------------------------------- | ------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| Typed block buffers, descriptors, checksums | Full retained capacities plus simultaneous encode/decode scratch                           | Reserve encoded bytes at admission, before buffering; flushing transfers ownership without double charging    |
| Text/metadata arenas and dictionaries       | Capacity, owned strings, entries/map overhead; enforce cap and spill/stop                  | Arena blocks, spilled text and directory bytes; include abandoned amendments                                  |
| Source/context/backing registries           | Bounded tables/handles, read-lease bookkeeping                                             | Manifest/registry bytes; source bytes excluded only for external source backing                               |
| Ordering and merge                          | Sort-key capacity, heap, run buffers, decoder scratch                                      | All run files/order maps and merge output simultaneously until old runs removed                               |
| Prefetch/coalescing                         | Full queued/in-flight buffers, not just consumed slices                                    | None unless explicitly spilled                                                                                |
| Derived/decompressed/snapshot bytes         | Write buffers, decompressor workspace and read buffers                                     | Full logical owned bytes, including copy/spool coexistence and failed cleanup                                 |
| Query construction and pages                | Predicate/materialization scratch, result buffers, complete statistics maps, page leases   | Match files, rank indexes if introduced, query manifests, old active/pinned queries                           |
| Details and exports                         | Decoded object graph plus owned raw bytes, pins, TLS plaintext references, in-flight reads | Retained dataset/overlay files while pinned; destination export file remains external and separately reported |
| Replacement sessions                        | All preceding charges for every retained generation/revision                               | All preceding owned files until successful cleanup                                                            |

Reserve before allocation, buffer admission or I/O. Checked addition,
multiplication, offset/length, row/count-to-int and reference bounds must precede
allocation/seek/read/write; compare both encoded and conservative decoded sizes.
An oversized first row/detail fails explicitly, never returns an empty page that
cannot advance. Reuse reservations when transferring buffers, but charge both
copies while they coexist. Release memory only after last lease/pin; release disk
only after successful removal. Flush/close errors cannot make bytes disappear
from the ledger or allow a completion manifest. No dataset-sized heap ID/offset
slice or high-cardinality intern map is allowed.

Retained cache is a logical budget, not a hard RSS cap: Go runtime/allocator,
loaded binary and analyzer/reassembly state need separate measured RSS/allocation
reporting and existing analyzer limits. Report analyzer overhead explicitly;
never call unaccounted analysis memory “bounded cache.” TLS plaintext, event/call
histories and statistics use their existing independent caps, are reported in
retained totals, and any newly persisted copies are charged to disk as well.
For benchmarks report completed index+metadata+sidecars+manifests, live query disk,
sort/copy/spool temporary peak and combined peak, avoiding double-counting an
artifact when it moves from temporary to completed ownership.
