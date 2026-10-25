# Offline dataset contracts

The completed `watch file` dataset uses storage, codecs, resource accounting,
and complete queries in `internal/pkg/offline`, without a dependency on Bubble Tea
or TUI filters. The authoritative parity source is `types.PacketDisplay` and the
existing filter constructors, including their current quirks.

## Filter inventory and parity

The accessor rules below apply to completed analysis. A base revision cannot
answer analysis-dependent filters with these missing-value defaults; query
readiness is checked first. Field names are case-sensitive at the record interface. Unknown strings return
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
Complete ordered base revision 0 and completed-analysis revision 1 preserve the
same PacketIDs and order. A published revision is immutable; metadata is never
amended in place after publication. `Dataset.Revision()` identifies the view.
Query rows refer to a completed ordered match set, never cache positions. Every
async envelope, including errors, carries dataset generation, exact analysis
revision, query generation and request ID (`Token`). Revision zero means base;
it is never a wildcard for the current revision. A base token cannot read a
completed dataset, including via a pin. Generation/request zero is reserved for synchronous
construction; model-owned requests use monotonically increasing nonzero values.
Page requests bound both rows and decoded bytes; only bounded page indices may
be converted to int. An oversized first row fails explicitly rather than making
pagination stall with an empty page. Summary field access never performs I/O. Returned pages retain a shared memory
lease until `Page.Close`; selected details use `PinDetail` and its explicit close.

A Dataset exposes count/global statistics, completed Query creation, related-flow
queries, details, accounting and Close. With no expression, a nil predicate is all-match; an empty
result is a valid completed query. Predicate closures must capture an immutable
snapshot (not the mutable FilterChain). Query exposes count/filtered statistics,
pages and cancellable streaming iteration for export. Filtered match IDs and record offsets stay on disk; all-match queries use
implicit IDs without a per-packet vector. Statistics snapshots own their
bounded maps (initially 1,000 protocols and 10,000 entries per address counter,
matching the current UI), plus 1 MiB of owned key bytes per map; packet/byte totals and min/max packet sizes are exact,
capped source/destination frequency and cardinality metrics are identified
separately. No page read updates statistics or reruns analysis.
`Query.Position` locates a stable PacketID by bounded lookup in ordered query IDs
without a dataset-sized map, preserving selection across revision publication.

Base queries admit only expressions proved to use B-ready fields from the
[field inventory](watch-file-packet-field-inventory.md). Protocol, Info, generic
text, application metadata/presence and opaque predicates return typed
`ErrAnalysisPending` before scanning or creating query files. Base counts, bytes,
sizes, endpoints, network details and raw export are available. Protocol
statistics, Events, Calls and decrypted results remain pending until completed
analysis. Pending is distinct from an absent value.

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

The model keeps the previous dataset until a complete new ordered base succeeds.
The TUI progressive adapter then installs that base and continues bounded ordered
analysis without a modal dialog. It publishes finalized packets, statistics,
complete Events and bounded Calls together as one immutable completed snapshot.
Analysis failure or cancellation retains the valid base with explicit status;
reopening is the retry path. Failed candidate resources remain owned for cleanup
retry. No provisional scan-time packet IDs are exposed.

One session lifecycle owns the base, completed snapshot, normalized source
handles, ordered replay and workers. Obsolete/abandoned successes are closed.
Query/export/detail reads pin their original immutable revision; publication
retires only view work, preserving already pinned exports. Whole-session cleanup
cancels analysis/exports/read work before joining query owners and closes backing
handles only after readers join. Shared backing leases survive retirement of the
base metadata directory. Filter
failure/cancellation leaves the prior completed query and filter description
installed. Progress is coalesced, never an authoritative packet/event channel;
physical byte percentages appear only when measurable.

## Record and query schemas

Phase 2 refines the provisional JSON record proposal into the bounded binary
[storage format](offline-storage-format.md). Binary decoding validates decoded
container allocation before allocating; checksummed 32-byte frames replace the
provisional 20-byte JSON frames. The schema layout is pinned by a recursive
fingerprint test, so changing protocol metadata cannot silently change storage.

Oracle schema 7 private session directories contain separate `summaries`, `details`, `offsets`,
query match vectors and completion manifests. Summary/detail streams use the
16-byte `LCODATA` header, and offsets use kind 3 followed by fixed 32-byte
entries: summary offset/length and detail offset/length, all little-endian uint64.
The offsets stay on disk and frame reads validate stream headers, lengths,
record IDs, checksums and allocation budgets before exposing decoded records.

The completed JSON dataset manifest records schema/analysis versions,
generation, revision, source identities, count, statistics, stream lengths and
`Complete=true`. Timestamps use seconds/nanoseconds DTOs. Data writers are
synced, closed and reopened read-only before the manifest is flushed, closed and
atomically renamed into place. This package does not reopen abandoned sessions;
only a successfully completed builder returns a dataset. Any construction error
makes the builder terminal, and its owner must close it to reclaim storage.

Packet query vectors use a 32-byte header: seven bytes `LCQUERY`, version byte 2,
dataset generation, query generation and exact analysis revision as little-endian uint64. Ordered uint64
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

See the
[ordering and navigation correction](../plans/watch-file-scalable-offline-dataset.md#ordering-and-navigation-correction)
for the change superseding the initial strict-rejection policy.

## Compact source index contracts

The compact source index is the production backend for `watch file`.
Oracle schema 7 remains a differential test backend. Milestone B publishes a
complete immutable base before ordered analysis and a separate completed revision
after finalized metadata. See the
[full field inventory](watch-file-packet-field-inventory.md) and
[implemented v2 wire specification](offline-storage-format.md).
The baseline environment and revision/working-tree identity are recorded in the
[Phase 0 baseline](../research/watch-file-phase0-baseline.md#baseline-identity-and-environment).

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
export bypassing the decoder. Milestone B shares validated source backings across
the two independent metadata revisions; persistent reuse remains deferred.

### Correctness, resource limits and readiness observations

Acceptance preserves exact logical record identity/order, fields and presence,
effective bytes, filters, statistics and output semantics. Compare the bounded
Calls/compatibility history policy separately from complete packet and event
storage. Configured disk/cache/record/source limits, source integrity, ownership,
authorization and cleanup remain correctness requirements.

Earlier plan-selected timing, throughput, storage and RSS comparison targets have
no independent acceptance authority. They are exploratory references, not gates;
a benchmark miss does not require a waiver, redesign, optimization cycle or
another audit. Milestone B records complete-base readiness, first useful page and
completed-analysis time separately, without a numerical cutoff. Keep optional
persistent cache/reuse and further parallelization outside this milestone.

For reproducible observations, record fixture generation or capture hash/size,
Go/build tags, relevant configuration and resource limits, operation boundaries,
and host/storage context. Distinguish warm filesystem from in-process cache reuse;
label OS-cold and private-fixture evidence unavailable when it was not measured.
Compare equivalent operations: the existing first-render harness materializes a
worker page and renders PacketList at 120×40, excluding terminal I/O. Describe
samples and accounting components honestly rather than claiming a process RSS
bound from the display cache. The historical benchmark reproduction commands and
recorded measurements remain available in the linked research documents.

### Explicit backing policy and source errors

`--offline-backing-policy` binds to `watch.offline.backing_policy`, with exactly
`source` and `snapshot`; default `source`. This policy applies to every production
file open. Snapshot is the explicit option for independence from
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
I/O error when present. The implementation exposes the stable
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

### Complete offline metadata events

Offline Events has a complete disk-backed projection in addition to the bounded
compatibility event store. Every metadata event admitted by analysis is persisted
before it reaches that retained store. File bodies remain excluded. Arrival row
IDs start at one and are independent of delivery event IDs: repeated IDs and
amended snapshots remain separate immutable rows in admission order. Preserve
the original typed identity, provenance, and sensitive-field policy.

Packet and event datasets publish together after analysis finalizes. Any event
write, allocation, quota, or finalization error fails the open; cancellation and
cleanup failure retain explicit ownership rather than publishing an incomplete
history. Events use the shared disk and cache ledgers, versioned checksummed
frames, disk offsets and query vectors, and bounded borrowed page/detail leases.

The offline Events view loads only a bounded viewport and selected detail. Its
filters scan the complete event dataset asynchronously; successful row sets and
descriptions install together. Cancelled, failed, and stale results preserve the
last installed query. Total, matching, and cached counts are distinct. Flow
navigation uses complete bounded queries, while packet export retains its packet
query semantics. Join query/read owners before event storage closes, and retry
failed cleanup without discarding the owner. Live/remote Events and Calls retain
their separate bounded-history semantics.

### Completed block queries (phase 4)

The TUI compiles constructed, immutable packet filters into validated expressions
in `offline/filterexpr`. The backend never imports TUI packages. Boolean and stack
semantics, aliases, numeric epsilon, metadata presence, text matching and the
accepted BPF subset remain those of the existing filter constructors. Unknown
custom filter implementations and accepted filters exceeding the structured
expression's representation limits use the opaque `QuerySpec.Match` fallback.
Other expression compilation errors remain errors; fallback does not relax the
backend's record, query or storage budgets.

Queries scan the authenticated row directory in logical order and reuse expanded
blocks. Compression and checksums require reading a whole block, but supported
expressions decode only their needed columns/arena values plus the fields needed
for complete match statistics. Opaque callbacks receive the full bounded Summary
projection. Summary accessors perform no I/O. Amendments follow the authoritative
directory, preserving finalized EOF metadata.

Match IDs use bounded buffered ordered uint64 vectors, charged on admission.
All-match results use implicit IDs. Dense bitsets and lazy related-flow postings
remain deferred pending measured benefit. Related matching is bidirectional,
normalizes mapped IPv4, preserves absent-node/unknown-transport wildcards, and
rejects invalid endpoints and zero ports. Query publication remains atomic with
complete statistics; failure or cancellation preserves the prior installed query.
Pinned exports retain their completed query and dataset across replacement.

`Storage.Peaks` reports exact monotonic admitted disk and cache/read memory peaks,
including coexistence across queries and replacement sessions. These are ledger
limits, not process RSS or analyzer-memory measurements. The phase-4 validation
report records the measured acceptance matrix and remaining engineering target gap.

Small-cache operation keeps the same hard limits. Below 16 MiB, compact builders
release completed decoder scratch before flushing and use smaller pending blocks;
uncompressed readers do not reserve an unused inflater. Locator replay scales
optional read-ahead to the shared cache budget, leaving room for the consumer.
The 128 KiB cache / 16 KiB record reference fixture still indexes, queries,
materializes details and exports without increasing its budgets.
