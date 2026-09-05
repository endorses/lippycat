# Offline dataset contracts (phase 0)

These contracts are scaffolding for phases 1–5, not an installed dataset path.
`internal/pkg/offline` has no production dependency on Bubble Tea or TUI filters.
The adapter is executable now; storage, codecs and lifecycle implementation are
future work. The authoritative parity source is `types.PacketDisplay` and the
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
pagination stall with an empty page. Summary field access never performs I/O.

A Dataset exposes count/global statistics, completed Query creation, related-flow
queries, details, accounting and Close. A nil predicate is all-match; an empty
result is a valid completed query. Predicate closures must capture an immutable
snapshot (not the mutable FilterChain). Query exposes count/filtered statistics,
pages and cancellable streaming iteration for export. Match IDs and record
offsets stay on disk even for all-match queries. Statistics snapshots own their
bounded maps (initially 1,000 protocols and 10,000 entries per address counter,
matching the current UI); packet/byte totals and min/max packet sizes are exact,
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

Session transitions are Opening → Indexing → Ready, or Cancelling → Cancelled /
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

This is the codec contract for phase 2, not a claim of implemented persistence.
Use separate `summaries`, `details`, `offsets`, `matches-*` and `manifest` streams
inside a private session directory. Each data stream starts with eight bytes
`LCODATA\0`, a little-endian uint16 schema version (1), a little-endian uint16
stream kind, and a little-endian uint32 reserved zero. Reject unknown versions,
kinds and nonzero reserved fields. Kinds are summary=1, detail=2, offsets=3,
matches=4. The data header is 16 bytes.

Summary/detail frames use the 20-byte little-endian RecordHeader: uint16 version,
uint16 kind, uint64 payload length, uint64 packet ID. Validate framing and remaining
file length before allocating; check arithmetic overflow and configured maximum
record/allocation size. Payloads use explicit versioned JSON DTOs (not Go memory
layout, gob, or reflection over Summary's private packet). Unknown versions,
truncated frames, invalid lengths/IDs, and malformed payloads fail the read.

The summary DTO stores the base PacketDisplay scalars listed above plus exactly
the projected metadata fields in NewSummary, with nullable metadata objects to
preserve presence and a nullable first DNS TTL to preserve an empty answer list.
Timestamp encoding is signed Unix seconds plus uint32 nanoseconds, without a
monotonic clock. The codec reconstructs the private projection inside package
offline; it must round-trip all field accessors. Summary's private fields are
intentionally not a public JSON serialization interface.

The detail DTO stores source argument index, exact source path, source interface
ID, logical source sequence, captured/original lengths, effective link type,
timestamp and **all** finalized PacketDisplay metadata plus owned effective raw
bytes (JSON byte fields use base64). Preserve nil/empty protocol metadata and
all fields of VoIP, DNS, email, TLS and HTTP, including headers/bodies and
reassembly/decryption-derived values needed by details. Version the schema when
these representations change; phase 2 must test full round-trips. Captured and
original lengths describe the normalized effective packet, so transformed raw
bytes are not mislabeled with the source frame's link type/lengths.

After its stream header, offsets stores fixed 32-byte entries indexed by ID:
summary offset, summary framed length, detail offset, detail framed length (four
little-endian uint64 values). Match streams store ordered uint64 IDs after their
header; empty/all-match outputs cannot allocate dataset-sized slices. The completed
JSON manifest records version, generation, source identities, count, global
statistics, analysis/schema versions, final stream lengths and complete=true.
Write/flush data and offsets, then publish the completed manifest atomically;
never interpret an unfinished directory as a ready dataset. Query manifests
similarly publish count/statistics/descriptions only after match flush succeeds.
Any source, BPF, analyzer, write, flush or close error prevents successful partial
publication and is returned with context.

## Resource and ordering policy

Provisional first-release configuration defaults are 64 MiB total display cache,
4 GiB total session disk, 8 MiB maximum encoded record/allocation, and 64 open
sources. The default parent is the OS temporary directory; create a private owned
child and never clean the parent. Configuration will follow normal flag/Viper
precedence when wired in phase 2/3. Phase 0 does not expose ineffective flags.

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

Heap merge retains one logical packet per source, ordered by timestamp, source
argument index, then logical sequence. Reassembly is source/interface-local;
application/TCP analysis consumes the globally merged stream. Preserve completion
packet timestamps and effective link type after decapsulation. Equal timestamps
are valid. Each source must emit nondecreasing logical timestamps; any regression
fails the entire session with exact path, argument/interface, logical sequence,
previous/current timestamps (TimestampRegressionError). Do not warn-and-continue,
implicitly deduplicate, apply clock correction, or preferentially reorder SIP.
Reject more than the supported source limit before opening readers, with an
error advising fewer inputs or an explicitly raised, validated resource limit.
