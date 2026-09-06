# Offline temporary storage formats

## Schema 1: completed production backend and legacy oracle

Phase 2 replaces the provisional JSON payload and 20-byte frame from the initial
contract with the binary format below. Standard JSON unmarshalling does not enforce decoded
container allocation limits before allocation. The binary decoder checks every
string, array and map length against both remaining payload and a decoded memory
budget before allocating. A preflight traversal bounds serialization before its
payload buffer is allocated. Reflection is only an implementation mechanism over
fixed typed schema records; it does not encode Go memory layouts or pointers.

All integers are little endian. Each stream starts with a 16-byte header:

| Byte offset | Width | Value                             |
| ----------- | ----- | --------------------------------- |
| 0           | 8     | `LCODATA` followed by a zero byte |
| 8           | 2     | Schema version, currently 1       |
| 10          | 2     | Stream kind                       |
| 12          | 4     | Reserved, must be zero            |

Summary records use kind 1 and detail records kind 2. Each record starts with:

| Byte offset | Width | Value                   |
| ----------- | ----- | ----------------------- |
| 0           | 4     | `LCOF`                  |
| 4           | 2     | Schema version          |
| 6           | 2     | Record kind             |
| 8           | 8     | Payload length          |
| 16          | 8     | Dataset-local packet ID |
| 24          | 4     | IEEE CRC32 of payload   |
| 28          | 4     | Reserved, must be zero  |

Header identities, offset overflow, length bounds, checksum, all scalar ranges,
reserved bytes and exact payload consumption are validated on reads. CRC32
provides accidental corruption detection, not authentication. These private
session files are temporary artifacts, not an interchange or reuse format.

Payload structs serialize fields in declaration order. A summary stores the
`PacketDisplay` filter projection; a detail stores `SourcePosition`, captured and
original uint32 lengths, and the complete finalized `PacketDisplay`. Tokens and
packet IDs are not repeated inside the payload. The frame supplies the ID;
request handling supplies the token. Effective link type, raw bytes and all
protocol metadata are preserved independently of the original source framing,
including IP reassembly and decapsulation results.

Before publication, analyzer finalization may append replacement summary/detail
frames for an existing packet ID and rewrite that packet's fixed-width offset
entry. Readers always follow the offset table, so superseded frames do not
contribute packets, query matches, or statistics. All appended frames remain
charged to the session disk budget until cleanup. Amendment errors prevent
publication; final statistics are rebuilt from the updated offsets before the
completion manifest is written.

Every integer and float64 occupies eight bytes; signed integers use two's
complement and floats use IEEE 754 bits. Narrow destination integers are range
checked. Booleans occupy one byte (0 or 1). Pointers begin with one byte (0 for
nil, 1 followed by the pointed value). Strings have an eight-byte byte length
followed by their exact bytes. Slices and maps begin with an eight-byte element
count; all-one bits denotes nil and zero denotes a non-nil empty container.
Byte slices store bytes directly; other slices store consecutive encoded values.
Maps store consecutive key/value pairs and reject duplicate keys; map iteration
order is not significant. Structs have no extra delimiters. Timestamps are an
int64 Unix seconds value followed by uint64 nanoseconds (less than 1 billion),
normalized to UTC on decode. Monotonic clock readings and display time zones are
not persisted. This retains precision beyond UnixNano's range and supports the
zero time and timestamps outside JSON's four-digit year restriction.

`TestCodecSchemaV1Shape` pins a SHA-256 fingerprint of both wire structures and
all recursively included protocol metadata field names, types and order. Any
metadata field addition or layout change fails the test and requires an explicit
schema-version decision. `TestCodecAllMetadataRoundTrip` fills every supported
field recursively, so newly supported metadata cannot silently disappear.

The record limit bounds both encoded payload and conservatively measured decoded
objects. Decoded accounting includes the root object, pointed objects, backing
arrays, string bytes, a 512-byte base allowance per non-nil map, and 128 bytes
per map entry in addition to map strings.
Runtime allocator and reflection overhead are separate from this logical budget;
the cache is not a hard RSS limit. Storage must reserve serialization and read
working space under its shared cache policy before invoking the codec, in addition
to accounting for retained and pinned records. Oversized records fail explicitly.

## Schema 2: compact completed dataset migration backend

Phase 3 implements the compact backend behind the internal `NewCompactBuilder`
and TUI migration entry points. The production path still uses schema 1 until
phase 4 passes its cutover gate. Both schemas publish only completed datasets.
There is no persisted-session opener, cross-process reuse, or partial-analysis
publication. Schema 1 is never interpreted as schema 2.

This implementation refines the **unshipped phase-0 layout proposal**. Base and
analysis columns share completed row blocks; text and compound values use
block-local arenas; a checksummed 64-byte entry per packet provides direct row
lookup; bounded source, label and context registries are recorded in the manifest.
The proposed separate base/analysis/text/registry streams and 72-byte global
block-directory entries were not implemented. Combining finalized columns keeps
row navigation and metadata amendments within the existing completed-dataset
lifecycle. Block-local references avoid a dataset-sized arena index, while the
row directory permits replacement blocks without copying unchanged packet bytes.
A future revision-aware overlay or persistent cache requires an explicit format
and API change rather than assuming the earlier proposal exists on disk.

The implementation is defined by `internal/pkg/offline/compact.go`,
`compact_block.go`, `compact_value.go`, `compact_labels.go`,
`compact_manifest.go` and the compact branches of `storage.go`.

### Files and headers

Each of the three indexed files begins with this 32-byte little-endian header:

| Offset | Width | Value              |
| ------ | ----- | ------------------ |
| 0      | 8     | `LCOV2DAT`         |
| 8      | 2     | Schema major: 2    |
| 10     | 2     | Schema minor: 1    |
| 12     | 2     | Stream kind        |
| 14     | 2     | Flags: zero        |
| 16     | 8     | Dataset generation |
| 24     | 8     | Reserved: zero     |

The filenames and stream kinds are `summaries` = 1 (combined completed row
columns), `details` = 2 (sparse protocol overrides), and `offsets` = 3 (direct row
directory). Block kinds are separate: row blocks use kind 1, and protocol-override
blocks inside the `details` stream use kind 4. There are no typed stream kinds
4–11 in this implementation. Original sources and owned snapshot, decompressed
or derived backings remain backing-registry files, outside these typed streams.
Ordering keys and query vectors retain their existing independent formats.

Typed blocks begin with 72 bytes:

| Offset | Width | Value                        |
| ------ | ----- | ---------------------------- |
| 0      | 4     | `LCB2`                       |
| 4      | 2     | Block kind: 1 or 4           |
| 6      | 2     | Header size: 72              |
| 8      | 8     | First packet ID              |
| 16     | 4     | Row count                    |
| 20     | 2     | Column count                 |
| 22     | 2     | Encoding: 0 raw, 1 DEFLATE   |
| 24     | 8     | Expanded payload byte length |
| 32     | 8     | Analysis revision: 1         |
| 40     | 32    | SHA-256 of expanded payload  |

Packet IDs are zero-based and implicit within a block as first ID plus row
position. The writer buffers at most 128 rows and closes a block earlier when
byte admission would exceed `MaxRecordBytes`. Readers reject more than 4096 rows.
Metadata replacement blocks currently contain one row. Both encoded payload and
decoded allocations must fit configured limits; an oversized first row fails
explicitly. Buffered rows and eventual disk bytes are charged before admission.

Schema 2.1 adds optional independent DEFLATE blocks. Readers reject other stream
minor versions and unknown encoding flags. The directory stores physical block
lengths; the header stores the exact expanded length, bounded before allocation.
The reader rejects truncated streams, excess expansion and trailing compressed
bytes, then checks the expanded payload checksum and all column/arena bounds.
Cached blocks retain expanded bytes and bind their original physical size.

Writers use a reused BestSpeed compressor for blocks of at least 4096 bytes when
the configured cache budget is at least 16 MiB; blocks that do not shrink retain
raw encoding. Compressor state is charged at 2 MiB; reader inflater scratch at
256 KiB. Reusable payload/output buffers are admitted before growth and released
at completion or cleanup. Compression never changes the row codec or projections.

### Columns and block-local arenas

The payload begins with one 24-byte descriptor per column, in field-ID order:
field ID u16, wire type u8, flags u8 (zero), count u32, payload-relative offset u64,
byte length u64. Types are u8=1, u16=2, u32=3, u64=4, i64=5, f64=6,
reference=7, fixed32=8. Descriptor counts equal the block row count. Fixed columns
contain consecutive values; reference columns contain one 16-byte reference per
row. Columns are contiguous in descriptor order, followed by the arena.

A reference contains `(block u32, offset u32, length u32, flags u32)`. The block
word must be zero and flags must be 1: references always select a present encoded
value in the same block. Offsets are relative to the entire block payload.
Arena values are contiguous in column order, then row order. Nil or absent
protocol values are represented **inside the value codec**, not with absent arena
references. Even an empty string has a four-byte encoded length in its referenced
value. References cannot overlap, skip bytes, escape the payload or leave trailing
arena data.

The row block has these exact field IDs. `ref` denotes the block-local reference
above; names correspond to the explicit schema table rather than Go declaration
order.

| ID  | Field                      | Wire type |
| --- | -------------------------- | --------- |
| 1   | Metadata block offset      | u64       |
| 2   | Metadata block total bytes | u64       |
| 3   | Argument                   | u32       |
| 4   | Interface                  | u32       |
| 5   | Sequence                   | u64       |
| 6   | Locator                    | ref       |
| 7   | Context                    | ref       |
| 8   | PhysicalOrdinal            | u64       |
| 9   | OriginalCaptured           | u32       |
| 10  | OriginalWire               | u32       |
| 11  | OriginalLink               | u32       |
| 12  | Derived                    | u8        |
| 13  | Captured                   | u32       |
| 14  | Original                   | u32       |
| 15  | Timestamp                  | ref       |
| 16  | SrcIP                      | ref       |
| 17  | DstIP                      | ref       |
| 18  | SrcPort                    | ref       |
| 19  | DstPort                    | ref       |
| 20  | Protocol                   | ref       |
| 21  | Info                       | ref       |
| 22  | Node                       | ref       |
| 23  | Device                     | ref       |
| 24  | Transport                  | u8        |
| 25  | Length                     | i64       |
| 26  | LinkType                   | u8        |
| 27  | Projection                 | ref       |
| 28  | NodeRef                    | u32       |
| 29  | DeviceRef                  | u32       |
| 30  | ContextRef                 | u32       |

`Argument` indexes the exact ordered source list, including repeated arguments.
`Sequence` is the per-argument normalized logical sequence; `PhysicalOrdinal`
counts original frames. `Interface` preserves source/reassembly attribution.
`Captured`, `Original`, `Timestamp` and `LinkType` are effective export metadata;
`Length` independently retains the display length. Address and port strings,
Protocol and Info are exact presentation/search values, preserving empty ports
versus the string `0` and all existing accessor quirks.

`Locator` encodes BackingID u32, Offset i64, Length u32 and Digest fixed32, in that
order. Backing IDs start at one. Offsets refer to the originally owned handle or
owned derived backing, never a replacement path. Original parser context encodes
Format u8, ByteOrder u8, SectionID u32, InterfaceID u32, LinkType u32, Snaplen u32,
TimestampResolutionBase u8, TimestampResolutionExponent u8, TimestampOffset i64
and TimestampMissing u8. Source framing validation and supported-format limits
remain the capture reader's responsibility. Derived provenance does not grant
permission to reopen a source pathname.

### Direct row directory and integrity

`offsets` contains exactly one 64-byte entry per packet after its stream header.
Entry position is `32 + packetID * 64`, with checked arithmetic. The entry holds
row-block offset u64, row-block total bytes u64, metadata-block offset u64,
metadata-block total bytes u64, then SHA-256 of packet ID (u64), those first 32
bytes, the referenced 72-byte row-block header, and the 72-byte metadata-block
header (all zeros when absent). Including the packet ID and headers prevents a
changed header or swapped directory row from reinterpreting otherwise valid
payload bytes. The metadata
pair is `(0, 0)` when no override is needed. The row block's first two columns
must agree with the directory's metadata pair.

A lookup validates directory checksum, block offset/size, kind, version, packet
ID range, revision, payload checksum, descriptor identities/types/counts, reserved
bits, column boundaries and exact arena consumption. Value decoding additionally
checks lengths, scalar ranges, duplicate map keys and allocation limits before
returning an owned result. Metadata blocks are read only when details need them;
summary and raw iteration do not decode protocol overrides. Raw reads validate
the effective source bytes with the backing registry, including source-change
checks and the per-record SHA-256 digest.

Block-cache keys use dataset identity, block offset and block kind; cached blocks
remain immutable. Full column/arena and checksum validation occurs before cache
admission; hits select the requested row from that validated encoding. Cached
encodings, read/decode scratch, owned rows/details,
page leases and detail pins share the storage memory budget. Query pins retain
the completed query and dataset locks before asynchronous exports are scheduled.
Raw callbacks receive one effective record at a time and do not invoke the
stateless detail decoder.

These hashes detect corruption, not authentication against an actor able to
rewrite the private index and its checksums. The completed manifest also records
full-stream digests, but no persisted-session reader currently consumes them to
reopen or authenticate a cached dataset.

### Value codec, searchable projection and overrides

`compactFieldNames` explicitly freezes struct field order, independent of Go
field declaration order. Integers use their declared widths; Go `int` is signed
64-bit on the wire. Float64 uses IEEE 754 bits. Booleans are one byte (0 or 1).
Pointers use one presence byte, followed by the value when present. Strings use
a u32 byte length and exact bytes. Slices and maps use a presence byte and,
when present, a u32 count; nil differs from non-nil empty. Byte slices contain
raw bytes, other slices contain encoded elements, and string maps are serialized
in sorted key order. Duplicate decoded keys are errors. Fixed arrays contain
consecutive elements. Timestamps use i64 Unix seconds and u32 nanoseconds below
one billion, normalized to UTC, without monotonic state.

`Projection` begins with a u8 presence mask: VoIP/DNS/Email/TLS/HTTP use bits
0–4; other bits are rejected. Only the groups selected by those bits follow, in
this exact order:

| Group | Encoded fields, in order                                                                                                     |
| ----- | ---------------------------------------------------------------------------------------------------------------------------- |
| VoIP  | User, From, To, CallID, Method, Codec, FromTag, ToTag, IMSI, IMEI (strings); Status i64; IsRTP u8; SequenceNum u16; SSRC u32 |
| DNS   | QueryName, QueryType (strings); QueryResponseTimeMs i64; AnswerPresent u8; TTL u32                                           |
| Email | Presence only; no projection payload                                                                                         |
| TLS   | SNI, JA3 (strings)                                                                                                           |
| HTTP  | Host, Path, HTTPMethod (strings); StatusCode i64; ContentLength i64                                                          |

No protocols therefore encode as a single zero byte. Metadata present with empty
contents remains distinguishable from metadata absent. `Summary` materialization
restores this exact projection and its accessors perform no further I/O.

A kind-4 metadata block has field 1 `Mask` (u8) and field 2 `Metadata` (ref).
`Metadata` is the explicit typed sequence of VoIP, DNS, Email, TLS and HTTP
pointers, including each protocol's full supported fields in `compactFieldNames`.
The mask uses the same five protocol bits. A set bit replaces the **entire
protocol metadata pointer** after stateless decoding, including an explicit nil
or empty value. This is a protocol-level override, not the per-field override
bitmap proposed in phase 0. Unset bits leave decoded metadata unchanged.

During append, the builder compares finalized protocol metadata with the injected
stateless decoder's result and writes only differing protocol pointers. A zero
mask writes no metadata block. On a detail read, the decoder reconstructs
packet-local fields from owned effective bytes and the frozen projection; the
backend restores persisted list fields, applies overrides, and returns owned raw
bytes. Reassembled SIP messages, RTP attribution and other metadata that cannot
be reproduced from one packet remain bounded retained content in overrides.
Separate bounded session event/call and TLS-decryption state keep their existing
ownership; this format does not serialize new event/call snapshot streams.

`AmendVoIP` updates Protocol, Info, the narrow projection and the VoIP override
without decoding or rewriting source bytes. It appends replacement row/metadata
blocks and rewrites the one packet's directory entry. Superseded blocks remain
charged until cleanup. Generic `UpdateDetail` also supports compact storage via
reconstruction, but rejects replacement of effective raw bytes. Final statistics
are rebuilt from amended rows before publication.

`TestCompactValueSchemaFingerprint` pins field IDs/order, exact types, widths,
value representation and sparse projection groups with SHA-256. Field coverage,
round-trip, fixed-width golden-byte, nil/empty, malformed-container and truncation
tests supplement this check. The schema-1 fingerprint remains independent.

### Bounded registries and completion manifest

Source paths are stored once in the bounded ordered source list. Node/interface
labels share a registry capped at 256 entries and 64 KiB of text. Contexts have a
separate 256-entry cap. Registries use bounded linear lookup; once a cap is reached,
new values remain inline in their row's bounded arena instead of growing a global
map. Registry references are one-based; zero selects the inline value. A nonzero
label reference requires an empty inline label. For referenced contexts, only
TimestampMissing remains in the inline context; parser-domain fields come from
the registry. Inconsistent or out-of-range references are errors.

The private JSON `manifest` has these actual top-level fields:
`Version` (2), `Generation`, `Sources`, `Count`, `Statistics`, `StreamLengths`,
`AnalysisVersion` (`"1"`), `Complete` (true), `CompactRegistries`, and `Compact`.
`CompactRegistries` contains `Labels` and `Contexts`; internal accounting fields
are not serialized. `Compact` contains `SchemaMajor` (2), `SchemaMinor` (1),
`NormalizationVersion`, `AnalyzerVersion`, `DecoderVersion`,
`FilterSemanticsVersion` (each `"1"`), `BaseComplete` and `AnalysisComplete`
(both true), `AnalysisRevision` (1), `FileSHA256`, and `Backings`.

`StreamLengths` and `FileSHA256` cover `summaries`, `details` and `offsets`, including
headers and superseded blocks. Each backing entry records `ID`, `Kind`, `Size`,
`SourceID`, `SourceIndex`, `SourceSize`, `SourceSHA256`, `Policy`, and `Compressed`.
Owned snapshot, decompressed and derived files additionally have `OwnedSHA256`,
computed over their complete retained bytes; external sources retain their
scan-derived identity without another full-file hash pass.
Backing kinds are source=1, snapshot=2, decompressed=3 and derived=4. Source paths
come from `Sources`; OS handle identity and private-file ownership remain in the
live backing registry. The manifest does not persist cryptographic secrets,
key-material identity or a complete frozen settings object, and is not a reusable
cache key. Backing handles are never reconstructed from this JSON.

Completion flushes pending blocks, validates backings, seals owned backing writers
with sync/close/read-only reopen and handle identity validation, rebuilds amended
statistics, syncs and closes index writers, and reopens streams read-only. It then
validates compact headers, computes stream SHA-256 values and bounded backing
identity records, serializes the manifest under a preflight memory reservation,
writes/syncs/closes `manifest.tmp`, and atomically renames it to `manifest`.
Write failures poison the builder; no failed build publishes a completed manifest.
Cleanup retains ownership and accounting when removal must be retried.

All-match queries can use implicit packet IDs; filtered queries retain the existing
ordered u64 match vector and separate completion manifest. This does not implement
phase-4 expression/block query acceleration or phase-5 analysis revisions. Source,
snapshot/decompression and derived bytes, buffered blocks, transposition scratch,
queries, overrides, registries and retained replacement sessions remain part of
resource accounting. No compact full `PacketDisplay` records or unchanged packet
payload copies are written into the indexed streams.
