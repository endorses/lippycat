# Offline temporary storage format, schema 1

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

## Compact schema v2 contract (specified, not implemented)

The sections above describe the implemented v1 oracle. This section is the
phase-0 design contract for the replacement, not a claim that v2 readers exist.
The migration must add independent v2 shape/round-trip tests before production
cutover; the v1 fingerprint remains unchanged. No v1 file is read as v2.

All integers below are fixed-width little endian; signed values use two's
complement and float64 uses IEEE 754 bits. There is no native Go struct encoding,
implicit padding, reflection-dependent field order, or unbounded dictionary.
IDs are uint64. Packet IDs, argument indexes, physical ordinals and logical
sequences are zero-based. Registry IDs start at one; zero means no reference.
Physical ordinal counts original frames before BPF/normalization, whereas logical
sequence counts emitted normalized packets per argument. Repeated arguments
have different source IDs even for the same inode/path. The packet ID is assigned
only after sorting by timestamp, argument index, logical sequence.

### Streams, blocks and references

Every v2 stream starts with 32 bytes: magic `LCOV2DAT` (8), schema major uint16
(2), minor uint16 (0), stream kind uint16, flags uint16 (0), dataset generation
uint64, reserved uint64 (0). Kinds are 1 base columns, 2 analysis columns,
3 text arena, 4 sparse metadata, 5 source registry, 6 backing registry,
7 context registry, 8 block directory, 9 derived bytes, 10 order keys,
11 query matches. Snapshot/decompression files retain their original container
framing and are registered backings, not typed streams.

Each typed block starts with 72 bytes: magic `LCB2` (4), kind uint16,
header bytes uint16 (72), first row/entry ID uint64, row count uint32,
column count uint16, flags uint16 (0), payload bytes uint64,
analysis revision uint64, payload SHA-256 (32). SHA-256 covers the payload. A directory entry records stream
kind uint16, reserved uint16 (0), block number uint32, first ID uint64,
row count uint32, reserved uint32 (0), offset uint64, total bytes uint64,
and SHA-256 of the entire header plus payload (32): 72 bytes. The directory is a flat array of these fixed-width entries after its stream
header, ordered by stream kind then block number, and does not index itself.
The manifest stores each kind’s first entry/count, allowing checked binary search
or fixed-position reads with one bounded entry buffer; kinds have at most 4096
rows per block and contiguous IDs. The manifest authenticates the complete directory with its byte length and SHA-256. These hashes detect
corruption/change, not malicious tampering by someone able to replace storage.

Column payloads begin with `column count` 24-byte descriptors: field ID uint16,
wire type uint8, flags uint8 (0), count uint32, payload-relative offset uint64,
byte length uint64. Types are u8=1, u16=2, u32=3, u64=4, i64=5, f64=6,
reference=7, fixed32=8. Fixed columns contain row-count values; sparse columns
carry explicit packet IDs. Overlapping descriptors, duplicate/unknown fields,
wrong type/count, trailing bytes, nonzero reserved fields and unsupported
versions are errors. Rows per block are at most 4096 and encoded/decoded bytes
must fit the configured record and shared memory limits; close a block earlier
for long rows. Directory entries permit bounded direct block lookup; do not load
a dataset-sized directory into heap memory.

An arena reference is `(block uint32, offset uint32, length uint32, flags uint32)`.
Flags 0 means absent with all other words zero; 1 means present, including an
empty value. Other flags are invalid. References never straddle arena blocks;
checked offset+length must fit the validated payload and decoded object budget.
Text is exact string bytes, without normalization. Metadata values use explicit
typed records, preserve nil versus empty slices/maps/pointers and map contents,
and reject duplicate keys. Counts/lengths precede containers and are checked
against remaining input and conservative allocation cost before allocation.
Metadata field IDs are explicitly the one-based row numbers within each type
in the linked [field inventory](watch-file-packet-field-inventory.md), frozen by
this contract. They initially match Go declaration order but a future Go reorder
does not change wire IDs. Changing wire names/types/order requires a schema
decision and shape-test update; code must use explicit IDs, not reflection order. Integers use their declared
width (Go int becomes i64), booleans are u8 0/1, strings/bytes use references,
containers use uint32 counts and a presence byte, structs are typed field sequences.
Times are i64 Unix seconds plus u32 nanoseconds (<1e9), UTC, without monotonic
state; zero time and values outside UnixNano range remain representable.

### Base columns and registries

Field IDs below start at one and are consecutive within their stream in the
listed order.

| Base fields (ordered)                               | Wire representation / meaning                                                                       |
| --------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| source_id, backing_id, context_id                   | u64 each; source argument, effective bytes owner, original parser context                           |
| physical_ordinal, logical_sequence                  | u64 each; source attribution retained through normalization                                         |
| payload_offset                                      | u64; parser-consumed position in registered backing, never buffered FD seek position                |
| effective_capture_length, effective_original_length | u32 each; exported capture metadata, independently preserved                                        |
| original_capture_length, original_wire_length       | u32 each; original physical frame, before transforms                                                |
| timestamp_seconds, timestamp_nanoseconds            | i64/u32; effective normalized timestamp                                                             |
| original_link_type, effective_link_type             | u32 each; validate against supported decoder range before narrowing                                 |
| provenance_flags                                    | u32; bit 0 derived, bit 1 decompressed, bit 2 snapshot, bit 3 timestamp absent; remaining bits zero |
| integrity                                           | fixed32 SHA-256 of exact effective bytes                                                            |
| src_address, dst_address, src_port, dst_port        | reference each; exact legacy rendering, empty distinct from string 0                                |
| transport                                           | u8; IP protocol number, 0 unknown                                                                   |
| display_length                                      | i64; preserve PacketDisplay.Length separately from capture lengths                                  |
| node, interface                                     | reference each; intern only under a bounded registry/dictionary budget                              |

Base ID is implicit `first row + row index`. Typed addresses/ports for query
acceleration may be supplemental columns only after a minor-version decision;
text columns above remain the rendering oracle. A locator must reference a known
open backing and context; offset+capture length must not overflow or exceed its
validated size. Validate original framing bounds/padding during scan and digest
effective bytes before returning them. Transform-produced bytes default to derived
backing, including nested subslices; source-backed subranges require proven
unchanged provenance. One physical frame can yield multiple logical rows.

Source registry entries store source ID, argument index, exact display path,
original byte size, SHA-256 of original input, source format, backing policy and
OS identity (device/inode where available, size and modification/change times).
Backing entries store backing ID, source ID, kind (source=1, snapshot=2,
decompressed=3, derived=4), validated byte size/digest, owned-file identity and
private filename when applicable. Registry variable strings are arena references.
Contexts store context ID, source ID, section/interface IDs, original link type,
snaplen, byte order, timestamp resolution base/exponent and signed time offset.
Missing timestamps retain current reader semantics plus explicit absence. These
fields do not extend supported PCAPNG sections/interfaces or gzip formats.
Physical frame metadata for a reassembled output uses the same attribution as the
legacy normalized CaptureInfo/SourcePosition; it must not invent a fragment origin.

### Analysis, exceptional content and completion

Analysis field IDs in order: Protocol (reference), Info (reference), presence
(u8: VoIP/DNS/Email/TLS/HTTP bits 0..4), then the exact Summary projection:
VoIP User, From, To, CallID, Method, Codec, FromTag, ToTag, IMSI, IMEI (references),
Status (i64), IsRTP (u8), SequenceNum (u16), SSRC (u32); DNS QueryName, QueryType
(references), QueryResponseTimeMs (i64), first-answer-present (u8), first TTL
(u32); TLS SNI, JA3Fingerprint (references); HTTP Host, Path, Method (references),
StatusCode (i64), ContentLength (i64); finally five metadata references in presence
bit order. All absent values must retain accessor semantics, including metadata
present with empty contents. Summary accessors perform no I/O after materialization.

For a present protocol, a metadata reference with flag 0 means reconstruct its
stateless fields from effective bytes; a reference with flag 1 supplies a typed
field-override record with an explicit field-presence bitmap. An override can
explicitly set a pointer/container to nil or empty. Protocol presence bits, not
reference absence, decide whether the final PacketDisplay metadata pointer is nil.
A populated F/D field must have an override even when its value is zero; applying
overrides after stateless decoding preserves exact legacy fields.

Sparse metadata retains only finalized non-reconstructible results and necessary
packet-local overrides. Full stateless metadata may be reconstructed from owned
effective bytes plus frozen decoder configuration. Protocol-specific field IDs
and nil/empty semantics are exhaustive in the inventory. Reassembled SIP, RTP
attribution, TLS plaintext/connection results, opt-in retained bodies and other
exceptional content use bounded metadata/derived arenas; they are never omitted
from size reports. Normalized event/call snapshots are separate versioned analysis
artifacts with their own checksums and bounded-history policy, not substitutes
for packet-local metadata. No complete PacketDisplay record is persisted.

The JSON manifest has `schema_major=2`, `schema_minor=0`, normalization,
analyzer, decoder and filter-semantics versions; dataset generation; ordered
source identities and aggregate input identity; frozen nonsecret configuration
and key-material identity; backing policy; count; complete statistics; and every
owned file's kind, byte size and SHA-256. It records `base_complete`,
`analysis_complete`, `analysis_revision` and `complete`. Revision 0 is complete
base without analysis; revision 1 is the first completed immutable overlay.
Through milestone A all three completion booleans must be true before publication.
Phase 5 may publish base_complete alone through an explicit revision-aware API.
Unknown major/minor or semantic versions are rejected; no implicit v1 upgrade.
Persistent reuse remains disabled.

Flush all blocks/arenas and amendments, rebuild statistics, sync and close writers,
validate/reopen read-only, then flush/sync/close and atomically rename the manifest.
An error poisons the builder and prevents publication. Old amendments, replaced
manifests and temporary copies remain charged while present. Order keys contain
(seconds i64, nanos u32, argument u64, sequence u64, locator-row u64) with checked
framing; query vectors contain ordered u64 packet IDs plus pinned generation and
revision. All-match queries are implicit. Query completion uses its own atomic
manifest and complete statistics. Query/sort format headers must reject v1 data.
EOF, checksum, range and allocation validation precede any exposed row or bytes.

### Format cardinality limits

Block numbers and arena offsets/lengths are uint32; reject more than 2^32 blocks
per stream, payloads above min(configured record limit, 2^32-1 bytes), or more
than 4096 rows/descriptors per block. The record limit defaults to 8 MiB;
configuration never relaxes wire widths. Reference arithmetic is promoted to
checked uint64 before narrowing. Source IDs are u64 but simultaneous sources
must fit configured MaxSources (default 64); repeated arguments count separately.
Registry entries, paths and context values use the same bounded block/arena model,
not an unlimited in-memory map. Manifest reading is limited to the record budget;
its ordered input registry uses checked references if it cannot fit inline.
Physical/logical ordinal and packet-count increments reject uint64 overflow.
Snapshot/decompressed/derived byte offsets use u64 but must fit the platform
ReadAt int64 range and configured disk budget before I/O. Unknown link types,
invalid timestamp resolutions, flags and provenance combinations are rejected.
