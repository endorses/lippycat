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
