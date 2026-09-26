# Snapshot rotation record codecs

These bounded codecs implement the authenticated records used by the
[offline snapshot rotation protocol](li-snapshot-key-rotation.md). They are
building blocks: publication or recovery authority does not follow from decoding
a record alone. The implemented Linux `RotateSnapshot` coordinator retains
ownership and enforces the [remaining-attempt workspace](li-snapshot-rotation-workspace.md)
and selected-state rules before effects.

All integers are unsigned and big-endian. Unknown versions, purposes, stages,
reserved bits, inconsistent stage fields, trailing bytes, invalid UTF-8 names,
and over-limit lengths fail. No JSON or unconstrained collection decoder is
involved. The request is limited to 4 KiB before parsing; encrypted progress is
limited to 16 KiB before decryption. Diagnostics contain fixed classifications,
never record contents, paths, key material, or comparison commitments.

## Request: LRQ1

The request is persisted only inside encrypted progress. It contains:

| Order                 | Encoding                                                                                                                                                                             |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Prefix                | `LRQ1`, version byte `1`, in-place byte `0` or `1`, owner purpose uint16                                                                                                             |
| Store identity        | Nonzero 16-byte UUID                                                                                                                                                                 |
| Filesystem identities | Parent device/inode, original source device/inode: four uint64 values                                                                                                                |
| Sizes                 | Original ciphertext length and validated unchanged payload length: two uint64 values                                                                                                 |
| Commitments           | Seven 32-byte values: source path hash, destination path hash, original ciphertext hash, payload hash, source-ring commitment, predecessor bootstrap hash, predecessor progress hash |
| Strings               | Object binding, source basename, destination basename, old active key ID, new active key ID; each uint16 length followed by exact bytes                                              |

The object uses the existing 512-byte binding limit; basenames are at most 255
bytes and cannot escape the held parent. Key IDs use the existing 64-byte syntax.
The two predecessor hashes are either both absent (all zero) or both present.
Explicit in-place mode agrees with basename equality. Payload and envelope lengths
must fit existing envelope ceilings. The owner still applies its narrower schema
limit and verifies the actual source ciphertext and exact payload bytes.

The source-ring commitment is HMAC-SHA256 under the new raw key with domain
`lippycat/securestore/rotation/source-ring/v1` followed by a NUL. Its input is the
length-prefixed old active ID followed by the source keys in ascending ID order,
each length-prefixed ID followed by its 32 raw bytes. Input scratch is cleared.
Loaded key material is immutable; no key file is reread. A new key matching any
source material or source ID is rejected; the new ring has exactly one key.

The operation token is HMAC-SHA256 under the new key over the entire canonical
LRQ1 request, with domain `lippycat/securestore/rotation/request/v1` followed by a
NUL. It is an opaque operation commitment, never an operator-facing fingerprint.
No active or prior source key is used to seal or update anything.

## Bootstrap: LRU1

The bootstrap is exactly 88 bytes and contains no sensitive request fields:

| Offset | Length | Meaning                                                |
| -----: | -----: | ------------------------------------------------------ |
|      0 |      4 | `LRU1`                                                 |
|      4 |      1 | Version `1`                                            |
|      5 |      1 | `1`: ledger-uninitialized; `2`: ledger-required        |
|      6 |      2 | Owner purpose: filter snapshot or administrative state |
|      8 |     16 | Nonzero store UUID                                     |
|     24 |     32 | Nonzero operation token                                |
|     56 |     32 | HMAC-SHA256 of bytes 0–55 under the new key            |

The bootstrap MAC domain is
`lippycat/securestore/rotation/bootstrap/v1` followed by a NUL. It is separate
from initialization, usage accounting, source-ring and request commitments.
Bootstrap decoding verifies its MAC and schema. The coordinator separately
compares the authenticated UUID/token/purpose with the exact request and selected
ledger state. A valid MAC by itself cannot authorize ledger initialization.

## Encrypted progress: LRP1 inside LCS1

Progress plaintext starts with a fixed 52-byte prefix:

| Offset |   Length | Meaning                                    |
| -----: | -------: | ------------------------------------------ |
|      0 |        4 | `LRP1`                                     |
|      4 |        1 | Version `1`                                |
|      5 |        1 | `1`: planned; `2`: prepared; `3`: complete |
|      6 |        2 | Reserved zero                              |
|      8 |        4 | Exact following LRQ1 request length        |
|     12 |        8 | Candidate ciphertext length                |
|     20 |       32 | Candidate ciphertext SHA-256               |
|     52 | Variable | Complete canonical LRQ1 request            |

Planned progress has zero candidate length/hash. Prepared and complete progress
have a nonzero hash and the exact envelope length implied by unchanged payload,
object binding and new key ID. No extra fields or trailing documents are accepted.

LCS1 uses the owner's snapshot purpose and store UUID. Its distinct object is
`snapshot-rotation/<destination-path-hash>/<operation-token>` using lowercase hex.
Opening requires an authenticated ledger-required bootstrap; after decryption,
the reader recomputes the request token and checks purpose, UUID and destination.
It does not accept a different request just because the enclosing GCM tag verifies.

Sealing uses the actual new-key usage owner and ordinary `Writer.Seal`, including
completion progress. It never borrows the final control reserve. The caller must
have already reserved all remaining stage inodes and durably selected
ledger-required before invoking this codec. Codec success is not publication.

## Compatibility evidence

Tests include independently constructed Python `struct.pack`/HMAC vectors,
single-byte mutation across the whole bootstrap, request commitment coverage,
every truncated request/bootstrap/progress prefix, oversized and inconsistent
lengths, wrong identity/key/purpose/destination/token, correctly encrypted but
mismatched request data, immutable loaded keys, old active/prior material reuse,
and ordinary-allowance exhaustion. Filesystem faults and process-death recovery
belong to the workspace/coordinator suites; these codec tests do not claim them.
