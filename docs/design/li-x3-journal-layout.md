# Production LI fixed-segment journal

This document describes the Linux implementation in
`internal/pkg/li/delivery/journal_segment*.go`, `journal_record.go`, and
`journal_control_linux.go`. It supersedes the earlier layout proposal. The
[encrypted-storage contract](li-encrypted-storage.md) defines the shared LCS1
crypto format, logical product digest and authorization rules. Timing results
remain separate evidence in the [benchmark report](../research/li-x3-storage-benchmarks.md).
The storage implementation does not authorize or send products.

## Selection, ownership and compatibility

An explicit `JournalConfig.Interface` selects X2 or X3 for a new segmented
journal. Zero retains the original X2 API behavior for a new directory. An
existing `.segments` catalog selects the segmented X2 reader even through the
legacy X2 configuration entry point; this is format dispatch, not conversion.
An existing per-record `.state` directory continues through the original X2
reader. LCX2 raw-key mappings and old record/sequence decoding remain separate.
X3 cannot open an X2 store. Unsupported non-Linux segmented operations fail.

Each journal has a private descriptor-opened directory, independent immutable
keyring and usage namespace, UUID, global `.lock` owner, worker queues and
capacity budget. Private stable lock sidecars and the retained data inode lock
protect replacement. Runtime checks `.journal-retired` and selects the format
**after acquiring the global owner lock**. A retirement marker prohibits a
writable source reopen. Offline read-only export remains available for the
coordinator to authenticate and resume its exact operation.

The expected interface comes from configuration, independently of the encrypted
header. It must match catalog, segment bootstrap, both segment heads, every
batch index, logical record and the actual encoded PDU header. Key material is
loaded once and retained by the owner; a supplied immutable ring is reused.

## Selected catalog and physical files

`.segments` is an atomically replaced, private LCS1 purpose-6 envelope with
object binding `segment-catalog` and the journal UUID. Its canonical JSON schema
has the exact Go field names `Version`, `JournalUUID`, `StateIncarnation`,
`Interface`, `RecordLease`, `AdmissionLease`, `MaxAgeNanos`, `Selected`, and
`Pending`. Version is 1. Each selected or pending reference contains exactly
`ID` (nonzero UUID) and `Kind` (`data` or `control`). Each list is bounded to
4,096 references. Duplicate or inconsistent references fail recovery.

The selected list is the authority for segment content. Pending entries are
catalog-authenticated allocation or retirement intents. A filename does not
select a segment. Catalog replacement follows file sync, atomic rename and
parent sync. Ordinary ID/admission leases advance by 4,096 before their values
can be assigned. Restart consumes the unused part of each durable lease;
identities never restart at the largest surviving product ID.

Segment names are `.segment-<canonical UUID>.bin`; unpublished allocation names
are `.segment-stage-<canonical UUID>.bin`. Offline reservations append
`.reserve` to the stage name. Segment names contain no task or destination data.

Each segment has a 32 MiB logical extent. Initialization uses `fallocate`, writes
zeroes throughout the extent with a bounded buffer, installs encrypted bootstrap
blocks, syncs the inode and publishes with Linux atomic no-clobber rename plus
parent sync. Sparse logical sizing alone is insufficient. The helper rejects
unsupported filesystems and allocation exceeding 64 MiB per extent. Admission
and catalog selection check actual allocated bytes, rather than treating the
logical size as the physical charge.

| Offset | Size             | Contents                                                   |
| ------ | ---------------- | ---------------------------------------------------------- |
| 0      | 4 KiB            | Immutable bootstrap, purpose 6, `segment/<UUID>/bootstrap` |
| 4,096  | 4 KiB            | Head 0, purpose 6, `segment/<UUID>/head/0`                 |
| 8,192  | 4 KiB            | Head 1, purpose 6, `segment/<UUID>/head/1`                 |
| 12,288 | Remaining extent | Aligned append frames and zero unused tail                 |

Each bootstrap/head block begins with a big-endian uint32 envelope length;
remaining bytes must be zero. Its canonical payload contains version, journal
UUID, segment UUID, expected interface, kind, generation, selected end offset
and SHA-256 chain value. Bootstrap and both initial heads use generation zero,
end 12,288 and zero chain. Both heads must authenticate. Operational generations
must be adjacent; only the initial generation-zero pair may be equal. The
highest generation selects the prefix. The lower head must describe its exact
prefix within that same authenticated chain. There is no corrupt-head fallback.

## Append frames and encryption purposes

Frames start at 4 KiB boundaries, are padded with zeroes to that boundary, and
are at most 2 MiB. The 32-byte clear prefix carries magic `LJS2`, padded frame
length, encrypted index offset/length, generation, and zero reserved bytes.
The index is purpose 9, bound to `segment/<UUID>/batch/<generation>`. Its strict
payload binds journal, segment, expected interface, kind, generation, start/end,
previous frame hash, and exactly the permitted fragment or control collection.
Hashing the complete padded frame supplies the next head chain value.

Data fragments use purpose 3 for X2 and 4 for X3, with object binding
`<decimal record ID>/fragment/<zero-based part>`. Plaintext chunks are at most
512 KiB; a 64 MiB PDU uses at most 128 chunks. The encrypted index identifies
each chunk's record/admission IDs, ordinal/count, original total length, exact
ciphertext offset/length/hash and canonical logical metadata. A record becomes
recoverable only when its final authenticated fragment is selected. An
interrupted prefix consumes identities and space but does not become a product.

Purpose 9 also carries **typed logical control batches**. The surrounding
journal/interface/kind binding authenticates the control type and context;
controls do not receive a redundant standalone envelope. Purpose 5 remains the
standalone sequence checkpoint format for the per-record backend. Purposes 7
and 8 remain assigned to standalone call/revocation envelopes. Catalogs,
bootstraps and heads use purpose 6. This mapping changes physical packing while
preserving each logical control's exact identity and terminal meaning.

Strict decoding bounds bytes, depth, strings, collection sizes and total tokens
before typed allocation. Re-encoding must exactly equal the authenticated JSON,
rejecting duplicate fields, case aliases, unknown fields, noncanonical numbers,
trailing bytes and invalid null/omitted forms. Typed union validation separately
rejects cross-kind fields even if the enclosing ciphertext authenticates.

## Logical records and controls

The logical-v2 digest covers the canonical binary prefix beginning
`lippycat/li-record/v2\x00`, expected interface, journal and state identities,
record ID, task/destination generations, timestamps, tagged provenance and
original PDU length, followed by **the exact original encoded PDU bytes**.
The stored SHA-256 digest is verified after lazy decryption. PDU headers/TLVs
must be structurally valid and match the expected interface and XID. Delivery
never re-encodes a recovered product.

Provenance is a strict union of `call`, `non_call` (RTP or RADIUS), and the
explicit legacy-X2 variant. Each variant admits only its defined fields. The
metadata prefix plus digest is bounded to 80 KiB plus 32 bytes; original PDUs
are bounded to 64 MiB. X3 admission stores its absolute deadline once. Restart
uses that stored deadline and does not extend it from the configured maximum age.

Control batch items form a closed union: `sequence`, `call_open`, `call_close`,
`revoke`, `complete`, `expired`, or `purge`. Inapplicable members must be null or
zero in the exact canonical representation. Sequences retain the complete
interface-specific sequence context and next uint32 value, including wrap.

Call controls contain version 1, journal/state incarnation, exact XID/task
generation and DID/destination generation, call incarnation/generation/ID,
state (`open`, `capture_closed`, or `revoked`), **both covered record and
admission highwaters**, and closure time when closed. They cannot reopen closed
capture. The state timestamp uses integer seconds and nanoseconds. Required
call-open and sequence controls are durable before product callbacks. Normal
startup durably closes recovered open captures while retaining historical
products. Offline export makes no such lifecycle changes.

Revocation controls preserve the administrative version, operation UUID,
journal/state incarnation, exact tagged task/destination/call scope, generation
identities, timestamp, and covered record/admission highwaters. Runtime validates
nonapplicable fields, nonzero identities and journal boundaries. A durable
revocation prevents matching pending callbacks from becoming eligible as well as
terminalizing retained products. Completion, expiry and purge are durable
terminal controls; success is not reported when only a volatile map changed.

## Batching, callbacks and shutdown

Admission reserves pending memory, record/index capacity, data bytes and future
terminal-control bytes before accepting ownership. Metadata-aware reservations
charge the exact canonical metadata bound; token consumption validates it.
The conservative API reserves the full possible metadata size. Reservation
release and token consumption are mutually exclusive.

A data worker accumulates at most 1 MiB of ordinary work per batch and waits at
most 10 ms while gathering. A single oversized admitted product is streamed in
bounded fragment frames. Storage contention and earlier queued work can extend
actual admission-to-callback latency; the 10 ms gather timer is not a durability
latency guarantee. The physical index and padded frame limits remain enforced.
The control worker similarly batches bounded independent controls. Disk mutation
is serialized by the journal storage owner.

A callback succeeds only after required controls, product bytes and selected
head updates have synchronized. Callbacks execute on a separate bounded owner,
so a callback can synchronously request completion/expiry without deadlocking
the data worker. Flush crosses earlier callbacks, including their synchronous
terminal operations. Shutdown drains data, callbacks and controls before closing
storage. Any uncertain mutation faults further admission. Typed outcomes keep
`NotCommitted`, `Uncertain`, and `Committed` distinct, including a cleanup error
after a definite commit.

## Resource partitions and supported outage capacity

Let `B` be configured maximum bytes and `R` the actual allocation retained by
metadata, old rewrite artifacts and other recognized nonselected files:

```
control = max(64 MiB, B / 10)
scratch = max(192 MiB, B / 10)
data    = B - control - scratch - max(4 MiB, R)
```

The minimum segmented spool is 320 MiB. Physical allocation, selected extents,
retained receipts, usage ledgers and lock files count toward its bounded
inventory. Recognized transaction stages use the actual 64-hex workspace token
and 32-hex nonce; predecessor receipts also use 64-hex tokens. Recognition only
permits validation/accounting, not authority or deletion. Unknown files fail
closed. The inventory admits at most 32,768 names.

Each pending or retained product reserves **1,024 bytes** of terminal control
credit. At most half the control partition can be committed to these credits;
the remaining half covers shared identities/checkpoints and replacement overlap.
Thus terminal credit capacity is `floor(control / (2 * 1024))`, independently of
payload capacity. A **4 GiB X3 spool supports only about 209,715 such credits**
and cannot hold the primary 1.2 million-record, 60-second outage workload.
**At least 24 GiB is required for that workload under this implementation's
conservative credit policy**, together with sufficient data space for the actual
encoded products/metadata. At 24 GiB the terminal limit is 1,258,291 records.
The two-million-record ceiling needs a larger budget (at least 40 GiB for terminal
credits alone); ceilings are not promises that a smaller disk budget can hold
that many records.

| Resource                           | Enforced bound                                                                    |
| ---------------------------------- | --------------------------------------------------------------------------------- |
| Retained product count             | X2 at most 1 million; X3 at most 2 million                                        |
| Pending admissions/callbacks       | Configured bound, capped at 4,096                                                 |
| Pending byte charge                | 64 MiB plus 8 MiB framing allowance                                               |
| Retained location index            | 2 GiB; `512 + metadata bytes + 64 * (PDU bytes / 512 KiB + 1)` per record         |
| Call/revocation identities         | 65,536 shared entries                                                             |
| Sequence identities                | 65,536 entries                                                                    |
| Control memory                     | 64 MiB; canonical encoded control plus 192 bytes, or 32 bytes per terminal marker |
| Segment references                 | 4,096 selected and 4,096 pending                                                  |
| Per-frame fragment/control entries | 4,096                                                                             |
| Catalog/plaintext decode ceiling   | 4 MiB, with token/depth/collection preflight                                      |

Live and recovery paths use the same location/control charges and reject a
budget that cannot retain the recovered records. Changes in encoded control
size, including call closure timestamps and sequence number digit growth, update
the charge. The client reserves `SegmentedJournalMemoryBytes` per explicit owner:
2 GiB index + 64 MiB pending + two 64 MiB product buffers + 8 MiB framing +
64 MiB control memory, currently **2,312 MiB for the backend alone**. The client
adds 512 MiB of staging/reservation capacity, so the complete managed reservation
is **2,824 MiB per enabled segmented owner**, or **5,648 MiB for X2 and X3
together**. The owners do not share a pool. These managed reservations are
separate from the process RSS allowance and must be included in deployment sizing.

## Expiry, reclamation and compaction

Deadline tracking is metadata-only; replay reads original PDU bytes lazily.
The online expiry worker drains all overdue records in bounded terminal batches,
including held/offline records. There is no fixed 256-record-per-second expiry
ceiling. Expired/revoked/completed products remain nonclaimable during physical
reclamation.

Data compaction copies the exact live product ciphertext from one bounded source
extent into a scratch extent and reseals only its index/heads. After all target
bytes are synchronized, a catalog replacement selects the targets and places the
old extents in authenticated pending retirement. Directory-synchronized deletion
then releases their allocation. A crash before selection retains the original
source; a crash afterward follows the exact selected catalog and pending list.
Control compaction preserves current call/revocation/sequence facts and needed
terminal markers, then uses the same selection/retirement protocol. Its temporary
extent count is bounded by both control and scratch partitions. Neither
compaction nor expiry resets cryptographic usage or durable identity leases.

## Startup and offline rewrite boundaries

Startup authenticates catalog, immutable bootstraps, **both** heads and every
selected frame/index/chain before exposing retained metadata. Products remain
held pending independent administrative approval. Actual product bytes are
loaded and authenticated on demand; offline rewrite additionally validates the
whole source payload stream before publishing any replacement.

A valid selected prefix may coexist with an interrupted, unselected append tail.
Only normal writable startup, after authenticating both heads and the complete
selected prefix, may zero that tail in place and synchronize it. A torn or
invalid head faults the store. Offline read-only source opening never clears a
tail, allocates usage, advances leases, closes calls, expires products or starts
workers. It exports only the authenticated selected history.

Offline source owners expose exact records, controls, UUID/incarnation,
highwaters, source digest and actual allocation. The coordinator holds source
and destination owners in stable descriptor order and authenticates request and
resume state. Target owners consume a preallocated finite set of segment inodes
and an explicitly reserved finite usage allowance; they cannot refill the pool.
The target returns an encrypted catalog candidate without selecting it. The
coordinator alone performs publication, receipt progression and source retirement.
Borrowed directory/primary/usage owners remain owned by that coordinator.
Existing keys, ledgers and retained old-key source artifacts are not deleted or
reset by import, and retained dependencies must be reported honestly.

The backend regressions cover actual X2/X3 PDUs, callback terminalization,
fragments, exact metadata and restart charges, revocation/expiry, compaction,
preallocated import, corrupt heads, read-only tail preservation, runtime tail
recovery, control identity substitution, terminal-credit sizing, and subprocess
cuts before selection, during head write, and after sync before callback. These
correctness checks do not substitute for the separately reported end-to-end
throughput, startup, expiry and RSS measurements.
