# Proposed bounded LI segment durability kernel

Status: **root-reviewed helper/codec/recovery and narrow 2/200 ×40 measurement
implemented; the small callback-floor gate passes; production layout remains
unselected**. This proposes one small alternative after all three
[immutable batch/head kernels](li-x3-batch-layout.md) failed the unchanged
25 ms callback-median gate on the [declared ext4 device](../research/li-x3-storage-benchmarks.md).
It supplements the [encrypted-storage contract](li-encrypted-storage.md) without
selecting a production X3 layout, changing X2, or completing phase 5.

## Durability premise and scope

The Linux `fdatasync` contract covers changed file data and metadata required
for subsequent retrieval. A file-size change requires metadata synchronization;
timestamps need not. Creating or renaming a file still requires separate parent
directory synchronization. This experiment therefore establishes the complete
fixed-size inode and its name before admission, then measures updates that change
neither size nor namespace. It does not omit the synchronization needed for new
file publication. [Linux fsync/fdatasync manual](https://man7.org/linux/man-pages/man2/fsync.2.html).

Ext4's usual journal protects metadata consistency; that alone does not make
application data writes or the two head slots atomic. This design assumes neither
an atomic 4 KiB write nor ordering between background persistence of its data and
head writes. Its integrity checks must detect incomplete selected data and torn
heads. [Linux ext4 journal documentation](https://cdn.kernel.org/doc/html/latest/filesystems/ext4/journal.html).

**Original performance hypothesis:** after fully initializing extents, one
`fdatasync` for an appended batch and its head might cost less than the immutable
file-plus-directory protocols. Metadata still needed for retrieval must be
flushed, and the actual device may offer insufficient headroom. Only the reviewed
2/200-record, 40-transaction probe can test that inference. Do not change drive
cache settings, filesystem mount options, flush behavior or any frozen threshold.

Root's separate raw I/O diagnostic on the same ext4 volume used one fully
zero-written/synced 64 MiB private file, then 50 iterations each of 80 KiB data
plus an alternate 4 KiB dummy head and one sync. Exact fsync p50/max were
8.787507/17.240829 ms; fdatasync p50/max were 3.037005/3.639451 ms. The script ran
fsync first and fdatasync second, without randomized ordering or repeated trials;
actual file allocation was 67,108,864 bytes. It omitted encryption, usage,
authenticated heads/recovery, accumulation, callbacks and the workload. This is
support for investigating the I/O floor, **not protocol or qualification evidence**.
The retained artifacts are `/tmp/li-segment-sync-floor.py` and
`/tmp/li-segment-sync-floor.log`; the private directory was removed. The encrypted
kernel's separate measured evidence appears below; the raw diagnostic does not
substitute for it.

The kernel uses one fresh private disposable store, synthetic raw key and source
PDUs, actual durable call controls, and the existing independently durable usage
ledger. It has no production admission queue, transport, expiry, revocation,
rotation, checkpoint, compaction or offline repair runtime. Success in a small
probe would not qualify the required 20,000 copies/s workload.

## Fixed file, names and ownership

The only segment file is `segment.lsg`. Its immutable segment UUID is fresh and
nonzero; the journal UUID comes from the authenticated usage ledger. Both head
payloads bind those identities and the immutable segment header. A fixed filename
contains no task, call or destination identity. Coherent authenticated rollback
still requires external reconciliation as in the parent contract; this layout
does not add a trusted external monotonic counter.

The experiment uses a **32 MiB exact file length** (33,554,432 bytes), below the
64 MiB segment ceiling. It has an immutable 4 KiB header, two separate 4 KiB head
slots, and a data region beginning at byte 12,288. Require the reviewed 4 KiB ext4
allocation unit. The actual allocated blocks, extent metadata and conservative
owner reserves must fit the configured budget; reject bootstrap if the object's
actual allocation exceeds 64 MiB or the whole store exceeds its bound. Logical
file length alone is not the capacity charge.

Hold both the stable `Dir.Lock("segment.lsg")` ownership and its data-inode lock
through every read, mutation, sync and recovery decision. All file access remains
relative to the held directory descriptor. A mutable I/O descriptor must be
opened privately with `O_RDWR|O_NOFOLLOW|O_CLOEXEC`, validated as the same regular,
mode-0600, one-link inode as the owned data descriptor, and retained for the
writer's lifetime. Opening a second descriptor must not release the original
inode flock. The helper must verify identity and exact size before mutation,
serialize operations in the existing directory/owner lock order, and forbid
truncate, extension, hole punching, replacement, hardlinks and path reopening.
Only one storage writer may prepare or publish a transaction at a time.
The helper admits one live `FixedSegment` handle per owned lock, rejects a
concurrent rotation helper, and refuses ownership close until that handle closes.
The benchmark owner also serializes complete preparation/publication operations;
serializing only the final writes would permit stale head preparation.

During initial construction only, use an exclusive private name
`.lsg-init-<32 lowercase segment UUID hex>.tmp`, outside generic temporary
recovery. An interrupted bootstrap is not an empty store. Its inode cannot be
silently deleted, resumed with reset usage, or promoted by ordinary runtime
startup. The benchmark may remove only its own entire disposable directory after
reporting the failed operation.

## Immutable header and data frames

All integer fields are unsigned big endian. The immutable header is exactly
4,096 bytes: this 64-byte prefix followed by 4,032 zero bytes. Each authenticated
head contains SHA-256 of the **entire** immutable header. Reserved/padding bytes
must be zero; neither unsupported versions nor unknown flags are ignored.

| Header offset | Bytes | Field                                      |
| ------------- | ----: | ------------------------------------------ |
| 0             |     4 | Magic `LSG1`                               |
| 4             |     1 | Segment version, exactly 1                 |
| 5             |     1 | Interface, exactly 2 (synthetic X3 kernel) |
| 6             |     2 | Flags, zero                                |
| 8             |    16 | Fresh nonzero segment UUID                 |
| 24            |     8 | Exact file size, 33,554,432                |
| 32            |     4 | Slot 0 offset, 4,096                       |
| 36            |     4 | Slot 1 offset, 8,192                       |
| 40            |     4 | Slot size, 4,096                           |
| 44            |     4 | Data-region offset, 12,288                 |
| 48            |     4 | Maximum embedded `LCB1` length, 2,097,152  |
| 52            |     4 | Maximum frames per batch, 4,096            |
| 56            |     4 | Immutable header length, 4,096             |
| 60            |     4 | Reserved, zero                             |

Append the existing complete `LCB1` encrypted batches, without changing their
internal physical offsets, purpose-9 metadata, purpose-4 product envelopes,
immutable encoded PDU bytes, sequence evidence or exact control dependencies.
Every batch starts at a 4 KiB-aligned cursor. Its physical span is
`round_up(exact LCB1 length, 4096)`; padding is exactly `span - length` required
zero bytes following the `LCB1` bytes. The existing 2 MiB physical batch ceiling therefore also bounds
the rounded span by 2 MiB. No next write shares a filesystem block with a
previously committed batch or either head slot.

The `LCB1` prefix's total length identifies the encrypted batch bytes, excluding
this segment-level padding. Its existing digest and predecessor-batch digests
cover those exact bytes. Padding is canonical zero and must be checked on every
committed read; an authenticated length/cursor plus required zero padding allows
only one accepted padded representation. Nonzero padding inside the selected
committed prefix is corruption, never a tolerable tail. The 1 MiB combined
plaintext, 256 KiB index plaintext, 4,096-frame and per-record limits remain
unchanged, including bindings. Unknown inner schemas fail closed.

This small experiment adds an explicit **4,096-byte PDU-header ceiling** before
the general PDU decoder allocates TLV objects, on both encode and authenticated
recovery. Require `header length + payload length == exact PDU bytes` and exact
TLV termination within that header. At most `(4096 - 40) / 4 = 1,014` zero-length
TLVs can reach decoding. This bound applies only to this kernel; it makes no
production compatibility claim for larger valid headers. The shared immutable
benchmark codec leaves this optional preflight hook disabled.

## Exact head-slot representation

Each slot is exactly 4,096 bytes: a 16-byte framing prefix, one purpose-6 LCS1
envelope, then zero padding. The expected slot index comes from its fixed physical
offset, never from untrusted bytes. The envelope uses
`{Store: authenticated usage-ledger UUID, Object: "journal-state"}` and has this
fixed 288-byte experimental owner payload. No production head schema is changed.

| Slot prefix offset | Bytes | Field                                          |
| ------------------ | ----: | ---------------------------------------------- |
| 0                  |     4 | Magic `LSH1`                                   |
| 4                  |     1 | Slot framing version, exactly 1                |
| 5                  |     1 | Slot index, 0 or 1, equal to physical position |
| 6                  |     2 | Flags, zero                                    |
| 8                  |     4 | Exact LCS1 envelope length                     |
| 12                 |     4 | Reserved, zero                                 |

| Head payload offset | Bytes | Field                                                             |
| ------------------- | ----: | ----------------------------------------------------------------- |
| 0                   |     4 | Kernel payload magic `LSP1`                                       |
| 4                   |     2 | Schema version, exactly 1                                         |
| 6                   |     1 | Kind: 0 = bootstrap head, 1 = product head                        |
| 7                   |     1 | Reserved, zero                                                    |
| 8                   |    16 | Exact complete slot prefix                                        |
| 24                  |    16 | Journal UUID, equal to independently authenticated store identity |
| 40                  |    16 | Segment UUID, equal to the authenticated immutable header         |
| 56                  |    32 | SHA-256 of the complete 4 KiB immutable header                    |
| 88                  |     8 | Head generation                                                   |
| 96                  |    32 | SHA-256 of the exact previous 4 KiB head slot, including padding  |
| 128                 |     8 | Committed cursor, aligned, within [12,288, 33,554,432]            |
| 136                 |     8 | Last batch start offset, or zero for bootstrap                    |
| 144                 |     4 | Last exact `LCB1` byte length, or zero for bootstrap              |
| 148                 |     4 | Product transaction count                                         |
| 152                 |    16 | Last batch UUID, or zero for bootstrap                            |
| 168                 |    32 | Last exact `LCB1` ciphertext SHA-256, or zero for bootstrap       |
| 200                 |     8 | Record-ID highwater                                               |
| 208                 |    16 | Nonzero synthetic call UUID                                       |
| 224                 |    32 | First durable purpose-7 control-file ciphertext SHA-256           |
| 256                 |    32 | Second durable purpose-7 control-file ciphertext SHA-256          |

For a `K`-byte key ID, the exact envelope length is
`32 + K + 18 + 13 + 288 + 16 = 367 + K`, at most 431 bytes. Thus the slot has at
most 447 non-padding bytes and always fits in 4 KiB. Length is computed before
sealing; the predicted and actual lengths must match. There is no head self-hash
or circular size dependency. A subsequent head hashes the **complete already
known prior slot bytes**, whose own predecessor hash is immutable.

Validate slot framing, exact envelope length from its actual key-ID length,
purpose, binding, payload length, schema, slot-index copy, journal/segment/header
identity and all padding before considering generation. Generation parity must
equal slot index. Product heads require transaction count 1–128 and generation
exactly `transaction_count + 1`; the measured writer admits at most 40 batches.
Record IDs, counts, offsets and additions must be checked before conversion or
allocation; no generation, count, sequence context or record-ID wrap is inferred.
Protocol-defined uint32 PDU sequence wrap remains the existing sequence policy.

For a product head, the last batch offset is aligned and at least 12,288, the
exact length is within the existing batch bound, and
`committed_cursor = last_batch_offset + round_up(last_batch_length, 4096)`.
Check this using subtraction from the bounded file length before adding or
rounding. The last batch's authenticated index revision equals transaction count;
its immutable record highwater and identity/digest must match the head. Earlier
batches are validated by the same index chain inside the selected prefix.

## Bootstrap: two authenticated heads before publication

A single valid root head plus an all-zero peer is ambiguous once tail writes are
possible: it can resemble either a first uncommitted data write or a zeroed newer
head. Operational startup must never resolve that ambiguity by selecting the
root. The reviewed correction is to publish the file only after **both** slots
contain valid adjacent bootstrap heads. An unused all-zero slot is permitted
only in the unpublished initializer; it is never valid operational state.

Bootstrap slot 0 has generation 0, kind 0, zero predecessor-head digest,
transaction count/highwater 0, cursor 12,288, and zero last-batch offset/length/
UUID/digest. Slot 1 has generation 1 and otherwise the same empty product state;
its predecessor-head digest is SHA-256 of the complete encrypted slot 0. Both
contain the same actual journal/segment/header/call/control identities. The
initializer consumes two real encryption invocations, with independent durable
usage reservations before each nonce. Root heads are never plaintext sentinels.

In an explicitly fresh private disposable directory, initialize the usage ledger
and both real purpose-7 controls durably. Create the exclusive staged inode and
optionally `fallocate` its full 32 MiB. **Fallocate alone does not establish that
extents have been initialized.** Write every byte of the entire file with a
bounded zero buffer of at most 64 KiB using complete offset writes. Do not use
hole punching, sparse truncation, `FALLOC_FL_ZERO_RANGE` or an unwritten-extent
shortcut as a replacement for these writes. Check every write count and error.
The zero-range API can implement logical zeros using unwritten extents rather
than physically writing them; this is why the experiment requires ordinary full
zero writes. [Linux fallocate manual](https://man7.org/linux/man-pages/man2/fallocate.2.html).
Then write the immutable header and both complete authenticated head slots.

Sync the complete file with `fsync`, validate exact size, private inode and actual
allocated blocks, and retain its inode lock while closing the construction
writer. Publish `segment.lsg` without replacement, transfer/retain the same inode
ownership, and sync the parent directory. Reopen the mutable descriptor under
that ownership if necessary, verify both heads and their empty data region,
and only then admit measurement products. Report all zero initialization,
preallocation, control, usage, file-sync and directory-sync setup time separately.
Any bootstrap failure stops; no used directory may initialize a new ledger or
replace a missing/corrupt segment automatically.

The full initialized file is charged from bootstrap onward. Setup intentionally
pays extent conversion before admission; if an implementation chooses otherwise,
it is a different experiment that must explicitly measure conversion costs and
obtain review rather than claim this probe's premise.

## One data/head write and one durability boundary

Before a candidate, the sole owner validates the current two-slot authority,
keeps the last committed in-memory generation/cursor, and checks the entire new
batch's input/count/size, record-ID and generation bounds. Reserve the required
codec memory, remaining segment span and independent metadata/control capacity
before encryption. Reject an insufficient remaining segment span as definite
capacity exhaustion; do not extend, rotate, overwrite, wrap or reuse committed
space in this kernel. The initial probe may conservatively reserve a full 2 MiB
span per attempt, although only the actual rounded span advances the cursor.

Encrypt all product/index/head objects with real usage accounting. Construct the
next head for the inactive slot with generation +1, the exact active-slot digest,
new cursor and all existing head/control identities. The head is completely
prepared in memory before any file mutation; nonce usage is never refunded.
Write the bounded padded batch only at the old committed cursor, with complete
`pwrite` loops and no `O_APPEND`. Then write the complete 4 KiB inactive head slot.
Do not clear that slot first. Enter the `Uncertain` state **before attempting the
first head write**, even if a particular failing syscall later reports zero
bytes; this avoids using a write-count guess as a durability decision.

After both full writes, call `fdatasync` exactly once on the retained segment
I/O descriptor. No callback success, feeder visibility or selected in-memory
highwater may advance before that call succeeds. On definite success, publish
the new committed in-memory generation/cursor and invoke each product callback
exactly once. A later cleanup/close failure is `Committed` plus error and must
not cause admission duplication. Keep descriptors and both ownership locks
throughout; a normal transaction neither closes/reopens the segment nor changes
its name, size or allocation plan. Usage-renewal writes remain separately durable
and are included in callback timing whenever they occur.

Every error latches the owner fault. A data-only error before any head attempt is
`NotCommitted`, with a possible unselected dirty tail. Any attempted head write,
partial head write, cancellation before sync, or failed/interrupted `fdatasync`
is `Uncertain`; the process must stop rather than retrying the syscall into a
claimed definite result. Never restore the older slot, erase a possibly selected
head or automatically resume this writer after an error. A shutdown close error
does not invalidate a previously successful sync; it stops the owner and is
reported separately from already delivered callbacks.

## Recovery authority and the permitted tail proof

Recovery is read-only until it has proven the entire authority. Acquire stable
and data-inode ownership, validate the fixed inode/size, the immutable header,
and **both complete slots**. A zero slot, invalid envelope, nonzero padding,
unknown version or wrong identity faults even when the other slot is valid.
Never select a lone valid head or search data for a plausible replacement head.

The two valid generations must be adjacent, parity-correct, and agree on all
journal/segment/header/call/control identities. The higher head must reference
SHA-256 of the exact lower slot bytes. Reject equal generations, gaps, swapped
slots, lower cursor/highwater ahead of higher, or a product transition other
than exactly one bounded batch. The lower head's authenticated predecessor may
be outside the two-slot window; it is explicitly not required to occupy a third
slot. It is never permission to skip the required higher-to-lower digest check.
The only equal-cursor transition is the exact generation-0/generation-1 empty
bootstrap pair. Select the higher head only after these checks.

Validate precisely the data prefix [12,288, higher cursor), with a 64 KiB hashing
buffer, one bounded batch/metadata decode at a time and at most 128 batches. The
head, not a scan, supplies the selected boundary and transaction count. Every
`LCB1` length/span must fit the remaining selected interval before allocation.
Authenticate indexes, product/control bindings, original PDU digests, sequence
evidence, contiguous record IDs, predecessor UUID/ciphertext hashes and canonical
padding. The final frame must end exactly at the selected cursor and match its
last-batch fields and highwater. At the lower head's transaction boundary, verify
its cursor, tip identity/digest and highwater too. The actual control files must
authenticate under the exact existing call bindings and match both head hashes.
Invalid selected bytes are committed corruption and always fault.

After both heads and their selected prefix pass, bytes beyond the selected cursor
are not selected by either authenticated authority. Under this protocol, no
callback could have committed such bytes: callback success requires a durable
new head, and invalid/torn/zero head states have already been rejected. A wholly
lost unacknowledged head update can leave the old adjacent pair intact; that pair
selects the old prefix and the extra bytes remain unacknowledged. A complete
valid newer head selects its appended data regardless of whether a callback was
observed before a crash; missing or corrupt data for that head faults. Do not
claim detection of a coherent replay of previously authentic adjacent slots;
trusted rollback detection is outside the parent contract and needs an external
monotonic witness. All conclusions here assume the declared successful-sync
storage contract, not a device falsely acknowledging lost writes.

Because the writer stops on its first error and allows at most one pending batch,
any nonzero unselected bytes must lie within at most one 2 MiB span immediately
following the selected cursor. Stream-check the whole remaining fixed tail with
a 64 KiB buffer; a nonzero byte beyond that single-attempt span, truncated file,
overlap with committed data or unexplained allocation change faults. Tail scan
never parses its contents into product, infers a head, counts a callback or
refunds an encryption invocation. A partial/corrupt unselected ciphertext tail
can be classified as unselected **only after** all two-head/prefix checks above.
The same bytes inside the selected prefix always fault.

The approved small kernel must stop with a classified unselected tail and defer
all reconciliation mutation to a later explicit offline operation. It never
reopens a dirty-tail store for continued appending. The only permissible future tail
reconciliation is: revalidate and pin the same two heads/selected prefix under
ownership, zero only the bounded unselected attempted span with a 64 KiB buffer,
then `fdatasync` the same fixed file and verify zero tail. No head changes,
truncation, hole punching, implicit generation reset or nonce reuse is permitted.
A cleanup sync error leaves the store stopped; subsequent inspection starts from
both heads again. Reconciliation cannot issue historical callbacks. Any invalid
head or selected data prohibits this cleanup entirely. This explicit operation is deferred by the initial implementation approval.

## Resource and measurement bounds

Each probe owns one 32 MiB segment plus actual control, usage, ownership and
bootstrap metadata. Charge actual allocated blocks and reserve another 4 MiB for
bounded metadata/control/failed-bootstrap work; the whole private disposable
store is capped at 96 MiB. Bootstrap must have room for the full fixed allocation
before admitting products. No extra segment or rewrite copy may be created by
this probe. Require at least 1 GiB free on the declared ext4 project volume and
clean only the experiment's private disposable directories. Do not use `/tmp`
for durability claims.

Codec/read memory is bounded by a 16 MiB reservation including simultaneous PDU,
frame, metadata, batch, padded-write and slot buffers; zero-init/tail/hash I/O
uses buffers no larger than 64 KiB. Preserve at most 8,000 exact callback durations
(64 KiB). Report process heap/RSS samples with their sampling limitation; they do
not replace the final production memory accounting or 15-minute soak. Full tail
validation reads a bounded 32 MiB file and is part of measured reopen time; the
future million-record lazy startup gate remains unqualified.

The reservation covers conservatively overlapping live codec objects, rather
than merely the on-disk ciphertext length:

| Live allocation category                                                              | Conservative reservation |
| ------------------------------------------------------------------------------------- | -----------------------: |
| Caller-owned encoded PDU bytes, total admission ceiling                               |                    1 MiB |
| Retained encrypted frames (at most 2 MiB), metadata, plaintext/encrypted index copies |                    3 MiB |
| Current `LRB2` plaintext and AEAD binding/plaintext scratch                           |                    2 MiB |
| Complete `LCB1` and its separately allocated padded write copy                        |                    4 MiB |
| Decoded PDU payload/TLV values and bounded decoded JSON strings                       |                    2 MiB |
| Slice backing arrays, TLV structs, heads/controls, bounded maps and I/O buffers       |                    2 MiB |
| Total conservative live allocation bound                                              |                   14 MiB |
| Reservation, including a further 2 MiB margin                                         |                   16 MiB |

The 4,095-record limit bounds both retained slice tables. On the measured amd64
build each slice descriptor is 24 bytes; even allowing each backing array twice
the live count, two frame/metadata tables plus the caller table are below 0.5 MiB.
The preflight TLV ceiling bounds current decoded TLV structs and old/new growing
slice storage below 128 KiB. The combined 1 MiB plaintext and 256 KiB index bounds
limit metadata values; recovery handles one bounded batch and one decoded record
at a time, without accumulating prior plaintext. These deliberately overlapping
budgets also cover the decoder's payload copy and both zero-tail comparison
buffers. Head and control buffers are each at most 4 KiB; the prefix walk retains
at most 128 UUIDs. Full zero initialization streams 64 KiB writes.

This is a live-object reservation derived from enforced codec limits, not a Go
heap/RSS cap or an arena allocator. Unreachable objects awaiting collection,
runtime/allocator overhead and the rest of the process require the separately
reported heap/RSS observations and the eventual production memory gate. The
benchmark memory samples retain those limitations.

After syscall/codec/authority/fault tests pass and root authorizes measurement,
run only the same 2- and 200-record batches, 40 transactions each, 10 ms real
accumulation and synthetic payload mix on the declared ext4 device. Product,
index and head sealing, actual usage renewal, data/head writes, `fdatasync` and
once-per-record callbacks stay inside timing. Root/control/zero initialization
is outside callbacks but separately reported. Use original encoded-byte oracles,
exact p50/p99/max, actual allocated/reserved bytes, fixed-size invariance,
reservation counters, read/authentication recovery time and sampled CPU/memory.

The first gate remains callback p50 ≤25 ms (p99 ≤100 ms, max ≤1 s); preserve raw
output and stop if it fails. A pass authorizes no automatic workload escalation:
throughput, completion, control priority, capacity, recovery, rotation/compaction,
X2 contention and eventual full integration still need separate review and
measurement. Keep the machine's shared-load caveat and all setup costs visible.

## Required fault and corruption matrix

| Condition or interruption                                                                                                                            | Live outcome                                                                                    | Mandatory recovery/validation behavior                                                                               |
| ---------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| Bootstrap zeroing, head sealing, file sync, publication or parent sync fails                                                                         | No product admission; retain bootstrap evidence and accurate publication outcome                | No operational zero-slot exemption; missing/incomplete used store never bootstraps itself                            |
| Input, generation/ID/span/size or independent usage reservation fails                                                                                | `NotCommitted`, no segment mutation                                                             | Preserve independent usage outcome/fault and reservations                                                            |
| Data write returns zero, invalid count, short write/error, ENOSPC or EIO before any head call                                                        | `NotCommitted`, fault latched                                                                   | Both heads/prefix must pass before classifying bounded tail; no retry without reconciliation                         |
| Death after partial/full data write, before head attempt                                                                                             | No success callback                                                                             | Intact adjacent pair selects its exact prefix; bounded tail is unselected only after full validation                 |
| Head write returns zero/error, partial progress, bad count, or death midway                                                                          | `Uncertain` once head attempt starts                                                            | Any invalid/zero peer faults; no fallback to the valid slot, no head erase                                           |
| Half-slot replacement, old/new mixed sectors, envelope truncation or bad padding                                                                     | `Uncertain` for interrupted attempt                                                             | Authenticate full exact slot; reject even if the other slot and older data are intact                                |
| Complete new head persists but some selected batch bytes or padding do not                                                                           | No success until sync                                                                           | Selected corruption faults; never downgrade to the older cursor                                                      |
| Data/head writes finish, sync not called or interrupted/failed                                                                                       | `Uncertain`                                                                                     | Validate both heads and selected data; a coherent complete new selection may recover, an invalid selection must stop |
| `fdatasync` succeeds                                                                                                                                 | `Committed`, callback once per record after success                                             | Both valid adjacent heads select exact durable prefix and byte oracle                                                |
| Post-sync cleanup/shutdown close fails                                                                                                               | `Committed` plus cleanup failure                                                                | Stop further work; never revoke prior callbacks or publish duplicate product                                         |
| Wrong purpose/store/segment/header, slot copied to wrong offset, generation parity mismatch, equal/gapped generations or wrong preceding-slot digest | Reject                                                                                          | No head selection, data scan recovery or tail cleanup                                                                |
| All-zero operational slot, including valid root plus zero peer and nonzero tail                                                                      | Reject                                                                                          | Bootstrap ambiguity is never resolved by dropping data                                                               |
| Lower head's cursor/highwater conflicts with the authenticated prefix, or higher head skips more than one batch                                      | Reject                                                                                          | Both heads must agree on exact historical boundary, not only generation numbers                                      |
| Valid selected prefix plus partial/corrupt bounded unselected tail                                                                                   | Original data-only attempt may be `NotCommitted`; crash outcome not reconstructed as a callback | Classify and stop, or explicitly reviewed bounded zero+sync reconciliation; never decode tail as committed           |
| Nonzero tail beyond one maximum attempt, wrong inode/size, corrupt committed batch, padding, IDs or controls                                         | Reject                                                                                          | Preserve evidence; no truncation, scan-derived head or partial import                                                |
| Prefix lengths/slot lengths/offsets overflow; zero/max/over-limit span, half-slot, trailing data or unknown fields                                   | Reject before unbounded allocation or write                                                     | No out-of-range offset I/O, index slicing or arithmetic wrap                                                         |
| Competing owner, renamed/replaced directory path, moved data inode, symlink/hardlink or descriptor substitution                                      | Reject alias/ownership failure; existing descriptor stays on original directory/inode           | Stable and data-inode locks remain effective; never write through the replacement pathname                           |
| Future explicit reconciliation: fault/death during tail zeroing or its sync                                                                          | Cleanup incomplete/uncertain; no callbacks                                                      | Deferred; this kernel never performs tail mutation                                                                   |

Use syscall fault injection and child-process death around every data/head/sync
boundary. Process death does not emulate a power cut: also construct missing,
old/new, torn, zeroed and malformed authenticated slot/data states explicitly.
Tests must assert preservation of earlier committed product bytes, no silent
fallback, fixed file size/allocation, fault-latched no-continuation behavior and
exact callback counts. Error text must omit keys, plaintext and payload markers.

## Implemented test gate and API

The Linux-only helper exposes `Dir.InitializeFixedSegment(stage, name, bootstrap)`,
`Dir.OpenFixedSegment(name)`, and `FixedSegment.ReadAt`, `Activate`, `Commit`,
`AllocatedBytes`, and `Close`. Initialization requires existing stable ownership;
it durably allocates and zero-writes all 32 MiB before publishing. The supplied
bootstrap is exactly 12 KiB. Opening acquires no new protocol authority:
`Activate(cursor, slot)` trusts only the owner's already authenticated recovery
and independently rejects every nonzero tail. Reads remain available for
inspection after a write fault; another write or activation cannot clear it.
`Commit` supplies neither an arbitrary offset nor a resize operation.

The helper checks the retained parent, stable ownership name/inode, current data
name/inode, private mode, one-link status, fixed length, 4 KiB filesystem block
size and captured actual allocation. Data-only failure is `NotCommitted` and
poisons the handle; the first head write attempt changes the outcome to
`Uncertain`; definite data sync establishes `Committed`. A later validation or
close error preserves that established outcome. The benchmark callback receives
the transaction outcome exactly once per supplied product, including a committed
cleanup error; that error stops further admissions.

The focused race gate passes the implemented syscall/lock/framing/two-head/tail
matrix, including child death at data/head/sync boundaries, cross-helper
exclusion, concurrent owner preparation, authenticated lower-boundary mismatch,
selected corruption, dirty-tail reopen without mutation, malformed authenticated
PDU preflight, and committed-error callback preservation. Deferred tail repair is
not implemented or tested as a mutation. The exact command and retained logs are
in the [measurement report](../research/li-x3-storage-benchmarks.md#fixed-segment-implementation-gate-no-measurement).
Tests run on disposable test directories and do not constitute ext4 measurements
or power-loss qualification. The crash matrix composes helper-process death with
separately constructed authenticated codec/recovery states; it is not an
integrated cryptographic process-crash recovery test.

The separately approved real-ext4 40-transaction probes then passed only the
small callback floor: exact actual-admission p50/p99/max were
13.718546/18.682567/18.682567 ms for 2 records and
14.767265/39.836771/39.838384 ms for 200 records. Every record uses its batch's
actual admission timestamp before the full 10 ms accumulation wait. An earlier
modeled per-record timestamp result is explicitly superseded in the report;
its raw log remains unchanged. The second corrected probe
exercised actual usage renewal. All 80/8,000 callbacks and independently hashed
original PDU bytes matched after full authenticated reopen. Setup durably
zero-initialized 32 MiB; committed updates used the real single `fdatasync`
helper. The [measurement report](../research/li-x3-storage-benchmarks.md#fixed-segment-callback-floor-measurement)
contains exact costs, resource observations and exclusions. Sequential throughput
was 12,769.94 copies/s in the larger probe, below the eventual 20,000/s workload;
this accumulation harness does not establish concurrent admission or that
qualification. Implementation stops for review of the remaining layout,
rotation, compaction, control and throughput obligations.

## Constraints on a later production layout

Rotation cannot overwrite, wrap or reset a full segment. A successor requires its
own full capacity reservation, initialized inode, authenticated linkage/selection
and durable name before admissions can reference it. Exactly identifying the
active segment and proving predecessor retirement across directory syncs are new
protocol decisions; a filename scan or largest generation is insufficient. They
are not implemented by this kernel and their latency must be amortized honestly
in later measurements.

Completion and revocation require durable authenticated terminal/control state,
priority independent of data backlog, reserved control capacity and key usage,
and exact coordinator boundaries before claims. Consuming the final data span
cannot block a revocation or require overwriting a committed product. A mutable
head's control fields do not substitute for the lifecycle/control proof. X2 must
retain its own capacity/worker and meet its shared-device latency gate.

Compaction needs immutable original bytes/deadlines, durable relocation/terminal
intent and selection, independently reserved old/new/scratch allocation, bounded
incremental work and the original expiry reclaim deadline. It may not silently
leave revoked/expired data in a live segment indefinitely, expose stale claims,
or make deletion depend on space that full data already consumed. Full bootstrap
zeroing costs for new segments and overlap with X2/control I/O are part of the
later full-capacity/15-minute/expiry workloads. No production layout is selected
until these obligations and the frozen acceptance campaign pass.

Review and implementation gates:

- [x] Verify the authoritative fdatasync/directory-sync and ext4 journaling premises; label speedup as an inference.
- [x] Identify and remove the one-root/zero-peer ambiguity by requiring two authenticated bootstrap heads before publication.
- [x] Specify exact framing, padding, authority, bounded tail rules, bootstrap allocation, callbacks and the failure matrix.
- [x] Root review the entire narrow segment design, including rollback assumptions; explicit tail reconciliation is deferred.
- [x] Authorize only a minimal descriptor-owned fixed-file helper and benchmark codec/recovery implementation plus tests; measurement remains separately gated.
- [x] Pass the implemented fault/lock/framing/two-head/tail matrix before measurement; explicit tail reconciliation remains deferred.
- [x] After separate approval, run and preserve the 2/200 ×40 real ext4 callback-floor measurements, including usage renewal and separately reported full initialization; the small gate passes.
- [ ] If the kernel passes, review rotation, compaction, control capacity and final workload scope before extending implementation.
- [ ] Select a production layout only after the full frozen qualification and final integration repeat.
