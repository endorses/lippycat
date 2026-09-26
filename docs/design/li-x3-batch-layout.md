# Historical immutable LI journal batch prototypes

Status: **historical benchmark-only prototype designs**. The user withdrew the
agent-imposed performance thresholds and qualification campaign. Measurements
are observations, not acceptance gates or completion blockers. Further
measurement is optional and requires a user task or deployment objective.
Correctness, security and configured storage/resource limits remain in force.
Production fixed-segment journals were implemented in `8aa35687`; the
[production layout](li-x3-journal-layout.md), not these immutable prototypes,
describes that implementation.

This document retains the reviewed framing, ownership, durability and recovery
contracts for three experiments: separate immutable batch/head publication,
grouped publication, and head-container exchange. Their measured behavior is
recorded in the [measurement report](../research/li-x3-storage-benchmarks.md).
The later [fixed-segment kernel](li-x3-segment-layout.md) was a separate
experiment. Neither document is an active plan for more prototype work.

## Scope and fixed bounds

Use immutable bounded batch files, not an in-place append log. Each batch has
independently authenticated metadata and product frames, allowing metadata
recovery without materializing all payloads. One journal owns its directory,
keyring, usage ledger, commit head, data/control queues and resource budgets.
X2 and X3 use different directories, UUIDs and raw keys on the same filesystem.

The first prototype uses a newly initialized synthetic X3 batch store alongside
the unchanged X2 journal for contention measurements. It never changes the
physical interpretation of an existing X2 directory or creates a fresh ledger
for a previously used raw key. Adopting this layout for existing X2 would require
explicit format dispatch, legacy readers and a separately authorized migration
that preserves store UUID, sequence history, raw-key usage and replay policy.

| Resource                                     | Proposed bound                                                                                                     |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ |
| Intentional accumulation delay               | At most 10 ms from the oldest queued record; dispatch sooner at the byte/count ceiling                             |
| Batch plaintext                              | At most 1 MiB, including every LCS1 encrypted binding and owner payload in that batch                              |
| Frames                                       | At most 4,096, including the metadata frame; byte ceiling normally binds first                                     |
| Metadata frame plaintext                     | At most 256 KiB, including binding                                                                                 |
| Physical batch file                          | At most 2 MiB, with conservative allocated-block rounding; no batch or future segment may exceed 64 MiB allocation |
| Product indexes / pending product operations | Existing X2 1m / X3 2m ceilings and 4,096 pending operations per journal                                           |
| Pending control operations                   | 256 reserved, with coalescing only for the same exact compatible identity                                          |
| Recovery read scratch                        | A bounded 64 KiB ciphertext hashing buffer plus one metadata frame; at most one decoded product per feeder         |
| Commit head plaintext                        | At most 64 KiB, including binding                                                                                  |
| Checkpoint page plaintext                    | At most 1 MiB; at most 256 child descriptors; maximum tree depth 4                                                 |
| Commit transactions after checkpoint         | At most 4,096; start the next checkpoint by 1,024 transactions                                                     |

The prototype uses a 10 ms accumulation timer. Recorded callback ages include
worker queueing, with the timestamp-model limitations described in the measurement
report. Pending queue capacity does not establish a sustainable persistence rate.

This prototype only admits products that fit one bounded batch. Oversized input
receives a definite size rejection before ownership transfer. It must not
silently reduce the existing X2 accepted size: keep the legacy X2 reader/writer
path for larger compatible objects until an independently specified large-object
path exists. The final supported X3 maximum PDU size must be explicit in config
validation, documentation and tests; the 64 MiB parser ceiling alone does not
promise admission into a 1 MiB batch. The historical comparison used the
report's synthetic RTP payload mix, all of which fits.

## Names and framing

Stable names are `batch-<32 lowercase UUID hex>.lcb`,
`checkpoint-<32 lowercase UUID hex>.lci`, and `.head`. These names reveal no
task, call, destination or record identity. Never reuse a physical batch or
checkpoint UUID. All integers in physical framing are unsigned big endian.

Every `.lcb` file starts with this fixed 40-byte prefix:

| Offset | Bytes | Field                                                      |
| ------ | ----: | ---------------------------------------------------------- |
| 0      |     4 | `LCB1`                                                     |
| 4      |     1 | Container version, exactly 1                               |
| 5      |     1 | Interface, 1 = X2, 2 = X3; must match the selected journal |
| 6      |     2 | Flags, exactly zero                                        |
| 8      |    16 | Physical batch UUID, equal to the filename                 |
| 24     |     4 | Frame count, 1–4,096                                       |
| 28     |     4 | Metadata-envelope length                                   |
| 32     |     8 | Exact complete file length, at most 2 MiB                  |

The metadata LCS1 envelope immediately follows, then zero or more framed LCS1
product/control envelopes. Each following frame has `uint32(envelope_length)`
followed by exactly that many bytes. No padding, trailing bytes, concatenated
objects within a frame, overlap, or duplicate IDs is permitted. Validate all
counts, total lengths and subtraction/addition bounds before allocation.

The metadata payload authenticates an exact copy of the fixed prefix and an
ordered table containing each frame's offset, encoded length, SHA-256 of the
complete LCS1 frame, purpose and expected object binding. Its schema is closed
and versioned. The metadata table also carries the complete immutable record
metadata, record content digest, sequence highwater changes and exact dependent
control identities/digests. Offsets are physical locations only: they do not
replace the immutable record ID or content identity. Every plaintext bound
includes binding bytes; unknown fields, versions or purposes fail.

The reviewed shared envelope purpose **9, Journal batch/index metadata** is now
implemented with purpose-isolation and usage-classification tests. Metadata tied to new
product uses ordinary usage allowance. Terminal-only metadata, checkpoint
preservation and revocation may use control allowance. Owners must not classify
data growth as a control merely because purpose 9 can represent both.

Metadata bindings are `batch/<batch UUID>` and checkpoint pages use
`index/<checkpoint UUID>`, always under the independently authenticated journal
UUID. Product frames retain purpose 3/4 and the canonical decimal record-ID
binding. Call and revocation frames retain purposes 7/8 and their exact canonical
composite bindings. Sequence identities remain interface-specific; metadata
grouping does not merge contexts or destinations.

Control versions form an authenticated predecessor chain. A product's referenced
open control proves its durable admission prerequisite; it does not override a
later closed/revoked version. Claims use the current monotonic control state.
Retain needed predecessors until a committed checkpoint proves their ancestry
and summarizes the latest state without weakening any covered boundary.

A product frame's owner payload is `LRB2`, `uint32(metadata_length)`,
`uint32(pdu_length)`, strict version-2 metadata JSON with the `data` field omitted,
then the original encoded PDU bytes. Metadata is bounded by the existing 64 KiB
limit including binding. The logical schema, timestamp validation, provenance
union and content digest are exactly those in the parent contract. The metadata
copy in the index must match the authenticated product frame on read. Decode the
actual PDU type, XID and sequence context before admission and again on replay;
an outer X3 label cannot turn an X2 frame into X3. Original PDU bytes and absolute
deadlines never change during batching or compaction.

## Commit head and transaction graph

`.head` is one atomically replaced purpose-6 LCS1 object bound to
`journal-state`. Its closed version-3 schema contains journal UUID, interface,
monotonic commit revision, current transaction UUID/digest, checkpoint root
UUID/digest/revision, reserved record-ID highwater, control/fault status and any
bounded in-progress checkpoint/GC intent. It contains no unbounded file list.
Head version 3 is separate from the envelope and record schema versions.

Each transaction metadata frame identifies the previous committed transaction
UUID/digest/revision and its own non-wrapping revision. The head selects exactly
one chain back to the authenticated checkpoint root. Transaction kinds are a
closed union: product batch, terminal/control batch, rewrite, checkpoint publish,
or GC completion. Each kind has only its own allowed fields. Product batches
add exact immutable records and sequence changes; terminal batches reference
exact IDs/identities and cannot create product or authorize replay. Rewrites map
old physical locations to new locations with unchanged content digests.

The checkpoint is a bounded authenticated tree of index pages. Leaf entries are
strict tagged product-location, sequence-context, call-control, revocation or
terminal/highwater entries. Branch entries contain child UUID, digest, exact
byte length, entry count and disjoint ordered key range. Check cumulative counts
against the selected journal's product/sequence/control ceilings before building
indexes. No duplicate identity, overlapping range, unexpected child, cycle or
over-depth tree is accepted. The root plus later transaction deltas defines the
entire live catalog; absence from a filename scan never grants authorization.

Record IDs are nonzero uint64 values. Reserve IDs in advance through the head,
in chunks of 4,096; after restart consume the whole previously reserved range.
Unused IDs may be skipped. The producer does no filesystem I/O: if the next
reservation is not ready, reject admission with bounded backpressure instead of
waiting. Highwater reservation and transaction publication share the same head
commit serialization. Exhaustion fails closed, with no wrap or reuse. Reserved
admission IDs also bound revocations over writes still pending at their boundary.

## Acknowledgement and error ordering

The historical baseline specifies this transaction order, including head and
control I/O.

Reserve product, metadata, future terminal-control, index and pending-memory
allocations before admission success. Clone or retain immutable PDU ownership
once and assign the exact record/admission identity. Establish required call-open
or other dependent controls durably; product metadata references their exact
identity, version and digest.

Build and seal bounded product/index frames using real durable usage reservations.
Coalesce sequence updates only by exact full context and the existing wrap-aware
ordering rule. Create the immutable batch through the descriptor-owned directory:
full write, file sync, publication and directory sync. Batch publication alone
acknowledges no record.

Under commit serialization, verify the old head revision and required controls,
then atomically replace and sync `.head` to select the transaction. Its sequence
updates and index metadata are already inside the authenticated batch. Only
then invoke each admission callback exactly once. Recheck the in-memory
revocation/expiry gate before eligibility publication; a successful persistence
callback alone grants no transport claim.

This conservative baseline has a batch publication and a head publication. Its
real sync costs must be included in the comparison; do not benchmark only the
first write. A descriptor-safe grouped publication helper could reduce redundant
directory syncs, but it is a separately reviewed optimization: all prerequisite
files must be synced and installed before a head can reference them. Its crash
matrix and typed outcomes are part of that helper's correctness contract.

Before batch publication, definite failure yields `NotCommitted`. If the batch
exists but the head is definitely unchanged, no callback succeeds and no record
is claimable. Clean up only that known unreferenced artifact under ownership; a
cleanup failure is surfaced. Once the head replacement may have happened, report
`Uncertain`, latch the journal fault, and never blindly roll back or retry as a
new record. A committed head with later cleanup/close failure retains committed
authority and reports the cleanup error. Usage-ledger failure retains its separate
reservation outcome; it never masquerades as product commitment.

## Startup and corruption

Acquire exclusive descriptor-based ownership, validate the key/usage ledger,
authenticate the head and checkpoint, then walk the exact committed graph.
Every referenced file must exist with its expected ownership, link count,
length, interface, UUID, hash and framing. Authenticate index/control metadata
before using it. Stream-hash all referenced product-frame ciphertext against its
authenticated index digest with bounded scratch. This reads ciphertext but keeps
payload allocation/decryption lazy. On a later claim, open the exact product
frame and validate its binding, full metadata, content digest and encoded PDU.
Benchmark startup ciphertext I/O explicitly; do not label a deferred corruption
check as completed recovery.

A corrupt or truncated committed batch, missing referenced file, unknown
version, bad index, or mismatched checkpoint faults recovery. Never interpret it
as an empty store or truncate it away. Immutable files have no discardable tail
inside their committed length. The only automatically discardable partial bytes
are recognized uncommitted temporary files that the authenticated head/catalog
cannot reference. A complete unreferenced batch is not automatically garbage:
validate and reconcile it against a durable rewrite/GC intent or fault for
explicit recovery. This deliberately favors a recoverable stopped store over
discarding potentially committed evidence after an interrupted head update.

Every recovered product is held. Current administrative reconciliation, exact
state/task/destination/capture incarnation, applicable revocations and the original
deadline remain mandatory. A historical open call is not permission to attach
new capture. Coherent old-backup rollback remains unsupported without a fresh
write key and current reconciliation, as in the parent contract.

## Controls, expiry and reclamation

Control admission has its own reserved queue, index entries, disk allocation and
key-usage allowance. Mark a revoked scope blocked synchronously under the
authorization owner, then enqueue its exact durable control outside read-map
locks. The control covers both committed record highwater and reserved admission
highwater; a later product callback cannot escape it. Acknowledge administrative
revocation only after the relevant journal head selects its control and the
administrative owner has completed the matching obligation.

The commit worker checks reserved control work between data batches, and does
not wait for an entire data backlog to drain. It cannot preempt an in-flight OS
sync. The protocol must fault on control-capacity exhaustion
rather than borrow X2 space or report successful revocation.

Transport completion creates a bounded terminal delta and removes in-memory
claimability immediately. Keep the physical product until that delta's head
commit is durable. A crash before durable completion may replay it as held;
neither local transport write nor terminal bookkeeping proves MDF receipt.

An independent indexed deadline sweeper uses original absolute deadlines and
runs even when disconnected or awaiting approval. Check expiry again immediately
before every transport claim. Claim suppression and physical reclamation are
separate operations. Cancellation and expiry never refresh admission/capture
timestamps or recompute a later deadline.

Fully dead batches are reclaimable after terminal controls are committed.
Bulk cleanup may unlink at most 128 validated owned files before one directory
sync; failure preserves a durable GC intent and typed uncertain outcome. This
requires an explicitly reviewed descriptor-based helper, not pathname deletion
or omission of the final sync. Bulk deadline expiry can require many such
operations; the protocol gives no elapsed-time guarantee for their completion.
Partially live batches are incrementally rewritten, at most one 2 MiB batch per
rewrite unit: verify original frames, retain the same IDs/content/deadlines,
publish the replacement, commit the location replacement in the head, then unlink
the old batch and sync the directory. All newly created files and the full overlap
must be reserved first. A durable GC intent identifies old files awaiting unlink;
restart verifies the new location before completing removal. Never remove the
last durable sequence/highwater or applicable revocation evidence with old data.

Checkpoint construction pins a committed index revision, writes bounded pages
incrementally, and records later changes in the bounded transaction chain. The
owner must provide a consistent immutable index view without a multi-million-entry
pause in producer admission. Charge pinned/COW metadata and every new checkpoint
page to explicit memory/scratch reservations. Publish the new root through the
head only after every referenced page is synced. If the operation cannot finish
within its reserved resources and transaction bound, stop data admission; do not
drop deltas or grow an unbounded log. Control capacity remains available.

After checkpoint publication, transactions older than the checkpoint may be
removed only when no live product/control frame still occupies them. Checkpoint
selection and GC intent survive restart. Controls are collectible only when no
covered product, pending admission/callback, historical approval or required
checkpoint can still reference them. Sequence/record highwaters survive deletion
of the last corresponding product.

Data may use at most 80% of the journal budget. Controls reserve at least 10%
and 4 MiB; scratch reserves at least 10% and twice the maximum admitted allocated
object. Larger checkpoint generations require their entire additional allocation
before starting, including pinned old pages. Reject an inadequate configuration.
Count directory blocks, usage/lock files, every index/transaction/control file,
temporary, conservative pending allocation and simultaneous old/new copies.
Reclamation must not rely on a destination borrowing another's reserved share.

## Historical comparison scope

The intended adapter included admission callbacks, independent disk readers,
completion, flush/close, held recovery enumeration, exact control publication,
claim gating, expiry sweeping, capacity accounting and fault injection. The
implemented small kernels covered only the subsets stated in the measurement
report. Their timings included per-copy encryption, real usage reservations,
index construction and head publication, while omitting TLS and the unimplemented
runtime work. A small publication probe does not establish complete client cost.

X2 and X3 retain separate workers, controls and capacity even when their storage
shares a physical device. The old comparison proposal used concurrent X2 traffic
and an X3 outage/recovery scenario; it is historical context, not a pending test
campaign or an elapsed-time guarantee.

## Reviewed grouped publication experiment

The measured kernel performs four synchronous durability calls per transaction:
batch file sync, batch parent sync, head file sync, head parent sync. Its
200-record callback median is approximately 47 ms even without sustained queueing.
The reviewed narrow experiment retains the same authenticated graph and framing
while publishing the batch and head through one descriptor-owned operation.
It is implemented only as a generic securestore helper plus a benchmark kernel;
the actual X2 journal and production X3 behavior do not use it. The ext4 probe
reported exact medians of 27.071412 ms for 2 records and 36.230369 ms for 200
records, including the latter's real usage-reservation renewal. The report
preserves these observations and the modeled-arrival timestamp limitation.

The helper accepts exactly one immutable prerequisite batch and one
replacement head in the same already locked private directory. It is not a
cross-directory transaction API. Validate both basenames, the existing head's
private regular inode, the expected old head identity/revision at the owner,
and all configured size/reservation bounds before starting. Retain the existing
stable ownership locks and replacement-inode locks throughout. Allocate two
exclusive private temporary files with complete random names and write their
full ciphertext. No caller-provided path is reopened outside the held directory.

After both full writes, sync the two temporary file descriptors concurrently
using exactly two bounded workers, and join both results. The files are
independent encrypted objects and already reference the same authenticated
transaction. Concurrent file sync is an I/O scheduling optimization, not weaker
durability: both must finish successfully before either commit-bearing name is
published. A failed write/sync/close at this stage publishes no new head and
returns `NotCommitted`, with cleanup errors retained.

Under the same directory/commit ownership, publish the batch with no-replace
semantics, then atomically replace the head. Never publish the head first.
Finally sync that parent directory once. Only a successful final directory sync
makes the transaction `Committed` and permits callbacks. Transfer/retain the
head's replacement inode lock exactly as the existing private-file writer does.
The helper must not call the public `Create`/`Replace` wrappers internally and
thereby accidentally keep their redundant intermediate directory syncs.

| Interruption                                                    | Live outcome / callback                                                                                         | Authenticated restart behavior                                                                                                                                                                                                                              |
| --------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Usage reservation fails                                         | Outer product `NotCommitted`; reservation retains its own definite/uncertain outcome; no batch/head publication | Validate the existing ledger; never reset or infer its reservation from files                                                                                                                                                                               |
| Either temporary write, file sync or prepublication close fails | `NotCommitted`; no success callback                                                                             | Old head remains authoritative; only recognized unreferenced temporaries are cleanup candidates                                                                                                                                                             |
| Batch no-replace publication fails before head rename           | `NotCommitted` for the transaction; retain prerequisite publication/cleanup outcome                             | Old head remains authoritative; a complete extra batch requires known-intent reconciliation or a stopped store                                                                                                                                              |
| Batch published, head rename definitely fails                   | `NotCommitted`; no callback success                                                                             | Authenticate old head; reconcile the complete unreferenced batch, never infer admission from its presence                                                                                                                                                   |
| Head rename succeeds, process dies before shared directory sync | No acknowledgement was emitted; runtime outcome would be `Uncertain`                                            | Old head, new head, or incomplete name persistence is possible; verify the selected head and every referenced batch. If new head references a missing/invalid batch, stop with a fault. Never fall back to an older head merely to obtain a successful open |
| Shared directory sync fails                                     | `Uncertain`, latch owner fault, preserve both names/evidence                                                    | Same full graph validation; do not blindly undo the rename or delete a possibly referenced batch                                                                                                                                                            |
| Shared directory sync succeeds                                  | `Committed`; callback once per record after current authorization/expiry gate checks                            | New head and its synced prerequisite are authoritative                                                                                                                                                                                                      |
| Postcommit cleanup or handle close fails                        | `Committed` plus cleanup error; no duplicate publication or rollback                                            | Authenticate new head and reconcile cleanup separately                                                                                                                                                                                                      |

The shared-directory ordering intentionally allows a stopped store after an
unacknowledged crash if the new head survived but its batch name did not. It does
not promise atomic multi-file rollback. Previously committed data is never
deleted during this operation. Only a definitely successful final sync permits
success acknowledgement. This stopped-store tradeoff was explicitly reviewed
for the small kernel. Tests cover syscall failure outcomes, process death around
publication, and authenticated recovery with a missing selected prerequisite;
process death is not a physical power-cut test.

### Implemented helper and kernel contract

The helper API is
`(*securestore.Dir).CreateAndReplace(newName string, newData []byte, headName string, headData []byte) (Outcome, error)`.
It accepts exactly two distinct safe basenames relative to one open directory.
The new name must be absent; the existing head must be a private regular file,
1 through `MaxGroupedHeadBytes` bytes, and match the inode owned by an active
`Dir.Lock(headName)` on this descriptor. Its new ciphertext is bounded by
`MaxGroupedHeadBytes = 64 KiB + MaxHeaderBytes + 16`, while the prerequisite is
bounded by `MaxGroupedNewBytes = 2 MiB`; zero lengths are rejected. Both writers
are closed before names are published. The head's stable sidecar remains locked
and the replacement inode lock is transferred without a gap. If the caller also
holds a new-name lock through this directory, its inode lock is transferred on
publication too. The journal-wide owner is the head lock; the helper does not
require an accumulating permanent sidecar for every immutable batch.

The owner authenticates the expected old head/revision, reserves conservative
pending allocation plus old/new metadata and scratch, and encrypts both inputs
with independently durable usage reservations before calling this generic byte
writer. The helper enforces fixed byte/path/inode limits; it is not the journal's
quota manager and performs no encryption. The probe is separately bounded to 40
batches, at most 81 MiB of retained/pending artifacts, with 1 GiB free required
before opening a store. This prototype does not implement production capacity
and reclamation handling.

The benchmark's exact synthetic schema remains distinct from the proposed
production schema. Each purpose-4 product contains `LRB2`, a 4-byte big-endian JSON
length, a 4-byte PDU length, closed JSON fields `kernel_version` (1), `journal`, `id`, `xid`, `did`,
`sequence_next`, `original_bytes`, `pdu_sha256`, `control_sha256`, then unchanged
synthetic PDU bytes. The prefix is the 40-byte `LCB1` framing above. Its purpose-9
index has a fixed 108-byte header: the exact 40-byte prefix, previous batch UUID
(16 bytes), previous ciphertext SHA-256 (32), revision (8), previous record-ID
highwater (8), and record count (4). Each product entry has a 56-byte fixed part
(record ID 8, frame-length-prefix offset 8, envelope length 4, SHA-256 32, metadata
length 4) followed by that exact product JSON metadata, all integers big endian. Recovery also
authenticates each product and its exact durable control dependency; the probe
is eager and is not the final lazy index recovery implementation.

The purpose-6 `.head` has closed JSON fields `kernel_version` (1), `journal`,
`revision`, `tip`, `tip_sha256`, `last_id`, `call`, `control_one_sha256`, and
`control_two_sha256`. UUIDs use canonical UUID JSON strings; SHA-256 uses lowercase
hex. It binds to `journal-state`. Indexes bind to `batch/<UUID>` and products to
their canonical decimal IDs under the same authenticated store UUID. The two
purpose-7 control files contain the literal synthetic call-open dependency and
bind to `call/<call UUID>/<XID>/1/<DID>/1`; this is a durability dependency, not a
claim that production lifecycle policy has been implemented.

Each kernel callback carries `(Outcome, error)` once per record after publication
returns. Only `Committed, nil` is success. A postcommit cleanup failure remains
`Committed` plus error and advances the selected in-memory head, preventing a
duplicate admission; all errors latch the owner fault. Before-head failures can
leave complete orphans and stop; recovery rejects complete unreferenced batches.
After-head uncertainty stops. Recovery selects only the authenticated head and
fails when its batch is absent/invalid, even if the earlier chain is intact.
Neither the helper nor the kernel performs an unsafe automatic orphan rollback.

Key-usage reservations remain independently durable **before** any nonce is
used. They cannot be folded into the shared final directory sync. Batch frames,
index, head, failed attempts and abandoned temporaries all consume the real
ledger. Close the usage reservation operation before preparing a grouped
publication to avoid holding a directory mutex while recursively writing that
same directory. Neither parallel file sync nor retry refunds a reservation.

The original latency hypothesis was one parallel file-sync round followed by
one parent-sync round, plus encryption and modeled average accumulation age.
Serializing both file syncs would instead require three sequential sync rounds.
The measured grouped probe includes actual reservation-renewal batches and head
I/O. Its harness reports histogram upper bounds and exact nearest-rank callback
p50/p99 from at most 8,000 retained durations (64 KiB), with the timestamp erratum
recorded in the measurement report.

This prototype does not measure completion and checkpoint costs.
Completion should commit bounded terminal deltas in the same grouped protocol,
with immediate memory claim suppression but no physical data deletion until the
terminal head is durable. Coalesce compatible terminal IDs up to the existing
byte/count/timer bounds. Control updates get priority over data backlog and
their own reservations; arbitrary waiting for a large completion batch is not
allowed. Batched unlink plus a directory sync amortizes reclaim, while a durable
GC intent retains restart authority. Incremental checkpoints still write and sync
all newly referenced pages before their root enters a committed head. They may
use reviewed bounded groups, but require the full additional scratch reservation.
These protocol costs are absent from the small measurements reported here.

## Reviewed head-container exchange experiment

This section records the reviewed small benchmark experiment: its bounded
helper, codec, recovery checks and calibration. It did not become the production
layout or implement the production checkpoint/compaction design. Existing X2
directories are never opened through this format. The experiment used a fresh
synthetic key, authenticated usage ledger and private directory, and the same
2/200-record, 40-transaction, 10 ms accumulation probes.

Implementation and calibration are complete. Exact callback medians were
28.607633 ms (2 records) and 29.515850 ms (200 records), including the latter's
real usage-reservation renewal. These are modeled-arrival observations with the
limitations in the [measurement report](../research/li-x3-storage-benchmarks.md#head-container-exchange-kernel-measurements).

### Container names, framing and authentication

Use `.head` for the selected container, `head-<32 lowercase UUID hex>.lhc` for an
archived container, and `.lch-stage-<32 lowercase UUID hex>.tmp` for the one
candidate/displaced container. Each newly prepared container has a fresh nonzero
UUID. The staged name always contains the **new attempt's UUID**: after exchange
it contains the old head's bytes, whose internal UUID is different. Archive names
always contain the archived object's own authenticated UUID. None of these
names reveal call, task or destination identity. All objects must remain private
regular mode-0600 files with link count exactly one. No hardlinks or exceptions
to the private-file validator are permitted.

A container is exactly a 48-byte prefix, optionally one complete existing `LCB1`
batch, then one purpose-6 LCS1 head envelope. All fixed integers are unsigned big
endian. No padding, trailing bytes, extra batches, overlapping sections or
concatenated envelopes are allowed. The prefix is only a bounded parsing hint
until its exact bytes are authenticated by the head.

| Prefix offset | Bytes | Field                                                        |
| ------------- | ----: | ------------------------------------------------------------ |
| 0             |     4 | Magic `LCH1`                                                 |
| 4             |     1 | Container version, exactly 1                                 |
| 5             |     1 | Interface, exactly 2 (synthetic X3 experiment)               |
| 6             |     1 | Kind: 0 = initial root, 1 = product transaction              |
| 7             |     1 | Flags, exactly zero                                          |
| 8             |    16 | Nonzero container UUID                                       |
| 24            |     4 | Embedded batch length; zero only for root, otherwise 1–2 MiB |
| 28            |     4 | Exact LCS1 head-envelope length                              |
| 32            |     8 | Exact whole-container byte length                            |
| 40            |     8 | Reserved, all zero                                           |

The head envelope uses purpose 6 (`JournalState`) and the existing binding
`{Store: independently authenticated usage-ledger UUID, Object: "journal-state"}`.
Do not take the expected store identity from the untrusted prefix or head. Its
owner payload is the following fixed 248-byte **kernel-only** binary schema,
which is distinct from the proposed production version-3 JSON head:

| Head payload offset | Bytes | Field                                                              |
| ------------------- | ----: | ------------------------------------------------------------------ |
| 0                   |     4 | Kernel head magic `LHK1`                                           |
| 4                   |     2 | Kernel schema version, exactly 1                                   |
| 6                   |     2 | Reserved, zero                                                     |
| 8                   |    48 | Exact complete outer prefix                                        |
| 56                  |    16 | Journal UUID, equal to the expected authenticated store            |
| 72                  |     8 | Commit revision                                                    |
| 80                  |    16 | Predecessor container UUID, or zero for root                       |
| 96                  |    32 | SHA-256 of the entire predecessor container, or zero for root      |
| 128                 |    32 | SHA-256 of the exact embedded batch bytes; SHA-256(empty) for root |
| 160                 |     8 | Record-ID highwater                                                |
| 168                 |    16 | Synthetic call UUID, nonzero and unchanged through this store      |
| 184                 |    32 | First durable purpose-7 control-file ciphertext SHA-256            |
| 216                 |    32 | Second durable purpose-7 control-file ciphertext SHA-256           |

Digest fields are raw 32-byte values; UUIDs are raw 16-byte values. The head
payload has no self-digest. The predecessor's whole ciphertext digest is known
before building the new container. The batch is encrypted first and its digest
is then known. For a key ID of `K` bytes, the head envelope has exactly
`32 + K + 18 + 13 + 248 + 16 = 327 + K` bytes: LCS1 header/nonce, binding framing,
`journal-state`, fixed payload, and tag. Thus the prefix's lengths are computed
once before head sealing. There is no circular digest, size iteration or
variable-width serialization dependency. Sealing must assert this predicted
length; decoding must validate both the selected header's actual key-ID length
and this exact length formula.

With the existing maximum 64-byte key ID, the head envelope is at most 391 bytes
and the exact maximum physical container is
`48 + 2,097,152 + 391 = 2,097,591` bytes. Reject this ceiling before allocation,
and check lengths with subtraction from the already bounded file length before
forming offsets or converting to `int`. The embedded batch keeps all current
bounds: 2 MiB physical, 1 MiB combined plaintext including bindings, 256 KiB
metadata plaintext including binding, and at most 4,096 frames. The purpose-6
payload must be exactly 248 bytes. Unknown kind/version/flags/reserved values or
mismatched lengths, identities, prefix copies and digests fail closed.

For a product transaction, the embedded `LCB1` UUID equals the outer container
UUID. Its authenticated index revision equals the head revision; its prior
record highwater equals the predecessor head's highwater; its contiguous new
record IDs end at the new head's highwater. The index's previous-batch UUID/hash
match the predecessor's embedded batch, or are both zero when the predecessor is
the root. Therefore the first product's container predecessor is the nonzero
root UUID even though its `LCB1` previous-batch UUID is zero. Subsequent product
heads increment revision by exactly one without wrapping. The batch's existing
purpose-9 index, per-product purpose-4 framing, original PDU bytes, exact sequence
evidence, XID/DID identities, call-control bindings and ciphertext hashes remain
unchanged and are authenticated using the existing bounded kernel reader.

### Exact initial root

A newly initialized root has kind 0, a fresh nonzero container UUID, no embedded
batch, revision 0, record highwater 0, zero predecessor UUID/digest, and
SHA-256(empty) as its batch digest. It still contains the full authenticated head
and the actual nonzero synthetic call UUID and both actual control ciphertext
digests. Its exact file length is `48 + 327 + K = 375 + K` bytes (381 bytes for
the benchmark's six-byte `kernel` key ID). A root elsewhere in a chain must have
this same representation; kind 0 is not an escape hatch for malformed products.

Initialization remains separate from an exchange. In a proven fresh disposable
store, initialize the usage ledger durably, write both real purpose-7 control
files durably, then encrypt the root using the same usage ledger. Under the
existing `.head` ownership lock, create its exclusive staged name, fully write,
sync and close its writer while retaining its inode lock, publish `.head`
without replacement, and sync the directory. Initialization succeeds only after
that sync. Root initialization emits no product callbacks. An interrupted used
store with no valid `.head` does not qualify as empty and cannot initialize a
new key ledger/root automatically; stop and preserve its evidence.

### Exchange operation and ownership

The proposed helper remains a descriptor-owned byte writer, not a codec or
quota manager. It receives the new staged basename derived from the candidate
UUID, the archive basename derived from the authenticated old head UUID, and
the complete bounded encrypted container. It requires active `.head` ownership
through the same `Dir`; it never reopens a caller-supplied path outside that
descriptor. The owner authenticates the old head, computes its full ciphertext
digest and validates the candidate's predecessor binding while that ownership
is held. Before preparing files, reject pre-existing stage/archive targets,
unsafe names, aliases, unknown inode identity or an unowned/missing old head.

The implemented Linux API is
`Dir.ExchangeAndArchive(stage, head, archive string, data []byte) (Outcome, error)`
in `securestore/exchange_linux.go`. `archive == ""` is an explicit initial
no-replace publication request requiring an absent head under active ownership;
a nonempty archive always requires the existing owned head. There is no inferred
initialization when a used head is missing. The helper enforces `MaxExchangeBytes
= 2,097,591`, distinct safe nonreserved basenames, stage/archive absence, and
private current/staged inode identity before exchange. Only the owner's codec
assigns the `LCH1` namespace and predecessor semantics. A new `fileOps.exchange`
seam exposes syscall fault injection without altering existing Create/Replace or
grouped behavior; non-Linux builds have an unsupported exchange stub.

The helper serializes the operation under the directory/owner mutexes in the
existing lock order. Keep the stable `.head` sidecar and old data-inode lock,
then create one exclusive no-follow mode-0600 staged inode. Retain a duplicate
open-file description with its own inode flock before closing the writer.
Fully write the container, sync that single file, and close the writer. Any
write/sync/close error here prevents exchange. Recheck the current `.head`
basename's private inode against the owned old data inode before publication.

Call descriptor-relative `renameat2(stage, .head, RENAME_EXCHANGE)`. Both names
must exist and have different private inodes. An unsupported or rejected exchange
returns `NotCommitted`; do not emulate it using hardlinks or multiple ordinary
renames. On successful exchange, immediately transfer `.head`'s data-inode lock
to the already locked new inode without any unlock/reopen gap; retain the old
inode lock while it occupies the stage. This is the irreversible publication
boundary for outcome classification, even though no callback is yet allowed.

Rename the old staged inode without replacement to its authenticated archive
basename. Use `RENAME_NOREPLACE` on the same descriptor; archive collisions
remain failures even if the colliding bytes appear identical. Finally sync the
parent directory once. Only that success makes the transaction `Committed` and
permits a once-per-record callback. Keep the retired old-inode lock through the
final sync, then close it; `.head`'s new inode and stable sidecar remain owned.
Do not acquire a permanent sidecar for every immutable archive. The journal-wide
head owner protects this experiment's archive namespace.

Before exchange, an owned live failure may unlink only the just-created candidate
whose descriptor identity still matches its staged name; retain cleanup errors,
and treat uncertain cleanup as requiring reconciliation before retry. After
exchange, no failure path may delete the staged inode, swap back, overwrite an
archive or select an older head. Preserve the displaced committed content and
latch the owner fault. An error after the final directory sync is a
`Committed` cleanup error, not permission to retry admission or roll back.

The small helper chooses the stricter preservation option: every failed staged
write is left for explicit owner investigation after closing its descriptors,
even when still `NotCommitted`. It performs no stage unlink or automatic retry.
The kernel latches every error; committed cleanup errors advance its in-memory
head while stopping further publication. It authenticates the current head and
checks its full ciphertext digest before every candidate, inside callback timing.

### Startup and bounded reconciliation

Acquire the journal's stable `.head` ownership before any recovery or cleanup.
Inventory only bounded recognized names through the held directory descriptor.
The experiment accepts at most 128 product revisions plus one root: at most
128 archived containers, one selected `.head`, and one staging name. A second
staging name, excess archives, unknown namespace, non-private inode, symlink or
hardlink stops startup without deleting evidence. Metadata/usage/control names
must match the existing exact owner whitelist and accounting rules. Directory
walking must stop at the configured bound rather than collecting an unbounded
filename slice. This experiment does not claim the final million-record lazy
recovery or checkpoint implementation.

First authenticate `.head` using the trusted store UUID, validate its exact
prefix/head/batch/controls, then traverse only the predecessor archive names and
whole-container digests authenticated by that selected chain. Each step checks
the archive filename UUID, embedded UUID, stable journal identity, revision
adjacency and record/sequence continuity. Stop at the exact root; reject cycles,
unreferenced complete archives, excess depth and any corruption. A selected
head missing its required predecessor is a stopped store even if the previous
head or product remains recoverable elsewhere. Never search for an older head
that happens to pass, infer commit from the largest revision, or treat missing
names as successful rollback.

`.lch-stage-*` is **never** eligible for `RecoverTemporaries`; that routine deletes
recognized `.securestore-tmp-*` files and cannot tell whether an inode contains
already committed content. Normal runtime startup performs validation only and
stops when staging reconciliation is needed. An explicitly invoked offline
owner may inspect at most the one bounded staged object and report/classify it:

| Recognized state                                                                                                    | Required evidence                                                                                                                                                                                       | Permitted explicit reconciliation                                                                                                                      |
| ------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Unpublished complete candidate                                                                                      | Stage suffix equals candidate UUID; candidate revision is selected head +1; predecessor UUID/hash exactly select the current authenticated head; candidate batch/head and controls validate             | Discard that exact candidate under ownership, sync directory, then reopen/validate; no record callback and no usage refund                             |
| Displaced predecessor after exchange                                                                                | Stage suffix equals current head UUID; staged internal UUID/hash exactly equal the selected head's required missing predecessor; staged container and its earlier chain validate; archive target absent | No-replace rename that exact inode to the required archive, sync directory, then reopen/validate the whole selected chain; emit no historical callback |
| Any other state, including malformed/partial staged bytes, target collision, multiple stages or unexplained archive | Insufficient unique authenticated transaction evidence                                                                                                                                                  | Preserve all names and stop for external investigation; never guess, delete, fallback or automatically reset                                           |

Reconciliation must hash and authenticate before mutation, retain descriptor
identity/locks through the operation, reserve its bounded metadata work, and
return its own durable outcome. An interruption remains stopped until another
explicit reconciliation validates the new inventory. It cannot fabricate an
acknowledgement that the interrupted writer never emitted. A healthy reopen
with a complete selected chain after an unacknowledged publication may recover
those products; the eventual replay/authorization policy remains a separate
owner obligation, unchanged by this storage experiment.

The approved small implementation deliberately stops after read-only stage
classification. It does not implement either offline reconciliation mutation;
those operations remain outside this historical prototype. Both complete candidate/displaced classifications and
unclassified partial objects preserve all evidence and prevent startup. This
deferral does not permit normal runtime cleanup or incomplete-chain recovery.

### Capacity, accounting and measurement

Use the same independent durable usage reservations before every product, index
and head nonce. Head/index metadata that introduces new products uses ordinary
`Seal`, not reserved control allowance. Root and both controls also consume real
usage. There is no usage refund on preparation failure, exchange failure,
reconciliation or abandonment, and no ledger publication is folded into the
container's directory sync.

Before preparing a candidate, reserve its conservatively rounded maximum
allocation plus directory growth and required usage/metadata work, while charging
all retained archives, current head, controls, usage ledger, stable lock,
recognized staging, pending allocation and scratch. Exchange/rename move names
and do not free the displaced old inode; archived old bytes remain charged.
Budget old plus new simultaneously and retain staging charges on every fault.
Reserve enough to finish archive publication and sync even when product capacity
is exhausted. The generic writer enforces fixed size/path/inode limits; the
owner is responsible for quota accounting and rejection before transfer.

The narrow probe permits 40 product transactions: at most 40 product containers,
one small root and one in-flight candidate. A conservative 96 MiB artifact
budget includes 4 KiB-rounded maximum containers, controls, metadata, directory
growth and disk scratch for reconciliation; stop before exceeding it. For this
4 KiB ext4 allocation unit, round each maximum container to 513 blocks, so even
41 maximum product containers consume only 86,151,168 bytes before the root and
reserved metadata/scratch. Reject a different allocation unit unless the same
96 MiB bound is recomputed and remains sufficient. Independently reserve at most
16 MiB of codec/read memory, counting simultaneously live PDU, frame, metadata,
batch, container and hash buffers; report actual peak usage rather than assuming
buffers alias. Keep the exact-percentile sample bounded to another 64 KiB. Require
at least 1 GiB available on the declared ext4 volume before creating the private
disposable store. Never accept production directories, keys or capture payloads.
Clean completed disposable stores after preserving the requested measurements.

The recorded measurements include 10 ms accumulation, per-record callbacks,
product/index/head encryption, usage renewal and the full file-sync/exchange/
archive/directory-sync operation. Root/control initialization is reported
separately. Recovery authenticates the same retained chain; the report preserves
allocation, reservation counters and sequential copies/s. These small probes do
not establish sustained-arrival, control-pressure, reclamation or X2-contention
performance.

### Required fault, crash, cleanup and lock matrix

| Boundary or injected condition                                                                              | Live transaction outcome / ownership                                                                                      | Startup or follow-up requirement                                                                          |
| ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------- |
| Invalid framing/binding/UUID/length/digest, capacity rejection, or usage-reservation failure                | `NotCommitted`; no exchange or callback success; preserve separate usage outcome                                          | Existing head remains selected; usage fault cannot reset ledger                                           |
| Candidate create/write/short-write/file-sync/prepublication-close failure                                   | `NotCommitted`; stable/old-inode locks remain; close new handles, limited own-candidate cleanup only                      | Partial candidate preserved if cleanup uncertain; never generic stage deletion                            |
| Process death before exchange                                                                               | No success callback; current head remains selected                                                                        | Authenticate inventory; complete unpublished candidate requires explicit discard, partial candidate stops |
| Unsupported/rejected exchange, including inode substitution detected before call                            | `NotCommitted`; old head ownership remains; no fallback syscall sequence                                                  | Old head and candidate retained/cleaned according to known ownership                                      |
| Successful exchange, before lock transfer or archive rename; process death at either boundary               | Live outcome becomes `Uncertain` immediately; stable lock never released, new inode was already flocked, retain old inode | New head may lack predecessor archive; stop, preserve displaced stage; no older fallback                  |
| Archive target collision, archive rename failure, or close/cleanup failure after exchange before final sync | `Uncertain`; no rollback/unlink of stage; latch owner fault                                                               | Inspect authentic selected head and preserve all evidence; collision never silently accepted              |
| Process death after archive rename but before parent sync                                                   | No success callback; never assume both names persisted merely because renames returned                                    | Validate selected graph; any missing/invalid predecessor stops; no fallback                               |
| Parent-directory sync failure                                                                               | `Uncertain`; owner stops, all staged/archive evidence retained                                                            | Authenticate selected head and dependencies; explicit reconciliation if needed                            |
| Parent-directory sync succeeds                                                                              | `Committed`; one callback per record after success, new `.head` stable/inode locks retained                               | New selected graph must authenticate; test exact immutable bytes and highwaters                           |
| Retired-inode close or other cleanup error after successful parent sync                                     | `Committed` plus error; advance selected in-memory head, stop owner, never duplicate callback/admission                   | No rollback; reconcile cleanup separately                                                                 |
| Directory pathname renamed/replaced while descriptor is held                                                | Operation remains in the original descriptor directory; no new path lookup                                                | Competitors cannot acquire stable or moved data-inode locks; no writes in replacement directory           |
| Competing owner, moved `.head` alias, symlink/hardlink or substituted inode                                 | Reject before mutation; never split ownership                                                                             | Maintain private no-alias validation and both stable/data lock tests                                      |
| Current valid head references missing/corrupt archive while an older intact chain exists                    | Startup fails closed                                                                                                      | Never select the older chain; explicit evidence-preserving reconciliation only                            |
| Staging cap, unknown names, malformed stage, invalid authenticated fields or arithmetic boundaries          | Bounded rejection before unbounded allocation or cleanup                                                                  | Preserve all objects; no best-effort import or partial recovery                                           |
| Death/retry during either explicit reconciliation operation                                                 | Reconciliation's own definite/uncertain outcome; no product callback                                                      | Re-inventory/authenticate within the same bounds before any further mutation                              |

Syscall injection and child-process death tests must cover every publication
boundary and lock transfer. Child-process tests are not physical power-loss
proof; explicitly inject the allowed missing-name and selected-head states to
prove no-fallback recovery. Exercise all size extrema and authenticated malformed
fields, including root/product confusion, prefix/body UUID and length mismatch,
wrong predecessor digest, reused UUID, record/revision overflow, wrong store,
wrong purpose, trailing bytes and corrupt embedded frames. Error output must
exclude plaintext, keys and synthetic payload markers.

Neither platform selection nor performance tuning permits omission of head
durability or the ownership and recovery checks above.

Historical implementation record:

- [x] Review bounded framing, purpose 9, baseline batch/head ordering and stopped-store orphan behavior for the small kernel.
- [x] Implement and measure the encrypted batch/head kernel with owner-boundary fault checks.
- [x] Review and measure grouped publication with parallel file-sync ownership and interrupted shared-directory-sync recovery checks.
- [x] Specify and implement the head-container framing, root, exchange, staging classification, capacity and failure matrix.
- [x] Preserve the 2/200-record measurements, usage-renewal observations and exact raw output.

The immutable prototypes did not implement full production checkpoints,
compaction or explicit offline stage reconciliation. These are scope limitations
of historical experiments, not pending tasks for production completion. The
production fixed-segment implementation is linked at the top of this document.
