# Finite workspace for one snapshot rotation attempt

Status: protocol design accepted, 2026-09-26. A Linux `RotationWorkspace` helper
implements the bounded physical stage pool and borrowed-lock usage adapter.
Focused tests verify full readiness before writes, single-inode consumption,
ledger renewals, fault cuts, recovery bounds, and monotonic prior-output outcomes.
The Linux `RotateSnapshot` coordinator and filter/state CLI now integrate exact
authenticated state selection, key-budget preflight and aggregate memory
admission. Their fault, process-death and explicit-resume tests pass. The accepted
per-write `RotationIO` helper remains unchanged; journals are outside this scope.
This document supplements [snapshot key rotation](li-snapshot-key-rotation.md)
and replaces neither its cryptographic identity rules nor its same-parent scope.

The guarantee is **one completely reserved remaining attempt**. A fresh
invocation or resume allocates every inode it may need through completion before
its first new seal or authoritative publication. Writes and renames consume those
same allocations. There is no reserve file that is deleted to make room for a
different output inode, no replenishment after the gate, and no automatic retry
after an I/O failure. A later explicit resume authenticates the operation again,
cleans only unselected owned temporaries, and reserves its entire remaining
attempt anew. Unlimited retries without acquiring space again are not promised.

## Authority, ownership, and the reservation gate

Retain the descriptor-identified source/destination parent and the stable source,
destination, old-active-usage, and new-active-usage locks, deduplicating equal
names and acquiring them in canonical order. There are at most four stable locks
for changed-basename rotation and three in-place. Acquire even an absent new
ledger's lock before sizing the workspace. Validate named stable/data inode
identity, key/input aliases, permissions, links, and immutable loaded rings.
No later stage acquires a new ownership lock or opens a mutable competing helper.

Logical state comes only from the authenticated old/new ledgers, bootstrap,
progress, source, candidate, destination, and any predecessor receipt. An opaque
request token is a keyed commitment to the complete request; a random suffix,
stage name, file count, allocation size, or last modification time is never proof
that a seal, reservation, publication, or directory sync committed.

The bootstrap has `U` (ledger-uninitialized) and `R`
(ledger-required) stages. In `U`, only an absent ledger or a matching zero-counter
ledger is eligible for initialization/reconciliation; no current-operation GCM
output may have been selected. In `R`, a missing/invalid ledger is fatal even when
planned progress is absent. No workspace file, ciphertext scan, or old receipt
permits reconstructing or resetting accounting. All historical ledgers remain.

After authenticating the selected state, the attempt proceeds in this order:

1. Determine the exact remaining stage set from the state table below and dry-run
   its ordinary new-key usage requirement from the authenticated highwaters.
2. Identify all unselected temporaries belonging to the exact authenticated
   operation. Validate the entire bounded set and aliases before removing any.
   Unlink them and sync the parent; preserve every selected ledger, candidate,
   prepared progress, destination, bootstrap, and required predecessor copy.
3. Measure retained allocations and locks. Check the byte cap using the complete
   remaining-stage formula before creating new reservation files.
4. Exclusively create a fresh random attempt's named stage inodes, all mode 0600.
   Use `fallocate(KEEP_SIZE)` for each stage's full rounded ceiling, verify exact
   allocated blocks, and sync every inode. Logical length remains zero. An empty
   preallocation contains no sensitive plaintext and is not a selected output.
5. Recheck all named inode identities and the complete allocation sum, then sync
   the parent. Only after that barrier mark the in-memory attempt **ready**.
6. Execute the selected stage sequence once, consuming only these prepared
   descriptors. Before each write/publication recheck the named inode and retained
   ownership. Any missing, substituted, undersized, or unexpectedly used slot
   faults the attempt. It cannot be replaced by an on-demand allocation.

Cleanup and reservation syncs can settle an _existing_ publication from a prior
attempt. That is allowed and must be reported honestly; it does not authorize any
new publication before the complete reservation gate. The outcome rules below
separate these cases.

## Exact stage vocabulary

`E` is the exact final candidate envelope length, derived from the validated
unchanged payload and the actual new key ID. On resume with a candidate or prepared
output, authenticate its exact recorded length/hash instead. All envelopes are
bounded by the owner limit, with overflow checks before any allocation.
`M = 16 KiB` is the fixed ceiling for an encrypted progress envelope or bounded
bootstrap/receipt metadata file. A usage ledger's logical size remains 72 bytes;
its stage reserves `M` conservatively. Let `R(x)` round `x` to the validated
filesystem allocation unit.

| Stage inode                                     | Maximum count per attempt                | Capacity    | Consumption                                                                                                               |
| ----------------------------------------------- | ---------------------------------------- | ----------- | ------------------------------------------------------------------------------------------------------------------------- |
| `bootstrap-u`                                   | 1                                        | `R(M)`      | Publish a new request's authenticated `U` bootstrap.                                                                      |
| `bootstrap-r`                                   | 1                                        | `R(M)`      | Replace `U` with `R`; successful directory sync precedes every GCM seal.                                                  |
| `usage-zero`                                    | 1                                        | `R(M)`      | No-clobber creation of a missing new ledger, only while authenticated `U` permits it.                                     |
| `usage-reservation-0..3`                        | Number of remaining GCM seals, at most 4 | `R(M)` each | At most one durable highwater rewrite per remaining seal; unused slots remain reserved until attempt cleanup.             |
| `progress-planned`                              | 1                                        | `R(M)`      | Seal and publish the exact request before candidate publication.                                                          |
| `candidate`                                     | 1                                        | `R(E)`      | Seal and publish the final-format encrypted snapshot when no usable selected candidate exists.                            |
| `progress-prepared`                             | 1                                        | `R(M)`      | Seal and publish the exact selected candidate ciphertext length/hash before destination publication.                      |
| `publication`                                   | 1                                        | `R(E)`      | Copy the exact selected candidate ciphertext into this inode and publish it as destination; no additional GCM seal.       |
| `progress-complete`                             | 1                                        | `R(M)`      | Seal and publish completion only after destination durability is established.                                             |
| `predecessor-bootstrap`, `predecessor-progress` | Up to 2 total                            | `R(M)` each | Preserve exact authenticated completed-predecessor bytes before replacing its current receipt slots; no old-key GCM seal. |

A full fresh attempt has four GCM objects: planned progress, candidate, prepared
progress, and complete progress. It therefore reserves four ledger-write slots,
even if the usage allocator ultimately extends its highwaters fewer times. A
single seal can charge several block chunks, but the existing allocator computes
that extension in one ledger replacement. The stage adapter must enforce this
bound and reject an unexpected extra rewrite rather than allocate a fifth slot.

Thus the fresh maximum with predecessor copies is **12 metadata stage inodes and
2 envelope stage inodes**. Without a predecessor it is 10 metadata and 2 envelope
inodes. These are stage counts, not the accepted helper's seven mutable roles.
That helper's `2*R(E) + 12*R(M)` per-write formula is not this protocol's complete
budget; retained objects and locks are additional here.

All stage inodes begin at logical length zero and are written once from offset
zero, then synced, checked, closed, and atomically renamed within the held parent.
Their allocations remain attached to the same inode throughout. Do not truncate,
punch holes, copy into a newly allocated inode, or borrow a later stage's space.
Ciphertext publication uses Linux atomic no-replace for a distinct destination;
in-place publication uses explicit replacement. Unsupported primitives fail closed.
Filesystem metadata operations and sync can still fail despite data preallocation.

## Fresh and resumed state table

Each row is selected by content authentication and binding, not by names alone.
`B` counts bootstrap stage inodes, `Z` a zero-ledger inode, `G` remaining GCM seals,
`J` encrypted progress stage inodes, `P` predecessor-copy inodes, and `D` envelope
stage inodes. Reserve `G` ledger-reservation inodes. `p` is the number of required
predecessor copies not already selected and authenticated, from zero to two.

| Authenticated starting state                                                      | Remaining new actions                                                                                   |   B |   Z |   G |   J |   P |   D |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | --: | --: | --: | --: | --: | --: |
| Fresh source, no current-operation bootstrap/ledger/progress/output               | Preserve predecessor if any; `U`, zero ledger, `R`, planned, candidate, prepared, publication, complete |   2 |   1 |   4 |   3 |   p |   2 |
| Before `U`, one or both exact predecessor copies already published                | Finish only missing copies, then the same sequence as fresh                                             |   2 |   1 |   4 |   3 |   p |   2 |
| `U`, new ledger absent                                                            | Zero ledger, `R`, planned, candidate, prepared, publication, complete                                   |   1 |   1 |   4 |   3 |   0 |   2 |
| `U`, matching zero ledger present                                                 | `R`, planned, candidate, prepared, publication, complete                                                |   1 |   0 |   4 |   3 |   0 |   2 |
| `R`, valid ledger, planned progress absent                                        | Planned, candidate, prepared, publication, complete                                                     |   0 |   0 |   4 |   3 |   0 |   2 |
| Planned progress, candidate absent                                                | Candidate, prepared, publication, complete                                                              |   0 |   0 |   3 |   2 |   0 |   2 |
| Planned progress, complete selected candidate matches request/payload             | Prepared, publication, complete                                                                         |   0 |   0 |   2 |   2 |   0 |   1 |
| Prepared progress, original in-place source or absent distinct destination        | Publish the exact selected candidate, then complete                                                     |   0 |   0 |   1 |   1 |   0 |   1 |
| Prepared progress, destination is exact prepared ciphertext, prior sync uncertain | Establish existing publication's durability, then complete                                              |   0 |   0 |   1 |   1 |   0 |   0 |
| Prepared progress, exact destination already proved durable                       | Complete                                                                                                |   0 |   0 |   1 |   1 |   0 |   0 |
| Complete receipt for this operation                                               | Authenticate current output lineage; cleanup/inventory only                                             |   0 |   0 |   0 |   0 |   0 |   0 |

For a row, additional reserved bytes are exactly bounded by:

```text
Q = (B + Z + G + J + P) * R(M) + D * R(E)
```

Before `U`, resume can reconstruct the request from the unchanged authenticated
source and immutable keys. Published predecessor copies must be request-qualified
by the opaque operation token and exactly match the authenticated prior receipt
hashes. Their bytes remain old authenticated bytes; the request commitment binds
them to this handoff. This prevents a fixed generic predecessor name from standing
in for proof of the new request. Unselected random stage filenames are never
accepted as completed copies. If no bootstrap, predecessor, or matching attempt
artifact exists, an invocation can only pass all fresh-operation checks; it cannot
claim proof that an earlier operation progressed.

Both predecessor copies must be durable before publishing the new canonical `U`.
If `U` exists while the current progress slot still contains the old completed
receipt, accept it only when its bytes match the authenticated predecessor copy.
Remove that obsolete current progress slot after the reservation gate and before
zero-ledger initialization or advancement to `R`. Its presence is not new-operation
planned progress. A partial or mismatching published predecessor is fatal.

At `U`, nonzero new accounting or selected current-operation GCM output is an
invalid combination. At `R`, missing accounting is always fatal. Missing/invalid
planned or prepared progress cannot be reconstructed from a candidate's filename.
A missing canonical progress object is eligible only in a table row that permits
absence; a present but unauthenticatable object is never treated as absent.

Prepared progress requires the exact selected candidate when destination still
needs publication. Once the destination itself authenticates as that exact
prepared ciphertext, it supplies those same bytes even if the redundant candidate
copy is absent; no candidate reseal or republishing is needed. If the candidate
is present, authenticate and retain it until completion cleanup. Any third
destination value, changed pending source, binding mismatch, or invalid selected
object stops recovery before cleanup/allocation.

## Peak allocation and final ownership

Measure `A0`, the actual allocated blocks of retained operation files at the
starting cut: current bootstrap/progress, new ledger if present, predecessor
copies, selected candidate, and already published new destination. Include current
completed-predecessor receipt files until their replacement; do not exclude them
merely because they predate this attempt. Deduplicate by descriptor identity while
still rejecting forbidden role aliases. Let `L` be actual allocated blocks of all
held stable locks. Lock creation/validation precedes this calculation; lock
contents are not rewritten during the attempt. Future names require no new locks.

The required workspace cap for this attempt is:

```text
W = A0 + L + Q
```

The filesystem must supply `Q` new, exact, physically allocated stage extents
while retaining `A0` and `L`. Check the cap before allocation, then verify actual
block totals throughout preparation and before declaring readiness. Unexpected
allocation behavior is an unsupported-filesystem failure, not a reason to shrink
the requirement, use sparse files, or proceed on a free-space estimate.

This is an exact conservative admission bound for the proposed schedule: at the
gate every retained allocation and every future stage allocation coexist. Later
renames and cleanup can only decrease it. Replacing a file may briefly retain the
old unlinked inode through its ownership/read descriptor; its allocation was
already included in `A0` or a previous stage, and remains charged until that last
descriptor closes. No stage depends on reclaiming it to make room for a new one.

| Starting cut                             | Additional pool Q                     | Retained objects that must also be charged                                                                                              |
| ---------------------------------------- | ------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| Fresh without predecessor                | `2*R(E) + 10*R(M)`                    | Locks; no new-operation metadata yet                                                                                                    |
| Fresh with completed predecessor         | `2*R(E) + 12*R(M)`                    | Existing bootstrap/receipt plus locks; upper bound becomes `2*R(E) + 14*R(M) + L` when both retained records occupy full metadata units |
| `U`, ledger absent / zero ledger present | `2*R(E) + 9*R(M)` / `2*R(E) + 8*R(M)` | Bootstrap, any predecessor/current old receipt, optional zero ledger, locks                                                             |
| `R`, planned absent                      | `2*R(E) + 7*R(M)`                     | Bootstrap, new ledger, predecessors, locks                                                                                              |
| Planned, candidate absent                | `2*R(E) + 5*R(M)`                     | Bootstrap, ledger, planned progress, predecessors, locks                                                                                |
| Candidate selected, not prepared         | `R(E) + 4*R(M)`                       | Candidate plus current metadata/predecessors/locks                                                                                      |
| Prepared, destination not yet new        | `R(E) + 2*R(M)`                       | Candidate plus current metadata/predecessors/locks                                                                                      |
| Destination already exact new ciphertext | `2*R(M)`                              | New output, optional candidate, current metadata/predecessors/locks                                                                     |
| Complete                                 | `0`                                   | All remaining operation files and locks until cleanup; no new data extent                                                               |

Pre-existing source data and historical old-key usage ledgers are retained baseline
storage outside `--max-working-bytes`, consistent with the command proposal. Report
their actual blocks separately as `O` and `H`; total relevant file allocation is
bounded by `O + H + W`. In-place replacement may release `O` after the last old
source descriptor closes. Changed-basename rotation retains `O` permanently and
adds the new output already charged in `W`; it never funds workspace by deleting
the original. Unrelated stores, external backups, and filesystem-internal metadata
or journal blocks are not represented as owned data extents by this accounting.

The default cap remains 128 MiB; reject a cut whose measured requirement exceeds
it unless the operator explicitly supplies a sufficient higher cap. Do not assume
the fixed default is sufficient merely because the payload length passes schema
validation. Existing malformed or oversized owned files fail before this budget
calculation can authorize writes.

No disk scratch file is needed. Hash/ciphertext copy uses one bounded streaming
buffer; plaintext decoding, encryption buffers, and the in-memory stage catalogue
share the existing 256 MiB transient reservation. Release owner decode trees before
sealing. At most 14 stage descriptors and a bounded set of ownership/read handles
are needed; reserve a total ceiling of 64 descriptors for the offline operation.

## Partial workspaces and restart

The workspace catalogue is **in memory only**, containing each stage's expected
role, random basename, descriptor identity, logical ceiling, and allocation.
There is no on-disk workspace manifest to select a commit or require another GCM
seal. A partially constructed catalogue has `ready=false`; a process crash loses
its readiness proof completely. A torn or partial stage file is simply an
unselected temporary, even if it contains a complete authenticated ciphertext.
It does not become a ledger, candidate, progress record, or output by resemblance.

This proposal deliberately chooses whole-attempt rebuilding on every explicit
resume. Do not reuse an old attempt's unpublished inode in place and do not infer
which of its slots were fully prepared. After authenticating the operation and
selected cut, remove its validated unselected stage files, sync, and allocate the
table's entire remaining set under a fresh random attempt nonce. Old nonce
reservations remain consumed. Missing old temporary slots need no replacement as
old slots; missing selected files follow the table's strict rules instead.

There are at most 14 temporary stage files in a valid attempt. Enumerate the shared
directory in batches of at most 128, inspecting at most 4,096 entries total. Validate
the operation token, attempt/stage syntax, unique roles, maximum lengths, private
regular single-link files, allocation bounds, and all protected/key aliases before
deleting the set. A recognized but malformed/duplicate stage or too many matching
files requires explicit investigation; it is not an excuse for broad cleanup.
Generic `.securestore-tmp-*`, other operation tokens, unknown metadata, and other
stores remain untouched and appear as unknown/unowned in inventory reporting.

If cleanup cannot complete durably, stop before allocating the next attempt. If
reservation subsequently fails partway through construction, stop before any new
seal or authoritative publication. Close descriptors; report and, where safely
possible, durably clean only the incomplete new stage set. Any surviving staged
files remain attributed for the next exact resume. A live ready attempt faults
on the first write/sync/close/rename error and cannot refill a consumed slot or try
again inside the same pool.

## Accounting across attempts and outcome rules

Open existing new-key accounting only after bootstrap/request authentication.
Restart treats every persisted reserved seal/block highwater as consumed, including
unused reservations from the failed attempt. Before allocating the pool, simulate
the at-most-four remaining ordinary seals and checked chunk rounding from that
floor. A key with insufficient ordinary allowance stops the attempt; rotation
does not consume the final 10% control reserve. Decrypting selected objects,
copying exact ciphertext/predecessor bytes, HMAC bootstrap updates, and cleanup
consume no GCM invocations. A complete row needs no further allowance.

The stage-bound usage adapter supplies one already allocated ledger inode whenever
the allocator extends a highwater. It performs no `Prepare`/`fallocate` after the
gate. File sync, atomic replacement, and directory sync must succeed before that
reservation can authorize a nonce. Failed or uncertain reservations block sealing.
Every retry starts from the current authenticated ledger; neither an unselected
ledger temporary nor a lower count in old progress can replace that current floor.

| Event                                                                                                                                                               | Snapshot result for this operation                                              | Auxiliary/workspace disposition                                                                                                                   |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| Capacity/reservation failure; destination remains original or absent                                                                                                | `NotCommitted`                                                                  | No new authoritative bytes; keep node stopped and resume the authenticated operation.                                                             |
| Prior attempt's exact prepared destination is visible, but no successful parent sync proves it durable                                                              | `Uncertain`                                                                     | Allocation/cleanup failure does not imply rollback or permit republishing different bytes.                                                        |
| Prior destination is authenticated against prepared progress and any subsequent successful parent sync establishes durability, including a cleanup/reservation sync | `Committed`                                                                     | Later capacity failure is `Committed` plus capacity/cleanup error and `ResumeRequired`; never downgrade it to preserve an earlier classification. |
| Complete receipt already proves this operation completed                                                                                                            | `Committed`                                                                     | Cleanup/inventory may fail with no new allocation or seal; keep the completion proof.                                                             |
| New stage/counter/bootstrap/progress failure before destination publication                                                                                         | `NotCommitted` unless this operation's destination was already proved committed | Preserve auxiliary `NotCommitted`/`Uncertain` cause and stop; selected accounting cannot be reset.                                                |
| New destination rename succeeds, parent sync fails                                                                                                                  | `Uncertain`                                                                     | Stop; exact resume authenticates current object and prepared progress.                                                                            |
| Destination is durable, then complete-receipt seal/publication or cleanup fails                                                                                     | `Committed`                                                                     | Keep the selected output and accounting; report error and resume remaining completion/cleanup.                                                    |

Revalidate the selected destination identity at a settling sync. A predecessor
receipt from an _earlier rotation_ proves historical success of that earlier
operation; it does not mark the new request committed. Outcomes are monotonic for
one authenticated operation and distinguish snapshot commitment from auxiliary
reservation, metadata, and cleanup durability.

## Completed lineage and remaining implementation gate

A fresh rotation after runtime `Save` authenticates the completed predecessor's
destination/store/key lineage, then independently authenticates the current
snapshot and ledger. It binds the current inode, ciphertext hash, and payload anew.
The old receipt is historical evidence, not a permanent ciphertext pin. Pending
or prepared receipts retain their exact source/candidate constraints. Completion
cleanup never restores the receipt's old payload over a later legitimate snapshot.

For changed-basename rotation, the original and output retain their separate
path/key lineages. A later operation may select either as its source and must
authenticate that path's current snapshot and ledger. Reusing an occupied output
as a distinct destination remains a no-clobber error; explicitly rotating it
in-place starts from its own current lineage. The source retained by an earlier
completed operation is not silently treated as that operation's output.

No logical protocol blocker is identified under the chosen per-attempt scope.
Implementation still needs a reviewed stage-set allocator/adaptor: the accepted
seven-role helper allocates another metadata inode per rewrite and therefore
cannot supply this guarantee unchanged. Request-qualified predecessor publication,
held usage-lock integration, the no-allocation usage stage adapter, and outcome
tracking across recovery syncs also require implementation and tests. The accepted
helper/code and main plan remain frozen by this design task.

Required verification includes every table cut and every reservation index;
allocation failure before the gate; directory-sync failure before/after existing
output settlement; ledger extension followed by a crash before its GCM object;
partial catalogue/stage cleanup and bounded inventory; zero fallocate/create calls
after readiness; actual peak allocation versus the measured formula; same inode
identity from reservation through publication; missing ledger under `R`; repeated
resumes with increasing highwaters; rotate then runtime-save then rotate; both
changed-basename lineages; and completed output with failed completion metadata.
