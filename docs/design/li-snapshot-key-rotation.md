# Encrypted snapshot key rotation

Status: implemented and verified for Linux snapshots on 2026-09-26. This document
describes one increment of [encrypted managed storage](li-encrypted-storage.md).
The coordinator, owner adapters, CLI, fault/resume tests and focused review are
complete within the scope below. Journal rotation remains outside this increment,
so it does not complete the full rotation gate in
[the implementation plan](../plans/li-x3-and-filter-storage-encryption.md).

The increment rotates one managed filter snapshot or LI administrative snapshot
offline. It preserves the authenticated store UUID and the exact validated owner
payload bytes. It starts no processor, policy manager, listener, capture, ADMF
reconciliation, allocator, or delivery client. Journals, format upgrades, key
retirement, and cross-directory encrypted rotation remain outside this increment.

## Scope and command surface

Encrypted rotation supports explicit in-place replacement or a different basename
in the **same descriptor-identified parent directory**. Comparing cleaned path
strings is insufficient: both held directory descriptors must identify the same
device/inode. Reject a different directory before creating rotation artifacts or
usage ledgers. This retains one raw-key usage namespace; copying ledgers into a
second writable directory would fork accounting. Existing plaintext migration
with a freshly provisioned key retains its separate cross-directory behavior.

The commands extend the existing offline commands:

```sh
lc migrate filter-store --source-format encrypted \
  --source /var/lib/lippycat/filters.enc \
  --destination /var/lib/lippycat/filters.enc --in-place \
  --source-key-id filters-1 --source-key-file /etc/lippycat/filters-1.key \
  --key-id filters-2 --key-file /etc/lippycat/filters-2.key

lc migrate li-state --source-format encrypted \
  --source /var/lib/lippycat/state.enc \
  --destination /var/lib/lippycat/state-next.enc \
  --source-key-id state-1 --source-key-file /etc/lippycat/state-1.key \
  --read-key state-0=/etc/lippycat/state-0.key \
  --key-id state-2 --key-file /etc/lippycat/state-2.key
```

`filter-store` remains available in all/cli/processor/tap builds; `li-state`
requires the LI build tag. These commands use explicit arguments, do not select a
runtime configuration implicitly, and do not change runtime configuration.

| Option                                 | Encrypted-source meaning                                                                                                                              |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--source-format=encrypted`            | Required format selection; never infer it from magic or failed plaintext decoding.                                                                    |
| `--source`, `--destination`            | Both required; same parent descriptor identity required.                                                                                              |
| `--source-key-id`, `--source-key-file` | Required current source active key; authenticates the source usage ledger and establishes its UUID.                                                   |
| `--read-key=id=path`                   | Zero to four prior **source** read keys; repeated IDs or material are rejected.                                                                       |
| `--key-id`, `--key-file`               | Required fresh destination active key; its ID must differ from every source-ring ID.                                                                  |
| `--in-place`                           | Required exactly when source and destination identify the same basename in the held directory; rejected for different basenames.                      |
| `--resume`                             | Continue the identical authenticated operation, including an already published candidate; never reset accounting.                                     |
| `--max-working-bytes`                  | Positive integer bytes, default 134217728 (128 MiB); limits newly allocated rotation workspace, excluding pre-existing source and historical ledgers. |
| `--init`                               | Rejected with encrypted source; existing empty initialization remains separate.                                                                       |
| `--radius-state-file`                  | Rejected for encrypted LI-state rotation: preserve the encrypted pin exactly, including an absent optional pin.                                       |

The two source-key options are rejected for plaintext migration and empty init.
For those modes existing key-option meanings remain unchanged. Rotation's read
keys are not automatically copied into runtime configuration. An operator keeps
old key material available until the reported dependencies and backups have been
accounted for; the destination snapshot itself needs only its new active key.

## Coordinator and owner boundary

A common, untagged `securestore` coordinator owns paths, ownership, accounting,
encrypted progress, publication, recovery, and the result report. Its
`RotateSnapshot` entry point accepts source/destination paths, immutable source and destination
keyrings, options, and an owner contract containing purpose, object name, payload
ceiling, and strict preflight/validation callbacks that accept the remaining decode
reservation. It returns a structured report, typed
snapshot outcome, and error. Concrete type names are an implementation detail.

Load each key reference once through the existing private-file reader. The source
ring contains its active key and up to four prior keys; the destination ring has
only its new active key. This avoids constructing a six-key runtime ring and
avoids a second load from mutable key paths. The coordinator compares every actual
loaded source key with the actual destination key, not filenames or IDs. Bind the
operation to the sorted source key IDs and their loaded material using a keyed
commitment; never expose raw keys or comparison fingerprints in diagnostics.

The filter wrapper supplies purpose `FilterSnapshot`, object `filters`, the
16 MiB payload ceiling, and `UnmarshalEncryptedFiltersWithBudget`. The LI wrapper supplies
purpose `AdministrativeState`, the existing `stateSnapshotObject` constant
(`administrative-state`), the 32 MiB ceiling, and `UnmarshalStateSnapshotWithBudget` plus
inner-incarnation equality. No shared package imports either owner package.

The callback validates the whole payload before any rotation data is written and
does not retain a decoded tree. The coordinator reseals the original payload bytes,
without normalizing, sorting, changing `written_at`, or synthesizing fields. Thus
filter revisions/scopes/RADIUS metadata and state generations, revocations,
obligations, intents, deadlines, incarnation, and RADIUS allocator pin survive
exactly. The allocator sidecar's bytes and inode are untouched.

## Ownership and key freshness

Open raw paths with the existing descriptor walk; do not clean away a symlink or
an invalid traversed component before validation. The parent already exists and
meets the private-store directory contract. Acquire source and destination stable
basename locks together in canonical `LockOrderKey` order, deduplicating the
in-place case. Retain data-inode locks across publication. Accounting locks use a
consistent order as well; all acquisition is nonblocking and partial acquisition
is released on failure. A narrow internal coordinator path may accept already
held usage locks to avoid reacquiring its own lock.

Reject descriptor aliases between keys, source, destination, accounting files,
progress/bootstrap/candidate paths, and the LI allocator sidecar. Validate absent
destinations by held parent identity plus basename. A distinct destination must
be absent, except when exact resume proves it is the operation's candidate.
Acquiring stable lock sidecars is the only allowed filesystem creation before
source authentication and full validation; those sidecars are retained normally.

The old active ledger must already exist and authenticate. It establishes the
store UUID even when the snapshot header selects a prior source key. Rotation
does not consume old-key GCM capacity and does not write old highwaters.

The new raw key must differ from every supplied old active/prior key. Before fresh
initialization, its raw-derived usage basename must be absent in the shared
parent. Any existing file there blocks a fresh operation, even a zero-counter
ledger or a ledger originally created under another key ID. Exact authenticated
resume is the sole exception. Never delete, truncate, copy, or reset any old
ledger, including after a read key is retired. The new ledger is created in this
same directory under the old ledger's authenticated UUID.

These checks cannot prove that externally provisioned material was never used in
an unrelated directory or that an operator did not delete/roll back history.
Independent provisioning and preservation of usage history remain requirements;
coherent backup rollback remains outside the existing detection contract.

## Authenticated operation records

Use destination-specific reserved bootstrap, progress, and candidate names, with
an owner-specific prefix to separate filters from state. All are private files.
The visible bootstrap contains only fixed format/version, stage, store UUID, an
opaque operation token, and HMAC. Paths, inode identities, payload/ciphertext
hashes, and key IDs are inside encrypted progress or opaque keyed commitments.

The bootstrap HMAC uses the new key and a dedicated rotation domain, separate
from initialization, usage ledgers, and GCM envelopes. Its committed request is
bounded to 4 KiB and includes owner purpose/object, source and destination path
hashes, held parent identity, source basename/inode, original ciphertext hash,
validated payload hash, old active ID/source-ring commitment, new active ID,
mode, and any completed-predecessor receipt hashes. The operation token is derived
from that same authenticated request; it can be reconstructed before first
publication while the original source still exists. No GCM is needed for it.

Encrypted progress is at most 16 KiB including binding and uses the new key with
the owner purpose and a distinct object name containing the destination digest
and operation token. It carries the complete request above, stage, source UUID,
and, once prepared, the exact candidate ciphertext length/hash. LI progress also
commits the pin retained in the validated payload. A file header's key ID only
selects a configured key; it never establishes identity by itself.

Bootstrap stages are `ledger-uninitialized` and `ledger-required`. The second
stage must be durable **before the first GCM seal**, including progress seals.
Missing accounting in `ledger-required` is fatal even if no encrypted progress
was published. In `ledger-uninitialized`, resume may create an absent new ledger,
or accept a matching zero-counter ledger, only after authenticating the exact
request and proving no current-operation progress, candidate, or new destination
exists. A nonzero ledger is never treated as initial.

## Durable sequence and crash cuts

Every artifact publication uses complete writes, file sync, checked close,
descriptor-relative rename, and directory sync. All sensitive output, including
temporaries, is encrypted before its file is opened. No plaintext backup exists.

| Durable boundary / interrupted action                                                           | Resume rule                                                                                                                                                                                                                                                                                                        |
| ----------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Authenticate original snapshot/ledger, validate whole payload, acquire workspace reservation    | No rotation artifacts yet; failures leave snapshot bytes unchanged.                                                                                                                                                                                                                                                |
| Create authenticated `ledger-uninitialized` bootstrap                                           | Reconstruct exact request from unchanged original and immutable keys. A partial transaction-owned temporary can be discarded; an invalid published bootstrap is fatal.                                                                                                                                             |
| Create new zero-counter usage ledger                                                            | Exact bootstrap may accept the matching zero ledger; absence permits retry. An uncertain ledger creation must be reconciled, never overwritten.                                                                                                                                                                    |
| Advance bootstrap to `ledger-required`                                                          | Old stage plus zero ledger permits retry. Required stage plus missing/invalid ledger is fatal. No seal was allowed before a definitely committed stage advance.                                                                                                                                                    |
| Reserve new-key usage and publish encrypted `planned` progress                                  | Lost reservations remain consumed. If progress is absent, reseal only after reopening the required ledger; never reinitialize it.                                                                                                                                                                                  |
| Seal and publish the encrypted candidate                                                        | The candidate is a final-format snapshot under the new key. Before a prepared hash exists, accept a complete candidate only after full authentication and exact payload-hash/binding comparison with planned progress. Remove only attributed partial temporaries. Missing candidate permits a newly charged seal. |
| Replace progress with `prepared`, recording exact candidate ciphertext hash/length              | Reuse the durable candidate; do not generate a second ciphertext merely because progress publication was interrupted. No destination publication precedes durable prepared progress.                                                                                                                               |
| Publish destination, using no-clobber or explicit replacement                                   | In-place current bytes must be the original ciphertext/inode or the exact prepared candidate. Changed-basename source must still be the exact original; destination must be absent or the exact candidate. Any third state fails closed.                                                                           |
| Sync destination directory                                                                      | Authentication of visible bytes alone is insufficient to settle a prior sync failure. Authenticate the exact prepared candidate, then successfully sync the held directory before reporting its commitment.                                                                                                        |
| Publish encrypted `complete` receipt, then remove candidate and attributed temporaries and sync | Destination remains committed if receipt writing, deletion, closing, or reporting fails. Resume completes cleanup without resealing the snapshot. The complete receipt and bootstrap remain for exact resume after a crash before the success message.                                                             |

After in-place publication, resume obtains the original request from authenticated
progress rather than trying to reconstruct it from the now-replaced source. It
authenticates the current new snapshot against the prepared ciphertext hash and
preserved UUID. The old ledger is still required. After changed-basename success,
the original remains usable with its old key and the same unchanged old ledger.

A later fresh rotation authenticates the prior completed receipt's destination,
store UUID, and key lineage, then independently authenticates the **current**
snapshot through its current source ring and usage ledger. A completed receipt is
historical evidence: legitimate runtime saves may have changed the ciphertext,
inode, and payload since the previous rotation. Bind those current values anew
in the fresh request. A pending or prepared receipt still pins its exact original
and candidate bytes and requires original-operation resume; unrelated runtime
changes are rejected there. First copy
the old bootstrap/receipt bytes into new-operation-owned predecessor slots and
sync them; include their hashes in the new bootstrap request. Then publish the
new bootstrap and remove the old current progress slot before creating the new
ledger. Resume accepts only those exact predecessor bytes at this handoff; a
pending or mismatching predecessor requires its original resume. Predecessor
slots are removed only after the new snapshot and completion receipt are durable.
This bounds receipt accumulation without discarding the only proof of an
interrupted operation. Historical usage ledgers are never part of that cleanup.
For changed-basename rotation, receipt lineage belongs to its recorded output;
it does not transfer to or permanently pin the retained original. Reusing either
path as a later source independently authenticates that path's current snapshot
and ledger. Reusing an occupied output as a different-basename destination remains
a no-clobber error; an explicit in-place rotation authenticates that output's own
lineage. Tests cover rotate, runtime save, then rotate again, plus subsequent use
of both the retained original and the prior output.

## Transaction-owned temporary files

The current `.securestore-tmp-<random>` naming does not identify which snapshot
transaction owns a partial file. `RecoverTemporaries` is a whole-directory owner
operation and is unsuitable when unrelated stores share the parent. Existing
`Dir.Replace`/`Create` alone therefore do not establish this proposal's complete
crash-cleanup contract.

The internal transaction I/O facility attributes every rotation
write, **including new-key usage-ledger updates**, to an exclusive unpredictable
temporary whose name contains an opaque authenticated operation token and role.
Recovery only removes matching private regular single-link files after validating
the bootstrap/request and all path aliases. Before the first bootstrap is
published, the unchanged authenticated source and new key reconstruct the token.
For predecessor handoff, both request commitments must authenticate. Unknown
generic temporaries are reported, never automatically removed.

The facility must retain the existing replacement-inode lock handoff and typed
outcomes. Its no-clobber publication must be one atomic namespace operation. The
initial increment should enable rotation only where that capability is available
(Linux `RENAME_NOREPLACE`), reject unsupported platforms before operation records
are created, and fail safely if the actual filesystem rejects publication. The
portable hard-link fallback requires separate two-name recovery qualification and
is not used by this protocol. `RotationWorkspace` provides the Linux implementation.

## Budget ownership

The authoritative formula and finite stage table are in
[the retained-workspace design](li-snapshot-rotation-workspace.md). For the
selected authenticated recovery cut, reserve
`Q = (B + Z + G + J + P) * R(16 KiB) + D * R(E)` in distinct physical stage
inodes and admit only when `W = A0 + L + Q` fits the supplied cap. `A0` is actual
retained operation metadata/output allocation; `L` is actual retained lock
allocation. Report the old source and historical usage files separately. The
former fixed `2*R(E) + 12*R(16 KiB)` estimate described a fresh stage pool only;
it was not a complete cap including retained predecessors and locks. The default
128 MiB is a cap, not permission to allocate it eagerly.

| Resource                                                              | Owner and admission rule                                                                                                                                                                                                                                                                    |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Old source and historical usage files                                 | Pre-existing storage; retain unchanged; enumerate/report their bytes separately. Never reclaim them for workspace.                                                                                                                                                                          |
| Candidate and final publication temporary                             | Coordinator; reserve both before sealing. Candidate bytes copied to publication do not consume a second GCM invocation. On changed-basename success the destination becomes retained output and leaves transient accounting.                                                                |
| Bootstrap/progress/new ledger/predecessor files and their temporaries | Coordinator transaction I/O; fixed bounded slots included in the same byte cap. Reconcile owned crash remnants before allocating another attempt.                                                                                                                                           |
| GCM invocations and blocks                                            | New-key usage owner; ordinary admission only, including progress and failed attempts. Never borrow the final 10% control reserve or old-key allowance.                                                                                                                                      |
| Decode and encryption buffers                                         | One 256 MiB transient reservation, including owner parser expansion and all simultaneous envelope/plaintext buffers. Release decoded trees before sealing; admission must account for the codec's existing estimate plus coordinator residency, not add two independent 256 MiB allowances. |
| Directory inventory                                                   | Streaming batches of at most 128 entries; at most 4,096 inspected entries per invocation. Exceeding the bound stops before mutation or returns a committed result with incomplete accounting if discovered after publication. No unbounded filename list.                                   |

A free-space query is advisory, not a reservation. Before operation artifacts are
published, the full coordinator must reserve/preallocate and retain the bounded
working extents needed through completion, or reject an unsupported filesystem;
metadata allocation, sync, and later I/O can still fail and follow the typed
outcomes. Preallocation contains no plaintext.
Implementation must demonstrate that truncation/write/rename retains the intended
allocation and that failures do not leave uncharged transaction artifacts. It
must not claim this guarantee merely from `statfs` or sparse file length.

The first `RotationIO` helper still provides only per-write preallocation. The
separate `RotationWorkspace` primitive reserves the entire caller-selected
remaining stage set, consumes those same inodes once, and routes new-ledger
rewrites through borrowed retained ownership. It provides no refill after
readiness. `RotateSnapshot` authenticates the request/cut, selects the exact
remaining set, validates key and memory budgets, enforces bootstrap ordering, and
integrates recovery/outcome reporting. The filter/state wrappers and CLI use that
coordinator; the helper alone does not establish transaction authority.

Resume may raise the supplied byte cap to cover the authenticated operation's
already determined minimum; it cannot lower it below current allocated workspace.
The resource cap is not part of the payload/key identity commitment. A full disk,
allocation failure, or failed nonce read can consume reservations but cannot reset
them or publish partial data.

## Rejections and outcomes

| Condition                                                                                                                                    | Snapshot outcome / required action                                                                                                                                             |
| -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Missing/invalid source, old ledger, key, schema, ownership; wrong purpose/UUID; cross-directory request; aliases; invalid option combination | `NotCommitted`; no rotation data or new accounting created. Lock-sidecar cleanup errors remain visible.                                                                        |
| New raw material equals any source key; duplicate/conflicting IDs; existing new usage ledger without exact resume                            | `NotCommitted`; provision a fresh independent key or resume the original operation.                                                                                            |
| Source changed after progress, wrong target/new key, unexpected destination, pending predecessor, missing required ledger                    | Fail closed; do not reset, reseal blindly, or overwrite. A previously uncertain destination stays unresolved until the authenticated original operation can settle it.         |
| Usage/bootstrap/progress write uncertain before destination publication                                                                      | Snapshot is `NotCommitted`; auxiliary outcome is `Uncertain`, resume is required, and the usage owner is faulted. Preserve both outcomes in the structured result/error chain. |
| Short/failed write, file sync, close, or failed rename before destination publication                                                        | `NotCommitted`; original remains usable. Keep authenticated resume state; lost usage stays consumed.                                                                           |
| Destination rename succeeded but directory sync failed                                                                                       | `Uncertain`; keep the node stopped, authenticate current snapshot and prepared progress on resume, then establish directory durability.                                        |
| Destination and directory sync succeeded; later completion/cleanup/reporting failed                                                          | `Committed` with joined auxiliary error and `ResumeRequired`; never label this a rollback.                                                                                     |
| All publication and cleanup steps completed                                                                                                  | `Committed`; report preserved identity, remaining old-key dependencies, and accounting completeness without changing runtime configuration.                                    |

Errors remain discoverable through `CommitError`/`OutcomeOf`; usage reservation
uncertainty retains its own typed cause. The result distinguishes snapshot
commitment from operation cleanup and inventory completeness. Diagnostics contain
constant classifications and counts, no selectors, plaintext, key bytes, or key
comparison fingerprints. A key ID may appear only as an explicit operator-facing
inventory label, never as proof that two raw keys differ.

## Old-key accounting and verification gate

Report each supplied old key's known live snapshot count, recognized migration or
rotation sidecar count, attributable interrupted rewrite count, and allocated
bytes. Changed-basename rotation necessarily reports the original old-key
snapshot. In-place rotation may still report old initialization/migration intent
or bootstrap dependencies; this increment does not silently delete those records.
HMAC-authenticated bootstrap dependencies count even though they contain no
payload. Usage ledgers are retained history and reported separately.

Only objects whose owner/binding and key attribution were authenticated can be
counted conclusively. Unknown temporaries, unrecognized artifacts, unavailable
read keys, or an inventory bound yield an explicit incomplete/unknown category,
never zero. Scope the report to the locked source/destination and recognized
operation namespace; another store sharing the directory is not implicitly owned.
External backups, copied snapshots, exports, and other directories are not scanned.
The command never declares that a key is safe to destroy or retires it. Complete
snapshot/journal rewrite and retirement accounting remain phase-8 work.

Implementation acceptance requires fault cuts at every table boundary, including
first bootstrap and predecessor handoff; short writes/ENOSPC/fsync/close/rename;
lost ledger after the first attempted progress seal; source/destination/key aliases;
old-key exhaustion with successful new-key rotation; retired-ID raw-key reuse;
immutable keyfile replacement; same-directory aliases and rejected cross-directory
requests; exact full owner payload preservation; present/absent optional state pin
and allocator alias rejection;
competing runtime ownership; committed-cleanup errors; allocation ceilings; and
unrelated generic temporary survival. Subprocess crash tests must demonstrate
restart behavior, not only injected function errors. No test may activate policy,
open delivery, or modify the RADIUS allocator.
