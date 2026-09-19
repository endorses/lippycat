# Event spool durability contract

**Status:** Normative for the event-spool merge boundary

The hunter and processor-upstream event spool preserves normalized protocol
events until a processor acknowledges them. This document defines the storage,
recovery, failure, and transport contracts used by the implementation and its
tests.

## Limits and accounting

The default maximum deterministic `ProtocolEventBatch` payload is 4 MiB. The
limit applies even when the total spool byte limit is unlimited. It is the
minimum processor event-ingress limit; processors reject lower configured
values at startup, while operators may raise the receiver ceiling. Both values
remain below the 10 MiB gRPC message ceiling so the enclosing ingress message
has headroom.

Admission validates the final batch after inherited and newly incurred loss
reports have been attached. It must satisfy the protobuf adapter limits of
4,096 events, 4,096 loss entries, and 4,096 total loss ranges as well as the
configured byte limit.

`logical_bytes` is the sum of immutable record files referenced by the active
set. It controls `MaxBytes`, pending status, and drain completion.
`physical_bytes` includes active records and unreferenced record or temporary
files retained for retryable cleanup. Physical bytes are reported separately
and never make an orphan logically pending. Manifest, journal, policy, and lock
metadata are not part of this record-storage counter.

## Record format

Published record files are immutable. A record contains a fixed-size header
followed by one deterministic protobuf payload. The header contains magic,
format version, creation time, payload length, and CRC-32.

The reader opens and stats the same file descriptor before allocating payload
memory. It rejects a file unless all of these checks pass:

- the file is at least the fixed header size;
- the declared payload length is no greater than the configured record limit;
- the declared length equals `file_size - header_size` using overflow-safe
  arithmetic; and
- the format version, checksum, protobuf, and transport validation all pass.

A rejected record remains on disk for operator recovery.

## Authoritative active set

Record-file presence does not define pending delivery. A versioned checkpoint
and its committed mutation journal are the authority for the ordered active
set, identity, logical byte total, sequence high-water marks, and exact pending
loss coverage.

The checkpoint contains:

- format version and journal generation;
- the last incorporated transaction number;
- the fixed source node and producer session, when bound;
- ordered active record basenames with size, creation time, batch sequence,
  and event high-water metadata;
- logical byte total, sequence high-water marks, and the durable cumulative
  retirement mark that prevents acknowledged or evicted batch identities from
  being published again; and
- normalized pending loss ranges.

Only safe basenames are accepted. Absolute paths, separators, traversal,
unexpected extensions, duplicates, missing records, inconsistent identity,
and incorrect byte totals are fatal startup errors.

The journal is a sequence of checksummed frames. Each frame has fixed magic and
version fields, generation, monotonically increasing transaction number,
payload length, and payload checksum. Its payload describes one complete
logical mutation: additions, removals, high-water changes, and the replacement
pending-loss state. Replay is idempotent by generation and transaction number.
Generation and transaction counters fail stopped before wraparound.
An incomplete final frame is an interrupted append and is ignored. A checksum
failure or malformed frame before the final incomplete tail is corruption and
stops recovery without deleting evidence.

## Publication and checkpoint ordering

An enqueue publishes and syncs its immutable record before a journal
transaction may reference it. The transaction is appended and synced before
the in-memory active set changes or success is reported. An ACK uses the same
ordering: its cumulative, source-and-session-scoped removal is committed before
memory changes. Physical cleanup happens only after logical commit.

Checkpoint replacement uses a same-directory temporary file, file sync,
close, rename, and directory sync. Journal generation handoff and retirement
wait until the replacement checkpoint and successor journal are durable.
Checkpoint work is triggered both by a geometrically growing active-set base
and when journal frames reach the current retained-record count plus the
configured threshold. The two triggers keep checkpoint bytes amortized linear
during growth, replacement, and drain; enqueue and one-record ACK do not rewrite
or traverse the entire active set each time. Recovery work is bounded by the
retained checkpoint plus the configured journal threshold.

A mutation whose exact metadata exceeds one bounded journal frame is committed
as the first checkpoint of a fresh journal generation. The old generation
remains authoritative until that checkpoint is durable, preserving atomic
cumulative ACK and replacement semantics without an unbounded frame.

Legacy directories without a checkpoint are migrated only after every record
has been validated and the set has one unambiguous identity and ordering.
Migration publishes the initial checkpoint and journal generation before
allowing mutation. Malformed, duplicate, mixed-session, or ambiguous legacy
data stops startup. A missing checkpoint alongside current-format journal
history is never treated as legacy; only the header-only generation-one journal
from an interrupted initial migration is a safe retry.

## Failure outcomes

Every storage operation has one of four outcomes:

1. **Pre-publication failure.** No authoritative mutation is visible. The old
   logical state remains in memory and on recovery, and an uncommitted new
   record may be cleaned up.
2. **Durable success.** The journal or checkpoint mutation is synced. Memory is
   updated exactly once and the caller may advance its batch sequence.
3. **Durability uncertain.** A rename or journal write may have made a complete
   mutation visible, but a later sync failed. Rollback cannot be claimed. The
   spool enters an explicit uncertain state and rejects sending, mutation, and
   garbage collection until it is closed and recovery resolves the visible
   state. Callers must not reuse the affected sequence.
4. **Committed with cleanup failure.** The logical transaction is durable and
   remains successful. Failed record unlinking is reported with the path and
   operation, retained as retryable orphan work, and retried at startup and
   later safe mutation points. It never reactivates a record or invites a
   caller retry.

A definite checkpoint-maintenance failure after a journal transaction commits
does not undo that transaction. The spool exposes a checkpoint-required state,
blocks further mutation and sending, and remains pending until recovery compacts
the bounded journal successfully. This prevents repeated checkpoint failures
from growing replay work without bound while preserving the committed result.

Process reopen observes the filesystem state that is visible at that time.
Power-loss tests model unsynced boundaries separately and permit only the old
or new complete transaction state. Files needed by either state are retained
until uncertainty is resolved.

One process owns a spool directory at a time. The owner holds an exclusive
directory lock throughout recovery and mutation and releases it on `Close` or
failed startup.

Authoritative manifest and journal files must be regular files opened without
following symlinks, and the opened descriptor must still identify the inspected
file. This applies both during recovery and to steady-state journal appends.

## Loss accounting and exhaustion

Loss coverage is normalized by source node, producer session, and loss kind.
Adjacent or overlapping ranges are merged and counts are recomputed from the
exact non-overlapping ranges. Inherited coverage carried on the wire is kept
separate from newly incurred loss returned for local counters.

Rejected incoming events and evicted records add exact coverage to the durable
pending-loss state in the same logical transaction that rejects or removes
them. Coverage is never truncated. When normalized coverage cannot accompany a
normal batch within byte or collection limits, it is emitted in ordered
loss-only batches, each independently satisfying receiver validation. A batch
sequence advances only after the corresponding record is committed.
Carrier prefixes follow event sequence order across loss kinds, so splitting
cannot advance the receiver past coverage reserved for a later carrier.

The forwarding sink checks the durable pending set after each rejection. Once
the complete set no longer fits one receiver-valid record, it publishes bounded
loss-only prefixes before accepting more events. A valid event encountering a
recovered oversized pending set triggers the same drain-and-retry behavior.
Loss-only records obey the configured byte and age exhaustion policy: drop-new
stops when no record fits, while drop-oldest atomically retains coverage for any
record it replaces and proceeds only when replacement strictly reduces the
remaining bounded loss work. Coverage from victims is merged before splitting
the outgoing carrier, so earlier evicted events cannot be deferred behind that
carrier's high-water mark. A non-progressing replacement fails stopped, so a
one-record spool cannot alternate loss carriers forever. Inherited wire loss
reports are not counted again in local loss counters when their carrier record
is later evicted.

If neither an event nor its exact loss report can be committed because storage
is exhausted or unhealthy, the spool enters terminal backpressure/fail-stop.
It does not acknowledge the event, delete victims, or silently forget the
range. Restart replays the durable state before normal forwarding resumes.

Producer event and batch sequences never wrap. Committing the final batch
sequence exhausts that producer authority: the final batch remains deliverable,
subsequent admission fails terminally without acknowledgement, and the operator
must drain it and rotate to a new producer session. Already queued events remain
the responsibility of their upstream admission boundary; no impossible batch
zero or reused identity is synthesized.

## Retrieval and wire behavior

Ordered retrieval is scoped to source node, producer session, and batch
sequence. It returns bounded cloned snapshots and uses sequence-aware lookup.
The forwarding client caches a suffix and advances through it without cloning
the complete active set for every send. Before selecting a cached record it
checks active membership so a concurrent ACK or eviction makes stale unsent
entries ineligible. The selection point may race only with eviction of the one
already selected in-flight batch; network I/O never holds the spool lock.
An eviction report can therefore overlap events already admitted by the
receiver before their ACK reaches the sender. Such historical coverage is
accepted without advancing the event high-water mark; every newly covered
sequence must still satisfy the receiver's exact gap checks.

ACK and flow-control messages have priority between sends. NACK rewinds the
cache to the requested sequence. Append wakes expose later batches after cache
exhaustion. Reconnect, pause/resume, sequence holes, cumulative ACK scope, and
the receiver-visible protobuf contract remain unchanged.
