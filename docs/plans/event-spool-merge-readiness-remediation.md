# Event Spool Merge-Readiness Remediation Plan

**Date:** 2026-09-17

**Status:** Complete — verified 2026-09-19

**Scope:** Reliable normalized-event forwarding from hunters and upstream
processors, plus merge-boundary documentation cleanup

## Objective

Resolve the pre-merge reliability and scalability findings in the durable event
spool without weakening its delivery, loss-reporting, flow-control, or recovery
contracts. The completed implementation must:

- drain a retained backlog with amortized linear retrieval, ACK processing,
  and active-set metadata work rather than repeatedly processing the complete
  spool;
- reject corrupt or oversized record lengths before allocating payload memory;
- keep the durable active set, in-memory records, byte accounting, and loss
  reports consistent across record publication, acknowledgement, cleanup
  failure, and restart; and
- state the branch's delivered offline milestone and deferred work without
  contradictory plan status.

## Merge boundary

This plan is a merge blocker for reliable event forwarding. The branch should
not merge until Phases 0–6 below are complete and their gates pass.

The compact source-backed offline index is a separate scope decision. This
branch delivers its completed-only milestone A. Progressive complete-base
browsing, analysis revisions, and the Phase-5-dependent final acceptance in
`watch-file-compact-source-index.md` remain milestone B and are not required by
this remediation. The documentation phase must make that boundary explicit; it
must not mark deferred work complete.

## Required invariants

- [x] A corrupt spool file cannot cause an allocation derived only from an
      untrusted record header.
- [x] Every accepted record fits the event transport's explicit maximum record
      size and exactly matches the bytes present in its file.
- [x] Record files are immutable after publication.
- [x] A versioned manifest checkpoint and its committed mutation journal are
      the source of truth for which immutable records are logically pending.
- [x] A logical transaction applies completely or not at all during recovery;
      partial cleanup never defines logical state.
- [x] `Spool.records`, logical pending bytes, `HasPending`, `RecoveryState`, and
      recovery agree after successful operations and failures before
      publication. Publication with uncertain durability stops normal operation
      until recovery resolves the state; it is never reported as rolled back.
- [x] Drop-oldest loss ranges describe exactly the records removed from the
      logical active set, even if physical orphan cleanup must be retried.
- [x] ACK remains cumulative only within the requested source node and producer
      session.
- [x] A reconnect drains `N` retained batches with O(N) batch cloning and no
      full-spool retrieval for each send.
- [x] Draining with one ACK per batch performs amortized O(N) active-set
      traversal and metadata work for fixed-size records, including checkpoint
      maintenance; enqueue does not rewrite the entire pending set each time.
- [x] Cached unsent records are checked against logical removal before send;
      eviction cannot leave a stale cached suffix eligible for transmission.
- [x] Oversized rejection and repeated exhaustion preserve exact, nonduplicated
      loss coverage and allow subsequent valid events to be admitted and ACKed.
- [x] Final replacement batches satisfy both byte and protobuf collection/range
      limits after inherited loss reports are attached. Local loss counters
      count newly incurred losses only.
- [x] NACK rewind, pause/resume, concurrent enqueue, reconnect, and ACK behavior
      remain unchanged at the wire-contract level.
- [x] No internal protobuf pointer is exposed to callers or mutated after
      publication.
- [x] Cleanup failures are reported with structured context and remain
      retryable; they are never silently discarded.

## Design decisions

### Bounded record admission

Use an explicit per-record maximum rather than platform `MaxInt`. Align the
default with the existing event transport limit: event ingress defaults to
4 MiB and gRPC has a 10 MiB upper bound. Define one shared or deliberately
related constant and reject a batch before writing if its deterministic
protobuf payload exceeds the configured limit. A zero total spool byte limit
must not disable the per-record safety limit.

Apply admission checks to the final payload, including all loss reports added
by eviction. Validate transport collection and range limits as well as bytes;
a record below 4 MiB can still be invalid at ingress. Account for the enclosing
gRPC message when relating the record bound to the transport ceiling. Define
how configured sender and receiver limits are kept compatible.

`readRecord` must inspect the already-open file before allocation. After
reading the fixed header, it must validate with overflow-safe arithmetic that:

1. the file is at least the header size;
2. the declared payload is within the per-record limit; and
3. `declared payload length == file size - header size`.

Only then may it allocate and read the payload. Corrupt files remain in place
for operator recovery.

### Rejection and exact loss accounting

Size rejection must have an explicit result that the forwarding sink handles;
returning an ordinary error for the dispatcher to log and forget is insufficient.
The sink must retain the rejected event's exact range, preserve inherited loss
coverage once, and advance batch sequence only for a committed batch. Separate
new losses used by `OnLoss` counters from inherited reports carried on the wire.

Normalize loss ranges by their source, session, and loss kind. Merge only
compatible adjacent or overlapping coverage, preserving exact counts and
non-overlapping wire ranges. Repeated `drop_new` must replace or merge pending
coverage, not append an inherited copy of it. Repeated `drop_oldest` must not
create an ever-growing list for coalescible ranges.

Coalescing alone cannot bound arbitrary fragmented coverage. Phase 0 must
select a durable bounded representation and a delivery strategy for loss
reports that exceed a single batch's byte or collection limits. If loss-only
batches are used, prove that receiver batch-gap and event-high-water rules
accept them. Never truncate ranges, delete victims before their loss report is
durable, or silently forget a rejected event. Define backpressure/fail-stop
behavior when neither the incoming event nor its exact loss report can be
persisted, including shutdown and restart recovery.

### Linear backlog retrieval

Replace `Serve`'s per-batch call to `Spool.Batches()` with a bounded ordered
suffix or cursor API scoped to source node, producer session, and batch
sequence. The forwarding client should cache the returned suffix/cursor and
advance through it without reacquiring and cloning the full active set.

Refill when the cached range is exhausted or a NACK rewinds the requested
sequence. Append wakes must expose later data without recloning the existing
suffix on every enqueue. Track logical removals separately, using an active
membership check or cursor invalidation that skips ACKed or evicted unsent
records without scanning/cloning the whole active set. Define a send-selection
linearization point and bound the race with a subsequently committed eviction
to the already selected in-flight batch; do not hold the spool lock over network
I/O. ACK and flow-control messages retain priority between sends. The API must
return clones or immutable values, not internal spool pointers.

### Failure-consistent logical deletion

Use immutable record files, a versioned active-record manifest checkpoint, and
a checksummed mutation journal. The checkpoint records ordered active basenames,
identity/accounting data, and the journal position/generation it incorporates.
Journal transactions record atomic additions/removals, including a replacement
and all its eviction victims together. Scope cumulative ACK transactions to the
source and producer session. Do not rewrite the full checkpoint or scan/copy
all retained records for each enqueue or ACK.

Publish and sync new immutable records before referencing them in a journal
transaction. Sync the transaction before reporting successful admission or ACK
retirement, then apply the same logical mutation in memory. Only afterward may
garbage collection unlink records no longer needed by recovery. Checkpoint
replacement uses a same-directory temporary file, file sync, rename, and
directory sync; journal retirement must wait until the replacement checkpoint
is durable. Define framing, transaction boundaries, strict corruption versus
incomplete-tail handling, replay idempotence, and generation handoff in Phase 0.
Checkpoint frequency and journal rotation must have an amortized linear cost
bound for backlog build and drain, with bounded recovery work relative to
retained records and the configured journal threshold.

Failures before publication preserve the previous authoritative state. A
successful rename followed by failed directory sync does **not** establish
rollback: the new checkpoint is already visible, but its power-loss durability
is uncertain. Likewise, a journal write/sync error may leave a complete visible
transaction. Classify these outcomes as durability-uncertain, preserve files
needed by either recoverable state, suspend sends/mutations/garbage collection,
and require recovery before resuming. Callers must not reuse a sequence or
forget an event based on a presumed rollback. Define how recovery reconciles
visible records, sequence allocation, and pending loss state before clearing
this barrier. Status APIs must expose uncertainty rather than claim an ordinary
empty or healthy spool.

Process reopen observes the filesystem's visible state; simulated power-loss
recovery may observe a different state at an unsynced boundary. Tests must
distinguish these cases and enumerate permitted complete outcomes. After a
durable commit, cleanup failures do not undo the mutation: reopening ignores
orphans and retries cleanup. Physical/orphan bytes must be distinguished from
logical pending bytes wherever capacity policy or status reporting depends on
them.

Legacy spool directories without a manifest must be validated completely and
then migrated by atomically publishing an initial checkpoint and establishing
its journal generation before enabling mutations. Do not silently
discard malformed, duplicate, mixed-session, or ambiguous legacy records.

## Phase 0 — Baseline and contracts

- [x] Add a focused benchmark or deterministic counter around current backlog
      retrieval that demonstrates repeated complete-spool cloning.
- [x] Record baseline time and allocations for 1,000 and 10,000 retained
      batches using fixed batch payload sizes.
- [x] Include backlog build and full drain with one ACK per batch; measure
      active-set visits, serialized metadata bytes, and sync/rotation counts
      separately from retrieval clones and wall time.
- [x] Add table-driven characterization tests for current ACK, NACK,
      pause/resume, reconnect, ordering, sequence holes, and enqueue-during-
      drain behavior before changing retrieval.
- [x] Define the exact per-record byte limit and its relationship to processor
      ingress and gRPC message limits in code comments and operator-facing
      documentation.
- [x] Specify checkpoint/journal formats, transaction framing and checksums,
      replay rules, generation handoff, compaction thresholds, and amortized
      cost bounds. Include incremental ACK indexing and record removal.
- [x] Define pre-publication, durable-success, durability-uncertain, and
      committed-with-cleanup-failure outcomes through spool, client, sink, and
      upstream callers, including status, recovery, and sequence reuse rules.
- [x] Define logical versus physical byte semantics, orphan policy, legacy
      migration, and exclusive ownership of a spool directory during recovery
      and mutation.
- [x] Specify normalized loss accounting, oversized-rejection handling,
      durable pending-loss representation, report overflow, receiver-compatible
      delivery, and terminal storage-exhaustion behavior.

**Gate:** The old quadratic behavior is reproducible, existing forwarding
semantics are pinned by tests, and the recovery/size contracts are unambiguous.

## Phase 1 — Bound record reads and writes

The read/admission changes can begin before Phase 3. Pending-loss persistence
and restart acceptance complete alongside Phase 3; this phase's final gate must
not be marked passed until that integration is verified.

Primary files:
`internal/pkg/hunter/eventspool/spool.go`,
`internal/pkg/hunter/eventforwarding/{client,sink}.go`,
`internal/pkg/events/protoadapter/adapter.go`, and their tests; receiver and
upstream integration tests in `internal/pkg/processor/`.

- [x] Add a non-zero default maximum record payload and validate configuration
      without allowing total-spool `MaxBytes == 0` to remove this safety bound.
- [x] Reject oversized deterministic protobuf payloads in `Enqueue` before
      creating a temporary record. Recheck the final replacement after adding
      eviction losses; reject invalid transport collections/ranges as well.
- [x] Implement explicit oversized-rejection handling in the sink and client,
      retaining exact loss coverage without reusing a committed sequence.
- [x] Fix repeated `drop_new` inherited-loss duplication and separate newly
      incurred losses from inherited coverage for `OnLoss` counters.
- [x] Normalize/coalesce loss coverage across repeated `drop_oldest`, with the
      Phase 0 overflow strategy when exact coverage cannot fit one batch.
- [x] Implement durable pending-loss and fail-stop/backpressure behavior;
      integrate its persistence with Phase 3 before declaring this gate passed.
- [x] Test oversized event followed by valid event through real receiver
      admission and ACK for both hunter and upstream forwarding.
- [x] Test repeated `drop_new`, more than 4,096 coalescible evictions,
      fragmented loss overflow, final-payload boundary growth, and terminal
      loss-only flush/restart. Assert exact ranges, counters, receiver acceptance,
      and subsequent forwarding progress.
- [x] Change `readRecord` to stat the open file and validate exact payload size
      and the per-record limit before allocation.
- [x] Preserve checksum, protobuf, format-version, and trailing-data validation
      after the new size checks.
- [x] Add tests for a header declaring `MaxUint64`, a declaration over the hard
      limit, a declaration larger or smaller than the remaining file, a
      header-only truncated record, trailing bytes, and an exact-boundary valid
      record.
- [x] Assert that every rejected corrupt record remains on disk and that open
      returns a contextual error without panic or large allocation.
- [x] Add fuzz coverage for header parsing and payload-length arithmetic with a
      small memory budget.

**Gate:** No untrusted length controls allocation before exact file-size and
hard-limit validation; final records satisfy receiver validation; rejection and
prolonged exhaustion preserve loss coverage and forwarding progress. Durable
loss-state checks depend on Phase 3. Malformed-record tests pass under the race
detector.

## Phase 2 — Make backlog drain linear

Primary files:
`internal/pkg/hunter/eventspool/spool.go`,
`internal/pkg/hunter/eventforwarding/client.go`, and their tests.

- [x] Add an ordered retrieval API such as
      `BatchesAfter(source, session, afterSequence, limit)` or an equivalent
      cursor that clones each returned batch at most once per forward pass.
- [x] Keep lookup ordered and bounded; use sequence-aware indexing or binary
      search where the single-session spool invariant permits it.
- [x] Cache and advance the retrieved range in `Client.Serve` rather than
      calling `Batches()` for each sent batch.
- [x] Invalidate and refill the cached range on NACK rewind, while preserving
      ACK/control priority and the one-batch pause overshoot bound.
- [x] Ensure a wake received during drain or after range exhaustion makes newly
      enqueued records visible without resending acknowledged records.
- [x] Add removal-aware send selection for cached records, including concurrent
      drop-oldest and ACK; append-only wakes must not invalidate/reclone the
      entire cached suffix. Release consumed clones promptly.
- [x] Add tests for large ordered backlogs, sequence holes, NACK rewind,
      enqueue during drain, ACK while a range is cached, reconnect, and
      pause/resume.
- [x] Test pause → concurrent eviction → resume, eviction during drain, and
      sustained enqueue wakes. Assert removed unsent records are skipped,
      receiver loss coverage remains valid, and any selection/eviction race is
      bounded to the already selected batch.
- [x] Add a retrieval-count seam proving a fixed backlog does not perform one
      complete-spool fetch per batch.
- [x] Add 1,000- and 10,000-batch benchmarks reporting time, allocations, and
      bytes allocated; demonstrate approximately linear scaling.
- [x] Run the processor upstream event-router regression tests because it
      reuses the forwarding client.

**Gate:** Retrieval preserves wire behavior and performs O(N) cloning and
traversal for N retained batches, including removal-aware caching. The complete
drain scaling gate also requires Phase 3 metadata and ACK changes.

## Phase 3 — Add atomic active-set transactions and checkpoint recovery

Primary files:
`internal/pkg/hunter/eventspool/spool.go` and
`internal/pkg/hunter/eventspool/spool_test.go`.

- [x] Introduce the versioned manifest checkpoint and checksummed mutation
      journal defined in Phase 0, including identity, accounting, generations,
      and atomic replacement-plus-victim transactions.
- [x] Reject unsafe manifest paths, duplicate entries, unsupported versions,
      missing referenced records, inconsistent record identity, and invalid
      logical byte totals.
- [x] Implement atomic manifest creation/replacement using a same-directory
      temporary file, file sync, rename, and directory sync.
- [x] Implement bounded, idempotent journal replay and durable checkpoint/
      journal handoff; never retire recovery data before its successor is synced.
- [x] Make `Open` use checkpoint plus journal as active-set authority and treat
      unreferenced record files as retryable orphans rather than pending data.
- [x] Migrate a validated legacy directory without a manifest by publishing an
      initial checkpoint and journal generation before normal mutation continues.
- [x] Refactor drop-oldest `Enqueue` to publish the replacement record, commit
      the active-set transaction, update in-memory state, and then collect
      unreferenced victims.
- [x] Route every successful enqueue, including `drop_new` admission and
      non-evicting admission, through the same transaction mechanism.
- [x] Refactor `Ack` to commit cumulative retirement before collecting records;
      use incremental indexing/removal without a full retained-set scan/copy.
- [x] Implement the durability-uncertain barrier and caller recovery contract
      for journal write/sync and post-rename directory-sync failures.
- [x] Integrate pending-loss durability and recovery with active-set mutations.
- [x] Enforce exclusive spool ownership so another opener cannot race journal
      replay, active-set publication, or orphan cleanup; release ownership on
      close and failed startup, including upstream route lifecycle paths.
- [x] Benchmark full backlog build and drain at 1,000 and 10,000 batches with
      one ACK per batch, forcing checkpoint/rotation boundaries. Assert
      amortized linear metadata work as well as retrieval cloning.
- [x] Track logical pending bytes independently from physical/orphan bytes and
      document which value enforces configured capacity.
- [x] Make orphan cleanup idempotent and retry it during `Open` and later safe
      mutation points.
- [x] Inject filesystem operations through per-spool, unexported test hooks;
      avoid mutable package globals so tests remain race-safe.
- [x] Return or log cleanup failures with record path, operation, and logical
      commit state. Ensure callers never retry an already committed batch with
      the same sequence because cleanup alone failed.

**Gate:** Checkpoint/journal recovery and memory agree for resolved outcomes;
uncertain outcomes halt normal operation until recovery. Cleanup cannot change
logical delivery or loss semantics. Full backlog build/drain meets the
amortized linear metadata and ACK-work bounds.

## Phase 4 — Failure and crash-point verification

- [x] Inject failure of the first, middle, and last victim unlink for both
      drop-oldest enqueue and cumulative ACK.
- [x] Inject manifest temporary-create, write, file-sync, rename, and directory-
      sync failures.
- [x] Inject record-publication and journal partial-write/sync failures;
      distinguish no visible transaction, incomplete tail, complete uncertain
      transaction, and interior corruption. Preserve corrupt evidence.
- [x] Test crash/reopen points after record publication, after manifest
      publication, during orphan cleanup, and after cleanup but before return.
- [x] For every failure point, compare active sequences, identities, logical
      bytes, loss ranges, sequence allocation, and recovery/status results
      against the permitted outcomes defined in Phase 0.
- [x] Verify failures before publication retain the previous active set. Test
      rename-success/directory-sync-failure separately: do not assert rollback
      of the visible checkpoint.
- [x] Verify uncertain durability prevents sends, mutations, cleanup, and
      sequence reuse until recovery resolves the state.
- [x] Separate process-reopen tests from a modeled power-loss persistence
      harness; enumerate old/new complete states at unsynced boundaries and
      prove that retained files support either recovery outcome.
- [x] Exercise checkpoint publication, journal rotation/retirement, and replay
      crash boundaries, including empty active sets and pending loss reports.
- [x] Verify committed transactions never reactivate an orphan, duplicate a batch
      sequence, or report loss for a logically retained record.
- [x] Verify cleanup retry eventually removes all unreferenced files without
      altering the logical active set.
- [x] Verify ACK failure handling never removes a record from another source or
      producer session.
- [x] Verify legacy migration is crash-safe and idempotent.
- [x] Test committed-with-cleanup-failure through the real sink/client and
      upstream router: advance sequence once, notify forwarding, retain exact
      loss accounting, and never retry a committed batch as a fresh enqueue.
- [x] Run the spool and forwarding tests repeatedly and under `-race`.

**Gate:** All injected failures and crash points recover a complete permitted
transaction state with exact loss accounting; uncertainty is explicit and
cannot trigger destructive cleanup or continued forwarding before recovery.

## Phase 5 — Plan and release-scope cleanup

Primary files:
`docs/plans/watch-file-compact-source-index.md`,
`docs/plans/tui-event-view-performance-optimization.md`, and relevant operator
documentation for event spool limits/recovery.

- [x] Add a compact-index `Merge boundary` section stating that this branch
      delivers completed-analysis milestone A only and that publication still
      waits for analyzer EOF.
- [x] Keep every milestone-B/Phase-5 revision, lifecycle, and progressive-
      browsing task unchecked and explicitly deferred.
- [x] Rename or reorganize compact-index Phase 6 so its dependency on milestone
      B is clear; move already completed milestone-A profiling work out of the
      still-pending final-acceptance checklist.
- [x] Record the disposition of persistent index reuse as deferred if it is not
      part of this merge.
- [x] Reconcile the TUI performance plan's completed status with its stale
      unchecked design/invariant/target lists: convert design choices to normal
      bullets, check only evidence-backed acceptance criteria, and preserve any
      genuinely deferred generic-ring extraction as a non-goal.
- [x] Replace the stale statement that manual gates remain unchecked with the
      later verified final-acceptance chronology, or reopen the top-level status
      if supporting evidence is missing.
- [x] Document the event spool record limit, manifest recovery behavior,
      journal/checkpoint lifecycle, durability-uncertain behavior, oversized
      rejection, loss-report overflow, orphan cleanup, physical versus logical
      capacity, and actionable startup errors.
- [x] Preserve the TUI acceptance evidence's controlled-live-delivery caveat;
      do not imply privileged NIC or transport-throughput verification.

**Gate:** No plan simultaneously claims final verification and pending
acceptance; milestone A and milestone B are unmistakably separated; spool
recovery behavior is operator-visible.

## Phase 6 — Final verification and merge gate

- [x] Run `gofmt` on every changed Go file before staging.
- [x] Run focused normal and race tests for `eventspool`, `eventforwarding`, and
      `processor/upstream`, plus affected protoadapter and processor ingress
      tests, including rejection/exhaustion → recovery → receiver ACK paths.
- [x] Run the malformed-record fuzz target for a bounded duration and record the
      seed/corpus result.
- [x] Run and record the 1,000- and 10,000-batch drain benchmarks against the
      Phase 0 baseline. Include build, one-ACK-per-batch drain, forced metadata
      compaction, and sustained enqueue/eviction; report metadata bytes/visits
      and cloning separately from filesystem latency.
- [x] Run `GOCACHE=<temporary-directory> make test` outside the sandbox so
      loopback integration tests can execute.
- [x] Run `make vet` for the required `all` and `li` partitions.
- [x] Run `make build-matrix` and verify `all`, `hunter`, `processor`, `tap`,
      `cli`, `tui`, `all,li`, `processor,li`, and `tap,li`.
- [x] Run `git diff --check` and confirm the worktree contains no unrelated
      edits.
- [x] Re-review the final diff specifically for manifest path safety,
      journal framing/replay, durability uncertainty, checkpoint handoff,
      byte-accounting overflow, lock scope, error handling, clone ownership,
      cached-record eviction, exact loss normalization, and caller sequence
      handling.
- [x] Update this plan with measured results and check off only tasks supported
      by code, tests, or recorded evidence.
- [x] Commit the implementation, tests, documentation, and completed plan
      together in scoped commits as required by repository instructions.
- [x] Remove temporary caches, fuzz artifacts, benchmark output, and test logs.

**Merge gate:** All prior phase gates pass; no high-severity spool finding
remains; full tests, race coverage, vet, and the supported build matrix pass;
and the plan/documentation state accurately describes delivered and deferred
scope.

## Recorded baseline and implementation evidence

The pre-remediation baseline was measured from commit `bdc1048c` on a
13th Gen Intel Core i9-13900HX with one benchmark iteration and fixed minimal
batches. Backlog construction was already approximately linear, while the old
send path called `Batches()` once per batch and cloned the complete remaining
active set. One-ACK-per-batch drain therefore made `N(N+1)/2` retrieval clones
and the same order of ACK visits.

| Workload     |    Time | Bytes allocated | Allocations |               Deterministic old-path work |
| ------------ | ------: | --------------: | ----------: | ----------------------------------------: |
| Build 1,000  | 9.23 ms |         2.14 MB |      22,445 |                 1,000 record publications |
| Build 10,000 | 95.3 ms |        21.35 MB |     220,097 |                10,000 record publications |
| Drain 1,000  | 67.2 ms |        76.65 MB |     505,522 |    500,500 clones plus full-scan ACK work |
| Drain 10,000 |  5.60 s |         7.63 GB |  50,055,135 | 50,005,000 clones plus full-scan ACK work |

Final implementation measurements used one benchmark iteration on the same
host. Filesystem latency dominates the absolute timings, while the counters
show the scaling change directly.

| Workload                     |     Time | Bytes allocated | Allocations |                   Deterministic final-path work |
| ---------------------------- | -------: | --------------: | ----------: | ----------------------------------------------: |
| Build + one-ACK drain 1,000  |  56.9 ms |        22.24 MB |     288,516 |                   checkpointed transaction path |
| Build + one-ACK drain 10,000 | 550.5 ms |       225.05 MB |   2,870,824 |                   checkpointed transaction path |
| Forwarding drain 1,000       |  13.3 ms |         4.08 MB |      34,743 |    1,000 clones, 1,999 ACK visits, 8 retrievals |
| Forwarding drain 10,000      | 115.9 ms |        42.49 MB |     350,056 | 10,000 clones, 19,999 ACK visits, 79 retrievals |
| Sustained replacement 1,000  |  73.1 ms |        23.47 MB |     390,857 |             446,876 metadata bytes, 7 rotations |
| Sustained replacement 10,000 | 514.9 ms |       234.81 MB |   3,913,460 |          4,519,980 metadata bytes, 78 rotations |

The fixed-backlog forwarding path changed from 500,500 to 1,000 clones at
1,000 batches and from 50,005,000 to 10,000 clones at 10,000 batches. ACK
visits are `2N-1`, and retrieval calls scale with the bounded 128-batch window.
Metadata bytes and rotations scale approximately tenfold from 1,000 to 10,000
mutations.

Final verification passed:

- focused normal and race tests for events, protoadapter, spool, forwarding,
  hunter, processor ingress, and upstream routing;
- the malformed-header fuzz target for 30 seconds with 165,333 executions and
  140 total corpus entries under a 256 MiB memory limit;
- `GOCACHE=/tmp/lippycat-remediation-gocache make test` outside the sandbox;
- `make vet` for the `all` and `li` partitions;
- `make build-matrix`, covering `all`, `hunter`, `processor`, `tap`, `cli`,
  `tui`, `all,li`, `processor,li`, and `tap,li` while intentionally skipping
  CUDA on this non-CUDA builder;
- `make manual`, `gofmt`, and `git diff --check`; and
- three review passes over path safety, framing and replay, uncertain
  durability, checkpoint handoff, overflow, locking, clone ownership, cached
  eviction, exact loss accounting, and sequence handling. No critical or high
  severity finding remains; the final multi-orphan cleanup finding was fixed
  and covered by regression tests.

### Post-completion source audit

A source-to-plan audit on 2026-09-17 found and corrected several gaps that the
initial verification had not exercised: steady-state fragmented-loss draining,
loss-only capacity enforcement, retained-loss identity validation, aggregate
loss-count overflow, duplicate batch publication, inherited-loss counter
duplication, recovery-state reset, short-write handling, record-only physical
byte accounting, definite pre-publication orphan cleanup, and batch-sequence
wrap guards. New regressions cover more than 4,096 fragmented loss ranges,
bounded drop-new/drop-oldest loss flushing, restart-safe duplicate rejection,
mixed identity rejection, aggregate counter overflow, maximum-range
normalization, short writes, and stable physical-byte semantics. Focused normal
and race tests for `eventspool`, `eventforwarding`, `processor/upstream`, and
`protoadapter`, plus hunter and processor event-ingress tests, passed after the
corrections. The complete `make test` target, including the `all` and `li`
partitions and loopback integration tests, also passed outside the sandbox.

A second source-to-plan audit on 2026-09-17 corrected six remaining boundary
conditions: a missing manifest can no longer cause current-format journal
history to be mistaken for legacy records; journal transactions larger than one
bounded frame use an atomic fresh-generation checkpoint instead of entering a
false uncertainty/retry loop; loss-only drop-oldest replacement must strictly
reduce pending-loss work and therefore cannot cycle carriers forever; live event
and batch sequences stop at `MaxUint64` without wrapping; and processors reject
an ingress byte limit below the shared 4 MiB durable-sender contract. Physical
record bytes are now reported immediately after a visible rename even when the
following directory sync makes durability uncertain. Regression tests cover
each case, including oversized-checkpoint rollback of a drained fixed session.
Focused normal and race tests for events, protoadapter, eventspool,
eventforwarding, and processor upstream routing passed, as did the tagged
processor event-ingress tests.

A third source-to-plan audit on 2026-09-18 corrected the remaining recovery
and accounting gaps: exact loss normalization now fails stopped before an
aggregate counter can overflow; pending ranges that overlap across different
loss kinds are rejected before they can become durable but unforwardable;
cumulative acknowledgement and eviction retirement state is checkpointed and
journaled so a retired batch identity cannot be reused after cleanup or
restart; journal transaction and generation counters fail before wraparound;
and failed cleanup of a
partially written temporary record remains included in physical-byte status.
The audit also removed the obsolete unused journal replay implementation and
added the previously missing regressions for repeated drop-new, more than
4,096 coalescible evictions, final replacement growth at the record limit,
real cached drop-oldest eviction, and committed cleanup failure through the
upstream sink/client path. Focused normal and race tests for `eventspool`,
`eventforwarding`, `processor/upstream`, and `protoadapter` passed after these
corrections.

A fourth source-to-plan audit on 2026-09-18 found and corrected five final
contract gaps: legacy migration now rejects malformed or record-mismatched
session policy before publishing a checkpoint; authoritative record loading
rejects symlinks and detects replacement during open; the checkpoint trigger
now bounds replay frames by the current retained set plus the configured
threshold during partial drains; processor ingress accepts exact loss-only
coverage across a retired batch gap while rejecting ranges that overlap prior
admission; and a recovered `MaxUint64` final batch starts in drain-only mode
instead of being rejected before forwarding. The hunter rotates to a fresh
producer session after that final batch is ACKed, while upstream routes remain
closed to wrapped admission. New regressions cover each boundary, including
restart and ACK retirement of the final batch. A final adversarial review also
verified multi-carrier loss recovery at `MaxUint64-1`: the last available
carrier remains forwardable, residual exact coverage remains durable and
fail-stops explicitly after that carrier drains, and normalized durable loss
sets above 4,096 ranges remain restart-valid even though each wire carrier is
bounded to the transport collection limit. The terminal recovery path also
starts forwarding before it publishes pending-loss carriers: on a byte-full
drop-new spool, ACK drain first frees capacity, the bounded carrier is then
committed and wakes the active stream, and only a carrier that still cannot be
stored after all older records drain causes an explicit terminal stop. Any ACK
or carrier publication that leaves durability uncertain also fails closed
instead of leaving the drain-only recovery loop waiting indefinitely; only a
post-commit physical-cleanup error remains non-terminal.

The audit also completed the benchmark evidence required by Phase 6. One-iteration
measurements on the recorded i9-13900HX host reported the deterministic counters
separately:

| Workload                     |     Time | Allocated | ACK visits | Metadata bytes | Retrieval clones/calls | Checkpoints/rotations |  Syncs |
| ---------------------------- | -------: | --------: | ---------: | -------------: | ---------------------: | --------------------: | -----: |
| Build + one-ACK drain 1,000  |  65.6 ms |  23.93 MB |      1,999 |      1,165,066 |                    n/a |                 8 / 7 |  5,039 |
| Build + one-ACK drain 10,000 | 552.4 ms | 245.40 MB |     19,999 |     12,264,870 |                    n/a |               14 / 13 | 50,069 |
| Forwarding drain 1,000       |  14.6 ms |   4.73 MB |      1,999 |      1,114,235 |              1,000 / 8 |                 6 / 5 |  5,029 |
| Forwarding drain 10,000      | 114.1 ms |  53.04 MB |     19,999 |     12,203,399 |            10,000 / 79 |               12 / 11 | 50,059 |
| Sustained replacement 1,000  |  61.9 ms |  25.68 MB |        n/a |        473,970 |                    n/a |               n/a / 7 |  4,038 |
| Sustained replacement 10,000 | 668.8 ms | 256.85 MB |        n/a |      4,801,072 |                    n/a |              n/a / 78 | 40,393 |

A fifth source-to-plan audit on 2026-09-18 corrected physical-byte accounting
for a fully written temporary record when publication rename and subsequent
cleanup both fail. The retryable temporary file is now reflected immediately
in status and subtracted exactly once when later cleanup succeeds. A focused
regression covers the failure and retry path. Accounting overflow is checked
before addition, and a failed disk reconciliation now enters the recovery
barrier instead of allowing mutation with stale status. Focused normal and race
tests for `eventspool`, `eventforwarding`, `processor/upstream`, and
`protoadapter` passed after the correction.

A sixth source-to-plan audit on 2026-09-18 corrected the remaining receiver,
forwarding, and storage-boundary gaps. Processor ingress now rejects loss-only
and normal batches whose reported loss ranges would advance the event high-water
across an uncovered trailing sequence. Assigned events that cannot satisfy the
transport representation limits are durably recorded as exact unsupported-event
losses instead of being logged and forgotten, and both hunter and upstream paths
continue with the next valid event using the unconsumed batch sequence.
Authoritative manifest and journal opens now reject symlinks and replacement,
including steady-state journal append. Replay rejects duplicate or inactive
removal names. Ambiguous cleanup followed by `ENOENT` reconciles physical bytes
instead of leaving the counter inflated. Finally, a definite checkpoint
publication failure after a committed transaction enters an explicit
checkpoint-required barrier: committed state and pending status remain visible,
further mutation and sending stop, and recovery compacts the bounded journal
before resuming. Focused normal and race tests for `eventspool`, focused
forwarding and upstream tests, and tagged processor-ingress regressions passed.

A seventh source-to-plan audit on 2026-09-19 corrected three recovery and
identity-boundary gaps. Hunter terminal-sequence recovery now treats a
checkpoint-required spool as a fail-closed recovery barrier instead of waiting
forever while the spool reports committed pending state but refuses sends and
mutations. Missing-manifest migration also opens the initial journal with the
same no-follow, regular-file validation used by normal authoritative metadata
recovery, so a symlink cannot be trusted as the generation-one migration
journal. Finally, every loss record must carry the enclosing producer session
before transport admission or durable spool publication; record recovery and
pending-loss commits defensively enforce the same rule, preventing unusable
gap coverage and self-inconsistent manifests after restart. Regression tests
cover all three cases, including preservation of the external symlink target.
The more-than-4,096 coalescible-eviction regression now publishes its synthetic
base as an authoritative checkpoint and reopens the replacement transaction,
so it exercises journal replay as well as live normalization.

An eighth source-to-plan audit on 2026-09-19 corrected six remaining issues:
live transaction validation and journal replay scanned the complete active set;
recovery could retire the old journal after uncertain checkpoint publication;
replay recomputed and thereby masked inconsistent checkpoint byte totals;
loss-carrier splitting followed loss-kind order instead of event sequence;
loss-only eviction deferred earlier victim coverage behind the outgoing
carrier; and ingress rejected valid historical loss coverage when eviction
raced a delayed ACK. Live membership and replay now use incrementally updated
maps, uncertain recovery preserves both journal generations, checkpoint totals
are validated before replay, and carrier partitions include victim coverage in
event sequence order across kinds. Ingress accepts historical coverage while
continuing to reject every uncovered new event gap.

Regression tests cover deterministic transaction/replay work, uncertain
recovery with the old checkpoint restored to model power loss, corrupt byte
totals, more than 4,096 interleaved mixed-kind ranges through real ingress,
loss-only eviction, and delayed-ACK eviction with both memory-only and reliable
receivers. Focused normal and race tests passed for `eventspool`,
`eventforwarding`, `processor/upstream`, and `protoadapter`; tagged processor
ingress and carrier tests also passed under the race detector. The full suite
and build matrix above remain historical verification, not reruns of this
audit. Formatting and `git diff --check` passed.

One-iteration measurements on the same host add counters for the previously
unmeasured transaction and replay traversal:

| Workload                           |     Time | Allocated | Transaction visits | Replay visits |
| ---------------------------------- | -------: | --------: | -----------------: | ------------: |
| Build + one-ACK drain 1,000        |  80.6 ms |  25.04 MB |              3,000 |           n/a |
| Build + one-ACK drain 10,000       | 604.3 ms | 256.54 MB |             30,000 |           n/a |
| Replay half-drained backlog 1,000  |  16.1 ms |   4.36 MB |                n/a |         2,000 |
| Replay half-drained backlog 10,000 |  92.0 ms |  42.94 MB |                n/a |        20,000 |

A ninth source-to-plan audit on 2026-09-19 found two additional boundary gaps.
Forwarding could wait indefinitely when removal consumed an entire cached
suffix even though another retrieval window remained pending. The client now
refills before waiting for another wake. Recovery also needed to sync the
visible replayed journal and spool directory before deleting retired records
or obsolete journals; without that barrier, a second crash could restore old
metadata after its required files had been deleted. Failed recovery syncs now
preserve those files and leave the durability barrier active.

Regressions cover complete cached-window retirement, failed recovery journal
and directory syncs, and a second crash restoring the older journal or
checkpoint. These tests reproduce the gaps before the fixes.
Focused normal and race suites passed for `eventspool`, `eventforwarding`,
`processor/upstream`, and `protoadapter`. Tagged processor ingress regressions
also passed under the race detector. Go formatting and `git diff --check`
passed; the full suite and build matrix remain the historical checks recorded
above.

A tenth source-to-plan audit on 2026-09-19 corrected two additional gaps.
Retired records retained protobuf payloads through the spool slice's backing
array after ACK or eviction; retirement now clears removed slots and releases
the backing array when drained. Reliable processor ingress also ACKed valid
eviction replacements across batch-sequence gaps without dispatching them.
Dispatch now checks whether all previously admitted batches were dispatched,
allowing validated gaps while preserving ordering behind deferred WAL records.

Deterministic retention tests and the delayed-ACK eviction delivery regression
failed before the fixes and passed afterward. Coverage also verifies subsequent
delivery and ordering behind an undispatched WAL batch. Focused normal tests
passed, followed by race tests with the `all` tag for `eventspool`,
`eventforwarding`, all processor packages, and `protoadapter`. Go formatting and
`git diff --check` passed. Full-suite and build-matrix results remain the
historical checks above.

## Explicit non-goals

- Implementing compact-index milestone B or marking its Phase 5 complete.
- Persistent reuse of offline compact indexes.
- Changing event protobuf identity, projection, authorization, or loss-range
  wire contracts.
- Weakening reliable delivery by deleting corrupt records automatically.
- Treating best-effort physical cleanup as the source of logical spool state.
- Adding CUDA verification on a host without the CUDA toolchain; CUDA remains a
  separate builder gate.
