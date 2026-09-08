# LI delivery buffer limits and X2 persistence

Drafted: 2026-09-08. Code baseline: `16c752cc`.

## Objective

Make X2/X3 delivery buffering configurable by bytes and age, preserve queued X2
across restarts, and expose resource exhaustion and discarded product. Apply the
same behavior to processor and tap.

The feature covers lippycat's delivery queues and their lifecycle. Authority-facing
handover protocols and external alarm adapters are outside its scope. Existing
reconnect handling and [delivery telemetry](li-delivery-telemetry.md) remain the
foundation. The implementation and validation record below defines the finalized policy.

## Current code and gaps

| Area                     | Implementation                                                                                                                                                                | Gap                                                                                                                                                             |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Queues                   | [client.go](../../internal/pkg/li/delivery/client.go): separate X2/X3 slices per destination, each capped at 10,000 PDUs by default                                           | No byte cap, age expiry or persistence. Overflow shifts the slice in O(n).                                                                                      |
| Dispatch                 | `peekBatch`, `destinationDispatcher`, `pop`                                                                                                                                   | Selected pointers can outlive eviction and still be written. One dispatcher/backoff per destination lets either interface stall the other.                      |
| Transport                | [destination.go](../../internal/pkg/li/delivery/destination.go)                                                                                                               | Separate interface pools exist, but acquisition also uses destination-wide connection state. The writer sets a relative timeout after acquiring its write lock. |
| Shutdown                 | `Client.Stop`                                                                                                                                                                 | Immediately discards queues as `shutdown_timeout`; does not use `ShutdownTimeout` to drain or decrement aggregate queue depth.                                  |
| Timing and lifecycle     | [reorder.go](../../internal/pkg/li/delivery/reorder.go), [processor_li.go](../../internal/pkg/processor/processor_li.go)                                                      | Final delivery enqueue starts the age clock. Delivery entries lack task/call generations carried by earlier admission stages.                                   |
| Producers                | [metadata_sink.go](../../internal/pkg/li/metadata_sink.go), synchronous send methods in `client.go`                                                                           | All producers need consistent queue policy; sync methods currently bypass queues and ordering.                                                                  |
| Configuration and status | [process flags](../../cmd/process/flags_li.go), [tap flags](../../cmd/tap/flags_li.go), [delivery stats mapping](../../internal/pkg/processor/processor_li_delivery_stats.go) | Expose separate limits, persistence state and byte accounting while preserving existing field meanings.                                                         |

The [older reconnect plan](li-delivery-reconnect-buffering.md) describes historical
code. Use the current implementation as the baseline.

## Feature design

### Configurable limits

Add independent X2/X3 byte budgets and PDU caps per destination/interface, an
optional X3 maximum age, and optional X2 journal configuration. Tentative options
are `--li-delivery-x2-queue-bytes`, `--li-delivery-x3-queue-bytes`,
`--li-delivery-x3-max-age`, `--li-delivery-x2-spool-dir` and
`--li-delivery-x2-spool-max-bytes`.

Keep existing behavior by default: the existing queue-size flag remains the PDU
cap, age expiry is disabled, and persistence is disabled. New limits are explicit
operator choices. A five-minute example is a configurable duration, not a fixed
requirement. X2 does not inherit X3 expiry.

Reserve configured capacity per destination/interface and validate allocations
against an overall memory budget. Include queued and in-flight items, ingress
buffers, reporting state and object overhead. Account logical destination bytes
separately from physically shared payload bytes. Define oversized-PDU rejection
and reject overcommitted configuration rather than borrowing another queue's
reserved capacity during an outage.

Document sizing as peak encoded bytes/second multiplied by the desired outage
duration, with headroom and a sufficient PDU cap. Recovery throughput must also
exceed ongoing traffic if the backlog is to drain.

### Queue ownership and expiry

Use an O(1) deque/ring and one dispatcher per `(destination, interface)`, each with
independent retry state. Backlog and live arrivals share FIFO ordering within
each interface. Preserve the existing RTP reorder stage before delivery enqueue.

Give entries explicit queued, claimed, completed and discarded states. Eviction,
expiry, lifecycle cancellation and shutdown must not leave stale sendable batch
pointers. Count claimed entries against capacity until resolved. Cancelling a
write may require closing its transport; classify partial or uncertain writes
separately from known queue drops.

Carry first local LI admission time, original capture/event time, immutable
deadline, task activation generation, destination generation and applicable call
generation through reorder, fan-out and retries. Measure live residence with a
monotonic clock. Capture timestamps remain diagnostic metadata and cannot extend
the local deadline. Retrying never resets age.

Expire X3 even while disconnected or idle, using the next deadline to wake the
owner. Revalidate absolute expiry after acquiring the transport write lock, and
limit the write deadline to remaining lifetime. Bytes already accepted by the
transport cannot be recalled; local write completion does not prove MDF receipt.

### Optional X2 journal

Persist X2 only, using bounded, versioned records with checksums, atomic
checkpoints and FIFO replay. Keep X3 memory-only. Restrict journal permissions
and define encryption/key configuration. Journal immutable encoded bytes and
their delivery/lifecycle identity rather than reconstructing PDUs on replay.

Keep filesystem I/O off the packet path. Distinguish accepted into memory from
confirmed persisted: an asynchronous enqueue success is not a durability
acknowledgement. Expose and test the crash window before the journal worker syncs.
Exhaustion must reject and account new admissions explicitly while preserving
already journaled X2. Bound pending ingress and reserve space for fault metadata.
The existing in-memory overflow behavior remains available when journaling is off.

Reconcile task and destination identities with ADMF before replay. Do not attach
old records to a reused XID or destination UUID. Preserve sequence values and
coordinate replay with new encoding to avoid sequence collisions after restart.
Define post-task X2 replay, administrative purge and destination-change behavior
as explicit options with tested defaults. Until replay is authorized, hold records
within the configured journal budget and expose that state.

Extend existing fail-closed X3 task/call finalization to the delivery queue using
generation-aware cancellation. Keep X2 replay decisions separate from X3 expiry.

### Accounting and shutdown

Record terminal outcomes once per destination copy, including PDU count, encoded
byte count, reason and first affected timestamp. Keep expiry, capacity rejection,
administrative purge, lifecycle suppression and uncertain writes distinguishable.
Retain aggregate counters after destination removal.

Extend status with effective limits, queued/in-flight bytes, expiry counters,
journal pressure, pending persistence and replay state. Use bounded aggregation
and rate-limited warnings for faults. Report observers must not block queue locks
or create a goroutine per discarded PDU. A durable external alarm outbox is a
separate feature.

Make `ShutdownTimeout` a real drain deadline. Drain eligible X3 before expiry,
checkpoint persistent X2, account remaining volatile drops and stop all workers.
Report retained-on-disk records separately from lost records and reconcile all
depth/byte gauges.

## Implementation phases

### 1. Configuration and policy contract

- [x] Finalize option names, units, defaults, limit precedence, memory budgeting,
      oversized-item handling and journal exhaustion behavior.
- [x] Specify post-task X2 replay and destination removal/replacement semantics,
      including bounded held records and explicit purge behavior.
- [x] Wire flags, YAML and environment settings through process/tap config with
      shared validation. Preserve non-LI stubs and existing precedence.
- [x] Correct queue-size help to say per destination and interface.

### 2. Queue ownership and independent delivery

- [x] Replace slice shifting and pointer-batch dispatch with owned deque entries,
      byte accounting and separate X2/X3 dispatchers/backoffs.
- [x] Audit interface connection acquisition and reconnection so destination-wide
      state cannot prevent an otherwise usable interface from progressing.
- [x] Keep transport operations and callbacks outside queue locks; bound workers,
      pending operations and cancellation waits.
- [x] Route synchronous APIs through the same owner with completion notification;
      prevent bypass of FIFO, expiry or journal policy.
- [x] Test overflow/removal during selection and writes, per-interface FIFO,
      destination/interface isolation and exactly-once terminal accounting.

### 3. X3 age and lifecycle limits

- [x] Extend delivery/reorder entries and all producer APIs with immutable timing
      and generation metadata, including normalized metadata producers.
- [x] Add expiry during idle outages and reconnect waits, pre-write revalidation
      and absolute deadlines checked after the transport write lock is acquired.
- [x] Wire task expiry/deactivation, reconciliation, call finalization and
      destination changes to generation-aware queue cancellation.
- [x] Test exact deadline boundaries, no new arrivals, reorder delay, wall-clock
      changes, control-frame lock contention, blocked writes and lifecycle races.

### 4. X2 persistence and replay

- [x] Implement bounded journal ingress, append/sync, checkpoint recovery,
      permissions/key handling and separate pending/persisted status.
- [x] Add identity reconciliation, ordered replay, sequence continuity and the
      selected task-end/destination-change policies.
- [x] Test crashes before/after sync, torn records, full disk, permission failures,
      duplicate replay, generation reuse and restart with pending IRI.
- [x] Verify X2 survives supported outages longer than the configured X3 lifetime,
      resource exhaustion is explicit, and X3 is never journaled.

### 5. Status, shutdown and documentation

- [x] Add reason-labelled byte/PDU accounting and bounded fault notifications;
      keep lifecycle suppression and uncertain transport outcomes separate.
- [x] Extend management protobuf fields, processor mapping and `lc show status`;
      test wire/JSON propagation and absent telemetry in non-LI builds.
- [x] Implement bounded shutdown drain/checkpoint, transport cancellation and
      worker joins. Verify gauges and retained-versus-dropped accounting.
- [x] Update LI documentation, command READMEs and manual with sizing examples,
      age semantics, persistence limitations, replay policies and migration.

### 6. Validation and completion

- [x] Extend mTLS MDF fixtures with short/long outages, slow readers, half-open
      connections, recovery under live traffic, variable PDU sizes and fan-out.
- [x] Run focused and package-level race tests with `all li` for LI, processor,
      process/tap commands and statusclient; verify `processor li`, `tap li` and
      non-LI `all` builds. Request escalation for socket tests when necessary.
- [x] Benchmark realistic outage-sized queues: RSS, allocations, disk throughput,
      capture latency and backlog drain rate must fit configured budgets.
- [x] Format changes, verify completed tasks, update this plan and commit the
      implementation with the checked-off plan.

The feature is complete when configured limits hold under concurrency and outages,
persistent X2 recovery follows the documented lifecycle policy, resource/loss
behavior is visible, and processor/tap remain equivalent.

## Finalized implementation contract

- Independent `x2-queue-size` / `x3-queue-size` values of zero inherit the existing
  per-destination/interface `queue-size` cap. Byte limits and X3 age remain disabled
  by default. An oversized entry is rejected before copying; volatile pressure can
  evict one unclaimed oldest entry only when that makes sufficient room. Claimed
  entries stay charged until their owner resolves them. Persistent X2 rejects new
  pressure instead of evicting journaled product.
- A configured memory budget reserves both interface payload budgets, conservative
  per-entry/worker overhead, a shared 16 MiB reorder budget, and bounded journal,
  replay, sequence-index and scratch storage. It is a managed-delivery reservation,
  not a process RSS ceiling. Startup rejects destinations whose reservations do
  not fit. Dynamic destination delivery activation is refused and logged when no
  reservation is available; ADMF registry acceptance remains a separate operation.
- X3 keeps its first local admission time through reorder, fan-out and retry.
  Capture timestamps are diagnostic. Deadline-heap expiry runs independently of
  blocked writes, and transport locking revalidates the absolute deadline. Task
  enforcement-definition changes, deactivation, call finalization and destination
  replacement revoke the appropriate queued generation. Uncertain transport writes
  remain distinguishable from known unsent drops; retry can duplicate product.
- X2 journal records are immutable, versioned, checksummed and AES-GCM encrypted.
  A private 32-byte key, private directory and exclusive process lock are required.
  Disk accounting rounds files to allocation units and reserves bookkeeping space;
  filesystem inode/directory overhead and an external durable alarm outbox are not
  included. Sequence checkpoints and the record-ID watermark survive product
  deletion, and are included in the bounded journal budget.
- Restarted X2 is held by default. Operators may explicitly purge held product or
  export and approve bounded identity manifests. Replay requires exact record
  identity, an unchanged persisted activation confirmed by startup ADMF sync, and
  the current destination generation. A single bounded feeder handles backlogs
  larger than the memory queue without blocking independent destinations. Previously
  authorized X2 may drain after task end; new replay authorization for ended tasks
  is denied. Destination replacement returns retained product to an unauthorized
  hold. Journal use through producer APIs requires lifecycle metadata.
- Asynchronous acceptance is not a durability acknowledgement. A crash before sync
  can lose pending ingress; faults after a product write are reported separately as
  uncertain persistence. Shutdown drains to its deadline, cancels transport work,
  checkpoints X2, joins workers and reconciles volatile versus retained product.
  Operating-system filesystem calls such as a stuck `fsync` cannot be interrupted
  safely in Go, so an unresponsive filesystem can exceed the shutdown deadline.

## Validation evidence

Focused race regressions cover claimed eviction/cancellation, concurrent removal,
logical and shared physical byte accounting, immutable reorder metadata and payload,
callback/timer joins, stale timer identities, exact expired deadlines, capture-clock
independence, blocked transport locks, mTLS outage fan-out under live arrivals,
replay authorization and FIFO beyond memory capacity, task-definition changes,
sequence wrap/continuity, subprocess crashes before and after durability boundaries,
injected ENOSPC, torn/corrupt records, permissions and exclusive journal ownership.

Measured on this workspace's `/tmp` filesystem and host:

| Measurement                       | Result                                           | Scope                                                  |
| --------------------------------- | ------------------------------------------------ | ------------------------------------------------------ |
| 100,000 variable-size queued PDUs | 144.7 MB RSS; 1,107 heap bytes/PDU               | Within configured 1 GiB memory reservation             |
| Local queue admission             | 1.226 microseconds/PDU                           | Encoded delivery admission, without transport          |
| Local owner drain                 | 4.67 million PDUs/second                         | Queue ownership operations, not MDF receipt            |
| Started owner with X3 age enabled | 1.334 / 1.211 microseconds at 10k / 100k entries | Confirms admission does not scan outage-sized queues   |
| Encrypted journal sync            | 58.43 MB/second; 24.8k PDUs/second               | 2,048 variable-size records; restart recovery verified |
| Journal admission latency         | p99 8.4 microseconds                             | Asynchronous admission, separate from durable sync     |

These measurements cover the delivery feature boundary. Complete capture-to-MDF
throughput and physical-drive performance remain deployment-specific; recovery
capacity must exceed ongoing encoded traffic. The filesystem benchmark is not a
promise about another storage device or MDF.

Final checks passed on 2026-09-08:

```text
go test -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -tags 'processor li' ./
go build -tags 'tap li' ./
go build -tags all ./
git diff --check
```

Socket-backed tests and builds requiring the Go module metadata cache ran with
sandbox escalation. Go sources were formatted with gofmt; changed Markdown was
formatted with Prettier before staging.

## Follow-up implementation audit (2026-09-08)

Three sub-agents reviewed queue ownership/transport, journal recovery, and
configuration/lifecycle integration. Independent review and cross-review found
and corrected the following gaps in the original completion:

- [x] Make journal admission nonblocking when a concurrent flush fills its bounded
      operation channel; roll back unpublished byte and entry reservations.
- [x] Keep claimed entries charged until their transport owner resolves them,
      preserving uncertain-write classification across retries and shutdown.
- [x] Retain pending X2 through destination removal until persistence completes,
      with exactly-once accounting and a stable removal reason.
- [x] Avoid reserving delivery queues for historical destinations during journal
      purge; aggregate purge accounting remains available.
- [x] Persist a destination delivery revision so endpoint A-to-B-to-A changes
      cannot restore an old replay identity. Unchanged restart identities and
      revision-zero legacy hashes remain stable.
- [x] Reserve capacity when replacing delivery destinations and allow previously
      capacity-refused destinations to activate after capacity becomes available.

New regressions cover blocked TLS writes during Stop/RemoveDestination, pending
journal writes during removal, purge reservations, endpoint reversion/restart,
and destination replacement after capacity refusal. The concurrent admission
regression reproduced the original deadlock using a Go source overlay and passed
500 race-enabled iterations with the fix.

Final verification passed:

```text
go test -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -tags 'processor li' -o /tmp/li-buffer-audit-processor-li .
go build -tags 'tap li' -o /tmp/li-buffer-audit-tap-li .
go build -tags all -o /tmp/li-buffer-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes required sandbox escalation. The
earlier performance measurements were not rerun as part of this correctness
audit. These checks establish the covered behavior; they do not establish the
absence of every possible defect or replace deployment-specific outage testing.

## Second implementation audit (2026-09-08)

Three sub-agents independently reviewed queue/transport ownership, journal replay,
and configuration/lifecycle integration. Parent review and cross-review confirmed
and corrected these additional concurrency gaps:

- [x] Disarm reorder timers when a sequence gap closes, so the next gap receives
      its own reorder window. Validate each timer invocation with an arm generation
      so an already-fired callback cannot flush or overwrite a newer timer on the
      same stream.
- [x] Transfer replayed X2 from held journal state into a delivery queue atomically
      with respect to journal hold operations. Concurrent destination removal can
      no longer strand durable product with neither a queue owner nor held status.
- [x] Serialize destination mutations and their delivery callbacks across X1 and
      ADMF reconciliation, preventing older callbacks from restoring stale
      endpoints after newer modifications or removal. Use canonical registry
      definitions for callbacks and retain unchanged destination queues.
- [x] Serialize state snapshots and writes so concurrent persistence calls cannot
      install an older lifecycle snapshot after a newer one.
- [x] Complete final race/build verification and format the audit record for the
      accompanying implementation commit.

New regressions cover resolved and stale same-stream reorder timers, replay
publication against journal holds, and overlapping destination modification,
reconciliation and removal. Review checked timer worker joins, journal/queue lock
ordering and destination callback reentrancy: callbacks may read state and update
callback registrations, but must not recursively mutate destinations.

Source overlays restoring the original timer behavior, replay publication order
and unserialized destination callbacks fail the corresponding new regressions.
After auditing the agent changes, the parent independently passed all new
regressions for 30 race-enabled iterations and the complete validation matrix:

```text
go test -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery ./internal/pkg/li -run 'TestReorderResolvedGapDisarmsDeadline|TestReorderRejectsPreviousTimerOnSameStream|TestJournalReplayPublicationSerializedWithHold|TestDestinationUpdatesSerializeDeliveryCallbacks' -count=30 -timeout 60s
go test -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -tags 'processor li' -o /tmp/li-review-processor-li .
go build -tags 'tap li' -o /tmp/li-review-tap-li .
go build -tags all -o /tmp/li-review-all .
git diff --check
```

Socket-backed tests and builds needing module-cache writes used sandbox escalation.
Changed Go sources were formatted with gofmt and the plan with Prettier.

Performance benchmarks were not rerun because this audit targets concurrency
correctness. These tests establish the covered behavior, not proof of the absence
of all defects.

## Third implementation audit (2026-09-08)

Three sub-agents reviewed queue/reorder ownership, journal recovery, and
configuration/lifecycle integration. Parent review and independent cross-review
confirmed and corrected four additional defects:

- [x] Preserve committed RTP callback order across concurrent arrivals, timer
      flushes, cleanup and shutdown. Reserve callback order under the reorder
      lock, then release producer admission before waiting outside that lock.
      Independent destination buffers remain independent, and pending callbacks
      retain their memory charges.
- [x] Repair sequence checkpoints and the record-ID watermark from recovered X2
      before replay or purge can remove the surviving product. A crash after
      product sync but before checkpoint sync can no longer cause sequence or ID
      reuse after purge and another restart. Recovery respects the journal budget
      and preserves product and releases its lock when repair cannot fit.
- [x] Serialize the startup destination bridge with destination mutations and
      delivery callbacks, preventing a concurrent removal from being undone by
      installation of a stale startup snapshot.
- [x] Return copied destination definitions from manager listings so callers
      cannot change endpoint fields outside lifecycle generation tracking.

New regressions fail with source overlays restoring the original behavior.
Agents cross-reviewed one another's changes, and the parent independently passed
all new regressions for 30 race-enabled iterations and the full validation matrix:

```text
go test -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery ./internal/pkg/li -run 'TestReorderCallbacksPreserveCommittedOrder|TestJournalRecoveryRepairsCheckpointsBeforePurge|TestDestinationStartupVisitSerializedWithRemoval|TestListDestinationsReturnsCopies' -count=30 -timeout 60s
go test -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -tags 'processor li' -o /tmp/li-third-audit-processor .
go build -tags 'tap li' -o /tmp/li-third-audit-tap .
go build -tags all -o /tmp/li-third-audit-all .
git diff --check
```

Socket-backed tests and builds needing module-cache writes used sandbox escalation.
Changed Go sources were formatted with gofmt and this plan with Prettier before
staging. Performance measurements were not rerun during this correctness audit.
No confirmed findings remain open; the checks cover the tested behavior and do
not establish the absence of every possible defect.

## Fourth implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport ownership, journal persistence/replay,
and configuration/lifecycle integration. The parent independently reviewed the
findings and regression tests; agents also cross-reviewed the transport changes.

- [x] Preserve queued X2/X3 when a destination update leaves its delivery identity
      unchanged, including repeated X1 requests and description-only edits.
- [x] Honor cancellation during TLS handshakes and stop background connection
      attempts during manager shutdown. Forced removal and shutdown close the
      underlying transport without waiting for TLS close notifications.
- [x] Serialize background connection publication with destination replacement
      and removal, rejecting superseded transports and stale failed-dial state
      updates.
- [x] Keep delivery destination definitions private so external mutations cannot
      bypass lifecycle generation tracking.
- [x] Complete independent regression, race-suite and build verification, format
      changes and commit the fixes with this audit record.

The parent independently passed the new transport and queue-retention regressions
for 30 race-enabled iterations. Source overlays restoring the original code fail
the queue-retention, handshake-cancellation, interface-reconnect and blocked
close-notification regressions. Atomic initial-dial publication was also verified
by lock-order review; its existing handshake-time generation check already passes
the new replacement test, so that test alone does not establish coverage of the
later check-to-publication window.

Final verification passed:

```text
go test -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery -run 'TestDialCancellationInterruptsTLSHandshake|TestBackgroundDialRejectsReplacedDestination|TestManagerStopCancelsBackgroundTLSHandshake|TestDeliveryDestinationDefinitionsAreCopies|TestManagerStopDoesNotWaitForTLSCloseNotify' -count=30 -timeout 90s
go test -race -tags 'all li' ./internal/pkg/processor -run 'TestLIDelivery(UnchangedDestinationPreservesQueuedProduct|ReplacementReservesCapacityAndRecoversRefusedDestination)' -count=30 -timeout 60s
go test -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -tags 'processor li' -o /tmp/li-fourth-audit-processor .
go build -tags 'tap li' -o /tmp/li-fourth-audit-tap .
go build -tags all -o /tmp/li-fourth-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes required sandbox escalation. Changed
Go sources were formatted with gofmt and this plan with Prettier before staging.
Journal review found no additional confirmed defects; its focused persistence and
replay race tests passed. Performance benchmarks were not rerun during this
correctness audit. No confirmed findings remain open; these checks establish the
covered behavior, not proof that every possible defect is absent.

## Fifth implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport ownership, journal persistence/replay,
and configuration/lifecycle integration. Parent review and independent agent
cross-review verified the existing uncommitted fixes and corrected further gaps.

- [x] Classify completed local writes correctly when lifecycle cancellation races
      completion; retain uncertain-write classification if deadline cleanup fails
      after the transport accepted the frame.
- [x] Bound journal recovery directory enumeration and reject records that exceed
      remaining capacity before reading or decrypting their payloads. Preserve FIFO
      replay across directory batches and release ownership after failed recovery.
- [x] Close discarded underlying transports during connection release without
      waiting for TLS close notifications, covering removed destinations, shutdown,
      invalid connections and full pools.
- [x] Reject purges from closed journal owners and retain exclusive spool ownership
      until an ongoing purge finishes. Keep purge lifetime locking independent of
      worker admission and callback locks.
- [x] Resolve directory aliases before exporting replay manifests, preventing
      exports from overwriting spool records, checkpoints or the encryption key.
- [x] Complete final race/build verification, format the audit record and commit
      the verified changes with this plan.

The parent independently passed all seven audit regressions for 30 race-enabled
iterations. Agent source overlays restoring the original write accounting, purge
and manifest behavior fail the corresponding regressions; the connection-release
test also failed all four cleanup branches before its fix. Cross-review checked
purge/close lock ordering and valid outside-spool manifest exports. Configuration,
processor/tap parity and lifecycle integration had no additional confirmed findings.

An initial full race suite passed, but a subsequent final run exhausted temporary
disk space during linking. After the user authorized cache cleanup, final
verification resumed with package parallelism limited to two. Performance benchmarks
were not rerun during this correctness audit.

Final verification passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -p 2 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-final-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-final-audit-tap .
go build -p 2 -tags all -o /tmp/li-final-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. Go sources
were formatted with gofmt and this plan with Prettier before staging. No confirmed
findings remain open; the checks establish the covered behavior, not proof of the
absence of every possible defect.

## Sixth implementation audit (2026-09-08)

Three sub-agents reviewed queue/reorder ownership, journal persistence/replay,
and configuration/lifecycle integration. Parent review and agent cross-review
identified additional gaps beyond the passing baseline race suite.

- [x] Establish missing or future admission timestamps at reorder ingress, so
      buffered delay counts against X3 age. Carry the reorder entry's authoritative
      call generation into delivery cancellation metadata.
- [x] Revoke replay approval for the entire held destination backlog during
      removal/replacement, including destinations without a delivery queue.
      Serialize revocation with authorization and replay publication.
- [x] Reserve one incoming payload up to the larger interface byte limit in the
      global memory budget, covering admission while existing queues remain
      charged. Check reservation arithmetic for overflow.
- [x] Preserve task generation watermarks independently of retained task
      definitions, including expired legacy state, purged tombstones and startup
      candidates not confirmed by ADMF. Preserve unchanged confirmed activations
      while rejecting generation exhaustion and reuse.
- [x] Checkpoint task generations before enabling their enforcement. Failed
      state-file writes roll back provisional activation/modification instead of
      allowing journal product to use an identity that restart could reuse.
- [x] Checkpoint destination identity changes before notifying delivery owners;
      roll back failed persistence without publishing an unrecorded revision.
- [x] Independently verify all regressions, complete the race/build matrix,
      format the changes and commit the fixes with this audit record.

The parent independently reviewed every implementation and regression, and passed
the new regressions for 30 race-enabled iterations. Agents cross-reviewed the
changes and used source overlays to demonstrate failures in the original code.
Coverage includes missing/future reorder admission, conflicting call metadata,
held backlog beyond queue capacity and without a queue, exact memory reservation
boundaries, expired/purged/unconfirmed task state, unchanged restart identities,
generation exhaustion, and failed task/destination state-file writes before
enforcement or delivery publication.

Explicit memory budgets may now need an additional allowance equal to the larger
interface byte limit. Per-XID generation watermarks remain in the LI state file
after task cleanup; retain this state together with the journal. These policies
are documented in the operator guide. Performance benchmarks were not rerun in
this correctness audit.

Final verification passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery -run 'TestReorderEstablishesAdmissionBeforeBufferedDelay|TestReorderCallIdentityReachesDeliveryCancellation|TestJournalDestinationRemovalRevokes|TestMemoryBudgetReservesAdmissionAlongsideFullQueues' -count=30 -timeout 60s
go test -race -tags li ./internal/pkg/li -run 'TestDestinationPersistencePrecedesDeliveryPublication|TestPersistedGeneration|TestPersistedActiveGeneration|TestTaskGeneration' -count=30 -timeout 60s
go test -p 2 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-final-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-final-audit-tap .
go build -p 2 -tags all -o /tmp/li-final-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. One matrix
run compiled an intermediate regression test that compared serialized timestamps
including monotonic state; the corrected timestamp-value assertion passed repeated
regressions and the final full matrix. Go sources were formatted with gofmt and
changed Markdown with Prettier before staging. No confirmed findings remain open;
these checks establish the covered behavior, not proof that all defects are absent.

## Seventh implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport/reorder ownership, journal recovery and
replay, and configuration/lifecycle integration. The parent independently reviewed
the fixes and regressions; agents also cross-reviewed both changes.

- [x] Copy every admitted reorder payload before releasing producer ownership,
      including initial, consecutive and late entries. These callbacks may wait
      behind earlier callbacks after admission is released. Keep the copy within
      the existing packet memory reservation.
- [x] Restore retained deactivated, failed and pending task identities when their
      destinations were subsequently removed, without blocking startup or enabling
      enforcement. Revalidate destinations before pending filter installation;
      missing destinations fail the task while preserving its generation.
- [x] Complete final race/build verification, format changes and commit this audit
      record with the fixes.

The parent reproduced both defects using original-code source overlays and passed
reorder and lifecycle regressions for 30 race-enabled iterations. A separate
agent overlay confirmed that restoring only the old pending-promotion code arms
a pending task whose destination was removed. Coverage verifies payload ownership
at the admission-release boundary, preserved lifecycle identities after restart,
denied replay, and disarmed pending tasks on both original and restarted owners.
Journal regressions passed 30 race-enabled iterations with no additional findings.

Final validation passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery -run 'TestReorder' -count=30 -timeout 90s
go test -race -tags li ./internal/pkg/li -run 'TestPersistenceRestoresTasksAfterDestinationRemoval|TestPersistedGeneration|TestTaskGeneration|TestPending' -count=30 -timeout 90s
go test -p 2 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-seventh-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-seventh-audit-tap .
go build -p 2 -tags all -o /tmp/li-seventh-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. Performance
benchmarks were not rerun; immediate reorder delivery now copies payload bytes,
covered by its existing memory reservation. These checks establish the covered
behavior, not proof that every possible defect is absent.

## Eighth implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport/reorder ownership, journal persistence
and replay, and configuration/lifecycle integration. Parent review and independent
cross-review confirmed and corrected two additional persistence defects.

- [x] Preserve unconfirmed activation definitions across interrupted startup
      checkpoints and provisional activation rollback. Keep candidates disarmed,
      require the unchanged generation watermark, and retire them after successful
      activation or a complete startup ADMF snapshot confirming their absence.
      Deactivation and tombstone purge cannot resurrect old replay identities.
- [x] Require an open state-directory handle before replacing a lifecycle
      checkpoint, and propagate directory open, sync and close failures. A
      write/search-only directory can no longer silently skip directory sync and
      enable enforcement without a confirmed durable generation checkpoint.
- [x] Independently review fixes and regressions, repeat new tests with the race
      detector, run the complete race/build matrix and format the audit changes.

Cross-review caught and corrected candidate retirement during provisional
snapshot writes before final validation. Regressions cover repeated interrupted
startups, unchanged ADMF confirmation, authoritative absence, deactivation/purge,
checkpoint and activation-commit rollback, and directory permission failures.
The parent independently restored the original persistence source through a Go
source overlay and reproduced both defects: replay generation advanced from 7
to 8, and the directory failure incorrectly allowed task activation with a filter.
All new regressions passed 30 race-enabled iterations against the fixed code.
Queue/reorder tests passed 10 race-enabled iterations and journal tests passed 30,
with no additional confirmed findings.

Final validation passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li -run 'TestPersistedReplayCandidate|TestPersistenceRequiresDirectorySyncBeforeActivation' -count=30 -timeout 60s
go test -p 2 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-eighth-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-eighth-audit-tap .
go build -p 2 -tags all -o /tmp/li-eighth-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. Go sources
were formatted with gofmt and this plan with Prettier before staging. Performance
benchmarks were not rerun during this correctness audit. No confirmed findings
remain open; these checks establish covered behavior, not proof that every
possible defect is absent.

## Ninth implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport/reorder ownership, journal persistence
and replay, and lifecycle integration. Parent review and independent agent
cross-review confirmed and corrected three additional defects.

- [x] Serialize fault finalization with task admissions before cancelling the
      delivery generation. An admitted producer can no longer enqueue X3 after
      the fault cancellation sweep.
- [x] Recheck shutdown during foreground destination lookup and transport
      publication, preventing a caller from installing a new connection after
      the manager has completed shutdown.
- [x] Preserve a healthy interface transport across competing foreground and
      background dials. Serialize publication, reject redundant background
      associations even while the active connection is checked out, and reuse
      a background winner before sending on a newly dialed foreground stream.
      This prevents FIFO overtaking across healthy TCP streams and protects
      return capacity in a one-connection pool.
- [x] Independently review the fixes and regressions, repeat race tests, complete
      the race/build matrix, and format the implementation and audit record.

The parent reproduced the original fault-finalization and pool-publication
failures using source overlays. An initial full suite also reproduced the
foreground shutdown regression against the original transport code. A later
full run exposed the FIFO defect in the unchanged mTLS outage/fan-out test;
that failure was investigated and fixed before final verification. Deterministic
regressions cover pool capacities one and two, idle and checked-out associations,
and a foreground TLS handshake that loses publication to a background dial.

The parent independently passed the new shutdown/lifecycle regressions for 30
race-enabled iterations, then the final FIFO regressions and unchanged mTLS
outage test for 30 iterations. Agents cross-reviewed both locking changes and
independently repeated the relevant regressions. Journal tests passed 30
race-enabled iterations with no additional confirmed findings.

Final validation passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery ./internal/pkg/li -run 'TestForegroundConnectionCannotPublishAfterManagerStop|TestTaskAdmissionSerializesFaultCancellation' -count=30 -timeout 60s
go test -race -tags li ./internal/pkg/li/delivery -run 'TestBackgroundConnectionPreservesActiveFIFOTransport|TestForegroundDialReusesConcurrentBackgroundConnection|TestAuditMutualTLSOutageFanoutDrainsUnderLiveTraffic' -count=30 -timeout 90s
go test -p 2 -count=1 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-ninth-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-ninth-audit-tap .
go build -p 2 -tags all -o /tmp/li-ninth-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. Go sources
were formatted with gofmt and this plan with Prettier before staging. Performance
benchmarks were not rerun during this correctness audit. No confirmed findings
remain open; these checks establish covered behavior, not proof that every
possible defect is absent.

## Tenth implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport/reorder ownership, journal persistence
and replay, and lifecycle integration. The parent independently reviewed processor
configuration and status integration, reproduced both confirmed defects against
the original source, and verified the fixes. Both other agents cross-reviewed the
transport changes.

- [x] Preserve healthy destination connection state when a competing background
      TLS handshake fails. Count the failed attempt without overwriting current
      connection errors or starting an obsolete reconnect loop.
- [x] Serialize transport invalidation's membership and connection-state update
      with connection publication, destination removal and shutdown. Closing an
      old transport can no longer mark its healthy replacement disconnected;
      transport cleanup remains outside manager and state locks.
- [x] Complete final race/build verification, format the changes and commit the
      fixes with this audit record.

The parent independently ran both deterministic regressions against the original
transport source using a Go source overlay; both failed on the stale disconnected
state. Both passed 30 race-enabled iterations against the fixes, independently
repeated by the implementing agent and a reviewing agent. Queue/reorder and
journal regressions passed 10 race-enabled iterations; lifecycle/persistence
regressions passed 30. These reviews found no other confirmed defects.

Final validation passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li/delivery -run 'TestFailedBackgroundDialPreservesPublishedConnectionState|TestInvalidationPreservesConnectionPublishedDuringClose' -count=30 -timeout 30s
go test -p 2 -count=1 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-tenth-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-tenth-audit-tap .
go build -p 2 -tags all -o /tmp/li-tenth-audit-all .
git diff --check
```

Socket-backed tests and module-cache writes used sandbox escalation. Go sources
were formatted with gofmt and this plan with Prettier before staging. Performance
benchmarks were not rerun during this correctness audit. No confirmed findings
remain open; these checks establish covered behavior, not proof that every
possible defect is absent.

## Eleventh implementation audit (2026-09-08)

Three sub-agents reviewed queue/transport/reorder ownership, journal persistence
and replay, and lifecycle integration. The parent reviewed processor integration,
independently reproduced the findings, and verified the fixes. Agents also
cross-reviewed lifecycle, transport and processor cleanup changes.

- [x] Cancel expired delivery generations even when filter withdrawal or lifecycle
      checkpointing fails. Keep the lifecycle barrier through processor cleanup.
- [x] Reject stale expiration snapshots before cleanup, and guard registry fallback
      finalization by activation generation. Expiry cannot remove a reactivated
      task's filters or deactivate its newer suspended generation.
- [x] Wake retired transport keepalive workers after invalidation, removal and
      replacement; disabled keepalive workers exit immediately. Reconnect churn
      no longer retains old workers until their P1/P2 timers expire.
- [x] Delete idle reorder buffers only when the map still contains the observed
      owner. Cleanup callbacks cannot remove a newer activation's replacement.
- [x] Complete the final race/build matrix and format the audit changes.

The parent reproduced all four lifecycle regression failures using original
manager/registry sources with only the regression's helper-call signature adapted.
Original transport source failed all four keepalive retirement cases. Restoring
unconditional reorder deletion also failed its replacement-owner regression.
All fixed regressions passed 30 race-enabled iterations, independently repeated
by reviewing agents. Journal tests passed 10 race-enabled iterations with no
additional confirmed findings. Performance benchmarks were not rerun during this
correctness audit.

Final validation passed:

```text
go test -p 2 -count=1 -race -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 180s
go test -race -tags li ./internal/pkg/li -run 'TestExpiry|TestStaleExpiry|TestPhase7Expiry|TestTaskAdmission' -count=30 -timeout 60s
go test -race -tags li ./internal/pkg/li/delivery -run TestKeepaliveWorkerExitsWhenDisabledOrRetired -count=30 -timeout 60s
go test -race -tags 'all li' ./internal/pkg/processor -run TestLIIdleReorderCleanupPreservesReplacement -count=30 -timeout 60s
go test -p 2 -count=1 -tags all ./cmd/process ./cmd/tap ./internal/pkg/statusclient -timeout 60s
go build -p 2 -tags 'processor li' -o /tmp/li-eleventh-audit-processor .
go build -p 2 -tags 'tap li' -o /tmp/li-eleventh-audit-tap .
go build -p 2 -tags all -o /tmp/li-eleventh-audit-all .
git diff --check
```

Socket-backed tests and Go module metadata cache writes used sandbox escalation.
Go sources were formatted with gofmt and this plan with Prettier before staging.
No confirmed findings remain open; these checks establish covered behavior, not
proof that every possible defect is absent.
