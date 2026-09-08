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
