# LI Delivery Reconnect Buffering Implementation Plan

**Date:** 2026-06-18
**Issue:** LI packets are dropped while an MDF destination reconnects
**Priority:** P0 (compliance and evidence loss)
**Effort:** Medium-high (delivery client and connection lifecycle refactor)
**Risk:** High (ordering, shutdown, retry, and duplicate-delivery semantics)

---

## Executive Summary

The LI delivery client currently has a bounded global ingress queue, but workers
remove items from that queue before acquiring a destination connection. If
`Manager.GetConnection()` returns `ErrNotConnected`, the batch is counted as
failed and discarded. A stale pooled socket can remain in `CLOSE-WAIT` until a
write discovers the disconnect, which widens the loss window.

The fix will:

1. Fan out each PDU into a bounded queue owned by its destination.
2. Keep the head item queued until it is written successfully.
3. Use one active dispatcher per destination to preserve enqueue order.
4. Reconnect in the background with capped exponential backoff.
5. Detect peer closure proactively through a connection read watcher and
   explicit TCP keepalive settings.
6. Drop the oldest queued item on sustained-overflow, with per-destination,
   per-PDU-type, and per-reason counters and rate-limited warning logs.

This provides bounded, ordered, at-least-once delivery across transient
disconnects. Exactly-once delivery is not possible without an MDF
application-level acknowledgement: a connection failure after a partial or
kernel-buffered write is ambiguous and may cause a replayed PDU to be received
twice.

---

## Current Failure Path

```text
SendX2/SendX3
    |
    v
global queue
    |
    v
deliveryWorker removes item
    |
    v
GetConnection(did) -> ErrNotConnected
    |
    v
recordFailure(item) and return          <-- item is permanently lost
```

Relevant implementation:

- `internal/pkg/li/delivery/client.go`
  - `deliveryWorker()`
  - `deliverBatch()`
  - `deliverToDestination()`
- `internal/pkg/li/delivery/destination.go`
  - `GetConnection()`
  - `InvalidateConnection()`
  - `connectDestination()`
  - `scheduleReconnect()`

Additional weaknesses to address:

- `ClientConfig.QueueSize` is documented as per-destination but currently
  creates one global queue.
- Multiple global workers can deliver batches for the same destination
  concurrently, so strict per-destination order is not guaranteed.
- `net.Dialer.KeepAlive` enables keepalive but does not set a complete,
  testable idle/interval/probe policy.
- Pooled connections do not have a reader that notices peer EOF while idle.
- The default reconnect cap is five minutes, which is too long for active LI
  delivery.
- Existing failure counters do not distinguish retrying, permanent failure,
  queue overflow, or shutdown loss.

---

## Target Architecture

```text
                         +-------------------------------+
SendX2/SendX3 ---------->| fan out one item per DID      |
                         +---------------+---------------+
                                         |
                     +-------------------+-------------------+
                     |                                       |
                     v                                       v
          destination A queue                     destination B queue
          bounded, drop-oldest                    bounded, drop-oldest
                     |                                       |
                     v                                       v
          one ordered dispatcher                 one ordered dispatcher
                     |                                       |
                     v                                       v
          wait for healthy connection             healthy connection
                     |                                       |
                     +------------> MDF <--------------------+
```

Each destination dispatcher owns delivery ordering and retries. A disconnected
destination therefore cannot block or consume capacity belonging to another
destination.

---

## Architectural Decisions

### Delivery guarantee

- Use **at-least-once** delivery for transient connection and write errors.
- Remove an item from the destination queue only after the entire PDU write
  succeeds.
- On any write error, invalidate the connection and retry the whole PDU after
  reconnect.
- Document that an ambiguous write may produce a duplicate at MDF. Preserve
  the existing XID, correlation ID, and sequence metadata so MDF can identify
  duplicates.
- Do not increment `X2Failed`/`X3Failed` for a transient attempt that remains
  queued. Increment terminal failure/drop counters only when an item is
  permanently discarded.

### Ordering and concurrency

- Preserve FIFO order independently for each destination.
- Run exactly one active send loop per destination.
- Batch only consecutive items from the same destination queue.
- Do not allow `Workers > 1` to create concurrent writers for one destination.
  Deprecate/remove the global worker meaning of this setting or redefine it as
  a limit on concurrently active destination dispatchers.
- A destination outage must not block healthy destinations.

### Queue policy

- `QueueSize` becomes the actual capacity **per destination**.
- On overflow, atomically evict the oldest item and enqueue the newest item.
- Record the evicted item's PDU type and reason `queue_overflow`.
- Emit a rate-limited warning containing DID, queue capacity, queue depth, PDU
  type, XID, and cumulative drops.
- Queue capacity remains bounded in memory; no disk persistence is included in
  this fix.

### Connection health

- Configure `net.Dialer.KeepAliveConfig` with explicit idle, interval, and probe
  count values. Proposed defaults:
  - idle: 15 seconds
  - interval: 5 seconds
  - probes: 3
- Start one read watcher for every established TLS connection. For this
  unidirectional X2/X3 stream, EOF or a non-timeout read error invalidates the
  connection immediately and schedules reconnect.
- Confirm that the MDF protocol sends no application data before discarding
  bytes in the watcher. If inbound control frames are valid, parse them instead
  of using a blind EOF watcher.
- Make invalidation idempotent so a read watcher and writer can report the same
  failure without double-counting or scheduling duplicate reconnects.
- Change the reconnect cap from five minutes to five seconds for LI delivery,
  while retaining exponential backoff and shutdown cancellation.

---

## Implementation Phases

### Phase 1: Add Regression Tests for the Existing Loss

#### Step 1.1: Build a controllable TLS MDF test server

In `internal/pkg/li/delivery/client_test.go` or a focused integration test file:

- Accept mTLS connections using the existing LI test certificates.
- Record complete framed PDUs in receive order.
- Support:
  - graceful peer close;
  - abrupt close/reset;
  - listener shutdown and restart on the same address;
  - delayed accept/read;
  - forced close after N received bytes or PDUs.
- Replace fixed sleeps with bounded polling/event channels where practical.

#### Step 1.2: Reproduce the reconnect-window loss

- Connect the destination and verify the initial connection is healthy.
- Stop/restart the MDF while leaving lippycat running.
- Enqueue an INVITE-like X2 item followed by additional X2 items during the
  reconnect window.
- Assert that the current behavior loses items; convert the test to require all
  items after Phase 2.

#### Step 1.3: Capture ordering and isolation requirements

- Assert FIFO delivery for a single destination with multiple configured
  workers.
- Assert that an offline destination does not delay delivery to a healthy
  destination.
- Assert fan-out sends one independent copy to each destination.

### Phase 2: Replace the Global Send Path with Per-Destination Queues

#### Step 2.1: Introduce destination-specific queue state

Refactor `internal/pkg/li/delivery/client.go` around a structure similar to:

```go
type destinationQueue struct {
    did      uuid.UUID
    items    deque[*destinationItem]
    notify   chan struct{}
    stop     chan struct{}
    done     chan struct{}
    mu       sync.Mutex
}

type destinationItem struct {
    pduType PDUType
    xid     uuid.UUID
    data    []byte
}
```

- Store queues in `Client.destinationQueues`, guarded by a mutex.
- Fan out multi-destination sends at enqueue time.
- Copy the destination ID slice at the public API boundary.
- Define ownership of `data`: either copy it on enqueue or document and test
  that callers must not mutate it. Prefer copying once per original PDU and
  sharing immutable bytes across destination items.
- Lazily create a queue/dispatcher on first enqueue, or explicitly create and
  remove it with destination lifecycle callbacks.

Use a mutex-protected ring/deque rather than a plain buffered channel because
drop-oldest must be atomic and race-free.

#### Step 2.2: Implement ordered dispatch

- Peek at the queue head without removing it.
- Wait for `Manager.GetConnection()` to return a healthy connection.
- Treat `ErrNotConnected`, connection timeout, EOF, reset, broken pipe, and
  temporary dial errors as retryable.
- Keep the head item in place while disconnected.
- Write one or a bounded batch in FIFO order.
- Pop and record success only after each full write succeeds.
- On a write error:
  - leave the failed item at the head;
  - invalidate the connection;
  - stop the current batch;
  - wait for the reconnect signal/backoff before retrying.
- Treat `ErrDestinationNotFound` as terminal: remove queued items for that DID
  and count them with reason `destination_removed`.

#### Step 2.3: Define enqueue and overflow API behavior

- Keep `SendX2`/`SendX3` non-blocking.
- A drop-oldest overflow still accepts the new item, so do not return
  `ErrQueueFull` as if the new item was rejected.
- Record overflow through stats and a rate-limited WARN.
- Retain `ErrQueueFull` only if another mode still rejects the newest item;
  otherwise deprecate it and update tests/documentation.
- If fan-out partly fails because a destination was concurrently removed,
  return a structured aggregate error while preserving successful enqueues.

#### Step 2.4: Handle destination lifecycle

- Add destination-created, destination-modified, and destination-removed
  callbacks between `internal/pkg/li/manager.go` and
  `internal/pkg/processor/processor_li.go`.
- On modify, reconnect when address/port/TLS-relevant settings change without
  discarding queued PDUs.
- On remove:
  - stop the dispatcher;
  - close its connections;
  - count and log queued terminal drops;
  - remove queue state to avoid goroutine and memory leaks.
- Ensure ADMF startup sync creates delivery destinations before matched traffic
  is processed.

### Phase 3: Make Connection Failure Detection Eager and Race-Safe

#### Step 3.1: Replace raw connection handoff with a managed lease

Refactor the pool API so callers do not lose connection identity:

```go
type ConnectionLease struct {
    conn  *tls.Conn
    entry *pooledConn
}
```

- `GetConnection()` returns a lease.
- `ReleaseConnection()` and `InvalidateConnection()` accept the lease.
- Track an atomic invalid/closed flag on `pooledConn`.
- Prevent a read watcher from invalidating a new connection generation or
  returning a dead connection to the pool.
- Make pool accounting (`inUse`) correct when a connection is closed instead
  of returned.

#### Step 3.2: Add proactive peer-close monitoring

- Start the watcher after a successful TLS handshake.
- Read until EOF/error or manager shutdown.
- On peer close:
  - atomically invalidate the connection;
  - remove it from availability;
  - transition the destination to disconnected when no healthy connections
    remain;
  - schedule one reconnect attempt;
  - wake the destination dispatcher.
- Stop the watcher when the connection is intentionally closed or destination
  is removed.
- Log state transitions once, not once per waiting item.

#### Step 3.3: Configure TCP keepalive explicitly

Extend `DestinationConfig` with:

- `KeepAliveIdle`
- `KeepAliveInterval`
- `KeepAliveCount`

Set these through `net.Dialer.KeepAliveConfig`. Keep zero-value normalization in
`DefaultConfig()` and unit-test the defaults. Avoid Linux-only socket calls
unless Go's portable configuration cannot provide the required behavior.

#### Step 3.4: Tighten reconnect scheduling

- Default to 500 ms initial backoff and 5 seconds maximum.
- Keep exponential growth and reset after successful connection.
- Ensure only one timer/connect attempt exists per destination.
- Add jitter if tests show synchronized reconnect storms are plausible.
- Add a connection-state notification channel so dispatchers wake immediately
  after reconnect instead of polling.

### Phase 4: Observability and Configuration

#### Step 4.1: Expand delivery statistics

Add per-destination statistics for:

- queue depth and capacity;
- X2/X3 queued;
- X2/X3 sent;
- retry attempts;
- reconnects;
- oldest-item drops;
- terminal drops;
- current connection state;
- oldest queued item age;
- last successful delivery time;
- last delivery error.

Use reason values with a controlled vocabulary:

- `queue_overflow`
- `destination_removed`
- `shutdown_timeout`
- `non_retryable_error`

Expose an aggregate equivalent of:

```text
lippycat_li_delivery_dropped_total{
  destination="<did>",
  pdu_type="x2|x3",
  reason="<reason>"
}
```

The repository currently has no Prometheus exporter. Implement the labelled
counter in the delivery stats model first and expose it through the existing
status/diagnostic surface. Adding a Prometheus HTTP endpoint is a separate
cross-cutting feature unless one is introduced before this work lands.

#### Step 4.2: Add operator configuration

Add LI build-tagged processor/tap flags and Viper bindings:

- `--li-delivery-queue-size` (per destination, default 10,000)
- `--li-delivery-send-timeout` (default 5s)
- `--li-delivery-reconnect-initial-backoff` (default 500ms)
- `--li-delivery-reconnect-max-backoff` (default 5s)
- `--li-delivery-keepalive-idle` (default 15s)
- `--li-delivery-keepalive-interval` (default 5s)
- `--li-delivery-keepalive-count` (default 3)
- `--li-delivery-shutdown-timeout` (default 10s)

Thread values through:

- `cmd/process/flags_li.go`
- `cmd/tap/flags_li.go`
- non-LI flag stubs/config types
- `internal/pkg/processor.Config`
- `internal/pkg/processor/processor_li.go`
- `delivery.ClientConfig`
- `delivery.DestinationConfig`

Validate positive capacities/durations and enforce initial backoff less than or
equal to maximum backoff.

#### Step 4.3: Correct logs

- Change processor messages such as `"X2 IRI delivered"` to `"X2 IRI queued"`
  because enqueue is not delivery confirmation.
- Log successful sends at debug level and reconnect state transitions at info
  or warn level.
- Rate-limit repeated outage/overflow warnings per destination.
- Include DID, XID, PDU type, queue depth, oldest age, retry count, and error
  where relevant.

### Phase 5: Shutdown Semantics and Documentation

#### Step 5.1: Implement bounded graceful shutdown

- Stop accepting new items.
- Allow destination dispatchers to flush until all queues are empty or the
  configured shutdown timeout expires.
- On timeout, count remaining items with reason `shutdown_timeout` and log the
  exact per-destination loss.
- Cancel reconnect timers, read watchers, and dispatcher goroutines.
- Close the destination manager only after client dispatchers stop using
  connections.
- Make `Start()` and `Stop()` idempotent or explicitly reject repeated calls.

#### Step 5.2: Update documentation

Update:

- `internal/pkg/li/AGENTS.md`
- `internal/pkg/li/CLAUDE.md`
- `docs/LI_INTEGRATION.md`
- `docs/manual/src/part5-advanced/lawful-interception.md`
- `docs/manual/src/appendices/command-reference.md`

Document:

- per-destination queue behavior;
- drop-oldest overflow policy;
- retry and ordering guarantees;
- at-least-once/possible-duplicate semantics;
- memory sizing (`destinations × queue size × average PDU size`);
- keepalive and reconnect tuning;
- monitoring and incident-response guidance.

---

## Test Matrix

### Unit tests

- Queue preserves FIFO order.
- Queue overflow evicts exactly the oldest item.
- Overflow counters identify DID, PDU type, and reason.
- One offline destination cannot consume another destination's queue.
- Multi-destination fan-out creates independent delivery state.
- Transient `ErrNotConnected` does not increment terminal failure/drop counts.
- Destination removal drains state and terminates its dispatcher.
- `Stop()` reports queued loss after timeout.
- Keepalive and backoff defaults/validation are correct.
- Connection invalidation is idempotent under simultaneous reader/writer
  errors.
- Pool accounting remains correct after invalidation.

### Integration tests

- MDF graceful restart: every PDU queued during the gap arrives after reconnect
  and in order.
- MDF abrupt reset: failed head PDU is replayed after reconnect.
- Idle peer close: read watcher marks disconnected before the next producer
  send.
- Listener unavailable for multiple backoff cycles: queue remains bounded and
  flushes after recovery.
- Sustained outage beyond capacity: oldest items are dropped, newest survive,
  and counters match exact losses.
- Two destinations, one unavailable: healthy destination continues without
  delay.
- X2 INVITE plus subsequent SIP messages: INVITE is retained and delivered
  first after reconnect.
- X3 reorder output remains ordered before entering the destination queue.
- Race test concurrent enqueue, reconnect, modify/remove destination, and
  shutdown.

### Verification commands

```bash
go test -race -tags li ./internal/pkg/li/delivery/...
go test -race -tags li ./internal/pkg/li/...
go test -race -tags li ./internal/pkg/processor/...
make build-li
make tap-li
make verify-no-li
```

Run a manual reproduction matching the issue:

1. Start `lc tap voip` with an active LI task and MDF destination.
2. Restart MDF and confirm lippycat detects peer closure.
3. Place a monitored SIP call during reconnect.
4. Verify all SIP PDUs, including INVITE, arrive in capture order.
5. Confirm queue/reconnect counters and logs show buffering with zero drops.
6. Repeat with a queue deliberately too small and verify exact drop-oldest
   accounting.

---

## Files Expected to Change

| File | Planned change |
|------|----------------|
| `internal/pkg/li/delivery/client.go` | Per-destination queues, ordered dispatch, retry, overflow accounting, graceful shutdown |
| `internal/pkg/li/delivery/client_test.go` | Queue, retry, ordering, overflow, isolation, and shutdown tests |
| `internal/pkg/li/delivery/destination.go` | Managed leases, read watcher, explicit keepalive, reconnect notifications/backoff |
| `internal/pkg/li/delivery/destination_test.go` | EOF detection, reconnect, pool race, and keepalive tests |
| `internal/pkg/li/manager.go` | Destination update/remove lifecycle callbacks |
| `internal/pkg/li/manager_test.go` | Callback lifecycle tests |
| `internal/pkg/processor/processor.go` | Delivery resilience configuration fields |
| `internal/pkg/processor/processor_li.go` | Wire configuration/stats and correct queued-vs-delivered logs |
| `cmd/process/flags_li.go` | Processor LI delivery resilience flags |
| `cmd/process/flags_li_stub.go` | Matching non-LI stubs/config shape |
| `cmd/tap/flags_li.go` | Tap LI delivery resilience flags |
| `cmd/tap/flags_li_stub.go` | Matching non-LI stubs/config shape |
| LI documentation files | Guarantees, tuning, monitoring, and command reference |

Exact stub filenames should be confirmed during implementation because command
packages may use shared LI config types rather than duplicated declarations.

---

## Acceptance Criteria

- No queued PDU is discarded solely because a destination is reconnecting.
- The seven-SIP-packet reproduction delivers all seven packets after a short
  MDF restart, with INVITE first.
- Delivery order is FIFO per destination.
- An unavailable destination does not block healthy destinations.
- Queues are bounded per destination and overflow drops the oldest item.
- Every terminal drop is visible through a reason-labelled counter and a
  rate-limited structured warning.
- Idle peer close is detected before or independently of the next producer
  send.
- Reconnect backoff is exponential and capped at five seconds by default.
- Concurrent disconnect/write/remove/shutdown paths pass `go test -race`.
- LI and non-LI builds continue to compile.

---

## Explicit Non-Goals

- Durable disk spooling across lippycat process or host restarts.
- Exactly-once delivery without MDF acknowledgements.
- Changing X2/X3 PDU encoding or correlation identifiers.
- Fixing MDF database or IPv6 validation issues listed as out of scope in the
  source issue.
- Adding a project-wide Prometheus server solely for this fix.

---

## Rollout

1. Land the queue/connection refactor behind LI build tags with defaults enabled.
2. Run unit, integration, race, LI build, and non-LI exclusion checks.
3. Deploy to a staging tap connected to a restartable MDF.
4. Exercise graceful restart, abrupt reset, and sustained-outage scenarios.
5. Compare capture counts against MDF receive counts and inspect drop counters.
6. Deploy to one production tap and monitor reconnects, queue depth, oldest
   queued age, and drops before broad rollout.
