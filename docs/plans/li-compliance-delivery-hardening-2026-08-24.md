# LI Compliance and Delivery Hardening Plan

**Date:** 2026-08-24  
**Code baseline:** `f045f6b` (`v0.9.4`)  
**Scope:** ETSI X1 task lifecycle, LI filter enforcement, X2/X3 product generation and delivery, VoIP call retention, distributed timestamps, and related availability controls.

## 1. Objective

Make LI task acknowledgement, packet interception, and delivery agree with one another under normal operation, partial failure, overload, restart, and task lifecycle transitions.

The implementation must preserve these invariants:

1. X1 returns success only when a task is valid and every required filter has been installed, or when a future-dated task has been durably registered as pending.
2. A task cannot intercept before `StartTime` or after an enforceable `EndTime`.
3. Filters from one XID cannot overwrite or remove filters belonging to another XID.
4. Deactivation, expiry, rollback, and reconciliation withdraw all filters for the affected task.
5. A supported target never activates into a state where matching packets are silently discarded.
6. Loss or overload in X3 media delivery cannot evict X2 signalling product.
7. A recoverable delivery outage applies bounded backoff without busy-spinning and without unbounded memory growth.
8. Legally significant timestamps come from packet capture time.
9. Interop-visible protocol changes are coordinated with the ADMF and MDF implementations.

## 2. Non-goals

- Redesigning the entire VoIP capture and sharding pipeline.
- Adding LI awareness directly to generic VoIP domain types.
- Implementing new non-VoIP protocol analysers solely to create protocol-specific IRI.
- Changing X1 version or X2/X3 sequence semantics without coordinated peer rollout.
- Treating ADMF reconciliation as a substitute for enforcing task state locally.

## 3. Phase 1 — Make task activation truthful

### 3.1 Propagate and roll back filter-push failures

**Current code:** `internal/pkg/li/filters.go`

`CreateFiltersForTask` and `UpdateFiltersForTask` currently ignore errors from `UpdateFilter` and `DeleteFilter`. This lets X1 acknowledge a task whose filters were never distributed.

Implement the following:

- [ ] Make filter installation transactional from the caller's perspective.
- [ ] During creation, push filters one at a time and record successful pushes.
- [ ] If any push fails:
  - [ ] delete all successfully pushed filters;
  - [ ] remove all newly created local mappings;
  - [ ] return a wrapped error containing the XID, filter ID, operation, and rollback outcome.
- [ ] If rollback itself fails, return a joined/aggregate error and log the residual filter IDs at ERROR.
- [ ] During update, preserve the old filter set until the new set is fully installed.
- [ ] Define a safe update sequence that does not create an interception gap:
  - [ ] Validate and construct the complete replacement set.
  - [ ] Install the replacement filters.
  - [ ] Remove the old filters.
  - [ ] Commit local mappings.
- [ ] If old-filter removal partially fails, report the task as failed or degraded and retain enough state to retry cleanup. Never silently forget a remotely installed filter.
- [ ] Make `RemoveFiltersForTask` return all delete failures instead of logging and continuing as if removal succeeded.
- [ ] Report activation and enforcement failures to the ADMF through the existing X1 error-reporting path where possible.

Tests:

- [ ] Failure on the first filter push leaves no task filters locally or remotely.
- [ ] Failure after one successful push rolls the first filter back.
- [ ] Rollback failure is returned and identifies the residual filter.
- [ ] Update failure leaves the original filter set active.
- [ ] Partial old-filter deletion is visible to the caller and retryable.
- [ ] X1 activation returns an error rather than OK when distribution fails.

### 3.2 Make activation rollback remove the registry entry

**Current code:** `internal/pkg/li/manager.go`, `internal/pkg/li/registry.go`

`Manager.ActivateTask` currently rolls back by deactivating the task, leaving a tombstone that prevents retry with the same XID.

Implement an internal registry rollback operation with these properties:

- [ ] It removes only a task whose activation has not committed.
- [ ] It does not emit an ordinary deactivation audit event.
- [ ] It cannot remove an older active task with the same XID.
- [ ] It is invoked after any activation-time filter failure.
- [ ] Rollback errors are combined with the original activation error.

Tests:

- [ ] A failed activation followed by a retry with the same XID succeeds.
- [ ] Concurrent activation attempts cannot roll back one another's committed task.

### 3.3 Use collision-safe filter IDs

**Current code:** `internal/pkg/li/filters.go`

Replace `li-{8-hex-prefix}-{index}` with a collision-safe format, preferably:

```text
li-{full-canonical-xid}-{index}
```

Also:

- [ ] Check `filterStore` and `filterToXID` before insertion. Reject a filter ID already owned by another XID.
- [ ] Update `liFilterXIDPrefix` to parse both the full-XID format and the legacy eight-character format.
- [ ] Update startup orphan-filter reconciliation to compare full XIDs exactly for new IDs.
- [ ] Treat legacy IDs conservatively during migration:
  - [ ] associate a legacy prefix only when it maps unambiguously to one authoritative XID;
  - [ ] remove and recreate ambiguous legacy filters using full-XID IDs;
  - [ ] never delete a legacy filter solely because two authoritative XIDs share its prefix without first identifying its owner.
- [ ] Update descriptions and log fields to include the full XID even if display output abbreviates it.

Tests:

- [ ] Two XIDs sharing the first eight characters receive distinct filters.
- [ ] Removing either task leaves the other's filters intact.
- [ ] New and legacy IDs are parsed correctly.
- [ ] Startup reconciliation migrates an unambiguous legacy filter.
- [ ] Ambiguous legacy IDs fail safe and produce an actionable log.

## 4. Phase 2 — Enforce the complete task lifecycle

### 4.1 Parse mediation time bounds

**Current code:** `internal/pkg/li/x1/server.go`, `internal/pkg/li/x1/schema`, `internal/pkg/li/convert.go`

- [ ] Parse `StartTime` and `EndTime` from `TaskDetails.ListOfMediationDetails` for activation and modification.
- [ ] Validate timestamp syntax, ordering, and representable range.
- [ ] Reject `EndTime <= StartTime`.
- [ ] Reject an activation whose non-zero `EndTime` is already in the past.
- [ ] Decide and document zero-`EndTime` policy before implementation:
  - [ ] either permit indefinite tasks explicitly; or
  - [ ] require an end time and reject its absence.
- [ ] Define multi-DID mediation semantics. If mediation entries contain inconsistent time windows that cannot be represented by the current task model, reject the request rather than flattening them silently.
- [ ] Include the effective start/end values in task-detail responses and reconciliation conversions.

Tests:

- [ ] Valid bounded activation populates both fields.
- [ ] Malformed, reversed, and already-expired windows are rejected.
- [ ] ModifyTask updates `EndTime` atomically.
- [ ] Inconsistent per-destination windows are rejected until the domain model supports them.

### 4.2 Do not install filters for pending tasks

**Current code:** `internal/pkg/li/registry.go`, `internal/pkg/li/manager.go`

The registry can mark a task pending, but the manager currently installs its filters immediately.

- [ ] Register a future-dated task with `TaskStatusPending` and no filters.
- [ ] Add a lifecycle scheduler that promotes pending tasks when `StartTime` is reached.
- [ ] Promotion must use the same transactional filter installation as immediate activation.
- [ ] If promotion fails:
  - [ ] mark the task failed;
  - [ ] keep filters absent or roll them back fully;
  - [ ] report the failure to ADMF;
  - [ ] retain enough error state for diagnostics and an explicit retry policy.
- [ ] Ensure periodic reconciliation does not repeatedly attempt to activate an already pending task as a duplicate.

Tests:

- [ ] A future task has no local or pushed filters before its start.
- [ ] Filters appear at the start boundary and matching packets are then processed.
- [ ] Promotion failure produces no partially armed task.
- [ ] Deactivation before `StartTime` prevents later promotion.

### 4.3 Withdraw filters on expiry

**Current code:** `internal/pkg/li/registry.go`, `internal/pkg/li/manager.go`

The registry expiration loop currently changes task status without removing filters.

- [ ] Move enforcement coordination into the manager, or make the registry emit an event that the manager handles synchronously.
- [ ] At expiry:
  - [ ] Prevent new packet processing for the task.
  - [ ] Remove all task filters.
  - [ ] Mark the task deactivated with reason `Expired`.
  - [ ] Clear LI delivery/reorder/sequence state for the XID.
  - [ ] Report implicit deactivation to ADMF.
  - [ ] Log XID, effective end time, filter count, and cleanup result at INFO or above.
- [ ] Failed filter withdrawal must be retried and surfaced as a compliance fault.
- [ ] Avoid calling external callbacks while manually unlocking and relocking inside a ranged map mutation. Collect expiry actions under lock, then execute them outside the registry lock.

Tests:

- [ ] An expiring task stops invoking its packet processor.
- [ ] Its local and pushed filters are removed.
- [ ] Reorder buffers and sequence state are cleared.
- [ ] Removal failure is retried and reported.
- [ ] Concurrent explicit deactivation and expiry are idempotent.

### 4.4 Support deliberate reactivation of a deactivated XID

- [ ] Permit reactivation only when the existing task is in `Deactivated` state.
- [ ] Replace/reset the task atomically while preserving its historical deactivation record in a separate audit trail.
- [ ] Do not permit reactivation over active, pending, suspended, or failed state without an explicit recovery operation.
- [ ] Recreate filters using the normal transactional activation path.
- [ ] Add configurable tombstone retention, default 24 hours, and invoke purge from the manager maintenance loop.
- [ ] Purging must not destroy the audit history required by the deployment; if the registry becomes persistent, separate operational tombstones from durable audit records.

Tests:

- [ ] Activate, deactivate, and reactivate the same XID.
- [ ] Reactivation with changed targets replaces the prior task definition.
- [ ] Purge does not affect active or pending tasks.

## 5. Phase 3 — Eliminate silent product loss

### 5.1 Define supported delivery for every target type

**Current code:** `internal/pkg/processor/processor_li.go`

IP and CIDR filters can match ordinary packets, but delivery is gated on VoIP metadata.

Use an explicit capability matrix at activation time:

| Target/traffic capability | X2 | X3 | Activation behavior |
|---|---:|---:|---|
| SIP identity with SIP/RTP analysis | Yes | Yes | Accept supported delivery combinations |
| IP/CIDR raw packet CC | No generic IRI initially | Yes | Accept X3-only; accept X2+X3 only if policy permits X3 with absent generic IRI |
| Target with no encoder/filter support | No | No | Reject |

Implementation:

- [ ] Add a raw-IP X3 encoding path with the ETSI-approved payload format selected in coordination with the MDF.
- [ ] Preserve original packet bytes, capture timestamp, network attributes, direction, XID, and matched target.
- [ ] Do not manufacture protocol-specific X2 IRI from traffic without a suitable analyser.
- [ ] Reject unsupported target/delivery combinations during activation with a specific X1 error.
- [ ] Add counters for rejected combinations and matched packets that reach no encoder; the latter should remain zero in normal operation.

Tests:

- [ ] IPv4, IPv6, and CIDR tasks produce X3 for matching non-VoIP packets.
- [ ] Unsupported X2-only combinations are rejected before filters are installed.
- [ ] No accepted task silently drops all matched product.

### 5.2 Fix RTP reorder-buffer starvation and bounds

**Current code:** `internal/pkg/li/delivery/reorder.go`

- [ ] Base the flush deadline on the oldest buffered packet.
- [ ] Do not reset an already armed timer merely because another early packet arrives.
- [ ] After a timer fires, re-arm only when buffered data remains or a new gap begins.
- [ ] Replace the linear-scan/removal loop with a sequence-keyed map plus ordered selection, or an equivalent bounded structure with wraparound-aware ordering.
- [ ] Add configurable packet and byte caps per SSRC.
- [ ] On cap pressure, flush buffered packets in sequence order across gaps; do not discard later packets merely because an earlier packet is permanently missing.
- [ ] Never invoke the delivery callback while holding the reorder-buffer mutex. Gather output under lock and deliver after unlocking.

Tests:

- [ ] A permanently missing RTP sequence flushes within `flushDelay` while traffic continues.
- [ ] Subsequent packets continue to flow.
- [ ] Sequence wraparound is correct.
- [ ] Buffer limits are enforced.
- [ ] A slow callback cannot deadlock delivery or cleanup.

### 5.3 Isolate X2 from X3 queue pressure

**Current code:** `internal/pkg/li/delivery/client.go`

- [ ] Maintain separate bounded X2 and X3 queues per destination.
- [ ] Reserve X2 capacity; X3 enqueue must never evict X2.
- [ ] Use a single per-destination dispatcher with explicit scheduling:
  - [ ] strict preference for X2 when present;
  - [ ] bounded fairness so sustained X2 does not permanently starve X3.
- [ ] Track queue depth, capacity, overflow, age, and drop reason separately by PDU type.
- [ ] Log any X2 terminal drop loudly with XID, DID, age, and reason.
- [ ] Keep queued item data immutable and avoid duplicate copies unless per-destination marshaling requires them.

Tests:

- [ ] Saturated X3 traffic drops/evicts only X3.
- [ ] X2 is delivered promptly during X3 saturation.
- [ ] Sustained X2 still permits bounded X3 progress.
- [ ] Shutdown and destination removal drain/account for both queues correctly.

### 5.4 Reject empty SIP IRI payloads

**Current code:** `internal/pkg/li/x2x3/x2_encoder.go`

- [ ] Change SIP payload extraction to return an error when neither `RawSIP` nor a valid SIP start in `RawData` is available.
- [ ] Make `buildSIPPDU` and public encode methods return that error.
- [ ] Do not marshal or enqueue an empty-payload X2 SIP PDU.
- [ ] Count failures and log at WARN with XID and sanitized Call-ID.

Tests:

- [ ] Both payload sources absent returns a typed error.
- [ ] Fallback scanning still succeeds for valid raw packet data.
- [ ] Processor delivery does not enqueue a failed PDU.

### 5.5 Protect active intercepted calls from ordinary LRU eviction

**Current code:** `internal/pkg/voip/calltracker.go`, `internal/pkg/processor/processor_li.go`

- [ ] Add a generic call-retention lease/pin mechanism to the call tracker; do not import LI packages into `internal/pkg/voip`.
- [ ] The processor LI integration pins a Call-ID while at least one active task requires its media and releases it on call completion/task deactivation.
- [ ] Prefer evicting unpinned inactive calls, then unpinned least-recently-active calls.
- [ ] If all calls are pinned, allow controlled growth beyond the soft cap and emit a rate-limited WARN plus metrics.
- [ ] Refresh RTP recency without taking the global write lock for every RTP packet, for example with atomic `lastSeen` values considered during eviction or a periodic promotion pass.
- [ ] Wire the existing `voip.max_calls` configuration into this tracker rather than hard-coding `DefaultMaxCalls`.

Tests:

- [ ] An RTP-only active call remains eligible and recent.
- [ ] An intercepted pinned call survives capacity pressure.
- [ ] Unpinned calls are still evicted.
- [ ] Pin release allows later eviction and does not leak state.

## 6. Phase 4 — Availability and resource controls

### 6.1 Apply real delivery retry backoff

**Current code:** `internal/pkg/li/delivery/client.go`, `internal/pkg/li/delivery/destination.go`

- [ ] Remove `q.notify` from the failed-connection retry wait. New traffic must not bypass backoff.
- [ ] Use exponential backoff with configured initial and maximum durations and bounded jitter.
- [ ] Reset backoff only after a successful connection/write threshold.
- [ ] Stop promptly on destination removal or client shutdown.
- [ ] Log state transitions and summarized failure counts, not every attempt.

Tests:

- [ ] Continuous enqueue during outage does not accelerate retries.
- [ ] Retry intervals grow and cap as configured.
- [ ] CPU remains idle between retries.
- [ ] Shutdown interrupts the wait immediately.

### 6.2 Bound and secure X1 rate limiting

**Current code:** `internal/pkg/li/x1/server.go`

- [ ] Use `RemoteAddr` by default.
- [ ] Add a configured trusted-proxy CIDR list, empty by default.
- [ ] Honour `Forwarded`/`X-Forwarded-For` only when the immediate peer is trusted and validate every parsed address.
- [ ] Replace the unbounded `sync.Map` with a bounded TTL cache or periodically prune idle limiters.
- [ ] Expose limiter entry count and eviction metrics.

Tests:

- [ ] Varying XFF from an untrusted peer cannot bypass limits or grow the cache.
- [ ] Trusted proxy extraction selects the intended client address.
- [ ] Idle entries expire and the cache remains bounded.

### 6.3 Remove manager-wide counter locks from the packet path

**Current code:** `internal/pkg/li/manager.go`

- [ ] Convert packet/match/error counters to typed atomics.
- [ ] Store/load the packet callback without a per-packet exclusive mutex, using `atomic.Pointer`, `atomic.Value`, or immutable configuration after startup.
- [ ] Audit all remaining manager locks reachable from `ProcessPacket`.
- [ ] Preserve a consistent stats snapshot API.

Tests and benchmarks:

- [ ] Race-enabled callback replacement/read test if callback mutation remains supported.
- [ ] Benchmark matched and unmatched packet paths before and after.

### 6.4 Prevent one flow shard from blocking the shared drain

**Current code:** `internal/pkg/voip/core.go`

- [ ] Make worker dispatch non-blocking or use a bounded overflow policy.
- [ ] Count drops by worker and reason.
- [ ] Expose per-worker queue depth/high-water marks.
- [ ] Rate-limit overload logs.
- [ ] Preserve flow affinity; document that drops are preferable to globally stalling all flows.
- [ ] Track TCP worker-0 concentration as a follow-up metric. Pipeline restructuring remains separate work.

Tests:

- [ ] A saturated worker does not block packets destined for another worker.
- [ ] Drops are attributed to the correct worker.
- [ ] Shutdown still closes workers without send-on-closed-channel races.

## 7. Phase 5 — Evidential correctness and interop

### 7.1 Preserve capture timestamps across hunters

**Current code:** `internal/pkg/hunter/hunter.go`

- [ ] In `convertPacket`, use `pkt.Metadata().Timestamp` when available.
- [ ] In `ForwardPacketWithMetadata`, use the original packet metadata timestamp.
- [ ] Define a fallback for synthetic packets without capture metadata and mark/log that fallback distinctly.
- [ ] Verify processor conversion preserves the nanosecond value into X2/X3 attribute 9.

Tests:

- [ ] Forwarded protobuf timestamps equal fixture capture timestamps.
- [ ] Delayed forwarding and reconnect buffering do not change them.
- [ ] X2/X3 decoded timestamp attributes match the source PCAP.

### 7.2 Repair X1 request-container handling

**Current code:** `internal/pkg/li/x1/server.go`, generated X1 schema types

- [ ] Support the ETSI `X1Request` envelope as the primary format.
- [ ] If legacy `requestContainer` remains supported, process every contained message, not only index zero.
- [ ] Do not pass the complete container XML to a single-message router.
- [ ] Preserve each message's concrete operation type and fields; the current generated base-message slice is insufficient on its own.
- [ ] Return one ordered response per request and define whether processing continues after an individual error.
- [ ] Reject truly nested containers explicitly.

Tests:

- [ ] Single-message envelope succeeds.
- [ ] Multi-message container executes every request in order.
- [ ] Mixed success/error responses retain transaction IDs.
- [ ] A nested container is rejected without affecting sibling messages.

### 7.3 Coordinate per-XID/per-destination sequence numbers

**Current code:** `internal/pkg/li/x2x3`, `internal/pkg/li/delivery/client.go`

Do not deploy this change until MDF behavior and cutover are agreed.

- [ ] Remove sequence ownership from the global X2/X3 encoder instances.
- [ ] Assign attribute 8 for each `(XID, DID)` delivery stream using `Client.NextSequence` or a replacement owned by the delivery layer.
- [ ] Because sequence differs by destination, marshal a destination-specific PDU after assigning the sequence.
- [ ] Reset sequence state on task deactivation and destination removal.
- [ ] Define restart behavior: persisted continuation or an explicitly signalled reset.
- [ ] Add bounds/cleanup for sequence-map entries.

Tests:

- [ ] Two XIDs each begin at the agreed initial value for one DID.
- [ ] The same XID has independent sequences across DIDs.
- [ ] X2 and X3 follow the peer-agreed shared or separate stream rule.
- [ ] Deactivation/reset and restart behavior are deterministic.

### 7.4 Add X2/X3 keepalive exchange

- [ ] Add configurable keepalive interval and missed-ACK threshold per destination.
- [ ] Send the existing ETSI keepalive PDU on idle connections.
- [ ] Parse inbound keepalive ACKs instead of discarding all reads.
- [ ] Reconnect after the configured number of missed acknowledgements.
- [ ] Keep data delivery ordering independent from keepalive control frames.
- [ ] Expose last ACK, missed ACKs, and reconnect reason in stats.

Tests:

- [ ] Keepalive and ACK maintain an idle connection.
- [ ] Missed ACKs trigger reconnect.
- [ ] Data delivery continues correctly around keepalive frames.

### 7.5 Align the X1 declared version

Coordinate one declared X1 revision across lippycat, the ADMF, and the MDF before changing defaults.

- [ ] Select the supported revision based on the actual XSD/schema behavior, not merely the newest string.
- [ ] Update server/client defaults, tests, fixtures, and documentation together.
- [ ] Optionally validate compatible inbound versions and return a precise error for unsupported revisions.
- [ ] Include version negotiation/cutover guidance in release notes.

### 7.6 Protect X2/X3 correlation identity

- [ ] Add an end-to-end regression test proving that X2 SIP and X3 RTP for the same call carry the same correlation identity expected by the MDF.
- [ ] Cover multiple SSRCs, both media directions, re-INVITE, and call-ID reuse.
- [ ] Document the correlation derivation as a wire-level compatibility invariant.

## 8. Phase 6 — State persistence and reconciliation completion

Current ADMF startup sync and periodic reconciliation already remove authoritative orphan tasks, guard incomplete/empty snapshots, and sweep orphan LI filters at startup. Preserve those behaviors.

Add local persistence only after lifecycle semantics above are stable:

- [ ] Persist tasks, destinations, status, effective time bounds, activation generation, and cleanup-needed state.
- [ ] Write atomically with versioned schema and restrictive file permissions.
- [ ] Do not persist secrets that need not be stored.
- [ ] Treat the ADMF as authoritative when a complete response is available.
- [ ] Keep the existing protections against conversion errors and transient empty-task responses.
- [ ] Reconcile destinations in both directions, with the same authoritative-snapshot safeguards used for tasks.
- [ ] Restore pending tasks without arming them early.
- [ ] Restore active tasks only after confirming time validity and ADMF authority.
- [ ] Resume cleanup for residual filters recorded after partial failure.

Tests:

- [ ] Restart restores bounded active and pending tasks correctly.
- [ ] Expired tasks are not re-armed.
- [ ] A complete ADMF snapshot removes local-only tasks and destinations.
- [ ] Incomplete or transiently empty snapshots do not cause mass teardown.
- [ ] Corrupt persistence fails closed with actionable diagnostics.

## 9. Cross-project decisions and rollout gates

The following require agreement with the ADMF/MDF implementations before deployment:

- [ ] Decide the missing/zero `EndTime` policy.
- [ ] Decide how to represent multiple mediation windows for one task and several DIDs.
- [ ] Agree the raw-IP X3 payload format and MDF decoding behavior.
- [ ] Agree attribute-8 scope, initial value, reset, and restart semantics.
- [ ] Agree the X2/X3 keepalive interval and ACK behavior.
- [ ] Agree the X1 declared version and compatibility validation.
- [ ] Agree the XID reuse policy and audit-history expectations.
- [ ] Agree correlation-ID derivation and multi-SSRC behavior.

Record each decision in protocol documentation and add a compatibility test fixture shared with the affected peer.

## 10. Verification strategy

Run after each phase as applicable:

```bash
make fmt
go vet -tags all ./...
go vet -tags "all li" ./...
go test -tags "all li" -race ./internal/pkg/li/...
go test -tags all -race ./internal/pkg/voip/... ./internal/pkg/processor/... ./internal/pkg/hunter/...
```

Add focused benchmarks for:

- [ ] LI `ProcessPacket` matched and unmatched paths.
- [ ] Reorder buffering under loss and sustained RTP.
- [ ] Mixed X2/X3 enqueue and dispatch under saturation.
- [ ] Call-tracker lookup/recency at configured capacity.

End-to-end scenarios:

- [ ] Immediate activation installs every filter before X1 OK.
- [ ] Injected filter-push failure returns X1 error and leaves no residual filter.
- [ ] Future activation remains unarmed until `StartTime`.
- [ ] Expiry stops product and withdraws filters at `EndTime`.
- [ ] Activate/deactivate/reactivate the same XID.
- [ ] Colliding legacy XID prefixes remain isolated.
- [ ] IP/CIDR X3 product reaches a test MDF or activation is rejected for unsupported delivery.
- [ ] Permanent RTP loss does not stall later CC.
- [ ] X3 saturation does not drop X2.
- [ ] MDF outage follows backoff without busy-spin.
- [ ] More than the configured call limit does not evict pinned intercepted calls.
- [ ] Hunter-forwarded product retains the source capture timestamp.
- [ ] Restart reconciliation neither re-arms expired tasks nor removes tasks from an untrusted snapshot.

## 11. Observability and operational acceptance

Expose at minimum:

- [ ] Task counts by status: pending, active, failed, deactivated.
- [ ] Filter install/delete attempts, failures, rollbacks, and residual cleanup count.
- [ ] Matched packets with no applicable encoder.
- [ ] X2/X3 queue depth, age, overflow, terminal drops, and retries per DID.
- [ ] Reorder-buffer streams, packets, bytes, timeout flushes, and forced cap flushes.
- [ ] Pinned calls, soft-cap overage, and call evictions.
- [ ] X1 rate-limiter entries and evictions.
- [ ] Delivery keepalive ACK age and missed ACKs.

Operational acceptance requires:

- [ ] No silent error branches in LI activation, filter distribution, deactivation, encoding, or delivery.
- [ ] Every compliance-affecting failure includes XID and, where applicable, DID/filter ID.
- [ ] Rate-limited logs for high-frequency failures, backed by monotonically increasing counters.
- [ ] Runbook entries for residual-filter cleanup, failed pending activation, MDF outage, and coordinated protocol cutover.

## 12. Implementation boundaries

Keep package dependencies clean:

- `internal/pkg/voip` exposes generic retention/recency capabilities and must not import `internal/pkg/li`.
- `internal/pkg/li` owns task lifecycle and filter-to-XID state.
- `internal/pkg/processor` connects LI tasks to packet encoders, delivery, and call-retention leases.
- `internal/pkg/li/delivery` owns per-destination delivery ordering, retry, and queue policy.
- X1 parsing converts wire types into explicit domain semantics before mutating registry state.

Each phase should land with its tests and documentation. Avoid combining coordinated wire-protocol changes with unrelated local correctness fixes in one deployment.
