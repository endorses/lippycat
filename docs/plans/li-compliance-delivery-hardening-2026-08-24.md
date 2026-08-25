# LI Compliance and Delivery Hardening Plan

**Date:** 2026-08-24  
**Code baseline:** `f045f6b` (`v0.9.4`)  
**Scope:** ETSI X1 task lifecycle, LI filter enforcement, X2/X3 product generation and delivery, VoIP call retention, distributed timestamps, and related availability controls.

## Implementation audit update — 2026-08-25 (post-hardening)

The implementation was re-audited against this plan after the Phase 1–6 changes
landed. The plan is **not complete** and must not be used to claim full LI
compliance or operational acceptance yet.

The following implementation gaps remain:

- Ambiguous legacy filter ownership still fails safe by retaining and logging the
  filter. Automated ownership identification and migration remain incomplete.
  `FilterLister` currently exposes only IDs, so ownership of an ambiguous
  eight-character legacy prefix cannot be proved without extending the API to
  return authoritative ownership metadata. Do not delete these filters
  heuristically.
- Compliance-critical focused, socket-backed, and end-to-end tests listed in
  sections 4, 6, 7, and 10 remain required. A sandboxed audit run of
  `go test -race -tags 'all,li' ./internal/pkg/li/...` could not execute tests
  requiring local TCP listeners (`socket: operation not permitted`); this is an
  environment limitation, not evidence that those tests pass or fail.

Completed checkboxes elsewhere in this document describe implemented local code,
not peer interoperability approval or completion of the operational acceptance
criteria in sections 9–11.

Checkbox convention in this document:

- `[x]` means the stated code change or named test has been implemented locally.
- `[ ]` means it is not implemented, not covered by the named test, or still
  requires external verification/coordination as described beside the item.
- A checked implementation item does not imply that a separate unchecked test,
  rollout gate, or operational-acceptance item has passed.

The post-audit hardening completed the three previously identified local code
gaps:

- `GetTaskDetails` returns targets, destinations, schema-valid provisioning
  status, unresolved faults, and effective mediation start/end bounds.
- Existing RTP calls refresh atomic last-seen timestamps, which eviction uses
  without taking the tracker-wide write lock for each media packet.
- X2 and X3 content and keepalive traffic use distinct interface-scoped TLS
  pools. ACK state belongs to one connection/interface, and a timeout closes and
  reconnects only that interface using bounded jittered backoff.

Post-hardening verification completed:

- Race-enabled focused tests pass for X1 task-detail responses, delivery
  keepalive configuration and interface-scoped ACK handling, X2/X3 control PDUs,
  and RTP call recency/pinning.
- All LI, VoIP, and processor packages compile with `-tags 'all li'`.
- `go vet -tags 'all li' ./internal/pkg/li/... ./internal/pkg/voip/...` passes.
- `git diff --check` passes.
- The complete race-enabled LI suite remains unverified in this sandbox because
  its `httptest` cases cannot bind local TCP listeners.

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

**Status (2026-08-25): Implemented, with one migration follow-up.** Filter creation and replacement now
propagate distribution failures, retain retryable cleanup state, use canonical
XIDs in new filter IDs, and remove uncommitted registry activations. The LI test
suite passes with `go test -tags li ./internal/pkg/li/...`. Ambiguous legacy
filter ownership deliberately fails safe; automated owner identification is
still required before those legacy filters can be removed.

### 3.1 Propagate and roll back filter-push failures

**Current code:** `internal/pkg/li/filters.go`

Previous behavior: `CreateFiltersForTask` and `UpdateFiltersForTask` ignored errors from `UpdateFilter` and `DeleteFilter`, allowing X1 to acknowledge a task whose filters were never distributed.

Implement the following:

- [x] Make filter installation transactional from the caller's perspective.
- [x] During creation, push filters one at a time and record successful pushes.
- [x] If any push fails:
  - [x] delete all successfully pushed filters;
  - [x] remove all newly created local mappings;
  - [x] return a wrapped error containing the XID, filter ID, operation, and rollback outcome.
- [x] If rollback itself fails, return a joined/aggregate error and log the residual filter IDs at ERROR.
- [x] During update, preserve the old filter set until the new set is fully installed.
- [x] Define a safe update sequence that does not create an interception gap:
  - [x] Validate and construct the complete replacement set.
  - [x] Install the replacement filters.
  - [x] Remove the old filters.
  - [x] Commit local mappings.
- [x] If old-filter removal partially fails, report the task as failed or degraded and retain enough state to retry cleanup. Never silently forget a remotely installed filter.
- [x] Make `RemoveFiltersForTask` return all delete failures instead of logging and continuing as if removal succeeded.
- [x] Report activation and enforcement failures to the ADMF through the existing X1 error-reporting path where possible.

Implementation note: replacement mappings are staged locally before old-filter
withdrawal and become the committed set after withdrawal. Any old filters whose
deletion fails remain in the mapping. `FilterCleanupError` causes the task to be
marked failed, which uses the existing fault-deactivation reporting path.

Tests:

- [x] Failure on the first filter push leaves no task filters locally or remotely.
- [x] Failure after one successful push rolls the first filter back.
- [x] Rollback failure is returned and identifies the residual filter.
- [x] Update failure leaves the original filter set active.
- [x] Partial old-filter deletion is visible to the caller and retryable.
- [x] X1 activation returns an error rather than OK when distribution fails.

### 3.2 Make activation rollback remove the registry entry

**Current code:** `internal/pkg/li/manager.go`, `internal/pkg/li/registry.go`

Previous behavior: `Manager.ActivateTask` rolled back by deactivating the task, leaving a tombstone that prevented retry with the same XID.

Implement an internal registry rollback operation with these properties:

- [x] It removes only a task whose activation has not committed.
- [x] It does not emit an ordinary deactivation audit event.
- [x] It cannot remove an older active task with the same XID.
- [x] It is invoked after any activation-time filter failure.
- [x] Rollback errors are combined with the original activation error.

Tests:

- [x] A failed activation followed by a retry with the same XID succeeds.
- [x] Concurrent activation attempts cannot roll back one another's committed task.

### 3.3 Use collision-safe filter IDs

**Current code:** `internal/pkg/li/filters.go`

Replace `li-{8-hex-prefix}-{index}` with a collision-safe format, preferably:

```text
li-{full-canonical-xid}-{index}
```

Also:

- [x] Check `filterStore` and `filterToXID` before insertion. Reject a filter ID already owned by another XID.
- [x] Update `liFilterXIDPrefix` to parse both the full-XID format and the legacy eight-character format.
- [x] Update startup orphan-filter reconciliation to compare full XIDs exactly for new IDs.
- [x] Treat legacy IDs conservatively during migration:
  - [x] associate a legacy prefix only when it maps unambiguously to one authoritative XID;
  - [ ] remove and recreate ambiguous legacy filters using full-XID IDs;
  - [x] never delete a legacy filter solely because two authoritative XIDs share its prefix without first identifying its owner.
- [x] Update descriptions and log fields to include the full XID even if display output abbreviates it.

Migration note: canonical replacements are installed from authoritative ADMF
tasks. Unambiguous legacy filters are then removed. Ambiguous legacy filters are
retained and logged at ERROR with all candidate XIDs because their owner cannot
be proven safely; the canonical filters already prevent new collisions. Removing
those retained legacy filters remains open until reconciliation can identify
their actual owner from authoritative filter metadata.

Tests:

- [x] Two XIDs sharing the first eight characters receive distinct filters.
- [x] Removing either task leaves the other's filters intact.
- [x] New and legacy IDs are parsed correctly.
- [ ] Startup reconciliation migrates an unambiguous legacy filter.
- [ ] Ambiguous legacy IDs fail safe and produce an actionable log.

The migration behaviors above are implemented and exercised by the broader
reconciliation suite, but dedicated regression tests for these two cases remain
to be added.

## 4. Phase 2 — Enforce the complete task lifecycle

**Status (2026-08-25): Implemented, with focused test follow-ups.** Mediation windows are parsed and validated,
future tasks remain unarmed until manager-driven promotion, expiry gates packet
processing before transactional filter withdrawal, and deactivated XIDs may be
deliberately reactivated. Zero `EndTime` explicitly means an indefinite task.
Manager maintenance purges operational tombstones after 24 hours by default;
reactivation history is retained separately in the registry audit history.
The full LI suite passes with `go test -tags li ./internal/pkg/li/...`. Dedicated
regressions are still needed for the unchecked concurrency, cleanup-failure,
and packet-processing cases below. Task-detail response content has focused
coverage; full socket-backed X1 coverage remains part of the verification gap.

### 4.1 Parse mediation time bounds

**Current code:** `internal/pkg/li/x1/server.go`, `internal/pkg/li/x1/schema`, `internal/pkg/li/convert.go`

- [x] Parse `StartTime` and `EndTime` from `TaskDetails.ListOfMediationDetails` for activation and modification.
- [x] Validate timestamp syntax, ordering, and representable range.
- [x] Reject `EndTime <= StartTime`.
- [x] Reject an activation whose non-zero `EndTime` is already in the past.
- [x] Decide and document zero-`EndTime` policy before implementation:
  - [x] permit indefinite tasks explicitly; or
  - [ ] require an end time and reject its absence.
- [x] Define multi-DID mediation semantics. If mediation entries contain inconsistent time windows that cannot be represented by the current task model, reject the request rather than flattening them silently.
- [x] Include the effective start/end values in task-detail responses and reconciliation conversions.

Tests:

- [x] Valid bounded activation populates both fields.
- [x] Malformed, reversed, and already-expired windows are rejected.
- [x] ModifyTask updates `EndTime` atomically.
- [x] Inconsistent per-destination windows are rejected until the domain model supports them.

### 4.2 Do not install filters for pending tasks

**Current code:** `internal/pkg/li/registry.go`, `internal/pkg/li/manager.go`

The registry can mark a task pending, but the manager currently installs its filters immediately.

- [x] Register a future-dated task with `TaskStatusPending` and no filters.
- [x] Add a lifecycle scheduler that promotes pending tasks when `StartTime` is reached.
- [x] Promotion must use the same transactional filter installation as immediate activation.
- [x] If promotion fails:
  - [x] mark the task failed;
  - [x] keep filters absent or roll them back fully;
  - [x] report the failure to ADMF;
  - [x] retain enough error state for diagnostics and an explicit retry policy. (No automatic retry; the failed task retains `LastError` and requires explicit recovery.)
- [x] Ensure periodic reconciliation does not repeatedly attempt to activate an already pending task as a duplicate.

Tests:

- [x] A future task has no local or pushed filters before its start.
- [ ] Filters appear at the start boundary and matching packets are then processed. (Filter installation is covered; matched-packet processing after promotion needs a dedicated assertion.)
- [ ] Promotion failure produces no partially armed task.
- [x] Deactivation before `StartTime` prevents later promotion.

### 4.3 Withdraw filters on expiry

**Current code:** `internal/pkg/li/registry.go`, `internal/pkg/li/manager.go`

The registry expiration loop currently changes task status without removing filters.

- [x] Move enforcement coordination into the manager, or make the registry emit an event that the manager handles synchronously.
- [x] At expiry:
  - [x] Prevent new packet processing for the task.
  - [x] Remove all task filters.
  - [x] Mark the task deactivated with reason `Expired`.
  - [x] Clear LI delivery/reorder/sequence state for the XID.
  - [x] Report implicit deactivation to ADMF.
  - [x] Log XID, effective end time, filter count, and cleanup result at INFO or above.
- [x] Failed filter withdrawal must be retried and surfaced as a compliance fault.
- [x] Avoid calling external callbacks while manually unlocking and relocking inside a ranged map mutation. Collect expiry actions under lock, then execute them outside the registry lock.

Tests:

- [ ] An expiring task stops invoking its packet processor.
- [x] Its local and pushed filters are removed.
- [ ] Reorder buffers and sequence state are cleared.
- [ ] Removal failure is retried and reported.
- [ ] Concurrent explicit deactivation and expiry are idempotent.

### 4.4 Support deliberate reactivation of a deactivated XID

- [x] Permit reactivation only when the existing task is in `Deactivated` state.
- [x] Replace/reset the task atomically while preserving its historical deactivation record in a separate audit trail.
- [x] Do not permit reactivation over active, pending, suspended, or failed state without an explicit recovery operation.
- [x] Recreate filters using the normal transactional activation path.
- [x] Add configurable tombstone retention, default 24 hours, and invoke purge from the manager maintenance loop.
- [x] Purging must not destroy the audit history required by the deployment; if the registry becomes persistent, separate operational tombstones from durable audit records.

Tests:

- [x] Activate, deactivate, and reactivate the same XID.
- [x] Reactivation with changed targets replaces the prior task definition.
- [x] Purge does not affect active or pending tasks.

## 5. Phase 3 — Eliminate silent product loss

**Status (2026-08-25): Implemented, with integration-test follow-ups.** IP/CIDR
matches now produce raw-packet X3 PDUs and unsupported X2-only combinations are
rejected before filter installation. RTP reordering is deadline-based and bounded,
X2 and X3 use isolated queues with bounded-fair dispatch, empty SIP products fail
encoding, and intercepted calls can be retained with generic tracker leases. The
focused Phase 3 tests and race-enabled reorder tests pass. Existing RTP calls use
atomic last-seen timestamps for eviction recency without a tracker-wide write lock.
Socket-backed end-to-end delivery tests remain open in an environment that permits
listeners.

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

- [x] Add a raw-IP X3 encoding path with the ETSI payload formats already represented by the wire implementation (`IPv4`, `IPv6`, or `Ethernet`). MDF rollout still requires the coordination gate in section 9.
- [x] Preserve original packet bytes, capture timestamp, network attributes, direction, XID, and matched target.
- [x] Do not manufacture protocol-specific X2 IRI from traffic without a suitable analyser.
- [x] Reject unsupported target/delivery combinations during activation with a specific typed error propagated through X1.
- [x] Add counters for rejected combinations and matched packets that reach no encoder; the latter should remain zero in normal operation.

Tests:

- [x] IPv4, IPv6, and CIDR tasks produce X3 for matching non-VoIP packets. (Encoder and activation paths have focused coverage; processor end-to-end delivery remains a follow-up.)
- [x] Unsupported X2-only combinations are rejected before filters are installed.
- [x] No accepted task silently drops all matched product; failures increment the no-encoder/error counters and log at WARN.

### 5.2 Fix RTP reorder-buffer starvation and bounds

**Current code:** `internal/pkg/li/delivery/reorder.go`

- [x] Base the flush deadline on the oldest buffered packet.
- [x] Do not reset an already armed timer merely because another early packet arrives.
- [x] After a timer fires, re-arm only when buffered data remains or a new gap begins.
- [x] Replace the linear-scan/removal loop with a sequence-keyed map plus ordered selection, or an equivalent bounded structure with wraparound-aware ordering.
- [x] Add configurable packet and byte caps per SSRC through `NewReorderBufferWithLimits`; the existing constructor supplies bounded defaults.
- [x] On cap pressure, flush buffered packets in sequence order across gaps; do not discard later packets merely because an earlier packet is permanently missing.
- [x] Never invoke the delivery callback while holding the reorder-buffer mutex. Gather output under lock and deliver after unlocking.

Tests:

- [x] A permanently missing RTP sequence flushes within `flushDelay` while traffic continues.
- [x] Subsequent packets continue to flow.
- [x] Sequence wraparound is correct through wraparound-relative ordered selection. (A dedicated boundary regression remains desirable.)
- [x] Buffer limits are enforced.
- [x] A slow callback cannot hold the reorder mutex or deadlock concurrent buffer access and cleanup.

### 5.3 Isolate X2 from X3 queue pressure

**Current code:** `internal/pkg/li/delivery/client.go`

- [x] Maintain separate bounded X2 and X3 queues per destination.
- [x] Reserve X2 capacity; X3 enqueue must never evict X2.
- [x] Use a single per-destination dispatcher with explicit scheduling:
  - [x] strict preference for X2 when present;
  - [x] bounded fairness so sustained X2 does not permanently starve X3 (one X3 opportunity after an eight-PDU X2 burst).
- [x] Track queue depth, capacity, overflow, age, and drop reason separately by PDU type.
- [x] Log any X2 terminal drop at ERROR with XID, DID, age, and reason.
- [x] Keep queued item data immutable and avoid duplicate copies unless per-destination marshaling requires them.

Tests:

- [x] Saturated X3 traffic drops/evicts only X3.
- [x] X2 is selected promptly during X3 saturation.
- [x] Sustained X2 still permits bounded X3 progress.
- [x] Shutdown and destination removal drain/account for both queues correctly. (Socket-backed delivery coverage requires a listener-capable test environment.)

### 5.4 Reject empty SIP IRI payloads

**Current code:** `internal/pkg/li/x2x3/x2_encoder.go`

- [x] Change SIP payload extraction to return typed `ErrNoSIPPayload` when neither `RawSIP` nor a valid SIP start in `RawData` is available.
- [x] Make `buildSIPPDU` and public encode methods return that error.
- [x] Do not marshal or enqueue an empty-payload X2 SIP PDU.
- [x] Count failures and log at WARN with XID and sanitized Call-ID.

Tests:

- [x] Both payload sources absent returns a typed error.
- [x] Fallback scanning still succeeds for valid raw packet data.
- [x] Processor delivery does not enqueue a failed PDU because encoding errors return before marshal/delivery.

### 5.5 Protect active intercepted calls from ordinary LRU eviction

**Current code:** `internal/pkg/voip/calltracker.go`, `internal/pkg/processor/processor_li.go`

- [x] Add a generic call-retention lease/pin mechanism to the call tracker; do not import LI packages into `internal/pkg/voip`.
- [x] The processor LI integration pins a Call-ID while at least one active task requires its media and releases it on call completion/task deactivation.
- [x] Prefer evicting unpinned inactive calls, then unpinned least-recently-active calls.
- [x] If all calls are pinned, allow controlled growth beyond the soft cap and emit a rate-limited WARN. (A dedicated controlled-growth metric remains a follow-up.)
- [x] Refresh RTP recency without taking the global write lock for every RTP packet, using atomic last-seen values considered during eviction.
- [x] Wire the existing `voip.max_calls` configuration into this tracker rather than hard-coding `DefaultMaxCalls`.

Tests:

- [x] An RTP-only active call remains eligible and recent.
- [x] An intercepted pinned call survives capacity pressure.
- [x] Unpinned calls are still evicted.
- [x] Pin release allows later eviction and does not leak state.

## 6. Phase 4 — Availability and resource controls

**Status (2026-08-25): Implemented.** Delivery dispatch now uses capped exponential
backoff with bounded jitter that enqueue notifications cannot bypass, and reconnect
backoff resets only after successful writes. X1 client identity defaults to the
immediate peer, trusts forwarding headers only for configured proxy CIDRs, and uses
a bounded idle-expiring limiter cache with entry/eviction stats. LI packet counters
and callback reads are atomic. VoIP flow-shard dispatch drops locally on saturation,
with per-worker drop, depth, and high-water statistics and rate-limited warnings.

### 6.1 Apply real delivery retry backoff

**Current code:** `internal/pkg/li/delivery/client.go`, `internal/pkg/li/delivery/destination.go`

- [x] Remove `q.notify` from the failed-connection retry wait. New traffic must not bypass backoff.
- [x] Use exponential backoff with configured initial and maximum durations and bounded jitter.
- [x] Reset backoff only after a successful connection/write threshold.
- [x] Stop promptly on destination removal or client shutdown.
- [x] Log state transitions and summarized failure counts, not every attempt.

Tests:

- [ ] Continuous enqueue during outage does not accelerate retries.
- [ ] Retry intervals grow and cap as configured.
- [ ] CPU remains idle between retries.
- [ ] Shutdown interrupts the wait immediately.

### 6.2 Bound and secure X1 rate limiting

**Current code:** `internal/pkg/li/x1/server.go`

- [x] Use `RemoteAddr` by default.
- [x] Add a configured trusted-proxy CIDR list, empty by default.
- [x] Honour `Forwarded`/`X-Forwarded-For` only when the immediate peer is trusted and validate every parsed address.
- [x] Replace the unbounded `sync.Map` with a bounded TTL cache or periodically prune idle limiters.
- [x] Expose limiter entry count and eviction metrics.

Tests:

- [x] Varying XFF from an untrusted peer cannot bypass limits or grow the cache.
- [x] Trusted proxy extraction selects the intended client address.
- [x] Idle entries expire and the cache remains bounded.

### 6.3 Remove manager-wide counter locks from the packet path

**Current code:** `internal/pkg/li/manager.go`

- [x] Convert packet/match/error counters to typed atomics.
- [x] Store/load the packet callback without a per-packet exclusive mutex, using `atomic.Pointer`, `atomic.Value`, or immutable configuration after startup.
- [x] Audit all remaining manager locks reachable from `ProcessPacket`.
- [x] Preserve a consistent stats snapshot API.

Tests and benchmarks:

- [ ] Race-enabled callback replacement/read test if callback mutation remains supported.
- [ ] Benchmark matched and unmatched packet paths before and after.

### 6.4 Prevent one flow shard from blocking the shared drain

**Current code:** `internal/pkg/voip/core.go`

- [x] Make worker dispatch non-blocking or use a bounded overflow policy.
- [x] Count drops by worker and reason.
- [x] Expose per-worker queue depth/high-water marks.
- [x] Rate-limit overload logs.
- [x] Preserve flow affinity; document that drops are preferable to globally stalling all flows.
- [x] Track TCP worker-0 concentration as a follow-up metric. Pipeline restructuring remains separate work. (Worker-0 depth, high-water, and drops provide this concentration signal.)

Tests:

- [ ] A saturated worker does not block packets destined for another worker.
- [ ] Drops are attributed to the correct worker.
- [ ] Shutdown still closes workers without send-on-closed-channel races.

## 7. Phase 5 — Evidential correctness and interop

**Status (2026-08-25): Implemented locally; coordinated enablement remains gated.**
Hunter forwarding now preserves capture timestamps, X1 handles ETSI envelopes and
all legacy-container messages in order, and X2/X3 correlation has a documented
wire invariant with an encoded-PDU regression test. Sequence ownership, X2/X3
keepalive behavior, and the declared X1 revision remain unchanged pending the
ADMF/MDF decisions explicitly required below.

### 7.1 Preserve capture timestamps across hunters

**Current code:** `internal/pkg/hunter/hunter.go`

- [x] In `convertPacket`, use `pkt.Metadata().Timestamp` when available.
- [x] In `ForwardPacketWithMetadata`, use the original packet metadata timestamp.
- [x] Define a fallback for synthetic packets without capture metadata and mark/log that fallback distinctly.
- [x] Verify processor conversion preserves the nanosecond value into X2/X3 attribute 9.

Tests:

- [x] Forwarded protobuf timestamps equal fixture capture timestamps.
- [ ] Delayed forwarding and reconnect buffering do not change them.
- [x] X2/X3 decoded timestamp attributes match the source capture time.

### 7.2 Repair X1 request-container handling

**Current code:** `internal/pkg/li/x1/server.go`, generated X1 schema types

- [x] Support the ETSI `X1Request` envelope as the primary format.
- [x] If legacy `requestContainer` remains supported, process every contained message, not only index zero.
- [x] Do not pass the complete container XML to a single-message router.
- [x] Preserve each message's concrete operation type and fields; the current generated base-message slice is insufficient on its own.
- [x] Return one ordered response per request and define whether processing continues after an individual error.
- [x] Reject truly nested containers explicitly.

Tests:

- [x] Single-message envelope succeeds.
- [x] Multi-message container executes every request in order.
- [x] Mixed success/error responses retain transaction IDs.
- [x] A nested container is rejected without affecting sibling messages.

### 7.3 Use ETSI-context-scoped sequence numbers

**Current code:** `internal/pkg/li/x2x3`, `internal/pkg/li/delivery/client.go`

**Status (2026-08-25): Implemented; MDF migration confirmation remains.**
The encoders share a bounded, fail-closed sequencer keyed by the complete ETSI
context. Counters are zero-based, X2/X3-independent, wrap at 32 bits, and are
cleared by XID deactivation. Destination fan-out continues to share one immutable
encoding. Restart policy is an in-memory reset to zero on new delivery connections
and is documented for operational agreement with the MDF.

ETSI TS 103 221-2 V1.10.1 clause 5.3.9 defines attribute 8 precisely. If the
attribute is used, its sequence starts at zero and increments once for each PDU
with the same `(XID, Domain ID, NFID, IPID, Correlation ID)` context. X2 and X3
maintain separate sequences for an otherwise identical context. The unsigned
32-bit value wraps to zero after its maximum value. See the
[official specification](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.10.01_60/ts_10322102v011001p.pdf).

The X2/X3 Domain ID conditional attribute is not the X1 `DId` used to identify
a delivery destination. Destination identity is not part of the sequence
context defined by clause 5.3.9. A PDU fanned out to several MDF destinations
therefore retains the same sequence attribute and serialized bytes.

The normative runtime behavior no longer requires a peer decision. Coordinate
deployment because existing MDFs may have adapted to lippycat's old global,
one-based counters. Restart behavior is not defined by TS 103 221-2 and still
requires an explicit operational policy agreed with the MDF.

- [x] Remove sequence ownership from the global X2/X3 encoder instances.
- [x] Replace `Client.NextSequence(xid, destinationDID)` with a sequencer keyed by PDU type plus `(XID, Domain ID, NFID, IPID, Correlation ID)`.
- [x] Begin every new context at zero, increment by one per PDU, and wrap naturally from `math.MaxUint32` to zero.
- [x] Maintain independent X2 and X3 sequences for the same remaining context fields.
- [x] Retain the existing architecture decision to enable attribute 8 and include exactly one occurrence in every applicable content PDU.
- [x] Assign the sequence before marshaling once; reuse that PDU unchanged when fanning it out to multiple MDF destinations.
- [x] Reset sequence state when its XID is deactivated. Destination removal alone does not reset it.
- [x] Define and document restart behavior: new process and delivery connections restart contexts at zero. TS 103 221-2 defines no reset signal, so MDF acceptance remains a rollout gate.
- [x] Bound the sequence map and fail closed when capacity is reached rather than evicting and silently resetting a live context.

Tests:

- [x] Every new ETSI context begins at zero.
- [x] Changing XID, Domain ID, NFID, IPID, or Correlation ID creates an independent sequence.
- [x] X2 and X3 have independent sequences for an otherwise identical context.
- [x] Two destination DIds receiving the same immutable PDU observe the same sequence value.
- [x] The counter wraps from `math.MaxUint32` to zero.
- [x] XID deactivation removes all of that task's sequence contexts; destination removal does not alter sequence state.
- [x] Deactivation/reset and restart behavior are deterministic.

### 7.4 Add X2/X3 keepalive exchange

**Status (post-hardening 2026-08-25): Implemented locally; socket-backed protocol
verification and coordinated MDF enablement remain open.** X2 and X3 use distinct
interface-scoped TLS pools for both content and keepalive traffic. Each connection
owns one zero-based keepalive sequence and outstanding-ACK set, making interface
association unambiguous. A timeout invalidates and reconnects only the affected
interface with capped jittered backoff. Production enablement remains gated on
the section 9 coordination decisions and the unchecked socket-backed tests below.

ETSI TS 103 221-2 V1.10.1 clause 6.2.4 requires POIs and MDFs to support
Keepalive and Keepalive Acknowledgement PDUs. When the TLS transport profile
enables the mechanism, the POI sends a Keepalive at least every `TIME_P1`
(default 60 seconds). The MDF acknowledges every Keepalive using the same
sequence number. If no acknowledgement is observed within `TIME_P2` (default
180 seconds), the POI disconnects, attempts to reconnect, and reports an error
through X1. The mechanism may be used independently on X2 and X3. See the
[official specification](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322102/01.10.01_60/ts_10322102v011001p.pdf).

The companion specifications are versioned independently: V1.10.1 is the
current TS 103 221-2 revision governing X2/X3 delivery, while V1.23.1 is the
current TS 103 221-1 revision governing X1 administration. The X1 revision
number does not supersede the X2/X3 keepalive requirements in Part 2.

Annex C defines X0 configuration independently for X2 and X3 using
`keepaliveEnabled`, `keepaliveTimeP1`, and `keepaliveTimeP2`; both timer values
have a minimum of one second when present. Until X0 configuration is supported,
provide equivalent local configuration with the normative defaults. This is a
time-based liveness rule, not a configurable count of missed ACKs.

- [x] Add independently configurable X2 and X3 keepalive enablement, `TIME_P1`, and `TIME_P2`, defaulting to 60 seconds and 180 seconds respectively and rejecting enabled timer values below one second.
- [x] Send a Keepalive PDU at least once during every `TIME_P1` interval while the applicable X2/X3 TLS connection is established; ordinary data traffic does not replace the required application-level Keepalive.
- [x] Encode Keepalive and Keepalive Acknowledgement PDUs as specified in clause 5.1: Version, PDU Type, and Header Length populated; all other mandatory header fields zero; exactly one Sequence Number attribute; no payload.
- [x] Maintain a zero-based 32-bit Keepalive sequence for each applicable X2/X3 connection/interface and require an acknowledgement to echo the corresponding Keepalive sequence number.
- [x] Run a framed inbound-PDU reader instead of discarding reads; validate Keepalive Acknowledgements and update liveness only for a valid outstanding sequence on the correct X2 or X3 interface.
- [x] If no valid Keepalive Acknowledgement has been observed within `TIME_P2`, close only the affected interface connection, enter its bounded reconnect path, and report the delivery fault through X1.
- [x] Serialize Keepalive and content writes on each TLS connection so frames cannot interleave, without placing control PDUs in the bounded X2/X3 content queues or changing content ordering.
- [x] Treat X2 and X3 keepalive state independently even when they share an MDF destination.
- [x] Use distinct X2 and X3 TLS connections so an ACK's interface is unambiguous.
- [x] Expose enabled state, configured `TIME_P1`/`TIME_P2`, last Keepalive sequence/time, last valid ACK time, ACK age, timeout count, and reconnect reason in per-interface destination stats.

Tests:

- [x] Defaults and minimum timer validation match clause 6.2.4 and Annex C.
- [ ] Keepalives are sent at least every `TIME_P1` on both idle and data-active connections.
- [x] A matching ACK is accepted only on its interface connection and updates liveness statistics. (Unit coverage; socket-backed connection-continuity coverage remains open.)
- [ ] A missing, malformed, stale, or wrong-sequence ACK does not satisfy liveness.
- [ ] Absence of a valid ACK for `TIME_P2` closes the affected connection, triggers bounded reconnect, and reports an X1 delivery error.
- [ ] X2 and X3 keepalive timers and sequences are independent.
- [ ] Concurrent content and Keepalive writes always decode as complete ordered PDUs.
- [ ] Data delivery continues in order around Keepalive control frames.

### 7.5 Align the X1 declared version

Coordinate one declared X1 revision across lippycat, the ADMF, and the MDF before changing defaults.

The current published X1 specification is
[ETSI TS 103 221-1 V1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf).
Treat V1.23.1 as the candidate target, subject to a schema and behavior gap
review; do not infer X1 support merely from implementing the independently
versioned TS 103 221-2 V1.10.1 wire protocol.

- [x] Compare the generated X1 schema, server behavior, client behavior, and fixtures against V1.23.1 and record every unsupported mandatory operation or field.
- [x] Select V1.23.1 only if that gap review passes or the unsupported surface is explicitly version-gated; never change only the declared version string. (The review did not pass: the bundled schema is V1.22.1, so the truthful default is V1.22.1.)
- [x] Update server/client defaults, tests, fixtures, and documentation together.
- [x] Optionally validate compatible inbound versions and return a precise error for unsupported revisions.
- [x] Include version negotiation/cutover guidance in release notes.

### 7.6 Protect X2/X3 correlation identity

- [x] Add an end-to-end regression test proving that X2 SIP and X3 RTP for the same call carry the same correlation identity expected by the MDF.
- [x] Cover multiple SSRCs, both media directions, re-INVITE, and call-ID reuse.
- [x] Document the correlation derivation as a wire-level compatibility invariant.

## 8. Phase 6 — State persistence and reconciliation completion

**Status (2026-08-25): Implemented.** LI lifecycle state can now be persisted to a
versioned, atomically replaced `0600` JSON file configured with `--li-state-file`.
Pending tasks are restored disarmed, active tasks require ADMF confirmation, expired
state remains disarmed, residual filter cleanup resumes before activation, and task
and destination reconciliation both preserve incomplete/empty-snapshot safeguards.

Current ADMF startup sync and periodic reconciliation already remove authoritative orphan tasks, guard incomplete/empty snapshots, and sweep orphan LI filters at startup. Preserve those behaviors.

Add local persistence only after lifecycle semantics above are stable:

- [x] Persist tasks, destinations, status, effective time bounds, activation generation, and cleanup-needed state.
- [x] Write atomically with versioned schema and restrictive file permissions.
- [x] Do not persist secrets that need not be stored.
- [x] Treat the ADMF as authoritative when a complete response is available.
- [x] Keep the existing protections against conversion errors and transient empty-task responses.
- [x] Reconcile destinations in both directions, with the same authoritative-snapshot safeguards used for tasks.
- [x] Restore pending tasks without arming them early.
- [x] Restore active tasks only after confirming time validity and ADMF authority.
- [x] Resume cleanup for residual filters recorded after partial failure.

Tests:

- [x] Restart restores bounded active and pending tasks correctly.
- [x] Expired tasks are not re-armed.
- [x] A complete ADMF snapshot removes local-only tasks and destinations.
- [x] Incomplete or transiently empty snapshots do not cause mass teardown.
- [x] Corrupt persistence fails closed with actionable diagnostics.

## 9. Cross-project decisions and rollout gates

The following require agreement with the ADMF/MDF implementations before deployment:

- [ ] Decide the missing/zero `EndTime` policy.
- [ ] Decide how to represent multiple mediation windows for one task and several DIDs.
- [ ] Agree the raw-IP X3 payload format and MDF decoding behavior.
- [ ] Follow the attribute-8 scope, zero initial value, separate X2/X3 streams, and wrap behavior mandated by ETSI TS 103 221-2 clause 5.3.9; agree only restart behavior and migration cutover with the MDF.
- [ ] Follow the X2/X3 Keepalive/ACK behavior and 60-second `TIME_P1` / 180-second `TIME_P2` defaults mandated by ETSI TS 103 221-2 clause 6.2.4; coordinate enablement, non-default timer configuration, X0 support, and rollout with the MDF.
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
- [ ] Delivery keepalive enabled state, `TIME_P1`/`TIME_P2`, last sequence/send/valid-ACK time, ACK age, timeout count, and reconnect reason per X2/X3 interface and destination.

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
