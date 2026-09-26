# X3 accepted-product permits and call draining

This is the accepted logical contract for the lifecycle work in
[phase 6](../plans/li-x3-and-filter-storage-encryption.md#6-implement-durable-x3-admission-post-call-delivery-and-revocation).
It follows the logical identities, control schemas and lock ordering in
[the encrypted-storage contract](li-encrypted-storage.md). It selects no physical
journal layout. The production integration now implements exact accepted-product
permits, incarnation-specific reorder draining, durable call closure and gated
historical replay. The focused tests exercise those boundaries; they do not
constitute qualification of the whole storage implementation.
The main plan remains the authority for implementation and qualification status.

The identity foundation now gives every processor call generation a random UUID,
retains its numeric stale-callback generation, and carries the UUID through
admission, finalization and LI/reorder metadata. Persistent capture reserves a
one-use `AcceptedX3` before reorder admission. Memory-only finalization still
cancels queued X3 and discards reorder.

## Existing boundaries

`CallLifecycleRegistry.finalize` in
`internal/pkg/processor/call_lifecycle.go` rejects new admissions, waits for
ordinary `CallAdmission` references, and then invokes subscribers without its
mutex. Keeping an ordinary reference until a subscriber drains reorder would
deadlock. A packet/PCAP owner can also lend its reference to LI; LI must not release
that borrowed reference early.

`ReorderBuffer.DeliverEntryX3AfterCommit` in
`internal/pkg/li/delivery/reorder.go` copies PDU bytes, mutates streams and reserves
callback order while holding `rb.mu`. After unlocking it calls `afterCommit`, then
delivery callbacks. **`afterCommit` is an ownership-release hook, not acceptance
or durability evidence:** it also runs for stopped buffers, invalid input and
budget rejection. Duplicate buffered RTP sequence slots are another nonacceptance
case. Detached batches remain charged and callback-owned even though
`DiscardCall`, `DiscardCount` and `Buffered` cannot see them.

The memory-only producer callback in `internal/pkg/processor/processor_li.go`
re-acquires task and live-call admission before sending a reordered PDU. The
persistent callback in `processor_li_persistent.go` instead consumes the accepted
product's exact permit, without re-entering Manager or ordinary call admission.

`delivery.Client.PrepareX3` reserves client/journal capacity before reorder,
`SendAcceptedX3` transfers accepted ownership to persistence, and `CloseCapture`
waits for prior accepted publication before recording closure. These operations
remain distinct from transport acknowledgement and actual policy revocation.

## Identity and immutable input

A call key is `(state incarnation, call UUID, local call generation)`. Call-ID
remains immutable diagnostic/protocol metadata and must match the recorded key,
but never substitutes for the UUID. A delivery copy further binds journal UUID,
interface X3, XID/task generation, DID/destination identity hash, original
admission/capture/deadline timestamps, provenance and exact encoded PDU bytes.
Administrative destination revision and destination identity hash remain distinct.

Compute the positive absolute X3 deadline once from original local admission
before candidate reservation/fan-out. A reorder gap, handoff, retry, call closure
or restart cannot recompute it from the current clock. Capture time remains
diagnostic and cannot extend the deadline.

Use the contract's closed provenance union. Call-attributed RTP has a nonzero
call UUID/generation. Directly IP-selected RTP without a Call-ID uses the explicit
`non_call/rtp` observation identity and capture epoch; it must not obtain a fake
call key. Its task/destination revocation, expiry, ownership and shutdown rules
are otherwise the same. RADIUS remains a separate X2-only producer. Legacy
zero-valued metadata stays valid for existing memory-only APIs and is rejected
only when attempting the new durable X3 boundary.

Freeze encoded bytes once before fan-out. Each destination copy has distinct
immutable metadata and a separate permit/accounting identity, while a reference
count can share the frozen PDU allocation. Reserve all required memory before
cloning; an uncharged clone followed by a budget check is insufficient. Final
record/content identity is the contract's canonical digest, including the journal
record ID; the PDU bytes and metadata never change when that ID is assigned after
reorder. The permit binds the earlier exact copy through its opaque owner identity,
immutable input and admission ID, then binds exactly one resulting record ID.

The journal owner provides a nonblocking, nonwrapping admission-ID reservation
from an already durably reserved range. No filesystem operation occurs on the
producer/reorder path. An unavailable reservation rejects the new copy. Gaps are
allowed; IDs are never returned for reuse. This logical highwater interface does
not prescribe how the owner stores it. It lets a revocation plan cover accepted
copies which have not reached the persistence queue yet.

That admission ID belongs to the bounded owner/callback bookkeeping and the
existing control highwater contract; this proposal does not add a field to the
frozen journal product schema or alter its canonical content digest.

## Proposed API responsibilities

These signatures illustrate the boundaries; the private type names and package
placement can change during implementation. Existing memory-only entry points
retain their behavior.

```go
// Candidate has bounded reservations and immutable input, but no backlog authority.
func (o *AdmissionOwner) ReserveCandidate(input ProductInput) (*Candidate, error)

// releaseAdmission runs once, after the insertion decision and unlocking,
// before any synchronous delivery callback, on every success/failure path.
func (rb *ReorderBuffer) AdmitProduct(
    candidate *Candidate, ssrc uint32, sequence uint16,
    releaseAdmission func(),
) AdmissionResult

// Callback ownership is transferred through this opaque, unforgeable handle.
func (c *Client) AcceptProduct(product *AcceptedProduct) AdmissionResult

// The ticket fences callback ownership transfer, not disk or transport success.
func (rb *ReorderBuffer) DrainCall(key CallKey) (*DrainTicket, error)
func (t *DrainTicket) Wait(ctx context.Context) (DrainResult, error)

// The coordinator combines drain tickets, pending-write resolution and control commit.
func (o *LifecycleOwner) CloseCapture(key CallKey) (securestore.Outcome, error)
```

`AdmissionResult` is a closed result: accepted, duplicate-slot rejection, or
rejected with a fixed reason/error. Accepted means the caller transferred memory
ownership; it never means durable. It must not expose a second usable copy of the
permit. `DrainResult` counts handed-off and terminally resolved copies and exposes
a bounded persistence fence/highwater, not an unbounded list of payloads. A wait
context cancellation ends that wait only; it cannot reopen capture, cancel an
already accepted control operation or silently free someone else's payload.

Constructors and permit fields are private to the owner. Public accessors return
metadata values; writable slices, pointers to mutable targets, and replacement
metadata are not arguments to permit consumption. A repeated callback with the
same handle returns already-consumed and does not enqueue, free or count the copy
again. One-use applies to the first handoff attempt: an admission rejection is a
terminal resolution, not permission to retry the handle with fresh timestamps or
another destination. Normal journal/transport retry belongs to its new owner.

The capture grant fixes the packet identity and original bounded fan-out set.
It cannot accept additional packets, duplicate destination copies or a destination
added to a later task definition, even while an ordinary reference remains held.

## Successful acceptance and capture closure

Reserve candidate memory, its permit slot, required control capacity and an
admission identity while the exact task/call capture admission is valid. This
reservation has no backlog authority. Reorder then validates the stream slot,
capacity, immutable identity and current block/expiry state. Only successful
insertion or immediate ordered-delivery acceptance changes the candidate into an
`AcceptedProduct`. Rejection/duplicate releases reservations and reports one
terminal destination-copy outcome. In particular, `afterCommit` returning and a
producer's encoded counter cannot mint a permit.

The ordinary admission winner determines which capture work may finish:

| In-memory capture stage                            | New ordinary admission                | Existing packet-specific grant                                                                               | Backlog permit                                            |
| -------------------------------------------------- | ------------------------------------- | ------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------- |
| Open                                               | Allowed under normal task/call checks | May attempt its one product insertion per destination                                                        | Created only on actual accepted insertion                 |
| Admission closing, ordinary references draining    | Rejected                              | May finish its already admitted packet's insertion; cannot name another packet or mint another capture grant | Accepted copies join the closing frontier                 |
| Capture-closed frontier, subscribers/drain running | Rejected                              | All ordinary references have ended                                                                           | Existing exact permits may move through drain only        |
| Revoked/faulted/expired                            | Rejected                              | Cannot accept product                                                                                        | Cannot become claimable; resolves under its current owner |

The durable call schema still has only `open`, `capture_closed` and `revoked`.
Admission closing is an in-memory synchronization stage. The capture-closed
frontier is fixed after ordinary references drain, so no successful insertion can
appear behind the finalizer's drain fence. An ordinary reference authorizes a
bounded packet admission attempt; it is never itself transferable backlog
authority. Task/destination revocation wins over such an attempt regardless of
the call's normal-closing stage.

The processor releases its owned ordinary references through the unconditional
release callback after the insertion decision. A borrowed packet/PCAP reference
remains with the packet owner until all of its sinks finish. Delivery callbacks
must not wait for that borrowed reference or re-acquire live-call admission.

## Bounded ownership and exact accounting

| State                                       | Payload/metadata owner and charge                                                                                                                    | Allowed next action                                                                         |
| ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Encoded input / candidate                   | Producer transient allocation; per-copy candidate and reserved control/permit capacity                                                               | Successful acceptance or one rejection; no disk claim                                       |
| Accepted reorder or detached callback batch | Reorder permit slot, metadata, payload reference and stream/batch overhead remain charged                                                            | One client handoff, expiry or revocation resolution                                         |
| Journal/queue admission pending             | Client reserves queue item and journal pending capacity before publishing ownership transfer; it retains the same payload reference                  | Durable callback, definite failure, or uncertain/fault hold                                 |
| Durably stored / queue eligible             | Journal record/control indexes and optional memory queue item are separately charged; immutable record identity replaces the consumed handoff permit | Claim, retain on disk, expiry or revoke                                                     |
| Transport claimed                           | Claim owner keeps payload and queue charge until the write resolves                                                                                  | Success, retry with original identity/deadline, or classified terminal/uncertain resolution |
| Settled                                     | Single terminal owner records outcome and releases only its own charges                                                                              | No second callback/free/drop                                                                |

The transfer reserves the destination owner's charges before releasing the source
charges. Brief overlap must fit the declared transient budget; there is no
unaccounted interval and no payload clone hidden in a callback. Shared bytes are
charged once per physical allocation, while logical queue bytes, permit/index
metadata and final outcomes remain per destination copy. If a layout needs an
encryption/encoding copy, its bounded worker scratch reservation is additional.

No separate unbounded permit map is allowed. Live permit count is bounded by
the configured reorder packet/byte budget plus explicitly reserved handoff and
journal-pending capacity. Retained durable records use the journal's existing
product/control ceilings. Metadata/string clones, closure tickets, callback
batches, control dependencies and reverse indexes all consume those bounds.
Detached batches continue charging their permits until transfer/resolution;
removing a stream does not release their bytes. Repeated drain requests coalesce
onto one live ticket per exact closure instead of allocating unlimited barriers.
Implementation must measure the actual structure sizes and include their charges
in reservation estimates; the current 512-byte packet overhead is not proof that
an expanded durable permit fits unchanged.

Only one owner can win the terminal-state transition. Keep encoded counters per
source encoding, accepted counters per destination copy, and persistence/transport
outcomes distinct. A fan-out can accept one DID and reject another. Preserve the
existing RTP duplicate-slot rule, but report the rejected encoded destination
copy once; do not issue another permit merely because it contains different PDU
sequence bytes. Duplicate handle invocation is an API misuse, not a new packet
drop. Timer detach, drain, expiry, cancellation, persistence failure and shutdown
race through that same owner transition, preventing duplicate drops and release.

Retained durable backlog is not a drop. A locally completed TLS write cannot be
reported as known-unsent because cancellation raced its completion. Uncertain
transport remains separate from the durable control's `securestore.Outcome`.
Successfully committed storage with later cleanup error stays committed; no error
branch rolls metadata or authorization back to the old generation.

## Exact-call drain and durable closure

`DrainCall` validates an exact key and seals only the matching call streams against
new insertion. Under `rb.mu`, disarm each matching timer (including its timer
generation), detach buffered entries in their existing RTP order, and reserve a
position in `callbackTail`. The fence must also exist for an empty detached batch
when an earlier callback already owns entries. Release `rb.mu` before waiting or
calling delivery. A timer which detached first is ahead of the fence; a timer
which loses sees the removed stream or obsolete generation and cannot redeliver.

The existing callback chain orders whole batches within an XID/DID buffer.
Draining one call therefore waits for earlier committed batches from that buffer,
including another call if necessary, but neither flushes nor discards that other
call's streams. Later work is ordered after the reserved drain position. Other
destination buffers remain independent. The drain ticket completes after every
covered entry transferred to a journal-pending owner or reached a terminal result;
it does not wait for MDF connectivity or successful transport.

The closure coordinator waits for that frontier's persistence outcomes, then
commits `capture_closed` for the exact composite call-control identities. Required
call-control capacity was reserved before acceptance; the first product cannot
be acknowledged durable before its authenticated control dependency is durable.
An already scheduled `open` dependency may precede closure in the writer's order,
but can never overwrite a selected newer closed/revoked control or reopen the
in-memory capture gate. The closure fence includes its pending dependency work.

Disk callbacks never wait for the drain ticket, and a drain callback never waits
for a worker result while holding a lock that worker needs. Journal submission is
bounded and nonblocking; durable closure waits in the coordinator outside registry,
reorder, queue and index locks. Failure/uncertainty faults the affected owner and
preserves its obligations; it cannot reopen capture. Return that outcome through
an explicit fault-returning lifecycle hook rather than logging from a void-only
subscriber and claiming closure succeeded. Direction and pinned-call cleanup
still runs once for normal completion.

Recovered `open` and `capture_closed` controls describe historical capture-closed
incarnations. They never reconstruct `CallAdmission`. Phase 7 supplies replay
approval and current ADMF checks; a drain ticket, permit or completion marker
does not supply that approval.

## Revocation and callback races

Keep a small journal-local eligibility gate keyed by the exact state/task,
destination and call identities, with current fault/revocation state and immutable
authorization facts needed at claim. Capture openness and delivery eligibility
are separate: normal closure removes capture openness but permits unexpired
accepted delivery; revocation removes both. Automatic task expiry must affect
claim eligibility when its policy instant arrives even if its maintenance callback
has not yet completed the durable control. No Call-ID/UUID-only fallback exists.

The gate receives monotonic updates from the administrative bridge; data workers
and callbacks never call `Manager.AcquireTaskAdmission`, acquire `adminMu`, or
re-enter registry/filter mutation. New capture still uses ordinary manager
admission. Startup publishes no delivery eligibility until required authenticated
state recovery and ADMF reconciliation finish.

The existing `DurableRevoker.Prepare/Commit` split remains authoritative. Prepare
is pure: under administrative/admission ordering it snapshots exact identities,
covered record/admission highwaters and reserved control capacity. It does not
cancel or write. Ordinary capture references have drained before the administrative
write barrier proceeds, so all accepted old-generation permits are covered even
if their journal record IDs are allocated later. Scope revocation remains a
monotonic identity block, not a rule which permits a later ID to escape the cut.

After the complete plan is durably recorded in administrative state, Commit first
marks the affected journal gate blocked, detaches matching reorder/queue work and
transport cancel handles, then writes idempotent controls using the reserved
capacity. Publish the block before submitting control I/O. Invoke cancels and
resolve detached work after unlocking. Required control results and transport
owner resolution precede acknowledgement of the revocation boundary; interruption
or failed joining cannot be reported as an entirely successful boundary. A control
may already be committed even if joining/cleanup fails, so preserve its actual
outcome and keep the gate blocked. Stable recorded controls are retried at restart.

| Race                                         | Resolution                                                                                                                                                                                              |
| -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Reorder acceptance vs block                  | Short gate/acceptance ordering selects one winner. A losing candidate is rejected; an accepted permit remains covered by the block.                                                                     |
| Timer/drain detach vs revoke                 | Discard resolves entries still buffered; detached callbacks test the same exact blocked identity and resolve their own entries.                                                                         |
| Journal admission vs revoke                  | Pending ownership is registered before it is visible to the writer; covered admission highwater includes it. No capacity-release/requeue gap exists.                                                    |
| Successful persistence callback after revoke | Bytes may be durable, but callback cannot publish claimable state. Retain/reclaim under the recorded revocation obligation.                                                                             |
| Dial/write-lock wait vs revoke               | Revalidate exact gate/deadline at claim and at the final transport-write boundary. Register the write claim in the same short ordering as the gate check, allowing revocation to find/cancel the owner. |
| Write already started vs revoke              | Cancel and resolve the existing claim; retain success/uncertain-byte accounting. Never claim that already emitted bytes were recalled.                                                                  |
| Closure vs revoke                            | Revocation dominates; close cannot restore open/eligible state, and its fence resolves rejected covered entries as well as successful handoffs.                                                         |

Gate state is retained while any permit, record, callback, claim, closure obligation
or replay approval could refer to it. Capacity reservation precedes accepting a
new identity; garbage collection cannot free the only block while a delayed
callback still exists.

## Ordering and shutdown

Keep administrative ordering `adminMu → lifecycleMu → destinationMu → filter
mutation → store worker`. Journal workers never acquire an earlier boundary.
The administrative coordinator may wait for durable controls only because worker
completion has no callback path into it. Notifications needing administrative
work must be scheduled through a bounded control-owner path after callback
completion, not synchronously invoked while a worker is awaited.

Registry, reorder, gate, journal-index and queue locks cover short ownership
changes. Do no disk I/O, transport write, external callback or worker wait while
holding them. If reorder acceptance needs gate serialization, the only nested
order is reorder then gate; revocation releases the gate before acquiring any
reorder lock. Queue-map then queue ordering is permitted for short updates.
No callback may recursively drain/flush/stop/wait on its own reorder callback
chain. Coalesced drain tickets make repeated callers observers, not new workers.

This restriction also applies transitively: a reorder/journal callback must not
synchronously call call finalization whose subscriber would wait on that same
chain. It may request closure from a bounded lifecycle owner, then return; the
owner starts the wait after the callback relinquishes ownership.

Shutdown requires an explicit owner sequence because the call registry deliberately
emits no shutdown finalization events:

| Order | Owner action                                                                                                                                                                                                                                            |
| ----- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1     | Reject new capture/packet-source work and join producer goroutines; stop the completion monitor from scheduling competing normal closures. Keep LI authorization, filters and journals owned.                                                           |
| 2     | Close call admissions and wait ordinary packet/PCAP references. Establish exact closed frontiers for all accepted calls and the non-call RTP owner.                                                                                                     |
| 3     | Drain accepted reorder while task/destination eligibility and journal admission remain available. Concurrent withdrawal still dominates. Join detached callback chains and timers.                                                                      |
| 4     | Resolve pending persistence and required closure/control fences. Retain durable unsent work; classify rejection, expiry, revocation, volatile loss and uncertain writes separately. A timeout does not free live worker state or release its file lock. |
| 5     | Stop transport claims, cancel/join remaining writers, hold durable backlog, then stop LI administration and delivery owners in an order which still allows their required filter cleanup. Close journals/locks only after their workers stop.           |

This replaces the current order in `processor_lifecycle.go` / `stopLIManager`,
which stops LI/client owners before `ReorderBuffer.Stop/Wait`. It does not require
an MDF to reconnect at shutdown. Storage I/O which cannot be cancelled is still
owned until it resolves; an unresponsive filesystem cannot be converted into a
truthful durability acknowledgement by abandoning a goroutine.

## Implementation evidence required later

The implementation should prove each ownership boundary rather than create a
full Cartesian test matrix. Required cases include rejection/duplicate without
permit; payload/metadata mutation after acceptance; fan-out partial acceptance;
all timer/drain detach orderings; callback-owned entries invisible to discard;
old Call-ID reuse; a shared ordinary reference held for PCAP; revocation before
admission and after successful persistence; full data capacity with reserved
control commit; definite/uncertain control failure; claim blocked during dial and
write-lock wait; exact expiry while MDF/approval is unavailable; and shutdown from
reorder, detached, journal-pending, durable-held and transport-claimed states.

Assert one terminal outcome and one release per accepted destination copy, no
live-call re-admission during drain, no callbacks entering administrative ordering,
no unrelated-call stream changes, and no missing control on durable-product
recovery. Measure expanded allocation charges before accepting the memory budget.
These tests and physical-storage performance gates are future implementation
work, not claims made by this proposal.
