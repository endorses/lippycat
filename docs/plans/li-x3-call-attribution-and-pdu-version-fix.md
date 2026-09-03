# LI X3 Call Attribution, Finalization, and PDU Version Fix Plan

**Date:** 2026-09-03
**Status:** Proposed
**Priority:** Critical interception-integrity fix for the first release after v0.11.4

## Overview

Correct two independent LI defects present in v0.11.4:

1. RTP associated with a shared or reused media endpoint is currently assigned the
   insertion-first Call-ID while inheriting the union of filter IDs from every call
   on that endpoint. X3 can consequently deliver one call's media under another
   call's XID, correlation ID, and direction state. Eviction can also remove the
   only inheritance route and silently drop later content.
2. The ETSI TS 103 221-2 Version field is encoded as `05 00` (major 5, minor 0),
   but version value 5 is major 0, minor 5 and must be encoded in network byte
   order as `00 05`.

The X3 fix must establish one authoritative call attribution before inheriting
identity filters or creating correlation state. Ambiguous media must fail closed:
it may retain legitimate direct IP/CIDR matches, but it must not inherit identity
filters, carry a guessed Call-ID, or be delivered as content for an identity task.

Call finalization must also become a shared processor lifecycle boundary rather
than a PCAP-writer-only tombstone. Both PCAP and X3 must use the same atomic
admission decision, including delayed X3 reorder-buffer sends and operation when
per-call PCAP output is disabled.

All fixtures, logs, and test identities added by this work must be synthetic.

## Goals

- Attribute RTP to exactly one live call using packet endpoints and stable media
  flow evidence; never use insertion order or recency as an LI attribution guess.
- Ensure inherited filter IDs, stamped Call-ID, X2/X3 correlation ID, and media
  direction all originate from the same authoritative call.
- Fail closed when media ownership is unresolved or ambiguous without suppressing
  valid direct IP/CIDR filter matches.
- Prevent finalized-call content from being encoded, buffered, or delivered over
  X3, whether or not per-call PCAP output is enabled.
- Make PCAP and X3 observe one race-free call-finalization boundary.
- Preserve safe Call-ID reuse after the bounded tombstone lifetime without
  allowing delayed work from an older generation to affect a newer call.
- Add explicit counters and rate-limited structured diagnostics for ambiguity,
  missing attribution, and finalized-call suppression.
- Encode and validate ETSI TS 103 221-2 version 0.5 as `00 05` in X2, X3,
  keepalive, and keepalive-ack PDUs.

## Non-Goals

- Do not make `MostRecentCallIDForEndpoint` authoritative for LI. Recency is a UI
  presentation heuristic and cannot prove media ownership.
- Do not restore port-only RTP matching; exact IP:port endpoint matching remains
  required. Existing port-only fallbacks in alternate capture paths must not be
  allowed to stamp security-sensitive Call-ID or LI filter attribution.
- Do not inspect RTP payload bytes with SIP/IMSI/IMEI matchers.
- Do not merge distinct XIDs with AXRI or otherwise change the LI product model.
- Do not upgrade the package from TS 103 221-2 version value 5 to version value 6;
  adopting V1.10.1 is separate work.
- Do not expose raw target identities, Call-IDs, or media payloads in new metrics.

## Required Semantics

### Authoritative RTP ownership

For a classified RTP packet, construct candidate call sets from the exact source
and destination IP:port endpoints:

- If both endpoints have owners, intersect the sets. A call associated with both
  sides is stronger evidence than one associated with only a shared relay side.
- If only one endpoint has owners, use that set.
- If the resulting set contains exactly one live call, resolution succeeds.
- If it is empty, resolution is unresolved.
- If it contains more than one call, resolution is ambiguous.

Return an explicit resolution value containing status and, only on success, the
single Call-ID. Do not expose an ordered candidate slice as an attribution result.
Do not fall back to `callIDs[0]`, endpoint insertion order, or `endpointWinner`.

A bounded media-flow binding keyed by canonical bidirectional 5-tuple plus SSRC
may preserve ownership after unique resolution. Such a binding may only be
created from an unambiguous result. It must contain the call lifecycle generation,
be invalidated on call finalization, SDP reassociation, expiry, and capacity
eviction, and never override contradictory current endpoint evidence.

Ambiguous or unresolved RTP remains classifiable as RTP. It may carry direct
packet-level IP/CIDR filter IDs, but it must have no Call-ID and must not:

- inherit cached SIP/identity filter IDs;
- refresh every candidate call's recency;
- update LI media-direction or pinned-call state;
- generate Call-ID-based X3 correlation; or
- enter an identity-target X3 task through inherited selection.

### Filter and correlation provenance

Replace multi-call filter inheritance with inheritance from the one resolved
Call-ID. Preserve stable deduplication between direct packet-level IDs and that
call's cached IDs. Direct IP/CIDR matches remain valid independently of call
resolution.

Carry enough internal provenance to distinguish direct packet matches from
call-inherited matches at the LI boundary. Audit local tap, hunter-to-processor,
and processor-to-processor paths before choosing whether this requires protobuf
fields. If the provenance crosses a transport, update the protobuf contract and
generated code rather than reconstructing it heuristically downstream.

For identity-derived X3, require a resolved Call-ID whose inherited filter maps
to the task being delivered. Generate correlation and direction from that same
Call-ID. For a legitimate directly matched IP/CIDR task with no resolved call,
retain the existing SSRC fallback correlation rather than inventing a Call-ID.

### Shared finalization authority

Extract terminal call state from `PcapWriterManager` into a processor-owned,
concurrency-safe lifecycle registry. The registry must exist whenever VoIP has a
consumer requiring terminal semantics, especially LI, even when PCAP is disabled.
Preserve v0.11.4's bounded one-hour tombstone and capacity behavior unless tests
or configuration requirements justify a deliberate change.

Use an atomic admission/finalization protocol, not a check-then-act
`IsFinalized` call:

- Packet processing acquires an admission token tied to Call-ID and generation.
- Finalization atomically prevents new admissions and waits for admitted critical
  sections to finish before endpoint cleanup and sink finalization complete.
- The token covers the irreversible acceptance step for each sink without holding
  the lifecycle mutex across encoding, file I/O, network queues, or callbacks.
- Shutdown remains process lifecycle and must not create semantic call tombstones.
- Expired tombstones may admit a new generation, but tokens and delayed callbacks
  from an older generation must remain invalid.

The call completion monitor must drive this lifecycle independently of PCAP
configuration. Endpoint associations, filter cache entries, flow bindings, LI
direction state, pinned-call state, and call-specific reorder state must be
cleaned from the same once-only finalization event.

### Delayed X3 delivery

The current reorder buffer is keyed only by XID and destination and may call
`SendX3` after finalization. Make buffered entries call/generation-aware. Either
use call-aware buffers that can selectively discard finalized-call entries or
validate an immutable generation token immediately around the eventual `SendX3`
enqueue. Finalization must prevent an already-buffered old-generation PDU from
being sent after the boundary.

Do not increment the same suppression counter twice when initial admission and
delayed-send validation both reject the same packet. Define one terminal reason
and accounting owner for each discarded PDU.

### Observability

Add monotonic counters for at least:

- RTP ownership unresolved;
- RTP ownership ambiguous;
- identity-filter inheritance suppressed because ownership was not authoritative;
- X3 suppressed because its call was finalized or its generation became stale;
- X3 buffered entries discarded during call/task finalization.

Increment source-stage counters before packets leave the observable pipeline;
`liX3Skipped` alone cannot represent packets that never reach the LI manager.
Expose the LI counters alongside existing encoding statistics and use sampled or
rate-limited structured warnings. Log sanitized Call-IDs only where necessary;
for ambiguity prefer candidate count and endpoint/flow hashes over identities.

## Phase 0: Reproduce and Freeze the Failure

- [x] Add a synthetic regression fixture with calls A and B sharing one media
  endpoint while having distinct identity filter IDs and XIDs.
- [x] Prove the v0.11.4 behavior in a test: B media inherits A and B filter IDs,
  is stamped with A, and produces A's Call-ID correlation hash.
- [x] Add the eviction reproduction showing that removal of the selected call's
  endpoint/cache association causes later identity-selected media to disappear
  before LI accounting.
- [x] Add a finalized-call reproduction with PCAP enabled showing PCAP rejects the
  late packet while X3 still accepts it.
- [x] Add the same late-X3 reproduction with PCAP disabled to prove finalization
  enforcement cannot depend on `PcapWriterManager` existence.
- [x] Record existing relevant benchmarks and test behavior before refactoring;
  use assertions rather than production packet captures.

Phase 0 implementation note: Phase 1 had already landed when these historical
characterizations were added. The shared-endpoint tests therefore use an
explicitly test-only model of the relevant v0.11.4 (`92ed306a`) attribution and
cache-eviction operations. On eviction, the remaining call B still owns the
endpoint and reaches LI, while the evicted call A's identity task disappears
before LI accounting. The fixture does not incorrectly model the whole packet
as disappearing.

## Phase 1: Introduce Explicit RTP Resolution

- [x] Inventory every RTP ownership implementation, including
  `voip/processor/rtp_detector.go`, `voip/udp.go`, and
  `voip/udp_handler_hunter.go`, and identify which results can reach tap, hunter,
  sniff, offline, upstream, PCAP, or LI consumers.
- [x] Put authoritative media resolution behind one shared abstraction used by
  every path that can stamp a forwarded Call-ID or inherited filter ID; do not
  repair only the local/tap processor path.
- [x] Define a resolution type with `resolved`, `unresolved`, and `ambiguous`
  states plus a Call-ID populated only for `resolved`.
- [x] Add call-registry queries needed to snapshot endpoint owner sets and verify
  that candidates are still active without leaking mutable slices.
- [x] Implement exact-endpoint intersection/one-sided resolution and document its
  invariants and lock ordering.
- [x] If flow bindings are required, implement the bounded 5-tuple+SSRC binding
  table with generation, expiry, capacity limits, and lifecycle invalidation.
- [x] Change `voip/processor` RTP detection to return one authoritative Call-ID or
  an explicit non-resolved status; remove insertion-first stamping.
- [x] Remove or isolate port-only and first-owner fallbacks from every
  security-sensitive attribution path while preserving any explicitly
  non-authoritative detection/diagnostic behavior that still needs them.
- [x] Touch call recency only for the resolved call. Do not touch all candidates
  when ownership is ambiguous.
- [x] Update source adapters/interfaces to carry resolution status without
  re-deriving it from an empty or non-empty Call-ID.
- [x] Retain all-candidate APIs only for diagnostics that genuinely need them;
  mark them unsuitable for filtering, output attribution, and LI correlation.
- [x] Add unit tests for unique two-sided intersection, unique one-sided owner,
  empty result, shared-endpoint ambiguity, contradictory endpoints, call removal,
  endpoint reuse, and binding invalidation/capacity.
- [x] Replace tests that bless `callIDs[0]` with tests asserting explicit
  ambiguity or the uniquely resolved owner.

Phase 1 implementation note: flow bindings were not required for the initial
authoritative resolver. Exact current endpoint evidence is sufficient, while a
binding would require the generation and finalization contract introduced in
Phase 3. Legacy port-only and all-candidate helpers remain diagnostic only and
are not used by packet forwarding, Call-ID stamping, filtering, or LI paths.

## Phase 2: Make Filter Inheritance Fail Closed

- [x] Change `LocalSource` to load cached filter IDs only for the authoritative
  resolved Call-ID.
- [x] Remove multi-call unioning from packet selection; retain a helper that
  combines direct IDs with one call's inherited IDs in stable deduplicated order.
- [x] Preserve direct media-safe IP/CIDR matches for unresolved and ambiguous RTP.
- [x] Suppress identity inheritance for unresolved or ambiguous media and account
  for the suppression before dropping or forwarding the packet.
- [x] Audit the hunter, tap, local processor, upstream forwarding, and replay paths
  so all paths apply the same attribution semantics.
- [x] Add explicit direct-versus-inherited provenance to the internal envelope or
  protobuf contract if it must cross process boundaries; regenerate code using
  the repository's normal protobuf workflow.
- [x] Add tests proving no foreign filter union, no identity-task delivery on
  ambiguity, direct IP/CIDR delivery remains possible, and in-dialog SIP sticky
  selection is unchanged.
- [x] Add a B2BUA/shared-relay test demonstrating that legitimate correlated legs
  are not guessed to be the same call without authoritative evidence.

Phase 2 implementation note: local/tap inheritance now consumes the explicit
media-resolution result and can load cached identity filters from only its one
resolved Call-ID. Direct and inherited IDs are carried separately through the
internal envelope and protobuf transport while the legacy combined field remains
a stable, deduplicated compatibility union. Hunter media handling also evaluates
safe packet-level matches before rejecting unresolved or ambiguous attribution,
so direct IP/CIDR evidence survives without a guessed Call-ID. Offline replay
does not perform call-filter inheritance; upstream processors preserve the
originating provenance without re-attributing packets. The hunter retains the
stable direct IDs that selected each call, labels later signaling and uniquely
resolved media as inherited from that call, and owns the single enqueue for
accepted UDP packets so a provenance-free duplicate cannot escape alongside it.
The integrated B2BUA/shared-relay regression models two independently selected
legs advertising one relay endpoint and verifies that ambiguous media inherits
neither leg while an independent direct IP match remains deliverable.

## Phase 3: Centralize Call Finalization

- [x] Extract bounded tombstones, lifecycle generation, and admission semantics
  into a focused processor call-lifecycle component independent of PCAP output.
- [x] Define atomic `Admit`/release and `Finalize` behavior, including how
  finalization waits for accepted critical sections without holding locks through
  slow work.
- [x] Instantiate the lifecycle component when LI requires it even if per-call
  PCAP is disabled.
- [x] Make the call completion monitor run and finalize calls independently of
  `PcapWriterManager` availability.
- [x] Migrate PCAP writer creation/write admission to the shared lifecycle while
  preserving its v0.11.4 artifact immutability, collision-safe Call-ID reuse,
  telemetry, callbacks, and shutdown behavior.
- [x] Move endpoint/cache/flow-binding cleanup out of the PCAP-only callback and
  subscribe it to the shared once-only finalization event.
- [x] Ensure protocol completion, idle timeout, manual completion, capacity
  behavior, and shutdown map deliberately to shared lifecycle reasons.
- [x] Add lifecycle unit tests for idempotent finalization, completion before the
  first packet, TTL expiry, capacity pruning, generation-safe Call-ID reuse,
  simultaneous admit/finalize, callback re-entry, and shutdown.
- [x] Add race tests proving finalization and packet admission have a single
  winner and cannot deadlock or admit work after the boundary.

Phase 3 implementation note: processor-owned `CallLifecycleRegistry` now provides
bounded tombstones, monotonic generations, atomic admission tokens, conditional
generation finalization, ordered finalization subscribers, and non-semantic
shutdown draining. Per-call PCAP uses this registry for writer creation and packet
write admission; writer generations, generation-conditional handle finalization,
and exclusive file creation preserve finalized artifacts across Call-ID reuse. The
completion monitor owns terminal decisions even
without PCAP, maps call-registry completion reasons deliberately, and publishes one
shared cleanup event. LI-enabled processors therefore instantiate and run the
lifecycle monitor with an optional PCAP sink. Focused and full processor tests pass
with `all` and `all,li` tags, including the race-enabled lifecycle/PCAP suite.
Local/tap terminal signaling retains call endpoint and filter attribution through
the configured trailing-media grace period; the shared lifecycle finalization
subscriber performs the once-only call cleanup. Standalone VoIP processing without
a shared lifecycle coordinator preserves immediate terminal cleanup.

## Phase 4: Guard X3 Encoding and Delayed Delivery

- [ ] Require authoritative attribution before an inherited identity filter may
  invoke X3 processing; validate the task/filter provenance defensively at the LI
  boundary.
- [ ] Acquire a lifecycle admission token before direction mutation, X3 encoding,
  sequence allocation, and reorder-buffer insertion for call-correlated media.
- [ ] Count finalization/stale-generation rejection without incrementing
  `liX3Encoded`.
- [ ] Make reorder entries and keys call/generation-aware, or validate immutable
  generation tokens in the delayed callback immediately around `SendX3`.
- [ ] Selectively discard buffered entries for a finalized call without affecting
  other calls sharing an XID or destination.
- [ ] Clear call-specific media-direction, pinned-call, flow-binding, and reorder
  state on finalization; preserve XID-wide task-deactivation cleanup.
- [ ] Ensure task deactivation remains a strict boundary and composes safely with
  call finalization without duplicate sends, counters, or cleanup.
- [ ] Add an LI integration test proving calls A/B on a shared endpoint can never
  deliver B media under A's XID or FNV correlation ID.
- [ ] Add tests proving finalized RTP is neither encoded nor queued with PCAP on
  and off, and that the finalization-suppression counter increments once.
- [ ] Add an out-of-order/buffered test that finalizes the call before the reorder
  timer fires and asserts zero `SendX3` calls afterward.
- [ ] Add a generation-reuse test proving an old buffered callback cannot become
  valid when the same Call-ID is admitted after tombstone expiry.
- [ ] Add direction tests proving state is keyed to the authoritative call and is
  cleared at finalization.

## Phase 5: Correct the ETSI PDU Version

- [ ] Change the canonical constants to `VersionMajor = 0`, `VersionMinor = 5`,
  and packed `Version = 0x0005`; keep all PDU constructors on this one value.
- [ ] Correct comments that describe major version 5, including package guidance
  that calls the protocol version 5.0.
- [ ] Preserve the decoder's compatibility rule deliberately: accept supported
  major version 0 minor revisions according to policy, and reject major versions
  greater than 0.
- [ ] Add independent literal assertions for packed value `0x0005` and wire bytes
  `00 05`; do not derive the expected bytes from the constants under test.
- [ ] Add a decode test accepting `00 05` and a regression test rejecting the
  legacy broken `05 00` value with `ErrInvalidVersion`.
- [ ] Adjust the existing unsupported-major test so it remains meaningful when
  the supported major is zero.
- [ ] Change the first two bytes of all five golden vectors under
  `internal/pkg/li/x2x3/testdata/x2x3/` from `0500` to `0005`.
- [ ] Decode all X2, X3, keepalive, and keepalive-ack golden variants in
  table-driven coverage, in addition to exact encoder byte comparisons.
- [ ] Reconcile stale X2/X3 header/version descriptions in `internal/pkg/li` and
  operator documentation with the actual 40-byte, uint32-length layout rather
  than updating only the version label in an otherwise incorrect diagram.

## Phase 6: Observability and Documentation

- [ ] Add source-level RTP resolution and inheritance-suppression counters with
  bounded-cardinality labels.
- [ ] Extend LI encoding statistics with finalized/stale-generation and buffered
  discard counters; document exactly where each counter is incremented.
- [ ] Add rate-limited structured warnings for ambiguous ownership and rejected
  late X3 content using sanitized or hashed identifiers.
- [ ] Expose new telemetry through existing status surfaces without breaking
  non-LI builds or build-tag variants.
- [ ] Document fail-closed ambiguity behavior, direct IP/CIDR behavior, lifecycle
  retention, and operator signals in LI and troubleshooting documentation.
- [ ] Update architecture guidance so future code cannot use all-owner endpoint
  lists or recency winners for security-sensitive attribution.

## Phase 7: Verification and Release Gate

- [ ] Run `gofmt` on every changed Go file before staging.
- [ ] Run focused call-registry, VoIP processor, local-source, PCAP lifecycle, LI
  manager, X2/X3 encoder, reorder-buffer, and processor integration tests.
- [ ] Run `GOCACHE=/tmp/lippycat-go-cache go test -tags li ./internal/pkg/li/... ./internal/pkg/processor/...`.
- [ ] Run race-enabled tests for call registry, VoIP processor, processor
  lifecycle, LI delivery, and X3 reorder/finalization paths.
- [ ] Run the repository's supported `processor`, `tap`, and `all` tagged suites
  to catch build-tag drift; request sandbox escalation if required.
- [ ] Verify non-LI builds compile and retain no LI runtime dependency.
- [ ] Verify all five corrected wire vectors start with `0005` and exact golden
  comparisons pass.
- [ ] Verify no test or benchmark relies on insertion order, `callIDs[0]`, or
  multi-call filter union for attribution.
- [ ] Verify PCAP and X3 make the same admission decision across the finalization
  race, including PCAP-disabled LI operation.
- [ ] Review counter behavior under rejection at source, initial LI admission,
  reorder discard, task deactivation, and delivery failure to prevent gaps or
  double counting.
- [ ] Update this plan by checking only tasks verified complete, then commit code,
  tests, documentation, generated artifacts, golden vectors, and this plan
  together as required by the project workflow.

## Acceptance Criteria

- [ ] Shared or reused endpoints cannot cause media from one call to inherit
  another call's identity filter, XID, Call-ID correlation, or direction state.
- [ ] Ambiguous media fails closed for identity interception while valid direct
  IP/CIDR interception remains functional and observable.
- [ ] Eviction, completion, or timeout cannot create silent identity-selected X3
  loss without a corresponding source or LI suppression counter.
- [ ] No X3 PDU is encoded, buffered, or delivered after its call finalization
  boundary, including delayed reorder callbacks and PCAP-disabled deployments.
- [ ] PCAP and X3 share an atomic lifecycle authority and cannot disagree because
  of pipeline ordering or a check-then-act race.
- [ ] Call-ID reuse creates a new generation without allowing old buffered work to
  enter it or mutate finalized PCAP artifacts.
- [ ] X2, X3, keepalive, and keepalive-ack headers encode version bytes `00 05`;
  the legacy `05 00` encoding is rejected by regression coverage.
- [ ] Tagged and race-enabled verification passes with no regressions in SIP
  sticky selection, B2BUA handling, PCAP finalization, or LI task deactivation.
