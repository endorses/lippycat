# RTP Filter Hot-Path Regression Fix Plan

**Date:** 2026-09-01
**Status:** Proposed
**Priority:** Release blocker for v0.11.3

## Overview

Restore local VoIP capture headroom by preventing classified RTP and RTCP media
packets from entering SIP, IMSI, and IMEI identity matching. Preserve every
filter that can legitimately match a media packet, especially protocol-neutral
IP filters, and preserve sticky call selection and LI filter-ID correlation.

The current local-source VoIP branch falls back to
`ApplicationFilter.MatchPacketWithIDs` whenever the VoIP processor did not
evaluate a filter. That is correct for SIP requiring a direct verdict, but RTP
results intentionally do not carry such a verdict. The fallback consequently
treats binary media as possible SIP, performs repeated header parsing and
identity matching, and creates substantial allocation and garbage-collection
pressure without producing useful SIP identity matches.

All fixtures, benchmark inputs, logs, documentation, and recorded results in
this work must be synthetic. Do not include deployment names, customer
identifiers, intercepted identities, production addresses, or captured
production payloads.

## Goals

- Classified RTP and RTCP must never invoke SIP, IMSI, or IMEI identity parsing.
- Packet-level filters that apply to media packets must retain their direct
  matches and filter IDs.
- Media packets associated with selected calls must retain inherited filter IDs.
- Packets with both direct and inherited matches must carry the required stable,
  deduplicated ID set for downstream LI correlation.
- SIP INVITE, in-dialog SIP, and reassembled SIP must retain their current direct
  verdict reuse, sticky selection, cache lifecycle, and correlation behavior.
- Remove avoidable allocation from SIP header extraction after the media-path
  bypass is proven independently.
- Provide a representative mixed VoIP benchmark that would catch the regression
  before release.

## Non-Goals

- Do not redesign the complete filter type system or protobuf contracts.
- Do not change detector classification rules, RTP call association, or TCP
  reassembly architecture unless a failing correctness test proves it necessary.
- Do not bypass protocol-neutral filters merely because a packet is classified
  as media.
- Do not weaken LI authorization or attach filter IDs that are neither a direct
  packet match nor inherited from an associated selected call.
- Do not use a wall-clock packets-per-second assertion as the sole CI gate;
  shared runners make strict timing thresholds unreliable.

## Required Semantics

### Match scopes

The application filter must distinguish these operations:

- **Full match:** protocol-neutral filters plus applicable protocol matchers,
  including SIP/IMSI/IMEI identity matching only when classification is SIP or
  an allocation-free start-line check establishes a credible SIP message. This
  remains the behavior for SIP and ordinary non-VoIP traffic, but RTP and RTCP
  passed by any caller must still skip SIP identity parsing.
- **Packet-level media match:** only filters that can match a classified media
  packet without interpreting its payload as SIP. With the current filter model,
  this includes IP filters and the existing no-filter policy. Adding another
  media-applicable filter later must require an explicit update to this scope.

Expose the media-safe operation through the narrow interface used by
`LocalSource`, for example `MatchPacketLevelWithIDs`. Implement both public
operations over one internal locked matching routine with an explicit scope so
filter-presence checks, locking, no-filter policy, and ID collection cannot drift.
Do not implement the fix by returning `matched=false` for every RTP packet.

The no-filter policy applies only when no filter family is configured at all. If
identity filters exist but no packet-level filter matches a media packet, its
direct result is false; call inheritance may still select it. The packet-level
scope must not mistake "no filters in this scope" for "no filters configured."

### Filter-ID composition

For a selected VoIP packet, compose IDs as the stable, deduplicated union of:

1. IDs that directly match the current packet; then
2. IDs inherited from every associated selected Call-ID.

An ID appearing in both inputs must occur once. Empty IDs must not be emitted.
The union must contain no IDs from unrelated calls. Use one helper for the UDP
VoIP and reassembled TCP SIP branches so their correlation behavior stays
consistent.

Selection remains based on the existing `SelectionPolicy` inputs:

- `DirectMatch` reflects the applicable direct match scope for the packet.
- `PreviouslySelected` reflects whether associated calls supplied inherited IDs.
- A selected packet receives the composed ID set; an unselected packet is
  dropped as before.

### Classification boundary

Use the VoIP processor result metadata already available in `LocalSource`:

- `Metadata.Rtp != nil` selects packet-level media matching and forbids SIP
  identity extraction.
- `Metadata.Sip != nil` uses the reusable VoIP filter verdict when present;
  otherwise it uses the full matcher.
- If a packet is marked VoIP but has neither metadata type, use a bounded,
  allocation-free credible-SIP start-line check before permitting full SIP
  identity matching. Otherwise use only the media-safe scope.

Keep this fallback conservative: an unclassified binary payload must not regain
the expensive RTP behavior, while a credible SIP message must not lose identity
filtering.

## Phase 0: Reproduce and Lock Down Existing Semantics

### Tests and baselines

- [x] Add synthetic packet builders for SIP, RTP, RTCP, and unclassified UDP
      payloads without real identities or addresses.
- [x] Add an instrumented application-filter test double that records full-match
      and packet-level-match calls independently.
- [x] Add a failing local-source regression test proving classified RTP currently
      reaches the full matcher when no reusable verdict is present.
- [x] Add baseline tests for matching and non-matching SIP, in-dialog SIP
      inheritance, RTP call inheritance, direct IP matching, no-filter policy,
      and unselected media drops.
- [x] Record current mixed-workload `ns/op`, `B/op`, and `allocs/op` before making
      the fix. Keep the recorded environment generic and exclude hostnames and
      network details.

Phase 0 baseline (`all` build tag, Linux/amd64, Go 1.26.3, CPU-only filter,
benchmark concurrency 32, 13th-generation Intel Core i9 class CPU):

```text
BenchmarkApplicationFilterMixedVoIP  4,449-4,879 ns/op  2,259 B/op  52 allocs/op
```

The synthetic workload contains 80 percent RTP, 10 percent RTCP, 10 percent
SIP, and 400 identity filters split evenly across SIP user, phone number, IMSI,
and IMEI families. Packet construction and detector-classification validation
run outside the timed region.

### Acceptance criteria

- [x] The test suite demonstrates the unwanted full-match call for classified
      media without relying only on timing evidence.
- [x] Existing selection and correlation behavior is captured before refactoring.

## Phase 1: Add a Media-Safe Filter Scope

### Implementation

- [ ] Extend the `source.ApplicationFilter` contract with a with-IDs operation
      for packet-level media matching.
- [ ] Add the corresponding method to `hunter.ApplicationFilter` and update test
      doubles and adapters at compile time.
- [ ] Refactor `MatchPacketWithIDs` and the new method onto one internal matching
      implementation with an explicit scope under a single read lock.
- [ ] Replace the current boolean VoIP gate in both `MatchPacket` and
      `MatchPacketWithIDs` with a SIP-specific classification gate so callers
      outside `LocalSource` also cannot send classified RTP or RTCP into identity
      extraction.
- [ ] Audit batch, GPU, IMSI/IMEI, authorization, contact, and payload helper call
      sites; every route to SIP header extraction must be dominated by the same
      SIP-specific gate or accept already-validated SIP input by contract.
- [ ] In packet-level scope, evaluate IP filters and the existing no-filter
      policy without invoking VoIP detection, application payload extraction,
      SIP header parsing, identity matchers, or their allocation-heavy setup.
- [ ] Document which filter families belong to packet-level scope and require
      future media-applicable filter types to opt in explicitly.
- [ ] Keep full-match behavior and filter-ID order compatible for existing
      callers.

### Tests

- [ ] Verify packet-level matching returns matching IPv4 and IPv6 filter IDs and
      correctly reports misses using only synthetic addresses generated by test
      helpers.
- [ ] Verify packet-level matching preserves no-filter allow/deny behavior.
- [ ] Verify hundreds of SIP, phone-number, IMSI, and IMEI filters do not cause
      SIP extraction or identity matching in packet-level scope.
- [ ] Verify the existing full boolean and with-IDs APIs also skip identity
      extraction when directly given classified RTP or RTCP by non-local-source
      callers.
- [ ] Verify full matching still evaluates every currently supported filter
      family and returns the same ordered IDs as before.
- [ ] Run package race tests covering concurrent full and packet-level matching
      while filters are read or updated through supported lifecycle paths.

### Acceptance criteria

- [ ] A classified media packet can obtain every applicable direct ID without
      examining its payload as SIP.
- [ ] The new scope introduces no second lock lifecycle or duplicated policy
      implementation.

## Phase 2: Route Local VoIP Packets by Classification

### Implementation

- [ ] Replace the single `matchFilter` closure in the local batching worker with
      an explicit decision that distinguishes reusable SIP verdicts, full SIP
      matching, and packet-level media matching.
- [ ] Route `Metadata.Rtp != nil` packets exclusively through the packet-level
      matcher before applying call-cache inheritance and selection policy.
- [ ] Preserve the VoIP processor's already-evaluated SIP verdict so a SIP packet
      is never matched twice.
- [ ] Add the bounded allocation-free credible-SIP fallback for VoIP results with
      neither SIP nor RTP metadata, with focused false-positive and false-negative
      tests.
- [ ] Extract stable ID deduplication/union into a small helper and use it when
      composing direct and inherited IDs.
- [ ] Apply the same ID-composition helper to the reassembled TCP SIP injection
      branch without changing its filtering scope or `AfterProcess` lifecycle.
- [ ] Cache only direct SIP filter IDs against a Call-ID; do not write inherited
      unions back into the cache, which could spread IDs between unrelated call
      associations over time.
- [ ] Keep batch normalization, forwarding counters, drop counters, and cache
      expiry behavior unchanged.

### Tests

- [ ] Verify classified RTP and RTCP make zero full-match calls and exactly one
      packet-level-match call when a filter is configured.
- [ ] Verify RTP with only identity filters is selected solely through associated
      call inheritance and is otherwise dropped without SIP parsing.
- [ ] Verify RTP with a direct IP-filter match retains that direct ID even when no
      call is selected.
- [ ] Verify RTP with both direct and inherited matches carries the stable,
      deduplicated union in direct-then-inherited order.
- [ ] Verify multiple associated call legs contribute only their own cached IDs,
      with duplicates removed and no unrelated cache entries included.
- [ ] Verify SIP direct matches populate the Call-ID cache, later in-dialog SIP
      inherits selection, and an already-evaluated VoIP verdict is not repeated.
- [ ] Verify reassembled TCP SIP uses the same direct-plus-inherited composition
      and invokes `AfterProcess` exactly once on forward, drop, and normalization
      error paths.
- [ ] Verify unclassified credible SIP uses the full matcher while arbitrary
      binary payload uses only packet-level matching.
- [ ] Run the local-source tests with the race detector to cover multiple flow
      workers sharing the application filter and call cache.

### Acceptance criteria

- [ ] No classified RTP or RTCP packet reaches SIP identity extraction.
- [ ] Direct packet-level matches, sticky call selection, and downstream filter
      IDs remain correct for every tested combination.
- [ ] SIP filtering and lifecycle behavior are unchanged.

## Phase 3: Make SIP Header Extraction Allocation-Light

Land this phase separately from the media bypass so its benefit and correctness
can be reviewed independently.

### Implementation

- [ ] Replace `bytes.Split` line materialization with an index-based scan that
      accepts the existing supported line endings and stops at the header/body
      boundary.
- [ ] Replace repeated `bytes.ToUpper` calls with an allocation-free
      case-insensitive byte-prefix helper local to the filtering package, or move
      an existing helper to a neutral package only if doing so avoids an import
      cycle and remains narrowly scoped.
- [ ] Parse the request-line tokens with indexes rather than `bytes.Fields`, while
      preserving response handling and malformed-line behavior.
- [ ] Extract SIP headers once per match operation and pass the parsed view to
      identity, URI, authorization, and contact matching helpers that need it.
- [ ] Remove or correct the current zero-allocation comment only after benchmarks
      establish the actual allocation count.
- [ ] Avoid pooling payload-backed header views; their ownership is limited to the
      packet match and pooling would create retention and reset risks.

### Tests and fuzzing

- [ ] Preserve coverage for long and compact header names, mixed casing, request
      URIs, responses, supported line endings, empty headers, malformed lines,
      and header/body termination.
- [ ] Add equivalence tests comparing the old parser behavior captured as test
      cases with the new scanner for all identity-bearing headers.
- [ ] Add fuzz seeds containing binary data, truncated lines, repeated headers,
      unusual casing, and oversized synthetic headers; assert no panic and
      bounded scanning.
- [ ] Add focused parser benchmarks with `ReportAllocs` for representative SIP,
      minimal SIP, no-match text, and binary media payloads.

### Acceptance criteria

- [ ] Header extraction introduces no per-line case-conversion or line-slice
      allocations.
- [ ] Identity matching results remain byte-for-byte compatible for valid SIP
      fixtures.
- [ ] Parser work is bounded by the supplied payload and retains no packet data
      after the match returns.

## Phase 4: Regression Benchmark and Validation

### Benchmarks

- [ ] Add a LocalSource-oriented mixed VoIP benchmark with at least 85 percent
      RTP, at least 500 synthetic identity filters, selected and unselected calls,
      direct packet-level matches, and representative SIP control traffic.
- [ ] Report `ns/op`, `B/op`, `allocs/op`, packets processed per second, and the
      number of full versus packet-level matcher invocations.
- [ ] Add a structural allocation assertion for the classified RTP filtering
      operation using `testing.AllocsPerRun`; keep timing measurements informative
      rather than brittle CI pass/fail thresholds.
- [ ] Record before-and-after results on the same generic test environment and
      explain which parts of the end-to-end capture pipeline the benchmark does
      and does not exercise.
- [ ] Capture bounded CPU and allocation profiles using only generated traffic;
      verify that SIP header extraction is absent from classified RTP samples.

### Validation

- [ ] Run `gofmt` on every changed Go file before staging.
- [ ] Run targeted tests for `internal/pkg/hunter`,
      `internal/pkg/processor/source`, and `internal/pkg/voip/processor`.
- [ ] Run race tests for the filter and local-source packages.
- [ ] Run the tagged suites relevant to tap, processor, hunter, and LI builds.
- [ ] Verify tap and processor variants compile and non-LI variants still exclude
      LI-only code.
- [ ] Search the final diff for deployment identifiers, customer data,
      production addresses, and captured identities before staging.
- [ ] Update operator or release documentation to state that v0.11.3 removes the
      RTP-to-SIP matcher regression without promising a fixed throughput gain.

### Acceptance criteria

- [ ] The mixed workload performs full matching only for SIP or a credible
      unclassified SIP fallback, never for classified RTP or RTCP.
- [ ] Classified media filtering meets the recorded allocation ceiling and shows
      a material end-to-end improvement over the baseline.
- [ ] All direct, inherited, union, and no-match filter-ID cases pass under the
      race detector.
- [ ] Full tagged validation and specialized builds pass before v0.11.3 is
      released.

## Recommended Delivery Order

- [x] Phase 0: reproduce the regression and freeze selection semantics.
- [ ] Phase 1: introduce the media-safe matching contract.
- [ ] Phase 2: route local packets correctly and unify ID composition.
- [ ] Phase 3: optimize real SIP parsing independently.
- [ ] Phase 4: benchmark, validate, document, and release.

## Principal Risks

- Skipping IP filters together with SIP identity filters on media packets.
- Losing inherited LI filter IDs when a different direct filter also matches.
- Caching a direct-plus-inherited union and contaminating later call correlation.
- Trusting `isVoIPPacket` as a SIP predicate even though it intentionally includes
  RTP and RTCP.
- Re-running SIP filters after the VoIP processor already supplied a verdict.
- Divergent behavior between UDP VoIP and reassembled TCP SIP paths.
- A permissive unclassified-payload fallback reintroducing binary media parsing.
- Parser optimization changing compact-header, request-line, or malformed-input
  behavior.
- Benchmarks measuring only detector improvements rather than the LocalSource
  application-filter path that caused the regression.
