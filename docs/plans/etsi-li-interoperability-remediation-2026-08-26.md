# ETSI LI interoperability remediation

**Date:** 2026-08-26
**Baseline:** `b20d17c` (v0.10.1)
**Scope:** lippycat behavior at conforming ETSI X1 and X2/X3 interfaces

This plan hardens lippycat for interoperability with independently implemented
ADMF and MDF systems. It deliberately does not encode assumptions about any
particular peer, deployment, or product. Compatibility claims are based on the
published ETSI schemas and on behavior lippycat can validate locally.

The governing principles are:

1. A compatible declared revision must not cause an otherwise valid request to
   fail.
2. Accepting a revision must not mean silently accepting semantics lippycat
   cannot enforce.
3. Repeated administrative requests must be safe, deterministic, and atomic.
4. Optional transport behavior must remain independently configurable until it
   is verified with the connected peer.
5. Unsupported interception modes must fail during provisioning, never after a
   task has apparently activated.

## 1. X1 revision compatibility

### 1.1 Evidence and compatibility boundary

lippycat declares and bundles ETSI TS 103 221-1 V1.22.1. The X1 server
currently accepts only an absent version, V1.13.1, and V1.22.1.

The official ETSI schema tags were compared from
[`LI / schemas-definitions`](https://forge.etsi.org/rep/li/schemas-definitions)
for every published revision from V1.13.1 through V1.23.1.

| Revision transition | Relevant schema change | Compatibility with the V1.22.1 model |
|---|---|---|
| 1.13.1 -> 1.14.1 | Optional task-status extension | Compatible |
| 1.14.1 -> 1.15.1 | Optional traffic-policy references | Compatible if unsupported policy semantics fail closed |
| 1.15.1 -> 1.16.1 | Optional task/NE issue extensions | Compatible |
| 1.16.1 -> 1.17.1 | Service-access target identifier | Compatible if unsupported target types are rejected |
| 1.17.1 -> 1.18.1 | Version-only schema change | Compatible |
| 1.18.1 -> 1.19.1 | Optional configuration schema | Compatible for implemented X1 operations |
| 1.19.1 -> 1.20.1 | H323/IMPU/IMPI types moved to TS 103 280 | Wire-compatible with the bundled common types |
| 1.20.1 -> 1.21.1 | Changes confined to optional configuration/traffic-policy schemas | Compatible for implemented X1 operations |
| 1.21.1 -> 1.22.1 | Optional TCP/UDP port-list and VRF target identifiers | Compatible if unsupported target types are rejected |
| 1.22.1 -> 1.23.1 | Optional IRI-policy references added to task details | Not yet approved; model and behavior review required |

The namespace remains stable throughout the approved range, and the changes to
the core X1 schema through V1.22.1 are additive or wire-compatible. Therefore:

- **Accepted inbound range:** V1.13.1 through V1.22.1, inclusive.
- **Declared outbound/default revision:** V1.22.1.
- **Not yet accepted:** V1.23.1 and later.
- **Absent version:** retain current compatibility behavior, but treat it as an
  observable legacy condition.

This is a protocol-revision compatibility claim, not a claim that lippycat
implements every optional facility present in every revision. Feature support
is validated separately as described in section 2.

Primary ETSI references:

- [TS 103 221-1 V1.13.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.13.01_60/ts_10322101v011301p.pdf)
- [TS 103 221-1 V1.20.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.20.01_60/ts_10322101v012001p.pdf)
- [TS 103 221-1 V1.22.1 schemas](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.22.01_60/)
- [TS 103 221-1 V1.23.1](https://www.etsi.org/deliver/etsi_ts/103200_103299/10322101/01.23.01_60/ts_10322101v012301p.pdf)

### 1.2 Implementation

- [x] Replace the discrete revision allowlist with a parser for the exact forms
      `vMAJOR.MINOR.PATCH` and `MAJOR.MINOR.PATCH`.
- [x] Normalize accepted versions to a numeric revision before comparison.
- [x] Accept the inclusive range V1.13.1 through V1.22.1.
- [x] Continue accepting an absent version for backward compatibility and
      record it as `unspecified` in logs and metrics.
- [x] Reject malformed versions and revisions outside the approved range with
      error 101. Name the received revision and the supported range without
      exposing request contents.
- [x] Keep `DefaultProtocolVersion` as the sole source of the declared outbound
      revision.
- [x] Log a peer revision different from the declared revision once per peer and
      observed revision, or rate-limit the message. Do not log once per request.
- [x] Add counters for accepted exact, accepted compatible, absent, malformed,
      and unsupported revisions.
- [x] Document that the accepted range follows the bundled schema's verified
      compatibility window, not a general semantic-version rule.

### 1.3 Tests

- [x] Table-test both prefixed and unprefixed forms of every revision from
      V1.13.1 through V1.22.1.
- [x] Test boundary rejection below V1.13.1 and above V1.22.1.
- [x] Test malformed, incomplete, negative, whitespace-padded, and trailing-data
      versions.
- [x] Test the existing absent-version behavior explicitly.
- [x] Exercise every implemented inbound request type with at least the oldest
      and newest accepted revisions.
- [x] Assert that error responses identify the received revision and supported
      range.
- [x] Assert mismatch observability without per-request log amplification.

### 1.4 Future revision procedure

A future revision is not added merely because its XML unmarshals. Before
extending the range:

1. Diff the tagged ETSI X1 and referenced TS 103 280 schemas against the bundled
   revision.
2. Classify every new or changed field as presentation-only, safely ignorable,
   supported, or enforcement-affecting.
3. Add generated model support where required.
4. Add explicit fail-closed validation for unsupported enforcement-affecting
   fields.
5. Add schema-derived fixtures and handler tests.
6. Only then extend the accepted range and, separately, consider changing the
   declared default.

V1.23.1 specifically requires review of `listOfIRIPolicyReferences` and the
referenced generic-object behavior before acceptance.

## 2. Separate revision acceptance from capability acceptance

Go's XML decoder ignores unknown elements by default. That is useful for
additive schema compatibility but unsafe when an ignored element changes what
traffic may be intercepted or delivered. Revision acceptance must therefore be
followed by explicit capability validation.

- [x] Define a single capability-validation layer for `ActivateTask`,
      `ModifyTask`, destination operations, and supported generic-object
      references.
- [x] Reject target identifier choices that cannot be converted into an exact
      lippycat filter.
- [x] Reject delivery types or destination configurations that cannot produce
      the requested X2/X3 behavior.
- [x] Reject non-empty policy references whose semantics are not implemented;
      never acknowledge them and then ignore them.
- [x] Detect multiple populated members of XSD choice structures and reject the
      request rather than selecting one by implementation order.
- [x] Validate all targets before changing registry or filter state.
- [x] Return a precise X1 error that distinguishes invalid syntax, unsupported
      capability, missing destination, and conflicting task state.
- [x] Maintain a tested capability matrix mapping each accepted X1 element to
      `supported`, `rejected`, or `response-only` behavior.

Tests must include conforming documents that use optional fields introduced at
each revision boundary. The expected result may be success or an explicit
unsupported-capability error, but never silent omission.

### 2.1 Implementation status

Implemented on 2026-08-26:

- `internal/pkg/li/x1/capabilities.go` is the shared fail-closed validation
  layer for task and destination requests.
- Supported target choices are validated for an exact filter representation;
  known unsupported choices, policy references, service scoping, and
  enforcement-affecting extensions are rejected explicitly.
- Target, delivery-address, IP-address, and port XSD choices reject zero or
  multiple populated members where exactly one is required.
- Destination delivery declarations and requested task delivery are checked
  for compatible X2/X3 capabilities before activation or modification.
- Registry modification validates a complete prospective task before mutating
  live state, preventing partial updates on validation failure.
- Capability-matrix tests are in `internal/pkg/li/x1/capabilities_test.go`, and
  registry-level destination enforcement is covered by
  `internal/pkg/li/capability_validation_test.go`.

Verification:

```text
go test -race -tags 'all li' ./internal/pkg/li/...
```

The complete race-enabled LI suite passes. Schema-derived conforming document
fixtures for every individual revision boundary remain desirable as additional
coverage when authoritative fixtures are added to the repository.

## 3. Make task activation idempotent

Administrative systems retry after timeouts, reconnects, and uncertain
responses. `ActivateTask` must therefore be safe to repeat whether registry
state is in memory or restored from durable storage.

### 3.1 Canonical activation identity

Define a canonical task definition containing every enforcement-affecting
field:

- XID;
- target identifiers, normalized by type and value;
- delivery type;
- destination IDs;
- mediation start and end instants;
- implicit-deactivation behavior;
- supported policy or scoping fields when implemented.

Target and destination order is not semantically significant. Canonicalization
must sort them, reject or remove exact duplicates consistently, compare times by
instant, and deep-copy all slices before comparison or storage.

### 3.2 Behavior

- [x] Reasserting an equivalent `Active` task returns success without mutating
      registry, generation, filters, workers, counters, or persistence state.
- [x] Reasserting an equivalent `Pending` task returns success without changing
      its scheduled boundary.
- [x] Reasserting an XID with a different canonical definition returns a
      conflict and directs the requester to `ModifyTask`; do not silently apply
      partial changes.
- [x] Define explicit fail-closed results for `Suspended`, `Expiring`, `Failed`,
      and `Deactivated` states.
- [x] Keep the equivalence check and any state transition under the manager's
      lifecycle serialization.
- [x] Do not remove and reinstall filters for a no-op reassertion.
- [x] Preserve the existing atomic rollback path for genuine activation.

### 3.3 Tests

- [x] Equivalent active and pending reassertions return success.
- [x] Reordered targets and destinations are equivalent.
- [x] Differing target, destination, delivery type, start time, end time, or
      lifecycle option is a conflict.
- [x] No-op reassertion causes zero filter-pusher calls and no generation bump.
- [x] A conflicting reassertion leaves registry, filters, workers, and persisted
      state byte-for-byte equivalent to their prior logical state.
- [x] Concurrent duplicate activations converge on one activation with no race
      or duplicate enforcement.
- [x] Repeat the cases after state restoration.

Durable LI state must not be considered operationally safe until these tests
pass.

### 3.4 Implementation status

Implemented on 2026-08-26:

- Activation identity canonicalizes enforcement fields, orders and deduplicates
  targets and destinations, compares mediation times by instant, and owns copied
  slices.
- Equivalent Active and Pending retries return while holding lifecycle
  serialization, before generation, filter, worker, counter, or persistence
  mutation.
- Definition changes and retries in Suspended (including expiration cleanup),
  Failed, and Deactivated states fail closed and direct the ADMF to ModifyTask.
- Tests cover reordered and duplicate values, every definition field,
  concurrency, state restoration, filter calls, generations, persistence, and
  lifecycle-state conflicts.

Verification:

```text
go test -race -tags 'all,li' ./internal/pkg/li/...
```

## 4. X2/X3 correlation and raw packet delivery

SIP IRI and RTP CC correctly derive the same correlation identifier from the
SIP Call-ID when it is available. Preserve that invariant.

Raw IP CC requires a different communication model. One correlation identifier
per interception target collapses unrelated traffic into a single indefinite
communication, while emitting CC without a corresponding IRI context may be
unusable to a conforming downstream implementation.

- [ ] Keep raw-IP interception capability-gated until its session and IRI model
      is fully implemented.
- [ ] Reject any activation that would route traffic into an incomplete raw-IP
      delivery path.
- [ ] Do not infer that payload format alone selects the downstream ETSI handover
      container; that selection belongs to explicit destination capability and
      configuration.
- [ ] Before enabling raw-IP delivery, define stable bidirectional flow identity
      (normally normalized 5-tuple plus an explicit lifecycle policy), generate
      correlated IRI and CC, and specify timeout/reuse behavior.
- [ ] Test that distinct flows under one target receive distinct communication
      identities and that both directions of one flow correlate.
- [ ] Retain a regression test proving SIP X2 and X3 correlation remains shared.

## 5. X2/X3 keepalive interoperability

Keepalive support is optional operational behavior and peers may enable it
independently per interface. lippycat must not assume that every conforming MDF
uses or acknowledges keepalives unless required by the negotiated/configured
profile.

- [ ] Keep outbound X2 and X3 keepalive disabled by default.
- [ ] Allow each interface to be enabled and monitored independently.
- [ ] Document the required acknowledgement behavior and timeout consequences
      next to the flags.
- [ ] When enabled, validate acknowledgement type and sequence and expose sent,
      acknowledged, timed-out, disconnected, and reconnected counters.
- [ ] Treat unexpected inbound control PDUs as observable protocol events using
      bounded metrics or rate-limited logs; do not create log amplification.
- [ ] Decide separately whether to acknowledge an inbound Keepalive. If enabled,
      echo its sequence and test simultaneous bidirectional keepalive loops.
- [ ] Add socket-backed conformance tests with peers that acknowledge, ignore,
      delay, duplicate, and send malformed acknowledgements.

## 6. Repair the current LI test baseline

The race-enabled LI suite currently fails because
`TestServer_DefaultConfig` asserts the obsolete literal `v1.13.1` while
`DefaultProtocolVersion` is `v1.22.1`.

- [x] Change the test to assert `DefaultProtocolVersion`.
- [x] Audit comments, fixtures, examples, and docs that still describe V1.13.1
      as the default; retain V1.13.1 only where it intentionally tests backward
      compatibility.
- [x] Run `go test -tags "all li" -race ./internal/pkg/li/...` in an environment
      that permits local listeners.
- [x] Require the complete race-enabled LI suite to pass before marking this
      plan complete.

## 7. Carry-over verification

The following existing hardening work remains part of interoperability quality
because failures are externally visible even when both peers conform:

- [ ] Identify ownership of ambiguous legacy filters before removing them.
- [ ] Verify start-boundary promotion installs filters before processing matched
      packets and rolls back atomically on failure.
- [ ] Verify expiry stops packet processing, clears sequencing/reorder state,
      retries failed removal, and is idempotent with concurrent deactivation.
- [ ] Verify outage retries grow and cap under continuous enqueue without busy
      looping, and shutdown interrupts them.
- [ ] Verify saturated destination workers are isolated and drops are attributed
      to the correct destination/interface.
- [ ] Verify queued and reconnected delivery preserves capture timestamps.
- [ ] Complete race-enabled callback-replacement tests and matched/unmatched
      packet benchmarks.

## 8. Completion criteria

This plan is complete when:

1. X1 V1.13.1 through V1.22.1 are accepted through a parsed, tested compatibility
   range, while malformed and unreviewed revisions fail clearly.
2. Every enforcement-affecting optional field is either implemented or rejected
   explicitly.
3. Equivalent task activation is idempotent for live and restored state without
   touching filters.
4. Incomplete raw-IP delivery cannot be provisioned successfully.
5. Keepalive behavior is safe by default, independently configurable, and fully
   observable when enabled.
6. The full race-enabled LI suite passes, including socket-backed lifecycle and
   delivery cases.
