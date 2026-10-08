# LI correlation and replay recovery hardening

**Status:** implemented and verified; implementation commit reference pending recording

**Scope:** optional LI call-leg correlation in processor/tap, and replay-pressure
recovery in the VoIP media-admission bridge.

## Purpose

Prevent correlation storage from blocking unrelated LI delivery, prevent stale or
overloaded SDP-origin evidence from joining unrelated calls, and avoid prolonged
replay-pressure degradation caused by SIP messages that carry no media proof.
Correct SIP header parsing and response eligibility, clarify matching policies,
and make the non-LI build verification meaningful.

This plan is standalone. Examples and fixtures must use synthetic identities and
addresses. Do not include deployment names, intercepted identities, real packet
contents, key material, absolute operator paths, or private verification artifacts.

## Invariants

- [x] Preserve task authorization, destination admission, content policy,
      direction, payload, delivery expiry, journal replay authorization, and
      secure-storage identity, locking and cryptographic bounds.
- [x] Preserve the selected Correlation ID once reserved for a leg; persistence
      failure must not rewrite previously published PDUs or change replay bytes.
- [x] Keep every correlation method independently configurable and off by
      default; preserve the existing disabled path and processor/tap parity.
- [x] Preserve configured resource limits without evicting retained decisions to
      accommodate new legs. No new latency, throughput, CPU or memory acceptance
      targets are introduced; timing measurements are diagnostic observations.
- [x] Separate missing evidence from contradictory valid evidence. Conservative
      fallback must neither create authorization nor silently discard ambiguity.

## 1. Isolate correlation persistence from unrelated delivery

Primary files: `internal/pkg/li/call_correlation.go`,
`internal/pkg/li/call_correlation_store.go`,
`internal/pkg/li/delivery/client.go`, and processor LI integration files.

- [x] Replace storage operations under the correlator mutex with a bounded
      reservation/commit protocol. Reserve a pending decision under the mutex,
      create its immutable persistence input, release the mutex, perform storage
      I/O, and apply the outcome under the mutex.
- [x] Serialize writes through a store owner outside the correlator mutex.
      Track snapshot revisions so an older write or retry cannot overwrite newer
      membership, retention, finalization, or removal state.
- [x] Preserve Committed/adopted, NotCommitted/standalone, and
      Uncertain/pinned-adopted outcomes. Keep retries bounded and preserve
      authenticated reconciliation without reinitializing damaged storage.
- [x] Make same-Call-ID packets share the pending decision. Account for pending
      reservations within existing bounds; provide cancellation and shutdown
      behavior without holding processor or delivery locks while waiting.
- [x] Handle overlapping group joins explicitly: include pending task
      intersections, prevent speculative membership from authorizing another
      join, and reconcile failed reservations without widening committed groups.
      A storage backlog may conservatively leave new legs standalone; it must
      not stall retained decisions for unrelated Call-IDs.
- [x] Remove blocking publication callbacks from delivery admission critical
      sections. Record actual acceptance through bounded bookkeeping or invoke
      callbacks after releasing those locks. Preserve partial fan-out and
      uncertain journal acceptance semantics; do not silently lose activity or
      final-outcome accounting on overflow.
- [x] Move full-map expiry scans to maintenance. Keep local logical deadline
      checks in lookup paths so expired records, transactions and candidates
      cannot be used between maintenance ticks. Preserve terminal grace and
      capacity/blind-period behavior.
- [x] Coalesce persistence of activity and retention changes. Treat activity as
      persisted content, because it controls restore expiry. Define the durable
      retention boundary and crash behavior; do not simply stop saving activity.
      Skip unchanged snapshots and use revision-based dirty tracking.
- [x] Keep configured-store startup failures explicit: unavailable,
      uninitialized, corrupt, wrongly keyed or incorrectly bound storage must
      not silently become an empty or in-memory store. Document offline recovery
      and the existing explicit store-free operating mode, including loss of
      restart continuity. Do not add automatic downgrade on startup failure.
- [x] Add blocking-store regressions proving unrelated retained and standalone
      Call-IDs continue resolving and enqueueing while a write is held. Release
      the test barrier explicitly instead of inventing a timing threshold.
- [x] Add outcome, concurrent-group, revision ordering, reconciliation,
      publication, cancellation, expiry and shutdown regressions. Exercise real
      processor delivery and journal paths as well as the correlator API.

## 2. Bound SDP-origin history without affecting unrelated origins

Primary files: `internal/pkg/li/call_correlation_sdp.go`,
`internal/pkg/li/call_correlation_roles.go`, and correlator candidate indexes.

- [x] Make per-origin transaction exhaustion affect only that origin. Maintain
      global conservative disablement only for genuinely incomplete global
      history, such as exhaustion of the configured tracked-origin capacity.
- [x] Replace unbounded accumulation within suspended entries with bounded
      suspension state and renewal accounting. Preserve fixed deadlines,
      retransmission discrimination, continuous-use suspension and quiet release.
      Clearing a transaction set must not let retransmissions repeatedly renew
      suspension or create a release gap.
- [x] Bind each candidate's S evidence to the history observation that validated
      it, using an observation generation or equivalent explicit validity token.
      Expiry, suspension release, history reset or capacity loss must invalidate
      that evidence; a newly created observation must not revive an old candidate.
- [x] Keep offer and answer roles separate. Preserve pre-match reuse/conflict
      detection, weaker-rule fallback, and valid H/P precedence.
- [x] Add regressions for continuous static-origin use beyond the per-origin
      bound while an unrelated unique origin remains usable; retransmissions at
      suspension boundaries; and quiet release without stale-candidate revival.
- [x] Add a regression where a retained call candidate outlives its origin
      observation and a later unrelated call reuses the origin. It must not join
      the old call by S, including after maintenance and out-of-order capture.

## 3. Restrict initial-transaction decisions and parse Session-ID correctly

Primary files: `internal/pkg/li/call_correlation_cseq.go`,
`internal/pkg/li/call_correlation_headers.go`, and `call_correlation.go`.

- [x] Require an observed initial INVITE request, or retained evidence identifying
      its transaction, before a response can trigger first-time grouping.
      A response-only leg without that evidence reserves standalone. Document
      this conservative split instead of guessing from a CSeq value or response
      To-tag. Preserve valid CSeq zero and nonzero initial CSeq values.
- [x] Test responses to re-INVITEs, unknown transactions, response-first capture,
      restart after the blind horizon, forks, and retransmissions. Existing
      retained decisions must remain immutable.
- [x] Parse RFC 7989 Session-ID generic parameters with SIP parameter grammar,
      including quoted values and escaping. Ignore valid unknown parameters for
      UUID selection; retain local/request and remote/response interpretation.
- [x] Reject duplicate/conflicting remote parameters and contradictory valid
      configured evidence. Treat a syntactically unusable single header as no
      usable key rather than automatically as a trusted conflict. Specify
      repeated-header handling explicitly, preserving conservative ambiguity.
- [x] Test generic parameters, quoted separators, nil and malformed UUIDs,
      duplicate remote parameters, repeated headers, configured proprietary
      headers, and fallback to S/R1/R2 when no usable trusted key exists.

## 4. Recover media admission after replay pressure

Primary files: `internal/pkg/voip/admission/lifetime_proof.go`,
`bridge.go`, `derivation.go`, and replay-pressure tests.

- [x] Classify proof-bearing observations before marking replay evidence missing.
      INFO, OPTIONS and retransmissions that add no media proof must not poison
      an already healthy selected call. Preserve independent malformed/conflicting
      evidence and explicitly mismatched lifetime rejection.
- [x] Retain proof received during pressure as bounded, quarantined evidence
      attached to the authoritative active lifetime. It must not authorize media
      while pressure is active or be confused with cached pre-pressure proof.
- [x] At the pressure deadline, revalidate quarantined complete exchanges against
      the active lifetime, surviving exact guards and the configured replay-window
      contract. Promote only evidence that satisfies that contract; do not clear
      uncertainty solely because time passed.
- [x] Define an explicit bound for pressure-only recovery using existing replay,
      pending-proof and call-lifetime expiry contracts. If bounded quarantine
      cannot retain enough proof, keep that call unknown and expire its incomplete
      derivation through configured lifecycle limits; do not indefinitely block
      unrelated calls or declare missing proof valid. Document the fresh-proof
      recovery requirement and replay-window assumptions for this case.
- [x] Preserve endpoint ownership and safe retirement during recovery. Test healthy
      calls touched by proof-free messages, calls established during pressure,
      incomplete exchanges, quarantine exhaustion, repeated pressure, explicit
      old lifetimes and late replay. Cover both configured open and closed policy.
- [x] Replace tests that require proof-free messages to cause persistent missing
      evidence. Add UDP and fragmented-TCP parser/pipeline regressions and verify
      that pressure expiry restores unaffected calls without a re-INVITE.
- [x] Remove full-map expiry scans from every SIP message where practical, keeping
      local deadline checks and maintenance-based cleanup. Describe both paths
      accurately in operator documentation.

## 5. Resolve policy and verification details

- [x] Make an exact H match with no common active task terminal for new grouping,
      consistent with an ineligible parent reference. Do not bypass a known exact
      association by joining a different group through weaker evidence. Add a
      regression with distinct task contexts.
- [x] Retain symmetric R2 capture-time matching for reversed arrival and document
      that choice. Test both directions and exact window boundaries.
- [x] Document capture-time matching versus processor-time retention, delayed
      batches, missing-timestamp fallback, and response-only standalone behavior.
      Add deterministic tests for these boundaries; do not imply arbitrary
      forwarding delay tolerance.
- [x] Document number/URI normalization, including scheme and port removal,
      host case normalization and preserved user case. Keep this behavior distinct
      from configurable trusted-header exact matching.
- [x] Define unresolved persistence telemetry as an aggregate pending condition
      or an actual bounded count, matching the revised writer design. Update
      protobuf/status documentation and compatibility tests as necessary.
- [x] Make `verify-no-li` inspect an unstripped non-LI binary. Fail on build or
      symbol-inspection errors and check representative LI implementation symbols;
      verify the predicate also detects those symbols in a corresponding LI build.

## 6. Documentation, validation and completion

- [x] Update LI deployment and configuration documentation, media-admission
      recovery documentation, processor/tap documentation, and affected manual
      chapters. Translate changed manual text in every configured language.
- [x] Use synthetic fixtures throughout. Keep status and logs aggregate; review
      new errors and diagnostics for identities, header values and key material.
- [x] Run focused regression tests during each change, then relevant LI and
      admission race suites, full `all` and `all li` tests, and `go vet`.
- [x] Build the supported role variants, including processor/tap with LI and the
      corrected non-LI exclusion check. Run `make manual-check` and `make manual`.
- [x] Run `make test-ebpf` with the required privileges before closing the
      admission portion; obtain permission for tests outside the sandbox.
- [x] Confirm that matching changes affect only correlation decisions and IDs,
      while task admission, payloads, destinations and durable replay remain
      unchanged. Verify storage-failure and restart limitations against the final
      documentation.
- [ ] Format changed files, record verification evidence and material limitations,
      check off only completed tasks, and commit implementation and plan updates.

## References

SIP transaction and parameter grammar: RFC 3261. Session-ID syntax and UUID
semantics: RFC 7989. Use these specifications for parser behavior; do not infer
initial transaction identity from a fixed CSeq value.

## Completion evidence

All implementation and verification tasks above are complete; the final commit
recording task remains pending. The bounded closure
review found one defect in the new deferred path: packets arriving behind a
pending write were not updating final-response and SDP role observations. The
primary repair observes those packets before queue admission, preserving evidence
also when the queue rejects publication. Accepted/rejected final-response and
delayed-offer/ACK regressions passed under the race detector. The integrated
review found no additional material issue; closure outcome is **CLOSED**.

| Area | Evidence |
| --- | --- |
| Persistence and delivery | Blocking-store barriers with Committed, NotCommitted and Uncertain outcomes; one real batch delivers retained and unrelated TLS products before releasing storage; journal admission, ordering, queue limits, cancellation, shutdown, dirty revisions and unchanged-snapshot checks |
| Authorization and continuity | Actual deferred task revocation and replaced-lifetime RTP rejection; original admission timestamp retained; authorized late BYE X2 keeps its retained ID; existing encoder/payload/destination and restart/outcome tests |
| SDP and headers | Static-origin per-entry exhaustion, unrelated usable origins, observation-generation expiry/reset/quiet-release tests, offer/answer roles, generic parameter parsing, malformed-header fallback and trusted-conflict regressions |
| Matching boundaries | Unknown responses stay standalone; CSeq zero requests remain valid; ineligible H is terminal; R2 both directions and exact window boundaries; missing timestamps and delayed batches use documented clock behavior |
| Replay recovery | Full admission/VoIP race suites, UDP and fragmented TCP open/closed pipeline checks, healthy proof-free messages, reliable PRACK and delayed ACK exchanges, exact guards, explicit lifetimes, incomplete/exhausted/expired quarantine and fixed pressure deadlines |
| Status and build exclusion | Additive aggregate protobuf fields 24–26 and JSON/mapper tests; unstripped LI-positive/non-LI-negative verifier, including build and symbol-inspection failure propagation |
| Full compatibility | Full `go test -json -tags all ./...` and `go test -json -tags 'all li' ./...` covered 117 and 119 tested packages. Concurrent execution initially collided on fixed integration ports; sequential `./test` reruns passed for both tag sets. Every tested package passed across these runs |
| Final affected race checks | `go test -race -json -tags 'all li' ./internal/pkg/li ./internal/pkg/li/delivery ./internal/pkg/processor ./internal/pkg/statusclient` and `go test -race -json -tags all ./internal/pkg/voip/admission ./internal/pkg/voip` passed |
| Privileged kernel and commands | `make test-ebpf` passed in the disposable privileged container; kernel admission, integration, and tap/hunter command tests passed. The optional measurement experiment was not requested and remained skipped |
| Builds and static checks | `make binaries processor-li tap-li verify-no-li` passed; final processor/tap LI builds and exclusion checks repeated after the evidence repair; scoped LI/processor/VoIP/status/command `go vet` passed; changed Go files formatted and diff checks clean |
| Manuals | `make manual-check` and `make manual` passed for every configured language; German and Catalan catalogs each contain 5579/5579 translated current messages |

### Explicit recovery and resource policies

A per-origin exact-history bound quarantines only that origin. Once distinctness
cannot be retained, release requires an entire observation TTL without traffic;
retransmissions also extend this overload quiet period. Ordinary suspension below
the bound still discriminates retransmissions and follows fixed renewal periods.
Candidate generation tokens prevent either release mode from reviving old evidence.

Deferred publication is bounded by `max_candidates` packets and 32 MiB of
accounted packet/task input. Additional pending-leg packets are rejected without
changing the reserved ID; unrelated new joins may instead reserve standalone.
Storage completion cannot be forcibly interrupted through the snapshot API.
Cancellation suppresses queued publication and releases waiters; shutdown joins
the storage owner outside decision/admission locks. Activity is coalesced and
persisted at maintenance commits; crash restoration uses the last committed
retention boundary, not every most recent live packet.

Replay quarantine is charged to the existing selected-derivation limits and has
a fixed `replay_window + pending_ttl` lifetime from its first pressure evidence.
Complete retained exchanges are revalidated before promotion. Incomplete,
exhausted or expired proof remains unknown until fresh complete proof or normal
lifecycle retirement; expiry never invents valid evidence. Configured replay-window
assumptions and independent uncertainty still apply.

Configured storage authentication failures remain explicit startup failures.
Store-free operation remains an explicit operator choice with reduced restart
continuity. No automatic reset, empty-store replacement, or in-memory downgrade
was added. Correlation remains best effort and independently disabled by default.
