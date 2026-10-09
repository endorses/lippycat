# Replay admission and LI delivery reliability implementation plan

**Status:** implemented, committed and verified locally and in GitHub.
**Date:** 2026-10-09

## Objective

Prevent replay evidence received during a retirement's protection window from
becoming authoritative after quarantine expires. Keep healthy calls unaffected
by proof-free SIP retransmissions, and complete eligible exchanges whose messages
cross a replay-pressure deadline. Prevent optional LI correlation persistence
from indefinitely delaying or discarding a leg's delivery, and prevent it from
indefinitely blocking processor shutdown. Execute LI regressions and scan LI
implementations in CI while retaining non-LI coverage.

This plan stands on its own. Use synthetic protocol messages, invented identities
and reserved example addresses in fixtures and documentation. Exclude subscriber
information, deployment details, private captures, operational logs, credentials,
key material, absolute operator paths and private verification artifacts.

## Scope and acceptance

| Area | Required behavior |
| --- | --- |
| Retirement freshness | Evidence observed within an unrecorded retirement's protected window never supplies proof for a later lifetime of that Call-ID, including after the window ends. |
| Proof-free retransmissions | A bodyless ACK or late bodyless provisional for the retained transaction does not introduce a new media-proof obligation. |
| Exchange across a pressure deadline | An eligible quarantined request can complete with its exact post-deadline response; rejected evidence remains rejected. |
| Pending correlation | A wait deadline or deferred-queue pressure selects and pins the reserved group ID as uncertain, releasing delivery without correlation-induced packet loss. |
| Storage ownership | Late outcomes cannot change a released ID or overwrite newer state; only one owner may write or close the store. |
| Shutdown | Correlation maintenance and close obey a shared shutdown budget without releasing resources beneath an active writer. |
| CI coverage | LI tests execute with race detection, and security/vulnerability scans cover both LI and non-LI implementations. |

The correlation delivery guarantee concerns loss introduced by correlation.
It does not override authorization, content restrictions, product expiry, caller
cancellation or independent downstream delivery failures. A caller's bounded
return does not imply that an underlying filesystem operation was cancelled.

## Invariants and exclusions

- [x] Preserve explicit session/generation binding, exact dialog and transaction
      checks, offer/answer confirmation, independent uncertainty and endpoint
      ownership. Replay-window expiry does not create missing proof.
- [x] Preserve admission opt-in behavior, open/closed policies, enforce/shadow
      modes, hunter/tap parity and default non-admission capture behavior.
- [x] Preserve task authorization, administrative incarnation and generation,
      destinations, content policy, direction, payload, original admission time,
      product expiry, journal replay authorization and encoded replay bytes.
- [x] Preserve an ID once its decision is released for delivery; persistence
      completion, retry, cancellation and queue pressure cannot change that ID.
- [x] Preserve configured count/byte limits, authenticated storage, exclusive
      file locking, cryptographic usage accounting and durable revision ordering.
- [x] Keep matching methods independently configurable and disabled by default.
      Do not change trusted-header matching, matching precedence, SDP-origin
      heuristics or response eligibility as part of this work.
- [x] Keep unreadable, corrupt, uninitialized, wrongly keyed or incorrectly bound
      configured storage as an explicit startup failure. Store-free operation
      remains an explicit operator choice; do not add automatic downgrade.
- [x] Leave activity persistence, restore expiry, active-call lifetime and
      terminal grace unchanged. Do not add snapshot batching, append-only storage
      or timestamp rounding as part of this scope.
- [x] Do not introduce latency, throughput, CPU, RSS, restart or soak acceptance
      targets. Duration tests verify configured deadlines, not benchmark gates.

## 1. Retain deterministic counterexamples

Primary locations: `internal/pkg/voip/admission/`, `internal/pkg/mediaadmission/`,
`internal/pkg/pipeline/`, `internal/pkg/li/`, `internal/pkg/processor/`, and
`internal/pkg/li/delivery/`.

- [x] Add permanent regressions for an unrecorded retired lifetime whose request
      and answer arrive during pressure, then attempt promotion after expiry.
      Include surviving exact guards and explicitly bound old-lifetime evidence.
- [x] Add genuine-call fixtures for an exchange completed during pressure and
      one crossing its deadline. State which recovery is permitted when identity
      history is complete and which requires fresh proof after history loss.
- [x] Add retained-transaction fixtures for late bodyless provisionals and ACK
      retransmissions, plus negative cases for changed SDP, delayed-offer ACK
      answers, reliable provisionals and malformed/conflicting headers.
- [x] Add blocking-store barriers for the initial adopting packet, subsequent
      SIP/RTP, queue-pressure release, maintenance I/O and real processor shutdown.
      Exercise Committed, NotCommitted and Uncertain late outcomes.
- [x] Use controllable clocks/deadlines and explicit barriers where practical.
      Assert delivery and shutdown complete while the store is still blocked,
      then release the barrier and verify safe completion and cleanup. Do not
      remove the tests after reproducing the problem or leave test writers stuck.

## 2. Preserve observation-time replay rejection

Primary files: `internal/pkg/voip/admission/lifetime_proof.go`,
`replay_recovery.go`, `bridge.go`, and replay-budget accounting in
`internal/pkg/mediaadmission/`.

- [x] Define observation eligibility using the bridge's monotonic retirement
      deadline and authoritative lifetime, independently of packet timestamps.
      Keep identical evidence newly observed after protection expires as the
      documented finite-window boundary; explicit old lifetimes remain rejected.
- [x] Design a bounded exact record of retirement identities for failed guard
      insertions. Account count, bytes, entry overhead, expiry and shutdown within
      the existing aggregate replay-resource contract. If capacity is partitioned
      or reserved, define that allocation explicitly; do not introduce an
      uncharged second guard pool or evict unexpired guards to make room.
- [x] Mark observations associated with those protected retired identities as
      ineligible when received. Keep that rejection attached to the observation
      or derivation after its identity record expires. Checking identity expiry
      only at promotion time is insufficient.
- [x] When the necessary retirement history cannot be retained, invalidate and
      discard affected pressure quarantine instead of promoting indistinguishable
      evidence. Use a bounded pressure-generation or equivalent validity marker
      so history loss does not require an unbounded list of rejected messages.
- [x] Preserve invalidation across repeated retirement failures, extended blocks,
      delayed metadata consumption, cleanup and subsequent pressure intervals.
      Released capacity or a newer pressure generation must not revive evidence
      invalidated by an earlier loss of history.
- [x] Release quarantine reservations safely. Preserve independently healthy
      retained proof and unrelated uncertainty; invalidation must not install
      endpoint ownership or erase independent obligations.
- [x] Recover a genuine exchange completed during pressure only if its eligibility
      can be established. After conservative quarantine invalidation, require a
      fresh complete eligible exchange and document this recovery cost.
- [x] Test count and byte exhaustion, exact deadline boundaries, multiple
      observation domains, repeated pressure, lifetime replacement and eventual
      resource reclamation under open/closed and enforce/shadow configurations.

## 3. Classify retransmissions and complete eligible cross-deadline exchanges

Primary files: `internal/pkg/voip/admission/replay_recovery.go`, `derivation.go`,
`bridge.go`, and parser/pipeline integration tests.

- [x] Align new-proof classification with retained derivation semantics.
      Recognize a bodyless ACK to an already answered INVITE and a late bodyless
      provisional for its retained transaction without introducing missing proof.
- [x] Bind exclusions to the authoritative lifetime, exact dialog, CSeq and
      applicable SIP transaction relationship. Preserve ACK branch semantics;
      do not exclude a message solely because its method or response code matches.
- [x] Preserve proof-bearing SDP changes, delayed-offer answers, reliable-answer
      obligations, malformed evidence and contradictory valid headers. A
      proof-free exclusion must not become an ambiguity-clearing shortcut.
- [x] Allow an eligible quarantined request and its exact post-deadline response
      to be evaluated together through normal confirmation rules. Keep incomplete
      eligible proof available for that evaluation within existing pending and
      quarantine limits; do not clear the only recovery marker prematurely.
- [x] Enforce observation-time rejection from section 2 before combining pools.
      If history loss invalidated the request, a later response cannot make it
      eligible; recovery then requires a fresh complete exchange.
- [x] Transfer proof and resource reservations without duplicate ownership or
      silent loss. Preserve other incomplete exchanges, endpoint retirement and
      configured grace while completing the eligible exchange.
- [x] Cover INVITE, UPDATE and applicable reliable/delayed-offer sequences,
      retransmissions, forks, response-first capture and boundary orderings through
      the real SIP parser and UDP/fragmented TCP paths. Verify both call state and
      endpoint attribution in enforce/shadow and open/closed modes.

## 4. Bound logical correlation waits without losing delivery

Primary files: `internal/pkg/li/call_correlation.go`,
`call_correlation_config.go`, `call_correlation_store.go`,
`internal/pkg/processor/processor_li.go`, `processor_li_persistent.go`,
`processor_li_correlation.go`, and process/tap LI configuration adapters.

- [x] Add explicit positive `wait_timeout` and `shutdown_timeout` durations under
      `processor.li.correlation` and `tap.li.correlation`, including shared defaults,
      normalization, validation and YAML/environment bindings. Select and document
      defaults as operational policy during implementation, not performance gates.
      Follow the established LI CLI contract when adding bindings.
- [x] Keep these durations separate from MDF socket-send timeout, delivery-queue
      shutdown timeout, decision horizon, terminal grace and X3 maximum age.
      None of those existing values describes a pending correlation-store wait.
- [x] Give every pending adoption one fixed logical wait deadline from reservation;
      additional packets must not renew it. Cover initial synchronous adoption,
      existing synchronous waiters and `ResolveAsync`, including caller cancellation.
- [x] Route persistence through one bounded serialized owner outside decision and
      delivery locks. Keep physical write ownership independent of caller waiting;
      do not create one writer or timer goroutine per waiting packet.
- [x] On deadline expiry or deferred count/byte pressure, atomically release the
      reserved group ID as uncertain. Drain retained eligible products and route
      the triggering and subsequent packets through the same selected ID instead
      of returning a correlation-capacity error that drops their product.
- [x] Implement exactly-once release and existing per-leg ordering across writer
      completion, timeout, pressure, cancellation and shutdown races. Preserve
      original admission timestamps and recheck current authorization and expiry
      at the established delivery boundary; never renew product lifetime.
- [x] Fence late completion with reservation tokens and snapshot revisions.
      NotCommitted may select standalone only before logical release; once released,
      keep the selected group ID, retain dirty current state and count uncertainty.
      A stale completion cannot mutate a replacement lifetime or newer decision.
- [x] Keep exclusive storage ownership until physical I/O ends. Reconcile and retry
      the latest required snapshot only afterward; never launch a competing retry,
      reopen the store or overwrite newer state with the stalled snapshot.
- [x] Preserve conservative unrelated-leg progress and task intersections. Pending
      or uncertain membership must not authorize speculative joins, widen a group
      or evict retained decisions to accommodate backlog.
- [x] Keep the existing durability limitation explicit: an uncertain adoption that
      never became durable may lose restart continuity. Do not claim a timeout
      creates a durable commit or silently initialize damaged storage.
- [x] Add aggregate deadline/pressure diagnostics and rate-limited warning logs,
      distinguishing logical timeout from physical write uncertainty and existing
      deferred rejection. Update protobuf, generated bindings and status adapters
      additively; expose no identities, addresses, SIP values or payloads.
- [x] Test timeout and pressure before/after publication, every late outcome,
      concurrent packet arrival, cancelled waiters, failed re-admission, journal
      acceptance and X3 reorder paths. Prove stable IDs, exactly-once handoff,
      unchanged expiry, newer-revision retention and unrelated delivery progress.

## 5. Bound correlation shutdown across maintenance and store close

Primary files: `internal/pkg/li/call_correlation.go`,
`call_correlation_store.go`, `internal/pkg/processor/processor_li_correlation.go`,
`processor_li.go` and `processor_lifecycle.go`.

- [x] Introduce a context/deadline-aware correlation stop/close contract and use one
      shared correlation shutdown budget for maintenance, pending decisions and
      close. Do not restart that budget separately for each join or cleanup step.
- [x] Stop accepting new correlation work and scheduling maintenance promptly.
      Remove unconditional maintenance-worker joins that can wait inside Save or
      Reconcile before the bounded close path can execute.
- [x] Resolve pending eligible handoffs under the selected-ID and delivery shutdown
      rules, then prevent callbacks from publishing into stopped components. Keep
      packet cancellation and ordinary downstream shutdown accounting intact.
- [x] Make the store owner responsible for eventual close after its active I/O ends.
      A deadline bounds the processor's wait, not the I/O operation itself. Retain
      the file lock, descriptors, keyring and cryptographic usage ledger until the
      active writer can no longer touch them; prevent competing reopen or retry.
- [x] On budget exhaustion, report unresolved persistence at warning/status level
      and continue shutdown of independent processor resources. Do not claim all
      worker resources were released while an operation remains active.
- [x] Ensure repeated stop/close calls are safe and eventual cleanup occurs exactly
      once. Fence late callbacks and preserve authenticated restart reconciliation
      without empty-store replacement or automatic persistence downgrade.
- [x] Test real processor shutdown while adoption and maintenance writes are held.
      Advance the configured shutdown deadline, verify independent shutdown and
      retained store ownership, then release I/O and assert safe eventual cleanup.
      Include late write failure, repeated close and store-lock contention.

## 6. Execute LI tests and scan both build configurations in CI

Primary files: `.github/workflows/ci.yml`, `.github/workflows/security.yml`,
`scripts/check-build-matrix.sh`, and relevant LI test helpers.

- [x] Keep the existing `all` unit job and add execution of the `all li` test suites
      with race detection. Compilation with `-run '^$'` remains a build-partition
      check and must not be counted as regression-test execution.
- [x] Exercise the permanent correlation, delivery, processor and shutdown tests in
      the LI job, including the delivery lifecycle test. Fix synchronization where
      a retained regression is flaky; do not hide races with retries or sleeps.
- [x] Run gosec and govulncheck for both `all` and `all,li`, using correct tag syntax
      for each tool. Keep vulnerability failures actionable and preserve existing
      scan policy; do not suppress newly reachable findings to make CI green.
- [x] Give scan outputs distinct names per configuration, including SARIF files
      and upload categories, so jobs do not overwrite results. Preserve required
      security-event permissions and appropriate pull-request behavior.
- [x] Retain non-LI stubs, role build/vet partitions and privileged eBPF integration.
      Describe coverage precisely: shared execution, LI execution, compile/vet,
      security scanning and privileged integration are separate evidence.
- [x] Use supported stable tooling/actions when changes require them, verify their
      official releases during implementation, and address relevant workflow
      annotations without introducing unrelated dependency upgrades.

## 7. Documentation and validation

- [x] Update `docs/VOIP_EBPF_ADMISSION.md` for observation-time rejection, retirement
      history loss, genuine-call recovery costs and eligible cross-deadline recovery.
      Describe SIP-triggered global retirement scans, touched-call checks,
      uncertainty publication scans and maintenance accurately; do not promise
      constant per-message work or add an unrelated scan optimization.
- [x] Update `docs/LI_INTEGRATION.md` and relevant command documentation for timeout
      configuration, queue-pressure release, stable uncertain IDs, late completion,
      shutdown ownership and the remaining crash-continuity limitation.
- [x] Update affected manual source and every translation configured in
      `docs/manual/languages.json` in the same implementation task. Preserve examples,
      link targets and IDs, resolve affected fuzzy entries, and validate all editions.
- [x] Format changed files and generated artifacts. Validate configuration/schema
      compatibility, workflow syntax and additive status serialization.
- [x] Run focused admission and LI concurrency tests with race detection, then
      `go test -race -tags all ./...` and `go test -race -tags 'all li' ./...`.
      Run `make test-ebpf` with the required privileges, `make build-matrix`,
      `make verify-no-li`, applicable lint, and both tagged security scans.
- [x] Run `make manual-check` and `make manual` after documentation changes, and
      check whitespace and sanitized fixture/documentation content.
- [x] Verify GitHub executes the intended LI tests and both security configurations
      and records successful results for the final implementation revision. Attribute
      failures to the affected configuration rather than relying on aggregate green
      status or earlier revisions.
- [x] Check off tasks only after their behavior is verified. Record concise test
      evidence and any explicit remaining operational limits in this plan, then
      commit the implementation and updated plan. Preserve previously completed
      plans; do not relabel this new scope as work they failed to complete.

## Implementation order

Start with permanent counterexamples and resource/lifecycle contracts. Complete
observation-time rejection before cross-deadline recovery can promote proof.
Establish logical decision release and late-outcome fencing before changing
shutdown ownership. Add CI execution/scanning alongside the fixes so the retained
regressions run continuously. Finish documentation, translations and bounded
verification of this scope without opening an unrelated hardening campaign.

## Implementation choices

The shared replay pool charges both exact guards and overflow identity records
at 128 bytes per entry. Its effective capacity is the smaller of the configured
count and byte limits. One quarter of that capacity is reserved for overflow
identities, with a minimum of one entry when at least two entries fit; ordinary
guards use the remainder. A pool that fits only one entry has no overflow
reserve and uses conservative quarantine invalidation when history is lost.
Receipt-time rejection and invalidated pressure generations survive expiry and
delayed metadata selection; generation counters saturate without reviving proof.
An immutable observer-owned receipt travels through the validated SIP
observer-to-selection handoff and binds its scope, normalized evidence and
original capture timestamp independently of staging expiry or eviction. Missing
provenance withholds new proof while preserving independently retained healthy
proof. A newly received identical message can obtain its own post-window receipt.

Correlation uses `wait_timeout: 5s` and `shutdown_timeout: 10s` as positive
operational defaults. Each adoption has one fixed wall-clock deadline and one
serialized physical writer. Deadline or queue pressure pins the group ID before
ordered handoff; late storage completion cannot revert that ID. Shutdown shares
one wait budget across maintenance and close while eventual cleanup retains
exclusive physical ownership. Status adds aggregate `wait_timeouts`,
`pressure_releases` and `shutdown_timeouts` counters without identifiers.

The finite replay-window boundary, uncertain adoption's crash-continuity limit,
and inability to forcibly cancel filesystem I/O remain explicit operator
contracts. Startup recovery policy, matching heuristics and persistence frequency
are unchanged.


## Verification evidence

Local verification used Go 1.27.2 on the final repaired implementation.

| Check | Result and scope |
| --- | --- |
| Focused race regressions | Admission replay/boundary/receipt tests and real UDP/fragmented TCP/orchestrator paths pass; LI correlation, delivery and real processor timeout/shutdown tests pass. |
| Real X2/X3 delivery | Timeout/pressure with late storage outcomes passes over TLS; memory/persistent X3 cases verify stable ID, unique payload, original capture timestamp and journal admission before correlation storage is released. |
| Full race suites | `go test -race -tags all ./...` and `go test -race -tags 'all li' ./...` pass after the receipt repair. |
| Privileged integration | `make test-ebpf` passes after the receipt repair, including kernel/libpcap and tap/hunter command cases. Optional performance measurement is not a correctness gate. |
| Build partitions | `make build-matrix` and `make verify-no-li` pass on the repaired revision. CUDA link qualification is unchanged and remains outside this scope. |
| Lint and workflow syntax | golangci-lint passes with `all` and `all,li`; actionlint passes for both changed workflows; generated bindings and changed Go files are formatted; whitespace checks pass. |
| Security | gosec completes for `all` and `all,li` under the existing scan policy with unchanged source findings; govulncheck reports no reachable vulnerabilities for either configuration. |
| Manual | `make manual-check` passes all tool tests and reports full current-message coverage in both German/Catalan catalogs; `make manual` builds and validates all three language editions using the project-pinned mdBook. Both were rerun successfully on the isolated implementation branch. |
| Compatibility and privacy | YAML/environment defaults, malformed/nonpositive timeouts, additive protobuf/status round trips, non-LI exclusion, and sanitized documentation/fixtures are verified. |
| GitHub implementation revision | `82bb68eb3ee88b9603ae4a48ff71cf70c8f24279`: [CI](https://github.com/endorses/lippycat/actions/runs/37925006514), [Security](https://github.com/endorses/lippycat/actions/runs/37925006504), and [Integration Tests](https://github.com/endorses/lippycat/actions/runs/37925006516) all pass. Both full race/coverage suites executed successfully; both tagged security scans, SARIF uploads and vulnerability checks succeeded; ordinary, Docker and privileged eBPF integration all passed. |

One bounded closure review found loss of receipt provenance after staging expiry
or eviction. The production handoff now carries an immutable receipt, and bridge
and real-orchestrator regressions retain the original counterexample. The affected
post-fix review found no remaining material defect; required local checks pass.

The first GitHub LI suite exposed two existing test synchronization races.
The destination-restart test now waits for the first sender outcome and empty
queue before closing the receiver; deadline-cleanup uncertainty still permits
the existing at-least-once retry. The authorization-narrowing test drains the
new call's accepted RTP through normal protocol completion before flushing the
journal, and no longer races a short task expiry against encrypted commits.
Exact FIFO, delivery counts, generation revocation and persisted-product
assertions remain intact. The restart and write-outcome regressions pass 100
race repetitions and 30 repetitions with atomic coverage; the processor
regression passes 20 race repetitions. The full LI suite also passes locally
with race detection and atomic coverage after these fixes. Production behavior
is unchanged. The final verification-record commit changes only this plan;
the tested implementation and tests remain identical to the revision above.
