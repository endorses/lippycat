# LI partial snapshot authorization and conflict recovery

Status: complete. Implementation and required verification passed on 2026-10-02.

## Purpose and evidence

Address G1–G5 from the updated 2026-10-02 verification of `3b387355`
(`fix(li): constrain conflict authorization and recover X1 reporting`), including
the accepted second opinion. The source report is
`/home/grischa/2026-10-02-conflict-authorization-verification-3b387355.md`.
This plan includes the findings and acceptance cases needed to implement the
work without access to that external file.

This follows [LI conflict authorization and X1 reporting](li-conflict-authorization-and-x1-reporting.md).
It supersedes that plan's retention of all held authorization on partial
snapshots and its allowance for an arbitrary authenticated modification to
resolve a disarmed conflict. Preserve its completed reporting, schema validation,
membership accounting, orphan removal, and replay protections.

The original verification reports race-tested scenarios; the second opinion
inspected source and tests without rerunning them. Those results are baseline
evidence, not validation of this implementation. The report also states that the
ADMF deployed routine end-time-only `ModifyTask` renewals on 2026-09-30. Treat
that as reported deployment context and reproduce the request behavior locally;
access to the production ADMF is not a prerequisite for these fixes.

## Findings and priority

| Finding | Problem                                                                                                                          | Planned treatment                                                                                                    |
| ------- | -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| G1      | An omitted mediation window causes supplied targets, task destinations, and delivery restrictions to be ignored.                 | Intersect supplied authorization dimensions while retaining only the unknown window from the held definition.        |
| G3      | A disarmed conflict retains the previous descriptive scope. A partial modification can clear disarming and restore that scope.   | Reject modification of conflict-disarmed tasks; use explicit lifecycle recovery with a complete activation.          |
| G2      | Narrowing can change protected identity, and `ModifyTask` cannot restore a changed start.                                        | Document and test complete reactivation for unchanged identity and replacement under a new XID for changed identity. |
| G5      | Older binaries reject new conflict metadata; restoring only an old state file can regress authorization and journal consistency. | Provide a coherent rollback procedure and assess safe omission of default metadata.                                  |
| G4      | A failed narrowing closes LI admission process-wide.                                                                             | Assess task-local isolation separately; retain the global barrier whenever safe isolation cannot be established.     |

G1 and G3 are authorization correctness work for both live and persistent
operation. G2 ships with the changed recovery behavior. G5 is persistence rollout
preparation. G4 and reporting backoff are independent availability improvements
and do not block completion of the authorization fixes.

G3 specifically concerns disarming that retains the previous broader definition.
A successful nonempty intersection already stores the narrowed scope; an
end-time-only renewal must retain those narrowed targets, destinations, and
delivery permissions. Do not describe all renewals after narrowing as widening.

No new throughput, latency, soak, CPU, or memory acceptance targets are part of
this plan. Preserve existing configured limits, durability, expiry, and
cryptographic bounds.

## Authorization and recovery contract

Snapshots may restrict authorization but cannot establish freshness or restore
withdrawn scope. A missing window is unknown; an explicitly open end in a
complete window is a different input. Do not infer selector overlap beyond the
existing canonical target equivalences. Destination membership must be checked
against the individual task as well as successfully confirmed destination
definitions.

For an active or pending task with a nonempty effective definition, ordinary
`ModifyTask` keeps its existing field-presence semantics: omitted fields retain
the effective stored values. Explicit changes still require normal validation
and authorization generation handling.

For a task marked `ConflictDisarmed`, reject every `ModifyTask`, including an
end-only renewal, an empty modification, and a modification containing all
currently mutable fields. Return the existing modification-not-allowed error
through the X1 mapping. Preserve the disarmed state, conflict diagnostics,
reporting, and replay prohibition. The retained definition is diagnostic scope,
not a safe base for a patch. `ModifyTask` cannot supply a replacement start, and
the failed intersection's restrictions are not retained in full.

Recovery uses existing authenticated X1 lifecycle operations:

| Required recovery                                                                                       | Operation and result                                                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Restore scope through supported mutable fields on a task that still has a nonempty effective definition | Explicit `ModifyTask`; omitted fields retain the narrowed definition.                                                                                                                 |
| Recover a disarmed task, or replace a start time, without changing retained protected identity          | Successfully `DeactivateTask`, then submit a complete `ActivateTask` for the same XID. Validate the intended window, destinations, and lifecycle options; reserve a fresh generation. |
| Replace retained targets or delivery type through lifecycle recovery                                    | Successfully deactivate the old task and activate a complete task under a new XID. Retain the old tombstone and revocations.                                                          |
| Retry an already successful activation                                                                  | Preserve the existing equivalent active/pending retry as a pure read; do not allocate another generation or reinstall filters.                                                        |

Protected identity remains the XID, canonical targets, and delivery type.
Deactivation must not reset it. A later matching snapshot does not clear a
conflict, reactivate a tombstone, or confirm historical product for replay.

To make lifecycle recovery enforceable without adding another durable marker,
require complete definitions for **all generic retained-task reactivations**,
including compatibility mode. Use the existing completeness contract: explicit
mediation details with known start and end semantics; an explicitly open end is
allowed and the optional implicit-deactivation flag retains its established
default. Preserve compatibility-mode behavior for first activations and keep
RADIUS on its specialized path. This is an intentional compatibility change for
clients that previously reactivated retained tasks with incomplete definitions;
document it with the recovery procedure.

## Implementation sequence

### 1. Establish permanent authorization regressions

Primary files: `internal/pkg/li/conflict_authorization_test.go`,
`internal/pkg/li/definition_verification_test.go`,
`internal/pkg/processor/processor_li_conflict_test.go`, and existing delivery
authorization tests.

- [x] Add the report's partial-snapshot case: two held targets and destinations,
      an incoming single target and task destination, `X2Only`, and no mediation
      window. Keep the removed DID globally configured to expose the difference
      between global existence and per-task authorization.
- [x] Add end-time-only renewals after each conflict-disarming reason: expired
      cutoff, empty window, no common targets, no common destinations, and no
      common delivery. Verify rejection and no resumed capture or delivery.
- [x] Replace the disarmed branch of
      `TestConflictResolutionRequiresExplicitMutationAndFreshGeneration` that
      expects a delivery-only modification to resolve disjoint targets. Retain
      separate coverage for valid modifications of nonempty narrowed scope.
- [x] Exercise memory-only live operation, persistent live operation, restored
      state, and a second restart. Include actual X1 request conversion for
      omitted fields, rather than relying only on direct manager calls.
- [x] Preserve useful original throwaway cases as repository tests, using the
      report's scenario descriptions where the original test files are absent.
      Assert filters, allowed product types, delivered destinations, generation
      revocation, and replay state, not only stored task fields.

### 2. Apply mandatory restrictions from partial snapshots — G1

Primary files: `internal/pkg/li/definition_convergence.go`,
`internal/pkg/li/conflict_authorization.go`, `internal/pkg/li/definition.go`, and
`internal/pkg/li/snapshot_sync.go` where snapshot evidence is assembled.

- [x] Replace the partial-snapshot early return/held-definition clone behavior
      for held generic authorization with dimension-aware convergence. Compare
      mandatory supplied fields even for an already live confirmed task.
- [x] Reuse the canonical target, task DID, confirmed-destination, and delivery
      intersections from complete conflicts. Retain the held start, end, and
      implicit-deactivation policy only where the window is unknown; do not
      interpret absence as an unbounded window or a new default.
- [x] Route narrowing and empty intersections through the same transactional
      filter, generation, revocation, and disarming paths as complete conflicts.
      Retain conflict state and queue reports when supplied dimensions differ.
- [x] Preserve existing admission policy for first-seen incomplete tasks and
      strict-mode candidates. A partial response must not satisfy a strict
      confirmation requirement, authorize replay, or promote an unknown window
      to known. Restrictive updates must not be skipped merely because the
      response cannot grant fresh authorization.
- [x] Cover equal and wider partial snapshots, already narrowed definitions,
      absent/unconfirmed DIDs, canonical target equivalents, empty intersections,
      both strict-mode settings, and repeated polls without generation churn.
      Keep RADIUS reconciliation separate.

### 3. Prevent implicit rearming and implement recovery — G3 and G2

Primary files: `internal/pkg/li/manager.go`,
`internal/pkg/li/conflict_authorization.go`,
`internal/pkg/li/definition_promotion.go`,
`internal/pkg/li/administrative_transactions.go`,
`internal/pkg/li/administrative_recovery.go`, `internal/pkg/li/persistence.go`,
`internal/pkg/li/activation_identity.go`, and `internal/pkg/li/x1/server.go`.

- [x] Reject `ModifyTask` on `ConflictDisarmed` before clearing definition
      metadata or constructing a candidate. Remove the special modification
      resolver if it has no remaining legitimate caller. Preserve the existing
      LI-to-X1 error mapping and provide actionable recovery documentation.
- [x] Apply the same rule across direct manager calls, X1 adapters, and durable
      mutation paths. Keep promotion of legitimate restored/narrowed definitions
      working without permitting promotion to bypass conflict disarming.
- [x] Require complete generic retained-task reactivation in both memory and
      persistent paths before filter installation, generation publication, or
      durable authorization. Reject incomplete reactivation without altering
      the tombstone. Preserve equivalent active/pending retries.
- [x] Verify same-XID recovery after successful explicit deactivation for
      unchanged identity, including replacement of a later start and destination
      changes. Verify changed protected identity remains rejected and a new-XID
      activation provides the documented replacement route.
- [x] Exercise failure and restart between deactivation and activation, failed
      deactivation, failed activation, unfinished administrative intents, and
      restored disarmed tasks from the baseline state format. Interrupted
      operations must not restore old authorization or reuse a revoked generation.
- [x] Verify an end-only renewal on a nonempty narrowed task retains its narrowed
      targets, destinations, delivery type, and start. Separately verify a
      modification omitting the window retains its effective cutoff and implicit
      policy. Do not reject normal valid renewals as a side effect of the fix.
- [x] Verify rejected modifications leave conflict reporting active; successful
      explicit deactivation clears obsolete reporting. Old-generation X2/X3 in
      memory queues and durable journals remains revoked after either recovery
      route. Already completed writes cannot be recalled.
- [x] Update `docs/LI_INTEGRATION.md` with the recovery table, examples, error
      behavior, retained-identity limitations, and the incomplete-reactivation
      compatibility change. Update conflict report wording if it currently
      suggests that an arbitrary modification resolves a disarmed task.

### 4. Define safe persistence rollback — G5

Primary files: `docs/LI_INTEGRATION.md`, `internal/pkg/li/definition.go`,
`internal/pkg/li/state_codec.go`, and existing state compatibility tests.

- [x] Document backup while the relevant processes are stopped: administrative
      state, applicable X2/X3 journals, controls, checkpoints, and usage history
      form one consistent set. Retain required encryption keys under separate
      access controls. Do not restore administrative state over newer journals.
- [x] Document downgrade as a coordinated binary/configuration and consistent
      state restore, followed by current ADMF reconciliation and existing replay
      checks. State explicitly that authenticated storage does not detect a
      coherent rollback and an old backup may omit later withdrawals. If current
      authority cannot be established safely, interception/replay stays disarmed.
- [x] Include the older binary's authorization limitations in the runbook;
      successful decoding is not evidence that rollback is operationally safe.
      Do not promise a safe downgrade to a build with the relevant authorization
      defect merely because a backup can be restored.
- [x] Assess omission of default-valued `ConflictDisarmed` and `ConflictReason`
      during encoding. Implement it only if strict validation and round-trip
      semantics remain intact. Never strip non-default conflict evidence or
      loosen unknown-field validation to force old-reader acceptance.
- [x] Add compatibility fixtures for baseline files, unaffected newly written
      files, and meaningful conflict state. Demonstrate the actual old-reader
      outcome with the baseline codec or an isolated historical build, not only
      a round trip through the new decoder. Record supported and deliberately
      rejected combinations; default-field omission is not a general downgrade.

### 5. Assess fault isolation independently — G4

Primary files: `internal/pkg/li/conflict_authorization.go`,
`internal/pkg/li/administrative_state.go`, administrative transaction helpers,
and existing fault-injection tests.

- [x] Classify narrowing failures by evidence: task-local failure with confirmed
      revocation and durable disarming, versus failed/uncertain revocation,
      failed filter cleanup, or ambiguous shared-store outcome.
- [x] Where existing primitives prove isolation, keep the affected task closed
      and allow an unrelated task to continue. Persist the withdrawal so restart
      cannot resurrect its wider definition. Preserve configured resource bounds.
- [x] Retain process-wide admission closure whenever isolation cannot be proved.
      Use fault-injection tests with two tasks to demonstrate both safe isolation
      and global closure for shared/uncertain outcomes. Do not simply replace
      `faultAdministrative` with a best-effort filter removal.
- [x] Record a bounded disposition: implement proven local cases, or document
      why the current primitives require global closure. A new isolation
      architecture is not required to close the authorization work.

### 6. Improve conflict retry scheduling independently

Primary files: `internal/pkg/li/conflict_reporting.go` and its reporting,
acknowledgment, and lifecycle tests.

- [x] Replace the fixed retry interval with capped exponential backoff per
      unacknowledged conflict episode. Retain the existing initial interval;
      choose and document the cap as an operational policy, not a performance
      acceptance target. Continue retrying at the cap until acknowledgment.
- [x] Preserve one worker, bounded concurrency, prompt cancellation, correlated
      acknowledgments, and immediate reporting for new/restored conflicts.
      Equivalent polls must not reset backoff; a meaningful new conflict episode
      must not inherit obsolete acknowledgment or retry state.
- [x] Use deterministic scheduling tests for delay growth/capping, fairness
      between pending tasks, cancellation, episode replacement, and restart.
      Avoid wall-clock sleeps as the correctness evidence.

## Verification and delivery

Complete sections 1–3 as the authorization/recovery change, section 4 as rollout
preparation, and sections 5–6 independently. Do not mark an unchecked item complete
without its stated evidence. Retain the prior V2–V5 behavior; this plan does not
reopen those completed features for redesign.

- [x] Run focused conflict, reactivation, state recovery, and X1 tests while
      implementing each change. Exercise both memory and persistent operation.
- [x] Run the relevant race suites after the corresponding changes are complete:

```bash
go test -race -tags li ./internal/pkg/li/...
go test -race -tags 'tap li' ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/tap/...
go test -race -tags 'all li' ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/process/...
```

- [x] Run the existing outbound XSD tests with their required `xmllint`
      dependency. Preserve schema-valid warnings and existing bounded diagnostics.
- [x] Verify non-LI exclusion with `make verify-no-li` if shared types or encoding
      change. Extend package coverage only for affected integrations or concrete
      failures; no repeated broad test rounds without new evidence.
- [x] If sandbox restrictions prevent required tests, request permission for
      those tests. Clean task-owned temporary caches/worktrees after use.
- [x] Track `TestTopologyUpdateBatcher_MultipleBatches` separately. If that or
      another unrelated failure prevents required validation, stop the immediate
      task and report the blocker per repository instructions; do not silently
      exclude it, mark a failed run passed, or absorb unrelated repairs here.
- [x] Format changed files, run `git diff --check`, record commands and actual
      results in this plan, and check off only verified work. Commit implementation,
      tests, documentation, and the updated plan together in coherent changes.

## Implementation decisions and evidence

G1 uses the existing conflict intersection for mandatory supplied dimensions.
Unknown mediation windows retain the held window and policy. Strict restored
scope is persisted pending behind the confirmation barrier; candidates cannot
arm through partial input. Full confirmation can admit the restricted scope,
but does not restore removed scope. RADIUS remains on its specialized path.

G2/G3 reject every modification of a conflict-disarmed task and require complete
generic retained-task reactivation in both administrative paths. No new durable
recovery marker or wire operation was introduced. A full activation can replace
a start only through the documented explicit lifecycle; protected identity and
old-generation revocation remain intact. The closure review found and repaired
one restoration gap: an elapsed implicit cutoff used to move deactivated/failed
records out of the registry, bypassing retained-task validation on the next push.
Terminal records now remain in the registry before elapsed-candidate
classification. `TestElapsedTerminalTaskRetainsRecoveryContractAcrossRestart`
verifies two restarts, both rejected replacement forms, stale pulls, and complete
unchanged-identity recovery with a fresh generation. The focused race regression
passed; the integrated post-fix review found no supplemental issue.

G4 disposition: retain process-wide closure on narrowing failures. The existing
transaction owner faults after failed withdrawal and shares its state across
tasks. A pre-reservation failure leaves the old wider definition on disk;
revocation and filter failures do not establish complete withdrawal; an uncertain
checkpoint cannot establish a task-local durable outcome. None of these failure
classes provides the proof needed to reopen unrelated admission. Successful
narrowing is task-local; `TestConflictFaultScopeWithUnrelatedTask` verifies that
control case and global closure for product-revocation, filter, reservation, and
uncertain-checkpoint failures without changing the unrelated task's definition.
No new isolation architecture is needed for this plan's bounded disposition.

G5 omits only default-valued conflict metadata. Synthetic version-2 fixtures
exercise the `702c2c3f` shape, explicit defaults from `3b387355`, and non-default
disarmed state. Isolated source archives of both historical revisions ran
`TestHistoricalConflictCodecCompatibility` against those fixtures and bytes
emitted by the current writer. Both historical test runs passed their acceptance
and rejection expectations:

| Reader     | Baseline without new fields / current unaffected output | Explicit defaults written by `3b387355` | Non-default disarmed state / current disarmed output |
| ---------- | ------------------------------------------------------- | --------------------------------------- | ---------------------------------------------------- |
| `702c2c3f` | Accept                                                  | Reject unknown fields                   | Reject unknown fields                                |
| `3b387355` | Accept                                                  | Accept                                  | Accept                                               |
| Current    | Accept                                                  | Accept; omit defaults on rewrite        | Accept; retain conflict evidence                     |

The historical harness called the actual `UnmarshalStateSnapshot` at each
revision; it did not emulate an old reader by deleting keys in the current
codec. The archived builds and export helper were temporary. Permanent
`TestConflictStateCompatibilityFixtures` additionally verifies lossless current
round trips and continued rejection of unknown authorization fields. Reader
acceptance is not a safe-downgrade guarantee.

Reporting uses a 30-second initial retry, exponential growth, and a 5-minute cap,
with earliest-deadline scheduling and a stable tie break. This cap is a documented
operational policy, not a new product acceptance target. Deterministic tests
cover growth, capping, fairness, poll deduplication, episode replacement,
cancellation, acknowledgment, and restart.

### Validation results

All test commands use the task-owned `GOCACHE=/tmp/lippycat-conflict-go-cache`.
Persistent fixtures initially hit sandbox directory-owner mapping errors; the
required storage/network suites run outside the sandbox with approval. The first
full LI suite identified three old expectations tied to the changed contract:
an unconfirmed partial destination now disarms and reports, retained reactivation
requires complete metadata, and a membership-streak fixture must return unchanged
destination definitions. Their safety assertions were retained and updated.

Final verification after the retained-record fix:

| Command or check                                                                                              | Result                                                                                                                                  |
| ------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------- |
| `go test -race -tags li ./internal/pkg/li/...`                                                                | Pass, including X1 outbound XSD validation with required `xmllint`. Unchanged subpackage results were reused from the passing race run. |
| `go test -race -tags 'tap li' ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/tap/...`     | Pass, including the real ADMF/MDF and mTLS X1 conflict/recovery regressions.                                                            |
| `go test -race -tags 'all li' ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/process/...` | Pass.                                                                                                                                   |
| `make verify-no-li`                                                                                           | Pass. The later restoration fix is LI-tagged and does not affect this build.                                                            |
| Historical codec runs at `702c2c3f` and `3b387355`                                                            | Pass with the acceptance/rejection matrix above.                                                                                        |
| Formatting and `git diff --check`                                                                             | Pass.                                                                                                                                   |

The existing proxy batching test passed in both required role suites; it was not
modified. The task-owned Go cache, historical archives, fixture export helper,
temporary test output, and audit worksheet were removed after recording evidence.

Closure decision: **CLOSED**. One bounded campaign found R1 (elapsed terminal
record restoration), repaired it, passed affected verification, and completed one
integrated review with no supplemental findings. G4 is closed through the plan's
explicit bounded assessment option: retain the global barrier where current
primitives cannot establish safe isolation. No required implementation or
verification is deferred. Code, tests, operator documentation, and this completed
plan are delivered together; production rollout is outside this task.
