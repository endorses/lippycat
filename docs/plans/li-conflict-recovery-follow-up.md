# LI conflict recovery follow-up

Status: complete. Implementation and required verification passed on 2026-10-02.

## Purpose and evidence

Address the four low-severity observations in the 2026-10-02 verification of
`7c028210` (`fix(li): enforce partial snapshot scope and explicit conflict
recovery`). The source report is
`/home/grischa/2026-10-02-partial-snapshot-and-recovery-verification-7c028210.md`.
This plan contains the findings and decisions needed without that external file.

The preceding [partial snapshot and conflict recovery plan](li-partial-snapshot-and-conflict-recovery.md)
remains complete. The verification report describes additional passing throwaway
tests; the second opinion checked relevant source without independently rerunning
those matrices. Neither substitutes for verification of the change below.

| Finding | Accepted observation                                                                                                                                             | Bounded treatment                                                                |
| ------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| R1      | An empty modification clears a narrowed task's conflict and reporting, and advances its generation despite supplying no task fields.                             | Reject empty modifications of generic narrowed conflicted tasks before mutation. |
| R2      | Protected identity is enforced while the task record is retained; tombstone purge removes that comparison record.                                                | Document the default retention and cleanup constraints.                          |
| R3      | A disarmed task retains the held window and can subsequently become implicitly deactivated; complete reactivation then needs no additional deactivation request. | Clarify lifecycle recovery after expiry; keep expiry behavior unchanged.         |
| R4      | Complete pulls can replace ordinary pull-owned definitions, and a first complete push can promote an eligible pull-owned task.                                   | Explain ownership distinctions and the conflict-disarmed exception.              |

These observations do not demonstrate unauthorized widening. Explicit,
authenticated operations can deliberately authorize broader scope under the
existing validation rules.

## Scope and decisions

R1 is the only production behavior change. For a generic active or pending task
with `Definition.Conflict` set and nonempty effective authorization, reject a
non-nil modification that supplies no supported task fields. Use the existing
`ErrModifyNotAllowed` and X1 error 100 mapping. Check field presence before the
manager synthesizes definition metadata or invokes mutation, persistence, filter,
revocation, or report-resolution operations. Internal metadata alone is not a
supplied task field.

An explicitly supplied field counts even if its value equals the current value.
Preserve normal validation for explicit false, zero times, and empty collections;
do not treat these as omitted. Preserve nil-input validation, nonconflicting
tasks, and the specialized RADIUS path. Conflict-disarmed tasks continue to
reject every modification. Nonempty modifications retain existing semantics:
omitted fields keep narrowed values, and successful explicit modification can
resolve the conflict. Reasserting every field involved in a conflict is not a
new requirement.

R2–R4 require documentation changes only. Do not alter tombstone retention,
generation watermarks, authorization cutoffs, implicit-deactivation policy,
ownership transitions, persistence formats, or rollback behavior. In particular,
do not implement the report's suggestion to expire at the earlier nominal end:
an effective cutoff depends on implicit-deactivation settings, and a disarmed
record retains diagnostic scope rather than a complete failed intersection.

This follow-up does not reopen G1–G5, add performance targets, reproduce the
throwaway historical-version matrices, or add the optional HTTP partial-snapshot
test. Existing coverage for those completed changes remains in place.

## Implementation tasks

### Empty modification guard and regression coverage

Primary files: `internal/pkg/li/manager.go` and
`internal/pkg/li/conflict_recovery_test.go`. Reuse existing modification types,
reporting fixtures, and restart helpers; change additional files only if the
shared field-presence check or focused regression coverage requires it.

- [x] Add the field-presence guard under the existing administrative and
      lifecycle locks, before conflict metadata is cleared. Cover the supported
      modification fields rather than comparing values with zero values.
- [x] Add focused cases for narrowed active and future-start pending tasks,
      using memory, persistent, and restored managers. Exercise direct manager
      calls and the X1 adapter; assert the established error mapping.
- [x] On rejection, assert unchanged effective definition, status, generation,
      filters, admission/replay eligibility, and conflict-report state. Confirm
      no mutation callbacks or durable transaction are initiated and the
      report's acknowledgment/retry state is not reset. Verify retained conflict
      and scope after restarting persistent state; reporting remains
      process-local and follows its existing restart behavior.
- [x] Cover explicit same-value fields and ordinary end-only renewal as accepted
      modifications, with omitted scope retained. Preserve existing validation
      for supplied invalid values, and confirm empty nonconflicting modifications
      and nil input retain their prior behavior. Keep the existing disarmed-task
      rejection and RADIUS regressions passing.

### Recovery documentation

Primary file: `docs/LI_INTEGRATION.md`, especially “Recovering a narrowed or
disarmed task,” “Explicit tombstone reactivation,” and the existing pull-owned
definition explanation. Keep those sections consistent through concise text and
cross-references.

- [x] Document R1's empty-modification rejection and unchanged behavior for
      explicit modifications, including end-only renewals.
- [x] Explain that `TombstoneRetention` defaults to 24 hours after deactivation,
      with purge performed by lifecycle maintenance. Outstanding cleanup,
      revocation, or unfinished administrative work can delay persistent purge.
      After removal, the old identity is no longer compared and a same-XID
      activation follows first-activation rules; generation watermarks and old
      product protections remain. Describe the configuration at its actual
      supported API level without inventing a CLI flag. Do not recommend waiting
      for purge as the normal way to replace an identity; use a new XID.
- [x] Explain that a suspended disarmed task may undergo normal implicit expiry
      at its held effective cutoff. Once read-back confirms deactivation, an
      additional `DeactivateTask` is unnecessary. Complete retained-task
      reactivation still requires unchanged protected identity and a fresh
      generation; it does not authorize historical product. A nominal end with
      implicit deactivation disabled does not supply this transition.
- [x] Explain ordinary pull-owned complete-snapshot replacement and first full
      push promotion of eligible active/pending pull-owned tasks. Distinguish
      push-owned definition conflicts, equivalent activation retries, and
      conflict-disarmed tasks, which cannot use the promotion shortcut. Existing
      conflicts on pull-owned tasks still constrain subsequent snapshot
      reconciliation; pull ownership is not a blanket exception to disarming.

## Verification and completion

The following is the fixed acceptance scope. Documentation-only observations
R2–R4 need source-backed review, not new lifecycle mechanisms or exhaustive test
matrices. Add tests only for R1 and directly affected existing expectations.

- [x] Run the new R1 regressions and existing conflict recovery/reporting tests,
      then `go test -race -tags li ./internal/pkg/li/...`. This covers the shared
      manager and X1 packages used by processor and tap. Broaden checks only if
      changed integration code or a concrete failure warrants it. Request
      permission if sandbox restrictions require running tests outside it.
- [x] Review documentation against `runLifecycleMaintenance`,
      `purgePersistentTasksLocked`, registry expiration, `ActivateTask`,
      `applySnapshotDefinition`, and `promoteTaskDefinitionLocked`; verify links
      and remove any unconditional claim that identity protection outlives the
      retained record or that every recovery needs a new deactivation request.
- [x] Format changed files, run `git diff --check`, and review the final diff
      against R1–R4 once. Preserve configured limits and existing authorization,
      durability, expiry, and replay protections; add no performance gates.
- [x] Record actual verification results here, mark only verified tasks complete,
      clean any task-owned temporary caches, and commit the implementation,
      documentation, and updated plan together.

Completion means the empty request can no longer resolve a narrowing conflict,
the four recovery cases are accurately documented, and the specified checks
pass. Unrelated observations do not automatically extend this follow-up or reopen
the completed predecessor plan.


## Completion evidence

Implemented the empty-modification guard in `Manager.ModifyTask` before conflict
metadata changes. Direct and X1 callers share the guard. Only generic conflicted
active/pending tasks with no supplied task fields are newly rejected; the existing
X1 mapping returns error 100. No expiry, retention, promotion, persistence-format,
or rollback behavior changed.

Permanent regressions in `conflict_recovery_test.go` cover memory, persistent,
and restored managers; active and future-start pending tasks; acknowledged and
retrying reports; direct, metadata-only, and X1 empty requests; and unchanged
filters, admission/replay eligibility, generations, callbacks, revocations, and
durable state. Restart checks verify the retained conflict before reconciliation
and a fresh process-local report afterward. Explicit same-value fields, false,
open ends, invalid supplied values, renewal, nil input, and nonconflicting/RADIUS
behavior are covered. The existing renewal test now rejects its empty request
and resolves the conflict with an explicit same-value field.

Verification on 2026-10-02:

| Check | Result |
| --- | --- |
| `go test -tags li ./internal/pkg/li -run 'Test(NarrowedConflict\|EmptyModification\|NonemptyConflictRenewal)' -count=1` | PASS, 0.042s |
| `go test -race -tags li ./internal/pkg/li/...` | PASS: li 42.955s, delivery 58.892s, x1 10.008s, x2x3 1.037s; schema has no tests |
| Go formatting and `git diff --check` | PASS |
| Touched documentation links and source-backed R2–R4 review | PASS |

The test runs used approved outside-sandbox execution because the sandbox's
directory-owner mapping blocks securestore persistence fixtures. An initial
focused run exposed an incorrect new test expectation that restored tasks and
reports publish before reconciliation; the fixture was corrected to assert the
existing restore contract, and the focused and full runs above passed. No
production restore behavior changed.

The single bounded closure review, including an independent reviewer, found no
material findings: **CLOSED**, with no deferrals or remediation batches. The
review covered R1–R4 only; the predecessor remains closed. Task-owned temporary
logs were removed after recording these results. Implementation, documentation,
and this completed plan are committed together.
