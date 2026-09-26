# LI X3 task authorization and lifecycle fixes

Status: completed; implementation, validation, and plan committed.

## Problem and scope

The release audit at `/home/grischa/v0.12.2-release-audit-li.md` identifies two
X3 lifecycle defects and a delivery-gate retention defect in the current source:

- An end-time-only `ModifyTask` retains the non-RADIUS activation generation,
  but the delivery client remembers the original cutoff. The processor only
  publishes committed authorization changes when the X3 journal is enabled.
- X3 enforces task end times even when `ImplicitDeactivationAllowed` is false,
  although the task registry deliberately keeps those tasks active.
- Task facts and revocation identities accumulate over the client lifetime.
  Reaching `maxDeliveryGateIdentities` latches a fault that suppresses all X3.

Fix these issues before the version bump. Include operator-facing release notes
for the fixes and the already implemented LI storage and flag changes. Do not
bump the version, tag a release, or change wire encoding in this work.

## Required behavior

The source of task authorization is committed administrative state. Packet
metadata can supply an initial fallback cutoff for legacy embeddings, but cannot
extend an already known authorization. A timing-only modification committed
before the old cutoff must update delivery authorization without changing the
non-RADIUS task generation.

An effective task cutoff is `EndTime` when implicit deactivation is allowed, and
zero otherwise. Apply that rule to live capture, persistent admission, committed
task publication, and replay. Task cutoffs remain independent of immutable
product retention deadlines; modifying a task must never refresh product age.

Expired or explicitly revoked generations remain rejected. Extending a cutoff
after it has elapsed must not resurrect retained content. Explicit reactivation
uses the manager's existing generation semantics. Preserve the stricter RADIUS
definition comparison and existing authorization, durable revocation, expiry,
cryptographic, and resource-limit enforcement.

Identity storage must be bounded by live or retained authorization obligations,
rather than all historical task churn. Retirement must not permit old content
to return through prepared admissions, reorder buffers, queues, in-flight writes,
or journal replay. Genuine capacity exhaustion or inconsistent state must still
fail closed with observable errors or existing fault reporting.

## Implementation steps

### Establish regression coverage

- [x] Add a processor/manager regression that activates a task, admits X3,
  commits an end-time-only `ModifyTask` before the original cutoff, and verifies
  X3 remains eligible after that cutoff with the same task generation. Run it
  with the X3 journal disabled and enabled.
- [x] Add a delivery-level test that explicitly publishes the committed extended
  cutoff using `SetX3TaskAuthorization`. Keep a separate test proving that newer
  packet metadata alone cannot extend a remembered cutoff.
- [x] Add coverage for a task remaining active beyond its end time when implicit
  deactivation is disabled, including persistent admission and replay.
- [x] Use explicit synchronization and controlled timestamps to establish the
  modification-before-expiry ordering. Use bounded eventual assertions only
  where worker activity is under test; do not rely on the audit's short sleeps.

The audit reproduction is evidence of stale fallback facts, not a valid
integration test for the callback fix: it never performs a committed task update.
Do not change delivery to trust successive packet cutoffs just to make it pass.

### Centralize effective cutoff policy

- [x] Introduce one narrowly scoped helper in the LI domain package for the
  effective task authorization cutoff, with tests for zero end time and both
  implicit deactivation settings. Place it in a semantic file such as
  `task_authorization.go`, consistent with the package's build-tag boundaries.
- [x] Use the helper when constructing live `DeliveryMetadata` in
  `internal/pkg/processor/processor_li.go`.
- [x] Use it in `deliverPersistentX3` and `authorizePersistentX3Replay` in
  `internal/pkg/processor/processor_li_persistent.go`.
- [x] Use it for committed authorization publication. Keep explicit zero facts
  distinguishable from missing facts so old packet metadata cannot reinstate a
  cutoff after implicit deactivation is disabled or the end time is removed.
- [x] Update `DeliveryMetadata.TaskEndAt` documentation to describe its effective
  policy meaning; preserve the journal format and original retention deadline.

### Publish committed changes consistently

- [x] Register the committed-task callback whenever the delivery client exists,
  outside the X3 spool-directory condition in `prepareLIStorage`. Keep durable
  revoker installation conditional on persistent X3 storage.
- [x] Verify publication on activation, same-generation modification,
  startup/reconciliation confirmation, and generation replacement. Handle
  inactive states through existing cancellation and retirement ownership rather
  than treating them as active authorization.
- [x] Preserve the manager's publication boundary in
  `finishTaskIntentLocked`: provisional, uncommitted, and uncertain storage
  outcomes must not authorize delivery.
- [x] Review the lock order between administrative transactions, gate facts,
  admissions, queue expiry updates, and cutoff sweeping. Ensure a committed
  extension cannot be overwritten by stale metadata or raced into revocation
  based on an obsolete cutoff.
- [x] Keep the committed callback within its documented contract: bounded memory
  updates, no manager reentry, external I/O, or worker waits. If queue updates
  require deferred work, eligibility must immediately consult the new fact and
  stale expiry entries must not drop otherwise eligible product.
- [x] Preserve cancellation of old-generation work and rejection after an
  elapsed cutoff, including the existing persistence regression tests.

### Retire task gate identities safely

- [x] Document ownership and references for `taskFacts`, `revokedTasks`, and
  `expiredTaskControls`, plus task-scoped entries in `revoked`. Account for
  prepared X3 permits, reorder ownership, destination queues, transport claims,
  retained journal records, and concurrent callback publication.
- [x] Choose and document a retirement rule before changing deletion behavior.
  Prefer reclaiming facts once no retained work references them, with committed
  current-generation authorization rejecting future stale admissions. If the
  legacy metadata-only API cannot prove freshness after retirement, retain its
  fail-closed behavior or require explicit authoritative publication; do not
  silently reauthorize an unknown old generation.
- [x] Implement retirement on terminal task lifecycle and generation replacement,
  and after the last retained reference drains. Ensure terminal cleanup is
  revisited when cancellation, permit release, delivery, or journal reclamation
  removes the final reference.
- [x] Keep durable revocation controls until their retained-product obligations
  are discharged under existing journal recovery/compaction rules. Prove replay
  and restart safety before reclaiming their in-memory counterparts.
- [x] Ensure zero-cutoff committed facts do not create another lifetime leak.
  Preserve active-task capacity limits; do not solve churn by increasing the
  constant, disabling the gate, clearing a fault blindly, or applying arbitrary
  time-based tombstone eviction.
- [x] Add deterministic churn coverage beyond the existing identity cap with
  bounded concurrent live/retained work. Verify map reclamation and continued
  delivery for unrelated active tasks. Exercise genuine live-capacity exhaustion
  separately and retain fail-closed behavior.
- [x] Retain an old permit or journal record across retirement attempts and verify
  it cannot deliver after deactivation or generation replacement. Include expiry,
  same-XID reactivation, late callbacks, and restart/replay cases.

### Complete lifecycle and failure-path tests

- [x] Verify end-time shortening suppresses queued and reordered X3 at the new
  cutoff, with journal-on/off cases and original retention deadlines unchanged.
- [x] Verify enabling implicit deactivation installs the effective cutoff, while
  disabling it or removing the end time before expiry clears it. Neither change
  may clear a prior revocation.
- [x] Verify explicit cancellation and actual expiry permanently reject the old
  generation, even after a later authorization update with a future cutoff.
- [x] Verify failed or uncertain administrative commits do not extend X3
  authorization, and startup confirmation supplies current authoritative facts.
- [x] Verify X2 continues to follow its existing behavior, multi-destination X3
  keeps existing fan-out semantics, and RADIUS authorization remains unchanged.

## Documentation and validation

- [x] Add release notes for the X3 lifecycle and identity-retention fixes.
- [x] Include the existing breaking LI encrypted filter-store default, required
  key flags, offline YAML migration, service ownership and directory modes, and
  removal of `--li-metadata-*` flags. Explain that X3 journaling remains opt-in
  and replay retains original bytes and sequence numbers without a replay marker.
  Use the repository's release-note convention without bumping `VERSION`.
- [x] Use role tags for processor tests (`all,li`); record the existing role-tag
  requirement in test instructions rather than adding unrelated build changes.
- [x] Run focused new tests during implementation, then
  `go test -tags all,li ./internal/pkg/li/... ./internal/pkg/processor/...`.
- [x] Run `go test -race -tags all,li ./internal/pkg/li/delivery ./internal/pkg/processor`
  to check the changed publication, expiry, and retirement concurrency paths.
- [x] Verify non-LI compilation with
  `go test -tags all -run '^$' ./internal/pkg/li/... ./internal/pkg/processor/...`.
- [x] Format changed Go files with `gofmt`, check the final diff, and run
  `git diff --check` before staging.
- [x] Check off only tasks supported by implementation and validation evidence,
  then commit the code, tests, documentation, and this updated plan together.

Run checks in the sandbox first. If tests require execution outside it, ask the
user. If unrelated failures prevent the work, stop and report those failures as
required by the project instructions. Clean up any task-owned temporary caches.

## Completion criteria

The task is complete when committed extensions work with either journal setting,
implicit deactivation policy is applied consistently, revoked generations cannot
return through any retained delivery path, and historical task churn no longer
exhausts the gate while live capacity enforcement remains intact. Required tests
must pass, release notes must describe operator-visible changes, and verified
implementation tasks must be checked off and committed.

This plan introduces no latency, throughput, CPU, RSS, or soak acceptance target.
Churn coverage validates the existing resource-limit and lifecycle defect, not a
new performance requirement.

## Implemented retirement and publication design

Processor delivery enables authoritative task publication. The ordered manager
callback is the only path that introduces an active XID/generation. Facts include
explicit zero cutoffs; packet metadata cannot introduce or refresh them. Replay
checks current policy without publishing its snapshot, so it cannot overwrite a
newer committed modification. Legacy metadata-only clients retain the original
bounded, permanent tombstones because they have no authoritative freshness source.

The delivery gate owns facts for currently published active tasks. Terminal
publication and generation replacement remove their old facts, revocation markers,
and cutoff-sweep completion markers. Missing facts reject both new and previously
prepared X3, so removal cannot reopen old generations. Prepared permits, reorder
callbacks, queues, and transport claims retain their immutable task generation;
none can republish authorization. Cancellation still visits queues even when the
terminal publication already removed the fact. Same-generation revocation remains
latched until the manager publishes a terminal state or a replacement generation.

Committed publication performs bounded memory updates and coalesces a nonblocking
notification. A delivery-owned dispatcher wakes queue owners, which rebuild expiry
indexes against the current facts. Expired candidates are revalidated before
dropping, and retention deadlines never change. Administrative publication does
not acquire queue locks or wait for transport workers.

The journal separately owns durable task-scoped revocation controls. The client
can release its duplicate control after a successful journal commit because strict
facts, including missing facts, still reject the generation. Journal retirement
requires no matching selected record fragments, no outstanding admission
reservations, and no pending producers. Terminal fragments remain obligations
until every selected fragment is retired. Control compaction first commits a
catalog selecting replacement extents; only then does it remove the in-memory
control. Reclamation and control admission revisit that rule. Legacy journals
retain permanent controls. No capacity constant or fault behavior is weakened.


## Verification evidence

The new processor tests exercise real committed `ModifyTask` operations with X3
journaling enabled and disabled: extension before expiry, disabling implicit
expiry, removing an end time, shortening, and enabling implicit expiry. Separate
cases verify persistent live admission beyond an explicitly managed end time and
actual held replay after ADMF confirms the unchanged persisted policy on restart.
The fixture preserves the existing rejection of a changed startup definition.

Delivery tests cover remembered metadata authority, stale queue expiry indexes,
unchanged product deadlines, prepared-permit and delayed-reorder rejection,
same-XID replacement, permanent expiry, more than 65,536 historical tasks, live
identity exhaustion, and independent X2 delivery. Journal tests cover prepared
reservations, pending old admissions, selected terminal bytes, multi-extent
fragments, legacy retention, discharged controls, and empty recovery after
catalog retirement. Existing committed-fact tests exercise failed and uncertain
final snapshots; existing processor/delivery tests cover cancellation, transport
claims, multi-destination delivery, startup/reconciliation and RADIUS semantics.

Completed checks on 2026-09-26:

- `go test -tags all,li ./internal/pkg/li/... ./internal/pkg/processor/...` passed.
- `go test -race -tags all,li ./internal/pkg/li/delivery ./internal/pkg/processor` passed.
- `go test -tags all -run '^$' ./internal/pkg/li/... ./internal/pkg/processor/...` passed.
- The subsequently added `TestX3ShortenedCutoffRejectsReorderedPermit` passed with
  `-race -tags all,li`; it adds coverage without changing production code.
- Changed Go files were formatted with `gofmt`; `git diff --check` passed.

Network/secure-store integration checks ran outside the sandbox with explicit
user authorization. No acceptance thresholds or external deployment checks were
added. One independent discovery review and one integrated post-fix review found
no remaining material authorization, retirement, replay, or concurrency issue.
The review's comment omission was fixed; immediate cancellation after terminal
fact retirement was also verified before final closure.
