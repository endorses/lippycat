# LI conflict authorization and X1 reporting

Status: complete. Implementation and required verification passed on 2026-10-02;
the completed checklist and evidence are recorded below.

## Purpose and baseline

Address the findings from the 2026-10-01 follow-up verification of commit
`702c2c3f` (`fix(li): close task drift and TCP SIP verification gaps`). This plan
contains the findings, implementation decisions, and acceptance cases; it does
not depend on a report outside the repository.

The earlier follow-up is recorded in
[tcp-sip-task-drift-verification-followup.md](tcp-sip-task-drift-verification-followup.md).
Its decision to retain the full pushed definition on every conflict is
superseded by the conservative enforcement policy below. Preserve the completed
TCP SIP fixes, optional implicit-deactivation flag handling, first-push
promotion, legacy TEL read-back, and explicit-deactivation restoration behavior.

This is a correctness and authorization change. Do not add latency, throughput,
soak, memory, or other performance acceptance gates.

## Findings

The behavior described here is the reviewed baseline at `702c2c3f`.

| Finding                                                                  | Current behavior and consequence                                                                                                                                                                                                                                                                                                                                                        |
| ------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| V1 — conflicting definitions can enforce excessive scope                 | `applySnapshotDefinition` re-arms a persisted push-owned definition whenever a complete snapshot differs. The live path likewise preserves it. A shorter window, removed target, removed task destination, or withdrawn delivery type in the snapshot is ignored. Checking that a DID exists globally does not establish that the task is authorized to use it.                         |
| V2 — invalid outbound conflict report                                    | `ReportTaskError` emits `taskReportType=Error`, which the bundled XSD excludes. Schema tests manually construct `Warning` messages rather than exercising the actual reporting methods. Other outbound helpers need the same validation coverage.                                                                                                                                       |
| V3 — notification suppression survives failed delivery and restart       | The persisted `Conflict` bit suppresses later warnings and reports. Existing bounded HTTP retries can exhaust without acknowledgment, after which restart still does not re-report the conflict.                                                                                                                                                                                        |
| V4 — partial snapshot recovery and concurrency evidence                  | A conversion failure suppresses all orphan removal indefinitely, even when some absence decisions could be established independently. Failing entries appear in logs but not status, and startup warnings repeat on every retry. The concurrent first-push test signals before entering the operation and does not deterministically exercise a push waiting behind the snapshot fetch. |
| V5 — existing explicit-deactivation state changes behavior after upgrade | An elapsed `EndTime` with implicit deactivation disabled now retains its generation through restore. This matches runtime policy and must remain covered and documented; restoration still requires ADMF confirmation before enforcement or replay.                                                                                                                                     |

Without a revision marker, snapshot freshness cannot be proven. V1 therefore
adopts a conservative policy for conflicting evidence; it does not assume every
pull is newer than every push. Disabling `--li-state-file` avoids the new restart
path but does not fix the live conflict path.

## Implementation order

- [x] Implement V1 authorization resolution and transactional revocation first;
      verify the live and restored cases before treating persistence as ready
      for rollout.
- [x] Correct and validate the V2 outbound X1 contract, then implement V3
      notification recovery using validated acknowledgments.
- [x] Implement V4 membership evidence, bounded diagnostics, and deterministic
      concurrency coverage.
- [x] Complete V5 documentation and the final verification checklist, recording
      evidence before closing the corresponding items.

## V1: enforce only common authorized scope

Apply the same resolution to a complete conflicting snapshot for a restored or
live generic push-owned task. An enforcing result must be no broader than either
the currently held definition or the snapshot definition. A wider snapshot alone
must never expand a pushed task. Partial snapshots must not be interpreted as
explicit removal of omitted fields.

### Resolution rules

| Dimension             | Resolution                                                                                                                                                                                                                                                                                                           |
| --------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Start                 | Use the later known start. A zero start that already means no lower bound must retain that meaning.                                                                                                                                                                                                                  |
| Cutoff                | Use the earlier finite effective cutoff from `TaskAuthorizationCutoff`; an absent cutoff is unbounded. Do not compare raw end timestamps without their implicit-deactivation policy.                                                                                                                                 |
| Implicit deactivation | A selected finite cutoff must be enforced with implicit deactivation enabled. If both definitions are effectively unbounded, do not invent expiry from a nominal end whose flag is false. Preserve compatible descriptive fields without letting them alter the effective window.                                    |
| Targets               | Intersect identities using the existing canonical target representation and established equivalences, including legacy bare-digit TEL/E.164 equivalence. Do not introduce new CIDR, SIP, or phone-pattern overlap inference. Unmatched selectors are excluded, even if a more elaborate matcher could prove overlap. |
| Destinations          | Intersect the two tasks' own destination-ID lists, then require the retained destinations to be successfully confirmed by the snapshot's destination definitions. Global destination existence is an additional condition, not task membership.                                                                      |
| Delivery              | Intersect allowed product types: `X2andX3` with `X2Only` yields `X2Only`, and with `X3Only` yields `X3Only`. `X2Only` with `X3Only` has no authorized delivery.                                                                                                                                                      |

An empty target set, destination set, delivery set, or effective time window
means no enforcement. An already elapsed finite cutoff also means no
enforcement. Do not pass an empty intersection through defaults that restore
the old scope or select an arbitrary delivery type. A future start produces a
pending task without capture filters until the normal activation boundary.

Repeated snapshots may further restrict a conflict but cannot re-expand it.
An accepted authenticated X1 mutation is required to expand or explicitly
resolve the conflicted definition. Keep push provenance and persisted conflict
state; do not relabel the conservative result as a fresh, unconflicted pull.
Keep replay unconfirmed while the conflict remains unresolved, including across
restart. Explicit resolution must still obey existing replay and generation
requirements; it does not automatically authorize historical product.

- [x] Add a pure resolution helper returning a validated common definition or
      an explicit no-enforcement result, with fixed reason categories.
- [x] Apply it in both restored and live push-conflict paths. Retain the existing
      behavior for partial snapshots and first complete pushes over pull-owned
      tasks. Keep RADIUS on its specialized authorization path.
- [x] Route nonempty narrowing through the existing administrative transaction,
      filter update, lifecycle admission, persistence, and generation machinery.
      Inspect `promoteTaskDefinitionLocked` rather than assuming a metadata
      replacement or its current failure compensation is sufficient.
- [x] On empty or expired results, withdraw filters and stop delivery through
      existing durable deactivation/revocation mechanisms while preserving
      conflict diagnostics. Avoid conflating this cause with an X1 command or
      an ordinary implicit-expiry notification.
- [x] Invalidate old-generation admission and affected queued/in-flight delivery
      at the existing commit boundary. Cover X2, X3, memory queues, and durable
      journals; already completed writes cannot be recalled.
- [x] Ensure failed narrowing cannot silently resume the broader definition.
      Use existing administrative fault/admission barriers when durable outcome
      or filter withdrawal is uncertain. Propagate and expose the failure.
- [x] Persist enough effective definition and conflict information that another
      restart cannot restore the broader scope. Preserve state compatibility;
      add migration coverage if serialization needs new fields.
- [x] Define and test explicit X1 conflict resolution, idempotent repeat pulls,
      and replay withholding. An exact match to an already narrowed effective
      definition must not accidentally erase unresolved conflict state.

### Required authorization regressions

Run each relevant scenario both with restored persistent state and against a
live task. Assert effective definitions, filters, generation behavior, and
delivery/replay outcomes, not merely successful API returns.

- [x] Snapshot shortens a future cutoff; snapshot cutoff has already elapsed.
- [x] Snapshot advances the start; resulting start is future or beyond cutoff.
- [x] A nominal earlier end with implicit deactivation false cannot erase the
      other definition's later but effective cutoff. Cover both orientations,
      equal end timestamps with differing flags, and both-unbounded definitions.
- [x] Snapshot removes one target and then all common targets.
- [x] Snapshot removes a task destination while that DID still exists globally;
      retained DID missing or failing confirmation; no common destination.
- [x] `X2andX3` narrows to each single delivery type; disjoint delivery types
      leave no enforcement.
- [x] Snapshot widens all dimensions; mixed widening and narrowing across
      dimensions; repeated pulls cannot undo an earlier restriction.
- [x] Delayed complete snapshot after an X1 mutation; explicit authenticated
      resolution; restart before and after resolution; conflict never confirms
      old replay merely because the effective definition matches a later pull.
- [x] Inject persistence and filter failures during narrowing and disarming;
      exercise queued-product revocation and concurrent packet admission.

## V2: validate actual outbound X1 requests

Use the bundled `internal/pkg/li/x1/xsd/TS_103_221_01.xsd` and imported schemas as
the wire contract. A valid error code does not make an invalid report-type enum
valid. Report schema version and method coverage in the verification record.

- [x] Provide a schema-valid warning path for definition conflicts. Replace the
      invalid `Error` report type with appropriate semantic categories;
      nonterminating task faults use `NonTerminatingFault`, while actual
      terminating faults and completion reports use their matching categories.
- [x] Inventory every public outbound client helper and its callers: task,
      destination, NE startup/shutdown/error/recovery reports, keepalive, and
      detail queries. Check actual emitted enums, required fields, envelopes,
      namespaces, identifiers, and timestamps against the bundled schema.
- [x] Validate captured HTTP request bodies produced by those real methods with
      the required `xmllint` harness. Do not substitute hand-built valid messages
      for the production builders. Cover retry attempts where request metadata
      must be regenerated.
- [x] Use realistic schema-valid success and error responses in reporting tests.
      Ensure rejection, malformed responses, and incorrect acknowledgments are
      failures rather than evidence that the ADMF accepted the conflict report.
- [x] Retain response/read-back schema tests and E.164 input validation.

## V3: separate conflict state from report delivery state

Persisted conflict state describes enforcement uncertainty, not successful
notification. Re-report unresolved conflicts after restart and retry failed
notifications during the current process lifetime without warning on every poll.

- [x] Track notification state separately, scoped to the task and conflict
      episode. Reset acknowledgment state on restart; a restored unresolved
      conflict becomes reportable again once its current state is established.
- [x] Allow at most one report attempt in flight per task/episode. Integrate
      bounded retries with the existing client/reconciliation machinery; avoid
      an unbounded goroutine or timer per failed poll.
- [x] Mark reporting complete only after a valid successful acknowledgment.
      Failed delivery remains eligible for retry; conflict resolution cancels
      obsolete work. A late acknowledgment must not acknowledge a newer conflict.
- [x] Tie report work to manager cancellation and shutdown. Bound bookkeeping
      by the managed task/conflict set and remove entries when no longer needed.
- [x] Log conflict entry, restoration, meaningful changes, and recovery without
      repetitive per-poll warnings. Preserve aggregate conflict visibility even
      after acknowledgment and exclude selectors from public diagnostics.
- [x] Test failed delivery then recovery, successful acknowledgment suppression,
      restart re-reporting, concurrent polls, superseded acknowledgments, task
      removal, and shutdown during retry.

## V4: partial-snapshot reconciliation and deterministic ordering

Separate evidence that an identifier list is complete from successful conversion
of every definition. A known malformed task entry is still evidence that its
XID is present; it need not prevent proving that a different XID is absent.
An unidentified entry, failed request, missing required list, or ambiguous
snapshot must not be treated as proof of absence.

- [x] Record validated task and destination membership independently of entry
      conversion/application. Track identifier-enumeration uncertainty separately
      from definition failures, including duplicate/conflicting entries.
- [x] Permit task orphan reconciliation only where the response establishes
      reliable task membership, using the existing consecutive-poll threshold
      and zero-task recovery guard. A destination-definition failure alone must
      not invalidate otherwise reliable task membership.
- [x] Keep listed-but-unconvertible tasks out of inferred orphan deletion.
      Preserve suppression where identity enumeration is uncertain. Destination
      cleanup must additionally respect retained task references and its own
      membership evidence.
- [x] Expose bounded structured failure diagnostics in startup/reconciliation
      status: task/destination counts, fixed failure categories, entry index,
      and validated UUID where available. Include an explicit indication when
      details are truncated and when orphan removal is suppressed. Never expose
      raw malformed identifiers, selectors, destinations' addresses, or remote
      response text. Keep aggregate metrics free of per-task labels.
- [x] Bound and deduplicate failure bookkeeping; prevent an indefinitely failing
      snapshot from growing diagnostic state. Reuse existing configured bounds
      where applicable, and document any new diagnostic-only bound.
- [x] Limit repeated identical startup/reconciliation warnings while preserving
      retry attempts, state-change warnings, and a recovery message. Keep retry
      behavior independent of whether another warning is emitted.
- [x] Test known malformed entries alongside determinably absent tasks, unknown
      identifiers that still suppress deletion, independent destination errors,
      empty-list recovery protection, status serialization/privacy, and recovery.
- [x] Make `TestConcurrentCompleteStaleSnapshotThenFirstPush` exercise the
      blocking interleaving deterministically with a controlled synchronization
      seam. Observe the push contending while the fetch holds `snapshotMu`,
      release the fetch, then verify push application and later-pull behavior.
      A sleep or signal before invoking the push is insufficient evidence.

## V5, documentation, and rollout

- [x] Keep elapsed-end tasks with implicit deactivation disabled by policy
      eligible for restoration with their generation retained, subject to ADMF
      confirmation. Preserve the implicit-expiry disarming regression.
- [x] Document that such existing state may re-arm after upgrade, the new
      conservative conflict policy, empty-intersection behavior, explicit X1
      resolution, replay restrictions, and notification acknowledgment/retry.
- [x] Update `docs/LI_INTEGRATION.md` and the earlier follow-up plan's retained-
      authority description to point to the superseding behavior. Document new
      status fields and any state compatibility considerations.
- [x] Recommend withholding persistence rollout until V1 is fixed and verified;
      explicitly explain that the live conflict path also needs the correction.
      Do not change deployment configuration or contact production ADMFs as
      part of implementation or verification.

## Verification and completion

- [x] Run focused authorization, persistence, X1 schema, notification, and
      reconciliation tests as each area changes, including the matrices above.
- [x] Run affected LI, processor, statusclient, and process/tap command suites
      with race detection and appropriate role/LI build tags. Preserve coverage
      of the three previously unstable processor LI tests and the real raw-XML
      push-after-pull test.
- [x] Verify processor and tap builds with and without LI. Regenerate protobuf
      code if status changes require it; preserve existing field numbers and
      check wire/JSON compatibility and LI-disabled omission.
- [x] Record actual commands, results, limitations, and any state migration in
      this file. Preserve independent expiry, destination authorization,
      cryptographic, configured resource-limit, and replay checks.
- [x] Format changed files, check off only verified implementation items, clean
      temporary caches/artifacts, and commit implementation and updated plan.

The plan is complete when the identified conflict paths cannot enforce beyond
the common scope, actual outbound messages validate, unresolved reports recover
from delivery failure/restart, and partial snapshot diagnostics and safe
reconciliation behavior are covered. Unknown or malformed enumeration may still
require operator correction or explicit X1 deactivation; do not claim its
absence can be proven or invent an automatic timeout-based authorization policy.

## Implementation and verification record (completed 2026-10-02)

The implementation includes the common-scope resolver and disarmed-conflict state,
schema-valid X1 builders and acknowledgment validation, managed conflict-report
retries, independent snapshot membership evidence, bounded reconciliation status,
and operator documentation. The final affected race suites, durable delivery
regressions, and all four role/LI builds passed.

Regression evidence is maintained in the repository:

| Scope                                                                                                                       | Evidence                                                                                                                                                              |
| --------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Live, persistent, and restored common authorization; expiry, canonical targets, task DID membership, interface intersection | `internal/pkg/li/conflict_authorization_test.go`, including `TestConflictAuthorizationMatrix` and effective-cutoff cases                                              |
| Explicit resolution, generation/replay barriers, persistence/filter/transport faults, old state compatibility               | The same file's resolution, narrowing-failure, state-codec, admission, and deactivation tests                                                                         |
| Actual X1 requests and validated acknowledgments                                                                            | `internal/pkg/li/x1/client_contract_test.go`: 21 helper paths, initial and retry requests validated with `xmllint` against bundled TS 103 221-1 V1.22.1 and imports   |
| Retry, stale acknowledgment isolation, restart notification, shutdown and administrative cancellation                       | `conflict_reporting_test.go`, `conflict_reporting_lifecycle_test.go`, and restored-renewal verification in `definition_verification_test.go` under `internal/pkg/li/` |
| Safe partial-snapshot orphan decisions, status bounds/privacy, warning deduplication                                        | `internal/pkg/li/snapshot_sync_test.go`, processor mapping and statusclient wire/JSON tests                                                                           |
| Queued and in-flight X2/X3 revocation, durable controls and restart                                                         | `internal/pkg/li/delivery/conflict_revocation_test.go` and `internal/pkg/processor/processor_li_conflict_test.go`                                                     |

Observed verification:

- [x] `go test -race -tags li ./internal/pkg/li/x1 -run '^(TestOutboundHelpersConformToBundledXSD|TestReportAcknowledgmentRequired)$' -count=1 -timeout 60s` passed for the production builders and acknowledgment validator.
- [x] Focused authorization, notification, reconciliation/status, and RADIUS
      lifecycle race tests passed. The complete affected suites below also
      passed after the final implementation changes.
- [x] `go test -race -tags li ./internal/pkg/li/delivery -run '^Test(ConflictRevocation|LegacyJournalConflictRevocation)' -count=1 -timeout 90s`
      passed (delivery: 3.297s).
- [x] `go test -race -tags 'tap li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/tap/...`
      passed (LI: 42.312s; delivery: 66.136s; processor: 71.986s).
- [x] `go test -race -tags 'all li' ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/process/...`
      passed (processor: 117.074s).
- [x] `go build -tags processor`, `go build -tags tap`,
      `go build -tags 'processor li'`, and `go build -tags 'tap li'`
      each passed with temporary binary output paths.
- [x] `go vet -tags 'all li' ./internal/pkg/li/... ./internal/pkg/processor/... ./internal/pkg/statusclient/... ./cmd/process/... ./cmd/tap/...`
      passed. Changed Go and Markdown files are formatted; `git diff --check`
      passed.
- [x] Remove the task-specific temporary build cache and verification binaries;
      commit the implementation and completed plan together.

The final runtime commands ran with approved outside-sandbox execution. The
previous environment denied local sockets and presented ancestor ownership that
encrypted-state fixtures rejected. Those restrictions were resolved through
execution permissions; fixture security checks were preserved. Test duration is
recorded as evidence only, with no performance acceptance target.

The processor suites include the wider-snapshot live-delivery regression,
X2/X3 conflict revocation in memory and durable queues, and the previously
unstable `TestRADIUSTapPOITLSFixtureAndShutdown`,
`TestProcessorX3CommittedTimingPolicy`, and
`TestProcessorX3ExplicitDeactivationHeldReplay`. The LI suite includes
`TestRawX1OpenPushAfterPartialPull`, lifecycle report cancellation,
persistence/restore, and deterministic snapshot ordering. Earlier fixture and
orphan-expectation corrections retain the authorization assertions and now pass
in the full suites.

Compatibility: existing state files lacking the new optional conflict fields
remain readable; new writes include fields rejected by older strict decoders.
The new processor protobuf field is 17 (`li_reconciliation`); existing field
numbers are retained, and the JSON object is omitted when unavailable. No
deployment configuration has been changed and no production ADMF has been used.

Verified delivery behavior includes preserving live delivery for an unchanged
generation when the conflicting snapshot is wider, cleanup of disarmed orphan
conflicts and their reporting state, multi-journal capacity preflight,
cancellation on conflict-gate exhaustion, and conflict revocation for X2-only
journaling without administrative persistence. Ordinary deactivation continues
to retain X2 signaling.

### Bounded closure decision

The single closure campaign found two implementation defects and completed one
repair batch and one integrated post-fix review. No supplemental defect was found.
The final execution evidence closes the earlier environment blocker without a
new discovery audit.

| Finding                                                                                     | Repair and evidence                                                                                                                                                                                                                                                                                                                                     | Disposition |
| ------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| F01: segmented-only revocation rejected per-record X2-only journals                         | Per-record owners gate stale admissions, drain pending writes, and revoke through existing authenticated deletion and directory sync. No migration, format, or minimum-capacity change. Partial retirement faults the owner with an uncertain outcome. Per-record and dual-journal restart/failure regressions and the full delivery race suite passed. | Closed      |
| F02: periodic RADIUS dispatch lost activation fallback and specialized replacement handling | Restored the handled/fallback contract. `TestSnapshotRADIUSLifecycleRouting` covers new activation, both replacement directions, and rejected changed-start withdrawal in both directions. Focused and full LI race suites passed.                                                                                                                      | Closed      |
| F03: required final runtime evidence unavailable                                            | Approved outside-sandbox execution allowed the encrypted-state, socket, delivery, and processor regressions to run with existing security checks intact. All required commands above passed.                                                                                                                                                            | Closed      |

Closure outcome: **CLOSED**. All identified implementation findings and required
verification are complete. The implementation and this plan are committed
together.
