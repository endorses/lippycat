# LI task-definition convergence and X1 read-back

**Status:** Proposed

**Implementation baseline:** `main` at `7ac7a1f3` or later

**Source:** LI task-definition drift review, including the 2026-10-01 follow-up

## Objective

Make LI task definitions converge across X1 pushes, ADMF snapshots, and local
restore without treating an omitted mediation window as an open-ended grant.
Repair X1 read-back for E.164 targets and make deactivation logs identify the
actual cause. Keep the existing behavior available for an ADMF that still
returns partial snapshots; enable strict handling only when its complete-task
contract has been established.

This plan contains no deployment inventory, live identifiers, target values,
destination addresses, or incident data. Tests must use synthetic definitions.

## Current code and constraints

- `internal/pkg/li/convert.go` maps a missing mediation list to zero start and
  end times and a missing implicit-deactivation flag to false.
- `internal/pkg/li/manager.go` installs snapshot tasks at startup and activates
  missing tasks during reconciliation, but does not compare held non-RADIUS
  definitions. X1 activation rejects a different active definition with error
  300. The persisted replay check requires exact definition equivalence.
- `snapshotMu` serializes local snapshot retrieval/application with X1 task
  changes. It prevents a locally fetched snapshot from overtaking a later X1
  push. It does not prove that a later ADMF response contains newer task data.
- The bundled X1 task schema has no per-task revision. Until an authoritative
  freshness signal exists, a conflicting pull must not silently replace a
  definition installed by a push or modification.
- `Registry.ModifyTask` cannot change an activated task's start time. An
  internal promotion path is needed for a partial pull followed by a full
  definition. The public X1 modification contract stays unchanged.
- The internal target type collapses E.164 into TEL URI, which can produce a
  schema-invalid `GetTaskDetails` response. A new type must preserve phone
  matching and account for persisted legacy values.

## Required behavior

1. A partial snapshot never clears a known start time, end time, or explicit
   implicit-deactivation value. An absent mediation list means unknown; a
   present, complete mediation list with no end means explicitly open-ended.
2. Compatibility mode continues to arm a new partial pull, labels its window
   unknown, and reports that it depends on explicit deactivation. Strict mode
   holds it as a non-enforcing candidate until a complete definition arrives.
   Strict mode is opt-in and documented as requiring a complete ADMF contract.
3. An X1 activation that completes a pull-owned partial task succeeds without
   error 300. It applies the full definition through the same authorization,
   filter, delivery, generation, and durable-state barriers as other task
   changes. Ordinary equivalent activation retries remain no-op reads.
4. Complete snapshots reconcile held pull-owned or restored tasks. A snapshot
   that conflicts with a push-owned definition and has no proof of freshness
   raises observable drift and leaves the pushed definition intact. An explicit
   X1 modification or a future task-revision contract can resolve that case.
5. A partial snapshot alone never confirms replay of buffered X2/X3. A later
   complete equivalent definition may confirm the persisted activation without
   admitting product from a different authorization generation.
6. X1 read-back preserves E.164 as E.164. It emits schema-valid target values,
   while TEL URIs retain their `tel:` scheme. Matching and filter admission
   must continue to behave the same for equivalent phone numbers.
7. Deactivation logs use the actual reason, with an end time for expiry. Logs
   and aggregate metrics do not include target values or destination details.
8. Keep the existing RADIUS-specific reconciliation and authorization path;
   changes to generic task convergence must not silently alter it.

## Work 1 — Represent completeness and provenance

- [ ] Add a typed snapshot conversion result that records whether mediation
      details, start, end, and implicit-deactivation fields were supplied.
      Keep omission distinct from an explicitly absent end in a complete
      mediation definition. Validate inconsistent or malformed combinations.
- [ ] Track whether the effective definition came from an X1 push/modify, an
      ADMF pull, or local restore. Persist enough provenance and completeness
      state to survive restart, without turning a restored candidate into an
      authority on its own. Migrate older state files conservatively.
- [ ] Include provenance and completeness changes in the existing
      administrative and lifecycle transactions. Remove or retire metadata
      with its task so it cannot affect reuse of an XID.
- [ ] Add an opt-in configuration setting for the complete-ADMF contract.
      Default to compatibility mode. Read the setting at startup, rather than
      switching live tasks in place. Document its effect on startup and
      reconciliation. Before enabling it, verify that held unknown-window
      tasks have been repaired or will be replaced by a complete startup
      snapshot; do not silently disarm them through a configuration change.
- [ ] In strict mode, keep a new incomplete task outside the enforcing
      registry/filter path until a complete definition arrives. In
      compatibility mode, preserve current admission but mark the window
      unknown. A partial pull of a held task must retain known fields in both
      modes.

## Work 2 — Converge task definitions safely

- [ ] Add one internal full-definition promotion operation for a pull-owned
      partial task, including a missing start time. Validate the proposed
      definition and destinations before changing live state; apply filters,
      delivery authorization, generation, and persistence atomically, with
      rollback on failure. Do not route this case through the public X1
      `ModifyTask` method, which has no start-time field.
- [ ] Use that operation when a full `ActivateTask` follows a partial pull.
      Keep the existing error 300 for a genuinely conflicting push-owned task
      and preserve idempotent behavior for equivalent retries.
- [ ] Reconcile complete definitions for held pull-owned and restored tasks.
      Use the existing modification path for fields it supports, and the
      internal promotion path when start time must be filled. Do not overwrite
      known fields from an incomplete pull. Keep RADIUS tasks on their
      existing specialized path.
- [ ] For a conflict between a complete pull and a push-owned definition,
      record drift and require an explicit X1 change unless the ADMF provides
      a monotonic task revision or another verifiable freshness guarantee.
      Do not infer freshness from the response message timestamp or local
      lock ordering. Document this limitation in operator guidance.
- [ ] Review narrowing changes to start/end, targets, delivery type, and
      destination set against queued X2/X3 and replay authorization. Cancel or
      reject buffered product that cannot be shown to belong to the resulting
      authorization; preserve a generation only when the existing lifecycle
      rules permit it.
- [ ] Keep incomplete startup snapshots from confirming persisted replay or
      removing tasks based on conversion failures. On a later complete
      snapshot, restore replay authorization only after exact authorized
      identity and generation checks.

## Work 3 — E.164 type and X1 response validity

- [ ] Add an internal E.164 target type without renumbering existing persisted
      target values. Update X1 push/pull conversion, canonical comparisons,
      registry validation, filters, direction matching, and state codec.
- [ ] Accept schema-valid E.164 wire values as 1–15 digits. Reject a
      plus-prefixed `e164Number` as invalid input unless an explicit
      compatibility rule is justified and tested; never emit an invalid
      `<e164Number>`. Keep a valid `tel:` URI as TEL URI.
- [ ] Handle legacy persisted bare-digit TEL URI values without changing their
      matching behavior or emitting invalid XML. Test how a full ADMF snapshot
      with the new E.164 type interacts with persisted activation identity and
      replay confirmation.
- [ ] Validate representative `GetTaskDetails` and related X1 responses
      against the bundled ETSI XSD, including E.164, TEL URI, and legacy state.

## Work 4 — Drift visibility and deactivation logs

- [ ] Expose aggregate counts for incomplete task definitions, pull-only
      definitions, and unresolved definition conflicts through existing LI
      status/telemetry. Distinguish unknown windows from explicitly open-ended
      tasks; avoid per-task metric labels.
- [ ] Log definition changes and unresolved conflicts with field names,
      provenance, and reason, without logging target or destination values.
      Count successful reconciliation repairs separately from unresolved
      conflicts.
- [ ] Change the processor deactivation message to a neutral phrase and a
      stable named cause (`admf`, `expired`, `fault`). Include the task end time
      only for expiry. Verify explicit ADMF deactivation is never described as
      implicit expiry.

## Verification and rollout

- [ ] Test compatibility and strict modes with synthetic complete, partial,
      and explicitly open-ended snapshots. Cover restart, missing destination,
      conversion failure, and a partial pull followed by a full push.
- [ ] Test held-task reconciliation for changed end time, targets, and
      destinations; a missing start filled by promotion; rollback on failure;
      and an outdated ADMF response returned after an X1 push. Assert no
      unauthorized filters or X2/X3 delivery during transitions.
- [ ] Test persisted candidates and replay authorization across partial then
      complete snapshots, including legacy state and activation-generation
      changes. Confirm incomplete definitions cannot authorize replay.
- [ ] Test X1 error mapping, schema-valid E.164 read-back, TEL URI read-back,
      phone matching, and named deactivation reasons. Use synthetic identifiers
      and payloads only.
- [ ] Run focused LI, X1, processor, and persistence tests with the `li` build
      tag; run relevant race tests and build processor/tap variants with and
      without LI. Record actual results without introducing performance gates.
- [ ] Document the compatibility default and the explicit precondition for
      strict mode. Before declaring old tasks repaired, verify complete
      start/end/implicit fields through a schema-valid X1 read-back or an
      equivalent authoritative check. A reassert request or error code alone
      is not proof of full repair.
- [ ] Format changed files, check off only verified plan tasks, and commit the
      code and updated plan when implementation is complete.
