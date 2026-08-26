# LI tombstone reactivation and lifecycle observability

**Date:** 2026-08-26  
**Code baseline:** `1290487` (`v0.10.2`)  
**Scope:** Explicit X1 task reactivation, activation rollback bookkeeping, and
externally observable task lifecycle state

## 1. Objective

Allow an explicit, authenticated activation request to replace a retained
deactivated task with the same XID when the interception identity is unchanged.
The replacement must pass normal activation validation, install enforcement
filters transactionally, retain the prior deactivation in audit history, and
remain distinguishable from an active task through the X1 status response.

This plan supersedes only the decision in
`docs/plans/etsi-li-interoperability-remediation-2026-08-26.md` that all
activations against a deactivated task must conflict. Active and pending retry
idempotency, and fail-closed handling of suspended and failed tasks, remain
unchanged.

## 2. Required invariants

1. A retained tombstone cannot become enforcing without a new explicit
   activation request.
2. Reactivation is allowed only when the canonical target identifiers and
   delivery type are unchanged.
3. A reactivation may provide a new destination set, mediation window, and
   lifecycle options; the complete proposed task must pass current activation
   and capability validation.
4. Changed targets under a retained XID fail closed and return an X1 error that
   is not error 300 (`XIDAlreadyExists`).
5. Activation failure leaves the tombstone, audit history, rollback state,
   generation, filters, and persisted state logically unchanged.
6. Activation success increments the activation generation, installs exactly
   the filters for the new activation, and preserves the previous deactivated
   task in audit history.
7. Task-detail responses expose whether a provisioned task is pending, active,
   suspended, deactivated, or failed without assigning a non-standard value to
   the closed `ProvisioningStatus` enumeration.
8. Existing active and pending duplicate-activation behavior remains a pure,
   idempotent read for equivalent definitions.

## 3. Non-goals

- Automatically reactivating a task during startup, reconciliation, or
  tombstone maintenance.
- Reactivating suspended or failed tasks through `ActivateTask`.
- Changing the meaning or retention period of deactivated tombstones.
- Treating a target change as a modification or silently assigning it a new
  interception identity.
- Extending the standard `ProvisioningStatus` enumeration.
- Redesigning task persistence or the general audit subsystem.

## 4. Phase 1 — Define reactivation identity and errors

### 4.1 Add a dedicated comparison

Add a comparison specifically for reactivation. Do not reuse
`equivalentTaskDefinition`, because ordinary retry identity includes mediation
times and destinations that are intentionally replaceable during reactivation.

Implementation tasks:

- [x] Extract shared target canonicalization from `activation_identity.go`
      rather than maintaining two subtly different sorting implementations.
- [x] Add a dedicated reactivation identity comparison that compares XID and
      delivery type.
- [x] Compare target type and value pairs after the same canonical sorting and
      duplicate handling used by activation identity.
- [x] Treat target order as insignificant.
- [x] Exclude destination IDs, mediation start/end, and lifecycle options from
      reactivation identity.
- [x] Ensure canonicalization and comparison do not retain aliases to
      caller-owned slices.

### 4.2 Introduce an explicit conflict

- [x] Add a dedicated sentinel error for a reactivation whose protected
      identity fields differ.
- [x] Preserve the sentinel through `managerTaskAdapter` so the X1 layer can
      map it independently from an ordinary duplicate XID.
- [x] Map the conflict to a standards-valid error other than 300. Unless a more
      specific existing protocol code is justified during implementation, use
      generic request failure code 100 with a stable description stating that
      the retained task's interception identity differs.
- [x] Do not introduce an unregistered numeric X1 error code solely for this
      case.
- [x] Test the internal contract with `errors.Is` and test the complete X1
      response mapping separately.

## 5. Phase 2 — Make registry reactivation validation atomic

`Registry.ActivateTask` currently stores the prior tombstone in `rollbackTask`
and appends it to `auditHistory` before validating destination references. Move
all fallible validation ahead of those mutations.

Implementation tasks, in mutation order:

- [ ] Validate the task structure and supported capabilities before mutating
      registry state.
- [ ] Lock the registry and inspect the current XID state.
- [ ] Validate every destination reference and task/destination delivery
      combination while holding the same lock used for the eventual mutation.
- [ ] Deep-copy the prior deactivated task into rollback state and audit history
      only after all validation succeeds.
- [ ] Deep-copy the replacement task, assign activation time and the next
      generation, and store it as pending or active.
- [ ] Commit the activation only after pending registration or successful
      filter installation.
- [ ] Ensure errors before rollback bookkeeping cause zero registry mutation.
- [ ] Ensure manager-level failures after provisional activation restore the
      tombstone and remove the provisional audit entry through
      `rollbackActivation`.
- [ ] Define and document generation behavior for failed reactivation attempts.
      If counters remain monotonic across failed attempts, ensure persisted and
      externally visible task state still cannot appear to have activated.

## 6. Phase 3 — Enable explicit reactivation in the manager

Update `Manager.activateTask` lifecycle dispatch as follows:

- [ ] Preserve existing canonical retry behavior for `Active` and `Pending`.
- [ ] Preserve the existing definition conflict for `Suspended` and `Failed`.
- [ ] For `Deactivated`, compare the protected reactivation identity.
- [ ] Return the new reactivation conflict on an identity mismatch without
      changing registry, filters, persistence, or audit state.
- [ ] On an identity match, continue through the ordinary registry activation,
      filter-installation, commit, logging, and persistence path.
- [ ] Continue to fail closed for unknown lifecycle states.
- [ ] Keep the normal transactional activation and rollback path as the single
      filter-enforcement path; do not create a separate reactivation installer.
- [ ] Add structured lifecycle logging that distinguishes reactivation from
      initial activation without logging target values. Include XID, previous
      and new generation, resulting state, destination count, and filter count
      where available.

## 7. Phase 4 — Expose lifecycle state through task status extensions

Implementation tasks:

- [ ] Preserve the schema-conformant provisioning mapping: pending to
      `awaitingProvisioning`, failed to `failed`, and active, suspended, and
      deactivated to `complete`.
- [ ] Define a `taskStatusExtensions` wire contract using a stable,
      project-controlled XML namespace and owner identifier.
- [ ] Define a versioned extension element or structure.
- [ ] Encode one of `pending`, `active`, `suspended`, `deactivated`, or `failed`.
- [ ] Keep the extension optional so peers that ignore unknown extensions
      remain compatible.
- [ ] Include the extension consistently in `GetTaskDetails` responses for
      every task state.
- [ ] Avoid exposing internal errors or sensitive operational details beyond
      the existing fault response.
- [ ] If generated schema types cannot marshal the extension body, add the
      smallest handwritten wire type or custom marshaling boundary needed.
- [ ] Do not modify bundled ETSI schemas to add a project-specific element.
- [ ] Document the extension namespace, version, values, and its role as an
      operational enforcement-state signal rather than a replacement for
      provisioning status.

## 8. Tests

### 8.1 Registry and manager tests

- [ ] Activate, deactivate, and reactivate the same XID with an identical task;
      assert success, active state, one generation increment, and installed
      filters.
- [ ] Reactivate with reordered or duplicate-equivalent targets; assert the
      chosen canonical duplicate policy is applied consistently.
- [ ] Reactivate with a changed target type, target value, added target, or
      removed target; assert the dedicated conflict and no state mutation.
- [ ] Reactivate with a changed delivery type; assert the dedicated conflict and
      no state mutation.
- [ ] Reactivate with a changed destination set and valid renewed mediation
      window; assert success and filters matching the replacement task.
- [ ] Reactivate with changed lifecycle options and otherwise stable identity;
      assert the replacement options are stored and enforced.
- [ ] Reactivate with a missing destination or incompatible delivery
      combination; assert the tombstone, `rollbackTask`, `auditHistory`, filters,
      and persistence remain unchanged.
- [ ] Inject filter creation and commit failures; assert the tombstone and its
      prior audit history are restored and no replacement filters remain.
- [ ] Assert successful reactivation retains one audit snapshot of the prior
      deactivated task.
- [ ] Assert suspended and failed tasks still reject activation.
- [ ] Assert active and pending equivalent retries retain their existing
      side-effect-free behavior.
- [ ] Exercise concurrent deactivate/reactivate and duplicate-reactivation
      attempts under the race detector; assert lifecycle serialization and one
      committed activation.
- [ ] Repeat successful and failed reactivation after durable state restoration.

### 8.2 X1 tests

- [ ] Changed protected identity maps to the selected non-300 response code and
      stable error description.
- [ ] An ordinary conflicting active/pending XID retains its current error-300
      behavior.
- [ ] Missing destinations and unsupported delivery combinations retain their
      existing specific response codes.
- [ ] Task details marshal a valid lifecycle extension for all five internal
      states while retaining schema-valid provisioning values.
- [ ] The extension has the documented owner, namespace, version, and value.
- [ ] A schema-aware round trip preserves the extension, and a peer that ignores
      it can still parse the rest of the response.

## 9. Documentation and compatibility updates

- [ ] Update lifecycle documentation to distinguish idempotent retry from
      explicit reactivation of a tombstone.
- [ ] Document which fields form protected reactivation identity and which may
      be replaced.
- [ ] Document the non-300 changed-identity response contract.
- [ ] Document the task-status extension wire format and monitoring semantics.
- [ ] Update the earlier interoperability plan's implementation-status section
      so it no longer claims that deactivated tasks always conflict.
- [ ] Review examples and runbooks that describe deactivate/reactivate recovery
      to ensure they include destination provisioning order and error handling.

## 10. Verification

- [ ] Run the focused registry, manager, and X1 tests added by this plan.
- [ ] Run the race-enabled LI suite:

```text
go test -race -tags 'all,li' ./internal/pkg/li/...
```

- [ ] Run the complete tagged repository suite:

```text
go test -tags 'all,li' ./...
```

- [ ] Run vet for the LI packages:

```text
go vet -tags 'all,li' ./internal/pkg/li/...
```

- [ ] Verify that LI code remains excluded from non-LI builds:

```text
make verify-no-li
```

- [ ] Check the final diff for whitespace errors:

```text
git diff --check
```

- [ ] Build the complete, processor-LI, and tap-LI variants to ensure the
      lifecycle extension and new errors do not leak into or break non-LI
      builds.

## 11. Acceptance criteria

The work is complete when:

1. An explicit activation can replace a retained deactivated task with the same
   protected interception identity inside the tombstone-retention window.
2. A changed target or delivery type fails closed with a response other than
   error 300 and causes no enforcement or state mutation.
3. Valid destination and mediation-window changes succeed through the normal
   transactional activation path.
4. Every activation failure restores the exact pre-request operational state
   and leaves no false audit event for a completed activation.
5. Successful reactivation preserves the prior deactivation in audit history
   and installs only the new activation's filters.
6. `GetTaskDetails` exposes the internal lifecycle state through a documented,
   schema-compatible extension while retaining conformant provisioning status.
7. Existing active/pending retry semantics and suspended/failed fail-closed
   behavior have no regressions.
8. Race-enabled LI tests, tagged repository tests, vet, non-LI exclusion checks,
   and required LI builds pass.
