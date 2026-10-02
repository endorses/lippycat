//go:build li

package li

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/google/uuid"
)

// resolveConflictAuthorization computes common authorization without mutation.
// A nil definition is an explicit empty authorization, never a set of defaults.
func resolveConflictAuthorization(held, snapshot *InterceptTask, confirmed map[uuid.UUID]bool, now time.Time) (*InterceptTask, string) {
	if held.Definition.ConflictDisarmed {
		return nil, held.Definition.ConflictReason
	}
	common := cloneInterceptTask(held)
	common.Definition.Conflict = true
	common.Definition.ConflictReason = "common_scope"
	if snapshot.StartTime.After(common.StartTime) {
		common.StartTime = snapshot.StartTime
	}
	cutoff, incoming := TaskAuthorizationCutoff(held), TaskAuthorizationCutoff(snapshot)
	if cutoff.IsZero() || (!incoming.IsZero() && incoming.Before(cutoff)) {
		cutoff = incoming
	}
	if !cutoff.IsZero() {
		common.EndTime, common.ImplicitDeactivationAllowed = cutoff, true
		common.Definition.Completeness.EndProvided = true
		common.Definition.Completeness.Implicit = true
		if !now.Before(cutoff) {
			return nil, "expired"
		}
		if !common.StartTime.IsZero() && !common.StartTime.Before(cutoff) {
			return nil, "empty_window"
		}
	} else if !common.EndTime.IsZero() && !common.StartTime.Before(common.EndTime) {
		// Nominal ends cannot create an invalid descriptive interval or expiry.
		common.EndTime = time.Time{}
		common.Definition.Completeness.EndProvided = false
	}
	common.Targets = nil
	snapshotTargets := canonicalizeTargets(snapshot.Targets)
	for _, target := range canonicalizeTargets(held.Targets) {
		if slices.Contains(snapshotTargets, target) {
			common.Targets = append(common.Targets, target)
		}
	}
	if len(common.Targets) == 0 {
		return nil, "no_common_targets"
	}
	common.DestinationIDs = nil
	for _, did := range held.DestinationIDs {
		if slices.Contains(snapshot.DestinationIDs, did) && (confirmed == nil || confirmed[did]) && !slices.Contains(common.DestinationIDs, did) {
			common.DestinationIDs = append(common.DestinationIDs, did)
		}
	}
	if len(common.DestinationIDs) == 0 {
		return nil, "no_confirmed_destinations"
	}
	if held.DeliveryType == DeliveryX2andX3 {
		common.DeliveryType = snapshot.DeliveryType
	} else if snapshot.DeliveryType != DeliveryX2andX3 && snapshot.DeliveryType != held.DeliveryType {
		return nil, "no_common_delivery"
	}
	if common.DeliveryType != DeliveryX2Only && common.DeliveryType != DeliveryX3Only && common.DeliveryType != DeliveryX2andX3 {
		return nil, "no_common_delivery"
	}
	return common, "common_scope"
}

// applyConflictAuthorizationLocked never restores broader authorization after a
// narrowing failure. Even a definitely uncommitted durable write closes the
// administrative admission barrier until restart and fresh reconciliation.
func (m *Manager) applyConflictAuthorizationLocked(held *InterceptTask, in *SnapshotTask, live bool) error {
	common, reason := resolveConflictAuthorization(held, in.Task, in.confirmedDestinations, time.Now())
	m.replayMu.Lock()
	delete(m.replayConfirmed, held.XID)
	m.replayMu.Unlock()
	if !live {
		restored := cloneInterceptTask(held)
		restored.Status = TaskStatusSuspended
		m.registry.mu.Lock()
		m.registry.tasks[held.XID] = restored
		m.registry.mu.Unlock()
	}
	if live && held.Definition.ConflictDisarmed {
		m.queueConflictReport(held)
		return nil
	}
	if common != nil && live && !m.pendingNeedsConfirmation(held.XID) && (held.Status == TaskStatusActive || held.Status == TaskStatusPending) && equivalentTaskDefinition(held, common) && held.Definition == common.Definition {
		m.queueConflictReport(held)
		return nil
	}
	// Conflict withdrawal also revokes X2 product, unlike ordinary task
	// shutdown where a previously authorized terminal IRI may drain.
	// A wider snapshot can establish a conflict without changing enforcement.
	// Do not revoke its unchanged generation: it must still admit new product.
	if !live || common == nil || !equivalentDeliveryDefinition(held, common) || authorizationWindowNarrows(held, common) {
		if err := m.notifyTaskConflict(held); err != nil {
			m.faultAdministrative(err)
			return errors.Join(err, m.filters.RemoveFiltersForTask(held.XID))
		}
	}
	var err error
	if common == nil {
		err = m.disarmConflictLocked(held, reason)
	} else {
		err = m.promoteTaskDefinitionLocked(common)
	}
	if err != nil {
		// A failed filter transaction may have compensated to the old filters;
		// they must not regain authority merely because the transaction rolled back.
		m.faultAdministrative(err)
		cleanupErr := m.filters.RemoveFiltersForTask(held.XID)
		m.notifyTaskModified(held)
		return errors.Join(err, cleanupErr)
	}
	current, err := m.registry.GetTaskDetails(held.XID)
	if err != nil {
		return err
	}
	m.queueConflictReport(current)
	return nil
}

func (m *Manager) disarmConflictLocked(held *InterceptTask, reason string) error {
	previous, err := m.registry.GetTaskDetails(held.XID)
	if err != nil {
		return err
	}
	if previous.Definition.ConflictDisarmed {
		return nil
	}
	closed := cloneInterceptTask(previous)
	closed.Definition.Conflict = true
	closed.Definition.ConflictDisarmed = true
	closed.Definition.ConflictReason = reason
	closed.Status = TaskStatusSuspended
	closed.LastError = "task definition conflict: " + reason
	if closed.ActivationGeneration == ^uint64(0) {
		return fmt.Errorf("%w: task generation exhausted", ErrInvalidTask)
	}
	closed.ActivationGeneration++
	if m.stateStore != nil {
		return m.commitPersistentTaskDefinitionLocked(previous, closed)
	}
	m.registry.mu.Lock()
	m.registry.tasks[closed.XID] = closed
	m.registry.generations[closed.XID] = max(m.registry.generations[closed.XID], closed.ActivationGeneration)
	m.registry.mu.Unlock()
	m.notifyTaskModified(previous)
	if err := m.filters.RemoveFiltersForTask(closed.XID); err != nil {
		return err
	}
	m.notifyCommittedTask(closed)
	return nil
}

// resolveDisarmedConflictLocked applies an explicit authenticated mutation to a
// diagnostic-only suspended definition. It validates in a detached view, then
// uses promotion to publish a fresh generation and policy atomically.
func (m *Manager) resolveDisarmedConflictLocked(xid uuid.UUID, mod *TaskModification) error {
	view := m.prospectiveRegistry(xid)
	previous, err := view.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	view.tasks[xid].Status = TaskStatusPending
	if err := view.ModifyTask(xid, mod); err != nil {
		return err
	}
	candidate, err := view.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	candidate.Definition.Conflict, candidate.Definition.ConflictDisarmed = false, false
	candidate.Definition.ConflictReason = ""
	// The promotion helper can validate a suspended conflict only in its private
	// view. Existing suspended tasks outside this policy remain non-modifiable.
	if !previous.Definition.ConflictDisarmed {
		return ErrModifyNotAllowed
	}
	return m.promoteTaskDefinitionLocked(candidate)
}
