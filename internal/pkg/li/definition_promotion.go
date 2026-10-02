//go:build li

package li

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// promoteTaskDefinitionLocked replaces a held generic task's full definition,
// including StartTime, which is deliberately unavailable to public ModifyTask.
// The caller establishes provenance authority and holds adminMu and lifecycleMu.
func (m *Manager) promoteTaskDefinitionLocked(task *InterceptTask) error {
	if task == nil || IsRADIUSTask(task) {
		return ErrInvalidTask
	}
	if err := m.unfinishedSubjectLocked(task.XID, uuid.Nil); err != nil {
		return err
	}
	view := m.prospectiveRegistry(task.XID)
	previous, err := view.GetTaskDetails(task.XID)
	if err != nil {
		return err
	}
	if IsRADIUSTask(previous) || previous.Definition.ConflictDisarmed {
		return ErrModifyNotAllowed
	}
	if previous.Status == TaskStatusSuspended {
		// Restored definitions are validated without
		// opening the live admission barrier.
		view.tasks[task.XID].Status = TaskStatusPending
	}
	// Changing the start only in this private view allows shared modification
	// validation to check the proposed complete window and destination set.
	view.tasks[task.XID].StartTime = task.StartTime
	mod := &TaskModification{
		Targets: &task.Targets, DestinationIDs: &task.DestinationIDs,
		DeliveryType: &task.DeliveryType, EndTime: &task.EndTime,
		ImplicitDeactivationAllowed: &task.ImplicitDeactivationAllowed,
		definition:                  &task.Definition,
	}
	if err := view.ModifyTask(task.XID, mod); err != nil {
		return err
	}
	candidate, err := view.GetTaskDetails(task.XID)
	if err != nil {
		return err
	}
	candidate.Definition = task.Definition
	if previous.Definition.Conflict && !candidate.Definition.Conflict {
		candidate.LastError = ""
	}
	if (authorizationWindowNarrows(previous, candidate) || previous.Status == TaskStatusSuspended) && candidate.ActivationGeneration == previous.ActivationGeneration {
		if view.generations[task.XID] == ^uint64(0) {
			return fmt.Errorf("%w: task generation exhausted", ErrInvalidTask)
		}
		view.generations[task.XID]++
		candidate.ActivationGeneration = view.generations[task.XID]
	}
	candidate.Status = TaskStatusPending
	if candidate.ShouldStart() {
		candidate.Status = TaskStatusActive
	}
	if m.stateStore != nil {
		if err := m.commitPersistentTaskDefinitionLocked(previous, candidate); err != nil {
			return err
		}
		m.registry.mu.Lock()
		delete(m.registry.unconfirmedPending, task.XID)
		m.registry.mu.Unlock()
		return nil
	}
	// Delivery admission stays closed under lifecycleMu while filter mutation
	// either commits or compensates. Consume generations even on failed attempts.
	m.registry.mu.Lock()
	m.registry.generations[task.XID] = max(m.registry.generations[task.XID], candidate.ActivationGeneration)
	m.registry.mu.Unlock()
	if candidate.Status == TaskStatusActive {
		err = m.filters.UpdateFiltersForTask(candidate)
	} else if previous.Status == TaskStatusActive {
		err = m.filters.RemoveFiltersForTask(task.XID)
	}
	if err != nil {
		var cleanupErr *FilterCleanupError
		if errors.As(err, &cleanupErr) || (previous.Status == TaskStatusActive && candidate.Status != TaskStatusActive) {
			m.notifyTaskModified(previous)
			return errors.Join(err, m.registry.MarkTaskFailed(task.XID, "definition promotion filter enforcement degraded"))
		}
		return err // filter transaction compensated; live registry is unchanged
	}
	m.registry.mu.Lock()
	m.registry.tasks[task.XID] = cloneInterceptTask(candidate)
	delete(m.registry.unconfirmedPending, task.XID)
	m.registry.mu.Unlock()
	delete(m.persistenceCandidates, task.XID)
	if candidate.ActivationGeneration != previous.ActivationGeneration {
		m.notifyTaskModified(previous)
	}
	m.notifyCommittedTask(candidate)
	return nil
}
