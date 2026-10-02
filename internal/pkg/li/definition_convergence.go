//go:build li

package li

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

// applySnapshotDefinition runs under snapshotMu, preserving the RADIUS path at
// its caller. Administrative and lifecycle locks protect every local change.
func (m *Manager) applySnapshotDefinition(in *SnapshotTask) error {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	if err := m.ensureAdministrativeStateLocked(); err != nil {
		return err
	}
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	task := cloneInterceptTask(in.Task)
	held, err := m.registry.GetTaskDetails(task.XID)
	if err != nil && !errors.Is(err, ErrTaskNotFound) {
		return err
	}
	live := held != nil
	if held == nil {
		held = cloneInterceptTask(m.persistenceCandidates[task.XID])
	}
	if held != nil && held.Definition.Source == DefinitionPush && (held.Status == TaskStatusDeactivated || held.Status == TaskStatusFailed) {
		// A stale pull cannot reactivate an explicitly withdrawn or faulted push.
		return nil
	}
	if held != nil && held.Definition.ConflictDisarmed {
		return m.applyConflictAuthorizationLocked(held, in, live)
	}
	if !in.Completeness.Complete() {
		if held != nil {
			// A missing window cannot grant authority, but mandatory supplied
			// selectors, task destinations and delivery still restrict it.
			comparison := cloneInterceptTask(task)
			comparison.StartTime, comparison.EndTime = held.StartTime, held.EndTime
			comparison.ImplicitDeactivationAllowed = held.ImplicitDeactivationAllowed
			if held.Definition.Conflict || !equivalentTaskDefinition(held, comparison) || snapshotHasUnconfirmedDestination(held, in) {
				return m.applyConflictAuthorizationLocked(held, in, live)
			}
			if live && !m.pendingNeedsConfirmation(task.XID) {
				return nil
			}
			task = cloneInterceptTask(held)
		}
		if in.confirmedDestinations != nil {
			for _, did := range task.DestinationIDs {
				if !in.confirmedDestinations[did] {
					return fmt.Errorf("%w: retained definition has unconfirmed destination", ErrDestinationNotFound)
				}
			}
		}
		if m.config.ADMFCompleteTaskContract {
			if held != nil && !held.Definition.Candidate {
				return fmt.Errorf("strict ADMF contract requires a complete definition for restored task")
			}
			return m.storeDefinitionCandidateLocked(task)
		}
		if err := m.activateSnapshotLocked(task); err != nil {
			return err
		}
		logPartialDefinitionAdmission(task)
		return nil
	}
	if held != nil && (held.Definition.Source == DefinitionPush || held.Definition.Conflict) {
		if held.Definition.Conflict || !equivalentTaskDefinition(held, task) || snapshotHasUnconfirmedDestination(held, in) {
			return m.applyConflictAuthorizationLocked(held, in, live)
		}
		// Exact confirmation never transfers ownership from a push to a pull.
		task.Definition.Source = DefinitionPush
	}
	if in.confirmedDestinations != nil {
		for _, did := range task.DestinationIDs {
			if !in.confirmedDestinations[did] {
				return fmt.Errorf("%w: definition has unconfirmed destination", ErrDestinationNotFound)
			}
		}
	}

	repaired := held != nil && (!held.Definition.Completeness.Complete() || !equivalentTaskDefinition(held, task))
	var changedFields []string
	if repaired {
		changedFields = changedDefinitionFields(held, task)
	}
	if live && (held.Status == TaskStatusActive || held.Status == TaskStatusPending) && !m.pendingNeedsConfirmation(task.XID) {
		if equivalentTaskDefinition(held, task) {
			held.Definition = task.Definition
			if err := m.updateDefinitionMetadataLocked(held); err != nil {
				return err
			}
		} else if err := m.promoteTaskDefinitionLocked(task); err != nil {
			return err
		}
	} else {
		if err := m.activateSnapshotLocked(task); err != nil {
			return err
		}
	}
	if repaired {
		m.definitionRepairs.Add(1)
		logger.Info("LI task definition repaired", "xid", task.XID, "provenance", task.Definition.Source, "fields", changedFields, "reason", "complete_snapshot")
	}
	m.confirmDefinitionReplayLocked(task)
	return nil
}

func (m *Manager) activateSnapshotLocked(task *InterceptTask) error {
	task = cloneInterceptTask(task)
	task.Definition.Candidate = false
	if m.stateStore != nil {
		return m.activatePersistentTaskLocked(task, true)
	}
	if old := m.persistedActive[task.XID]; old != nil {
		m.registry.seedGeneration(task.XID, old.ActivationGeneration)
	}
	if old := m.persistedActive[task.XID]; old != nil && old.ActivationGeneration > 0 && equivalentTaskDefinition(old, task) {
		m.registry.seedGeneration(task.XID, old.ActivationGeneration)
		m.registry.mu.Lock()
		if m.registry.tasks[task.XID] == nil && m.registry.generations[task.XID] == old.ActivationGeneration {
			m.registry.generations[task.XID]--
		}
		m.registry.mu.Unlock()
		defer m.registry.seedGeneration(task.XID, old.ActivationGeneration)
	}
	return m.activateTask(task)
}

func (m *Manager) storeDefinitionCandidateLocked(task *InterceptTask) error {
	view := m.prospectiveRegistry(task.XID)
	delete(view.tasks, task.XID)
	if err := view.ActivateTask(task); err != nil {
		return err
	}
	previous := m.persistenceCandidates[task.XID]
	task = cloneInterceptTask(task)
	task.Status, task.Definition.Candidate = TaskStatusPending, true
	task.ActivationGeneration = m.registry.generations[task.XID]
	m.persistenceCandidates[task.XID] = task
	if err := m.persistStateLocked(); err != nil {
		if previous == nil {
			delete(m.persistenceCandidates, task.XID)
		} else {
			m.persistenceCandidates[task.XID] = previous
		}
		return err
	}
	return nil
}

func (m *Manager) updateDefinitionMetadataLocked(task *InterceptTask) error {
	if m.stateStore == nil {
		return m.registry.restoreTask(task)
	}
	previous, err := m.registry.GetTaskDetails(task.XID)
	if err != nil {
		return err
	}
	if previous.Definition == task.Definition {
		return nil
	}
	intent, err := m.taskIntentLocked(StateTaskUpdate, previous, task)
	if err != nil {
		return err
	}
	if err := m.reserveAdministrativeLocked([]*StateIntent{intent}, nil, false); err != nil {
		if securestore.OutcomeOf(err) != securestore.NotCommitted {
			return m.failAdministrativeTaskLocked(intent, task, err)
		}
		return err
	}
	if err := m.finishTaskIntentLocked(intent, task, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.Committed {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, task, err)
	}
	return nil
}

func (m *Manager) confirmDefinitionReplayLocked(task *InterceptTask) {
	if task.Definition.Conflict || !task.Definition.Completeness.Complete() {
		return
	}
	old := m.persistedActive[task.XID]
	live, err := m.registry.GetTaskDetails(task.XID)
	if old == nil || err != nil || old.ActivationGeneration == 0 || old.ActivationGeneration != live.ActivationGeneration || !equivalentTaskDefinition(old, task) || !equivalentTaskDefinition(live, task) {
		return
	}
	m.replayMu.Lock()
	m.replayConfirmed[task.XID] = old.ActivationGeneration
	m.replayMu.Unlock()
}

func changedDefinitionFields(a, b *InterceptTask) []string {
	var fields []string
	if !a.StartTime.Equal(b.StartTime) {
		fields = append(fields, "start")
	}
	if !a.EndTime.Equal(b.EndTime) {
		fields = append(fields, "end")
	}
	if a.ImplicitDeactivationAllowed != b.ImplicitDeactivationAllowed {
		fields = append(fields, "implicit_deactivation")
	}
	ca, cb := canonicalizeTaskDefinition(a), canonicalizeTaskDefinition(b)
	if !slices.Equal(ca.Targets, cb.Targets) {
		fields = append(fields, "targets")
	}
	if !slices.Equal(ca.DestinationIDs, cb.DestinationIDs) {
		fields = append(fields, "destinations")
	}
	if a.DeliveryType != b.DeliveryType {
		fields = append(fields, "delivery_type")
	}
	if a.Definition.Completeness != b.Definition.Completeness {
		fields = append(fields, "completeness")
	}
	return fields
}

func (m *Manager) definitionStats() DefinitionStats {
	m.adminMu.Lock()
	defer m.adminMu.Unlock()
	s := DefinitionStats{Repairs: m.definitionRepairs.Load()}
	seen := make(map[uuid.UUID]bool)
	count := func(task *InterceptTask) {
		if IsRADIUSTask(task) || seen[task.XID] || task.Status == TaskStatusDeactivated || task.Status == TaskStatusFailed {
			return
		}
		seen[task.XID] = true
		c := task.Definition.Completeness
		if !c.Complete() {
			s.Incomplete++
		}
		if !c.Mediation || !c.Start || !c.End {
			s.UnknownWindows++
		} else if task.EndTime.IsZero() {
			s.OpenEnded++
		}
		if task.Definition.Source == DefinitionPull {
			s.PullOnly++
		}
		if task.Definition.Conflict {
			s.Conflicts++
		}
	}
	m.registry.ListTasks(func(task *InterceptTask) bool { count(task); return true })
	for _, task := range m.persistenceCandidates {
		count(task)
	}
	return s
}

// Check before starting listeners: strict-mode rollout cannot silently discard
// a previously enforcing unknown-window definition. Repair in compatibility
// mode first, or supply a complete startup snapshot synchronously.
func (m *Manager) validateStrictTransition() error {
	if !m.config.ADMFCompleteTaskContract {
		return nil
	}
	var repairIDs []uuid.UUID
	for _, task := range m.persistenceCandidates {
		if !IsRADIUSTask(task) && !task.Definition.Candidate && !task.Definition.Completeness.Complete() {
			repairIDs = append(repairIDs, task.XID)
		}
	}
	m.registry.ListTasks(func(task *InterceptTask) bool {
		if !IsRADIUSTask(task) && task.Status == TaskStatusPending && task.Definition.Restored && !task.Definition.Completeness.Complete() {
			repairIDs = append(repairIDs, task.XID)
		}
		return true
	})
	if len(repairIDs) == 0 {
		return nil
	}
	if !m.config.SyncOnStartup || m.x1Client == nil {
		return fmt.Errorf("strict ADMF contract requires repairing persisted incomplete tasks before startup")
	}
	ctx, cancel := context.WithTimeout(m.recoveryCtx, m.syncAttemptTimeout())
	defer cancel()
	if err := m.syncStateFromADMF(ctx); err != nil {
		return fmt.Errorf("strict ADMF contract startup repair: %w", err)
	}
	for _, id := range repairIDs {
		live, err := m.registry.GetTaskDetails(id)
		if err != nil || !live.Definition.Completeness.Complete() {
			return fmt.Errorf("strict ADMF contract requires complete startup definitions for previously enforcing tasks")
		}
	}
	return nil
}

func logPartialDefinitionAdmission(task *InterceptTask) {
	c := task.Definition.Completeness
	window := "unknown"
	if c.Mediation && c.Start && c.End {
		window = "bounded"
		if task.EndTime.IsZero() {
			window = "open_ended"
		}
	}
	logger.Warn("LI task admitted from partial ADMF snapshot", "xid", task.XID,
		"provenance", task.Definition.Source, "reason", "incomplete_snapshot", "window", window,
		"explicit_deactivation_required", task.EndTime.IsZero() || !task.ImplicitDeactivationAllowed)
}

// Global destination existence alone is insufficient evidence for delivery.
func snapshotHasUnconfirmedDestination(held *InterceptTask, in *SnapshotTask) bool {
	if in.confirmedDestinations != nil {
		for _, did := range held.DestinationIDs {
			if !in.confirmedDestinations[did] {
				return true
			}
		}
	}
	return false
}
