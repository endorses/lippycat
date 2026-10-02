//go:build li

package li

import (
	"errors"
	"slices"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

func stateIDPointer(id uuid.UUID) *uuid.UUID { return &id }

func (m *Manager) unfinishedSubjectLocked(xid, did uuid.UUID) error {
	for _, intent := range m.stateIntents {
		if intent.Phase == StateFinished {
			continue
		}
		if xid != uuid.Nil && intent.XID != nil && *intent.XID == xid || did != uuid.Nil && intent.DID != nil && *intent.DID == did {
			return ErrAdministrativeFault
		}
	}
	return nil
}

// prospectiveRegistry validates a single prospective task without publishing a
// provisional task or decrementing the real reservation watermark.
func (m *Manager) prospectiveRegistry(xid uuid.UUID) *Registry {
	r := NewRegistry(nil)
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()
	for id, d := range m.registry.destinations {
		copyDest := *d
		r.destinations[id] = &copyDest
	}
	if task := m.registry.tasks[xid]; task != nil {
		r.tasks[xid] = cloneInterceptTask(task)
	}
	r.generations[xid] = m.registry.generations[xid]
	return r
}

func (m *Manager) pendingNeedsConfirmation(xid uuid.UUID) bool {
	m.registry.mu.RLock()
	defer m.registry.mu.RUnlock()
	return m.registry.unconfirmedPending[xid]
}

func canonicalStateTask(task *InterceptTask) *InterceptTask {
	copyTask := cloneInterceptTask(task)
	if copyTask == nil {
		return nil
	}
	copyTask.Targets = canonicalizeTargets(task.Targets)
	slices.SortFunc(copyTask.DestinationIDs, func(a, b uuid.UUID) int { return slices.Compare(a[:], b[:]) })
	copyTask.DestinationIDs = slices.Compact(copyTask.DestinationIDs)
	return copyTask
}

func (m *Manager) taskIntentLocked(kind StateIntentKind, previous, candidate *InterceptTask) (*StateIntent, error) {
	subject := candidate
	if subject == nil {
		subject = previous
	}
	if subject == nil {
		return nil, ErrInvalidTask
	}
	i := &StateIntent{OperationID: uuid.New(), Kind: kind, StateIncarnation: m.stateID, XID: stateIDPointer(subject.XID), Phase: StateReserved,
		CandidateTask: cloneInterceptTask(candidate), CleanupFilterIDs: []string{}, RevocationIDs: []uuid.UUID{}}
	if previous != nil {
		i.PreviousGeneration = previous.ActivationGeneration
	}
	if candidate != nil {
		i.ReservedGeneration = candidate.ActivationGeneration
	}
	i.CleanupFilterIDs = append(i.CleanupFilterIDs, m.filters.GetFiltersForXID(subject.XID)...)
	if candidate != nil && candidate.Status == TaskStatusActive {
		filters, err := m.filters.filtersForTask(candidate)
		if err != nil {
			return nil, err
		}
		for _, filter := range filters {
			if !containsCleanupID(i.CleanupFilterIDs, filter.Id) {
				i.CleanupFilterIDs = append(i.CleanupFilterIDs, filter.Id)
			}
		}
	}
	return i, nil
}

func (m *Manager) saveAdministrativeSnapshotLocked(s *StateSnapshot, control bool) (securestore.Outcome, error) {
	if m.stateStore == nil {
		return securestore.NotCommitted, errors.New("administrative transaction requires an owned encrypted store")
	}
	var out securestore.Outcome
	var err error
	if control {
		out, err = m.stateStore.SaveControl(s)
	} else {
		out, err = m.stateStore.Save(s)
	}
	if err == nil && out != securestore.Committed {
		err = errors.New("administrative transaction checkpoint did not commit")
	}
	if out == securestore.Uncertain {
		m.faultAdministrative(err)
	}
	if err != nil {
		err = &securestore.CommitError{Outcome: out, Op: "administrative checkpoint", Err: err}
	}
	return out, err
}

// reserveAdministrativeLocked validates/commits the complete group before any
// journal, registry, filter or endpoint side effect. It consumes watermarks even
// when a subsequent stage cannot complete; only definite pre-reservation failure
// leaves the previous committed state eligible to continue.
func (m *Manager) reserveAdministrativeLocked(intents []*StateIntent, controls []*StateRevocation, control bool) error {
	s := m.snapshotAdministrativeLocked()
	s.Intents = append(append([]*StateIntent{}, s.Intents...), intents...)
	s.Revocations = append(append([]*StateRevocation{}, s.Revocations...), controls...)
	for _, i := range intents {
		if i.XID != nil {
			s.Generations[*i.XID] = max(s.Generations[*i.XID], i.PreviousGeneration, i.ReservedGeneration)
			for _, id := range i.CleanupFilterIDs {
				if !containsCleanupID(s.CleanupNeeded[*i.XID], id) {
					s.CleanupNeeded[*i.XID] = append(s.CleanupNeeded[*i.XID], id)
				}
			}
		}
	}
	out, err := m.saveAdministrativeSnapshotLocked(s, control)
	if out == securestore.NotCommitted {
		return err
	}
	m.stateIntents, m.stateRevocations, m.stateCleanup = s.Intents, s.Revocations, s.CleanupNeeded
	m.registry.mu.Lock()
	for id, generation := range s.Generations {
		m.registry.generations[id] = max(m.registry.generations[id], generation)
	}
	m.registry.mu.Unlock()
	if err != nil {
		return &securestore.CommitError{Outcome: out, Op: "reserve administrative operation", Err: err}
	}
	return nil
}

func (m *Manager) checkpointIntentLocked(intent *StateIntent, phase StateIntentPhase, control bool) error {
	previous := intent.Phase
	intent.Phase = phase
	out, err := m.saveAdministrativeSnapshotLocked(m.snapshotAdministrativeLocked(), control)
	if out == securestore.NotCommitted {
		intent.Phase = previous
	}
	return err
}

func replaceSnapshotTask(s *StateSnapshot, task *InterceptTask) {
	for n, existing := range s.Tasks {
		if existing.XID == task.XID {
			s.Tasks[n] = cloneInterceptTask(task)
			return
		}
	}
	s.Tasks = append(s.Tasks, cloneInterceptTask(task))
}

func (m *Manager) finishTaskIntentLocked(intent *StateIntent, task *InterceptTask, control bool) error {
	previousPhase, previousCleanup := intent.Phase, intent.CleanupFilterIDs
	intent.Phase, intent.CleanupFilterIDs = StateFinished, []string{}
	s := m.snapshotAdministrativeLocked()
	replaceSnapshotTask(s, task)
	delete(s.CleanupNeeded, task.XID)
	if ids := m.filters.GetFiltersForXID(task.XID); len(ids) != 0 {
		s.CleanupNeeded[task.XID] = ids
	}
	out, err := m.saveAdministrativeSnapshotLocked(s, control)
	if out == securestore.NotCommitted {
		intent.Phase, intent.CleanupFilterIDs = previousPhase, previousCleanup
	}
	if out == securestore.Committed {
		m.registry.mu.Lock()
		if intent.Kind == StateTaskReactivate {
			if previous := m.registry.tasks[task.XID]; previous != nil {
				m.registry.auditHistory[task.XID] = append(m.registry.auditHistory[task.XID], *cloneInterceptTask(previous))
			}
		}
		m.registry.tasks[task.XID] = cloneInterceptTask(task)
		if intent.Kind == StateTaskActivate || intent.Kind == StateTaskReactivate || intent.Kind == StateTaskConfirm || task.Status == TaskStatusDeactivated || task.Status == TaskStatusFailed {
			delete(m.registry.unconfirmedPending, task.XID)
		}
		delete(m.registry.rollbackTask, task.XID)
		m.registry.mu.Unlock()
		delete(m.persistenceCandidates, task.XID)
		m.stateCleanup = s.CleanupNeeded
		m.notifyCommittedTask(task)
	}
	return err
}

// failAdministrativeTaskLocked keeps the affected generation closed and retains
// exact cleanup/intents. A partially completed multi-store operation faults the
// owner; restart must reconcile its authenticated intent before further work.
func (m *Manager) failAdministrativeTaskLocked(intent *StateIntent, subject *InterceptTask, cause error) error {
	intent.Failed = true
	failed := cloneInterceptTask(subject)
	if (intent.Kind == StateTaskModify || intent.Kind == StateTaskReactivate) && intent.PreviousGeneration == 0 {
		if old, err := m.registry.GetTaskDetails(subject.XID); err == nil && old.ActivationGeneration == 0 {
			failed = old
		}
	}
	failed.Status, failed.LastError, failed.DeactivatedAt = TaskStatusFailed, "administrative operation requires reconciliation", time.Now().UTC()
	m.registry.mu.Lock()
	m.registry.tasks[failed.XID] = failed
	m.registry.mu.Unlock()
	delete(m.persistenceCandidates, failed.XID)
	cleanupErr := m.filters.RemoveFiltersForTask(failed.XID)
	for _, id := range intent.CleanupFilterIDs {
		if !containsCleanupID(m.stateCleanup[failed.XID], id) {
			m.stateCleanup[failed.XID] = append(m.stateCleanup[failed.XID], id)
		}
	}
	var saveErr error
	if m.stateFault.Load() == nil {
		_, saveErr = m.saveAdministrativeSnapshotLocked(m.snapshotAdministrativeLocked(), true)
	}
	err := errors.Join(cause, cleanupErr, saveErr)
	m.faultAdministrative(err)
	return &securestore.CommitError{Outcome: securestore.Uncertain, Op: "incomplete administrative operation", Err: err}
}

func (m *Manager) activatePersistentTaskLocked(task *InterceptTask, startup bool) error {
	if task == nil {
		return ErrInvalidTask
	}
	if err := m.unfinishedSubjectLocked(task.XID, uuid.Nil); err != nil {
		return err
	}
	previous, err := m.registry.GetTaskDetails(task.XID)
	if err != nil && !errors.Is(err, ErrTaskNotFound) {
		return err
	}
	kind := StateTaskActivate
	unconfirmed := previous != nil && previous.Status == TaskStatusPending && m.pendingNeedsConfirmation(task.XID)
	if previous != nil && !unconfirmed {
		switch previous.Status {
		case TaskStatusActive, TaskStatusPending:
			if equivalentTaskDefinition(previous, task) {
				return nil
			}
			return ErrTaskDefinitionConflict
		case TaskStatusDeactivated:
			if !equivalentReactivationIdentity(previous, task) {
				return ErrReactivationIdentityConflict
			}
			if err := validateReactivationDefinition(task); err != nil {
				return err
			}
			kind = StateTaskReactivate
		default:
			return ErrTaskDefinitionConflict
		}
	}
	view := m.prospectiveRegistry(task.XID)
	if unconfirmed {
		delete(view.tasks, task.XID)
	}
	input := canonicalStateTask(task)
	if startup && previous == nil {
		if old := m.persistedActive[task.XID]; old != nil && !IsRADIUSTask(task) && old.ActivationGeneration > 0 && view.generations[task.XID] == old.ActivationGeneration && equivalentTaskDefinition(old, task) {
			kind, previous = StateTaskConfirm, cloneInterceptTask(old)
			view.generations[task.XID]-- // detached prospective view only
		}
	}
	if err := view.ActivateTask(input); err != nil {
		return err
	}
	candidate, err := view.GetTaskDetails(task.XID)
	if err != nil {
		return err
	}
	if kind == StateTaskConfirm {
		candidate.Status = TaskStatusActive
	}
	intent, err := m.taskIntentLocked(kind, previous, candidate)
	if err != nil {
		return err
	}
	if err := m.reserveAdministrativeLocked([]*StateIntent{intent}, nil, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.NotCommitted {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	if candidate.Status == TaskStatusActive {
		if _, err := m.filters.CreateFiltersForTask(candidate); err != nil {
			return m.failAdministrativeTaskLocked(intent, candidate, err)
		}
		if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, false); err != nil {
			return m.failAdministrativeTaskLocked(intent, candidate, err)
		}
	}
	if err := m.finishTaskIntentLocked(intent, candidate, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.Committed {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	logTaskActivation(kind == StateTaskReactivate, candidate, intent.PreviousGeneration, len(m.filters.GetFiltersForXID(task.XID)))
	return nil
}

func (m *Manager) modifyPersistentTaskLocked(xid uuid.UUID, mod *TaskModification) error {
	if err := m.unfinishedSubjectLocked(xid, uuid.Nil); err != nil {
		return err
	}
	view := m.prospectiveRegistry(xid)
	previous, err := view.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	if err := view.ModifyTask(xid, mod); err != nil {
		return err
	}
	candidate, err := view.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	return m.commitPersistentTaskDefinitionLocked(previous, candidate)
}

// commitPersistentTaskDefinitionLocked is shared by ordinary modifications and
// internal complete-definition promotion. Callers validate in a detached view.
func (m *Manager) commitPersistentTaskDefinitionLocked(previous, candidate *InterceptTask) error {
	xid := candidate.XID
	candidate = canonicalStateTask(candidate)
	kind := StateTaskUpdate
	if candidate.ActivationGeneration != previous.ActivationGeneration {
		kind = StateTaskModify
	} else if previous.Status == TaskStatusPending && candidate.Status == TaskStatusActive {
		kind = StateTaskPromote
	}
	intent, err := m.taskIntentLocked(kind, previous, candidate)
	if err != nil {
		return err
	}
	var controls []*StateRevocation
	if kind == StateTaskModify {
		if previous.ActivationGeneration != 0 {
			controls, err = m.prepareRevocationsLocked(intent, previous, nil)
		}
		if err != nil {
			return err
		}
		for _, c := range controls {
			intent.RevocationIDs = append(intent.RevocationIDs, c.ControlID)
		}
	}
	if err := m.reserveAdministrativeLocked([]*StateIntent{intent}, controls, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.NotCommitted {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	if kind == StateTaskModify {
		m.registry.mu.Lock()
		if previous.Status == TaskStatusActive {
			m.registry.tasks[xid].Status = TaskStatusSuspended
		}
		m.registry.mu.Unlock()
		_, revocationErr := m.commitRevocationsLocked(controls)
		m.notifyTaskModified(previous)
		if revocationErr != nil {
			return m.failAdministrativeTaskLocked(intent, candidate, revocationErr)
		}
		if err := m.checkpointIntentLocked(intent, StateRevocationCommitted, true); err != nil {
			return m.failAdministrativeTaskLocked(intent, candidate, err)
		}
	}
	if kind == StateTaskModify || previous.Status != candidate.Status {
		if candidate.Status == TaskStatusActive {
			if err := m.filters.UpdateFiltersForTask(candidate); err != nil {
				return m.failAdministrativeTaskLocked(intent, candidate, err)
			}
		} else if previous.Status == TaskStatusActive {
			if err := m.filters.RemoveFiltersForTask(xid); err != nil {
				return m.failAdministrativeTaskLocked(intent, candidate, err)
			}
		}
		if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, false); err != nil {
			return m.failAdministrativeTaskLocked(intent, candidate, err)
		}
	}
	if err := m.finishTaskIntentLocked(intent, candidate, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.Committed {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	return nil
}

func (m *Manager) withdrawPersistentTaskLocked(xid uuid.UUID, kind StateIntentKind, reason string) error {
	if err := m.unfinishedSubjectLocked(xid, uuid.Nil); err != nil {
		return err
	}
	previous, err := m.registry.GetTaskDetails(xid)
	if err != nil {
		return err
	}
	if previous.Status == TaskStatusDeactivated && len(m.filters.GetFiltersForXID(xid)) == 0 && kind == StateTaskDeactivate {
		return nil
	}
	intent, err := m.taskIntentLocked(kind, previous, nil)
	if err != nil {
		return err
	}
	var controls []*StateRevocation
	if previous.ActivationGeneration != 0 {
		controls, err = m.prepareRevocationsLocked(intent, previous, nil)
		if err != nil {
			m.faultAdministrative(err)
			return err
		}
	}
	for _, c := range controls {
		intent.RevocationIDs = append(intent.RevocationIDs, c.ControlID)
	}
	// The write admission barrier is already held before reservation I/O.
	if err := m.reserveAdministrativeLocked([]*StateIntent{intent}, controls, true); err != nil {
		if securestore.OutcomeOf(err) == securestore.NotCommitted {
			m.faultAdministrative(err) // requested withdrawal must not reopen admission after failed reservation
			return err
		}
		return m.failAdministrativeTaskLocked(intent, previous, err)
	}
	closed := cloneInterceptTask(previous)
	closed.Status, closed.DeactivatedAt = TaskStatusDeactivated, time.Now().UTC()
	if kind == StateTaskDeactivate {
		closed.Definition.Conflict, closed.Definition.ConflictDisarmed = false, false
		closed.Definition.ConflictReason = ""
	}
	callbackReason := DeactivationReasonADMF
	if kind == StateTaskExpire {
		callbackReason = DeactivationReasonExpired
	}
	if kind == StateTaskFail {
		closed.Status, closed.LastError, callbackReason = TaskStatusFailed, reason, DeactivationReasonFault
	}
	m.registry.mu.Lock()
	m.registry.tasks[xid] = cloneInterceptTask(closed)
	m.registry.mu.Unlock()
	_, revocationErr := m.commitRevocationsLocked(controls)
	if m.registry.onDeactivation != nil {
		m.registry.onDeactivation(closed, callbackReason)
	}
	if revocationErr != nil {
		return m.failAdministrativeTaskLocked(intent, closed, revocationErr)
	}
	if err := m.checkpointIntentLocked(intent, StateRevocationCommitted, true); err != nil {
		return m.failAdministrativeTaskLocked(intent, closed, err)
	}
	if err := m.filters.RemoveFiltersForTask(xid); err != nil {
		return m.failAdministrativeTaskLocked(intent, closed, err)
	}
	if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, true); err != nil {
		return m.failAdministrativeTaskLocked(intent, closed, err)
	}
	if err := m.finishTaskIntentLocked(intent, closed, true); err != nil {
		if securestore.OutcomeOf(err) == securestore.Committed {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, closed, err)
	}
	return nil
}

func (m *Manager) promotePersistentTaskLocked(task *InterceptTask) error {
	if m.pendingNeedsConfirmation(task.XID) {
		return errors.New("restored pending task requires current activation")
	}
	if err := m.unfinishedSubjectLocked(task.XID, uuid.Nil); err != nil {
		return err
	}
	if err := m.registry.validateTask(task); err != nil {
		return err
	}
	destinations := make([]*Destination, 0, len(task.DestinationIDs))
	for _, id := range task.DestinationIDs {
		d, err := m.registry.GetDestination(id)
		if err != nil {
			return err
		}
		destinations = append(destinations, d)
	}
	if err := validateDestinationDelivery(task, destinations); err != nil {
		return err
	}
	candidate := cloneInterceptTask(task)
	candidate.Status = TaskStatusActive
	intent, err := m.taskIntentLocked(StateTaskPromote, task, candidate)
	if err != nil {
		return err
	}
	if err := m.reserveAdministrativeLocked([]*StateIntent{intent}, nil, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.NotCommitted {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	if _, err := m.filters.CreateFiltersForTask(candidate); err != nil {
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, false); err != nil {
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	if err := m.finishTaskIntentLocked(intent, candidate, false); err != nil {
		if securestore.OutcomeOf(err) == securestore.Committed {
			return err
		}
		return m.failAdministrativeTaskLocked(intent, candidate, err)
	}
	return nil
}
