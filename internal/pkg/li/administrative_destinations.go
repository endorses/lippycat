//go:build li

package li

import (
	"errors"
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

func (m *Manager) destinationIntentLocked(kind StateIntentKind, previous, candidate *Destination) *StateIntent {
	subject := previous
	if candidate != nil {
		subject = candidate
	}
	i := &StateIntent{OperationID: uuid.New(), Kind: kind, StateIncarnation: m.stateID, DID: stateIDPointer(subject.DID), Phase: StateReserved, CandidateDestination: stateDestination(candidate), CleanupFilterIDs: []string{}, RevocationIDs: []uuid.UUID{}}
	if previous != nil {
		i.PreviousGeneration = previous.DeliveryRevision
	}
	if candidate != nil {
		i.ReservedGeneration = candidate.DeliveryRevision
	}
	return i
}

func (m *Manager) failAdministrativeDestinationLocked(intent *StateIntent, cause error) error {
	intent.Failed = true
	// The old endpoint may have been revoked. Retain its definition for recovery,
	// but never authorize delivery through a partial administrative transaction.
	m.faultAdministrative(cause)
	return &securestore.CommitError{Outcome: securestore.Uncertain, Op: "incomplete destination operation", Err: cause}
}

func (m *Manager) changePersistentDestinationLocked(did uuid.UUID, dest *Destination, create bool) error {
	if err := m.unfinishedSubjectLocked(uuid.Nil, did); err != nil {
		return err
	}
	view := m.prospectiveRegistry(uuid.Nil)
	var previous *Destination
	var err error
	if dest == nil {
		return ErrInvalidTask
	}
	input := *dest
	kind := StateDestinationCreate
	if create {
		// New identities always begin at revision 1; imported legacy revision 0 is
		// preserved until a delivery-relevant replacement reserves its successor.
		input.DeliveryRevision = 1
		err = view.CreateDestination(&input)
	} else {
		previous, err = view.GetDestination(did)
		if err != nil {
			return err
		}
		err = view.ModifyDestination(did, &input)
		kind = StateDestinationModify
	}
	if err != nil {
		return err
	}
	candidate, err := view.GetDestination(did)
	if err != nil {
		return err
	}
	if previous != nil && previous.DeliveryRevision == candidate.DeliveryRevision {
		kind = StateDestinationUpdate
	}
	intent := m.destinationIntentLocked(kind, previous, candidate)
	var controls []*StateRevocation
	if kind == StateDestinationModify {
		controls, err = m.prepareRevocationsLocked(intent, nil, previous)
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
		return m.failAdministrativeDestinationLocked(intent, err)
	}
	if kind == StateDestinationModify {
		if _, err := m.commitRevocationsLocked(controls); err != nil {
			return m.failAdministrativeDestinationLocked(intent, err)
		}
		if err := m.checkpointIntentLocked(intent, StateRevocationCommitted, true); err != nil {
			return m.failAdministrativeDestinationLocked(intent, err)
		}
	}
	if kind != StateDestinationUpdate {
		if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, false); err != nil {
			return m.failAdministrativeDestinationLocked(intent, err)
		}
	}
	oldPhase := intent.Phase
	intent.Phase = StateFinished
	snapshot := m.snapshotAdministrativeLocked()
	replaced := false
	for n, d := range snapshot.Destinations {
		if d.DID == did {
			snapshot.Destinations[n] = stateDestination(candidate)
			replaced = true
			break
		}
	}
	if !replaced {
		snapshot.Destinations = append(snapshot.Destinations, stateDestination(candidate))
	}
	out, err := m.saveAdministrativeSnapshotLocked(snapshot, false)
	if out == securestore.NotCommitted {
		intent.Phase = oldPhase
	}
	if out != securestore.Committed {
		return m.failAdministrativeDestinationLocked(intent, err)
	}
	m.registry.mu.Lock()
	m.registry.destinations[did] = candidate
	m.registry.mu.Unlock()
	callbackErr := m.notifyDestinationDefinition(did, !create)
	return errors.Join(err, callbackErr)
}

func (m *Manager) removePersistentDestinationLocked(did uuid.UUID) error {
	if err := m.unfinishedSubjectLocked(uuid.Nil, did); err != nil {
		return err
	}
	previous, err := m.registry.GetDestination(did)
	if err != nil {
		return err
	}
	var affected []*InterceptTask
	m.registry.ListTasks(func(task *InterceptTask) bool {
		if task.Status != TaskStatusActive && task.Status != TaskStatusSuspended {
			return true
		}
		for _, id := range task.DestinationIDs {
			if id == did {
				affected = append(affected, task)
				break
			}
		}
		return true
	})
	// Reserve the entire group before any withdrawal: partial planning cannot
	// withdraw only a prefix of tasks or exceed the per-intent control bound.
	intents := make([]*StateIntent, 0, len(affected)+1)
	controls := make([]*StateRevocation, 0)
	grouped := make(map[uuid.UUID][]*StateRevocation, len(affected)+1)
	for _, task := range affected {
		if err := m.unfinishedSubjectLocked(task.XID, uuid.Nil); err != nil {
			return err
		}
		intent, err := m.taskIntentLocked(StateTaskDeactivate, task, nil)
		if err != nil {
			return err
		}
		planned, err := m.prepareRevocationsLocked(intent, task, nil)
		if err != nil {
			return err
		}
		for _, c := range planned {
			intent.RevocationIDs = append(intent.RevocationIDs, c.ControlID)
		}
		intents = append(intents, intent)
		controls = append(controls, planned...)
		grouped[intent.OperationID] = planned
		if len(m.stateRevocations)+len(controls) > MaxStateRevocations || len(m.stateIntents)+len(intents)+1 > MaxStateObligations {
			return stateError("destination removal transaction limit")
		}
	}
	destinationIntent := m.destinationIntentLocked(StateDestinationRemove, previous, nil)
	planned, err := m.prepareRevocationsLocked(destinationIntent, nil, previous)
	if err != nil {
		return err
	}
	for _, c := range planned {
		destinationIntent.RevocationIDs = append(destinationIntent.RevocationIDs, c.ControlID)
	}
	intents = append(intents, destinationIntent)
	controls = append(controls, planned...)
	grouped[destinationIntent.OperationID] = planned
	if err := m.reserveAdministrativeLocked(intents, controls, true); err != nil {
		if securestore.OutcomeOf(err) == securestore.NotCommitted {
			return err
		}
		return m.failAdministrativeDestinationLocked(destinationIntent, err)
	}
	// All associated authorizations are closed, including tasks with other DIDs.
	// Never persist or publish an enforcing task that references a removed DID.
	for n, task := range affected {
		intent := intents[n]
		closed := cloneInterceptTask(task)
		closed.Status = TaskStatusDeactivated
		closed.DeactivatedAt = time.Now().UTC()
		m.registry.mu.Lock()
		m.registry.tasks[task.XID] = closed
		m.registry.mu.Unlock()
		if _, err := m.commitRevocationsLocked(grouped[intent.OperationID]); err != nil {
			return m.failAdministrativeTaskLocked(intent, closed, err)
		}
		if m.registry.onDeactivation != nil {
			m.registry.onDeactivation(closed, DeactivationReasonADMF)
		}
		if err := m.checkpointIntentLocked(intent, StateRevocationCommitted, true); err != nil {
			return m.failAdministrativeTaskLocked(intent, closed, err)
		}
		if err := m.filters.RemoveFiltersForTask(task.XID); err != nil {
			return m.failAdministrativeTaskLocked(intent, closed, err)
		}
		if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, true); err != nil {
			return m.failAdministrativeTaskLocked(intent, closed, err)
		}
		if err := m.finishTaskIntentLocked(intent, closed, true); err != nil {
			return m.failAdministrativeDestinationLocked(destinationIntent, err)
		}
	}
	if _, err := m.commitRevocationsLocked(grouped[destinationIntent.OperationID]); err != nil {
		return m.failAdministrativeDestinationLocked(destinationIntent, err)
	}
	if err := m.checkpointIntentLocked(destinationIntent, StateRevocationCommitted, true); err != nil {
		return m.failAdministrativeDestinationLocked(destinationIntent, err)
	}
	if err := m.checkpointIntentLocked(destinationIntent, StatePolicyCommitted, true); err != nil {
		return m.failAdministrativeDestinationLocked(destinationIntent, err)
	}
	destinationIntent.Phase = StateFinished
	snapshot := m.snapshotAdministrativeLocked()
	remaining := make([]*StateDestination, 0, len(snapshot.Destinations))
	for _, d := range snapshot.Destinations {
		if d.DID != did {
			remaining = append(remaining, d)
		}
	}
	snapshot.Destinations = remaining
	out, err := m.saveAdministrativeSnapshotLocked(snapshot, true)
	if out != securestore.Committed {
		return m.failAdministrativeDestinationLocked(destinationIntent, err)
	}
	m.registry.mu.Lock()
	delete(m.registry.destinations, did)
	m.registry.mu.Unlock()
	m.callbackMu.RLock()
	callback := m.onDestinationRemoved
	m.callbackMu.RUnlock()
	if callback != nil {
		callback(did)
	}
	return err
}
