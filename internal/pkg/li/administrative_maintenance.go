//go:build li

package li

import (
	"time"

	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/google/uuid"
)

func (m *Manager) purgePersistentTasksLocked(olderThan time.Duration) (int, error) {
	cutoff := time.Now().Add(-olderThan)
	taskObligations := make(map[uuid.UUID]bool)
	for _, control := range m.stateRevocations {
		if control.XID != nil {
			taskObligations[*control.XID] = true
		}
	}
	var candidates []*InterceptTask
	m.registry.ListTasks(func(task *InterceptTask) bool {
		if (task.Status == TaskStatusDeactivated || task.Status == TaskStatusFailed) && !task.DeactivatedAt.IsZero() && task.DeactivatedAt.Before(cutoff) && len(m.stateCleanup[task.XID]) == 0 && !taskObligations[task.XID] && m.unfinishedSubjectLocked(task.XID, uuid.Nil) == nil {
			candidates = append(candidates, task)
		}
		return true
	})
	if len(candidates) == 0 {
		return 0, nil
	}
	intents := make([]*StateIntent, 0, len(candidates))
	for _, task := range candidates {
		intents = append(intents, &StateIntent{OperationID: uuid.New(), Kind: StatePurge, StateIncarnation: m.stateID, XID: stateIDPointer(task.XID), PreviousGeneration: task.ActivationGeneration, Phase: StateReserved, CleanupFilterIDs: []string{}, RevocationIDs: []uuid.UUID{}})
	}
	if err := m.reserveAdministrativeLocked(intents, nil, true); err != nil {
		return 0, err
	}
	snapshot := m.snapshotAdministrativeLocked()
	removed := make(map[uuid.UUID]bool, len(candidates))
	for _, task := range candidates {
		removed[task.XID] = true
	}
	kept := make([]*InterceptTask, 0, len(snapshot.Tasks))
	for _, task := range snapshot.Tasks {
		if !removed[task.XID] {
			kept = append(kept, task)
		}
	}
	snapshot.Tasks = kept
	for _, intent := range intents {
		intent.Phase = StateFinished
	}
	out, err := m.saveAdministrativeSnapshotLocked(snapshot, true)
	if out != securestore.Committed {
		for _, intent := range intents {
			intent.Phase = StateReserved
		}
		m.faultAdministrative(err)
		return 0, err
	}
	m.registry.mu.Lock()
	for _, task := range candidates {
		delete(m.registry.tasks, task.XID)
		delete(m.registry.rollbackTask, task.XID)
		delete(m.registry.unconfirmedPending, task.XID)
		delete(m.persistenceCandidates, task.XID)
	}
	m.registry.mu.Unlock()
	return len(candidates), err
}

// cleanupPersistentFiltersLocked accepts only observed LI filter identifiers;
// an unresolvable legacy short owner is never expanded into a fabricated XID.
func (m *Manager) cleanupPersistentFiltersLocked(ids []string) (int, error) {
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if _, ok := stateCleanupOwner(id); !ok || seen[id] {
			return 0, stateError("cleanup filter ownership")
		}
		seen[id] = true
	}
	intents := make([]*StateIntent, 0, (len(ids)+maxStateReferences-1)/maxStateReferences)
	for offset := 0; offset < len(ids); offset += maxStateReferences {
		end := min(offset+maxStateReferences, len(ids))
		intents = append(intents, &StateIntent{OperationID: uuid.New(), Kind: StateCleanup, StateIncarnation: m.stateID, Phase: StateReserved, CleanupFilterIDs: append([]string{}, ids[offset:end]...), RevocationIDs: []uuid.UUID{}})
	}
	if err := m.reserveAdministrativeLocked(intents, nil, true); err != nil {
		return 0, err
	}
	removed := 0
	for _, intent := range intents {
		for _, id := range intent.CleanupFilterIDs {
			if err := m.config.FilterPusher.DeleteFilter(id); err != nil {
				intent.Failed = true
				m.faultAdministrative(err)
				return removed, err
			}
			removed++
		}
		if err := m.checkpointIntentLocked(intent, StatePolicyCommitted, true); err != nil {
			m.faultAdministrative(err)
			return removed, err
		}
		if err := m.checkpointIntentLocked(intent, StateFinished, true); err != nil {
			m.faultAdministrative(err)
			return removed, err
		}
	}
	return removed, nil
}
