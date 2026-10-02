//go:build li

package li

import (
	"errors"
	"fmt"
)

// restrictUnconfirmedDefinitionLocked persists withdrawal without turning a
// partial response into strict-mode confirmation. Pending plus the existing
// confirmation barrier survives restart and prevents lifecycle promotion.
// The caller holds adminMu and lifecycleMu and has seeded the restored registry.
func (m *Manager) restrictUnconfirmedDefinitionLocked(held, common *InterceptTask) error {
	common.Status = TaskStatusPending
	common.Definition.Candidate = false
	m.registry.mu.Lock()
	m.registry.unconfirmedPending[held.XID] = true
	m.registry.mu.Unlock()
	if held.Status == TaskStatusPending && held.Definition.Conflict && equivalentTaskDefinition(held, common) && held.Definition == common.Definition {
		m.queueConflictReport(common)
		return nil
	}
	if err := m.notifyTaskConflict(held); err != nil {
		m.faultAdministrative(err)
		return errors.Join(err, m.filters.RemoveFiltersForTask(held.XID))
	}
	if common.ActivationGeneration == ^uint64(0) {
		err := fmt.Errorf("%w: task generation exhausted", ErrInvalidTask)
		m.faultAdministrative(err)
		return err
	}
	common.ActivationGeneration++
	var err error
	if m.stateStore != nil {
		err = m.commitPersistentTaskDefinitionLocked(held, common)
	} else {
		m.registry.mu.Lock()
		m.registry.tasks[held.XID] = cloneInterceptTask(common)
		m.registry.generations[held.XID] = max(m.registry.generations[held.XID], common.ActivationGeneration)
		m.registry.mu.Unlock()
		m.notifyTaskModified(held)
		m.notifyCommittedTask(common)
	}
	if err != nil {
		m.faultAdministrative(err)
		return errors.Join(err, m.filters.RemoveFiltersForTask(held.XID))
	}
	m.queueConflictReport(common)
	return nil
}
