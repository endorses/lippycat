//go:build li

package li

import (
	"errors"
	"fmt"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/uuid"
)

// bindRADIUSDeployment applies the local dedicated POI contract to X1 data.
// X1 identifiers cannot select or broaden the operator's configured scope.
func (m *Manager) bindRADIUSDeployment(task *InterceptTask) {
	if !IsRADIUSTask(task) {
		return
	}
	task.RADIUSScope = m.config.RADIUSScope
	task.RADIUSMACProfile = m.config.RADIUSMACProfile
}

// withdrawPersistedRADIUS removes both canonical and pre-migration short IDs
// before any listeners or task activations can run. A failed withdrawal fails
// startup; retaining an obsolete SIP selector is not an acceptable migration.
func (m *Manager) withdrawPersistedRADIUS(task *InterceptTask, cleanup []string) error {
	if m.config.FilterPusher == nil {
		return nil
	}
	ids := make(map[string]bool)
	if lister, ok := m.config.FilterPusher.(FilterLister); ok {
		for _, id := range lister.ListFilterIDs() {
			owner, li := liFilterXIDPrefix(id)
			if li && (owner == task.XID.String() || owner == task.XID.String()[:8]) {
				ids[id] = true
			}
		}
	}
	if _, ok := m.config.FilterPusher.(FilterLister); !ok {
		if task.RADIUSScope.OperatorScope == "" {
			return fmt.Errorf("legacy NAI migration requires a filter lister to withdraw obsolete short IDs")
		}
		for _, id := range cleanup {
			ids[id] = true
		}
		count := len(task.Targets)
		// Scoped definitions were emitted by the compound implementation.
		if task.RADIUSScope.OperatorScope != "" {
			count = 1
		}
		for i := 0; i < count; i++ {
			ids[fmt.Sprintf(liFilterIDPrefix+"%s-%d", task.XID, i)] = true
		}
	}
	for id := range ids {
		if !strings.HasPrefix(id, liFilterIDPrefix) {
			continue
		}
		if err := m.config.FilterPusher.DeleteFilter(id); err != nil {
			return fmt.Errorf("withdraw persisted RADIUS XID %s filter %s: %w", task.XID, id, err)
		}
	}
	logger.Info("RADIUS task requires fresh scoped authorization after restart", "xid", task.XID, "previous_generation", task.ActivationGeneration)
	return nil
}

// reconcileRADIUSTask replaces stale RADIUS definitions using the same lifecycle
// barrier as X1 modification. Invalid replacement policy withdraws the old
// authorization instead of retaining a legacy NAI/SIP task indefinitely.
func (m *Manager) reconcileRADIUSTask(task *InterceptTask) (bool, error) {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	previous, err := m.registry.GetTaskDetails(task.XID)
	if err != nil || (!IsRADIUSTask(previous) && !IsRADIUSTask(task)) {
		return false, nil
	}
	if previous.Status != TaskStatusActive && previous.Status != TaskStatusPending {
		return true, nil
	}
	validationErr := m.registry.validateTask(task)
	if !previous.StartTime.Equal(task.StartTime) {
		validationErr = errors.Join(validationErr, fmt.Errorf("RADIUS reconciliation cannot change StartTime; deactivate and reprovision"))
	}
	if err := validationErr; err != nil {
		// Revoke admission before best-effort withdrawal; a failed remote
		// filter deletion must not preserve the obsolete authorization.
		markErr := m.registry.MarkTaskFailed(task.XID, err.Error())
		m.notifyTaskModified(previous)
		cleanupErr := m.filters.RemoveFiltersForTask(task.XID)
		return true, errors.Join(err, markErr, cleanupErr, m.persistState())
	}
	if equivalentTaskDefinition(previous, task) {
		return true, nil
	}
	modifyErr := m.modifyTask(task.XID, &TaskModification{
		Targets: &task.Targets, DestinationIDs: &task.DestinationIDs,
		DeliveryType: &task.DeliveryType, EndTime: &task.EndTime,
		ImplicitDeactivationAllowed: &task.ImplicitDeactivationAllowed,
		RADIUSScope:                 &task.RADIUSScope, RADIUSMACProfile: &task.RADIUSMACProfile,
	})
	if modifyErr != nil {
		// A rejected ADMF replacement cannot leave the old target armed.
		markErr := m.registry.MarkTaskFailed(task.XID, modifyErr.Error())
		m.notifyTaskModified(previous)
		return true, errors.Join(modifyErr, markErr, m.filters.RemoveFiltersForTask(task.XID), m.persistState())
	}
	return true, nil
}

// rejectRADIUSReplacement handles a malformed ADMF definition whose XID is still
// readable. Preserve generic ADMF snapshot safeguards, but do not let a failed
// RADIUS conversion leave the previous RADIUS authorization armed.
func (m *Manager) rejectRADIUSReplacement(xid uuid.UUID, cause error) error {
	m.lifecycleMu.Lock()
	defer m.lifecycleMu.Unlock()
	previous, err := m.registry.GetTaskDetails(xid)
	if err != nil || !IsRADIUSTask(previous) {
		return nil
	}
	markErr := m.registry.MarkTaskFailed(xid, cause.Error())
	m.notifyTaskModified(previous)
	return errors.Join(markErr, m.filters.RemoveFiltersForTask(xid), m.persistState())
}
