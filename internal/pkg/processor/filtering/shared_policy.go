package filtering

import (
	"errors"
	"fmt"
	"strings"

	"github.com/endorses/lippycat/api/gen/management"
	filtercodec "github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"google.golang.org/protobuf/proto"
)

// SetSharedNamespace reserves centrally owned identifiers against ordinary
// operator mutations, including IDs currently absent from an empty snapshot.
func (m *Manager) SetSharedNamespace(namespace string) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if namespace == "" || (!strings.HasSuffix(namespace, "/") && namespace != "li-") {
		return ErrFilterInvalid
	}
	if m.sharedNamespace != "" && m.sharedNamespace != namespace {
		return fmt.Errorf("shared policy namespace cannot change during manager lifetime")
	}
	m.sharedNamespace = namespace
	return nil
}

// ReplaceSharedSnapshot persists one complete desired-policy map, preserving
// relay-local filters outside the owner namespace. Signed state is the primary
// rollback watermark; callers reconcile it again on startup before readiness.
func (m *Manager) ReplaceSharedSnapshot(namespace string, filters []*management.Filter) error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	if namespace == "" || namespace != m.sharedNamespace {
		return ErrFilterInvalid
	}
	if err := m.ensureInitialized(); err != nil {
		return err
	}
	m.mu.RLock()
	previous := cloneFilterMap(m.filters)
	candidate := cloneFilterMap(m.filters)
	m.mu.RUnlock()
	for id := range candidate {
		if strings.HasPrefix(id, namespace) {
			delete(candidate, id)
		}
	}
	seen := make(map[string]struct{}, len(filters))
	newRadius := make(map[string]struct{})
	for _, input := range filters {
		if input == nil || !strings.HasPrefix(input.Id, namespace) {
			return ErrFilterInvalid
		}
		if _, duplicate := seen[input.Id]; duplicate {
			return ErrFilterInvalid
		}
		seen[input.Id] = struct{}{}
		filter := proto.Clone(input).(*management.Filter)
		if err := filtercodec.ValidateManagedFilter(filter); err != nil {
			return ErrFilterInvalid
		}
		if err := m.validateSharedRevision(previous[filter.Id], filter); err != nil {
			return err
		}
		candidate[filter.Id] = filter
		if filtercodec.IsRADIUSFilter(filter.Type) {
			if _, known := m.radiusRevisions[filter.Id]; !known {
				newRadius[filter.Id] = struct{}{}
			}
		}
	}
	if len(m.radiusRevisions)+len(newRadius) > 65536 {
		return fmt.Errorf("%w: RADIUS revision history capacity reached", ErrFilterInvalid)
	}
	// Reapplying the same recovered snapshot need not rewrite storage.
	equal := len(candidate) == len(previous)
	if equal {
		for id, f := range candidate {
			if !proto.Equal(f, previous[id]) {
				equal = false
				break
			}
		}
	}
	if equal {
		return nil
	}
	committed, saveErr := m.persistCandidate(candidate)
	if !committed {
		return saveErr
	}
	m.mu.Lock()
	m.filters = candidate
	m.initialized = true
	for _, f := range filters {
		if filtercodec.IsRADIUSFilter(f.Type) {
			m.radiusRevisions[strings.Clone(f.Id)] = f.Revision
		}
	}
	m.mu.Unlock()
	// Existing ordinary subscribers reconnect for a complete snapshot. Shared
	// subscribers use the signed replacement service and never consume deltas.
	m.closeSubscriptions()
	if m.onFilterChange != nil {
		m.onFilterChange()
	}
	if saveErr != nil {
		return &securestore.CommitError{Outcome: securestore.Committed, Op: "publish shared filter policy", Err: saveErr}
	}
	return nil
}

func (m *Manager) validateSharedRevision(old, next *management.Filter) error {
	isRadius := filtercodec.IsRADIUSFilter(next.Type)
	if isRadius {
		previous, known := m.radiusRevisions[next.Id]
		if !known && len(m.radiusRevisions) >= 65536 {
			return fmt.Errorf("%w: RADIUS revision history capacity reached", ErrFilterInvalid)
		}
		if known && (old == nil || !filtercodec.IsRADIUSFilter(old.Type)) && next.Revision <= previous {
			return fmt.Errorf("%w: RADIUS restoration requires newer revision", ErrFilterInvalid)
		}
	}
	if old == nil {
		return nil
	}
	if (isRadius || filtercodec.IsRADIUSFilter(old.Type)) && !proto.Equal(old, next) && next.Revision <= old.Revision {
		return fmt.Errorf("%w: RADIUS modification requires newer revision", ErrFilterInvalid)
	}
	if isRadius && old.Radius != nil && next.Radius != nil && !proto.Equal(old.Radius, next.Radius) {
		a, b := old.Radius, next.Radius
		if a.TaskId != "" && a.TaskId == b.TaskId && b.TaskGeneration <= a.TaskGeneration {
			return fmt.Errorf("%w: RADIUS task modification requires newer generation", ErrFilterInvalid)
		}
		for _, oldCriterion := range a.Criteria {
			for _, newCriterion := range b.Criteria {
				if oldCriterion != nil && newCriterion != nil && oldCriterion.FilterId == newCriterion.FilterId && !proto.Equal(oldCriterion, newCriterion) && newCriterion.FilterRevision <= oldCriterion.FilterRevision {
					return fmt.Errorf("%w: RADIUS criterion modification requires newer revision", ErrFilterInvalid)
				}
			}
		}
	}
	return nil
}

// ReplaceSharedSnapshot on LocalTarget reconciles application and BPF state in
// one existing coordinated boundary, including complete deletion and empty state.
func (t *LocalTarget) ReplaceSharedSnapshot(namespace string, filters []*management.Filter) error {
	t.mutationMu.Lock()
	defer t.mutationMu.Unlock()
	for _, filter := range filters {
		if filter == nil || !strings.HasPrefix(filter.Id, namespace) {
			return ErrFilterInvalid
		}
		if err := t.validateFilterCapability(filter); err != nil {
			return err
		}
	}
	previous, next := t.candidateState(func(candidate map[string]*management.Filter) {
		for id := range candidate {
			if strings.HasPrefix(id, namespace) {
				delete(candidate, id)
			}
		}
		for _, filter := range filters {
			candidate[filter.Id] = cloneFilter(filter)
		}
	})
	if err := t.reconcileCandidate(previous, next); err != nil {
		return errors.New("failed to reconcile shared local filter policy")
	}
	t.commitCandidate(next)
	return nil
}
