// Package filtering - HunterTarget Implementation
//
// HunterTarget implements the FilterTarget interface for distributing filters
// to remote hunters via gRPC. It wraps the existing filtering.Manager to
// provide a unified filter distribution interface.
//
// Architecture:
//
//	UpdateFilter → HunterTarget.ApplyFilter() → filtering.Manager.Update() → Hunters
//
// The target is used in the distributed capture architecture:
//   - Processor receives filter update requests via gRPC management API
//   - HunterTarget routes filter updates to the appropriate hunters
//   - Manager handles capability checking and channel-based delivery
package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// HunterTarget implements FilterTarget for distributing filters to hunters.
// It wraps the filtering.Manager to provide the FilterTarget interface.
type HunterTarget struct {
	manager *Manager
}

// NewHunterTarget creates a new HunterTarget wrapping the given manager.
func NewHunterTarget(manager *Manager) *HunterTarget {
	return &HunterTarget{
		manager: manager,
	}
}

// ApplyFilter adds or updates a filter and distributes it to hunters.
// Returns the number of hunters that received the filter update.
func (t *HunterTarget) ApplyFilter(filter *management.Filter) (uint32, error) {
	if filter == nil {
		return 0, nil
	}

	logger.Debug("HunterTarget applying filter",
		"filter_id", filter.Id,
		"filter_type", filter.Type,
		"pattern", filter.Pattern,
		"target_hunters", filter.TargetHunters)

	return t.manager.Update(filter)
}

// RemoveFilter removes a filter and notifies hunters.
// Returns the number of hunters that received the removal notification.
func (t *HunterTarget) RemoveFilter(filterID string) (uint32, error) {
	if filterID == "" {
		return 0, nil
	}

	logger.Debug("HunterTarget removing filter", "filter_id", filterID)

	return t.manager.Delete(filterID)
}

// GetActiveFilters returns all currently active filters.
func (t *HunterTarget) GetActiveFilters() []*management.Filter {
	return t.manager.GetAll()
}

// SupportsFilterType returns true if hunters can handle the given filter type.
// HunterTarget supports all filter types because hunters have different capabilities
// and the manager handles capability checking per-hunter.
func (t *HunterTarget) SupportsFilterType(filterType management.FilterType) bool {
	// HunterTarget supports all filter types at the target level.
	// Individual hunter capabilities are checked by the Manager when distributing.
	// This allows centralized filter management with per-hunter capability filtering.
	switch filterType {
	case management.FilterType_FILTER_BPF,
		management.FilterType_FILTER_IP_ADDRESS,
		management.FilterType_FILTER_SIP_USER,
		management.FilterType_FILTER_PHONE_NUMBER,
		management.FilterType_FILTER_CALL_ID,
		management.FilterType_FILTER_CODEC:
		return true
	default:
		return false
	}
}

// FilterCount returns the number of active filters.
func (t *HunterTarget) FilterCount() int {
	return t.manager.Count()
}

// GetForHunter returns filters applicable to a specific hunter.
// This delegates to the manager's capability-aware filter lookup.
func (t *HunterTarget) GetForHunter(hunterID string) []*management.Filter {
	return t.manager.GetForHunter(hunterID)
}

// AddChannel creates a filter update channel for a hunter.
// This is used when a hunter subscribes to filter updates.
func (t *HunterTarget) AddChannel(hunterID string) chan *management.FilterUpdate {
	return t.manager.AddChannel(hunterID)
}

// RemoveChannel removes and closes a filter update channel for a hunter.
func (t *HunterTarget) RemoveChannel(hunterID string) {
	t.manager.RemoveChannel(hunterID)
}

// Load loads filters from the persistence file.
func (t *HunterTarget) Load() error {
	return t.manager.Load()
}

// Manager returns the underlying filter manager.
// This provides access to the full manager API when needed.
func (t *HunterTarget) Manager() *Manager {
	return t.manager
}

// Ensure HunterTarget implements FilterTarget.
var _ FilterTarget = (*HunterTarget)(nil)
