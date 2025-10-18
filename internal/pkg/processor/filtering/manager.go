package filtering

import (
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// Manager manages filters and their distribution to hunters
type Manager struct {
	mu      sync.RWMutex
	filters map[string]*management.Filter

	channelsMu sync.RWMutex
	channels   map[string]chan *management.FilterUpdate // hunterID -> channel

	// Capabilities
	capabilityProvider CapabilityProvider

	// Callbacks
	onFilterFailure func(hunterID string, failed bool)
	onFilterChange  func() // Called when filter count changes

	// Persistence
	persistenceFile string
	persistence     PersistenceHandler
}

// PersistenceHandler handles filter persistence
type PersistenceHandler interface {
	Load(file string) (map[string]*management.Filter, error)
	Save(file string, filters map[string]*management.Filter) error
}

// CapabilityProvider provides hunter capabilities for filtering
type CapabilityProvider interface {
	GetCapabilities(hunterID string) *management.HunterCapabilities
}

// NewManager creates a new filter manager
func NewManager(persistenceFile string, persistence PersistenceHandler, capabilityProvider CapabilityProvider, onFilterFailure func(string, bool), onFilterChange func()) *Manager {
	return &Manager{
		filters:            make(map[string]*management.Filter),
		channels:           make(map[string]chan *management.FilterUpdate),
		capabilityProvider: capabilityProvider,
		onFilterFailure:    onFilterFailure,
		onFilterChange:     onFilterChange,
		persistenceFile:    persistenceFile,
		persistence:        persistence,
	}
}

// Load loads filters from persistence file
func (m *Manager) Load() error {
	if m.persistence == nil {
		return nil
	}

	filters, err := m.persistence.Load(m.persistenceFile)
	if err != nil {
		return err
	}

	m.mu.Lock()
	m.filters = filters
	m.mu.Unlock()

	logger.Info("Loaded filters from file", "count", len(filters), "file", m.persistenceFile)
	return nil
}

// Save saves filters to persistence file
func (m *Manager) Save() error {
	if m.persistence == nil {
		return nil
	}

	m.mu.RLock()
	filters := make(map[string]*management.Filter, len(m.filters))
	for k, v := range m.filters {
		filters[k] = v
	}
	m.mu.RUnlock()

	return m.persistence.Save(m.persistenceFile, filters)
}

// hunterSupportsFilterType checks if a hunter supports a given filter type
func hunterSupportsFilterType(capabilities *management.HunterCapabilities, filterType management.FilterType) bool {
	if capabilities == nil || len(capabilities.FilterTypes) == 0 {
		// No capabilities info - assume supports all (backward compatibility)
		return true
	}

	// Map protobuf enum to string (using existing helper from persistence.go)
	filterTypeStr := filterTypeToString(filterType)

	// Check if hunter supports this filter type
	for _, supportedType := range capabilities.FilterTypes {
		if supportedType == filterTypeStr {
			return true
		}
	}

	return false
}

// GetForHunter returns filters applicable to a hunter
func (m *Manager) GetForHunter(hunterID string) []*management.Filter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Get hunter capabilities from hunter manager
	var hunterCaps *management.HunterCapabilities
	if m.capabilityProvider != nil {
		hunterCaps = m.capabilityProvider.GetCapabilities(hunterID)
	}

	filters := make([]*management.Filter, 0)

	for _, filter := range m.filters {
		// Check if hunter supports this filter type
		if !hunterSupportsFilterType(hunterCaps, filter.Type) {
			logger.Debug("Skipping filter incompatible with hunter capabilities",
				"hunter_id", hunterID,
				"filter_id", filter.Id,
				"filter_type", filter.Type)
			continue
		}

		// If no target hunters specified, apply to all
		if len(filter.TargetHunters) == 0 {
			filters = append(filters, filter)
			continue
		}

		// Check if this hunter is targeted
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				filters = append(filters, filter)
				break
			}
		}
	}

	return filters
}

// Update adds or modifies a filter
func (m *Manager) Update(filter *management.Filter) (uint32, error) {
	// Generate ID for new filters
	m.mu.Lock()
	if filter.Id == "" {
		filter.Id = fmt.Sprintf("filter-%d", time.Now().UnixNano())
		logger.Info("Generated filter ID", "filter_id", filter.Id)
	}

	// Determine if this is add or modify, and get old filter for scope comparison
	oldFilter, exists := m.filters[filter.Id]
	m.filters[filter.Id] = filter

	updateType := management.FilterUpdateType_UPDATE_ADD
	if exists {
		updateType = management.FilterUpdateType_UPDATE_MODIFY
	}
	m.mu.Unlock()

	// If modifying an existing filter, check if scope changed
	// and send DELETE to hunters that are no longer targeted
	if exists {
		huntersToRemove := m.getHuntersToRemove(oldFilter, filter)
		if len(huntersToRemove) > 0 {
			deleteUpdate := &management.FilterUpdate{
				UpdateType: management.FilterUpdateType_UPDATE_DELETE,
				Filter:     filter, // Use new filter but with DELETE type
			}
			m.pushFilterUpdateToSpecificHunters(huntersToRemove, deleteUpdate)
		}
	}

	// Push filter update to affected hunters
	update := &management.FilterUpdate{
		UpdateType: updateType,
		Filter:     filter,
	}

	huntersUpdated := m.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := m.Save(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already in memory
	}

	return huntersUpdated, nil
}

// Delete removes a filter
func (m *Manager) Delete(filterID string) (uint32, error) {
	m.mu.Lock()
	filter, exists := m.filters[filterID]
	if !exists {
		m.mu.Unlock()
		return 0, fmt.Errorf("filter not found")
	}
	delete(m.filters, filterID)
	m.mu.Unlock()

	// Push filter deletion to affected hunters
	update := &management.FilterUpdate{
		UpdateType: management.FilterUpdateType_UPDATE_DELETE,
		Filter:     filter,
	}

	huntersUpdated := m.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := m.Save(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already removed from memory
	}

	return huntersUpdated, nil
}

// AddChannel creates and adds a filter update channel for a hunter
func (m *Manager) AddChannel(hunterID string) chan *management.FilterUpdate {
	ch := make(chan *management.FilterUpdate, constants.FilterUpdateChannelBuffer)

	m.channelsMu.Lock()
	m.channels[hunterID] = ch
	m.channelsMu.Unlock()

	return ch
}

// RemoveChannel removes and closes a filter update channel for a hunter
func (m *Manager) RemoveChannel(hunterID string) {
	m.channelsMu.Lock()
	if ch, exists := m.channels[hunterID]; exists {
		delete(m.channels, hunterID)
		close(ch)
	}
	m.channelsMu.Unlock()
}

// getHuntersToRemove determines which hunters should receive DELETE when filter scope changes
func (m *Manager) getHuntersToRemove(oldFilter, newFilter *management.Filter) []string {
	m.channelsMu.RLock()
	defer m.channelsMu.RUnlock()

	// Build set of hunters that should receive the new filter
	newTargets := make(map[string]bool)
	if len(newFilter.TargetHunters) == 0 {
		// New filter applies to all hunters - no one needs DELETE
		return nil
	}
	for _, hunterID := range newFilter.TargetHunters {
		newTargets[hunterID] = true
	}

	// Find hunters that were receiving the old filter but won't receive new one
	var huntersToRemove []string

	if len(oldFilter.TargetHunters) == 0 {
		// Old filter applied to all hunters - remove from all except new targets
		for hunterID := range m.channels {
			if !newTargets[hunterID] {
				huntersToRemove = append(huntersToRemove, hunterID)
			}
		}
	} else {
		// Old filter applied to specific hunters - remove from old targets not in new targets
		for _, hunterID := range oldFilter.TargetHunters {
			if !newTargets[hunterID] {
				huntersToRemove = append(huntersToRemove, hunterID)
			}
		}
	}

	return huntersToRemove
}

// pushFilterUpdateToSpecificHunters sends filter update to a specific list of hunters
func (m *Manager) pushFilterUpdateToSpecificHunters(hunterIDs []string, update *management.FilterUpdate) uint32 {
	m.channelsMu.RLock()
	defer m.channelsMu.RUnlock()

	var huntersUpdated uint32
	const sendTimeout = 2 * time.Second

	// Helper to send with timeout and track failures
	sendUpdate := func(hunterID string, ch chan *management.FilterUpdate) bool {
		timer := time.NewTimer(sendTimeout)
		defer timer.Stop()

		select {
		case ch <- update:
			// Success - reset failure counter
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, false)
			}
			logger.Debug("Sent filter update", "hunter_id", hunterID, "filter_id", update.Filter.Id, "update_type", update.UpdateType)
			return true

		case <-timer.C:
			// Timeout - track failure
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, true)
			}

			logger.Warn("Filter update send timeout",
				"hunter_id", hunterID,
				"filter_id", update.Filter.Id,
				"update_type", update.UpdateType)
			return false
		}
	}

	// Send to specific hunters
	for _, hunterID := range hunterIDs {
		if ch, exists := m.channels[hunterID]; exists {
			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
	}

	return huntersUpdated
}

// pushFilterUpdate sends filter update to affected hunters
func (m *Manager) pushFilterUpdate(filter *management.Filter, update *management.FilterUpdate) uint32 {
	m.channelsMu.RLock()
	defer m.channelsMu.RUnlock()

	var huntersUpdated uint32
	const sendTimeout = 2 * time.Second
	const maxConsecutiveFailures = 5
	const circuitBreakerThreshold = 10 // Disconnect after this many failures

	// Helper to send with timeout and track failures
	sendUpdate := func(hunterID string, ch chan *management.FilterUpdate) bool {
		timer := time.NewTimer(sendTimeout)
		defer timer.Stop()

		select {
		case ch <- update:
			// Success - reset failure counter
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, false)
			}
			logger.Debug("Sent filter update", "hunter_id", hunterID, "filter_id", filter.Id)
			return true

		case <-timer.C:
			// Timeout - track failure
			if m.onFilterFailure != nil {
				m.onFilterFailure(hunterID, true)
			}

			// Get failure count to determine logging level
			// Note: This is a bit circular since we're calling back to hunter manager
			// but it's acceptable for logging purposes
			logger.Warn("Filter update send timeout",
				"hunter_id", hunterID,
				"filter_id", filter.Id)
			return false
		}
	}

	// If no target hunters specified, send to all
	if len(filter.TargetHunters) == 0 {
		for hunterID, ch := range m.channels {
			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
		return huntersUpdated
	}

	// Send to specific hunters
	for _, targetID := range filter.TargetHunters {
		if ch, exists := m.channels[targetID]; exists {
			if sendUpdate(targetID, ch) {
				huntersUpdated++
			}
		}
	}

	return huntersUpdated
}

// Count returns the total number of filters
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.filters)
}

// GetAll returns all filters
func (m *Manager) GetAll() []*management.Filter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	filters := make([]*management.Filter, 0, len(m.filters))
	for _, filter := range m.filters {
		filters = append(filters, filter)
	}
	return filters
}
