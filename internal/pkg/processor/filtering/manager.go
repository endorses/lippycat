package filtering

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"google.golang.org/protobuf/proto"
)

// Manager manages filters and their distribution to hunters
type Manager struct {
	// Serialize mutations through distribution and persistence so hunters cannot
	// receive an older revision (or deletion) after a newer committed update.
	// Keep mu separate: distribution callbacks may read the current filters.
	mutationMu      sync.Mutex
	mu              sync.RWMutex
	filters         map[string]*management.Filter
	radiusRevisions map[string]uint64
	initialized     bool

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
		radiusRevisions:    make(map[string]uint64),
		channels:           make(map[string]chan *management.FilterUpdate),
		capabilityProvider: capabilityProvider,
		onFilterFailure:    onFilterFailure,
		onFilterChange:     onFilterChange,
		persistenceFile:    persistenceFile,
		persistence:        persistence,
	}
}

// Load restores startup state exactly once, before any filter mutation.
// Runtime reconciliation must use Update/Delete to preserve revision history.
func (m *Manager) Load() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()

	if m.persistence == nil {
		return nil
	}

	filters, err := m.persistence.Load(m.persistenceFile)
	if err != nil {
		return err
	}

	m.mu.Lock()
	if m.initialized {
		m.mu.Unlock()
		return fmt.Errorf("filter Load is startup-only; use Update/Delete after initialization")
	}
	revisions := make(map[string]uint64)
	restored := make(map[string]*management.Filter, len(filters))
	for id, f := range filters {
		if f == nil {
			m.mu.Unlock()
			return fmt.Errorf("nil persisted filter %q", id)
		}
		if filtering.IsRADIUSFilter(f.Type) {
			if err := filtering.ValidateFilter(f); err != nil {
				m.mu.Unlock()
				return fmt.Errorf("invalid persisted RADIUS filter: %w", err)
			}
			if len(revisions) >= 65536 {
				m.mu.Unlock()
				return fmt.Errorf("RADIUS revision history capacity reached")
			}
			revisions[strings.Clone(id)] = f.Revision
		}
		restored[id] = proto.Clone(f).(*management.Filter)
	}
	m.radiusRevisions = revisions
	m.filters = restored
	m.initialized = true
	m.mu.Unlock()

	logger.Info("Loaded filters from file", "count", len(filters), "file", m.persistenceFile)
	return nil
}

// Save saves filters to persistence file
func (m *Manager) Save() error {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	return m.save()
}

// save requires mutationMu, keeping the snapshot and its write in mutation order.
func (m *Manager) save() error {
	if m.persistence == nil {
		return nil
	}

	m.mu.RLock()
	filters := make(map[string]*management.Filter, len(m.filters))
	for k, v := range m.filters {
		filters[k] = proto.Clone(v).(*management.Filter)
	}
	m.mu.RUnlock()

	return m.persistence.Save(m.persistenceFile, filters)
}

// hunterSupportsFilterType checks if a hunter supports a given filter type
func hunterSupportsFilterType(capabilities *management.HunterCapabilities, filterType management.FilterType) bool {
	if filtering.IsRADIUSFilter(filterType) && (capabilities == nil || capabilities.RadiusFilterVersion != 1) {
		return false
	}
	if capabilities == nil {
		// No capabilities info - this is a legacy hunter from before v0.2.8
		// Assume it's a generic hunter (only supports BPF and IP filters)
		logger.Debug("Hunter capabilities missing - treating as generic hunter (BPF/IP only)",
			"filter_type", filterType)
		// Only BPF and IP filters supported by legacy/generic hunters
		return filterType == management.FilterType_FILTER_BPF ||
			filterType == management.FilterType_FILTER_IP_ADDRESS
	}

	if len(capabilities.FilterTypes) == 0 {
		// Empty capabilities - this shouldn't happen with current hunters
		// Treat as generic hunter for safety
		logger.Warn("Hunter has empty FilterTypes capability list - treating as generic hunter (BPF/IP only)",
			"filter_type", filterType)
		return filterType == management.FilterType_FILTER_BPF ||
			filterType == management.FilterType_FILTER_IP_ADDRESS
	}

	// Map protobuf enum to string
	filterTypeStr := filtering.FilterTypeToString(filterType)

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
			filters = append(filters, proto.Clone(filter).(*management.Filter))
			continue
		}

		// Check if this hunter is targeted
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				filters = append(filters, proto.Clone(filter).(*management.Filter))
				break
			}
		}
	}

	return filters
}

// Update adds or modifies a filter
func (m *Manager) Update(filter *management.Filter) (uint32, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()

	if filter == nil {
		return 0, fmt.Errorf("filter is required")
	}
	if filtering.IsRADIUSFilter(filter.Type) {
		if err := filtering.ValidateFilter(filter); err != nil {
			return 0, err
		}
		for _, hunterID := range filter.TargetHunters {
			var caps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				caps = m.capabilityProvider.GetCapabilities(hunterID)
			}
			if !hunterSupportsFilterType(caps, filter.Type) {
				return 0, fmt.Errorf("hunter %s lacks RADIUS criteria/provenance capability v1", hunterID)
			}
		}
	}
	// Normalize phone number patterns before storage/distribution
	// This ensures consistent matching regardless of input format
	if filter.Type == management.FilterType_FILTER_PHONE_NUMBER {
		originalPattern := filter.Pattern
		filter.Pattern = filtering.NormalizePhonePattern(filter.Pattern)
		if filter.Pattern != originalPattern {
			logger.Debug("Normalized phone pattern",
				"original", originalPattern,
				"normalized", filter.Pattern)
		}
	}

	// Generate ID for new filters
	m.mu.Lock()
	if filter.Id == "" {
		filter.Id = fmt.Sprintf("filter-%d", time.Now().UnixNano())
		logger.Info("Generated filter ID", "filter_id", filter.Id)
	}

	// Determine if this is add or modify, and get old filter for scope comparison
	oldFilter, exists := m.filters[filter.Id]
	if filtering.IsRADIUSFilter(filter.Type) {
		previous, known := m.radiusRevisions[filter.Id]
		if (!known && len(m.radiusRevisions) >= 65536) || ((!exists || !filtering.IsRADIUSFilter(oldFilter.Type)) && known && filter.Revision <= previous) {
			m.mu.Unlock()
			return 0, fmt.Errorf("RADIUS revision history requires newer revision or has reached capacity")
		}
	}

	if exists && (filtering.IsRADIUSFilter(filter.Type) || filtering.IsRADIUSFilter(oldFilter.Type)) && !proto.Equal(oldFilter, filter) && filter.Revision <= oldFilter.Revision {
		m.mu.Unlock()
		return 0, fmt.Errorf("RADIUS filter modification requires a newer revision")
	}
	if exists && filtering.IsRADIUSFilter(filter.Type) && oldFilter.Radius != nil && filter.Radius != nil && !proto.Equal(oldFilter.Radius, filter.Radius) {
		oldR, newR := oldFilter.Radius, filter.Radius
		if oldR.TaskId != "" && oldR.TaskId == newR.TaskId && newR.TaskGeneration <= oldR.TaskGeneration {
			m.mu.Unlock()
			return 0, fmt.Errorf("RADIUS task criteria modification requires a newer task generation")
		}
		for _, oldC := range oldR.Criteria {
			for _, newC := range newR.Criteria {
				if oldC != nil && newC != nil && oldC.FilterId == newC.FilterId && !proto.Equal(oldC, newC) && newC.FilterRevision <= oldC.FilterRevision {
					m.mu.Unlock()
					return 0, fmt.Errorf("RADIUS criterion modification requires a newer criterion revision")
				}
			}
		}
	}
	m.initialized = true
	m.filters[filter.Id] = proto.Clone(filter).(*management.Filter)
	if filtering.IsRADIUSFilter(filter.Type) {
		m.radiusRevisions[strings.Clone(filter.Id)] = filter.Revision
	}

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
				Filter:     proto.Clone(oldFilter).(*management.Filter), // The recipient understands the previously installed type.
			}
			m.pushFilterUpdateToSpecificHunters(huntersToRemove, deleteUpdate)
		}
	}

	// Push filter update to affected hunters
	update := &management.FilterUpdate{
		UpdateType: updateType,
		Filter:     proto.Clone(filter).(*management.Filter),
	}

	huntersUpdated := m.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := m.save(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already in memory
	}

	return huntersUpdated, nil
}

// Delete removes a filter
func (m *Manager) Delete(filterID string) (uint32, error) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()

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
		Filter:     proto.Clone(filter).(*management.Filter),
	}

	huntersUpdated := m.pushFilterUpdate(filter, update)

	// Persist filters to disk
	if err := m.save(); err != nil {
		logger.Error("Failed to save filters to disk", "error", err)
		// Don't fail the request - filter is already removed from memory
	}

	return huntersUpdated, nil
}

// SubscribeSnapshot atomically captures policy and attaches the live stream.
// mutationMu ensures no committed mutation can be queued before its snapshot.
func (m *Manager) SubscribeSnapshot(hunterID string) (chan *management.FilterUpdate, []*management.Filter) {
	m.mutationMu.Lock()
	defer m.mutationMu.Unlock()
	filters := m.GetForHunter(hunterID)
	ch := m.AddChannel(hunterID)
	return ch, filters
}

// AddChannel creates and adds a filter update channel for a hunter
func (m *Manager) AddChannel(hunterID string) chan *management.FilterUpdate {
	ch := make(chan *management.FilterUpdate, constants.FilterUpdateChannelBuffer)

	m.channelsMu.Lock()
	if oldCh, exists := m.channels[hunterID]; exists {
		close(oldCh)
	}
	m.channels[hunterID] = ch
	m.channelsMu.Unlock()

	return ch
}

// RemoveChannel removes and closes a filter update channel for a hunter
func (m *Manager) RemoveChannel(hunterID string, ch chan *management.FilterUpdate) {
	m.channelsMu.Lock()
	if storedCh, exists := m.channels[hunterID]; exists && storedCh == ch {
		delete(m.channels, hunterID)
		close(storedCh)
	}
	m.channelsMu.Unlock()
}

// getHuntersToRemove finds connected hunters that could receive the old filter
// but cannot receive its replacement because of target scope or capability.
func (m *Manager) getHuntersToRemove(oldFilter, newFilter *management.Filter) []string {
	m.channelsMu.RLock()
	defer m.channelsMu.RUnlock()

	targetsHunter := func(filter *management.Filter, hunterID string) bool {
		if len(filter.TargetHunters) == 0 {
			return true
		}
		for _, target := range filter.TargetHunters {
			if target == hunterID {
				return true
			}
		}
		return false
	}

	var huntersToRemove []string
	for hunterID := range m.channels {
		if !targetsHunter(oldFilter, hunterID) {
			continue
		}
		var caps *management.HunterCapabilities
		if m.capabilityProvider != nil {
			caps = m.capabilityProvider.GetCapabilities(hunterID)
		}
		if !hunterSupportsFilterType(caps, oldFilter.Type) {
			continue
		}
		if !targetsHunter(newFilter, hunterID) || !hunterSupportsFilterType(caps, newFilter.Type) {
			huntersToRemove = append(huntersToRemove, hunterID)
		}
	}
	return huntersToRemove
}

// pushFilterUpdateToSpecificHunters sends filter update to a specific list of hunters
func (m *Manager) pushFilterUpdateToSpecificHunters(hunterIDs []string, update *management.FilterUpdate) uint32 {
	m.channelsMu.RLock()
	// A missed policy update invalidates the stream. Remove it after releasing
	// the read lock, using channel identity so reconnect replacements survive.
	failedChannels := make(map[string]chan *management.FilterUpdate)
	defer func() {
		m.channelsMu.RUnlock()
		for id, ch := range failedChannels {
			m.RemoveChannel(id, ch)
		}
	}()

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
			failedChannels[hunterID] = ch
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
	// A missed policy update invalidates the stream. Remove it after releasing
	// the read lock, using channel identity so reconnect replacements survive.
	failedChannels := make(map[string]chan *management.FilterUpdate)
	defer func() {
		m.channelsMu.RUnlock()
		for id, ch := range failedChannels {
			m.RemoveChannel(id, ch)
		}
	}()

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
			failedChannels[hunterID] = ch
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

	// If no target hunters specified, send to all COMPATIBLE hunters
	if len(filter.TargetHunters) == 0 {
		for hunterID, ch := range m.channels {
			// Check if hunter supports this filter type
			var hunterCaps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				hunterCaps = m.capabilityProvider.GetCapabilities(hunterID)
			}

			if !hunterSupportsFilterType(hunterCaps, filter.Type) {
				logger.Debug("Skipping filter update for incompatible hunter",
					"hunter_id", hunterID,
					"filter_id", filter.Id,
					"filter_type", filter.Type)
				continue
			}

			if sendUpdate(hunterID, ch) {
				huntersUpdated++
			}
		}
		return huntersUpdated
	}

	// Send to specific hunters (still check capabilities)
	for _, targetID := range filter.TargetHunters {
		if ch, exists := m.channels[targetID]; exists {
			// Check if hunter supports this filter type
			var hunterCaps *management.HunterCapabilities
			if m.capabilityProvider != nil {
				hunterCaps = m.capabilityProvider.GetCapabilities(targetID)
			}

			if !hunterSupportsFilterType(hunterCaps, filter.Type) {
				logger.Warn("Skipping filter update for targeted but incompatible hunter",
					"hunter_id", targetID,
					"filter_id", filter.Id,
					"filter_type", filter.Type)
				continue
			}

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
		filters = append(filters, proto.Clone(filter).(*management.Filter))
	}
	return filters
}
