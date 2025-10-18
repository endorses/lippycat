package hunter

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// ConnectedHunter represents a connected hunter node
type ConnectedHunter struct {
	ID                      string
	Hostname                string
	RemoteAddr              string
	Interfaces              []string
	ConnectedAt             int64
	LastHeartbeat           int64
	PacketsReceived         uint64 // Packets received by processor from this hunter
	PacketsCaptured         uint64 // Packets captured by hunter (from heartbeat stats)
	PacketsForwarded        uint64 // Packets forwarded by hunter (from heartbeat stats)
	ActiveFilters           uint32 // Active filter count from hunter stats
	Status                  management.HunterStatus
	FilterUpdateFailures    uint32 // Consecutive filter update send failures
	LastFilterUpdateFailure int64  // Timestamp of last filter update failure
}

// Manager manages connected hunter nodes
type Manager struct {
	mu      sync.RWMutex
	hunters map[string]*ConnectedHunter

	maxHunters int

	// Callbacks for stats updates
	onStatsChanged func()
}

// NewManager creates a new hunter manager
func NewManager(maxHunters int, onStatsChanged func()) *Manager {
	return &Manager{
		hunters:        make(map[string]*ConnectedHunter),
		maxHunters:     maxHunters,
		onStatsChanged: onStatsChanged,
	}
}

// Register registers or re-registers a hunter
func (m *Manager) Register(hunterID, hostname string, interfaces []string) (*ConnectedHunter, bool, error) {
	m.mu.Lock()

	isReconnect := false
	if _, exists := m.hunters[hunterID]; exists {
		logger.Info("Hunter re-registering (replacing old connection)", "hunter_id", hunterID)
		isReconnect = true
		// Allow re-registration (old connection will be replaced)
	} else {
		// Check max hunters limit (only for new hunters)
		if len(m.hunters) >= m.maxHunters {
			logger.Warn("Max hunters limit reached", "limit", m.maxHunters)
			m.mu.Unlock()
			return nil, false, ErrMaxHuntersReached
		}
	}

	// Register/re-register hunter
	hunter := &ConnectedHunter{
		ID:          hunterID,
		Hostname:    hostname,
		Interfaces:  interfaces,
		ConnectedAt: time.Now().UnixNano(),
		Status:      management.HunterStatus_STATUS_HEALTHY,
	}
	m.hunters[hunterID] = hunter

	// Note: We need to trigger stats callback after releasing lock to avoid deadlock
	// since the callback might call GetHealthStats() which needs a read lock
	shouldTriggerCallback := !isReconnect && m.onStatsChanged != nil

	m.mu.Unlock() // Release lock before callback

	// Trigger stats update for new registrations
	if shouldTriggerCallback {
		m.onStatsChanged()
	}

	return hunter, isReconnect, nil
}

// UpdateHeartbeat updates a hunter's heartbeat and status
// Returns true if stats changed (e.g., filter count changed)
func (m *Manager) UpdateHeartbeat(hunterID string, timestampNs int64, status management.HunterStatus, stats *management.HunterStats) bool {
	m.mu.Lock()

	statsChanged := false
	if hunter, exists := m.hunters[hunterID]; exists {
		hunter.LastHeartbeat = timestampNs
		hunter.Status = status
		if stats != nil {
			// Update packet counts from hunter's reported stats
			hunter.PacketsCaptured = stats.PacketsCaptured
			hunter.PacketsForwarded = stats.PacketsForwarded

			// Check if filter count changed
			oldFilters := hunter.ActiveFilters
			if hunter.ActiveFilters != stats.ActiveFilters {
				hunter.ActiveFilters = stats.ActiveFilters
				statsChanged = true
				logger.Info("Hunter filter count changed",
					"hunter_id", hunterID,
					"old_filters", oldFilters,
					"new_filters", stats.ActiveFilters)
			}
		} else {
			logger.Warn("Received heartbeat with nil stats",
				"hunter_id", hunterID)
		}
	}

	m.mu.Unlock() // Release lock BEFORE calling callback to avoid deadlock

	// Update aggregated stats immediately if filter count changed
	// IMPORTANT: Callback is called AFTER releasing the lock because it may
	// call back into GetHealthStats() which needs to acquire the read lock.
	if statsChanged && m.onStatsChanged != nil {
		m.onStatsChanged()
	}

	return statsChanged
}

// UpdatePacketStats updates packet statistics for a hunter
func (m *Manager) UpdatePacketStats(hunterID string, packetsReceived uint64, timestampNs int64) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hunter, exists := m.hunters[hunterID]; exists {
		hunter.PacketsReceived += packetsReceived
		hunter.LastHeartbeat = timestampNs
	}
}

// Get retrieves a hunter by ID
func (m *Manager) Get(hunterID string) (*ConnectedHunter, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hunter, exists := m.hunters[hunterID]
	return hunter, exists
}

// GetAll returns all hunters (optionally filtered by ID)
func (m *Manager) GetAll(filterID string) []*ConnectedHunter {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hunters := make([]*ConnectedHunter, 0, len(m.hunters))
	for _, hunter := range m.hunters {
		if filterID != "" && hunter.ID != filterID {
			continue
		}
		hunters = append(hunters, hunter)
	}

	return hunters
}

// Count returns the number of connected hunters
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return len(m.hunters)
}

// MarkStale marks hunters as stale based on heartbeat timeout
// Returns the number of hunters marked as stale
func (m *Manager) MarkStale(staleThreshold time.Duration) int {
	m.mu.Lock()

	now := time.Now().UnixNano()
	staleCount := 0

	for hunterID, hunter := range m.hunters {
		if hunter.LastHeartbeat > 0 {
			timeSinceHeartbeat := now - hunter.LastHeartbeat

			if timeSinceHeartbeat > int64(staleThreshold) {
				if hunter.Status != management.HunterStatus_STATUS_ERROR {
					logger.Warn("Hunter heartbeat timeout",
						"hunter_id", hunterID,
						"last_heartbeat_sec", timeSinceHeartbeat/int64(time.Second))
					hunter.Status = management.HunterStatus_STATUS_ERROR
					staleCount++
				}
			}
		}
	}

	m.mu.Unlock() // Release lock BEFORE calling callback

	// Update stats if any hunters were marked stale
	// IMPORTANT: Callback is called AFTER releasing the lock because it may
	// call back into GetHealthStats() which needs to acquire the read lock.
	if staleCount > 0 && m.onStatsChanged != nil {
		m.onStatsChanged()
	}

	return staleCount
}

// RemoveStale removes hunters that have been in ERROR state for longer than gracePeriod
// Returns the list of removed hunter IDs
func (m *Manager) RemoveStale(gracePeriod time.Duration) []string {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	var toRemove []string

	for hunterID, hunter := range m.hunters {
		if hunter.Status == management.HunterStatus_STATUS_ERROR {
			// Check how long it's been in ERROR state
			lastHeartbeat := time.Unix(0, hunter.LastHeartbeat)
			timeSinceError := now.Sub(lastHeartbeat)

			if timeSinceError > gracePeriod {
				toRemove = append(toRemove, hunterID)
			}
		}
	}

	// Remove stale hunters
	for _, hunterID := range toRemove {
		logger.Info("Removing stale hunter from map",
			"hunter_id", hunterID,
			"reason", "in ERROR state beyond grace period")
		delete(m.hunters, hunterID)
	}

	return toRemove
}

// GetHealthStats returns hunter health statistics
func (m *Manager) GetHealthStats() (total, healthy, warning, errCount uint32, totalFilters uint32) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	for _, hunter := range m.hunters {
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			healthy++
		case management.HunterStatus_STATUS_WARNING:
			warning++
		case management.HunterStatus_STATUS_ERROR:
			errCount++
		}
		// Aggregate active filters from all hunters
		totalFilters += hunter.ActiveFilters
	}

	total = uint32(len(m.hunters)) // #nosec G115 - hunter count won't exceed uint32 max

	return total, healthy, warning, errCount, totalFilters
}

// UpdateFilterFailure updates filter update failure tracking for a hunter
func (m *Manager) UpdateFilterFailure(hunterID string, failed bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if hunter, exists := m.hunters[hunterID]; exists {
		if failed {
			hunter.FilterUpdateFailures++
			hunter.LastFilterUpdateFailure = time.Now().UnixNano()
		} else {
			// Success - reset failure counter
			hunter.FilterUpdateFailures = 0
		}
	}
}

// GetFilterFailures returns the filter failure count and last failure time for a hunter
func (m *Manager) GetFilterFailures(hunterID string) (failures uint32, lastFailure int64) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	if hunter, exists := m.hunters[hunterID]; exists {
		return hunter.FilterUpdateFailures, hunter.LastFilterUpdateFailure
	}
	return 0, 0
}
