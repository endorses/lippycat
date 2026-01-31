package hunter

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
)

// TopologyPublisher defines the interface for publishing topology updates upstream
type TopologyPublisher interface {
	PublishTopologyUpdate(update *management.TopologyUpdate)
}

// ConnectedHunter represents a connected hunter node
type ConnectedHunter struct {
	ID                      string
	Hostname                string
	RemoteAddr              string
	Interfaces              []string
	Capabilities            *management.HunterCapabilities // Filter capabilities advertised by hunter
	ConnectedAt             int64
	LastHeartbeat           int64
	PacketsReceived         uint64 // Packets received by processor from this hunter
	PacketsCaptured         uint64 // Packets captured by hunter (from heartbeat stats)
	PacketsForwarded        uint64 // Packets forwarded by hunter (from heartbeat stats)
	ActiveFilters           uint32 // Active filter count from hunter stats
	Status                  management.HunterStatus
	FilterUpdateFailures    uint32 // Consecutive filter update send failures
	LastFilterUpdateFailure int64  // Timestamp of last filter update failure
	// System metrics (from heartbeat stats)
	CpuPercent       float32 // CPU usage percentage (0-100, -1 if unavailable)
	MemoryRssBytes   uint64  // Process RSS memory in bytes
	MemoryLimitBytes uint64  // Cgroup memory limit in bytes (0 if no limit)
}

// Manager manages connected hunter nodes
type Manager struct {
	mu      sync.RWMutex
	hunters map[string]*ConnectedHunter

	processorID string // ID of the processor this manager belongs to
	maxHunters  int

	// Callbacks for stats updates
	onStatsChanged func()

	// topologyPublisher forwards topology updates upstream for multi-level management
	topologyPublisher TopologyPublisher
}

// NewManager creates a new hunter manager
func NewManager(processorID string, maxHunters int, onStatsChanged func()) *Manager {
	return &Manager{
		processorID:    processorID,
		hunters:        make(map[string]*ConnectedHunter),
		maxHunters:     maxHunters,
		onStatsChanged: onStatsChanged,
	}
}

// SetTopologyPublisher sets the topology publisher for forwarding updates upstream
func (m *Manager) SetTopologyPublisher(publisher TopologyPublisher) {
	m.topologyPublisher = publisher
}

// Register registers or re-registers a hunter
func (m *Manager) Register(hunterID, hostname string, interfaces []string, capabilities *management.HunterCapabilities) (*ConnectedHunter, bool, error) {
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
	now := time.Now().UnixNano()
	hunter := &ConnectedHunter{
		ID:            hunterID,
		Hostname:      hostname,
		Interfaces:    interfaces,
		Capabilities:  capabilities,
		ConnectedAt:   now,
		LastHeartbeat: now, // Initialize to connection time so stale detection works
		Status:        management.HunterStatus_STATUS_HEALTHY,
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

	// Publish topology update for hunter connection
	if m.topologyPublisher != nil {
		m.topologyPublisher.PublishTopologyUpdate(&management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
			ProcessorId: m.processorID,
			TimestampNs: time.Now().UnixNano(),
			Event: &management.TopologyUpdate_HunterConnected{
				HunterConnected: &management.HunterConnectedEvent{
					Hunter: &management.ConnectedHunter{
						HunterId:     hunterID,
						Hostname:     hostname,
						RemoteAddr:   "", // Will be set by the processor when receiving registration
						Status:       management.HunterStatus_STATUS_HEALTHY,
						Interfaces:   interfaces,
						Capabilities: capabilities,
					},
				},
			},
		})
		logger.Debug("Published HUNTER_CONNECTED topology event",
			"hunter_id", hunterID,
			"hostname", hostname,
			"processor_id", m.processorID)
	}

	return hunter, isReconnect, nil
}

// UpdateHeartbeat updates a hunter's heartbeat and status
// Returns true if stats changed (e.g., filter count changed)
func (m *Manager) UpdateHeartbeat(hunterID string, timestampNs int64, status management.HunterStatus, stats *management.HunterStats) bool {
	m.mu.Lock()

	statsChanged := false
	statusChanged := false
	var oldStatus management.HunterStatus
	if hunter, exists := m.hunters[hunterID]; exists {
		hunter.LastHeartbeat = timestampNs

		// Track status changes for topology updates
		if hunter.Status != status {
			oldStatus = hunter.Status
			hunter.Status = status
			statusChanged = true
			logger.Info("Hunter status changed",
				"hunter_id", hunterID,
				"old_status", oldStatus,
				"new_status", status)
		}

		if stats != nil {
			// Update packet counts from hunter's reported stats
			hunter.PacketsCaptured = stats.PacketsCaptured
			hunter.PacketsForwarded = stats.PacketsForwarded

			// Update system metrics (CPU/RAM)
			hunter.CpuPercent = stats.CpuPercent
			hunter.MemoryRssBytes = stats.MemoryRssBytes
			hunter.MemoryLimitBytes = stats.MemoryLimitBytes

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

	// Publish topology update if status changed
	if statusChanged && m.topologyPublisher != nil {
		m.topologyPublisher.PublishTopologyUpdate(&management.TopologyUpdate{
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED,
			ProcessorId: m.processorID,
			TimestampNs: timestampNs,
			Event: &management.TopologyUpdate_HunterStatusChanged{
				HunterStatusChanged: &management.HunterStatusChangedEvent{
					HunterId:  hunterID,
					NewStatus: status,
					OldStatus: oldStatus,
				},
			},
		})
		logger.Debug("Published HUNTER_STATUS_CHANGED topology event",
			"hunter_id", hunterID,
			"old_status", oldStatus,
			"processor_id", m.processorID,
			"new_status", status)
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

// GetCapabilities returns the capabilities for a hunter
func (m *Manager) GetCapabilities(hunterID string) *management.HunterCapabilities {
	m.mu.RLock()
	defer m.mu.RUnlock()

	hunter, exists := m.hunters[hunterID]
	if !exists {
		return nil
	}

	return hunter.Capabilities
}

// MarkStale marks hunters as stale based on heartbeat timeout
// Returns the number of hunters marked as stale
func (m *Manager) MarkStale(staleThreshold time.Duration) int {
	m.mu.Lock()

	now := time.Now().UnixNano()
	staleCount := 0
	staleHunters := make([]string, 0) // Track hunters that became stale for topology updates

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
					staleHunters = append(staleHunters, hunterID)
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

	// Publish topology updates for hunters that became stale
	if m.topologyPublisher != nil {
		for _, hunterID := range staleHunters {
			m.topologyPublisher.PublishTopologyUpdate(&management.TopologyUpdate{
				UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_STATUS_CHANGED,
				ProcessorId: m.processorID,
				TimestampNs: now,
				Event: &management.TopologyUpdate_HunterStatusChanged{
					HunterStatusChanged: &management.HunterStatusChangedEvent{
						HunterId:  hunterID,
						NewStatus: management.HunterStatus_STATUS_ERROR,
						OldStatus: management.HunterStatus_STATUS_HEALTHY, // Assumption: was healthy before timeout
					},
				},
			})
			logger.Debug("Published HUNTER_STATUS_CHANGED topology event",
				"processor_id", m.processorID,
				"hunter_id", hunterID,
				"new_status", "ERROR",
				"reason", "heartbeat timeout")
		}
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

		// Publish topology update for hunter disconnection
		if m.topologyPublisher != nil {
			m.topologyPublisher.PublishTopologyUpdate(&management.TopologyUpdate{
				UpdateType:  management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
				ProcessorId: m.processorID,
				TimestampNs: time.Now().UnixNano(),
				Event: &management.TopologyUpdate_HunterDisconnected{
					HunterDisconnected: &management.HunterDisconnectedEvent{
						HunterId: hunterID,
						Reason:   "heartbeat timeout - in ERROR state beyond grace period",
					},
				},
			})
			logger.Debug("Published HUNTER_DISCONNECTED topology event",
				"processor_id", m.processorID,
				"hunter_id", hunterID,
				"reason", "heartbeat timeout")
		}
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
