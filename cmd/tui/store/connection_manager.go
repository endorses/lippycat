package store

import (
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components"
)

// ProcessorState represents the connection state of a processor
type ProcessorState int

const (
	ProcessorStateUnknown ProcessorState = iota // Unknown state (not yet connected or discovered via hierarchy)
	ProcessorStateDisconnected
	ProcessorStateConnecting
	ProcessorStateConnected
	ProcessorStateFailed
)

// ProcessorConnection represents a configured processor and its connection state
type ProcessorConnection struct {
	Address            string
	ProcessorID        string                     // ID of the processor (from ProcessorHeartbeat)
	Status             management.ProcessorStatus // Status of the processor
	State              ProcessorState
	IsConnected        bool
	Client             interface{ Close() }
	LastAttempt        time.Time
	LastDisconnectedAt time.Time // Time when processor was last disconnected (for cleanup)
	FailureCount       int
	ReconnectTimer     *time.Timer
	SubscribedHunters  []string // Hunter IDs we're subscribed to (empty = all hunters)
	TLSInsecure        bool     // True if connection is insecure (no TLS)
	UpstreamAddr       string   // Address of upstream processor (if this processor forwards to another)
}

// ConnectionManager manages remote processor connections
type ConnectionManager struct {
	mu                 sync.RWMutex
	Processors         map[string]*ProcessorConnection    // address -> connection
	HuntersByProcessor map[string][]components.HunterInfo // address -> hunters
	RemoteClients      map[string]interface{ Close() }    // DEPRECATED: backward compatibility
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		Processors:         make(map[string]*ProcessorConnection),
		HuntersByProcessor: make(map[string][]components.HunterInfo),
		RemoteClients:      make(map[string]interface{ Close() }),
	}
}

// AddProcessor adds a processor connection
func (cm *ConnectionManager) AddProcessor(address string, conn *ProcessorConnection) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.Processors[address] = conn
}

// RemoveProcessor removes a processor connection and closes it
func (cm *ConnectionManager) RemoveProcessor(address string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if conn, exists := cm.Processors[address]; exists {
		if conn.Client != nil {
			conn.Client.Close()
		}
		if conn.ReconnectTimer != nil {
			conn.ReconnectTimer.Stop()
		}
		delete(cm.Processors, address)
		delete(cm.HuntersByProcessor, address)
	}
}

// GetProcessor retrieves a processor connection
func (cm *ConnectionManager) GetProcessor(address string) (*ProcessorConnection, bool) {
	cm.mu.RLock()
	defer cm.mu.RUnlock()
	conn, exists := cm.Processors[address]
	return conn, exists
}

// ListProcessors returns all processor connections
func (cm *ConnectionManager) ListProcessors() map[string]*ProcessorConnection {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string]*ProcessorConnection, len(cm.Processors))
	for k, v := range cm.Processors {
		result[k] = v
	}
	return result
}

// UpdateHunters updates the hunters list for a processor
func (cm *ConnectionManager) UpdateHunters(processorAddr string, hunters []components.HunterInfo) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.HuntersByProcessor[processorAddr] = hunters
}

// GetHunters retrieves hunters for a processor
func (cm *ConnectionManager) GetHunters(processorAddr string) []components.HunterInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	hunters, exists := cm.HuntersByProcessor[processorAddr]
	if !exists {
		return []components.HunterInfo{}
	}

	result := make([]components.HunterInfo, len(hunters))
	copy(result, hunters)
	return result
}

// GetAllHunters returns all hunters grouped by processor
func (cm *ConnectionManager) GetAllHunters() map[string][]components.HunterInfo {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	result := make(map[string][]components.HunterInfo, len(cm.HuntersByProcessor))
	for k, v := range cm.HuntersByProcessor {
		hunters := make([]components.HunterInfo, len(v))
		copy(hunters, v)
		result[k] = hunters
	}
	return result
}

// CloseAll closes all connections
func (cm *ConnectionManager) CloseAll() {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	for _, conn := range cm.Processors {
		if conn.Client != nil {
			conn.Client.Close()
		}
		if conn.ReconnectTimer != nil {
			conn.ReconnectTimer.Stop()
		}
	}

	for _, client := range cm.RemoteClients {
		client.Close()
	}

	cm.Processors = make(map[string]*ProcessorConnection)
	cm.HuntersByProcessor = make(map[string][]components.HunterInfo)
	cm.RemoteClients = make(map[string]interface{ Close() })
}

// ConnectionCount returns the number of active connections
func (cm *ConnectionManager) ConnectionCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	count := 0
	for _, conn := range cm.Processors {
		if conn.IsConnected {
			count++
		}
	}
	return count
}

// TotalHunterCount returns the total number of hunters across all processors
func (cm *ConnectionManager) TotalHunterCount() int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	count := 0
	for _, hunters := range cm.HuntersByProcessor {
		count += len(hunters)
	}
	return count
}
