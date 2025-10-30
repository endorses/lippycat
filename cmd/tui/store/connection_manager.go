package store

import (
	"fmt"
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
	Reachable          bool     // Whether this processor is reachable for management operations
	UnreachableReason  string   // Reason why processor is unreachable (empty if reachable)
}

// ConnectionManager manages remote processor connections
type ConnectionManager struct {
	mu                 sync.RWMutex
	Processors         map[string]*ProcessorConnection    // address -> connection
	HuntersByProcessor map[string][]components.HunterInfo // address -> hunters
	RemoteClients      map[string]interface{ Close() }    // DEPRECATED: backward compatibility
	rootProcessorCache map[string]string                  // target address -> root processor address (for hierarchy routing)
}

// NewConnectionManager creates a new connection manager
func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		Processors:         make(map[string]*ProcessorConnection),
		HuntersByProcessor: make(map[string][]components.HunterInfo),
		RemoteClients:      make(map[string]interface{ Close() }),
		rootProcessorCache: make(map[string]string),
	}
}

// AddProcessor adds a processor connection
func (cm *ConnectionManager) AddProcessor(address string, conn *ProcessorConnection) {
	cm.mu.Lock()
	defer cm.mu.Unlock()
	cm.Processors[address] = conn
	// Invalidate cache when topology changes
	cm.rootProcessorCache = make(map[string]string)
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
		// Invalidate cache when topology changes
		cm.rootProcessorCache = make(map[string]string)
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
	cm.rootProcessorCache = make(map[string]string)
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

// GetRootProcessorForAddress finds the root processor (directly connected to TUI) for a given target address
// by walking up the hierarchy via UpstreamAddr fields. Returns the root processor address and client,
// or an error if no root processor is found.
//
// The root processor is the processor that the TUI is directly connected to (has a Client) and can be used
// to route operations to the target processor through the hierarchy.
//
// Example hierarchy:
//
//	TUI -> Processor A (root) -> Processor B -> Processor C (target)
//
// GetRootProcessorForAddress("processor-c:50051") would return Processor A's address and client.
func (cm *ConnectionManager) GetRootProcessorForAddress(targetAddr string) (string, interface{ Close() }, error) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	// Check cache first
	if rootAddr, exists := cm.rootProcessorCache[targetAddr]; exists {
		if proc, exists := cm.Processors[rootAddr]; exists && proc.Client != nil && proc.State == ProcessorStateConnected {
			return rootAddr, proc.Client, nil
		}
		// Cache entry is stale, remove it
		delete(cm.rootProcessorCache, targetAddr)
	}

	// Walk up the hierarchy to find the root processor
	visited := make(map[string]bool) // Prevent infinite loops
	currentAddr := targetAddr
	maxDepth := 20 // Prevent infinite loops even with cycle detection

	for i := 0; i < maxDepth; i++ {
		// Check for cycles
		if visited[currentAddr] {
			return "", nil, fmt.Errorf("cycle detected in processor hierarchy at %s", currentAddr)
		}
		visited[currentAddr] = true

		// Get the processor
		proc, exists := cm.Processors[currentAddr]
		if !exists {
			return "", nil, fmt.Errorf("processor %s not found in hierarchy", currentAddr)
		}

		// If this processor is directly connected (has a Client), it's the root
		if proc.Client != nil && proc.State == ProcessorStateConnected {
			// Cache the result
			cm.rootProcessorCache[targetAddr] = currentAddr
			return currentAddr, proc.Client, nil
		}

		// If no upstream, we've reached the top but it's not connected
		if proc.UpstreamAddr == "" {
			return "", nil, fmt.Errorf("processor %s has no upstream and is not connected", currentAddr)
		}

		// Move to upstream processor
		currentAddr = proc.UpstreamAddr
	}

	return "", nil, fmt.Errorf("maximum hierarchy depth exceeded (max %d levels)", maxDepth)
}

// InvalidateRootProcessorCache clears the root processor cache for a specific target address
// or all cache entries if targetAddr is empty. This should be called when the hierarchy changes
// (e.g., processor connects/disconnects, upstream changes).
func (cm *ConnectionManager) InvalidateRootProcessorCache(targetAddr string) {
	cm.mu.Lock()
	defer cm.mu.Unlock()

	if targetAddr == "" {
		// Clear entire cache
		cm.rootProcessorCache = make(map[string]string)
	} else {
		// Clear specific entry
		delete(cm.rootProcessorCache, targetAddr)
	}
}

// GetHierarchyDepth calculates the depth of a processor in the hierarchy.
// Directly connected processors have depth 0, their downstream processors have depth 1, etc.
// Returns -1 if the processor is not found or if there's a cycle.
func (cm *ConnectionManager) GetHierarchyDepth(targetAddr string) int {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	visited := make(map[string]bool)
	currentAddr := targetAddr
	depth := 0
	maxDepth := 20 // Prevent infinite loops

	for depth < maxDepth {
		// Check for cycles
		if visited[currentAddr] {
			return -1 // Cycle detected
		}
		visited[currentAddr] = true

		// Get the processor
		proc, exists := cm.Processors[currentAddr]
		if !exists {
			return -1 // Processor not found
		}

		// If this processor is directly connected (has a Client), we've reached the root
		if proc.Client != nil && proc.State == ProcessorStateConnected {
			return depth
		}

		// If no upstream, this is the top but not connected
		if proc.UpstreamAddr == "" {
			// Check if it's a disconnected root (depth 0)
			return depth
		}

		// Move to upstream processor and increment depth
		currentAddr = proc.UpstreamAddr
		depth++
	}

	return -1 // Maximum depth exceeded
}

// GetProcessorPath returns the full path from the root processor to the target processor.
// Returns a slice of processor addresses in order from root to target.
// Returns nil if the processor is not found or if there's a cycle.
//
// Example: For hierarchy TUI -> P-A -> P-B -> P-C, GetProcessorPath("P-C") returns ["P-A", "P-B", "P-C"]
func (cm *ConnectionManager) GetProcessorPath(targetAddr string) []string {
	cm.mu.RLock()
	defer cm.mu.RUnlock()

	visited := make(map[string]bool)
	path := []string{}
	currentAddr := targetAddr
	maxDepth := 20

	// Build path from target up to root
	for len(path) < maxDepth {
		// Check for cycles
		if visited[currentAddr] {
			return nil // Cycle detected
		}
		visited[currentAddr] = true

		// Get the processor
		proc, exists := cm.Processors[currentAddr]
		if !exists {
			return nil // Processor not found
		}

		// Add current processor to path
		path = append(path, currentAddr)

		// If this processor is directly connected (has a Client), we've reached the root
		if proc.Client != nil && proc.State == ProcessorStateConnected {
			// Reverse the path to go from root to target
			for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
				path[i], path[j] = path[j], path[i]
			}
			return path
		}

		// If no upstream, this is the top
		if proc.UpstreamAddr == "" {
			// Reverse the path to go from root to target
			for i, j := 0, len(path)-1; i < j; i, j = i+1, j-1 {
				path[i], path[j] = path[j], path[i]
			}
			return path
		}

		// Move to upstream processor
		currentAddr = proc.UpstreamAddr
	}

	return nil // Maximum depth exceeded
}

// EstimateOperationLatency estimates the round-trip latency for an operation
// through the processor hierarchy based on depth.
// Base latency: 100ms, per-hop: 50ms
// Returns latency in milliseconds.
func (cm *ConnectionManager) EstimateOperationLatency(targetAddr string) int {
	depth := cm.GetHierarchyDepth(targetAddr)
	if depth < 0 {
		return -1 // Unknown or invalid
	}

	const baseLatency = 100  // Base operation latency in ms
	const perHopLatency = 50 // Additional latency per hop in ms

	return baseLatency + (depth * perHopLatency)
}
