package proxy

import (
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
)

// TopologyCache maintains a thread-safe in-memory cache of the complete
// processor hierarchy topology, including hunters, downstream processors,
// and active filters.
//
// The cache is updated by applying TopologyUpdate messages received from
// downstream processors via the SubscribeTopology() gRPC stream.
//
// All methods are thread-safe and can be called concurrently.
type TopologyCache struct {
	mu sync.RWMutex

	// hunters maps hunter ID to hunter information
	// Key format: "processor-id/hunter-id"
	hunters map[string]*HunterNode

	// processors maps processor ID to processor information
	processors map[string]*ProcessorNode

	// filters maps filter ID to filter information
	// Key format: "processor-id/hunter-id/filter-id"
	filters map[string]*FilterNode
}

// HunterNode represents a hunter in the topology cache
type HunterNode struct {
	ID          string
	ProcessorID string // Parent processor ID
	Address     string
	Status      string
	Metadata    map[string]string
}

// ProcessorNode represents a processor in the topology cache
type ProcessorNode struct {
	ID                string
	Address           string
	ParentID          string // Empty for root processor
	HierarchyDepth    int32
	Reachable         bool
	UnreachableReason string
	Metadata          map[string]string
}

// FilterNode represents an active filter in the topology cache
type FilterNode struct {
	ID          string
	HunterID    string
	ProcessorID string
	FilterType  string
	Pattern     string
	Active      bool
}

// NewTopologyCache creates a new empty topology cache
func NewTopologyCache() *TopologyCache {
	return &TopologyCache{
		hunters:    make(map[string]*HunterNode),
		processors: make(map[string]*ProcessorNode),
		filters:    make(map[string]*FilterNode),
	}
}

// GetHunter retrieves a hunter by its full ID (processor-id/hunter-id)
// Returns nil if the hunter is not found
func (c *TopologyCache) GetHunter(fullHunterID string) *HunterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.hunters[fullHunterID]
}

// GetProcessor retrieves a processor by its ID
// Returns nil if the processor is not found
func (c *TopologyCache) GetProcessor(processorID string) *ProcessorNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.processors[processorID]
}

// GetFilter retrieves a filter by its full ID (processor-id/hunter-id/filter-id)
// Returns nil if the filter is not found
func (c *TopologyCache) GetFilter(fullFilterID string) *FilterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.filters[fullFilterID]
}

// GetHuntersForProcessor returns all hunters registered to a specific processor
func (c *TopologyCache) GetHuntersForProcessor(processorID string) []*HunterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*HunterNode
	for _, hunter := range c.hunters {
		if hunter.ProcessorID == processorID {
			result = append(result, hunter)
		}
	}
	return result
}

// GetFiltersForHunter returns all filters active on a specific hunter
func (c *TopologyCache) GetFiltersForHunter(processorID, hunterID string) []*FilterNode {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var result []*FilterNode
	for _, filter := range c.filters {
		if filter.ProcessorID == processorID && filter.HunterID == hunterID {
			result = append(result, filter)
		}
	}
	return result
}

// GetSnapshot returns a complete snapshot of the current topology state
// This is used to send initial state to new subscribers
func (c *TopologyCache) GetSnapshot() *TopologySnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	snapshot := &TopologySnapshot{
		Hunters:    make([]*HunterNode, 0, len(c.hunters)),
		Processors: make([]*ProcessorNode, 0, len(c.processors)),
		Filters:    make([]*FilterNode, 0, len(c.filters)),
	}

	for _, hunter := range c.hunters {
		snapshot.Hunters = append(snapshot.Hunters, hunter)
	}

	for _, processor := range c.processors {
		snapshot.Processors = append(snapshot.Processors, processor)
	}

	for _, filter := range c.filters {
		snapshot.Filters = append(snapshot.Filters, filter)
	}

	return snapshot
}

// TopologySnapshot represents a complete topology state at a point in time
type TopologySnapshot struct {
	Hunters    []*HunterNode
	Processors []*ProcessorNode
	Filters    []*FilterNode
}

// Apply applies a topology update to the cache
// The update parameter must be a *management.TopologyUpdate message
func (c *TopologyCache) Apply(update *management.TopologyUpdate) {
	if update == nil {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	// Handle different event types using type switch on the oneof field
	switch event := update.Event.(type) {
	case *management.TopologyUpdate_HunterConnected:
		c.applyHunterConnected(update.ProcessorId, event.HunterConnected)

	case *management.TopologyUpdate_HunterDisconnected:
		c.applyHunterDisconnected(update.ProcessorId, event.HunterDisconnected)

	case *management.TopologyUpdate_ProcessorConnected:
		c.applyProcessorConnected(event.ProcessorConnected)

	case *management.TopologyUpdate_ProcessorDisconnected:
		c.applyProcessorDisconnected(event.ProcessorDisconnected)

	case *management.TopologyUpdate_HunterStatusChanged:
		c.applyHunterStatusChanged(update.ProcessorId, event.HunterStatusChanged)
	}
}

// applyHunterConnected handles a hunter connected event
func (c *TopologyCache) applyHunterConnected(processorID string, event *management.HunterConnectedEvent) {
	if event == nil || event.Hunter == nil {
		return
	}

	hunter := event.Hunter
	fullID := processorID + "/" + hunter.HunterId

	// Create HunterNode from protobuf message
	node := &HunterNode{
		ID:          hunter.HunterId,
		ProcessorID: processorID,
		Address:     hunter.RemoteAddr,
		Status:      hunter.Status.String(),
		Metadata:    make(map[string]string),
	}

	// Copy metadata if available
	if len(hunter.Interfaces) > 0 {
		node.Metadata["interfaces"] = hunter.Interfaces[0] // Store first interface
	}
	if hunter.Hostname != "" {
		node.Metadata["hostname"] = hunter.Hostname
	}

	c.hunters[fullID] = node
}

// applyHunterDisconnected handles a hunter disconnected event
func (c *TopologyCache) applyHunterDisconnected(processorID string, event *management.HunterDisconnectedEvent) {
	if event == nil {
		return
	}

	fullID := processorID + "/" + event.HunterId
	delete(c.hunters, fullID)

	// Also remove all filters for this hunter
	for filterID, filter := range c.filters {
		if filter.ProcessorID == processorID && filter.HunterID == event.HunterId {
			delete(c.filters, filterID)
		}
	}
}

// applyProcessorConnected handles a processor connected event
func (c *TopologyCache) applyProcessorConnected(event *management.ProcessorConnectedEvent) {
	if event == nil || event.Processor == nil {
		return
	}

	proc := event.Processor

	// Create ProcessorNode from protobuf message
	node := &ProcessorNode{
		ID:                proc.ProcessorId,
		Address:           proc.Address,
		ParentID:          proc.UpstreamProcessor,
		HierarchyDepth:    int32(proc.HierarchyDepth),
		Reachable:         proc.Reachable,
		UnreachableReason: proc.UnreachableReason,
		Metadata:          make(map[string]string),
	}

	// Store metadata
	node.Metadata["status"] = proc.Status.String()

	c.processors[proc.ProcessorId] = node

	// Add hunters from this processor
	for _, hunter := range proc.Hunters {
		fullID := proc.ProcessorId + "/" + hunter.HunterId
		hunterNode := &HunterNode{
			ID:          hunter.HunterId,
			ProcessorID: proc.ProcessorId,
			Address:     hunter.RemoteAddr,
			Status:      hunter.Status.String(),
			Metadata:    make(map[string]string),
		}
		if hunter.Hostname != "" {
			hunterNode.Metadata["hostname"] = hunter.Hostname
		}
		c.hunters[fullID] = hunterNode

		// Add filters for this hunter
		for _, filter := range hunter.Filters {
			filterFullID := proc.ProcessorId + "/" + hunter.HunterId + "/" + filter.Id
			filterNode := &FilterNode{
				ID:          filter.Id,
				HunterID:    hunter.HunterId,
				ProcessorID: proc.ProcessorId,
				FilterType:  filter.Type.String(),
				Pattern:     filter.Pattern,
				Active:      filter.Enabled,
			}
			c.filters[filterFullID] = filterNode
		}
	}
}

// applyProcessorDisconnected handles a processor disconnected event
func (c *TopologyCache) applyProcessorDisconnected(event *management.ProcessorDisconnectedEvent) {
	if event == nil {
		return
	}

	processorID := event.ProcessorId
	delete(c.processors, processorID)

	// Remove all hunters for this processor
	for hunterID, hunter := range c.hunters {
		if hunter.ProcessorID == processorID {
			delete(c.hunters, hunterID)
		}
	}

	// Remove all filters for this processor
	for filterID, filter := range c.filters {
		if filter.ProcessorID == processorID {
			delete(c.filters, filterID)
		}
	}
}

// applyHunterStatusChanged handles a hunter status change event
func (c *TopologyCache) applyHunterStatusChanged(processorID string, event *management.HunterStatusChangedEvent) {
	if event == nil {
		return
	}

	fullID := processorID + "/" + event.HunterId
	if hunter, exists := c.hunters[fullID]; exists {
		hunter.Status = event.NewStatus.String()
	}
}

// AddHunter adds or updates a hunter in the cache
func (c *TopologyCache) AddHunter(hunter *HunterNode) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fullID := hunter.ProcessorID + "/" + hunter.ID
	c.hunters[fullID] = hunter
}

// RemoveHunter removes a hunter from the cache
func (c *TopologyCache) RemoveHunter(processorID, hunterID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fullID := processorID + "/" + hunterID
	delete(c.hunters, fullID)

	// Also remove all filters for this hunter
	for filterID, filter := range c.filters {
		if filter.ProcessorID == processorID && filter.HunterID == hunterID {
			delete(c.filters, filterID)
		}
	}
}

// AddProcessor adds or updates a processor in the cache
func (c *TopologyCache) AddProcessor(processor *ProcessorNode) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.processors[processor.ID] = processor
}

// RemoveProcessor removes a processor from the cache
func (c *TopologyCache) RemoveProcessor(processorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.processors, processorID)

	// Also remove all hunters and filters for this processor
	for hunterID, hunter := range c.hunters {
		if hunter.ProcessorID == processorID {
			delete(c.hunters, hunterID)
		}
	}

	for filterID, filter := range c.filters {
		if filter.ProcessorID == processorID {
			delete(c.filters, filterID)
		}
	}
}

// AddFilter adds or updates a filter in the cache
func (c *TopologyCache) AddFilter(filter *FilterNode) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fullID := filter.ProcessorID + "/" + filter.HunterID + "/" + filter.ID
	c.filters[fullID] = filter
}

// RemoveFilter removes a filter from the cache
func (c *TopologyCache) RemoveFilter(processorID, hunterID, filterID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	fullID := processorID + "/" + hunterID + "/" + filterID
	delete(c.filters, fullID)
}

// MarkProcessorUnreachable marks a processor and its entire subtree as unreachable
func (c *TopologyCache) MarkProcessorUnreachable(processorID, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if processor, exists := c.processors[processorID]; exists {
		processor.Reachable = false
		processor.UnreachableReason = reason
	}
}

// MarkProcessorReachable marks a processor as reachable again
func (c *TopologyCache) MarkProcessorReachable(processorID string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if processor, exists := c.processors[processorID]; exists {
		processor.Reachable = true
		processor.UnreachableReason = ""
	}
}
