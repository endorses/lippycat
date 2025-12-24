//go:build li

// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ManagerConfig holds configuration for the LI Manager.
type ManagerConfig struct {
	// Enabled controls whether LI processing is active.
	Enabled bool

	// X1ListenAddr is the address for the X1 administration interface.
	// Format: "host:port" (e.g., "0.0.0.0:8443")
	X1ListenAddr string

	// ADMFEndpoint is the address of the ADMF for X1 notifications.
	// Format: "https://host:port"
	ADMFEndpoint string

	// FilterPusher integrates with the processor's filter management system.
	FilterPusher FilterPusher
}

// PacketProcessor is the callback for processing matched packets.
// Called when a packet matches an active intercept task.
type PacketProcessor func(task *InterceptTask, pkt *types.PacketDisplay)

// Manager coordinates all LI components.
//
// It aggregates:
//   - Registry: task and destination storage
//   - FilterManager: XID-to-filter mapping
//   - (Future) DestinationManager: X2/X3 delivery connections
//   - (Future) X1Client: ADMF notification sender
//
// The Manager is the main entry point for LI operations in the processor.
type Manager struct {
	mu sync.RWMutex

	config   ManagerConfig
	registry *Registry
	filters  *FilterManager

	// onPacketMatch is called when a packet matches an intercept task.
	// This allows the processor to handle X2/X3 delivery.
	onPacketMatch PacketProcessor

	// stats tracks LI processing statistics.
	stats ManagerStats

	// stopChan signals shutdown.
	stopChan chan struct{}
	wg       sync.WaitGroup
}

// ManagerStats contains LI processing statistics.
type ManagerStats struct {
	PacketsProcessed uint64
	PacketsMatched   uint64
	X2EventsSent     uint64
	X3EventsSent     uint64
	MatchErrors      uint64
}

// NewManager creates a new LI Manager.
//
// The deactivationCallback is called when a task is implicitly deactivated
// (e.g., EndTime expiration). This is used to notify ADMF via X1.
func NewManager(config ManagerConfig, deactivationCallback DeactivationCallback) *Manager {
	registry := NewRegistry(deactivationCallback)
	filters := NewFilterManager(config.FilterPusher)

	return &Manager{
		config:   config,
		registry: registry,
		filters:  filters,
		stopChan: make(chan struct{}),
	}
}

// Start begins LI Manager operation.
//
// This starts the registry's expiration checker and any other
// background goroutines needed for LI processing.
func (m *Manager) Start() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.config.Enabled {
		logger.Info("LI Manager disabled")
		return nil
	}

	// Start the registry's background task management
	m.registry.Start()

	logger.Info("LI Manager started",
		"x1_listen", m.config.X1ListenAddr,
		"admf_endpoint", m.config.ADMFEndpoint,
	)

	return nil
}

// Stop halts LI Manager operation.
func (m *Manager) Stop() {
	m.mu.Lock()
	defer m.mu.Unlock()

	close(m.stopChan)
	m.registry.Stop()
	m.wg.Wait()

	logger.Info("LI Manager stopped",
		"packets_processed", m.stats.PacketsProcessed,
		"packets_matched", m.stats.PacketsMatched,
	)
}

// SetPacketProcessor sets the callback for matched packets.
//
// This is called by the processor to handle X2/X3 delivery.
func (m *Manager) SetPacketProcessor(processor PacketProcessor) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onPacketMatch = processor
}

// ProcessPacket processes a packet that has already been matched by the
// filter infrastructure.
//
// This is called by the processor when a packet matches one or more filters.
// The matchedFilterIDs come from lippycat's existing optimized filter system
// (IP hash map, PhoneNumberMatcher, SIP URI Aho-Corasick) - the LI Manager
// does NOT do its own matching.
//
// Flow:
//  1. Hunter matches packet using optimized filters (Phase 0 infrastructure)
//  2. Processor receives packet with matched filter IDs
//  3. ProcessPacket looks up which XIDs those filter IDs belong to
//  4. PacketProcessor callback is invoked for X2/X3 delivery
func (m *Manager) ProcessPacket(pkt *types.PacketDisplay, matchedFilterIDs []string) {
	if pkt == nil || len(matchedFilterIDs) == 0 {
		return
	}

	if !m.config.Enabled {
		return
	}

	// Update stats
	m.mu.Lock()
	m.stats.PacketsProcessed++
	m.mu.Unlock()

	// Look up which LI tasks these filter IDs belong to
	matches := m.filters.LookupMatches(matchedFilterIDs)
	if len(matches) == 0 {
		return
	}

	// Update match stats and get processor
	m.mu.Lock()
	m.stats.PacketsMatched++
	processor := m.onPacketMatch
	m.mu.Unlock()

	if processor == nil {
		return
	}

	// For each matching task, invoke the packet processor
	for _, match := range matches {
		task, err := m.registry.GetTaskDetails(match.XID)
		if err != nil {
			// Task may have been deactivated between match and lookup
			m.mu.Lock()
			m.stats.MatchErrors++
			m.mu.Unlock()
			continue
		}

		if !task.IsActive() {
			continue
		}

		processor(task, pkt)
	}
}

// ActivateTask adds and activates a new intercept task.
//
// This creates filters for the task's targets and pushes them
// to the filter management system.
func (m *Manager) ActivateTask(task *InterceptTask) error {
	// First activate in registry (validates task)
	if err := m.registry.ActivateTask(task); err != nil {
		return err
	}

	// Create filters for the task
	filterIDs, err := m.filters.CreateFiltersForTask(task)
	if err != nil {
		// Rollback: deactivate the task
		_ = m.registry.DeactivateTask(task.XID)
		return err
	}

	logger.Info("LI task activated",
		"xid", task.XID,
		"targets", len(task.Targets),
		"filters", len(filterIDs),
		"delivery_type", task.DeliveryType.String(),
	)

	return nil
}

// ModifyTask updates an existing task's parameters atomically.
func (m *Manager) ModifyTask(xid uuid.UUID, mod *TaskModification) error {
	// First modify in registry
	if err := m.registry.ModifyTask(xid, mod); err != nil {
		return err
	}

	// If targets changed, update filters
	if mod.Targets != nil {
		task, err := m.registry.GetTaskDetails(xid)
		if err != nil {
			return err
		}
		if err := m.filters.UpdateFiltersForTask(task); err != nil {
			return err
		}
	}

	logger.Info("LI task modified", "xid", xid)
	return nil
}

// DeactivateTask removes a task from active interception.
func (m *Manager) DeactivateTask(xid uuid.UUID) error {
	// Remove filters first
	if err := m.filters.RemoveFiltersForTask(xid); err != nil {
		logger.Error("Failed to remove filters for task",
			"xid", xid,
			"error", err,
		)
	}

	// Then deactivate in registry
	if err := m.registry.DeactivateTask(xid); err != nil {
		return err
	}

	logger.Info("LI task deactivated", "xid", xid)
	return nil
}

// GetTaskDetails retrieves a task by its XID.
func (m *Manager) GetTaskDetails(xid uuid.UUID) (*InterceptTask, error) {
	return m.registry.GetTaskDetails(xid)
}

// GetActiveTasks returns all active intercept tasks.
func (m *Manager) GetActiveTasks() []*InterceptTask {
	return m.registry.GetActiveTasks()
}

// CreateDestination adds a new X2/X3 delivery destination.
func (m *Manager) CreateDestination(dest *Destination) error {
	return m.registry.CreateDestination(dest)
}

// GetDestination retrieves a destination by its DID.
func (m *Manager) GetDestination(did uuid.UUID) (*Destination, error) {
	return m.registry.GetDestination(did)
}

// RemoveDestination removes a delivery destination.
func (m *Manager) RemoveDestination(did uuid.UUID) error {
	return m.registry.RemoveDestination(did)
}

// Stats returns current LI processing statistics.
func (m *Manager) Stats() ManagerStats {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.stats
}

// TaskCount returns the total number of tasks.
func (m *Manager) TaskCount() int {
	return m.registry.TaskCount()
}

// ActiveTaskCount returns the number of active tasks.
func (m *Manager) ActiveTaskCount() int {
	return m.registry.ActiveTaskCount()
}

// FilterCount returns the total number of LI filters.
func (m *Manager) FilterCount() int {
	return m.filters.FilterCount()
}

// IsEnabled returns whether LI processing is enabled.
func (m *Manager) IsEnabled() bool {
	return m.config.Enabled
}

// Config returns the manager configuration.
func (m *Manager) Config() ManagerConfig {
	return m.config
}

// MarkTaskFailed marks a task as failed with an error message.
func (m *Manager) MarkTaskFailed(xid uuid.UUID, errMsg string) error {
	// Remove filters
	if err := m.filters.RemoveFiltersForTask(xid); err != nil {
		logger.Error("Failed to remove filters for failed task",
			"xid", xid,
			"error", err,
		)
	}

	return m.registry.MarkTaskFailed(xid, errMsg)
}

// PurgeDeactivatedTasks removes old deactivated tasks.
func (m *Manager) PurgeDeactivatedTasks(olderThan time.Duration) int {
	return m.registry.PurgeDeactivatedTasks(olderThan)
}
