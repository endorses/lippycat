//go:build li

// Package li provides ETSI X1/X2/X3 lawful interception support for lippycat.
package li

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/endorses/lippycat/internal/pkg/li/x1"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// X1ClientConfig holds configuration for the X1 client (ADMF notifications).
// These are separate from X1ServerConfig used for the X1 server.
type X1ClientConfig struct {
	// TLSCertFile is the path to the client TLS certificate for mutual TLS with ADMF.
	TLSCertFile string

	// TLSKeyFile is the path to the client TLS private key.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate for ADMF server verification.
	TLSCAFile string

	// KeepaliveInterval is the interval for sending keepalive messages to ADMF.
	// Set to 0 to disable keepalive.
	KeepaliveInterval time.Duration
}

// ManagerConfig holds configuration for the LI Manager.
type ManagerConfig struct {
	// Enabled controls whether LI processing is active.
	Enabled bool

	// X1ListenAddr is the address for the X1 administration interface.
	// Format: "host:port" (e.g., "0.0.0.0:8443")
	X1ListenAddr string

	// X1TLSCertFile is the path to the X1 server TLS certificate.
	X1TLSCertFile string

	// X1TLSKeyFile is the path to the X1 server TLS key.
	X1TLSKeyFile string

	// X1TLSCAFile is the path to the CA certificate for X1 client verification (mutual TLS).
	X1TLSCAFile string

	// ADMFEndpoint is the address of the ADMF for X1 notifications.
	// Format: "https://host:port"
	ADMFEndpoint string

	// NEIdentifier is the network element identifier for X1 responses.
	// Defaults to hostname if empty.
	NEIdentifier string

	// X1Client contains configuration for the X1 client (ADMF notifications).
	X1Client X1ClientConfig

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
//   - X1Server: administration interface for ADMF communication
//   - X1Client: ADMF notification sender (keepalive, error reports)
//   - (Future) DestinationManager: X2/X3 delivery connections
//
// The Manager is the main entry point for LI operations in the processor.
type Manager struct {
	mu sync.RWMutex

	config   ManagerConfig
	registry *Registry
	filters  *FilterManager

	// x1Client sends notifications to ADMF.
	x1Client *x1.Client

	// x1Server is the X1 administration interface server.
	x1Server *x1.Server

	// x1ServerCtx controls the X1 server lifecycle.
	x1ServerCtx    context.Context
	x1ServerCancel context.CancelFunc

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
	m := &Manager{
		config:   config,
		filters:  NewFilterManager(config.FilterPusher),
		stopChan: make(chan struct{}),
	}

	// Create X1 client if ADMF endpoint is configured.
	// This is used to send notifications (keepalive, errors, etc.) to the ADMF.
	if config.ADMFEndpoint != "" {
		x1ClientConfig := x1.ClientConfig{
			ADMFEndpoint:      config.ADMFEndpoint,
			NEIdentifier:      config.NEIdentifier,
			TLSCertFile:       config.X1Client.TLSCertFile,
			TLSKeyFile:        config.X1Client.TLSKeyFile,
			TLSCAFile:         config.X1Client.TLSCAFile,
			KeepaliveInterval: config.X1Client.KeepaliveInterval,
		}

		client, err := x1.NewClient(x1ClientConfig)
		if err != nil {
			logger.Warn("X1 client creation failed, ADMF notifications disabled",
				"error", err,
				"admf_endpoint", config.ADMFEndpoint,
			)
		} else {
			m.x1Client = client
		}
	}

	// Create deactivation callback that reports to ADMF and then calls user callback.
	internalCallback := func(task *InterceptTask, reason DeactivationReason) {
		// Report implicit deactivation to ADMF via X1 client.
		if m.x1Client != nil && reason != DeactivationReasonADMF {
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()

				reasonStr := reason.String()
				if reason == DeactivationReasonExpired {
					reasonStr = "Task EndTime reached"
				} else if reason == DeactivationReasonFault {
					reasonStr = task.LastError
					if reasonStr == "" {
						reasonStr = "Task terminated due to fault"
					}
				}

				if err := m.x1Client.ReportTaskImplicitDeactivation(ctx, task.XID, reasonStr); err != nil {
					logger.Error("Failed to report implicit deactivation to ADMF",
						"xid", task.XID,
						"reason", reason,
						"error", err,
					)
				}
			}()
		}

		// Call user's callback if provided.
		if deactivationCallback != nil {
			deactivationCallback(task, reason)
		}
	}

	m.registry = NewRegistry(internalCallback)

	// Create X1 server if TLS is configured.
	if config.X1ListenAddr != "" && config.X1TLSCertFile != "" && config.X1TLSKeyFile != "" {
		x1Config := x1.ServerConfig{
			ListenAddr:   config.X1ListenAddr,
			TLSCertFile:  config.X1TLSCertFile,
			TLSKeyFile:   config.X1TLSKeyFile,
			TLSCAFile:    config.X1TLSCAFile,
			NEIdentifier: config.NEIdentifier,
		}
		// Create adapters that implement x1.DestinationManager and x1.TaskManager.
		destAdapter := &managerDestinationAdapter{m: m}
		taskAdapter := &managerTaskAdapter{m: m}
		m.x1Server = x1.NewServer(x1Config, destAdapter, taskAdapter)
	}

	return m
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

	// Start X1 server if configured.
	if m.x1Server != nil {
		m.x1ServerCtx, m.x1ServerCancel = context.WithCancel(context.Background())
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			if err := m.x1Server.Start(m.x1ServerCtx); err != nil {
				logger.Error("X1 server error", "error", err)
			}
		}()
		logger.Info("X1 server started", "addr", m.config.X1ListenAddr)
	} else if m.config.X1ListenAddr != "" {
		logger.Warn("X1 server not started: TLS certificate not configured",
			"addr", m.config.X1ListenAddr,
			"hint", "provide --li-x1-tls-cert and --li-x1-tls-key",
		)
	}

	// Start X1 client if configured (for ADMF notifications).
	if m.x1Client != nil {
		m.x1Client.Start()

		// Send startup notification to ADMF.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if err := m.x1Client.ReportStartup(ctx); err != nil {
				logger.Warn("Failed to send startup notification to ADMF",
					"error", err,
					"admf", m.config.ADMFEndpoint,
				)
			}
		}()

		logger.Info("X1 client started", "admf_endpoint", m.config.ADMFEndpoint)
	}

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

	// Send shutdown notification to ADMF before stopping X1 client.
	if m.x1Client != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		if err := m.x1Client.ReportShutdown(ctx); err != nil {
			logger.Warn("Failed to send shutdown notification to ADMF",
				"error", err,
				"admf", m.config.ADMFEndpoint,
			)
		}
		cancel()
	}

	// Stop X1 server.
	if m.x1ServerCancel != nil {
		m.x1ServerCancel()
	}
	if m.x1Server != nil {
		if err := m.x1Server.Shutdown(); err != nil {
			logger.Error("X1 server shutdown error", "error", err)
		}
	}

	// Stop X1 client.
	if m.x1Client != nil {
		m.x1Client.Stop()
	}

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

// ModifyDestination updates an existing delivery destination.
func (m *Manager) ModifyDestination(did uuid.UUID, dest *Destination) error {
	return m.registry.ModifyDestination(did, dest)
}

// managerDestinationAdapter adapts the Manager to the x1.DestinationManager interface.
type managerDestinationAdapter struct {
	m *Manager
}

// Ensure managerDestinationAdapter implements x1.DestinationManager.
var _ x1.DestinationManager = (*managerDestinationAdapter)(nil)

// CreateDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) CreateDestination(dest *x1.Destination) error {
	return a.m.CreateDestinationX1(dest)
}

// GetDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) GetDestination(did uuid.UUID) (*x1.Destination, error) {
	return a.m.GetDestinationX1(did)
}

// RemoveDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) RemoveDestination(did uuid.UUID) error {
	return a.m.RemoveDestinationX1(did)
}

// ModifyDestination implements x1.DestinationManager.
func (a *managerDestinationAdapter) ModifyDestination(did uuid.UUID, dest *x1.Destination) error {
	return a.m.ModifyDestinationX1(did, dest)
}

// The following methods are the actual implementation,
// adapting between x1.Destination and li.Destination types.

// CreateDestinationX1 creates a destination from X1 request data.
func (m *Manager) CreateDestinationX1(dest *x1.Destination) error {
	liDest := &Destination{
		DID:         dest.DID,
		Address:     dest.Address,
		Port:        dest.Port,
		X2Enabled:   dest.X2Enabled,
		X3Enabled:   dest.X3Enabled,
		Description: dest.Description,
	}
	err := m.registry.CreateDestination(liDest)
	if err != nil {
		// Convert to x1 error type
		if errors.Is(err, ErrDestinationAlreadyExists) {
			return x1.ErrDestinationAlreadyExists
		}
	}
	return err
}

// GetDestinationX1 retrieves a destination for X1 response.
func (m *Manager) GetDestinationX1(did uuid.UUID) (*x1.Destination, error) {
	liDest, err := m.registry.GetDestination(did)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return nil, x1.ErrDestinationNotFound
		}
		return nil, err
	}
	return &x1.Destination{
		DID:         liDest.DID,
		Address:     liDest.Address,
		Port:        liDest.Port,
		X2Enabled:   liDest.X2Enabled,
		X3Enabled:   liDest.X3Enabled,
		Description: liDest.Description,
	}, nil
}

// RemoveDestinationX1 removes a destination via X1 request.
func (m *Manager) RemoveDestinationX1(did uuid.UUID) error {
	err := m.registry.RemoveDestination(did)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
	}
	return err
}

// ModifyDestinationX1 modifies a destination via X1 request.
func (m *Manager) ModifyDestinationX1(did uuid.UUID, dest *x1.Destination) error {
	liDest := &Destination{
		DID:         dest.DID,
		Address:     dest.Address,
		Port:        dest.Port,
		X2Enabled:   dest.X2Enabled,
		X3Enabled:   dest.X3Enabled,
		Description: dest.Description,
	}
	err := m.registry.ModifyDestination(did, liDest)
	if err != nil {
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
	}
	return err
}

// managerTaskAdapter adapts the Manager to the x1.TaskManager interface.
type managerTaskAdapter struct {
	m *Manager
}

// Ensure managerTaskAdapter implements x1.TaskManager.
var _ x1.TaskManager = (*managerTaskAdapter)(nil)

// ActivateTask implements x1.TaskManager.
func (a *managerTaskAdapter) ActivateTask(task *x1.Task) error {
	return a.m.ActivateTaskX1(task)
}

// DeactivateTask implements x1.TaskManager.
func (a *managerTaskAdapter) DeactivateTask(xid uuid.UUID) error {
	return a.m.DeactivateTaskX1(xid)
}

// ModifyTask implements x1.TaskManager.
func (a *managerTaskAdapter) ModifyTask(xid uuid.UUID, mod *x1.TaskModification) error {
	return a.m.ModifyTaskX1(xid, mod)
}

// GetTaskDetails implements x1.TaskManager.
func (a *managerTaskAdapter) GetTaskDetails(xid uuid.UUID) (*x1.Task, error) {
	return a.m.GetTaskDetailsX1(xid)
}

// The following methods are the actual implementation,
// adapting between x1.Task and li.InterceptTask types.

// ActivateTaskX1 activates a task from X1 request data.
func (m *Manager) ActivateTaskX1(task *x1.Task) error {
	// Convert x1.Task to li.InterceptTask
	liTask := &InterceptTask{
		XID:                         task.XID,
		DestinationIDs:              task.DestinationIDs,
		StartTime:                   task.StartTime,
		EndTime:                     task.EndTime,
		ImplicitDeactivationAllowed: task.ImplicitDeactivationAllowed,
	}

	// Convert targets
	for _, t := range task.Targets {
		liTask.Targets = append(liTask.Targets, TargetIdentity{
			Type:  convertTargetType(t.Type),
			Value: t.Value,
		})
	}

	// Convert delivery type
	liTask.DeliveryType = convertDeliveryType(task.DeliveryType)

	err := m.ActivateTask(liTask)
	if err != nil {
		// Convert to x1 error types
		if errors.Is(err, ErrTaskAlreadyExists) {
			return x1.ErrTaskAlreadyExists
		}
		if errors.Is(err, ErrInvalidTask) {
			return x1.ErrInvalidTask
		}
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
	}
	return err
}

// DeactivateTaskX1 deactivates a task via X1 request.
func (m *Manager) DeactivateTaskX1(xid uuid.UUID) error {
	err := m.DeactivateTask(xid)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return x1.ErrTaskNotFound
		}
	}
	return err
}

// ModifyTaskX1 modifies a task via X1 request.
func (m *Manager) ModifyTaskX1(xid uuid.UUID, mod *x1.TaskModification) error {
	// Convert x1.TaskModification to li.TaskModification
	liMod := &TaskModification{
		DestinationIDs:              mod.DestinationIDs,
		EndTime:                     mod.EndTime,
		ImplicitDeactivationAllowed: mod.ImplicitDeactivationAllowed,
	}

	// Convert targets if provided
	if mod.Targets != nil {
		targets := make([]TargetIdentity, len(*mod.Targets))
		for i, t := range *mod.Targets {
			targets[i] = TargetIdentity{
				Type:  convertTargetType(t.Type),
				Value: t.Value,
			}
		}
		liMod.Targets = &targets
	}

	// Convert delivery type if provided
	if mod.DeliveryType != nil {
		dt := convertDeliveryType(*mod.DeliveryType)
		liMod.DeliveryType = &dt
	}

	err := m.ModifyTask(xid, liMod)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return x1.ErrTaskNotFound
		}
		if errors.Is(err, ErrModifyNotAllowed) {
			return x1.ErrModifyNotAllowed
		}
		if errors.Is(err, ErrDestinationNotFound) {
			return x1.ErrDestinationNotFound
		}
	}
	return err
}

// GetTaskDetailsX1 retrieves a task for X1 response.
func (m *Manager) GetTaskDetailsX1(xid uuid.UUID) (*x1.Task, error) {
	liTask, err := m.GetTaskDetails(xid)
	if err != nil {
		if errors.Is(err, ErrTaskNotFound) {
			return nil, x1.ErrTaskNotFound
		}
		return nil, err
	}

	// Convert li.InterceptTask to x1.Task
	task := &x1.Task{
		XID:                         liTask.XID,
		DestinationIDs:              liTask.DestinationIDs,
		StartTime:                   liTask.StartTime,
		EndTime:                     liTask.EndTime,
		ImplicitDeactivationAllowed: liTask.ImplicitDeactivationAllowed,
		Status:                      convertTaskStatusToX1(liTask.Status),
		ActivatedAt:                 liTask.ActivatedAt,
		LastError:                   liTask.LastError,
	}

	// Convert targets
	for _, t := range liTask.Targets {
		task.Targets = append(task.Targets, x1.TargetIdentity{
			Type:  convertTargetTypeToX1(t.Type),
			Value: t.Value,
		})
	}

	// Convert delivery type
	task.DeliveryType = convertDeliveryTypeToX1(liTask.DeliveryType)

	return task, nil
}

// convertTargetType converts x1.TargetType to li.TargetType.
func convertTargetType(t x1.TargetType) TargetType {
	switch t {
	case x1.TargetTypeSIPURI:
		return TargetTypeSIPURI
	case x1.TargetTypeTELURI:
		return TargetTypeTELURI
	case x1.TargetTypeIPv4Address:
		return TargetTypeIPv4Address
	case x1.TargetTypeIPv4CIDR:
		return TargetTypeIPv4CIDR
	case x1.TargetTypeIPv6Address:
		return TargetTypeIPv6Address
	case x1.TargetTypeIPv6CIDR:
		return TargetTypeIPv6CIDR
	case x1.TargetTypeNAI:
		return TargetTypeNAI
	case x1.TargetTypeE164:
		return TargetTypeTELURI // E.164 is essentially TEL URI without prefix
	default:
		return TargetTypeSIPURI // Default to SIPURI
	}
}

// convertTargetTypeToX1 converts li.TargetType to x1.TargetType.
func convertTargetTypeToX1(t TargetType) x1.TargetType {
	switch t {
	case TargetTypeSIPURI:
		return x1.TargetTypeSIPURI
	case TargetTypeTELURI:
		return x1.TargetTypeTELURI
	case TargetTypeIPv4Address:
		return x1.TargetTypeIPv4Address
	case TargetTypeIPv4CIDR:
		return x1.TargetTypeIPv4CIDR
	case TargetTypeIPv6Address:
		return x1.TargetTypeIPv6Address
	case TargetTypeIPv6CIDR:
		return x1.TargetTypeIPv6CIDR
	case TargetTypeNAI:
		return x1.TargetTypeNAI
	default:
		return x1.TargetTypeSIPURI
	}
}

// convertDeliveryType converts x1.DeliveryType to li.DeliveryType.
func convertDeliveryType(dt x1.DeliveryType) DeliveryType {
	switch dt {
	case x1.DeliveryX2Only:
		return DeliveryX2Only
	case x1.DeliveryX3Only:
		return DeliveryX3Only
	case x1.DeliveryX2andX3:
		return DeliveryX2andX3
	default:
		return DeliveryX2andX3
	}
}

// convertDeliveryTypeToX1 converts li.DeliveryType to x1.DeliveryType.
func convertDeliveryTypeToX1(dt DeliveryType) x1.DeliveryType {
	switch dt {
	case DeliveryX2Only:
		return x1.DeliveryX2Only
	case DeliveryX3Only:
		return x1.DeliveryX3Only
	case DeliveryX2andX3:
		return x1.DeliveryX2andX3
	default:
		return x1.DeliveryX2andX3
	}
}

// convertTaskStatusToX1 converts li.TaskStatus to x1.TaskStatus.
func convertTaskStatusToX1(s TaskStatus) x1.TaskStatus {
	switch s {
	case TaskStatusPending:
		return x1.TaskStatusPending
	case TaskStatusActive:
		return x1.TaskStatusActive
	case TaskStatusSuspended:
		return x1.TaskStatusSuspended
	case TaskStatusDeactivated:
		return x1.TaskStatusDeactivated
	case TaskStatusFailed:
		return x1.TaskStatusFailed
	default:
		return x1.TaskStatusPending
	}
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

// ReportTaskError reports a task execution error to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportTaskError(xid uuid.UUID, errorCode int, details string) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportTaskError(ctx, xid, errorCode, details); err != nil {
			logger.Error("Failed to report task error to ADMF",
				"xid", xid,
				"error_code", errorCode,
				"error", err,
			)
		}
	}()
}

// ReportDeliveryError reports an X2/X3 delivery error to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportDeliveryError(did uuid.UUID, errorCode int, details string) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportDeliveryError(ctx, did, errorCode, details); err != nil {
			logger.Error("Failed to report delivery error to ADMF",
				"did", did,
				"error_code", errorCode,
				"error", err,
			)
		}
	}()
}

// ReportDeliveryRecovered reports that X2/X3 delivery has recovered to ADMF via X1.
// This is a non-blocking operation; errors are logged but not returned.
func (m *Manager) ReportDeliveryRecovered(did uuid.UUID) {
	if m.x1Client == nil {
		return
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := m.x1Client.ReportDeliveryRecovered(ctx, did); err != nil {
			logger.Error("Failed to report delivery recovered to ADMF",
				"did", did,
				"error", err,
			)
		}
	}()
}

// X1ClientStats returns the X1 client statistics.
// Returns zero values if X1 client is not configured.
func (m *Manager) X1ClientStats() x1.ClientStats {
	if m.x1Client == nil {
		return x1.ClientStats{}
	}
	return m.x1Client.Stats()
}

// IsADMFConnected returns whether the X1 client is connected to ADMF.
// Returns false if X1 client is not configured.
func (m *Manager) IsADMFConnected() bool {
	if m.x1Client == nil {
		return false
	}
	return m.x1Client.IsConnected()
}
