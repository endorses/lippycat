package downstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/grpcpool"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/proxy"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// ProcessorInfo holds information about a downstream processor
type ProcessorInfo struct {
	ProcessorID   string
	ListenAddress string
	Version       string
	RegisteredAt  time.Time
	LastSeen      time.Time

	// gRPC client for querying this downstream processor
	Client management.ManagementServiceClient
	Conn   *grpc.ClientConn

	// Topology streaming fields
	TopologyStream       management.ManagementService_SubscribeTopologyClient
	TopologyCancel       context.CancelFunc
	TopologyUpdateChan   chan *management.TopologyUpdate
	TopologyStreamActive bool

	// Reconnection state for exponential backoff
	reconnectAttempts int           // Number of consecutive reconnection attempts
	reconnectBackoff  time.Duration // Current backoff duration
}

// TopologyPublisher defines the interface for publishing topology updates upstream
type TopologyPublisher interface {
	PublishTopologyUpdate(update *management.TopologyUpdate)
}

// Manager tracks downstream processors that forward packets to this processor
type Manager struct {
	mu            sync.RWMutex
	downstreams   map[string]*ProcessorInfo // processorID -> info
	tlsInsecure   bool                      // TLS mode for downstream connections
	tlsCertFile   string
	tlsKeyFile    string
	tlsCAFile     string
	tlsSkipVerify bool
	tlsServerName string

	// Connection pooling
	connPool *grpcpool.ConnectionPool

	// topologyPublisher forwards topology updates from downstream processors upstream
	topologyPublisher TopologyPublisher

	// ctx and cancel for managing goroutines
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Health check configuration
	healthCheckInterval time.Duration
}

const (
	// DefaultHealthCheckInterval is the default interval for health checks (30 seconds)
	DefaultHealthCheckInterval = 30 * time.Second
)

// NewManager creates a new downstream processor manager
func NewManager(tlsInsecure bool, tlsCertFile, tlsKeyFile, tlsCAFile string, tlsSkipVerify bool, tlsServerName string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	m := &Manager{
		downstreams:         make(map[string]*ProcessorInfo),
		tlsInsecure:         tlsInsecure,
		tlsCertFile:         tlsCertFile,
		tlsKeyFile:          tlsKeyFile,
		tlsCAFile:           tlsCAFile,
		tlsSkipVerify:       tlsSkipVerify,
		tlsServerName:       tlsServerName,
		connPool:            grpcpool.NewConnectionPool(grpcpool.DefaultPoolConfig()),
		ctx:                 ctx,
		cancel:              cancel,
		healthCheckInterval: DefaultHealthCheckInterval,
	}

	// Start health check goroutine
	m.wg.Add(1)
	go m.healthCheckLoop(m.healthCheckInterval)

	return m
}

// SetTopologyPublisher sets the topology publisher for forwarding updates upstream
func (m *Manager) SetTopologyPublisher(publisher TopologyPublisher) {
	m.topologyPublisher = publisher
}

// Register registers a downstream processor
func (m *Manager) Register(processorID, listenAddress, version string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()

	// Check if already registered
	if existing, exists := m.downstreams[processorID]; exists {
		logger.Info("Downstream processor re-registered",
			"processor_id", processorID,
			"address", listenAddress)
		existing.LastSeen = now
		existing.ListenAddress = listenAddress // Update in case it changed
		existing.Version = version
		return nil
	}

	logger.Info("Registering downstream processor",
		"processor_id", processorID,
		"address", listenAddress,
		"version", version)

	// Create gRPC client to this downstream processor using connection pool
	var opts []grpc.DialOption
	if m.tlsInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsCreds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
			CAFile:             m.tlsCAFile,
			CertFile:           m.tlsCertFile,
			KeyFile:            m.tlsKeyFile,
			SkipVerify:         m.tlsSkipVerify,
			ServerNameOverride: m.tlsServerName,
		})
		if err != nil {
			logger.Error("Failed to build TLS credentials for downstream processor",
				"processor_id", processorID,
				"address", listenAddress,
				"error", err)
			return fmt.Errorf("build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
	}

	conn, err := grpcpool.Get(m.connPool, m.ctx, listenAddress, opts...)
	if err != nil {
		logger.Error("Failed to create client for downstream processor",
			"processor_id", processorID,
			"address", listenAddress,
			"error", err)
		return err
	}

	client := management.NewManagementServiceClient(conn)

	proc := &ProcessorInfo{
		ProcessorID:   processorID,
		ListenAddress: listenAddress,
		Version:       version,
		RegisteredAt:  now,
		LastSeen:      now,
		Client:        client,
		Conn:          conn,
	}

	m.downstreams[processorID] = proc

	// Automatically subscribe to topology updates from this downstream processor
	if err := m.SubscribeToDownstream(proc); err != nil {
		logger.Warn("Failed to subscribe to downstream topology (will retry)",
			"processor_id", processorID,
			"error", err)
		// Don't fail registration - subscription will be retried on reconnection
	}

	return nil
}

// Unregister removes a downstream processor
func (m *Manager) Unregister(processorID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if proc, exists := m.downstreams[processorID]; exists {
		logger.Info("Unregistering downstream processor", "processor_id", processorID)

		// Cancel topology subscription
		if proc.TopologyCancel != nil {
			proc.TopologyCancel()
		}

		// Release connection back to pool
		if proc.Conn != nil {
			grpcpool.Release(m.connPool, proc.ListenAddress)
		}

		delete(m.downstreams, processorID)
	}
}

// GetAll returns all registered downstream processors
func (m *Manager) GetAll() []*ProcessorInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	procs := make([]*ProcessorInfo, 0, len(m.downstreams))
	for _, proc := range m.downstreams {
		procs = append(procs, proc)
	}
	return procs
}

// Get returns a downstream processor by ID, or nil if not found
func (m *Manager) Get(processorID string) *ProcessorInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return m.downstreams[processorID]
}

// GetTopology recursively queries all downstream processors for their topology
func (m *Manager) GetTopology(ctx context.Context, myProcessorID string, myStatus management.ProcessorStatus, myUpstream string, myHunters []*management.ConnectedHunter, nodeType management.NodeType, captureInterfaces []string) (*management.ProcessorNode, error) {
	m.mu.RLock()
	downstreams := make([]*ProcessorInfo, 0, len(m.downstreams))
	for _, proc := range m.downstreams {
		downstreams = append(downstreams, proc)
	}
	m.mu.RUnlock()

	// Build this processor's node
	node := &management.ProcessorNode{
		Address:           "", // Will be filled by caller (TUI knows the address it connected to)
		ProcessorId:       myProcessorID,
		Status:            myStatus,
		UpstreamProcessor: myUpstream,
		Hunters:           myHunters,
		NodeType:          nodeType,
		CaptureInterfaces: captureInterfaces,
	}

	// Query each downstream processor for its topology
	downstreamNodes := make([]*management.ProcessorNode, 0, len(downstreams))
	for _, downstream := range downstreams {
		logger.Debug("Querying downstream processor for topology",
			"downstream_id", downstream.ProcessorID,
			"address", downstream.ListenAddress)

		resp, err := downstream.Client.GetTopology(ctx, &management.TopologyRequest{})
		if err != nil {
			logger.Error("Failed to get topology from downstream processor",
				"downstream_id", downstream.ProcessorID,
				"error", err)
			// Continue with other downstreams even if one fails
			continue
		}

		if resp.Processor != nil {
			// Set the address to the downstream's listen address
			resp.Processor.Address = downstream.ListenAddress
			downstreamNodes = append(downstreamNodes, resp.Processor)
		}
	}

	node.DownstreamProcessors = downstreamNodes
	return node, nil
}

// SubscribeToDownstream subscribes to topology updates from a downstream processor.
// This should be called after a downstream processor registers to start receiving
// real-time topology updates from it.
func (m *Manager) SubscribeToDownstream(proc *ProcessorInfo) error {
	// Create context for this subscription
	ctx, cancel := context.WithCancel(m.ctx)
	proc.TopologyCancel = cancel
	proc.TopologyUpdateChan = make(chan *management.TopologyUpdate, 100)

	// Subscribe to topology updates
	req := &management.TopologySubscribeRequest{
		IncludeDownstream: true,
		ClientId:          m.getProcessorID(),
	}

	stream, err := proc.Client.SubscribeTopology(ctx, req)
	if err != nil {
		logger.Warn("Failed to subscribe to downstream topology (will retry)",
			"processor_id", proc.ProcessorID,
			"error", err)
		// Don't fail - start the receive goroutine which will retry
		// This handles the case where the downstream processor hasn't fully started yet
		m.wg.Add(1)
		go m.receiveTopologyUpdates(proc, nil)
		return nil
	}

	proc.TopologyStream = stream
	proc.TopologyStreamActive = true

	logger.Info("Subscribed to downstream processor topology",
		"processor_id", proc.ProcessorID,
		"address", proc.ListenAddress)

	// Start goroutine to receive topology updates
	m.wg.Add(1)
	go m.receiveTopologyUpdates(proc, stream)

	return nil
}

// receiveTopologyUpdates receives topology updates from a downstream processor
// and forwards them upstream. Runs until the stream is closed or context canceled.
func (m *Manager) receiveTopologyUpdates(proc *ProcessorInfo, stream management.ManagementService_SubscribeTopologyClient) {
	defer m.wg.Done()
	defer func() {
		proc.TopologyStreamActive = false
		close(proc.TopologyUpdateChan)
	}()

	// If stream is nil, immediately try to establish connection
	if stream == nil {
		proc.reconnectAttempts = 0
		proc.reconnectBackoff = 500 * time.Millisecond

		logger.Info("Attempting initial topology subscription",
			"processor_id", proc.ProcessorID,
			"backoff", proc.reconnectBackoff)

		select {
		case <-m.ctx.Done():
			return
		case <-time.After(proc.reconnectBackoff):
			if err := m.reconnectTopologyStream(proc); err != nil {
				logger.Error("Failed initial topology subscription",
					"processor_id", proc.ProcessorID,
					"error", err)
				// Will retry in main loop below
			} else {
				stream = proc.TopologyStream
				logger.Info("Initial topology subscription successful",
					"processor_id", proc.ProcessorID)
			}
		}
	}

	for {
		var update *management.TopologyUpdate
		var err error

		// Check if we have a valid stream
		if stream != nil {
			update, err = stream.Recv()
		} else {
			// No stream available, treat as error to trigger retry
			err = fmt.Errorf("no active stream")
		}

		if err != nil {
			logger.Warn("Topology stream error from downstream processor",
				"processor_id", proc.ProcessorID,
				"error", err)

			// Attempt automatic reconnection with exponential backoff
			// Start at 500ms, double each time, max 60s
			proc.reconnectAttempts++
			if proc.reconnectBackoff == 0 {
				proc.reconnectBackoff = 500 * time.Millisecond
			} else {
				proc.reconnectBackoff *= 2
				if proc.reconnectBackoff > 60*time.Second {
					proc.reconnectBackoff = 60 * time.Second
				}
			}

			logger.Info("Waiting before reconnection attempt",
				"processor_id", proc.ProcessorID,
				"attempt", proc.reconnectAttempts,
				"backoff", proc.reconnectBackoff)

			select {
			case <-m.ctx.Done():
				return
			case <-time.After(proc.reconnectBackoff):
				if err := m.reconnectTopologyStream(proc); err != nil {
					logger.Error("Failed to reconnect topology stream",
						"processor_id", proc.ProcessorID,
						"attempt", proc.reconnectAttempts,
						"error", err)
					// Continue loop to retry with next backoff
					continue
				}
				// Successfully reconnected, reset backoff and update local stream variable
				proc.reconnectAttempts = 0
				proc.reconnectBackoff = 0
				stream = proc.TopologyStream
				logger.Info("Topology stream reconnected successfully",
					"processor_id", proc.ProcessorID)
				continue
			}
		}

		// Forward update upstream via publisher
		if m.topologyPublisher != nil {
			m.topologyPublisher.PublishTopologyUpdate(update)
		}

		// Send to local channel (non-blocking)
		select {
		case proc.TopologyUpdateChan <- update:
		default:
			logger.Warn("Topology update channel full, dropping update",
				"processor_id", proc.ProcessorID,
				"update_type", update.UpdateType)
		}

		// Update last seen time
		m.mu.Lock()
		proc.LastSeen = time.Now()
		m.mu.Unlock()
	}
}

// reconnectTopologyStream attempts to reconnect the topology stream for a downstream processor.
// After reconnection, it performs a full topology re-sync by waiting for the initial snapshot
// from the topology stream.
func (m *Manager) reconnectTopologyStream(proc *ProcessorInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	logger.Info("Reconnecting topology stream",
		"processor_id", proc.ProcessorID)

	// Cancel old stream if it exists
	if proc.TopologyCancel != nil {
		proc.TopologyCancel()
	}

	// Create new context for subscription
	ctx, cancel := context.WithCancel(m.ctx)
	proc.TopologyCancel = cancel

	// Subscribe to topology updates
	req := &management.TopologySubscribeRequest{
		IncludeDownstream: true,
		ClientId:          m.getProcessorID(),
	}

	stream, err := proc.Client.SubscribeTopology(ctx, req)
	if err != nil {
		cancel()
		return err
	}

	proc.TopologyStream = stream
	proc.TopologyStreamActive = true

	logger.Info("Topology stream reconnected, waiting for initial snapshot",
		"processor_id", proc.ProcessorID)

	// Perform full topology re-sync
	// The first message in a topology subscription is always a snapshot
	// This will be handled by receiveTopologyUpdates goroutine
	// Mark processor as reachable again if publisher is set
	if m.topologyPublisher != nil {
		// Publish processor reconnected event
		update := &management.TopologyUpdate{
			TimestampNs: time.Now().UnixNano(),
			ProcessorId: proc.ProcessorID,
			UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
			Event: &management.TopologyUpdate_ProcessorConnected{
				ProcessorConnected: &management.ProcessorConnectedEvent{
					Processor: &management.ProcessorNode{
						ProcessorId: proc.ProcessorID,
						Address:     proc.ListenAddress,
						Reachable:   true,
					},
				},
			},
		}
		m.topologyPublisher.PublishTopologyUpdate(update)

		logger.Info("Published processor reconnected event",
			"processor_id", proc.ProcessorID)
	}

	return nil
}

// getProcessorID returns this processor's ID for use in subscription requests
// This should be set during manager initialization
func (m *Manager) getProcessorID() string {
	// TODO: This should be configurable or passed during manager creation
	// For now, return a placeholder
	return "processor-upstream"
}

// Shutdown gracefully shuts down the downstream manager, closing all connections
// and waiting for active goroutines to complete.
//
// This should be called during processor shutdown to ensure clean cleanup.
func (m *Manager) Shutdown(timeout time.Duration) {
	logger.Info("Shutting down downstream manager",
		"timeout", timeout,
		"downstream_count", len(m.downstreams))

	// Cancel all subscriptions and connections
	m.cancel()

	// Create timeout context for waiting on goroutines
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Wait for all goroutines to complete with timeout
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All downstream goroutines completed")
	case <-ctx.Done():
		logger.Warn("Timeout waiting for downstream goroutines to complete",
			"timeout", timeout)
	}

	// Release all downstream connections back to pool
	m.mu.Lock()
	for processorID, proc := range m.downstreams {
		logger.Debug("Releasing downstream connection",
			"processor_id", processorID)

		// Cancel topology subscription
		if proc.TopologyCancel != nil {
			proc.TopologyCancel()
		}

		// Release connection back to pool
		if proc.Conn != nil {
			grpcpool.Release(m.connPool, proc.ListenAddress)
		}
	}
	// Clear the map
	m.downstreams = make(map[string]*ProcessorInfo)
	m.mu.Unlock()

	// Close the connection pool
	grpcpool.Close(m.connPool)

	logger.Info("Downstream manager shutdown complete")
}

// ForwardUpdateFilter forwards a filter update operation to a downstream processor.
// This is used for recursive routing where the target may not be a direct downstream.
//
// Parameters:
//   - ctx: Context with timeout for the operation
//   - downstreamID: The direct downstream processor to forward through
//   - req: The original filter update request (target may be further downstream)
//   - processorPath: Current processor path from root (for chain error context)
//   - currentProcessorID: ID of this processor (for chain error context)
//
// Returns the filter update result or an error with chain context.
func (m *Manager) ForwardUpdateFilter(ctx context.Context, downstreamID string, req *management.ProcessorFilterRequest, processorPath []string, currentProcessorID string) (*management.FilterUpdateResult, error) {
	downstream := m.Get(downstreamID)
	if downstream == nil {
		logger.Error("Downstream processor not found for forwarding",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId)
		return nil, fmt.Errorf("downstream processor not found: %s (target: %s)",
			downstreamID, req.ProcessorId)
	}

	logger.Info("Forwarding filter update operation",
		"downstream_id", downstreamID,
		"target_processor_id", req.ProcessorId,
		"filter_id", req.Filter.Id)

	var result *management.FilterUpdateResult
	var err error

	// Execute with retry logic for transient failures
	retryErr := withRetry(ctx, func() error {
		result, err = downstream.Client.UpdateFilterOnProcessor(ctx, req)
		return err
	}, "UpdateFilter", req.ProcessorId)

	if retryErr != nil {
		logger.Error("Failed to forward filter update",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", retryErr)

		// Build chain context for error
		// If err is already a ChainError from downstream, preserve it
		// Otherwise, create new ChainError with full context
		return nil, m.wrapChainError(retryErr, processorPath, currentProcessorID, downstreamID, "UpdateFilter")
	}

	return result, nil
}

// ForwardDeleteFilter forwards a filter deletion operation to a downstream processor.
// This is used for recursive routing where the target may not be a direct downstream.
//
// Parameters:
//   - ctx: Context with timeout for the operation
//   - downstreamID: The direct downstream processor to forward through
//   - req: The original filter delete request (target may be further downstream)
//   - processorPath: Current processor path from root (for chain error context)
//   - currentProcessorID: ID of this processor (for chain error context)
//
// Returns the filter update result or an error with chain context.
func (m *Manager) ForwardDeleteFilter(ctx context.Context, downstreamID string, req *management.ProcessorFilterDeleteRequest, processorPath []string, currentProcessorID string) (*management.FilterUpdateResult, error) {
	downstream := m.Get(downstreamID)
	if downstream == nil {
		logger.Error("Downstream processor not found for forwarding",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId)
		return nil, fmt.Errorf("downstream processor not found: %s (target: %s)",
			downstreamID, req.ProcessorId)
	}

	logger.Info("Forwarding filter delete operation",
		"downstream_id", downstreamID,
		"target_processor_id", req.ProcessorId,
		"filter_id", req.FilterId)

	var result *management.FilterUpdateResult
	var err error

	// Execute with retry logic for transient failures
	retryErr := withRetry(ctx, func() error {
		result, err = downstream.Client.DeleteFilterOnProcessor(ctx, req)
		return err
	}, "DeleteFilter", req.ProcessorId)

	if retryErr != nil {
		logger.Error("Failed to forward filter delete",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", retryErr)

		// Build chain context for error
		return nil, m.wrapChainError(retryErr, processorPath, currentProcessorID, downstreamID, "DeleteFilter")
	}

	return result, nil
}

// ForwardGetFilters forwards a filter query operation to a downstream processor.
// This is used for recursive routing where the target may not be a direct downstream.
//
// Parameters:
//   - ctx: Context with timeout for the operation
//   - downstreamID: The direct downstream processor to forward through
//   - req: The original filter query request (target may be further downstream)
//   - processorPath: Current processor path from root (for chain error context)
//   - currentProcessorID: ID of this processor (for chain error context)
//
// Returns the filter response or an error with chain context.
func (m *Manager) ForwardGetFilters(ctx context.Context, downstreamID string, req *management.ProcessorFilterQuery, processorPath []string, currentProcessorID string) (*management.FilterResponse, error) {
	downstream := m.Get(downstreamID)
	if downstream == nil {
		logger.Error("Downstream processor not found for forwarding",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId)
		return nil, fmt.Errorf("downstream processor not found: %s (target: %s)",
			downstreamID, req.ProcessorId)
	}

	logger.Info("Forwarding filter query operation",
		"downstream_id", downstreamID,
		"target_processor_id", req.ProcessorId,
		"hunter_id", req.HunterId)

	var result *management.FilterResponse
	var err error

	// Execute with retry logic for transient failures
	retryErr := withRetry(ctx, func() error {
		result, err = downstream.Client.GetFiltersFromProcessor(ctx, req)
		return err
	}, "GetFilters", req.ProcessorId)

	if retryErr != nil {
		logger.Error("Failed to forward filter query",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", retryErr)

		// Build chain context for error
		return nil, m.wrapChainError(retryErr, processorPath, currentProcessorID, downstreamID, "GetFilters")
	}

	return result, nil
}

// wrapChainError wraps an error with chain context information.
// If the error is already a ChainError, it is returned as-is (already has context).
// Otherwise, a new ChainError is created with the current processor path.
//
// Parameters:
//   - err: The error to wrap
//   - processorPath: Current processor path from root
//   - currentProcessorID: ID of this processor
//   - downstreamID: ID of the downstream processor that was contacted
//   - operation: Operation being performed (for context)
func (m *Manager) wrapChainError(err error, processorPath []string, currentProcessorID, downstreamID, operation string) error {
	// Check if error is already a ChainError
	if chainErr, ok := proxy.IsChainError(err); ok {
		// Already has chain context, return as-is
		return chainErr
	}

	// Create new ChainError with full context
	// Build processor path: existing path + current processor
	fullPath := make([]string, len(processorPath)+1)
	copy(fullPath, processorPath)
	fullPath[len(fullPath)-1] = currentProcessorID

	// The failed processor is the downstream we tried to contact
	return proxy.NewChainErrorWithOperation(
		operation,
		fullPath,
		downstreamID, // The downstream processor is where it failed
		len(fullPath),
		err,
	)
}

// healthCheckLoop runs periodically to check the health of downstream processors
// and mark them as unreachable if the topology stream is not active.
// The interval parameter is passed at goroutine creation to avoid data races.
func (m *Manager) healthCheckLoop(interval time.Duration) {
	defer m.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	logger.Info("Starting downstream health check loop",
		"interval", interval)

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Downstream health check loop stopped")
			return
		case <-ticker.C:
			m.performHealthCheck(interval)
		}
	}
}

// performHealthCheck checks the health of all downstream processors.
// The interval parameter is used to determine warning thresholds.
func (m *Manager) performHealthCheck(interval time.Duration) {
	// Snapshot processor state within the lock to avoid races
	type procSnapshot struct {
		ProcessorID          string
		LastSeen             time.Time
		TopologyStreamActive bool
		ReconnectAttempts    int
	}

	m.mu.RLock()
	snapshots := make([]procSnapshot, 0, len(m.downstreams))
	for _, proc := range m.downstreams {
		snapshots = append(snapshots, procSnapshot{
			ProcessorID:          proc.ProcessorID,
			LastSeen:             proc.LastSeen,
			TopologyStreamActive: proc.TopologyStreamActive,
			ReconnectAttempts:    proc.reconnectAttempts,
		})
	}
	m.mu.RUnlock()

	for _, snap := range snapshots {
		// Check if topology stream is active
		if !snap.TopologyStreamActive {
			logger.Warn("Downstream processor topology stream inactive",
				"processor_id", snap.ProcessorID,
				"last_seen", snap.LastSeen,
				"reconnect_attempts", snap.ReconnectAttempts)

			// Mark processor as unreachable if publisher is set
			if m.topologyPublisher != nil {
				reason := fmt.Sprintf("topology stream inactive (last seen: %v ago, reconnect attempts: %d)",
					time.Since(snap.LastSeen).Round(time.Second),
					snap.ReconnectAttempts)

				// Publish processor unreachable event
				update := &management.TopologyUpdate{
					TimestampNs: time.Now().UnixNano(),
					ProcessorId: snap.ProcessorID,
					UpdateType:  management.TopologyUpdateType_TOPOLOGY_PROCESSOR_DISCONNECTED,
					Event: &management.TopologyUpdate_ProcessorDisconnected{
						ProcessorDisconnected: &management.ProcessorDisconnectedEvent{
							ProcessorId: snap.ProcessorID,
							Reason:      reason,
						},
					},
				}
				m.topologyPublisher.PublishTopologyUpdate(update)

				logger.Info("Published processor unreachable event",
					"processor_id", snap.ProcessorID,
					"reason", reason)
			}
		} else {
			// Stream is active, update last seen
			timeSinceLastSeen := time.Since(snap.LastSeen)
			if timeSinceLastSeen > interval*2 {
				logger.Warn("Downstream processor has not sent updates recently",
					"processor_id", snap.ProcessorID,
					"last_seen", timeSinceLastSeen.Round(time.Second))
			} else {
				logger.Debug("Downstream processor health check passed",
					"processor_id", snap.ProcessorID,
					"last_seen", timeSinceLastSeen.Round(time.Second))
			}
		}
	}
}

// GetPoolStats returns statistics about the connection pool
func (m *Manager) GetPoolStats() grpcpool.Stats {
	return grpcpool.GetStats(m.connPool)
}

// Close closes all downstream connections and cancels topology subscriptions
func (m *Manager) Close() {
	// Cancel all topology subscriptions
	m.cancel()

	// Wait for all goroutines to finish
	m.wg.Wait()

	m.mu.Lock()
	for _, proc := range m.downstreams {
		// Cancel topology subscription
		if proc.TopologyCancel != nil {
			proc.TopologyCancel()
		}

		// Release connection back to pool
		if proc.Conn != nil {
			grpcpool.Release(m.connPool, proc.ListenAddress)
		}
	}
	m.downstreams = make(map[string]*ProcessorInfo)
	m.mu.Unlock()

	// Close the connection pool
	grpcpool.Close(m.connPool)
}
