package downstream

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/logger"
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

	// topologyPublisher forwards topology updates from downstream processors upstream
	topologyPublisher TopologyPublisher

	// ctx and cancel for managing goroutines
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new downstream processor manager
func NewManager(tlsInsecure bool, tlsCertFile, tlsKeyFile, tlsCAFile string, tlsSkipVerify bool, tlsServerName string) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		downstreams:   make(map[string]*ProcessorInfo),
		tlsInsecure:   tlsInsecure,
		tlsCertFile:   tlsCertFile,
		tlsKeyFile:    tlsKeyFile,
		tlsCAFile:     tlsCAFile,
		tlsSkipVerify: tlsSkipVerify,
		tlsServerName: tlsServerName,
		ctx:           ctx,
		cancel:        cancel,
	}
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

	// Create gRPC client to this downstream processor
	var opts []grpc.DialOption
	if m.tlsInsecure {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		// TODO: Implement TLS credentials similar to remotecapture client
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.Dial(listenAddress, opts...)
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

		// Close gRPC connection
		if proc.Conn != nil {
			_ = proc.Conn.Close()
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
func (m *Manager) GetTopology(ctx context.Context, myProcessorID string, myStatus management.ProcessorStatus, myUpstream string, myHunters []*management.ConnectedHunter) (*management.ProcessorNode, error) {
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
		logger.Error("Failed to subscribe to downstream topology",
			"processor_id", proc.ProcessorID,
			"error", err)
		cancel()
		return err
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

	for {
		update, err := stream.Recv()
		if err != nil {
			logger.Warn("Topology stream closed from downstream processor",
				"processor_id", proc.ProcessorID,
				"error", err)

			// Attempt automatic reconnection with exponential backoff
			// Start at 5s, double each time, max 60s
			proc.reconnectAttempts++
			if proc.reconnectBackoff == 0 {
				proc.reconnectBackoff = 5 * time.Second
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
				// Successfully reconnected, reset backoff and continue receiving
				proc.reconnectAttempts = 0
				proc.reconnectBackoff = 0
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

// reconnectTopologyStream attempts to reconnect the topology stream for a downstream processor
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

	logger.Info("Topology stream reconnected",
		"processor_id", proc.ProcessorID)

	return nil
}

// getProcessorID returns this processor's ID for use in subscription requests
// This should be set during manager initialization
func (m *Manager) getProcessorID() string {
	// TODO: This should be configurable or passed during manager creation
	// For now, return a placeholder
	return "processor-upstream"
}

// ForwardUpdateFilter forwards a filter update operation to a downstream processor.
// This is used for recursive routing where the target may not be a direct downstream.
//
// Parameters:
//   - ctx: Context with timeout for the operation
//   - downstreamID: The direct downstream processor to forward through
//   - req: The original filter update request (target may be further downstream)
//
// Returns the filter update result or an error with chain context.
func (m *Manager) ForwardUpdateFilter(ctx context.Context, downstreamID string, req *management.ProcessorFilterRequest) (*management.FilterUpdateResult, error) {
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

	result, err := downstream.Client.UpdateFilterOnProcessor(ctx, req)
	if err != nil {
		logger.Error("Failed to forward filter update",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", err)
		return nil, fmt.Errorf("forward to %s (target: %s): %w",
			downstreamID, req.ProcessorId, err)
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
//
// Returns the filter update result or an error with chain context.
func (m *Manager) ForwardDeleteFilter(ctx context.Context, downstreamID string, req *management.ProcessorFilterDeleteRequest) (*management.FilterUpdateResult, error) {
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

	result, err := downstream.Client.DeleteFilterOnProcessor(ctx, req)
	if err != nil {
		logger.Error("Failed to forward filter delete",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", err)
		return nil, fmt.Errorf("forward to %s (target: %s): %w",
			downstreamID, req.ProcessorId, err)
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
//
// Returns the filter response or an error with chain context.
func (m *Manager) ForwardGetFilters(ctx context.Context, downstreamID string, req *management.ProcessorFilterQuery) (*management.FilterResponse, error) {
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

	result, err := downstream.Client.GetFiltersFromProcessor(ctx, req)
	if err != nil {
		logger.Error("Failed to forward filter query",
			"downstream_id", downstreamID,
			"target_processor_id", req.ProcessorId,
			"error", err)
		return nil, fmt.Errorf("forward to %s (target: %s): %w",
			downstreamID, req.ProcessorId, err)
	}

	return result, nil
}

// Close closes all downstream connections and cancels topology subscriptions
func (m *Manager) Close() {
	// Cancel all topology subscriptions
	m.cancel()

	// Wait for all goroutines to finish
	m.wg.Wait()

	m.mu.Lock()
	defer m.mu.Unlock()

	for _, proc := range m.downstreams {
		// Cancel topology subscription
		if proc.TopologyCancel != nil {
			proc.TopologyCancel()
		}

		// Close gRPC connection
		if proc.Conn != nil {
			_ = proc.Conn.Close()
		}
	}
	m.downstreams = make(map[string]*ProcessorInfo)
}
