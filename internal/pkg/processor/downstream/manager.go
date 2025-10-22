package downstream

import (
	"context"
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
}

// NewManager creates a new downstream processor manager
func NewManager(tlsInsecure bool, tlsCertFile, tlsKeyFile, tlsCAFile string, tlsSkipVerify bool, tlsServerName string) *Manager {
	return &Manager{
		downstreams:   make(map[string]*ProcessorInfo),
		tlsInsecure:   tlsInsecure,
		tlsCertFile:   tlsCertFile,
		tlsKeyFile:    tlsKeyFile,
		tlsCAFile:     tlsCAFile,
		tlsSkipVerify: tlsSkipVerify,
		tlsServerName: tlsServerName,
	}
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

	m.downstreams[processorID] = &ProcessorInfo{
		ProcessorID:   processorID,
		ListenAddress: listenAddress,
		Version:       version,
		RegisteredAt:  now,
		LastSeen:      now,
		Client:        client,
		Conn:          conn,
	}

	return nil
}

// Unregister removes a downstream processor
func (m *Manager) Unregister(processorID string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if proc, exists := m.downstreams[processorID]; exists {
		logger.Info("Unregistering downstream processor", "processor_id", processorID)
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

// Close closes all downstream connections
func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, proc := range m.downstreams {
		if proc.Conn != nil {
			_ = proc.Conn.Close()
		}
	}
	m.downstreams = make(map[string]*ProcessorInfo)
}
