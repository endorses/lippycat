package upstream

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/grpcpool"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config contains upstream connection configuration
type Config struct {
	Address       string // Upstream processor address
	TLSEnabled    bool   // Enable TLS for upstream connection
	TLSCAFile     string // CA certificate file
	TLSCertFile   string // Client certificate file
	TLSKeyFile    string // Client key file
	ProcessorID   string // This processor's ID (for registration)
	ListenAddress string // This processor's listen address (for upstream to query back)
	// OutboundQueueSize bounds batches waiting for the upstream connection. When
	// full, Forward drops the new batch; because forwarded packet accounting only
	// happens after Send succeeds, the processor flow controller observes the
	// resulting backlog and applies pressure to hunters.
	OutboundQueueSize int
}

const defaultOutboundQueueSize = 256

type upstreamStream interface {
	Send(*data.PacketBatch) error
	Recv() (*data.StreamControl, error)
	CloseSend() error
}

// connection owns all outbound operations for exactly one stream generation.
// In particular, only sender calls Send and CloseSend.
type connection struct {
	stream upstreamStream
	queue  chan *data.PacketBatch
	ctx    context.Context
	cancel context.CancelFunc

	accepting      atomic.Bool
	inFlight       atomic.Int64
	disconnectOnce sync.Once
	wg             sync.WaitGroup
}

// Manager handles upstream processor connection and forwarding
type Manager struct {
	config Config

	// gRPC connection
	conn       *grpc.ClientConn
	dataClient data.DataServiceClient
	mgmtClient management.ManagementServiceClient
	generation *connection
	mu         sync.Mutex

	// Connection pooling
	connPool *grpcpool.ConnectionPool

	// Upstream processor ID (learned during registration)
	upstreamProcessorID string

	// Packet forwarding stats
	packetsForwarded *atomic.Uint64

	// Reconnection state
	reconnecting      bool
	reconnectMu       sync.Mutex
	reconnectAttempts int
	// consecutiveFailures counts failed Send calls until a batch is successfully
	// sent. It intentionally spans connection generations: opening a replacement
	// stream is not evidence that packet delivery has recovered.
	consecutiveFailures  atomic.Int32
	droppedBatches       atomic.Uint64
	maxReconnectAttempts int // 0 = unlimited

	// Context for goroutines
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new upstream connection manager
func NewManager(config Config, packetsForwarded *atomic.Uint64) *Manager {
	if config.OutboundQueueSize <= 0 {
		config.OutboundQueueSize = defaultOutboundQueueSize
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		config:           config,
		connPool:         grpcpool.NewConnectionPool(grpcpool.DefaultPoolConfig()),
		packetsForwarded: packetsForwarded,
		ctx:              ctx,
		cancel:           cancel,
	}
}

// Start begins the upstream connection manager (runs in background)
// It handles initial connection and automatic reconnection on failure.
func (m *Manager) Start() error {
	if m.config.Address == "" {
		return fmt.Errorf("upstream address not configured")
	}

	m.wg.Add(1)
	go m.connectionManager()

	return nil
}

// connectionManager manages upstream connection lifecycle with automatic reconnection
func (m *Manager) connectionManager() {
	defer m.wg.Done()

	logger.Info("Upstream connection manager started", "addr", m.config.Address)

	for {
		select {
		case <-m.ctx.Done():
			logger.Info("Upstream connection manager stopping")
			return
		default:
		}

		// Attempt to connect
		err := m.connectAndRegister()
		if err == nil {
			// Successfully connected
			logger.Info("Connected to upstream processor", "addr", m.config.Address)

			// Reset reconnection state
			m.reconnectMu.Lock()
			m.reconnecting = false
			m.reconnectAttempts = 0
			m.reconnectMu.Unlock()
			// Monitor for disconnection
			m.monitorConnection()

			// If we get here, connection was lost - clean up before reconnecting
			logger.Warn("Upstream connection lost, cleaning up before retry")
			m.cleanup()
			continue
		}

		// Connection failed
		logger.Error("Failed to connect to upstream processor", "error", err)

		// Exponential backoff
		m.reconnectMu.Lock()
		m.reconnectAttempts++
		attempts := m.reconnectAttempts
		m.reconnectMu.Unlock()

		if m.maxReconnectAttempts > 0 && attempts >= m.maxReconnectAttempts {
			logger.Error("Max upstream reconnection attempts reached, giving up",
				"attempts", attempts,
				"max", m.maxReconnectAttempts)
			return
		}

		backoff := min(time.Duration(1<<uint(min(attempts-1, 6)))*time.Second, 60*time.Second) // #nosec G115

		logger.Info("Retrying upstream connection",
			"attempt", attempts,
			"backoff", backoff)

		select {
		case <-time.After(backoff):
		case <-m.ctx.Done():
			return
		}
	}
}

// connectAndRegister establishes connection to upstream processor and registers
func (m *Manager) connectAndRegister() error {
	logger.Info("Connecting to upstream processor", "addr", m.config.Address)

	// Create gRPC connection with TLS if enabled
	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(constants.MaxGRPCMessageSize)),
		// Configure keepalive to detect broken connections quickly
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second, // Send ping every 10s
			Timeout:             3 * time.Second,  // Wait 3s for ping ack
			PermitWithoutStream: true,             // Send pings even without active streams
		}),
	}

	if m.config.TLSEnabled {
		tlsCreds, err := tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
			CAFile:   m.config.TLSCAFile,
			CertFile: m.config.TLSCertFile,
			KeyFile:  m.config.TLSKeyFile,
		})
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials for upstream: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
		logger.Info("Using TLS for upstream connection")
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Warn("Using insecure upstream connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext")
	}

	conn, err := grpcpool.Get(m.connPool, m.ctx, m.config.Address, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial upstream: %w", err)
	}

	m.conn = conn
	m.dataClient = data.NewDataServiceClient(conn)
	m.mgmtClient = management.NewManagementServiceClient(conn)

	// Register this processor with upstream
	if m.config.ProcessorID != "" && m.config.ListenAddress != "" {
		logger.Info("Registering processor with upstream",
			"processor_id", m.config.ProcessorID,
			"listen_address", m.config.ListenAddress)

		regResp, err := m.mgmtClient.RegisterProcessor(m.ctx, &management.ProcessorRegistration{
			ProcessorId:   m.config.ProcessorID,
			ListenAddress: m.config.ListenAddress,
			Version:       "dev", // TODO: Use actual version
		})
		if err != nil {
			grpcpool.Release(m.connPool, m.config.Address)
			return fmt.Errorf("failed to register with upstream processor: %w", err)
		}
		if !regResp.Accepted {
			grpcpool.Release(m.connPool, m.config.Address)
			return fmt.Errorf("upstream processor rejected registration: %s", regResp.Error)
		}

		// Store the upstream processor ID for topology reporting
		m.upstreamProcessorID = regResp.UpstreamProcessorId
		logger.Info("Successfully registered with upstream processor",
			"upstream_processor_id", m.upstreamProcessorID)
	} else {
		logger.Warn("ProcessorID or ListenAddress not configured, skipping processor registration")
	}

	// Create streaming connection
	generationCtx, generationCancel := context.WithCancel(m.ctx)
	stream, err := m.dataClient.StreamPackets(generationCtx)
	if err != nil {
		generationCancel()
		grpcpool.Release(m.connPool, m.config.Address)
		return fmt.Errorf("failed to create upstream stream: %w", err)
	}

	generation := &connection{
		stream: stream,
		queue:  make(chan *data.PacketBatch, m.config.OutboundQueueSize),
		ctx:    generationCtx,
		cancel: generationCancel,
	}
	generation.accepting.Store(true)
	m.mu.Lock()
	m.generation = generation
	m.mu.Unlock()

	generation.wg.Add(2)
	go m.sendBatches(generation)
	go m.receiveAcks(generation)

	return nil
}

// monitorConnection monitors for disconnections and returns when reconnection is needed
func (m *Manager) monitorConnection() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-m.ctx.Done():
			return

		case <-ticker.C:
			// Check if we need to reconnect
			m.reconnectMu.Lock()
			needsReconnect := m.reconnecting
			m.reconnectMu.Unlock()

			if needsReconnect {
				// Return to let connectionManager retry
				return
			}
		}
	}
}

// Disconnect closes upstream connection
func (m *Manager) Disconnect() {
	m.cancel() // Cancel context to stop goroutines

	m.wg.Wait() // Wait for goroutines to finish

	m.cleanup()

	// Close the connection pool
	grpcpool.Close(m.connPool)

	logger.Info("Disconnected from upstream processor")
}

// MarkDisconnected marks the connection as disconnected and triggers reconnection
func (m *Manager) MarkDisconnected() {
	m.reconnectMu.Lock()
	defer m.reconnectMu.Unlock()

	if m.reconnecting {
		// Already reconnecting
		return
	}

	m.reconnecting = true
	logger.Warn("Upstream connection lost, will attempt reconnection")
}

// cleanup closes current connection resources (called before reconnect or shutdown)
func (m *Manager) cleanup() {
	m.mu.Lock()
	generation := m.generation
	m.generation = nil
	m.mu.Unlock()
	if generation != nil {
		generation.accepting.Store(false)
		generation.cancel()
		generation.wg.Wait()
	}

	if m.conn != nil {
		// Release connection back to pool
		grpcpool.Release(m.connPool, m.config.Address)
		m.conn = nil
	}
}

// Forward forwards packet batch to upstream processor
func (m *Manager) Forward(batch *data.PacketBatch) {
	if batch == nil {
		return
	}
	m.mu.Lock()
	generation := m.generation
	m.mu.Unlock()

	if generation == nil || !generation.accepting.Load() {
		logger.Debug("Upstream stream not available, dropping batch")
		return
	}

	select {
	case generation.queue <- batch:
	case <-generation.ctx.Done():
	case <-m.ctx.Done():
	default:
		dropped := m.droppedBatches.Add(1)
		logger.Warn("Upstream outbound queue full, dropping batch",
			"queue_capacity", cap(generation.queue), "dropped_batches", dropped,
			"packets", len(batch.Packets))
	}
}

// QueueDepth returns the current connection generation's outstanding batches.
func (m *Manager) QueueDepth() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation == nil {
		return 0
	}
	return len(m.generation.queue) + int(m.generation.inFlight.Load())
}

// QueueCapacity returns the bounded upstream queue capacity.
func (m *Manager) QueueCapacity() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation != nil {
		return cap(m.generation.queue)
	}
	return m.config.OutboundQueueSize
}

func (m *Manager) sendBatches(generation *connection) {
	defer generation.wg.Done()
	defer func() {
		generation.accepting.Store(false)
		if err := generation.stream.CloseSend(); err != nil {
			logger.Error("Failed to close gRPC stream during cleanup", "error", err)
		}
	}()

	for {
		select {
		case <-generation.ctx.Done():
			// The queue is bounded. Discarding it on connection loss prevents an
			// old generation from forwarding into its successor.
			return
		case batch := <-generation.queue:
			generation.inFlight.Add(1)
			if err := generation.stream.Send(batch); err != nil {
				generation.inFlight.Add(-1)
				failures := m.consecutiveFailures.Add(1)
				logger.Error("Failed to forward batch to upstream", "error", err,
					"consecutive_failures", failures)
				if failures == constants.MaxConsecutiveSendFailures {
					logger.Warn("Upstream packet delivery has repeatedly failed",
						"consecutive_failures", failures,
						"threshold", constants.MaxConsecutiveSendFailures)
				}
				m.disconnectGeneration(generation)
				return
			}
			generation.inFlight.Add(-1)
			m.consecutiveFailures.Store(0)
			if m.packetsForwarded != nil {
				m.packetsForwarded.Add(uint64(len(batch.Packets)))
			}
			logger.Debug("Forwarded batch to upstream", "hunter_id", batch.HunterId,
				"sequence", batch.Sequence, "packets", len(batch.Packets))
		}
	}
}

// disconnectGeneration terminates a failed stream generation and requests one
// reconnect, even when both its sender and receiver observe the failure.
func (m *Manager) disconnectGeneration(generation *connection) {
	generation.disconnectOnce.Do(func() {
		generation.accepting.Store(false)
		generation.cancel()
		m.MarkDisconnected()
	})
}

// receiveAcks receives acknowledgments from upstream (connection-scoped goroutine)
func (m *Manager) receiveAcks(generation *connection) {
	defer generation.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in receiveAcks", "panic", r)
		}
	}()

	for {
		// Check context before each Recv to avoid blocking on closed stream
		select {
		case <-generation.ctx.Done():
			logger.Debug("receiveAcks: context cancelled, exiting")
			return
		default:
		}

		ack, err := generation.stream.Recv()
		if err != nil {
			// Check if we're shutting down
			if generation.ctx.Err() != nil {
				logger.Debug("receiveAcks: error during shutdown, exiting gracefully", "error", err)
				return
			}
			logger.Error("Upstream ack receive error", "error", err)
			// Trigger reconnection
			m.disconnectGeneration(generation)
			return
		}

		logger.Debug("Received upstream ack",
			"ack_sequence", ack.AckSequence,
			"flow_control", ack.FlowControl)

		// TODO: Implement flow control from upstream (pause forwarding if FLOW_PAUSE)
	}
}

// IsConnected returns true if connected to upstream
func (m *Manager) IsConnected() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation != nil && m.generation.accepting.Load()
}

// GetUpstreamProcessorID returns the upstream processor ID (learned during registration)
func (m *Manager) GetUpstreamProcessorID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProcessorID
}

// GetPoolStats returns statistics about the connection pool
func (m *Manager) GetPoolStats() grpcpool.Stats {
	return grpcpool.GetStats(m.connPool)
}
