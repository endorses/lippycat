package upstream

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"time"
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
}

// Manager handles upstream processor connection and forwarding
type Manager struct {
	config Config

	// gRPC connection
	conn       *grpc.ClientConn
	dataClient data.DataServiceClient
	mgmtClient management.ManagementServiceClient
	stream     data.DataService_StreamPacketsClient
	mu         sync.Mutex

	// Upstream processor ID (learned during registration)
	upstreamProcessorID string

	// Packet forwarding stats
	packetsForwarded *atomic.Uint64

	// Context for goroutines
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// NewManager creates a new upstream connection manager
func NewManager(config Config, packetsForwarded *atomic.Uint64) *Manager {
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		config:           config,
		packetsForwarded: packetsForwarded,
		ctx:              ctx,
		cancel:           cancel,
	}
}

// Connect establishes connection to upstream processor
func (m *Manager) Connect() error {
	if m.config.Address == "" {
		return fmt.Errorf("upstream address not configured")
	}

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

	conn, err := grpc.Dial(m.config.Address, opts...)
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
			if closeErr := conn.Close(); closeErr != nil {
				logger.Error("Failed to close connection during error cleanup", "error", closeErr, "upstream", m.config.Address)
			}
			return fmt.Errorf("failed to register with upstream processor: %w", err)
		}
		if !regResp.Accepted {
			if closeErr := conn.Close(); closeErr != nil {
				logger.Error("Failed to close connection during error cleanup", "error", closeErr, "upstream", m.config.Address)
			}
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
	stream, err := m.dataClient.StreamPackets(m.ctx)
	if err != nil {
		if closeErr := conn.Close(); closeErr != nil {
			logger.Error("Failed to close connection during error cleanup", "error", closeErr, "upstream", m.config.Address)
		}
		return fmt.Errorf("failed to create upstream stream: %w", err)
	}

	m.mu.Lock()
	m.stream = stream
	m.mu.Unlock()

	// Start goroutine to receive upstream acks
	m.wg.Add(1)
	go m.receiveAcks()

	logger.Info("Connected to upstream processor", "addr", m.config.Address)
	return nil
}

// Disconnect closes upstream connection
func (m *Manager) Disconnect() {
	m.cancel() // Cancel context to stop goroutines

	m.mu.Lock()
	if m.stream != nil {
		if err := m.stream.CloseSend(); err != nil {
			logger.Error("Failed to close gRPC stream during shutdown", "error", err)
		}
		m.stream = nil
	}
	m.mu.Unlock()

	if m.conn != nil {
		if err := m.conn.Close(); err != nil {
			logger.Error("Failed to close connection during shutdown", "error", err, "upstream", m.config.Address)
		}
		m.conn = nil
	}

	m.wg.Wait() // Wait for goroutines to finish
	logger.Info("Disconnected from upstream processor")
}

// Forward forwards packet batch to upstream processor
func (m *Manager) Forward(batch *data.PacketBatch) {
	m.mu.Lock()
	stream := m.stream
	m.mu.Unlock()

	if stream == nil {
		logger.Warn("Upstream stream not available, dropping batch")
		return
	}

	// Forward batch (keeping original hunter ID for traceability)
	if err := stream.Send(batch); err != nil {
		logger.Error("Failed to forward batch to upstream", "error", err)
		return
	}

	// Update forwarded stats (atomic increment)
	if m.packetsForwarded != nil {
		m.packetsForwarded.Add(uint64(len(batch.Packets)))
	}

	logger.Debug("Forwarded batch to upstream",
		"hunter_id", batch.HunterId,
		"sequence", batch.Sequence,
		"packets", len(batch.Packets))
}

// receiveAcks receives acknowledgments from upstream
func (m *Manager) receiveAcks() {
	defer m.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in receiveAcks", "panic", r)
		}
	}()

	m.mu.Lock()
	stream := m.stream
	m.mu.Unlock()

	if stream == nil {
		logger.Error("Upstream stream not available for receiving acks")
		return
	}

	for {
		// Check context before each Recv to avoid blocking on closed stream
		select {
		case <-m.ctx.Done():
			logger.Debug("receiveAcks: context cancelled, exiting")
			return
		default:
		}

		ack, err := stream.Recv()
		if err != nil {
			// Check if we're shutting down
			if m.ctx.Err() != nil {
				logger.Debug("receiveAcks: error during shutdown, exiting gracefully", "error", err)
				return
			}
			logger.Error("Upstream ack receive error", "error", err)
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
	return m.stream != nil
}

// GetUpstreamProcessorID returns the upstream processor ID (learned during registration)
func (m *Manager) GetUpstreamProcessorID() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.upstreamProcessorID
}
