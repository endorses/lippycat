//go:build hunter || all

package connection

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"syscall"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/hunter/circuitbreaker"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config contains connection manager configuration
type Config struct {
	ProcessorAddr string
	HunterID      string
	Interfaces    []string
	BufferSize    int
	BatchSize     int
	BatchTimeout  time.Duration
	// TLS settings
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	TLSSkipVerify         bool
	TLSServerNameOverride string
	// Reconnection
	MaxReconnectAttempts int
}

// StatsCollector interface for statistics access
type StatsCollector interface {
	GetCaptured() uint64
	GetForwarded() uint64
	GetMatched() uint64
	GetDropped() uint64
	GetAll() (captured, matched, forwarded, dropped, bufferBytes uint64)
	ToProto(activeFilters uint32) *management.HunterStats
}

// FilterManager interface for filter management
type FilterManager interface {
	GetFilterCount() int
	SetInitialFilters(filters []*management.Filter)
	Subscribe(ctx, connCtx context.Context, mgmtClient management.ManagementServiceClient)
}

// CaptureManager interface for capture management
type CaptureManager interface {
	GetPacketBuffer() *capture.PacketBuffer
}

// ForwardingManagerFactory creates forwarding managers for new connections
type ForwardingManagerFactory interface {
	CreateForwardingManager(connCtx context.Context, stream data.DataService_StreamPacketsClient) *forwarding.Manager
}

// Manager handles processor connection lifecycle
type Manager struct {
	config Config

	// gRPC connections
	dataConn       *grpc.ClientConn
	managementConn *grpc.ClientConn
	dataClient     data.DataServiceClient
	mgmtClient     management.ManagementServiceClient

	// Packet streaming
	stream   data.DataService_StreamPacketsClient
	streamMu sync.Mutex

	// Managers
	statsCollector     StatsCollector
	filterManager      FilterManager
	captureManager     CaptureManager
	forwardingFactory  ForwardingManagerFactory
	forwardingManager  *forwarding.Manager
	flowControlHandler func(*data.StreamControl)

	// Reconnection
	reconnectAttempts int
	reconnecting      bool
	reconnectMu       sync.Mutex
	circuitBreaker    *circuitbreaker.CircuitBreaker

	// Control
	ctx        context.Context
	cancel     context.CancelFunc
	connCtx    context.Context
	connCancel context.CancelFunc
	connWg     sync.WaitGroup
}

// New creates a new connection manager
func New(
	config Config,
	statsCollector StatsCollector,
	filterManager FilterManager,
	captureManager CaptureManager,
	forwardingFactory ForwardingManagerFactory,
	flowControlHandler func(*data.StreamControl),
) *Manager {
	// Create circuit breaker for connection management
	cb := circuitbreaker.New(circuitbreaker.Config{
		Name:             "processor-connection",
		MaxFailures:      5,                // Open after 5 consecutive failures
		ResetTimeout:     30 * time.Second, // Try again after 30s
		HalfOpenMaxCalls: 3,                // Allow 3 test calls in half-open
	})

	return &Manager{
		config:             config,
		statsCollector:     statsCollector,
		filterManager:      filterManager,
		captureManager:     captureManager,
		forwardingFactory:  forwardingFactory,
		flowControlHandler: flowControlHandler,
		reconnectAttempts:  0,
		reconnecting:       false,
		circuitBreaker:     cb,
	}
}

// Start begins connection management
func (m *Manager) Start(ctx context.Context, wg *sync.WaitGroup) {
	m.ctx, m.cancel = context.WithCancel(ctx)
	wg.Add(1)
	go m.connectionManager(wg)
}

// Stop stops the connection manager
func (m *Manager) Stop() {
	if m.cancel != nil {
		m.cancel()
	}
}

// GetMgmtClient returns the management client
func (m *Manager) GetMgmtClient() management.ManagementServiceClient {
	return m.mgmtClient
}

// GetDataClient returns the data client
func (m *Manager) GetDataClient() data.DataServiceClient {
	return m.dataClient
}

// GetStream returns the current stream
func (m *Manager) GetStream() data.DataService_StreamPacketsClient {
	m.streamMu.Lock()
	defer m.streamMu.Unlock()
	return m.stream
}

// GetForwardingManager returns the current forwarding manager (nil if not connected)
func (m *Manager) GetForwardingManager() *forwarding.Manager {
	return m.forwardingManager
}

// MarkDisconnected marks the connection as disconnected and triggers reconnection
func (m *Manager) MarkDisconnected() {
	m.reconnectMu.Lock()
	defer m.reconnectMu.Unlock()

	logger.Debug("MarkDisconnected() called", "already_reconnecting", m.reconnecting)

	if m.reconnecting {
		// Already reconnecting
		logger.Debug("MarkDisconnected: already reconnecting, ignoring")
		return
	}

	m.reconnecting = true
	logger.Warn("Connection lost, will attempt reconnection")
}

// connectionManager manages processor connection lifecycle
func (m *Manager) connectionManager(wg *sync.WaitGroup) {
	defer wg.Done()

	logger.Info("Connection manager started")

	// Attempt initial connection with retries
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}

		// Use circuit breaker for connection attempts
		err := m.circuitBreaker.Call(func() error {
			return m.connectAndRegister()
		})

		if err == nil {
			// Successfully connected
			logger.Info("Connected to processor")

			// Reset reconnection state
			m.reconnectMu.Lock()
			m.reconnecting = false
			m.reconnectAttempts = 0
			m.reconnectMu.Unlock()

			// Create connection-scoped context for this connection's goroutines
			m.connCtx, m.connCancel = context.WithCancel(m.ctx)

			// Create forwarding manager for this connection
			m.forwardingManager = m.forwardingFactory.CreateForwardingManager(m.connCtx, m.stream)

			// Start connection-dependent goroutines with connection-scoped waitgroup
			m.connWg.Add(4)
			go m.forwardingManager.ForwardPackets(&m.connWg)
			go m.handleStreamControl()
			go m.subscribeToFilters()
			go m.sendHeartbeats()

			// Monitor for disconnection
			m.monitorConnection()

			// If we get here, connection was lost - clean up before reconnecting
			logger.Warn("Connection to processor lost, cleaning up goroutines before retry")
			m.cleanup()
			continue
		}

		// Connection failed or circuit breaker open
		logger.Error("Failed to connect to processor", "error", err)

		// Exponential backoff
		m.reconnectMu.Lock()
		m.reconnectAttempts++
		attempts := m.reconnectAttempts
		m.reconnectMu.Unlock()

		if m.config.MaxReconnectAttempts > 0 && attempts >= m.config.MaxReconnectAttempts {
			logger.Error("Max reconnection attempts reached, giving up",
				"attempts", attempts,
				"max", m.config.MaxReconnectAttempts)
			m.cancel()
			return
		}

		backoff := time.Duration(1<<uint(min(attempts-1, 6))) * time.Second // #nosec G115 - safe: exponential backoff, max 6
		if backoff > 60*time.Second {
			backoff = 60 * time.Second
		}

		logger.Info("Retrying connection",
			"attempt", attempts,
			"backoff", backoff)

		select {
		case <-time.After(backoff):
		case <-m.ctx.Done():
			return
		}
	}
}

// connectAndRegister connects to processor and registers
func (m *Manager) connectAndRegister() error {
	// Connect to processor
	if err := m.connectToProcessor(); err != nil {
		return fmt.Errorf("failed to connect to processor: %w", err)
	}

	// Register with processor
	if err := m.register(); err != nil {
		return fmt.Errorf("failed to register with processor: %w", err)
	}

	// Start packet streaming
	if err := m.startStreaming(); err != nil {
		return fmt.Errorf("failed to start streaming: %w", err)
	}

	// Reset reconnect attempts on successful connection
	m.reconnectMu.Lock()
	m.reconnectAttempts = 0
	m.reconnecting = false
	m.reconnectMu.Unlock()

	return nil
}

// connectToProcessor establishes gRPC connections
func (m *Manager) connectToProcessor() error {
	logger.Info("Connecting to processor", "addr", m.config.ProcessorAddr)

	// Create custom dialer with TCP keepalive
	// This provides defense-in-depth with gRPC keepalive
	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 10 * time.Second, // TCP keepalive every 10s
		Control: func(network, address string, c syscall.RawConn) error {
			var opErr error
			err := c.Control(func(fd uintptr) {
				// Enable TCP keepalive at socket level
				opErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1)
				if opErr != nil {
					return
				}
				// TCP_KEEPIDLE: 10s before first probe
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPIDLE, 10)
				if opErr != nil {
					return
				}
				// TCP_KEEPINTVL: 5s between probes
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPINTVL, 5)
				if opErr != nil {
					return
				}
				// TCP_KEEPCNT: 3 probes before giving up
				opErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_KEEPCNT, 3)
			})
			if err != nil {
				return err
			}
			return opErr
		},
	}

	opts := []grpc.DialOption{
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(constants.MaxGRPCMessageSize)),
		// Use custom dialer with TCP keepalive
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", addr)
		}),
		// Configure keepalive to survive long network interruptions (e.g., laptop standby)
		// More lenient settings to handle temporary network disruptions
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                30 * time.Second, // Send ping every 30s (less aggressive)
			Timeout:             20 * time.Second, // Wait 20s for ping ack (tolerate delays)
			PermitWithoutStream: true,             // Send pings even without active streams
		}),
	}

	// Configure TLS or insecure credentials
	if m.config.TLSEnabled {
		tlsCreds, err := m.buildTLSCredentials()
		if err != nil {
			return fmt.Errorf("failed to build TLS credentials: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(tlsCreds))
		logger.Info("Using TLS for gRPC connection", "skip_verify", m.config.TLSSkipVerify)
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		logger.Warn("Using insecure gRPC connection (no TLS)",
			"security_risk", "packet data transmitted in cleartext")
	}

	// Connect data channel
	dataConn, err := grpc.Dial(m.config.ProcessorAddr, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial processor data: %w", err)
	}
	m.dataConn = dataConn
	m.dataClient = data.NewDataServiceClient(dataConn)

	// Connect management channel (same address for now, different service)
	mgmtConn, err := grpc.Dial(m.config.ProcessorAddr, opts...)
	if err != nil {
		_ = dataConn.Close()
		return fmt.Errorf("failed to dial processor management: %w", err)
	}
	m.managementConn = mgmtConn
	m.mgmtClient = management.NewManagementServiceClient(mgmtConn)

	logger.Info("Connected to processor", "addr", m.config.ProcessorAddr, "tls", m.config.TLSEnabled,
		"tcp_keepalive", "enabled")
	return nil
}

// buildTLSCredentials creates TLS credentials for gRPC client
func (m *Manager) buildTLSCredentials() (credentials.TransportCredentials, error) {
	return tlsutil.BuildClientCredentials(tlsutil.ClientConfig{
		CAFile:             m.config.TLSCAFile,
		CertFile:           m.config.TLSCertFile,
		KeyFile:            m.config.TLSKeyFile,
		SkipVerify:         m.config.TLSSkipVerify,
		ServerNameOverride: m.config.TLSServerNameOverride,
	})
}

// register registers hunter with processor
func (m *Manager) register() error {
	logger.Info("Registering with processor", "hunter_id", m.config.HunterID)

	// Get local IP address - prefer the capture interface IP
	hostname := getInterfaceIP(m.config.Interfaces)
	logger.Info("Detected IP from capture interface", "ip", hostname)

	if hostname == "" {
		// Fallback to connection-based detection
		hostname = getConnectionLocalIP(m.managementConn)
		logger.Info("Using connection local IP", "ip", hostname)
	}

	if hostname == "" {
		logger.Warn("Failed to detect local IP, using hunter ID as hostname")
		hostname = m.config.HunterID // Final fallback to hunter ID
	}

	req := &management.HunterRegistration{
		HunterId:   m.config.HunterID,
		Hostname:   hostname,
		Interfaces: m.config.Interfaces,
		Version:    "0.1.0", // TODO: version from build
		Capabilities: &management.HunterCapabilities{
			FilterTypes:     []string{"sip_user", "phone_number", "ip_address"},
			MaxBufferSize:   uint64(m.config.BufferSize * 2048), // #nosec G115 - Assume 2KB avg packet
			GpuAcceleration: false,                              // TODO: detect GPU
			AfXdp:           false,                              // TODO: detect AF_XDP
		},
	}

	resp, err := m.mgmtClient.RegisterHunter(m.ctx, req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Error)
	}

	logger.Info("Registration accepted",
		"assigned_id", resp.AssignedId,
		"initial_filters", len(resp.Filters))

	// Store initial filters in filter manager
	m.filterManager.SetInitialFilters(resp.Filters)

	return nil
}

// startStreaming establishes the bidirectional packet stream
func (m *Manager) startStreaming() error {
	logger.Info("Starting packet stream to processor")

	stream, err := m.dataClient.StreamPackets(m.ctx)
	if err != nil {
		return fmt.Errorf("failed to create stream: %w", err)
	}

	m.streamMu.Lock()
	m.stream = stream
	m.streamMu.Unlock()

	// NOTE: Do NOT start receiveStreamControl here - handleStreamControl is started
	// in connectionManager() and will handle receiving flow control messages.
	// Having two goroutines calling stream.Recv() causes race conditions and deadlocks.

	logger.Info("Packet stream established with flow control")
	return nil
}

// handleStreamControl receives flow control messages from processor
func (m *Manager) handleStreamControl() {
	defer m.connWg.Done()
	logger.Debug("handleStreamControl goroutine starting")
	defer logger.Debug("handleStreamControl goroutine exiting")
	defer func() {
		if r := recover(); r != nil {
			logger.Error("Recovered from panic in handleStreamControl", "panic", r)
		}
	}()

	m.streamMu.Lock()
	stream := m.stream
	m.streamMu.Unlock()

	if stream == nil {
		logger.Error("Stream not available for control messages")
		return
	}

	for {
		// Check context before each Recv to avoid blocking on closed stream
		select {
		case <-m.ctx.Done():
			logger.Debug("handleStreamControl: context cancelled, exiting")
			return
		case <-m.connCtx.Done():
			logger.Debug("handleStreamControl: connection context cancelled, exiting")
			return
		default:
		}

		ctrl, err := stream.Recv()
		if err == io.EOF {
			logger.Info("Stream closed by processor")
			m.MarkDisconnected()
			return
		}
		if err != nil {
			// Check if we're shutting down
			if m.ctx.Err() != nil || m.connCtx.Err() != nil {
				// Context canceled, normal shutdown
				logger.Debug("handleStreamControl: error during shutdown, exiting gracefully", "error", err)
				return
			}
			logger.Error("Stream control error", "error", err)
			m.MarkDisconnected()
			return
		}

		logger.Debug("Received flow control",
			"ack_sequence", ctrl.AckSequence,
			"flow_control", ctrl.FlowControl)

		// TODO: Implement flow control logic
		// For now, just log acknowledgments
	}
}

// subscribeToFilters subscribes to filter updates from processor
func (m *Manager) subscribeToFilters() {
	defer m.connWg.Done()
	logger.Debug("subscribeToFilters goroutine starting")
	defer logger.Debug("subscribeToFilters goroutine exiting")
	m.filterManager.Subscribe(m.ctx, m.connCtx, m.mgmtClient)
}

// sendHeartbeats sends periodic heartbeat to processor
func (m *Manager) sendHeartbeats() {
	defer m.connWg.Done()
	logger.Debug("sendHeartbeats goroutine starting")
	defer logger.Debug("sendHeartbeats goroutine exiting")

	logger.Info("Starting heartbeat stream to processor")

	stream, err := m.mgmtClient.Heartbeat(m.ctx)
	if err != nil {
		logger.Error("Failed to create heartbeat stream", "error", err)
		return
	}

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	logger.Info("Heartbeat stream established")

	// Separate goroutine for receiving responses to prevent blocking
	respCh := make(chan *management.ProcessorHeartbeat, constants.ErrorChannelBuffer)
	respErrCh := make(chan error, constants.ErrorChannelBuffer)

	go func() {
		defer func() {
			if r := recover(); r != nil {
				logger.Error("Recovered from panic in heartbeat receiver", "panic", r)
			}
		}()
		for {
			// Check context before Recv
			select {
			case <-m.ctx.Done():
				return
			case <-m.connCtx.Done():
				return
			default:
			}

			resp, err := stream.Recv()
			if err != nil {
				// Only send error if not shutting down
				if m.ctx.Err() == nil && m.connCtx.Err() == nil {
					respErrCh <- err
				}
				return
			}
			select {
			case respCh <- resp:
			case <-m.ctx.Done():
				return
			case <-m.connCtx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-m.connCtx.Done():
			logger.Info("Heartbeat stream closed")
			return

		case err := <-respErrCh:
			if m.ctx.Err() != nil {
				return
			}
			logger.Error("Heartbeat stream error", "error", err)
			m.MarkDisconnected()
			return

		case <-ticker.C:
			// Determine hunter status based on current state
			status := m.calculateStatus()

			// Send heartbeat
			// Get filter count (safe: filter count won't exceed uint32 max)
			activeFilters := uint32(m.filterManager.GetFilterCount()) // #nosec G115

			// Collect stats for heartbeat
			packetsCaptured := m.statsCollector.GetCaptured()
			packetsForwarded := m.statsCollector.GetForwarded()

			logger.Debug("Sending heartbeat",
				"hunter_id", m.config.HunterID,
				"active_filters", activeFilters,
				"packets_captured", packetsCaptured,
				"packets_forwarded", packetsForwarded,
				"status", status)

			hb := &management.HunterHeartbeat{
				HunterId:    m.config.HunterID,
				TimestampNs: time.Now().UnixNano(),
				Status:      status,
				Stats:       m.statsCollector.ToProto(activeFilters),
			}

			if err := stream.Send(hb); err != nil {
				if m.ctx.Err() != nil {
					return
				}
				logger.Error("Failed to send heartbeat", "error", err)
				m.MarkDisconnected()
				return
			}

		case resp := <-respCh:
			logger.Debug("Heartbeat acknowledged",
				"processor_status", resp.Status,
				"hunters_connected", resp.HuntersConnected)
		}
	}
}

// calculateStatus determines hunter health status
func (m *Manager) calculateStatus() management.HunterStatus {
	// Check if we're shutting down
	if m.ctx.Err() != nil {
		return management.HunterStatus_STATUS_STOPPING
	}

	// Check buffer usage
	if m.captureManager != nil && m.captureManager.GetPacketBuffer() != nil {
		buffer := m.captureManager.GetPacketBuffer()
		bufferUsage := buffer.Len()
		bufferCapacity := buffer.Cap()

		if bufferCapacity > 0 {
			usagePercent := (bufferUsage * 100) / bufferCapacity

			// Buffer filling up (>80%)
			if usagePercent > 80 {
				return management.HunterStatus_STATUS_WARNING
			}
		}
	}

	// Check for excessive drops
	captured := m.statsCollector.GetCaptured()
	if captured > 0 {
		dropped := m.statsCollector.GetDropped()
		dropRate := (dropped * 100) / captured
		if dropRate > 10 {
			return management.HunterStatus_STATUS_WARNING
		}
	}

	return management.HunterStatus_STATUS_HEALTHY
}

// monitorConnection monitors for disconnections
func (m *Manager) monitorConnection() {
	// Check frequently for faster reconnection (100ms polling)
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

// cleanup closes connections
func (m *Manager) cleanup() {
	// Cancel connection-scoped context to signal all goroutines to exit
	if m.connCancel != nil {
		m.connCancel()
	}

	// Wait for all connection-scoped goroutines to finish with timeout
	logger.Debug("Waiting for connection goroutines to finish...")

	done := make(chan struct{})
	go func() {
		m.connWg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("All connection goroutines finished")
	case <-time.After(10 * time.Second):
		logger.Warn("Cleanup timeout - some goroutines may still be running, proceeding anyway")
	}

	m.streamMu.Lock()
	if m.stream != nil {
		_ = m.stream.CloseSend()
	}
	m.streamMu.Unlock()

	if m.dataConn != nil {
		_ = m.dataConn.Close()
	}

	if m.managementConn != nil {
		_ = m.managementConn.Close()
	}
}

// Helper functions

// min returns minimum of two ints
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// getConnectionLocalIP returns the local IP address used for the gRPC connection
func getConnectionLocalIP(conn *grpc.ClientConn) string {
	if conn == nil {
		logger.Debug("getConnectionLocalIP: conn is nil")
		return ""
	}

	// Parse the target address to determine what we're connecting to
	target := conn.Target()
	logger.Debug("getConnectionLocalIP: target", "target", target)

	host, port, err := net.SplitHostPort(target)
	if err != nil {
		logger.Debug("getConnectionLocalIP: failed to split host:port, using target as host", "error", err)
		host = target
		port = "1"
	}
	if port == "" {
		port = "1"
	}

	// Check if the target is a loopback address
	resolvedIPs, err := net.LookupIP(host)
	if err == nil && len(resolvedIPs) > 0 {
		targetIP := resolvedIPs[0]
		logger.Debug("getConnectionLocalIP: resolved target", "host", host, "ip", targetIP.String())

		if targetIP.IsLoopback() {
			logger.Debug("getConnectionLocalIP: target is loopback, finding non-loopback IP")
			return getFirstNonLoopbackIP()
		}
	}

	dialAddr := net.JoinHostPort(host, port)
	logger.Debug("getConnectionLocalIP: dialing UDP", "addr", dialAddr)

	// Dial a temporary UDP connection to see which local IP would be used
	udpConn, err := net.Dial("udp", dialAddr)
	if err != nil {
		logger.Debug("getConnectionLocalIP: failed to dial UDP", "error", err)
		return ""
	}
	defer udpConn.Close()

	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	ip := localAddr.IP.String()

	if localAddr.IP.IsLoopback() {
		logger.Debug("getConnectionLocalIP: got loopback IP, finding non-loopback IP")
		return getFirstNonLoopbackIP()
	}

	logger.Debug("getConnectionLocalIP: detected IP", "ip", ip)
	return ip
}

// getFirstNonLoopbackIP returns the first non-loopback IPv4 address
func getFirstNonLoopbackIP() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		logger.Debug("getFirstNonLoopbackIP: failed to get interfaces", "error", err)
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				logger.Debug("getFirstNonLoopbackIP: found IPv4", "ip", ipnet.IP.String())
				return ipnet.IP.String()
			}
		}
	}

	logger.Debug("getFirstNonLoopbackIP: no non-loopback IPv4 found")
	return ""
}

// getInterfaceIP returns the IP address of the capture interface
func getInterfaceIP(interfaces []string) string {
	if len(interfaces) == 0 {
		logger.Debug("getInterfaceIP: no interfaces specified")
		return ""
	}

	if len(interfaces) > 1 || interfaces[0] == "any" {
		logger.Debug("getInterfaceIP: multiple interfaces or 'any', using first non-loopback IP")
		return getFirstNonLoopbackIP()
	}

	ifaceName := interfaces[0]
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		logger.Debug("getInterfaceIP: failed to get interface", "interface", ifaceName, "error", err)
		return ""
	}

	addrs, err := iface.Addrs()
	if err != nil {
		logger.Debug("getInterfaceIP: failed to get interface addresses", "interface", ifaceName, "error", err)
		return ""
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			if ipnet.IP.To4() != nil {
				logger.Debug("getInterfaceIP: found IPv4 on interface", "interface", ifaceName, "ip", ipnet.IP.String())
				return ipnet.IP.String()
			}
		}
	}

	logger.Debug("getInterfaceIP: no IPv4 found on interface", "interface", ifaceName)
	return ""
}
