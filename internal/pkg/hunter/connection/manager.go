//go:build hunter || all

package connection

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"github.com/endorses/lippycat/internal/pkg/version"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config contains connection manager configuration
type Config struct {
	ProcessorAddr    string
	Processors       []failover.Endpoint
	Failover         failover.Config
	OnEndpoint       func(context.Context, failover.Endpoint) error
	OpenPacketStream func(lifetimeCtx, setupCtx context.Context, conn grpc.ClientConnInterface) (data.DataService_StreamPacketsClient, error)
	HunterID         string
	Interfaces       []string
	BufferSize       int
	BatchSize        int
	BatchTimeout     time.Duration
	VoIPMode         bool // Determines filter capabilities advertised to processor (legacy)
	// Filter capabilities advertised to processor
	InventoryEnabled     bool
	RADIUSIngress        bool     // Observation-aware capture and provenance transport are installed.
	SupportedFilterTypes []string // If set, overrides VoIPMode-based defaults
	// TLS settings
	TLSEnabled            bool
	TLSCertFile           string
	TLSKeyFile            string
	TLSCAFile             string
	TLSSkipVerify         bool
	TLSServerNameOverride string
	// Reconnection
	MaxReconnectAttempts   int
	ForwardMode            string
	EventFallbackToPackets bool
	RequiredEventKinds     []eventsv1.EventKind
	EventSpoolMaxBytes     uint64
	EventSpoolMaxAge       time.Duration
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
	SetInitialFilters(filters []*management.Filter) error
	ApplyPendingInitial()
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

	// Public client/sender snapshots are protected across generation replacement.
	clientsMu sync.RWMutex

	// gRPC connections
	dataConn       *grpc.ClientConn
	managementConn *grpc.ClientConn
	dataClient     data.DataServiceClient
	mgmtClient     management.ManagementServiceClient
	eventClient    eventsv1.EventServiceClient

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
	eventForwarder     *eventforwarding.Client
	eventForwarderMu   sync.RWMutex
	acceptedMode       management.ForwardingMode
	modeReady          chan management.ForwardingMode
	startupError       chan error

	statusMu     sync.RWMutex
	status       Status
	endpoint     failover.Endpoint
	setupCtx     context.Context
	registration *management.RegistrationResponse
	firstControl *data.StreamControl

	candidateKinds   []eventsv1.EventKind
	eventSetupCommit func() error

	// Reconnection
	reconnectAttempts int
	reconnecting      bool
	reconnectMu       sync.Mutex

	// Control
	ctx        context.Context
	cancel     context.CancelFunc
	connCtx    context.Context
	connCancel context.CancelFunc
	connWg     sync.WaitGroup
	generation atomic.Uint64

	// Test seams for the bounded sender shutdown path. Production uses the
	// defaults below.
	forwardingExitGrace time.Duration
	closeDataTransport  func() error
}

func (m *Manager) SetEventForwarder(client *eventforwarding.Client) {
	m.eventForwarderMu.Lock()
	defer m.eventForwarderMu.Unlock()
	m.eventForwarder = client
}

func (m *Manager) getEventForwarder() *eventforwarding.Client {
	m.eventForwarderMu.RLock()
	defer m.eventForwarderMu.RUnlock()
	return m.eventForwarder
}

const defaultForwardingExitGrace = time.Second

// New creates a new connection manager
func New(
	config Config,
	statsCollector StatsCollector,
	filterManager FilterManager,
	captureManager CaptureManager,
	forwardingFactory ForwardingManagerFactory,
	flowControlHandler func(*data.StreamControl),
) *Manager {

	return &Manager{
		config:             config,
		statsCollector:     statsCollector,
		filterManager:      filterManager,
		captureManager:     captureManager,
		forwardingFactory:  forwardingFactory,
		flowControlHandler: flowControlHandler,
		reconnectAttempts:  0,
		reconnecting:       false,
		modeReady:          make(chan management.ForwardingMode, 1),
		startupError:       make(chan error, 1),
	}
}

func (m *Manager) WaitAcceptedMode(ctx context.Context) (management.ForwardingMode, error) {
	select {
	case mode := <-m.modeReady:
		return mode, nil
	case err := <-m.startupError:
		return 0, err
	case <-ctx.Done():
		return 0, ctx.Err()
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
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()
	return m.mgmtClient
}

// GetDataClient returns the data client
func (m *Manager) GetDataClient() data.DataServiceClient {
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()
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
	m.clientsMu.RLock()
	defer m.clientsMu.RUnlock()
	return m.forwardingManager
}

// MarkDisconnected marks the connection as disconnected and triggers reconnection
func (m *Manager) MarkDisconnected() {
	m.markGenerationDisconnected(m.generation.Load())
}

// markGenerationDisconnected cancels only the connection generation which
// observed the failure. A late callback from an old sender must never tear
// down its successor.
func (m *Manager) markGenerationDisconnected(generation uint64) {
	m.reconnectMu.Lock()

	logger.Debug("MarkDisconnected() called", "already_reconnecting", m.reconnecting)

	if generation != m.generation.Load() || m.reconnecting {
		// Already reconnecting
		logger.Debug("MarkDisconnected: already reconnecting, ignoring")
		m.reconnectMu.Unlock()
		return
	}

	m.reconnecting = true
	cancel := m.connCancel
	m.reconnectMu.Unlock()
	logger.Warn("Connection lost, will attempt reconnection")
	if cancel != nil {
		cancel()
	}
}

// Status is a race-safe snapshot of endpoint selection, independent of legacy
// scalar configuration. Candidate addresses are copied on every read.
type Status struct {
	Candidates      []failover.Endpoint
	ActiveEndpoint  string
	AttemptEndpoint string
	State           string
	Reason          string
	LastConnected   time.Time
	Failovers       uint64
}

func (m *Manager) Status() Status {
	m.statusMu.RLock()
	defer m.statusMu.RUnlock()
	snapshot := m.status
	snapshot.Candidates = append([]failover.Endpoint(nil), snapshot.Candidates...)
	return snapshot
}

// connectionManager is the sole owner of transport generations and selection.
func (m *Manager) connectionManager(wg *sync.WaitGroup) {
	defer wg.Done()
	defer m.cleanup()
	endpoints, err := failover.NormalizeEndpoints(m.config.ProcessorAddr, m.config.Processors)
	if err != nil {
		m.failStartup(err)
		return
	}
	cfg, err := failover.NormalizeConfig(m.config.Failover)
	if err != nil {
		m.failStartup(err)
		return
	}
	if len(endpoints) == 0 {
		m.failStartup(errors.New("at least one processor is required"))
		return
	}
	if m.config.TLSEnabled {
		if _, err := m.buildTLSCredentials(); err != nil {
			m.failStartup(fmt.Errorf("processor TLS configuration: %w", err))
			return
		}
	}
	m.statusMu.Lock()
	m.status.Candidates = append([]failover.Endpoint(nil), endpoints...)
	m.statusMu.Unlock()
	selector := failover.NewSelector(endpoints, cfg)
	var previous string
	for m.ctx.Err() == nil {
		endpoint, index, wait := selector.Next(time.Now())
		if wait > 0 {
			m.setSelection("waiting", "", "all processors cooling down")
			timer := time.NewTimer(wait)
			select {
			case <-m.ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			continue
		}
		m.endpoint = endpoint
		m.setSelection("connecting", endpoint.Address, "attempting processor")
		m.reconnectMu.Lock()
		m.connCtx, m.connCancel = context.WithCancel(m.ctx)
		m.reconnecting = false
		generation := m.generation.Add(1)
		m.reconnectMu.Unlock()
		attemptCtx, cancelAttempt := context.WithTimeout(m.connCtx, cfg.AttemptTimeout)
		m.setupCtx = attemptCtx
		var err error
		if m.config.OnEndpoint != nil {
			err = m.config.OnEndpoint(attemptCtx, endpoint)
		}
		if err == nil {
			err = m.connectAndRegister()
		}
		cancelAttempt()
		m.setupCtx = nil
		if err != nil {
			m.cleanup()
			selector.Failed(index, time.Now())
			m.setSelection("retrying", endpoint.Address, err.Error())
			logger.Warn("Processor connection attempt failed", "processor", endpoint.Address, "error", err)
			m.reconnectAttempts++
			if m.config.MaxReconnectAttempts > 0 && m.reconnectAttempts >= m.config.MaxReconnectAttempts {
				m.cancel()
				return
			}
			continue
		}

		// A new route must not inherit peer-owned PAUSE state.
		if m.flowControlHandler != nil {
			m.flowControlHandler(&data.StreamControl{FlowControl: data.FlowControl_FLOW_CONTINUE})
		}
		if m.acceptedMode == management.ForwardingMode_FORWARDING_MODE_PACKETS {
			forwarder := m.forwardingFactory.CreateForwardingManager(m.connCtx, m.stream)
			forwarder.SetDisconnectCallback(func() { m.markGenerationDisconnected(generation) })
			m.clientsMu.Lock()
			m.forwardingManager = forwarder
			m.clientsMu.Unlock()
			if m.firstControl != nil && m.flowControlHandler != nil {
				m.flowControlHandler(m.firstControl)
			}
			m.firstControl = nil
			m.connWg.Add(2)
			go forwarder.ForwardPackets(&m.connWg)
			go m.handleStreamControl()
		}
		if policy, ok := m.filterManager.(interface{ ApplyPendingInitialE() error }); ok {
			if err := policy.ApplyPendingInitialE(); err != nil {
				logger.Error("Failed to apply processor policy", "processor", endpoint.Address, "error", err)
				m.setSelection("retrying", endpoint.Address, err.Error())
				m.cleanup()
				selector.Failed(index, time.Now())
				continue
			}
		} else {
			m.filterManager.ApplyPendingInitial()
		}
		// Successful policy rotation may deliberately replace the producer and
		// cancel this generation. Reconnect that route without publishing it ready.
		if m.connCtx.Err() != nil {
			m.cleanup()
			selector.Connected(index)
			selector.Disconnected(index)
			continue
		}
		selector.Connected(index)
		m.reconnectAttempts = 0
		m.reconnectMu.Lock()
		m.reconnecting = false
		m.reconnectMu.Unlock()
		m.statusMu.Lock()
		if previous != "" && previous != endpoint.Address {
			m.status.Failovers++
		}
		previous = endpoint.Address
		m.status.ActiveEndpoint = endpoint.Address
		m.status.State = "connected"
		m.status.Reason = "registration and ingress ready"
		m.status.LastConnected = time.Now()
		m.statusMu.Unlock()

		m.publishAcceptedMode()
		m.connWg.Add(2)
		go m.subscribeToFilters()
		go m.sendHeartbeats()
		m.monitorConnection()
		m.cleanup()
		m.statusMu.Lock()
		m.status.ActiveEndpoint = ""
		m.statusMu.Unlock()
		selector.Disconnected(index)
	}
	m.setSelection("stopped", "", "connection manager stopped")
}

func (m *Manager) failStartup(err error) {
	m.setSelection("invalid", "", err.Error())
	logger.Error("Processor connection configuration failed", "error", err)
	select {
	case m.startupError <- err:
	default:
	}
}

func (m *Manager) setSelection(state, endpoint, reason string) {
	m.statusMu.Lock()
	defer m.statusMu.Unlock()
	m.status.State, m.status.AttemptEndpoint, m.status.Reason = state, endpoint, reason
}

func (m *Manager) publishAcceptedMode() {
	if m.acceptedMode == management.ForwardingMode_FORWARDING_MODE_PACKETS {
		m.config.ForwardMode = "packets"
	}
	select {
	case m.modeReady <- m.acceptedMode:
	default:
	}
}

// connectAndRegister bounds setup independently from its long-lived streams.
func (m *Manager) connectAndRegister() error {
	if err := m.connectToProcessor(); err != nil {
		return fmt.Errorf("connect processor: %w", err)
	}
	if err := m.register(); err != nil {
		return err
	}
	if m.acceptedMode == management.ForwardingMode_FORWARDING_MODE_PACKETS {
		if err := m.startStreaming(); err != nil {
			return err
		}
	} else {
		if err := m.startEventStreaming(); err != nil {
			return err
		}
	}
	if policy, ok := m.filterManager.(interface {
		InitializePolicy(context.Context, grpc.ClientConnInterface) error
	}); ok {
		if err := policy.InitializePolicy(m.registrationContext(), m.managementConn); err != nil {
			return fmt.Errorf("initialize processor policy: %w", err)
		}
	}
	if err := m.filterManager.SetInitialFilters(m.registration.GetFilters()); err != nil {
		return fmt.Errorf("apply initial processor filters: %w", err)
	}
	if m.eventSetupCommit != nil {
		return m.eventSetupCommit()
	}
	return nil
}

// connectToProcessor establishes gRPC connections
func (m *Manager) connectToProcessor() error {
	logger.Info("Connecting to processor", "addr", m.endpointAddress())

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
	dataConn, err := grpc.NewClient(m.endpointAddress(), opts...)
	if err != nil {
		return fmt.Errorf("failed to dial processor data: %w", err)
	}
	m.dataConn = dataConn
	m.clientsMu.Lock()
	m.dataClient = data.NewDataServiceClient(dataConn)
	m.eventClient = eventsv1.NewEventServiceClient(dataConn)
	m.clientsMu.Unlock()

	// Connect management channel (same address for now, different service)
	mgmtConn, err := grpc.NewClient(m.endpointAddress(), opts...)
	if err != nil {
		if closeErr := dataConn.Close(); closeErr != nil {
			logger.Error("Failed to close data connection during error cleanup", "error", closeErr, "processor", m.config.ProcessorAddr)
		}
		return fmt.Errorf("failed to dial processor management: %w", err)
	}
	m.managementConn = mgmtConn
	m.clientsMu.Lock()
	m.mgmtClient = management.NewManagementServiceClient(mgmtConn)
	m.clientsMu.Unlock()

	logger.Info("Connected to processor", "addr", m.endpointAddress(), "tls", m.config.TLSEnabled,
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
		ServerNameOverride: m.endpointServerName(),
	})
}

func (m *Manager) endpointAddress() string {
	if m.endpoint.Address != "" {
		return m.endpoint.Address
	}
	return m.config.ProcessorAddr
}
func (m *Manager) endpointServerName() string {
	if m.endpoint.TLSServerName != "" {
		return m.endpoint.TLSServerName
	}
	return m.config.TLSServerNameOverride
}
func (m *Manager) registrationContext() context.Context {
	if m.setupCtx != nil {
		return m.setupCtx
	}
	return m.ctx
}

// register registers hunter with processor
func (m *Manager) register() error {
	logger.Info("Registering with processor", "hunter_id", m.config.HunterID)

	// Get local IP address - prefer the capture interface IP
	hostname := getInterfaceIP(m.config.Interfaces)
	logger.Info("Detected IP from capture interface", "ip", hostname)

	if hostname == "" {
		// Fallback to connection-based detection
		hostname = getConnectionLocalIPContext(m.registrationContext(), m.managementConn)
		logger.Info("Using connection local IP", "ip", hostname)
	}

	if hostname == "" {
		logger.Warn("Failed to detect local IP, using hunter ID as hostname")
		hostname = m.config.HunterID // Final fallback to hunter ID
	}

	// Determine filter capabilities based on hunter mode
	var filterTypes []string
	if len(m.config.SupportedFilterTypes) > 0 {
		// Use explicitly configured filter types
		filterTypes = m.config.SupportedFilterTypes
	} else if m.config.VoIPMode {
		// VoIP hunter - supports all filter types (call buffering + RTP association)
		filterTypes = []string{"bpf", "ip_address", "sip_user", "phone_number", "call_id", "codec", "sip_uri"}
	} else {
		// Generic hunter - only BPF and IP filters (no call buffering)
		filterTypes = []string{"bpf", "ip_address"}
	}

	requestedMode := management.ForwardingMode_FORWARDING_MODE_PACKETS
	if m.config.ForwardMode == "events" {
		requestedMode = management.ForwardingMode_FORWARDING_MODE_EVENTS
	}
	var radiusVersion uint32
	if m.config.RADIUSIngress {
		radiusVersion = 1
		filterTypes = append(append([]string(nil), filterTypes...), "radius_username", "radius_mac", "radius_attribute", "radius_compound")
	}

	features := []string{"tcp_reassembly", "connection_tracking", "file_metadata"}
	if m.config.InventoryEnabled {
		features = append(features, protoadapter.InventoryProductionFeature)
	}
	req := &management.HunterRegistration{
		HunterId:   m.config.HunterID,
		Hostname:   hostname,
		Interfaces: m.config.Interfaces,
		Version:    version.GetVersion(),
		Capabilities: &management.HunterCapabilities{
			FilterTypes:         filterTypes,
			RadiusFilterVersion: radiusVersion,
			MaxBufferSize:       uint64(m.config.BufferSize * 2048), // #nosec G115 - Assume 2KB avg packet
			GpuAcceleration:     false,                              // TODO: detect GPU
			AfXdp:               false,                              // TODO: detect AF_XDP
		},
		EventForwarding: &management.EventForwardingCapabilities{
			RequestedMode: requestedMode, EventApiMajors: []uint32{1},
			EventKinds: protoadapter.SupportedKindIDs(m.config.InventoryEnabled), SemanticProfileRevision: 1,
			StatefulAnalysisFeatures: features,
			SensitiveEnrichment:      viper.GetBool("logs.include_http_headers"),
			MaxSpoolBytes:            m.config.EventSpoolMaxBytes, MaxSpoolAgeSeconds: uint64(max(m.config.EventSpoolMaxAge/time.Second, 0)),
			AllowPacketFallback: m.config.EventFallbackToPackets,
		},
	}

	resp, err := m.mgmtClient.RegisterHunter(m.registrationContext(), req)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if !resp.Accepted {
		return fmt.Errorf("registration rejected: %s", resp.Error)
	}
	accepted := resp.GetAcceptedForwardingMode()
	if accepted == management.ForwardingMode_FORWARDING_MODE_UNSPECIFIED {
		accepted = management.ForwardingMode_FORWARDING_MODE_PACKETS
	}
	if requestedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS && accepted != requestedMode && !m.config.EventFallbackToPackets {
		return fmt.Errorf("registration rejected requested event forwarding profile: processor selected %s", accepted)
	}
	if requestedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS && accepted == management.ForwardingMode_FORWARDING_MODE_PACKETS {
		if forwarder := m.getEventForwarder(); forwarder != nil && forwarder.HasPending() {
			return errors.New("registration selected packet fallback while recovered event batches remain unacknowledged")
		}
	}
	if accepted == management.ForwardingMode_FORWARDING_MODE_EVENTS {
		if err := validateAcceptedEventProfile(resp, m.config.RequiredEventKinds...); err != nil {
			return fmt.Errorf("registration accepted an insufficient event forwarding profile: %w", err)
		}
	}
	if accepted == management.ForwardingMode_FORWARDING_MODE_EVENTS && m.getEventForwarder() == nil {
		return fmt.Errorf("registration selected event forwarding without an event runtime")
	}
	if accepted == management.ForwardingMode_FORWARDING_MODE_EVENTS {
		var kinds []eventsv1.EventKind
		for _, kind := range resp.GetAcceptedEventKinds() {
			kinds = append(kinds, eventsv1.EventKind(kind))
		}
		m.candidateKinds = kinds
		if m.setupCtx == nil {
			if err := m.getEventForwarder().SetAcceptedKinds(kinds); err != nil {
				return fmt.Errorf("apply accepted event kinds: %w", err)
			}
		} else if err := m.getEventForwarder().ValidateAcceptedKinds(kinds); err != nil {
			return fmt.Errorf("validate accepted event kinds: %w", err)
		}
	}
	m.acceptedMode = accepted

	logger.Info("Registration accepted",
		"assigned_id", resp.AssignedId,
		"initial_filters", len(resp.Filters), "forwarding_mode", accepted, "forwarding_notice", resp.GetForwardingNotice())

	m.registration = resp
	// Direct register calls in compatibility tests have no setup transaction.
	// Production publishes only after bounded ingress readiness and policy setup.
	if m.setupCtx == nil {
		if err := m.filterManager.SetInitialFilters(resp.Filters); err != nil {
			return fmt.Errorf("apply initial processor filters: %w", err)
		}
		m.publishAcceptedMode()
	}

	return nil
}

func validateAcceptedEventProfile(resp *management.RegistrationResponse, extraRequired ...eventsv1.EventKind) error {
	if resp.GetAcceptedEventApiMajor() != 1 {
		return fmt.Errorf("unsupported event API major %d", resp.GetAcceptedEventApiMajor())
	}
	if resp.GetAcceptedSemanticProfileRevision() != 1 {
		return fmt.Errorf("unsupported semantic profile revision %d", resp.GetAcceptedSemanticProfileRevision())
	}

	acceptedKinds := make(map[int32]struct{}, len(resp.GetAcceptedEventKinds()))
	for _, kind := range resp.GetAcceptedEventKinds() {
		acceptedKinds[kind] = struct{}{}
	}
	requiredKinds := []int32{1, 2, 3, 4, 5, 6, 7}
	for _, kind := range extraRequired {
		requiredKinds = append(requiredKinds, int32(kind))
	}
	for _, required := range requiredKinds {
		if _, ok := acceptedKinds[required]; !ok {
			return fmt.Errorf("required event kind %d was not accepted", required)
		}
	}
	return nil
}

// boundedSetup runs an operation on the generation's stream context, while
// cancelling the entire generation if its separate setup budget expires.
func (m *Manager) boundedSetup(operation func() error) error {
	if m.setupCtx == nil {
		return operation()
	}
	done := make(chan error, 1)
	m.connWg.Add(1)
	go func() { defer m.connWg.Done(); done <- operation() }()
	select {
	case err := <-done:
		return err
	case <-m.setupCtx.Done():
		m.connCancel()
		return m.setupCtx.Err()
	}
}

// startStreaming verifies admission with a zero-packet, sequence-zero control
// probe. This sends no captured traffic and never enters forwarding statistics.
// Legacy packet peers ACK ordinary empty batches, so no new RPC is required.
func (m *Manager) startStreaming() error {
	return m.boundedSetup(func() error {
		var stream data.DataService_StreamPacketsClient
		var err error
		if m.config.OpenPacketStream != nil {
			stream, err = m.config.OpenPacketStream(m.connCtx, m.registrationContext(), m.dataConn)
		} else {
			stream, err = m.dataClient.StreamPackets(m.connCtx)
		}
		if err != nil {
			return fmt.Errorf("create packet stream: %w", err)
		}
		m.streamMu.Lock()
		m.stream = stream
		m.streamMu.Unlock()
		if err := stream.Send(&data.PacketBatch{HunterId: m.config.HunterID, TimestampNs: time.Now().UnixNano()}); err != nil {
			return fmt.Errorf("probe packet ingress: %w", err)
		}
		control, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("packet ingress readiness: %w", err)
		}
		m.firstControl = control
		return nil
	})
}

func (m *Manager) startEventStreaming() error {
	ctx, cancel := context.WithCancel(m.connCtx)
	stream, err := m.eventClient.StreamEvents(ctx)
	if err != nil {
		cancel()
		return fmt.Errorf("create event stream: %w", err)
	}
	ready := make(chan struct{})
	proceed := make(chan struct{})
	committed := make(chan error, 1)
	exited := make(chan error, 1)
	forwarder := m.getEventForwarder()
	kinds := append([]eventsv1.EventKind(nil), m.candidateKinds...)
	connectionCtx := m.connCtx
	generation := m.generation.Load()
	m.connWg.Add(1)
	go func() {
		defer m.connWg.Done()
		err := forwarder.ServeNegotiated(ctx, stream, cancel, kinds, func() error {
			close(ready)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-proceed:
			}
			err := forwarder.SetAcceptedKinds(kinds)
			committed <- err
			return err
		})
		exited <- err
		if connectionCtx.Err() == nil {
			m.markGenerationDisconnected(generation)
		}
	}()
	select {
	case <-ready:
		m.eventSetupCommit = func() error {
			close(proceed)
			select {
			case err := <-committed:
				return err
			case err := <-exited:
				return err
			case <-m.registrationContext().Done():
				return m.registrationContext().Err()
			}
		}
		return nil
	case err := <-exited:
		cancel()
		if err == nil {
			return errors.New("event stream ended during setup")
		}
		return err
	case <-m.registrationContext().Done():
		cancel()
		return m.registrationContext().Err()
	}
}

// handleStreamControl receives flow control messages from processor
func (m *Manager) handleStreamControl() {
	defer m.connWg.Done()
	ctx := m.connCtx
	generation := m.generation.Load()
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
		case <-ctx.Done():
			logger.Debug("handleStreamControl: connection context cancelled, exiting")
			return
		default:
		}

		ctrl, err := stream.Recv()
		if err == io.EOF {
			logger.Info("Stream closed by processor")
			m.markGenerationDisconnected(generation)
			return
		}
		if err != nil {
			// Check if we're shutting down
			if m.ctx.Err() != nil || ctx.Err() != nil {
				// Context canceled, normal shutdown
				logger.Debug("handleStreamControl: error during shutdown, exiting gracefully", "error", err)
				return
			}
			logger.Error("Stream control error", "error", err)
			m.markGenerationDisconnected(generation)
			return
		}

		logger.Debug("Received flow control",
			"ack_sequence", ctrl.AckSequence,
			"flow_control", ctrl.FlowControl)

		// Delegate to flow control handler (hunter → forwarding manager)
		if m.flowControlHandler != nil {
			m.flowControlHandler(ctrl)
		}
	}
}

// subscribeToFilters subscribes to filter updates from processor
func (m *Manager) subscribeToFilters() {
	defer m.connWg.Done()
	logger.Debug("subscribeToFilters goroutine starting")
	defer logger.Debug("subscribeToFilters goroutine exiting")
	m.filterManager.Subscribe(m.connCtx, m.connCtx, m.mgmtClient)
}

// sendHeartbeats sends periodic heartbeat to processor
func (m *Manager) sendHeartbeats() {
	defer m.connWg.Done()
	ctx := m.connCtx
	generation := m.generation.Load()
	logger.Debug("sendHeartbeats goroutine starting")
	defer logger.Debug("sendHeartbeats goroutine exiting")

	logger.Info("Starting heartbeat stream to processor")

	stream, err := m.mgmtClient.Heartbeat(ctx)
	if err != nil {
		logger.Error("Failed to create heartbeat stream", "error", err)
		m.markGenerationDisconnected(generation)
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
			case <-ctx.Done():
				return
			default:
			}

			resp, err := stream.Recv()
			if err != nil {
				// Only send error if not shutting down
				if m.ctx.Err() == nil && ctx.Err() == nil {
					respErrCh <- err
				}
				return
			}
			select {
			case respCh <- resp:
			case <-m.ctx.Done():
				return
			case <-ctx.Done():
				return
			}
		}
	}()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Heartbeat stream closed")
			return

		case err := <-respErrCh:
			if m.ctx.Err() != nil {
				return
			}
			logger.Error("Heartbeat stream error", "error", err)
			m.markGenerationDisconnected(generation)
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

			stats := m.statsCollector.ToProto(activeFilters)
			if m.captureManager != nil {
				applyCaptureBufferStats(stats, m.captureManager.GetPacketBuffer())
			}
			logger.Debug("Sending heartbeat",
				"hunter_id", m.config.HunterID,
				"active_filters", activeFilters,
				"packets_captured", packetsCaptured,
				"packets_forwarded", packetsForwarded,
				"packets_dropped", stats.PacketsDropped,
				"capture_buffer_regular_drops", stats.CaptureBufferRegularDrops,
				"capture_buffer_sip_drops", stats.CaptureBufferSipDrops,
				"capture_buffer_sip_demotions", stats.CaptureBufferSipDemotions,
				"capture_buffer_regular_len", stats.CaptureBufferRegularLen,
				"capture_buffer_regular_capacity", stats.CaptureBufferRegularCapacity,
				"capture_buffer_sip_len", stats.CaptureBufferSipLen,
				"capture_buffer_sip_capacity", stats.CaptureBufferSipCapacity,
				"capture_buffer_output_len", stats.CaptureBufferOutputLen,
				"capture_buffer_output_capacity", stats.CaptureBufferOutputCapacity,
				"batch_channel_drops", stats.BatchChannelDrops,
				"status", status)
			hb := &management.HunterHeartbeat{
				HunterId:    m.config.HunterID,
				TimestampNs: time.Now().UnixNano(),
				Status:      status,
				Stats:       stats,
			}

			if err := stream.Send(hb); err != nil {
				if m.ctx.Err() != nil {
					return
				}
				logger.Error("Failed to send heartbeat", "error", err)
				m.markGenerationDisconnected(generation)
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
		snapshot := buffer.Snapshot()
		bufferUsage := snapshot.TotalLength()
		bufferCapacity := snapshot.TotalCapacity()

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
		case <-m.connCtx.Done():
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
	if policy, ok := m.filterManager.(interface{ PolicyDisconnected() }); ok {
		policy.PolicyDisconnected()
	}
	// Cancel connection-scoped context to signal all goroutines to exit
	if m.connCancel != nil {
		m.connCancel()
	}

	// Closing management transport releases stream receivers, including partial setup.
	if m.managementConn != nil {
		if err := m.managementConn.Close(); err != nil {
			logger.Error("Close management transport", "error", err)
		}
		m.managementConn = nil
	}
	if m.forwardingManager != nil {
		grace := m.forwardingExitGrace
		if grace <= 0 {
			grace = defaultForwardingExitGrace
		}
		senderDone := make(chan struct{})
		go func(manager *forwarding.Manager) {
			manager.Wait()
			close(senderDone)
		}(m.forwardingManager)

		select {
		case <-senderDone:
		case <-time.After(grace):
			logger.Warn("Forwarding sender did not exit after cancellation; forcing data transport closed")
			if err := m.forceCloseDataTransport(); err != nil {
				logger.Error("Failed to force data transport closed", "error", err, "processor", m.config.ProcessorAddr)
			}
			// Do not permit creation of a successor while the old generation still
			// owns Send/CloseSend. Closing a gRPC ClientConn unblocks its streams.
			<-senderDone
		}
	}

	if m.dataConn != nil {
		if err := m.dataConn.Close(); err != nil {
			logger.Error("Close data transport", "error", err)
		}
		m.dataConn = nil
	}
	// Never let a successor reuse the waitgroup or transport fields while a
	// predecessor still owns them. Cancellation and transport closure unblock RPCs.
	m.connWg.Wait()
	m.clientsMu.Lock()
	m.forwardingManager = nil
	m.dataClient = nil
	m.mgmtClient = nil
	m.eventClient = nil
	m.clientsMu.Unlock()
	m.eventSetupCommit = nil
	m.candidateKinds = nil
	m.firstControl = nil
	m.streamMu.Lock()
	m.stream = nil
	m.streamMu.Unlock()

}

func (m *Manager) forceCloseDataTransport() error {
	if m.closeDataTransport != nil {
		return m.closeDataTransport()
	}
	if m.dataConn != nil {
		conn := m.dataConn
		m.dataConn = nil // cleanup must not close and report the same transport twice
		return conn.Close()
	}
	return nil
}

// getConnectionLocalIP returns the local IP address used for the gRPC connection
func getConnectionLocalIP(conn *grpc.ClientConn) string {
	return getConnectionLocalIPContext(context.Background(), conn)
}

func getConnectionLocalIPContext(ctx context.Context, conn *grpc.ClientConn) string {
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
	resolvedIPs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err == nil && len(resolvedIPs) > 0 {
		targetIP := resolvedIPs[0].IP
		logger.Debug("getConnectionLocalIP: resolved target", "host", host, "ip", targetIP.String())

		if targetIP.IsLoopback() {
			logger.Debug("getConnectionLocalIP: target is loopback, finding non-loopback IP")
			return getFirstNonLoopbackIP()
		}
	}

	dialAddr := net.JoinHostPort(host, port)
	logger.Debug("getConnectionLocalIP: dialing UDP", "addr", dialAddr)

	// Dial a temporary UDP connection to see which local IP would be used
	udpConn, err := (&net.Dialer{}).DialContext(ctx, "udp", dialAddr)
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

func applyCaptureBufferStats(stats *management.HunterStats, buffer *capture.PacketBuffer) {
	if stats == nil || buffer == nil {
		return
	}
	snapshot := buffer.Snapshot()
	stats.CaptureBufferRegularDrops = uint64(snapshot.RegularDropped)     // #nosec G115 -- counters cannot be negative
	stats.CaptureBufferSipDrops = uint64(snapshot.SIPDropped)             // #nosec G115 -- counters cannot be negative
	stats.CaptureBufferSipDemotions = uint64(snapshot.SIPDemoted)         // #nosec G115 -- counters cannot be negative
	stats.CaptureBufferRegularLen = uint64(snapshot.RegularLength)        // #nosec G115 -- channel lengths cannot be negative
	stats.CaptureBufferRegularCapacity = uint64(snapshot.RegularCapacity) // #nosec G115 -- channel capacities cannot be negative
	stats.CaptureBufferSipLen = uint64(snapshot.SIPLength)                // #nosec G115 -- channel lengths cannot be negative
	stats.CaptureBufferSipCapacity = uint64(snapshot.SIPCapacity)         // #nosec G115 -- channel capacities cannot be negative
	stats.CaptureBufferOutputLen = uint64(snapshot.OutputLength)          // #nosec G115 -- channel lengths cannot be negative
	stats.CaptureBufferOutputCapacity = uint64(snapshot.OutputCapacity)   // #nosec G115 -- channel capacities cannot be negative
	stats.PacketsDropped = stats.CaptureBufferRegularDrops + stats.CaptureBufferSipDrops + stats.BatchChannelDrops
}
