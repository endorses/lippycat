package upstream

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/constants"
	"github.com/endorses/lippycat/internal/pkg/events/protoadapter"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/grpcpool"
	learnedwire "github.com/endorses/lippycat/internal/pkg/learnedrules/wire"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/tlsutil"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

// Config contains upstream connection configuration
type Config struct {
	OnEndpoint    func(context.Context, failover.Endpoint) error
	Address       string // Legacy upstream processor address
	Endpoints     []failover.Endpoint
	Failover      failover.Config
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
	OutboundQueueSize      int
	ForwardMode            string
	EventFallbackToPackets bool
	RequiredEventKinds     []eventsv1.EventKind
	InventoryEnabled       bool
	DNSNoticesEnabled      bool
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
	enqueueMu      sync.Mutex
	wg             sync.WaitGroup
}

// Manager handles upstream processor connection and forwarding
type Manager struct {
	config        Config
	selector      *failover.Selector
	activeAddress string
	activeIndex   int
	configErr     error

	// gRPC connection
	conn        *grpc.ClientConn
	dataClient  data.DataServiceClient
	mgmtClient  management.ManagementServiceClient
	eventClient eventsv1.EventServiceClient
	generation  *connection
	mu          sync.Mutex

	// Connection pooling
	connPool *grpcpool.ConnectionPool

	// Upstream processor ID (learned during registration)
	upstreamProcessorID string
	acceptedEventKinds  []eventsv1.EventKind

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
	droppedPackets       atomic.Uint64
	modeNegotiated       atomic.Bool
	eventFallbackGuard   func() bool
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
	endpoints, endpointErr := failover.NormalizeEndpoints(config.Address, config.Endpoints)
	config.Endpoints = endpoints
	if !config.TLSEnabled {
		for _, endpoint := range endpoints {
			if endpoint.TLSServerName != "" {
				endpointErr = errors.Join(endpointErr, errors.New("tls_server_name requires TLS"))
			}
		}
	}
	normalized, configErr := failover.NormalizeConfig(config.Failover)
	config.Failover = normalized
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		selector:         failover.NewSelector(endpoints, normalized),
		activeIndex:      -1,
		configErr:        errors.Join(endpointErr, configErr),
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
	if m.configErr != nil {
		return m.configErr
	}
	if len(m.config.Endpoints) == 0 {
		return fmt.Errorf("upstream address not configured")
	}

	initialConnected := false
	// Packet fallback cannot safely change the forwarding mode after local tap
	// capture has begun: packets observed before negotiation would already have
	// been committed to the event pipeline. Resolve that explicit boundary
	// synchronously before Processor.Start launches local capture.
	if m.config.ForwardMode == "events" && m.config.EventFallbackToPackets {
		var attemptErrors []error
		for index, endpoint := range m.config.Endpoints {
			if err := m.connectEndpoint(endpoint); err != nil {
				attemptErrors = append(attemptErrors, err)
				m.selector.Failed(index, time.Now())
				continue
			}
			m.activeIndex = index
			m.selector.Connected(index)
			initialConnected = true
			break
		}
		if !initialConnected {
			return fmt.Errorf("negotiate initial upstream forwarding mode: %w", errors.Join(attemptErrors...))
		}
	}

	m.wg.Add(1)
	go m.connectionManager(initialConnected)

	return nil
}

// SetEventFallbackGuard installs a check that reports whether switching to
// packet forwarding would strand durable event batches recovered at startup.
// It must be configured before Start.
func (m *Manager) SetEventFallbackGuard(guard func() bool) {
	m.mu.Lock()
	m.eventFallbackGuard = guard
	m.mu.Unlock()
}

func (m *Manager) canFallbackToPackets() bool {
	m.mu.Lock()
	guard := m.eventFallbackGuard
	m.mu.Unlock()
	return guard == nil || !guard()
}

// connectionManager manages upstream connection lifecycle with automatic reconnection
func (m *Manager) connectionManager(initialConnected bool) {
	defer m.wg.Done()
	for m.ctx.Err() == nil {
		if !initialConnected {
			if err := m.connectNext(); err != nil {
				if m.ctx.Err() == nil && !errors.Is(err, errCandidatesCoolingDown) {
					logger.Warn("Upstream candidate failed", "error", err)
				}
				continue
			}
		}
		initialConnected = false
		m.monitorConnection()
		index := m.activeIndex
		m.cleanup()
		if index >= 0 {
			m.selector.Disconnected(index)
		}
	}
}

func (m *Manager) connectNext() error {
	endpoint, index, wait := m.selector.Next(time.Now())
	if wait > 0 {
		timer := time.NewTimer(wait)
		defer timer.Stop()
		select {
		case <-timer.C:
			return errCandidatesCoolingDown
		case <-m.ctx.Done():
			return m.ctx.Err()
		}
	}
	if err := m.connectEndpoint(endpoint); err != nil {
		m.selector.Failed(index, time.Now())
		return err
	}
	m.activeIndex = index
	m.selector.Connected(index)
	return nil
}

var errCandidatesCoolingDown = errors.New("upstream candidates cooling down")

// connectAndRegister establishes connection to upstream processor and registers
func (m *Manager) connectAndRegister() error {
	if m.configErr != nil {
		return m.configErr
	}
	if len(m.config.Endpoints) == 0 {
		return errors.New("upstream address not configured")
	}
	return m.connectEndpoint(m.config.Endpoints[0])
}

func (m *Manager) connectEndpoint(endpoint failover.Endpoint) error {
	attemptCtx, cancelAttempt := context.WithTimeout(m.ctx, m.config.Failover.AttemptTimeout)
	defer cancelAttempt()
	if m.config.OnEndpoint != nil {
		if err := m.config.OnEndpoint(attemptCtx, endpoint); err != nil {
			return err
		}
	}
	logger.Info("Connecting to upstream processor", "addr", endpoint.Address)

	// Create gRPC connection with TLS if enabled
	opts := []grpc.DialOption{
		grpc.WithBlock(),
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
			CAFile:             m.config.TLSCAFile,
			ServerNameOverride: endpoint.TLSServerName,
			CertFile:           m.config.TLSCertFile,
			KeyFile:            m.config.TLSKeyFile,
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

	conn, err := grpcpool.Get(m.connPool, attemptCtx, endpoint.Address, opts...)
	if err != nil {
		return fmt.Errorf("failed to dial upstream: %w", err)
	}

	committed := false
	defer func() {
		if !committed {
			grpcpool.Release(m.connPool, endpoint.Address)
		}
	}()
	dataClient := data.NewDataServiceClient(conn)
	mgmtClient := management.NewManagementServiceClient(conn)
	effectiveMode := m.config.ForwardMode
	var acceptedKinds []eventsv1.EventKind
	var upstreamID string
	var rawRelayVersion uint32

	// Register this processor with upstream
	if m.config.ProcessorID != "" && m.config.ListenAddress != "" {
		logger.Info("Registering processor with upstream",
			"processor_id", m.config.ProcessorID,
			"listen_address", m.config.ListenAddress)

		requestedMode := management.ForwardingMode_FORWARDING_MODE_PACKETS
		if m.config.ForwardMode == "events" {
			requestedMode = management.ForwardingMode_FORWARDING_MODE_EVENTS
		}
		allowFallback := m.config.EventFallbackToPackets && !m.modeNegotiated.Load()
		regResp, err := mgmtClient.RegisterProcessor(attemptCtx, &management.ProcessorRegistration{
			ProcessorId:     m.config.ProcessorID,
			ListenAddress:   m.config.ListenAddress,
			Version:         "dev", // TODO: Use actual version
			EventForwarding: &management.EventForwardingCapabilities{RequestedMode: requestedMode, EventApiMajors: []uint32{1}, EventKinds: protoadapter.SupportedKindIDs(true), SemanticProfileRevision: 1, StatefulAnalysisFeatures: m.eventAnalysisFeatures(), AllowPacketFallback: allowFallback},
		})
		if err != nil {
			return fmt.Errorf("failed to register with upstream processor: %w", err)
		}
		if !regResp.Accepted {
			return fmt.Errorf("upstream processor rejected registration: %s", regResp.Error)
		}
		acceptedMode := regResp.GetAcceptedForwardingMode()
		if acceptedMode == management.ForwardingMode_FORWARDING_MODE_UNSPECIFIED {
			acceptedMode = management.ForwardingMode_FORWARDING_MODE_PACKETS
		}
		if acceptedMode != management.ForwardingMode_FORWARDING_MODE_EVENTS && acceptedMode != management.ForwardingMode_FORWARDING_MODE_PACKETS {
			return fmt.Errorf("upstream selected unsupported forwarding mode %s", acceptedMode)
		}
		if requestedMode == management.ForwardingMode_FORWARDING_MODE_PACKETS && acceptedMode != requestedMode {
			return fmt.Errorf("upstream changed requested packet forwarding mode to %s", acceptedMode)
		}
		if requestedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS && acceptedMode != requestedMode && !allowFallback {
			return fmt.Errorf("upstream rejected requested event forwarding profile: selected %s", acceptedMode)
		}
		if requestedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS && acceptedMode == management.ForwardingMode_FORWARDING_MODE_PACKETS {
			if !m.canFallbackToPackets() {
				return errors.New("upstream selected packet fallback while recovered event batches remain unacknowledged")
			}
			effectiveMode = "packets"
			logger.Warn("Upstream explicitly selected packet fallback", "notice", regResp.GetForwardingNotice())
		}
		if acceptedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS {
			if err := validateAcceptedEventProfile(regResp, protoadapter.RequiredDNSNoticeKinds(m.config.RequiredEventKinds, m.config.DNSNoticesEnabled)...); err != nil {
				return fmt.Errorf("upstream accepted an insufficient event forwarding profile: %w", err)
			}
		}
		if acceptedMode == management.ForwardingMode_FORWARDING_MODE_EVENTS {
			for _, kind := range regResp.GetAcceptedEventKinds() {
				acceptedKinds = append(acceptedKinds, eventsv1.EventKind(kind))
			}
		}

		// Store the upstream processor ID for topology reporting
		upstreamID = regResp.UpstreamProcessorId
		rawRelayVersion = regResp.GetRawRelayVersion()
		logger.Info("Successfully registered with upstream processor",
			"upstream_processor_id", regResp.UpstreamProcessorId)
	} else {
		logger.Warn("ProcessorID or ListenAddress not configured, skipping processor registration")
	}

	// Stream lifetime belongs to the generation, while setup is bounded by the
	// attempt deadline. Stop its cancellation hook before committing the generation.
	generationCtx, generationCancel := context.WithCancel(m.ctx)
	stopAttempt := context.AfterFunc(attemptCtx, generationCancel)
	generation := &connection{queue: make(chan *data.PacketBatch, m.config.OutboundQueueSize), ctx: generationCtx, cancel: generationCancel}
	if effectiveMode != "events" {
		var stream upstreamStream
		var err error
		switch rawRelayVersion {
		case 0:
			logger.Warn("Upstream does not advertise authenticated raw relay ingress; using legacy packet forwarding", "address", endpoint.Address, "notice", "legacy admission may reject relayed hunter origins")
			var legacy data.DataService_StreamPacketsClient
			legacy, err = dataClient.StreamPackets(generationCtx)
			if err == nil {
				stream = learnedwire.NewPacketStream(legacy, nil)
			}
		case 1:
			stream, err = openRelayStream(generationCtx, conn, m.config.ProcessorID)
		default:
			err = fmt.Errorf("unsupported upstream raw relay version %d", rawRelayVersion)
		}
		if err != nil {
			stopAttempt()
			generationCancel()
			return fmt.Errorf("create upstream stream: %w", err)
		}
		generation.stream = stream
	}

	if !stopAttempt() || attemptCtx.Err() != nil || generationCtx.Err() != nil {
		generationCancel()
		return fmt.Errorf("upstream attempt ended before commit: %w", attemptCtx.Err())
	}
	generation.accepting.Store(true)
	// Publish only fully initialized state. Failed candidates never change mode,
	// accepted kinds or topology, nor expose an event client to a route sender.
	m.reconnectMu.Lock()
	m.reconnecting = false
	m.reconnectAttempts = 0
	m.reconnectMu.Unlock()
	m.mu.Lock()
	m.conn = conn
	m.dataClient = dataClient
	m.mgmtClient = mgmtClient
	m.eventClient = eventsv1.NewEventServiceClient(conn)
	m.config.ForwardMode = effectiveMode
	m.acceptedEventKinds = acceptedKinds
	m.upstreamProcessorID = upstreamID
	m.activeAddress = endpoint.Address
	m.generation = generation
	m.modeNegotiated.Store(true)
	m.mu.Unlock()
	committed = true
	if generation.stream != nil {
		generation.wg.Add(2)
		go m.sendBatches(generation)
		go m.receiveAcks(generation)
	}
	return nil
}

func validateAcceptedEventProfile(resp *management.ProcessorRegistrationResponse, extraRequired ...eventsv1.EventKind) error {
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

// ForwardingEvents reports the fixed effective transport mode. It changes only
// once when an explicitly permitted initial event negotiation falls back.
func (m *Manager) ForwardingEvents() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config.ForwardMode == "events"
}

// RequiredInventoryKinds expands an inventory production promise to both
// inventory kinds when accepting downstream sources. This must not expand
// outbound consumer requirements: an optional inventory producer can still
// forward baseline events to an older upstream and report compatibility loss.
// One required inventory stream cannot promise an unchecked other kind.
func RequiredInventoryKinds(required []eventsv1.EventKind, inventoryEnabled bool) []eventsv1.EventKind {
	for _, kind := range required {
		inventoryEnabled = inventoryEnabled || kind == eventsv1.EventKind_EVENT_KIND_KNOWN_HOST || kind == eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE
	}
	result := append([]eventsv1.EventKind(nil), required...)
	if !inventoryEnabled {
		return result
	}
	for _, kind := range []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_KNOWN_HOST, eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE} {
		found := false
		for _, existing := range result {
			found = found || existing == kind
		}
		if !found {
			result = append(result, kind)
		}
	}
	return result
}

func (m *Manager) eventAnalysisFeatures() []string {
	features := []string{"relay"}
	notices := m.config.DNSNoticesEnabled
	for _, kind := range m.config.RequiredEventKinds {
		notices = notices || kind == eventsv1.EventKind_EVENT_KIND_NOTICE
	}
	if notices {
		features = append(features, protoadapter.DNSNoticeProductionFeature)
	}
	// Processor registration enforces both inventory kinds on event-mode
	// children whenever either of these conditions makes an upstream promise.
	// Merely having inventory codecs is deliberately insufficient.
	inventory := m.config.InventoryEnabled
	for _, kind := range m.config.RequiredEventKinds {
		inventory = inventory || kind == eventsv1.EventKind_EVENT_KIND_KNOWN_HOST || kind == eventsv1.EventKind_EVENT_KIND_KNOWN_SERVICE
	}
	if inventory {
		features = append(features, protoadapter.InventoryProductionFeature)
	}
	return features
}

// Until registration completes only legacy kinds are eligible for spooling.
func (m *Manager) eventKinds() []eventsv1.EventKind {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.acceptedEventKinds) == 0 {
		return []eventsv1.EventKind{1, 2, 3, 4, 5, 6, 7}
	}
	return append([]eventsv1.EventKind(nil), m.acceptedEventKinds...)
}

func (m *Manager) eventServiceClient() eventsv1.EventServiceClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventClient
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
	m.eventClient = nil
	address := m.activeAddress
	m.activeAddress = ""
	m.upstreamProcessorID = ""
	conn := m.conn
	m.conn = nil
	m.mu.Unlock()
	if generation != nil {
		generation.enqueueMu.Lock()
		generation.accepting.Store(false)
		generation.enqueueMu.Unlock()
		generation.cancel()
		generation.wg.Wait()
	}

	if conn != nil {
		grpcpool.Release(m.connPool, address)
	}
}

// Forward forwards packet batch to upstream processor
func (m *Manager) Forward(batch *data.PacketBatch) {
	m.TryForward(batch)
}

// TryForward reports acceptance by the current bounded outbound queue, not
// remote delivery. Rejected observations remain eligible at other origins.
func (m *Manager) TryForward(batch *data.PacketBatch) bool {
	if batch == nil {
		return false
	}
	m.mu.Lock()
	generation := m.generation
	m.mu.Unlock()

	if generation == nil {
		m.recordDropped(batch, "stream unavailable")
		logger.Debug("Upstream stream not available, dropping batch")
		return false
	}

	// Serialize the accepting check with generation teardown. This prevents a
	// producer that already loaded the old generation pointer from enqueueing
	// after its sender has discarded the generation's queue.
	generation.enqueueMu.Lock()
	defer generation.enqueueMu.Unlock()
	if !generation.accepting.Load() {
		m.recordDropped(batch, "generation stopped")
		return false
	}

	select {
	case generation.queue <- batch:
		return true
	case <-generation.ctx.Done():
		m.recordDropped(batch, "generation cancelled")
	case <-m.ctx.Done():
		m.recordDropped(batch, "manager stopped")
	default:
		dropped := m.recordDropped(batch, "queue full")
		logger.Warn("Upstream outbound queue full, dropping batch",
			"queue_capacity", cap(generation.queue), "dropped_batches", dropped,
			"packets", len(batch.Packets))
	}
	return false
}

func (m *Manager) recordDropped(batch *data.PacketBatch, reason string) uint64 {
	dropped := m.droppedBatches.Add(1)
	m.droppedPackets.Add(uint64(len(batch.Packets)))
	logger.Debug("Discarded upstream batch", "reason", reason,
		"packets", len(batch.Packets), "dropped_batches", dropped)
	return dropped
}

// DroppedBatches returns the total number of batches rejected or discarded.
func (m *Manager) DroppedBatches() uint64 { return m.droppedBatches.Load() }

// DroppedPackets returns the total number of packets in rejected or discarded batches.
func (m *Manager) DroppedPackets() uint64 { return m.droppedPackets.Load() }

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
		m.discardGenerationQueue(generation)
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
			// Cancellation may race with a ready queue. Once cancelled, do not
			// send another batch on this obsolete generation.
			if generation.ctx.Err() != nil {
				m.recordDropped(batch, "generation cancelled")
				return
			}
			generation.inFlight.Add(1)
			if err := generation.stream.Send(batch); err != nil {
				generation.inFlight.Add(-1)
				m.recordDropped(batch, "send failed")
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

// discardGenerationQueue stops producers and synchronously empties only the
// bounded in-memory queue. It never waits for delivery, so shutdown remains
// bounded once the active Send returns.
func (m *Manager) discardGenerationQueue(generation *connection) {
	generation.enqueueMu.Lock()
	defer generation.enqueueMu.Unlock()
	generation.accepting.Store(false)
	for {
		select {
		case batch := <-generation.queue:
			m.recordDropped(batch, "generation teardown")
		default:
			return
		}
	}
}

// disconnectGeneration terminates a failed stream generation and requests one
// reconnect, even when both its sender and receiver observe the failure.
func (m *Manager) disconnectGeneration(generation *connection) {
	generation.disconnectOnce.Do(func() {
		generation.enqueueMu.Lock()
		generation.accepting.Store(false)
		generation.enqueueMu.Unlock()
		generation.cancel()
		m.mu.Lock()
		current := m.generation == generation
		if current {
			m.MarkDisconnected()
		}
		m.mu.Unlock()
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

// ActiveAddress reports the committed connection, or empty while disconnected.
func (m *Manager) ActiveAddress() string { m.mu.Lock(); defer m.mu.Unlock(); return m.activeAddress }

// Configured is independent of current upstream availability.
func (m *Manager) Configured() bool { return len(m.config.Endpoints) > 0 }

func (m *Manager) eventGeneration() (eventsv1.EventServiceClient, *connection) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.eventClient, m.generation
}

// LearnedEvidenceVersions reports preservation validated across the active raw route.
func (m *Manager) LearnedEvidenceVersions() []uint32 {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.generation == nil || m.generation.stream == nil || !m.generation.accepting.Load() || m.generation.ctx.Err() != nil {
		return nil
	}
	if stream, ok := m.generation.stream.(interface{ LearnedEvidenceVersions() []uint32 }); ok {
		return stream.LearnedEvidenceVersions()
	}
	return nil
}
