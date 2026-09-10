//go:build hunter || all

package hunter

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	eventsv1 "github.com/endorses/lippycat/api/gen/events/v1"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/gpuaccel"
	huntercapture "github.com/endorses/lippycat/internal/pkg/hunter/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter/connection"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventforwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/eventspool"
	"github.com/endorses/lippycat/internal/pkg/hunter/filtering"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/hunter/stats"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/radius"
	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

func stableFilterIDUnion(direct, inherited []string) []string {
	result := make([]string, 0, len(direct)+len(inherited))
	seen := make(map[string]struct{}, len(direct)+len(inherited))
	for _, ids := range [][]string{direct, inherited} {
		for _, id := range ids {
			if id == "" {
				continue
			}
			if _, exists := seen[id]; exists {
				continue
			}
			seen[id] = struct{}{}
			result = append(result, id)
		}
	}
	return result
}

// Config contains hunter configuration
type Config struct {
	RADIUSPorts       []uint16
	RADIUSScope       radius.CaptureScope
	RADIUSOnly        bool
	RADIUSCorrelation radius.CorrelatorConfig
	RADIUSMatcher     radius.ObservationMatcher
	ProcessorAddr     string
	HunterID          string
	Interfaces        []string
	BPFFilter         string
	BufferSize        int
	BatchSize         int
	BatchTimeout      time.Duration
	BatchQueueSize    int // Number of batches to buffer for async sending (0 = default: 1000)
	// Flow control settings
	MaxBufferedBatches int           // Max batches to buffer before blocking (0 = unlimited)
	SendTimeout        time.Duration // Timeout for sending batches (0 = no timeout)
	// VoIP filtering
	VoIPMode         bool   // True for 'lc hunt voip' (with call buffering), false for generic hunt
	EnableVoIPFilter bool   // Enable VoIP filtering with GPU acceleration
	GPUBackend       string // GPU backend: "auto", "cuda", "opencl", "cpu-simd"
	GPUBatchSize     int    // Batch size for GPU processing
	// Filter capabilities advertised to processor
	SupportedFilterTypes []string // Filter types this hunter supports (overrides VoIPMode defaults)
	// TLS settings
	TLSEnabled            bool   // Enable TLS encryption for gRPC connections
	TLSCertFile           string // Path to TLS certificate file (for server verification)
	TLSKeyFile            string // Path to TLS key file (for mutual TLS)
	TLSCAFile             string // Path to CA certificate file
	TLSSkipVerify         bool   // Skip certificate verification (insecure, for testing only)
	TLSServerNameOverride string // Override server name for TLS verification (testing only)
	// Disk overflow buffer
	DiskBufferEnabled bool   // Enable disk overflow buffer for nuclear-proof resilience
	DiskBufferDir     string // Directory for disk buffer (default: /var/tmp/lippycat-buffer)
	DiskBufferMaxSize uint64 // Maximum disk buffer size in bytes (default: 1GB)
	// Filter policy
	NoFilterPolicy string // Policy when no filters: "allow" (default) or "deny"
	// Normalized event forwarding. Packet forwarding remains the compatibility default.
	ForwardMode                string
	EventFallbackToPackets     bool
	EventDeliveryProfile       string
	EventSpoolDir              string
	EventSpoolMaxBytes         uint64
	EventSpoolMaxAge           time.Duration
	EventSpoolExhaustionPolicy string
}

// Hunter represents a hunter node
type Hunter struct {
	config Config

	// Managers
	captureManager    *huntercapture.Manager
	filterManager     *filtering.Manager
	connectionManager *connection.Manager
	statsCollector    *stats.Collector

	// Application-level filtering (GPU-accelerated, protocol-agnostic)
	applicationFilter *ApplicationFilter

	// DNS processing (tunneling detection at edge)
	dnsProcessor *DNSProcessor

	// Custom packet processing
	packetProcessor forwarding.PacketProcessor // Optional custom processor for VoIP buffering, etc.

	// Persistent batch queue (survives reconnections)
	batchQueue     chan *pipeline.PacketBatch
	batchQueueSize int

	// Control
	ctx             context.Context
	cancel          context.CancelFunc
	wg              sync.WaitGroup
	eventRuntime    *eventanalysis.Runtime
	eventDispatcher *events.Dispatcher
	eventForwarder  *eventforwarding.Client
	eventSpool      *eventspool.Spool
	eventMu         sync.RWMutex
	eventLossMu     sync.Mutex
	eventLossSource *events.Dispatcher
	eventLossCount  uint64
}

// New creates a new hunter instance
func New(config Config) (*Hunter, error) {
	if _, err := radius.NewCorrelator(config.RADIUSCorrelation); err != nil {
		return nil, err
	}
	for _, port := range config.RADIUSPorts {
		if port == 0 {
			return nil, fmt.Errorf("RADIUS service port must be nonzero")
		}
	}
	if config.ProcessorAddr == "" {
		return nil, fmt.Errorf("processor address is required")
	}

	if config.HunterID == "" {
		return nil, fmt.Errorf("hunter ID is required")
	}

	// Set defaults for flow control if not configured
	if config.MaxBufferedBatches == 0 {
		config.MaxBufferedBatches = 10 // Default: buffer up to 10 batches
	}
	if config.SendTimeout == 0 {
		config.SendTimeout = 5 * time.Second // Default: 5s timeout
	}

	// Create main context for initialization (will be replaced in Start())
	// This is just for the capture manager constructor
	ctx := context.Background()

	// Create capture manager (will be recreated with proper context in Start())
	captureManager := huntercapture.New(huntercapture.Config{
		ReassembleIPFragments: config.VoIPMode,
		RADIUSPorts:           config.RADIUSPorts,
		Interfaces:            config.Interfaces,
		BaseFilter:            config.BPFFilter,
		BufferSize:            config.BufferSize,
		ProcessorAddr:         config.ProcessorAddr,
	}, ctx)

	// Determine batch queue size (default or configured)
	batchQueueSize := config.BatchQueueSize
	if batchQueueSize == 0 {
		// Default: 1000 batches (matches forwarding manager default)
		batchQueueSize = 1000
	}

	h := &Hunter{
		config:         config,
		statsCollector: stats.New(),
		captureManager: captureManager,
		batchQueue:     make(chan *pipeline.PacketBatch, batchQueueSize),
		batchQueueSize: batchQueueSize,
	}

	// Create filter manager with capture restarter interface
	h.filterManager = filtering.New(config.HunterID, captureManager, h)
	if config.ForwardMode == "events" {
		h.filterManager.SetPolicyChangeCoordinator(h)
	}

	// Note: Application filter will be wired up in Start() after initialization
	// This allows filter manager to hot-reload app-level filters without restart

	return h, nil
}

// SetPacketProcessor sets a custom packet processor for this hunter.
// This should be called before Start() to enable custom packet handling.
func (h *Hunter) SetPacketProcessor(processor forwarding.PacketProcessor) {
	h.packetProcessor = processor
}

// Start begins hunter operation
func (h *Hunter) Start(ctx context.Context) error {
	h.ctx, h.cancel = context.WithCancel(ctx)
	defer h.cancel()

	logger.Info("Hunter starting", "hunter_id", h.config.HunterID)
	if h.config.ForwardMode == "events" {
		if err := h.initializeEventForwarding(); err != nil {
			return err
		}
		defer func() {
			h.eventMu.Lock()
			defer h.eventMu.Unlock()
			if h.eventRuntime != nil {
				h.eventRuntime.Close()
			}
			if h.eventDispatcher != nil {
				if err := h.eventDispatcher.Close(context.Background()); err != nil {
					logger.Error("Failed to close hunter event dispatcher", "error", err)
				}
			}
		}()
	}

	// Start system metrics collection (CPU/RAM monitoring)
	metricsCollector := sysmetrics.New()
	metricsCollector.Start(h.ctx)
	defer metricsCollector.Stop()

	// Periodically update stats with system metrics
	var lastCaptureLosses int64
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-h.ctx.Done():
				return
			case <-ticker.C:
				h.statsCollector.SetSystemMetrics(metricsCollector.Get())
				h.updateCaptureLossStats(&lastCaptureLosses)
				h.eventMu.RLock()
				dispatcher := h.eventDispatcher
				h.eventMu.RUnlock()
				if dispatcher != nil {
					h.sampleEventQueueLosses(dispatcher)
				}
			}
		}
	}()

	// Initialize application filter (always, for hot-reload support)
	// GPU acceleration is only enabled if VoIP filtering is enabled
	var gpuConfig *gpuaccel.GPUConfig
	if h.config.EnableVoIPFilter {
		gpuConfig = &gpuaccel.GPUConfig{
			Enabled:      true,
			DeviceID:     0,
			Backend:      h.config.GPUBackend,
			MaxBatchSize: h.config.GPUBatchSize,
			PinnedMemory: true,
			StreamCount:  4,
		}
	} else {
		// CPU-only mode (no GPU acceleration)
		gpuConfig = &gpuaccel.GPUConfig{
			Enabled: false,
		}
	}

	appFilter, err := NewApplicationFilter(gpuConfig)
	if err != nil {
		logger.Warn("Failed to initialize application filter, continuing without it", "error", err)
	} else {
		h.applicationFilter = appFilter

		// Apply no-filter policy if configured
		if h.config.NoFilterPolicy == "deny" {
			appFilter.SetNoFilterPolicy(NoFilterPolicyDeny)
		}

		logger.Info("Application filter initialized",
			"gpu_enabled", h.config.EnableVoIPFilter,
			"gpu_backend", h.config.GPUBackend,
			"batch_size", h.config.GPUBatchSize,
			"no_filter_policy", h.config.NoFilterPolicy)

		// Wire up application filter to filter manager for hot-reload
		h.filterManager.SetApplicationFilterUpdater(appFilter)
		logger.Info("Application filter hot-reload enabled (filters update without restart)")

		// Wire up ApplicationFilter to packet processor if it supports it
		// This allows VoIP packet processor to use the filter for proper multi-filter support
		if h.packetProcessor != nil {
			if receiver, ok := h.packetProcessor.(forwarding.ApplicationFilterReceiver); ok {
				receiver.SetApplicationFilter(appFilter)
				logger.Info("ApplicationFilter wired to packet processor")
			}
		}
	}
	defer func() {
		if h.applicationFilter != nil {
			h.applicationFilter.Close()
		}
	}()

	// Initialize DNS processor if tunneling detection is enabled
	if viper.GetBool("dns.detect_tunneling") {
		h.dnsProcessor = NewDNSProcessor(true)
		logger.Info("DNS tunneling detection enabled at hunter edge")
	}
	defer func() {
		if h.dnsProcessor != nil {
			h.dnsProcessor.Stop()
		}
	}()

	// Note: We use the capture manager created in New() constructor.
	// It was created with a background context, but that's fine - it will create
	// its own child context in Start() anyway. No need to recreate the manager here.

	// Start packet capture first (works independently of processor connection)
	filters := h.filterManager.GetFilters()
	if err := h.captureManager.Start(filters); err != nil {
		return fmt.Errorf("failed to start capture: %w", err)
	}
	defer h.captureManager.Stop()

	// Create and start connection manager (handles initial connect and reconnections)
	h.connectionManager = connection.New(
		connection.Config{
			ProcessorAddr:         h.config.ProcessorAddr,
			HunterID:              h.config.HunterID,
			Interfaces:            h.config.Interfaces,
			BufferSize:            h.config.BufferSize,
			BatchSize:             h.config.BatchSize,
			BatchTimeout:          h.config.BatchTimeout,
			VoIPMode:              h.config.VoIPMode,
			SupportedFilterTypes:  h.config.SupportedFilterTypes,
			RADIUSIngress:         !h.config.VoIPMode && h.applicationFilter != nil && h.packetProcessor == nil,
			TLSEnabled:            h.config.TLSEnabled,
			TLSCertFile:           h.config.TLSCertFile,
			TLSKeyFile:            h.config.TLSKeyFile,
			TLSCAFile:             h.config.TLSCAFile,
			TLSSkipVerify:         h.config.TLSSkipVerify,
			TLSServerNameOverride: h.config.TLSServerNameOverride,
			MaxReconnectAttempts:  0, // 0 = infinite
			ForwardMode:           h.config.ForwardMode, EventFallbackToPackets: h.config.EventFallbackToPackets,
			EventSpoolMaxBytes: h.config.EventSpoolMaxBytes, EventSpoolMaxAge: h.config.EventSpoolMaxAge,
		},
		h.statsCollector,
		h.filterManager,
		h.captureManager,
		h, // ForwardingManagerFactory interface
		h.handleFlowControl,
	)
	h.connectionManager.SetEventForwarder(h.eventForwarder)
	h.connectionManager.Start(h.ctx, &h.wg)
	if h.eventRuntime != nil {
		h.wg.Add(1)
		go func() {
			defer h.wg.Done()
			mode, err := h.connectionManager.WaitAcceptedMode(h.ctx)
			if err == nil && mode == management.ForwardingMode_FORWARDING_MODE_EVENTS {
				h.analyzeEvents()
			}
		}()
	}

	logger.Info("Hunter started successfully", "hunter_id", h.config.HunterID)

	// Wait for shutdown
	<-h.ctx.Done()

	// Wait for goroutines
	h.wg.Wait()

	logger.Info("Hunter stopped", "hunter_id", h.config.HunterID)
	return nil
}

func (h *Hunter) updateCaptureLossStats(previous *int64) {
	if h == nil || h.captureManager == nil || h.statsCollector == nil || previous == nil {
		return
	}
	buffer := h.captureManager.GetPacketBuffer()
	if buffer == nil {
		return
	}
	current := buffer.GetDropped() + buffer.GetSIPDropped()
	if current > *previous {
		h.statsCollector.IncrementCaptureLoss(uint64(current - *previous))
	}
	*previous = current
}

func (h *Hunter) sampleEventQueueLosses(dispatcher *events.Dispatcher) {
	if dispatcher == nil {
		return
	}
	h.eventLossMu.Lock()
	defer h.eventLossMu.Unlock()
	if dispatcher != h.eventLossSource {
		h.eventLossSource = dispatcher
		h.eventLossCount = 0
	}
	stats := dispatcher.Stats()
	current := stats.Dropped + stats.SinkDropped
	if current > h.eventLossCount {
		h.statsCollector.IncrementQueueLoss(current - h.eventLossCount)
	}
	h.eventLossCount = current
}

func (h *Hunter) initializeEventForwarding() error {
	spool, err := eventspool.Open(eventspool.Config{Directory: h.config.EventSpoolDir, MaxBytes: h.config.EventSpoolMaxBytes, MaxAge: h.config.EventSpoolMaxAge, Policy: eventspool.ExhaustionPolicy(h.config.EventSpoolExhaustionPolicy)})
	if err != nil {
		return fmt.Errorf("initialize hunter event spool: %w", err)
	}
	source, session, lastEvent, lastBatch, err := spool.RecoveryState()
	if err != nil {
		return err
	}
	var producer *events.Producer
	if session == "" {
		producer, err = events.NewLiveProducer(h.config.HunterID)
	} else {
		if source != h.config.HunterID {
			return fmt.Errorf("event spool belongs to node %q, configured node is %q", source, h.config.HunterID)
		}
		producer, err = events.ResumeLiveProducer(source, session, lastEvent)
	}
	if err != nil {
		return err
	}
	if err := spool.BindSessionPolicy(h.eventSessionPolicy(producer.SessionID())); err != nil {
		return err
	}
	h.eventSpool = spool
	forwarder, dispatcher, runtime, err := h.newEventPipeline(spool, producer, lastBatch+1)
	if err != nil {
		return err
	}
	h.eventForwarder, h.eventDispatcher, h.eventRuntime = forwarder, dispatcher, runtime
	return nil
}

func (h *Hunter) eventSessionPolicy(sessionID string) eventspool.SessionPolicy {
	deliveryProfile := h.config.EventDeliveryProfile
	if deliveryProfile == "" {
		deliveryProfile = "reliable"
	}
	return eventspool.SessionPolicy{
		Version: 1, SourceNodeID: h.config.HunterID, ProducerSessionID: sessionID,
		DeliveryProfile: deliveryProfile, IncludeHTTPHeaders: viper.GetBool("logs.include_http_headers"), SemanticRevision: 1,
	}
}

func (h *Hunter) newEventPipeline(spool *eventspool.Spool, producer *events.Producer, firstBatch uint64) (*eventforwarding.Client, *events.Dispatcher, *eventanalysis.Runtime, error) {
	profile := eventsv1.IngressProfile_INGRESS_PROFILE_RELIABLE
	if h.config.EventDeliveryProfile == "memory_only" {
		profile = eventsv1.IngressProfile_INGRESS_PROFILE_MEMORY_ONLY
	}
	forwarder, err := eventforwarding.New(eventforwarding.Config{SourceNodeID: h.config.HunterID, ProducerSessionID: producer.SessionID(), EventAPIMajor: 1, SemanticProfileRevision: 1, EventKinds: []eventsv1.EventKind{eventsv1.EventKind_EVENT_KIND_CONN, eventsv1.EventKind_EVENT_KIND_DNS, eventsv1.EventKind_EVENT_KIND_TLS, eventsv1.EventKind_EVENT_KIND_HTTP, eventsv1.EventKind_EVENT_KIND_SMTP, eventsv1.EventKind_EVENT_KIND_FILE_METADATA, eventsv1.EventKind_EVENT_KIND_RADIUS}, Profile: profile, OnLoss: func(kind eventsv1.LossKind, count uint64) {
		switch kind {
		case eventsv1.LossKind_LOSS_KIND_TRANSPORT:
			h.statsCollector.IncrementTransportLoss(count)
		case eventsv1.LossKind_LOSS_KIND_UNSUPPORTED_EVENT:
			h.statsCollector.IncrementUnsupportedKindLoss(count)
		}
	}}, spool)
	if err != nil {
		return nil, nil, nil, err
	}
	sink, err := eventforwarding.NewSink(forwarder, firstBatch, 1)
	if err != nil {
		return nil, nil, nil, err
	}
	dispatcher, err := events.NewDispatcher(events.Config{QueueSize: 1024, SinkQueueSize: 1024, DropPolicy: events.DropNew, Producer: producer})
	if err != nil {
		return nil, nil, nil, err
	}
	if err = dispatcher.Register(sink); err != nil {
		return nil, nil, nil, err
	}
	runtime, err := eventanalysis.New(eventanalysis.Config{Dispatcher: dispatcher, LiveExpiry: true, IncludeHTTPHeaders: viper.GetBool("logs.include_http_headers")})
	if err != nil {
		return nil, nil, nil, err
	}
	if err := dispatcher.Start(h.ctx); err != nil {
		runtime.Close()
		return nil, nil, nil, err
	}
	return forwarder, dispatcher, runtime, nil
}

func (h *Hunter) analyzeEvents() {
	for {
		select {
		case <-h.ctx.Done():
			return
		case info, ok := <-h.captureManager.GetPacketBuffer().Receive():
			if !ok {
				return
			}
			h.eventMu.RLock()
			h.statsCollector.IncrementCaptured()
			if h.packetProcessor != nil {
				if !h.packetProcessor.ProcessPacket(info) {
					h.eventMu.RUnlock()
					continue
				}
				h.statsCollector.IncrementMatched()
			} else if h.applicationFilter != nil {
				if matched, _ := h.applicationFilter.MatchPacketWithIDs(info.Packet); !matched {
					h.eventMu.RUnlock()
					continue
				}
				h.statsCollector.IncrementMatched()
			}
			err := h.eventRuntime.ObservePacket(eventanalysis.Source{NodeID: h.config.HunterID, CaptureSource: h.config.HunterID, InterfaceName: info.Interface, CaptureScope: events.CaptureScopeFiltered}, info)
			h.eventMu.RUnlock()
			if err != nil {
				h.statsCollector.IncrementDropped(1)
				h.statsCollector.IncrementAnalysisLoss(1)
				logger.Debug("Hunter event analysis skipped packet", "error", err)
			}
		}
	}
}

// ApplyPolicyChange creates a strict analysis-authority boundary around an
// effective live filter change. Old-session state is flushed and acknowledged
// before the new policy becomes visible, so one producer session never spans
// two filtering policies.
func (h *Hunter) ApplyPolicyChange(apply func() error) error {
	if apply == nil {
		return nil
	}
	if h.config.ForwardMode != "events" || h.eventRuntime == nil {
		return apply()
	}
	boundaryCtx, boundaryCancel := context.WithTimeout(h.ctx, 30*time.Second)
	defer boundaryCancel()
	if err := h.captureManager.Quiesce(boundaryCtx); err != nil {
		return fmt.Errorf("quiesce capture before policy change: %w", err)
	}
	if buffer := h.captureManager.GetPacketBuffer(); buffer != nil {
		emptySamples := 0
		for emptySamples < 5 {
			if len(buffer.Receive()) == 0 {
				emptySamples++
			} else {
				emptySamples = 0
			}
			select {
			case <-boundaryCtx.Done():
				if h.cancel != nil {
					h.cancel()
				}
				return fmt.Errorf("drain captured packets before policy change: %w", boundaryCtx.Err())
			case <-time.After(time.Millisecond):
			}
		}
	}
	h.eventMu.Lock()
	defer h.eventMu.Unlock()
	h.eventRuntime.Close()
	drainCtx := boundaryCtx
	if err := h.eventDispatcher.Close(drainCtx); err != nil {
		if h.cancel != nil {
			h.cancel()
		}
		return fmt.Errorf("flush event session before policy change: %w", err)
	}
	h.sampleEventQueueLosses(h.eventDispatcher)
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for h.eventSpool.Bytes() != 0 {
		select {
		case <-drainCtx.Done():
			if h.cancel != nil {
				h.cancel()
			}
			return fmt.Errorf("drain event spool before policy change: %w", drainCtx.Err())
		case <-ticker.C:
		}
	}
	producer, err := events.NewLiveProducer(h.config.HunterID)
	if err != nil {
		if h.cancel != nil {
			h.cancel()
		}
		return err
	}
	if err := h.eventSpool.BindSessionPolicy(h.eventSessionPolicy(producer.SessionID())); err != nil {
		if h.cancel != nil {
			h.cancel()
		}
		return err
	}
	forwarder, dispatcher, runtime, err := h.newEventPipeline(h.eventSpool, producer, 1)
	if err != nil {
		if h.cancel != nil {
			h.cancel()
		}
		return err
	}
	if err := apply(); err != nil {
		runtime.Close()
		_ = dispatcher.Close(context.Background())
		if h.cancel != nil {
			h.cancel()
		}
		return err
	}
	h.eventForwarder, h.eventDispatcher, h.eventRuntime = forwarder, dispatcher, runtime
	if h.connectionManager != nil {
		h.connectionManager.SetEventForwarder(forwarder)
		h.connectionManager.MarkDisconnected()
	}
	return nil
}

// CreateForwardingManager implements ForwardingManagerFactory interface
func (h *Hunter) CreateForwardingManager(connCtx context.Context, stream data.DataService_StreamPacketsClient) *forwarding.Manager {
	// Log queue depth on reconnection (shows buffered batches)
	queueDepth := len(h.batchQueue)
	if queueDepth > 0 {
		logger.Info("Reconnected with buffered batches",
			"queued_batches", queueDepth,
			"estimated_packets", queueDepth*h.config.BatchSize,
			"queue_capacity", h.batchQueueSize)
	}

	fwdMgr := forwarding.New(
		forwarding.Config{
			RADIUSPorts:        h.config.RADIUSPorts,
			RADIUSScope:        h.config.RADIUSScope,
			RADIUSOnly:         h.config.RADIUSOnly,
			RADIUSCorrelation:  h.config.RADIUSCorrelation,
			RADIUSMatcher:      h.config.RADIUSMatcher,
			HunterID:           h.config.HunterID,
			BatchSize:          h.config.BatchSize,
			BatchTimeout:       h.config.BatchTimeout,
			BufferSize:         h.config.BufferSize,
			DiskBufferEnabled:  h.config.DiskBufferEnabled,
			DiskBufferDir:      h.config.DiskBufferDir,
			DiskBufferMaxSize:  h.config.DiskBufferMaxSize,
			IncludeHTTPHeaders: viper.GetBool("logs.include_http_headers"),
			// BatchQueueSize omitted - we pass the queue directly
		},
		h.statsCollector,
		h.captureManager,
		connCtx,
		h.batchQueue, // Pass persistent queue (survives reconnections)
	)
	fwdMgr.SetStream(stream)
	if h.packetProcessor != nil {
		fwdMgr.SetPacketProcessor(h.packetProcessor)
	}
	if h.applicationFilter != nil {
		fwdMgr.SetApplicationFilter(h.applicationFilter)
	}
	if h.dnsProcessor != nil {
		fwdMgr.SetDNSMetadataProvider(h.dnsProcessor)
	}
	// Set disconnect callback to trigger reconnection on send failures
	fwdMgr.SetDisconnectCallback(func() {
		h.MarkDisconnected()
	})
	return fwdMgr
}

// handleFlowControl processes flow control signals from processor
// This is called by the connection manager and delegated to the forwarding manager
func (h *Hunter) handleFlowControl(ctrl *data.StreamControl) {
	if h.connectionManager != nil {
		if fwdMgr := h.connectionManager.GetForwardingManager(); fwdMgr != nil {
			fwdMgr.HandleFlowControl(ctrl)
		}
	}
}

// convertPacket converts capture.PacketInfo to the normalized pipeline format.
func (h *Hunter) convertPacket(pktInfo capture.PacketInfo) *pipeline.PacketEnvelope {
	pkt := pktInfo.Packet

	captureLen := 0
	originalLen := 0
	var packetData []byte
	timestamp := time.Now()
	hasCaptureTimestamp := false

	if pkt != nil {
		if pkt.Data() != nil {
			packetData = pkt.Data()
			captureLen = len(packetData)
		}
		if meta := pkt.Metadata(); meta != nil {
			captureLen = meta.CaptureLength
			originalLen = meta.Length
			if !meta.Timestamp.IsZero() {
				timestamp = meta.Timestamp
				hasCaptureTimestamp = true
			}
		}
	}
	if !hasCaptureTimestamp {
		logger.Debug("Packet has no capture timestamp; using forwarding time",
			"interface", pktInfo.Interface,
			"timestamp_source", "forwarding_fallback")
	}

	// Packet field conversions (safe: lengths are from pcap, LinkType is enum < 300)
	return &pipeline.PacketEnvelope{
		Data:           packetData,
		CaptureTime:    timestamp,
		CaptureLength:  captureLen,
		OriginalLength: originalLen,
		LinkType:       pktInfo.LinkType,
		Source: pipeline.SourceProvenance{
			Kind:          pipeline.SourceLiveCapture,
			NodeID:        h.config.HunterID,
			InterfaceName: pktInfo.Interface,
		},
		// TODO: Add metadata extraction (SIP, RTP, etc.)
	}
}

// ForwardPacketWithMetadata forwards a packet with embedded metadata to the processor
// This is used by TCP SIP handler to forward reassembled packets with extracted metadata
func (h *Hunter) ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType) error {
	return h.ForwardPacketWithFilterProvenance(packet, metadata, interfaceName, linkType, nil, nil)
}

// ForwardPacketWithFilterProvenance forwards a packet while retaining the
// origin of each filter match for downstream LI authorization.
func (h *Hunter) ForwardPacketWithFilterProvenance(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType, directFilterIDs, inheritedFilterIDs []string) error {
	if packet == nil {
		return fmt.Errorf("cannot forward nil packet")
	}

	if h.connectionManager == nil {
		return fmt.Errorf("connection manager not initialized")
	}

	forwardingManager := h.connectionManager.GetForwardingManager()
	if forwardingManager == nil {
		return fmt.Errorf("forwarding manager not initialized")
	}

	captureLen := 0
	originalLen := 0
	var packetData []byte
	timestamp := time.Now()
	hasCaptureTimestamp := false

	if packet.Data() != nil {
		packetData = packet.Data()
		captureLen = len(packetData)
	}
	if meta := packet.Metadata(); meta != nil {
		captureLen = meta.CaptureLength
		originalLen = meta.Length
		if !meta.Timestamp.IsZero() {
			timestamp = meta.Timestamp
			hasCaptureTimestamp = true
		}
	}
	if !hasCaptureTimestamp {
		logger.Debug("Packet has no capture timestamp; using forwarding time",
			"interface", interfaceName,
			"timestamp_source", "forwarding_fallback")
	}

	encodedMetadata, err := grpcadapter.MetadataFromProto(metadata)
	if err != nil {
		return fmt.Errorf("normalize packet metadata: %w", err)
	}
	stages := pipeline.StageProvenance(0).With(pipeline.StageAnalyzed)
	if len(directFilterIDs) > 0 || len(inheritedFilterIDs) > 0 {
		stages = stages.With(pipeline.StageFiltered)
	}

	// Use the provided link type from the capture source (preserves Linux cooked, raw IP, etc.)
	envelope := &pipeline.PacketEnvelope{
		Data:           packetData,
		CaptureTime:    timestamp,
		CaptureLength:  captureLen,
		OriginalLength: originalLen,
		LinkType:       linkType,
		Source: pipeline.SourceProvenance{
			Kind:          pipeline.SourceLiveCapture,
			NodeID:        h.config.HunterID,
			InterfaceName: interfaceName,
		},
		Stages:                    stages,
		Metadata:                  encodedMetadata,
		DirectMatchedFilterIDs:    append([]string(nil), directFilterIDs...),
		InheritedMatchedFilterIDs: append([]string(nil), inheritedFilterIDs...),
		MatchedFilterIDs:          stableFilterIDUnion(directFilterIDs, inheritedFilterIDs),
	}

	// Add to current batch and send if full
	if forwardingManager.AddPacketToBatch(envelope) {
		forwardingManager.SendBatch()
	}

	return nil
}

// MarkDisconnected marks the hunter as disconnected and triggers reconnection
// This method is exported so the filter manager can call it when connection is lost
func (h *Hunter) MarkDisconnected() {
	if h.connectionManager != nil {
		h.connectionManager.MarkDisconnected()
	}
}

// GetStatsCollector returns the statistics collector
func (h *Hunter) GetStatsCollector() *stats.Collector {
	return h.statsCollector
}

// GetStatsValues returns current statistics as plain uint64 values
func (h *Hunter) GetStatsValues() (captured, matched, forwarded, dropped, bufferBytes uint64) {
	return h.statsCollector.GetAll()
}
