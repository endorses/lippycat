// Package source - LocalSource Implementation
//
// LocalSource implements the PacketSource interface for capturing packets
// from local network interfaces. It is used for standalone "tap" mode where
// the processor captures packets directly without remote hunters.
//
// Architecture:
//
//	Interface → gopacket → LocalSource.captureLoop() → batching → Batches() channel → Processor
//
// The source reuses the capture package for packet capture and optionally
// supports application-layer filtering via ApplicationFilter (GPU/CPU).
package source

import (
	"bytes"
	"context"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/capture/pcaptypes"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/grpcadapter"
	"github.com/endorses/lippycat/internal/pkg/protocolmeta"
	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/spf13/viper"
)

// ApplicationFilter provides application-layer packet filtering.
// This interface is satisfied by hunter.ApplicationFilter.
type ApplicationFilter interface {
	// MatchPacket checks if a packet matches any filter.
	MatchPacket(packet gopacket.Packet) bool

	// MatchPacketWithIDs checks if a packet matches any filters and returns the matched filter IDs.
	// Used for LI correlation to map matched filters back to intercept task XIDs.
	MatchPacketWithIDs(packet gopacket.Packet) (matched bool, filterIDs []string)
	MatchPacketLevelWithIDs(packet gopacket.Packet) (matched bool, filterIDs []string)
}

// VoIPProcessor is an alias for voipprocessor.SourceAdapter.
// It provides VoIP packet processing for SIP/RTP detection.
type VoIPProcessor = *voipprocessor.SourceAdapter

// InjectedPacket represents a packet with pre-attached metadata
// for injection into the batch processing pipeline.
// Used by TCP SIP handlers to inject reassembled packets with metadata.
type InjectedPacket struct {
	PacketInfo capture.PacketInfo
	Metadata   *data.PacketMetadata
	// AfterProcess runs after the packet's batch has traversed the processor
	// pipeline. It is used for lifecycle transitions that must follow the final
	// packet's processing and synchronous output writes.
	AfterProcess func()
}

// TCPAssembler handles TCP packets for stream reassembly.
// This interface decouples LocalSource from specific TCP reassembly implementations.
type TCPAssembler interface {
	// AssemblePacket processes a TCP packet for stream reconstruction.
	// Returns true if the packet was handled (don't process further).
	AssemblePacket(pktInfo capture.PacketInfo) bool
}

// cachedFilterIDs stores filter IDs with a timestamp for TTL-based cleanup.
type cachedFilterIDs struct {
	filterIDs  []string
	storedAt   time.Time
	generation uint64
}

const defaultCallFilterCacheSize = 10000

type callFilterCache struct {
	mu             sync.Mutex
	entries        map[string]cachedFilterIDs
	order          []cachedFilterOrder
	maxSize        int
	nextGeneration uint64
}

type cachedFilterOrder struct {
	key        string
	generation uint64
}

func newCallFilterCache(maxSize int) *callFilterCache {
	if maxSize <= 0 {
		maxSize = defaultCallFilterCacheSize
	}
	return &callFilterCache{entries: make(map[string]cachedFilterIDs), maxSize: maxSize}
}

func (c *callFilterCache) Store(key string, value cachedFilterIDs) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.entries[key]; !exists {
		if len(c.entries) >= c.maxSize {
			for len(c.order) > 0 {
				oldest := c.order[0]
				c.order = c.order[1:]
				if live, ok := c.entries[oldest.key]; ok && live.generation == oldest.generation {
					delete(c.entries, oldest.key)
					break
				}
			}
		}
		c.nextGeneration++
		value.generation = c.nextGeneration
		c.order = append(c.order, cachedFilterOrder{key: key, generation: value.generation})
	} else {
		value.generation = c.entries[key].generation
	}
	value.filterIDs = append([]string(nil), value.filterIDs...)
	c.entries[key] = value
}

func (c *callFilterCache) Load(key string) (cachedFilterIDs, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	value, ok := c.entries[key]
	value.filterIDs = append([]string(nil), value.filterIDs...)
	return value, ok
}

func (c *callFilterCache) Delete(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, key)
}

func (c *callFilterCache) DeleteExpired(now time.Time, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if now.Sub(entry.storedAt) > ttl {
			delete(c.entries, key)
		}
	}
}

func (c *callFilterCache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// cachedFilterIDsForCall returns filter IDs inherited from exactly one call.
// Call attribution must be resolved before this helper is called; accepting a
// candidate slice here would make it too easy to reintroduce cross-call unions.
func (s *LocalSource) cachedFilterIDsForCall(callID string) []string {
	if callID == "" {
		return nil
	}
	cached, ok := s.callFilterCache.Load(callID)
	if !ok {
		return nil
	}
	return composeFilterIDs(cached.filterIDs, nil)
}

// composeFilterIDs returns the stable, deduplicated union of direct packet
// matches followed by IDs inherited from one authoritatively selected call.
func composeFilterIDs(direct, inherited []string) []string {
	filterIDs := make([]string, 0, len(direct)+len(inherited))
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
			filterIDs = append(filterIDs, id)
		}
	}
	return filterIDs
}

const credibleSIPStartLineLimit = 256

// hasCredibleSIPStartLine conservatively recognizes a bounded SIP request or
// response start line without converting packet data to strings or allocating.
func hasCredibleSIPStartLine(packet gopacket.Packet) bool {
	if packet == nil || packet.TransportLayer() == nil {
		return false
	}
	payload := packet.TransportLayer().LayerPayload()
	if len(payload) == 0 {
		return false
	}
	if len(payload) > credibleSIPStartLineLimit {
		payload = payload[:credibleSIPStartLineLimit]
	}
	lineEnd := bytes.IndexByte(payload, '\n')
	if lineEnd < 0 {
		return false
	}
	line := payload[:lineEnd]
	if len(line) > 0 && line[len(line)-1] == '\r' {
		line = line[:len(line)-1]
	}
	if bytes.HasPrefix(line, []byte("SIP/2.0 ")) {
		status := line[len("SIP/2.0 "):]
		return len(status) >= 3 && status[0] >= '1' && status[0] <= '6' &&
			status[1] >= '0' && status[1] <= '9' && status[2] >= '0' && status[2] <= '9' &&
			(len(status) == 3 || status[3] == ' ')
	}

	space := bytes.IndexByte(line, ' ')
	if space <= 0 || !credibleSIPMethod(line[:space]) {
		return false
	}
	rest := line[space+1:]
	version := bytes.LastIndex(rest, []byte(" SIP/2.0"))
	return version > 0 && version+len(" SIP/2.0") == len(rest) &&
		bytes.IndexByte(rest[:version], ' ') < 0
}

func credibleSIPMethod(method []byte) bool {
	for _, known := range [...][]byte{
		[]byte("ACK"), []byte("BYE"), []byte("CANCEL"), []byte("INFO"),
		[]byte("INVITE"), []byte("MESSAGE"), []byte("NOTIFY"), []byte("OPTIONS"),
		[]byte("PRACK"), []byte("PUBLISH"), []byte("REFER"), []byte("REGISTER"),
		[]byte("SUBSCRIBE"), []byte("UPDATE"),
	} {
		if bytes.Equal(method, known) {
			return true
		}
	}
	return false
}

// LocalSource captures packets from local network interfaces.
// It implements the PacketSource interface for standalone capture mode.
type LocalSource struct {
	// Configuration
	config LocalSourceConfig

	// Capture state (packetBuffer is atomic: Stats() reads it concurrently with Start())
	packetBuffer  atomic.Pointer[capture.PacketBuffer]
	captureCtx    context.Context
	captureCancel context.CancelFunc
	captureDone   chan struct{}

	// Batching
	batchMu      sync.Mutex
	currentBatch []*pipeline.PacketEnvelope
	// currentBatchAfterProcess is protected by batchMu and moves atomically
	// with currentBatch into the emitted PacketBatch.
	currentBatchAfterProcess []func()
	batchSeq                 uint64

	// Packet batch channel for processing
	batches chan *PacketBatch

	// Optional filtering
	appFilter       ApplicationFilter
	selectionPolicy callregistry.SelectionPolicy

	// Optional VoIP processing for SIP/RTP metadata extraction
	voipProcessor VoIPProcessor

	// Optional DNS processing for DNS parsing and tunneling detection
	dnsProcessor DNSProcessor

	// Optional TCP packet injection channel for TCP SIP reassembly
	// When set, TCP SIP packets with metadata are received from this channel
	tcpInjectionChan <-chan InjectedPacket

	// Optional TCP assembler for TCP stream reassembly (e.g., TCP SIP)
	// When set, TCP packets are routed to the assembler instead of direct processing
	tcpAssembler TCPAssembler

	// Stats tracking
	stats *AtomicStats

	// LI: CallID → filterIDs cache for RTP packets
	// SIP packets that match LI filters store their CallID→filterIDs mapping,
	// so RTP packets for the same call can inherit the filter IDs.
	callFilterCache *callFilterCache

	// Lifecycle
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// State
	started bool
	mu      sync.Mutex
}

// LocalSourceConfig contains configuration for LocalSource.
type LocalSourceConfig struct {
	// Interfaces to capture from (e.g., "eth0", "eth0,eth1")
	Interfaces []string

	// BPFFilter is the initial BPF filter expression
	BPFFilter string

	// BatchSize is the number of packets per batch (default: 100)
	BatchSize int

	// BatchTimeout is the maximum time to wait before sending a partial batch
	BatchTimeout time.Duration

	// BufferSize is the packet buffer size (default: 10000)
	BufferSize int

	// BatchBuffer is the channel buffer size for batches (default: 1000)
	BatchBuffer int

	// ProcessorID is the processor's ID, used for virtual hunter ID generation.
	// When set, SourceID() returns "{ProcessorID}-local" instead of "local".
	ProcessorID string

	// ProtocolMode indicates the capture protocol mode (e.g., "generic", "voip", "dns", "email", "http", "tls").
	// Used for TUI display and filter validation.
	ProtocolMode string

	// IncludeHTTPHeaders controls whether protocol enrichment retains complete
	// HTTP header maps. Resolve this once during command composition; packet
	// processing must not perform configuration lookups on the hot path.
	IncludeHTTPHeaders bool

	// CallFilterCacheSize bounds retained selected-call filter attribution.
	CallFilterCacheSize int
}

// DefaultLocalSourceConfig returns a LocalSourceConfig with sensible defaults.
func DefaultLocalSourceConfig() LocalSourceConfig {
	return LocalSourceConfig{
		BatchSize:           100,
		BatchTimeout:        100 * time.Millisecond,
		BufferSize:          10000,
		BatchBuffer:         1000,
		CallFilterCacheSize: defaultCallFilterCacheSize,
	}
}

// NewLocalSource creates a new LocalSource for local packet capture.
func NewLocalSource(cfg LocalSourceConfig) *LocalSource {
	// Apply defaults
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 100
	}
	if cfg.BatchTimeout == 0 {
		cfg.BatchTimeout = 100 * time.Millisecond
	}
	if cfg.BufferSize == 0 {
		cfg.BufferSize = 10000
	}
	if cfg.BatchBuffer == 0 {
		cfg.BatchBuffer = 1000
	}
	if cfg.CallFilterCacheSize <= 0 {
		cfg.CallFilterCacheSize = defaultCallFilterCacheSize
	}

	return &LocalSource{
		config:          cfg,
		currentBatch:    make([]*pipeline.PacketEnvelope, 0, cfg.BatchSize),
		batches:         make(chan *PacketBatch, cfg.BatchBuffer),
		stats:           NewAtomicStats(),
		callFilterCache: newCallFilterCache(cfg.CallFilterCacheSize),
		selectionPolicy: callregistry.StickySelectionPolicy{},
	}
}

// SetApplicationFilter sets an optional application-layer filter.
// Packets not matching the filter will be dropped before batching.
// Pass nil to disable filtering (all packets pass through).
func (s *LocalSource) SetApplicationFilter(filter ApplicationFilter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appFilter = filter
}

// SetSelectionPolicy sets the topology's call-selection inheritance policy.
func (s *LocalSource) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	if policy == nil {
		policy = callregistry.StickySelectionPolicy{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.selectionPolicy = policy
}

// SetVoIPProcessor sets an optional VoIP processor for SIP/RTP detection.
// When set, packets are processed for VoIP metadata which is attached to
// the CapturedPacket.Metadata field for downstream per-call PCAP writing.
// Pass nil to disable VoIP processing.
func (s *LocalSource) SetVoIPProcessor(processor VoIPProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.voipProcessor = processor
	if processor != nil {
		processor.AddLifecycleObserver(s)
	}
}

// OnCallStarted implements callregistry.LifecycleObserver. A reused Call-ID
// must earn a fresh selection decision rather than inheriting stale filter IDs.
func (s *LocalSource) OnCallStarted(call callregistry.Call) {
	s.callFilterCache.Delete(call.CallID)
}

// OnCallEnded removes selection attribution at every registry end boundary.
func (s *LocalSource) OnCallEnded(call callregistry.Call, _ callregistry.EndReason) {
	s.callFilterCache.Delete(call.CallID)
}

// CleanupCallPorts clears all call-scoped attribution owned by the local
// capture path at the processor's shared finalization boundary.
func (s *LocalSource) CleanupCallPorts(callID string) {
	s.callFilterCache.Delete(callID)
	s.mu.Lock()
	processor := s.voipProcessor
	s.mu.Unlock()
	if processor != nil {
		processor.CleanupCallPorts(callID)
	}
}

// GetVoIPProcessor returns the VoIP processor if set.
// Returns nil if no VoIP processor is configured.
func (s *LocalSource) GetVoIPProcessor() VoIPProcessor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.voipProcessor
}

// SetDNSProcessor sets an optional DNS processor for DNS parsing and tunneling detection.
// When set, DNS packets are parsed and metadata is attached to the CapturedPacket.
// Pass nil to disable DNS processing.
func (s *LocalSource) SetDNSProcessor(processor DNSProcessor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dnsProcessor = processor
}

// GetDNSProcessor returns the DNS processor if set.
// Returns nil if no DNS processor is configured.
func (s *LocalSource) GetDNSProcessor() DNSProcessor {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dnsProcessor
}

// SetTCPInjectionChannel sets a channel for receiving TCP packets with pre-attached metadata.
// This is used for TCP SIP reassembly where complete SIP messages spanning multiple TCP
// segments need to be processed and injected into the batch with proper metadata.
// The channel should send InjectedPacket structs with PacketInfo and Metadata already set.
func (s *LocalSource) SetTCPInjectionChannel(ch <-chan InjectedPacket) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpInjectionChan = ch
}

// SetTCPAssembler sets a TCP assembler for TCP stream reassembly.
// When set, TCP packets are routed to the assembler instead of direct processing.
// This is used for TCP SIP reassembly where SIP messages span multiple TCP segments.
// The assembler should buffer packets and call back with complete messages.
func (s *LocalSource) SetTCPAssembler(assembler TCPAssembler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tcpAssembler = assembler
}

// Start begins packet capture. Blocks until ctx is cancelled.
func (s *LocalSource) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.mu.Unlock()

	logger.Info("LocalSource starting",
		"interfaces", s.config.Interfaces,
		"bpf_filter", s.config.BPFFilter,
		"batch_size", s.config.BatchSize)

	// Start system metrics collection (CPU/RAM monitoring)
	metricsCollector := sysmetrics.New()
	metricsCollector.Start(s.ctx)

	// Periodically update stats with system metrics
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer metricsCollector.Stop()
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.stats.SetSystemMetrics(metricsCollector.Get())
			}
		}
	}()

	// Start periodic cleanup of callFilterCache (remove entries older than 5 minutes)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				return
			case <-ticker.C:
				s.callFilterCache.DeleteExpired(time.Now(), 5*time.Minute)
			}
		}
	}()

	// Create packet buffer
	s.packetBuffer.Store(capture.NewPacketBuffer(s.ctx, s.config.BufferSize))

	// Create capture context (separate from main context for restart support)
	s.captureCtx, s.captureCancel = context.WithCancel(s.ctx)
	s.captureDone = make(chan struct{})

	// Start capture goroutines
	s.wg.Add(1)
	go s.capturePackets(s.captureCtx, s.config.BPFFilter, s.captureDone)

	// Start batching goroutine
	s.wg.Add(1)
	go s.batchingLoop()

	// Wait for context cancellation
	<-s.ctx.Done()

	// Stop capture
	if s.captureCancel != nil {
		s.captureCancel()
	}

	// Close packet buffer to signal batchingLoop
	if pb := s.packetBuffer.Load(); pb != nil {
		pb.Close()
	}

	// Wait for goroutines
	s.wg.Wait()

	// Close batches channel
	close(s.batches)

	logger.Info("LocalSource stopped",
		"packets_captured", s.stats.packetsCaptured.Load(),
		"packets_forwarded", s.stats.packetsForwarded.Load(),
		"packets_dropped", s.droppedTotal())

	return nil
}

// capturePackets starts the gopacket capture loop.
func (s *LocalSource) capturePackets(ctx context.Context, filter string, done chan<- struct{}) {
	defer s.wg.Done()
	defer close(done)

	// Build interface list
	var devices []pcaptypes.PcapInterface
	for _, iface := range s.config.Interfaces {
		for _, device := range strings.Split(iface, ",") {
			device = strings.TrimSpace(device)
			if device != "" {
				devices = append(devices, pcaptypes.CreateLiveInterface(device))
			}
		}
	}

	if len(devices) == 0 {
		logger.Error("LocalSource: no interfaces configured")
		return
	}

	// Use InitWithBuffer to capture packets into our buffer
	// nil processor means we own the buffer and read from it externally
	capture.InitWithBuffer(ctx, devices, filter, s.packetBuffer.Load(), nil, nil)
}

// batchingLoop reads from packet buffer, applies filtering, and creates batches.
// detectionWorkerChanBuffer is the per-worker routed-packet channel depth.
const detectionWorkerChanBuffer = 4096

// batchingLoop drains the capture buffer and dispatches packets to detection
// workers, lifting the single-goroutine ceiling that otherwise caps packet
// processing to one CPU core — the bottleneck under a high-rate mirror.
//
// Packets are routed to a worker by a direction-independent flow hash, so every
// packet of a flow (and thus a call leg) is handled by the same worker. This
// keeps per-flow detector state (ctx.Flow: LastSeen/Protocols/State) single-
// goroutine, which is required because that state is not internally locked. The
// cross-flow shared state IS thread-safe (DetectionCache/FlowTracker RWMutex,
// SIPSignature.knownSIPIPPairs sync.Map), so distinct flows parallelise safely.
//
// The dispatcher only hashes per packet (cheap); the expensive detection and
// filtering run in the workers. Worker count is processor.detection_workers
// (default NumCPU-2); a value of 1 keeps the original single-goroutine path.
func (s *LocalSource) batchingLoop() {
	defer s.wg.Done()

	packetBuffer := s.packetBuffer.Load()

	numWorkers := getDetectionWorkerCount()
	if numWorkers <= 1 {
		s.batchingWorker(packetBuffer.Receive())
		return
	}

	logger.Info("LocalSource starting detection workers", "workers", numWorkers)
	workerChans := make([]chan capture.PacketInfo, numWorkers)
	var wg sync.WaitGroup
	for i := range workerChans {
		workerChans[i] = make(chan capture.PacketInfo, detectionWorkerChanBuffer)
		wg.Add(1)
		go func(in <-chan capture.PacketInfo, receiveTCPInjection bool) {
			defer wg.Done()
			s.batchingWorkerWithInjection(in, receiveTCPInjection)
		}(workerChans[i], i == 0)
	}

	closeWorkers := func() {
		for _, ch := range workerChans {
			close(ch)
		}
		wg.Wait()
	}

	for pktInfo := range packetBuffer.Receive() {
		idx := 0
		if pkt := pktInfo.Packet; pkt != nil {
			netLayer := pkt.NetworkLayer()
			transLayer := pkt.TransportLayer()
			if netLayer != nil && transLayer != nil {
				idx = pipeline.FlowShard(netLayer.NetworkFlow(), transLayer.TransportFlow(), numWorkers)
			}
		}
		select {
		case workerChans[idx] <- pktInfo:
		case <-s.ctx.Done():
			closeWorkers()
			return
		}
	}

	// Capture buffer closed: close worker channels so workers drain and exit.
	closeWorkers()
}

// getDetectionWorkerCount returns the number of concurrent detection/batching
// workers. Configurable via voip processor.detection_workers; defaults to
// NumCPU-2 (leaving headroom for the capture goroutine and downstream stages),
// minimum 1.
func getDetectionWorkerCount() int {
	if viper.IsSet("processor.detection_workers") {
		if n := viper.GetInt("processor.detection_workers"); n >= 1 {
			return n
		}
	}
	n := runtime.NumCPU() - 2
	if n < 1 {
		n = 1
	}
	return n
}

// batchingWorker runs one detection/batching loop, consuming packets pre-routed
// to it by flow (see batchingLoop). Because every packet of a flow arrives on the
// same worker, per-flow detector state stays single-goroutine and in order.
// Cross-worker shared state is concurrency-safe: the detector's cache/flow-tracker
// (RWMutex) and SIP IP-pair map (sync.Map), callFilterCache (sync.Map),
// currentBatch (batchMu), and stats (atomic). TCP assembler concurrency is
// handled by the reassembly engine's flow shards.
func (s *LocalSource) batchingWorker(input <-chan capture.PacketInfo) {
	s.batchingWorkerWithInjection(input, true)
}

// batchingWorkerWithInjection processes one flow-routed ingress queue. Exactly
// one worker receives reassembled TCP injections: multiple consumers would
// preserve channel receive order but could finish filtering and append to the
// shared batch out of order for consecutive messages on the same TCP flow.
func (s *LocalSource) batchingWorkerWithInjection(input <-chan capture.PacketInfo, receiveTCPInjection bool) {
	ticker := time.NewTicker(s.config.BatchTimeout)
	defer ticker.Stop()

	// Get TCP injection channel and assembler (may be nil - nil channels block forever in select)
	s.mu.Lock()
	tcpChan := s.tcpInjectionChan
	tcpAssembler := s.tcpAssembler
	s.mu.Unlock()
	if !receiveTCPInjection {
		tcpChan = nil
	}

	for {
		select {
		case <-s.ctx.Done():
			// Send remaining batch before shutdown
			s.sendBatch()
			return

		case injectedPkt := <-tcpChan:
			// TCP SIP packet injected from TCP reassembly handler
			// These packets already have metadata attached, so skip VoIP/DNS processing
			s.stats.AddCaptured()

			// Convert to protobuf format
			pbPkt := convertPacketInfo(injectedPkt.PacketInfo)

			// Attach the pre-computed metadata from TCP handler
			pbPkt.Metadata = injectedPkt.Metadata

			// Apply filter to TCP SIP packets (same rules as UDP VoIP)
			s.mu.Lock()
			tcpFilter := s.appFilter
			selectionPolicy := s.selectionPolicy
			s.mu.Unlock()

			if tcpFilter != nil {
				matched, directIDs := tcpFilter.MatchPacketWithIDs(injectedPkt.PacketInfo.Packet)
				callID := ""
				if pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil {
					callID = pbPkt.Metadata.Sip.CallId
				}
				inheritedIDs := s.cachedFilterIDsForCall(callID)
				selected := selectionPolicy.Select(callregistry.SelectionInput{
					FilterConfigured:   true,
					DirectMatch:        matched,
					PreviouslySelected: len(inheritedIDs) > 0,
				})
				if !selected {
					if injectedPkt.AfterProcess != nil {
						injectedPkt.AfterProcess()
					}
					continue
				}
				filterIDs := composeFilterIDs(directIDs, inheritedIDs)
				if matched && len(directIDs) > 0 {
					// Cache SIP CallID → filterIDs for RTP correlation
					if pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil && pbPkt.Metadata.Rtp == nil {
						callID := pbPkt.Metadata.Sip.CallId
						if callID != "" {
							cachedCallIDs := s.cachedFilterIDsForCall(callID)
							s.callFilterCache.Store(callID, cachedFilterIDs{
								filterIDs: composeFilterIDs(cachedCallIDs, directIDs),
								storedAt:  time.Now(),
							})
						}
					}
				}
				if !matched && len(filterIDs) == 0 {
					if injectedPkt.AfterProcess != nil {
						injectedPkt.AfterProcess()
					}
					continue
				}
				pbPkt.MatchedFilterIds = filterIDs
				pbPkt.DirectMatchedFilterIds = composeFilterIDs(directIDs, nil)
				pbPkt.InheritedMatchedFilterIds = composeFilterIDs(inheritedIDs, nil)
			}

			// Add to batch
			envelope, err := s.normalizeLocalPacket(pbPkt)
			if err != nil {
				s.stats.AddDropped(1)
				logger.Error("Failed to normalize injected local packet", "error", err)
				if injectedPkt.AfterProcess != nil {
					injectedPkt.AfterProcess()
				}
				continue
			}
			s.stats.AddForwarded(uint64(len(pbPkt.Data)))
			s.batchMu.Lock()
			s.currentBatch = append(s.currentBatch, envelope)
			if injectedPkt.AfterProcess != nil {
				s.currentBatchAfterProcess = append(s.currentBatchAfterProcess, injectedPkt.AfterProcess)
			}
			batchLen := len(s.currentBatch)
			s.batchMu.Unlock()

			// Send if batch is full
			if batchLen >= s.config.BatchSize {
				s.sendBatch()
			}

		case pktInfo, ok := <-input:
			if !ok {
				// Channel closed
				s.sendBatch()
				return
			}

			// Count ALL packets received from buffer (before filtering)
			s.stats.AddCaptured()

			// Route TCP packets to assembler if set (for TCP SIP reassembly)
			// TCP packets will come back via tcpInjectionChan when SIP messages are complete
			if tcpAssembler != nil && pktInfo.Packet != nil && pktInfo.Packet.TransportLayer() != nil {
				if _, isTCP := pktInfo.Packet.TransportLayer().(*layers.TCP); isTCP {
					handled := tcpAssembler.AssemblePacket(pktInfo)
					if handled {
						// TCP packet handled by assembler, don't process further
						continue
					}
				}
			}

			s.mu.Lock()
			filter := s.appFilter
			voipProc := s.voipProcessor
			dnsProc := s.dnsProcessor
			selectionPolicy := s.selectionPolicy
			s.mu.Unlock()
			filterConfigured := filter != nil

			// Convert to protobuf format first
			pbPkt := convertPacketInfo(pktInfo)
			pbPkt.Metadata = protocolmeta.Enrich(pktInfo.Packet, pbPkt.Metadata, s.config.IncludeHTTPHeaders)

			// Apply VoIP processing BEFORE filtering
			// This ensures RTP packets associated with calls are detected
			// before the application filter can drop them
			// The VoIP processor already evaluates the application filter while
			// detecting SIP, so reuse its verdict rather than matching again.
			var isVoIPPacket bool
			var voipCallID string
			var mediaResolution callregistry.MediaResolution
			var reuseVerdict, reuseMatched bool
			var reuseIDs []string
			if voipProc != nil {
				if result := voipProc.Process(pktInfo.Packet); result != nil {
					voipCallID = result.GetCallID()
					mediaResolution = result.GetMediaResolution()
					reuseVerdict, reuseMatched, reuseIDs = result.FilterVerdict()
					if result.IsVoIPPacket() {
						pbPkt.Metadata = result.GetMetadata()
						isVoIPPacket = true
					}
				}
			}
			// Apply DNS processing if enabled and not a VoIP packet
			// DNS packets are not VoIP, so skip if already identified as VoIP
			if dnsProc != nil && !isVoIPPacket {
				if dnsMetadata := dnsProc.ProcessPacket(pktInfo.Packet); dnsMetadata != nil {
					// Create metadata if nil, then set DNS field
					if pbPkt.Metadata == nil {
						pbPkt.Metadata = &data.PacketMetadata{}
					}
					pbPkt.Metadata.Dns = grpcadapter.DNSMetadataToProto(dnsMetadata)
				}
			}

			// Apply application filter if set
			// Both VoIP and non-VoIP packets are subject to filter drop decisions.
			// Special case: RTP packets that don't directly match can pass if their
			// CallID is in the callFilterCache (associated with a matched SIP call).
			var matchedFilterIDs []string
			var directMatchedFilterIDs []string
			var inheritedMatchedFilterIDs []string
			if filterConfigured && !isVoIPPacket {
				// Non-VoIP: filter decides pass/drop
				matched, filterIDs := reuseMatched, reuseIDs
				if !reuseVerdict {
					matched, filterIDs = filter.MatchPacketWithIDs(pktInfo.Packet)
				}
				if !matched {
					continue
				}
				matchedFilterIDs = filterIDs
				directMatchedFilterIDs = composeFilterIDs(filterIDs, nil)
			} else if filterConfigured && isVoIPPacket {
				// Classified media is restricted to packet-level filters. SIP can
				// reuse the processor verdict; conservative start-line recognition
				// handles VoIP results lacking protocol metadata.
				var matched bool
				var directFilterIDs []string
				switch {
				case pbPkt.Metadata != nil && pbPkt.Metadata.Rtp != nil:
					matched, directFilterIDs = filter.MatchPacketLevelWithIDs(pktInfo.Packet)
				case pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil && reuseVerdict:
					matched, directFilterIDs = reuseMatched, reuseIDs
				case pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil:
					matched, directFilterIDs = filter.MatchPacketWithIDs(pktInfo.Packet)
				case hasCredibleSIPStartLine(pktInfo.Packet):
					matched, directFilterIDs = filter.MatchPacketWithIDs(pktInfo.Packet)
				default:
					matched, directFilterIDs = filter.MatchPacketLevelWithIDs(pktInfo.Packet)
				}

				isMedia := pbPkt.Metadata != nil && pbPkt.Metadata.Rtp != nil
				if isMedia {
					// RTP may inherit identity selection only after exact-endpoint
					// resolution proves one authoritative owner. In particular, do
					// not reconstruct ownership from metadata or candidate lists.
					if mediaResolution.Status == callregistry.MediaResolved {
						voipCallID = mediaResolution.CallID
					} else {
						voipCallID = ""
						s.stats.AddIdentityInheritanceSuppressed()
					}
				} else if pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil && voipCallID == "" {
					voipCallID = pbPkt.Metadata.Sip.CallId
				}
				inheritedFilterIDs := s.cachedFilterIDsForCall(voipCallID)
				selected := selectionPolicy.Select(callregistry.SelectionInput{
					FilterConfigured:   filterConfigured,
					DirectMatch:        matched,
					PreviouslySelected: len(inheritedFilterIDs) > 0,
				})
				if !selected {
					continue
				}
				matchedFilterIDs = composeFilterIDs(directFilterIDs, inheritedFilterIDs)
				directMatchedFilterIDs = composeFilterIDs(directFilterIDs, nil)
				inheritedMatchedFilterIDs = composeFilterIDs(inheritedFilterIDs, nil)
				if matched {

					// For SIP packets that match, cache CallID → filterIDs
					// so RTP packets (same CallID) can inherit the filter IDs
					if len(directFilterIDs) > 0 && pbPkt.Metadata != nil && pbPkt.Metadata.Sip != nil && pbPkt.Metadata.Rtp == nil {
						callID := pbPkt.Metadata.Sip.CallId
						if callID != "" {
							cachedCallIDs := s.cachedFilterIDsForCall(callID)
							s.callFilterCache.Store(callID, cachedFilterIDs{
								filterIDs: composeFilterIDs(cachedCallIDs, directFilterIDs),
								storedAt:  time.Now(),
							})
						}
					}
				} else {
					// No direct filter match. Allow packets belonging to an
					// already-matched call through by inheriting the filter IDs
					// cached when the call's INVITE matched. This covers:
					//   - trailing RTP for the call (media never matches a SIP filter)
					//   - in-dialog SIP (BYE, ACK, re-INVITE, ...) that does not
					//     re-carry the matched identity. In IMS the matched identity
					//     (e.g. P-Asserted-Identity) often appears only in the INVITE,
					//     so a BYE would otherwise be dropped here and the call would
					//     never be reported as ended downstream — it stays "Active"
					//     forever in the TUI.
					// Mirrors the hunter's IsCallMatched() termination forwarding.
					// If still no filter IDs, drop the packet
					if len(matchedFilterIDs) == 0 {
						continue
					}
				}
			}

			// Set matched filter IDs for LI correlation
			if len(matchedFilterIDs) > 0 {
				pbPkt.MatchedFilterIds = matchedFilterIDs
				pbPkt.DirectMatchedFilterIds = directMatchedFilterIDs
				pbPkt.InheritedMatchedFilterIds = inheritedMatchedFilterIDs
			}

			// Add to batch
			envelope, err := s.normalizeLocalPacket(pbPkt)
			if err != nil {
				s.stats.AddDropped(1)
				logger.Error("Failed to normalize local packet", "error", err)
				continue
			}
			// A packet is forwarded only after it can be admitted to a batch.
			s.stats.AddForwarded(uint64(len(pbPkt.Data)))
			s.batchMu.Lock()
			s.currentBatch = append(s.currentBatch, envelope)
			batchLen := len(s.currentBatch)
			s.batchMu.Unlock()

			// Send if batch is full
			if batchLen >= s.config.BatchSize {
				s.sendBatch()
			}

		case <-ticker.C:
			// Send batch on timeout
			s.sendBatch()
		}
	}
}

// sendBatch sends the current batch to the batches channel.
func (s *LocalSource) sendBatch() {
	s.batchMu.Lock()
	if len(s.currentBatch) == 0 {
		s.batchMu.Unlock()
		return
	}

	s.batchSeq++
	batchTime := time.Now()
	for _, envelope := range s.currentBatch {
		envelope.Source.BatchSequence = s.batchSeq
		envelope.Source.BatchTimestamp = batchTime
	}
	batch := &PacketBatch{
		SourceID:    s.SourceID(),
		Envelopes:   s.currentBatch,
		Sequence:    s.batchSeq,
		TimestampNs: batchTime.UnixNano(),
		Stats: &data.BatchStats{
			TotalCaptured:             s.stats.packetsCaptured.Load(),
			FilteredMatched:           s.stats.packetsForwarded.Load(),
			Dropped:                   s.droppedTotal(),
			CaptureBufferRegularDrops: s.captureBufferRegularDrops(),
			CaptureBufferSipDrops:     s.captureBufferSIPDrops(),
			BatchChannelDrops:         s.stats.packetsDropped.Load(),
		},
		AfterProcess: s.currentBatchAfterProcess,
	}

	// Reset batch
	s.currentBatch = make([]*pipeline.PacketEnvelope, 0, s.config.BatchSize)
	s.currentBatchAfterProcess = nil
	s.batchMu.Unlock()
	s.stats.AddBatch()

	// Non-blocking send
	select {
	case s.batches <- batch:
		// Successfully sent
	default:
		// Buffer full - drop batch
		s.stats.AddDropped(uint64(len(batch.Envelopes)))
		batch.RunAfterProcess()
		logger.Warn("LocalSource batch buffer full, dropping batch",
			"sequence", batch.Sequence,
			"packets", len(batch.Envelopes))
	}
}

func (s *LocalSource) normalizeLocalPacket(packet *data.CapturedPacket) (*pipeline.PacketEnvelope, error) {
	return grpcadapter.FromCapturedPacket(packet, pipeline.SourceProvenance{
		Kind:   pipeline.SourceLiveCapture,
		NodeID: s.SourceID(),
	})
}

// Batches returns the channel that receives packet batches.
func (s *LocalSource) Batches() <-chan *PacketBatch {
	return s.batches
}

// Stats returns current capture statistics.
func (s *LocalSource) Stats() Stats {
	st := s.stats.Snapshot()
	st.CaptureBufferRegularDrops = s.captureBufferRegularDrops()
	st.CaptureBufferSIPDrops = s.captureBufferSIPDrops()
	st.BatchChannelDrops = s.stats.packetsDropped.Load()
	st.PacketsDropped = st.CaptureBufferRegularDrops + st.CaptureBufferSIPDrops + st.BatchChannelDrops
	return st
}

func (s *LocalSource) captureBufferRegularDrops() uint64 {
	if pb := s.packetBuffer.Load(); pb != nil {
		return uint64(pb.GetDropped()) // #nosec G115 -- drop counters cannot be negative
	}
	return 0
}

func (s *LocalSource) captureBufferSIPDrops() uint64 {
	if pb := s.packetBuffer.Load(); pb != nil {
		return uint64(pb.GetSIPDropped()) // #nosec G115 -- drop counters cannot be negative
	}
	return 0
}

// droppedTotal returns capture buffer overflow (regular + SIP) plus batch channel overflow.
func (s *LocalSource) droppedTotal() uint64 {
	return s.captureBufferRegularDrops() + s.captureBufferSIPDrops() + s.stats.packetsDropped.Load()
}

// SourceID returns the source identifier for this local capture.
// Returns "{ProcessorID}-local" if ProcessorID is configured, otherwise "local".
func (s *LocalSource) SourceID() string {
	if s.config.ProcessorID != "" {
		return s.config.ProcessorID + "-local"
	}
	return "local"
}

// GetProtocolMode returns the protocol mode for this local capture.
// Returns the configured ProtocolMode, or "generic" if not set.
func (s *LocalSource) GetProtocolMode() string {
	if s.config.ProtocolMode != "" {
		return s.config.ProtocolMode
	}
	return "generic"
}

// SetBPFFilter updates the BPF filter. This requires restarting capture.
// Returns nil on success, or an error if the filter update fails.
func (s *LocalSource) SetBPFFilter(filter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Re-applying an identical filter needlessly tears down and recreates every
	// live capture handle. Apart from causing a capture gap, repeated libpcap
	// filter operations while the old capture loops are winding down have been
	// observed to crash inside pcap_setfilter. Application-layer filter changes
	// commonly arrive here without changing the effective BPF expression, so
	// make equality a hard no-op at the capture-source boundary.
	if filter == s.config.BPFFilter {
		return nil
	}

	if !s.started {
		// Not started yet, just update config
		s.config.BPFFilter = filter
		return nil
	}

	logger.Info("LocalSource updating BPF filter", "new_filter", filter)

	// Update config
	s.config.BPFFilter = filter

	// Cancel current capture
	if s.captureCancel != nil {
		s.captureCancel()
	}
	// A changed filter is applied by reopening capture handles. Wait until every
	// old handle is closed before creating the next generation; otherwise the
	// old pcap_wait calls can overlap the new generation's pcap_setfilter calls.
	if s.captureDone != nil {
		<-s.captureDone
	}

	// Shutdown may have started while the previous capture generation drained.
	// Preserve the requested configuration without adding a goroutine after
	// Start has begun waiting on its WaitGroup.
	if s.ctx == nil || s.ctx.Err() != nil {
		return nil
	}

	// Create new capture context
	s.captureCtx, s.captureCancel = context.WithCancel(s.ctx)
	s.captureDone = make(chan struct{})

	// Start new capture goroutine
	s.wg.Add(1)
	go s.capturePackets(s.captureCtx, filter, s.captureDone)

	return nil
}

// Stop gracefully stops the source.
func (s *LocalSource) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	// Stop DNS processor if set
	if s.dnsProcessor != nil {
		s.dnsProcessor.Stop()
	}
}

// IsStarted returns whether the source has been started.
func (s *LocalSource) IsStarted() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.started
}

// Interfaces returns the configured capture interfaces.
func (s *LocalSource) Interfaces() []string {
	return s.config.Interfaces
}

// convertPacketInfo converts capture.PacketInfo to protobuf CapturedPacket.
// This is similar to forwarding.convertPacket but works with capture.PacketInfo.
func convertPacketInfo(pktInfo capture.PacketInfo) *data.CapturedPacket {
	pkt := pktInfo.Packet

	captureLen := 0
	originalLen := 0
	var packetData []byte
	var timestampNs int64

	if pkt != nil {
		if pkt.Data() != nil {
			packetData = pkt.Data()
			captureLen = len(packetData)
		}
		if meta := pkt.Metadata(); meta != nil {
			captureLen = meta.CaptureLength
			originalLen = meta.Length
			// Use actual packet capture timestamp, not current time
			timestampNs = meta.Timestamp.UnixNano()
		}
	}

	// Fallback to current time if no metadata timestamp available
	if timestampNs == 0 {
		timestampNs = time.Now().UnixNano()
	}

	return &data.CapturedPacket{
		Data:           packetData,
		TimestampNs:    timestampNs,
		CaptureLength:  uint32(captureLen),  // #nosec G115
		OriginalLength: uint32(originalLen), // #nosec G115
		InterfaceIndex: 0,
		LinkType:       uint32(pktInfo.LinkType), // #nosec G115
		InterfaceName:  pktInfo.Interface,
	}
}

// Ensure LocalSource implements PacketSource.
var _ PacketSource = (*LocalSource)(nil)
