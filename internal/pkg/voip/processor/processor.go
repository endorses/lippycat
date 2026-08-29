// Package processor provides a reusable VoIP packet processor that can be used
// by both hunter nodes and tap nodes for SIP/RTP detection and call tracking.
//
// The processor extracts VoIP metadata from packets and associates RTP streams
// with their corresponding SIP calls via SDP port extraction.
package processor

import (
	"fmt"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// VoIPProcessor processes packets for VoIP (SIP/RTP) detection and call tracking.
// It is designed to be reusable across hunter, tap, and processor nodes.
type VoIPProcessor interface {
	// Process analyzes a packet and returns VoIP metadata if applicable.
	// Returns nil if the packet is not a VoIP packet or doesn't match filters.
	Process(packet gopacket.Packet) *ProcessResult

	// ActiveCalls returns information about currently tracked calls.
	ActiveCalls() []CallInfo

	// Close releases any resources held by the processor.
	Close()
}

// ProcessResult contains the result of processing a single packet.
type ProcessResult struct {
	// IsVoIP indicates whether the packet is a VoIP packet (SIP or RTP).
	IsVoIP bool

	// PacketType indicates whether this is a SIP or RTP packet.
	PacketType PacketType

	// CallID is the SIP Call-ID associated with this packet.
	// For SIP packets, this is extracted from headers.
	// For RTP packets, this is looked up from the port-to-call mapping.
	CallID string

	// CallIDs contains every SIP Call-ID associated with this packet. RTP can
	// belong to multiple call legs when a B2BUA advertises a shared media
	// endpoint. CallID remains the first entry for compatibility with consumers
	// that can represent only one call.
	CallIDs []string

	// Metadata contains protobuf metadata for forwarding to processors.
	Metadata *data.PacketMetadata

	// CallMetadata contains extracted SIP header information (for SIP packets only).
	CallMetadata *CallMetadata

	// FilterEvaluated reports that the application filter was already applied here;
	// callers can reuse the verdict instead of matching the same packet again.
	FilterEvaluated bool

	// FilterMatched is the verdict, valid only when FilterEvaluated is true.
	FilterMatched bool

	// FilterIDs holds the matched filter IDs, populated only when NeedFilterIDs is set.
	FilterIDs []string
}

// PacketType indicates the type of VoIP packet.
type PacketType int

const (
	PacketTypeUnknown PacketType = iota
	PacketTypeSIP
	PacketTypeRTP
)

// CallInfo contains information about an active call.
type CallInfo = callregistry.Call

// CallMetadata contains extracted SIP header information.
type CallMetadata struct {
	CallID            string
	From              string
	To                string
	FromTag           string
	ToTag             string
	PAssertedIdentity string
	Method            string
	CSeqMethod        string // CSeq header method token (recovers a response's transaction method)
	ResponseCode      uint32
	SDPBody           string
	ContentType       string // Content-Type header
	Body              string // Message body (for MESSAGE method, size-limited)

	// 3GPP IMS network information (P-Access-Network-Info, P-Visited-Network-ID)
	AccessType       string            // Access technology (e.g., "IEEE-802.11", "3GPP-E-UTRAN")
	BSSID            string            // WiFi AP MAC address (from i-wlan-node-id)
	CellID           string            // Cellular cell ID (from cgi-3gpp, ecgi, ncgi, etc.)
	LocalIP          string            // UE local IP address
	AccessParams     map[string]string // Additional P-Access-Network-Info parameters
	VisitedNetworkID string            // P-Visited-Network-ID header value
}

// ApplicationFilter is an optional filter interface for VoIP call filtering.
// When set, only SIP packets matching the filter will create call tracking entries.
// RTP packets are only tracked for calls that passed the filter.
type ApplicationFilter interface {
	// MatchPacket returns true if the packet matches any active filter.
	MatchPacket(packet gopacket.Packet) bool

	// MatchPacketWithIDs also returns the IDs of the filters that matched.
	MatchPacketWithIDs(packet gopacket.Packet) (bool, []string)
}

// Config contains configuration for the VoIPProcessor.
type Config struct {
	// MaxCalls is the maximum number of calls to track concurrently.
	// Older calls are evicted when this limit is reached.
	MaxCalls int

	// MaxEndpointsPerCall bounds SDP-derived media endpoints retained for one call.
	MaxEndpointsPerCall int

	// MaxEndpointAssociations bounds all call-to-endpoint associations.
	MaxEndpointAssociations int

	// CallTimeout is the duration after which inactive calls are expired.
	CallTimeout time.Duration

	// MaxBufferAge is the maximum time to buffer packets before filter decision.
	MaxBufferAge time.Duration

	// MaxBufferSize is the maximum number of packets to buffer per call.
	MaxBufferSize int

	// ApplicationFilter is an optional filter for call selection.
	// When set, only SIP packets matching the filter will be tracked.
	ApplicationFilter ApplicationFilter

	// SelectionPolicy controls direct-match and in-dialog selection inheritance.
	SelectionPolicy callregistry.SelectionPolicy

	// NeedFilterIDs makes the processor collect matched filter IDs (required for
	// LI correlation). Without it the cheaper boolean match is used, which can
	// also take the GPU path.
	NeedFilterIDs bool

	// LifecycleObservers receive ordered notifications after registry mutations.
	LifecycleObservers []callregistry.LifecycleObserver
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() Config {
	return Config{
		MaxCalls:                10000,
		MaxEndpointsPerCall:     32,
		MaxEndpointAssociations: 40000,
		CallTimeout:             30 * time.Minute,
		MaxBufferAge:            30 * time.Second,
		MaxBufferSize:           1000,
	}
}

// Processor implements VoIPProcessor for SIP/RTP packet processing.
type Processor struct {
	config Config

	// Call tracking
	calls     map[string]*callState
	registry  *callregistry.Core // calls retains processor-only metadata
	mu        sync.RWMutex
	eventMu   sync.Mutex
	janitorWG sync.WaitGroup

	// Optional application filter for call selection
	appFilter       ApplicationFilter
	needFilterIDs   bool
	selectionPolicy callregistry.SelectionPolicy
	sipFlow         *sipflow.Orchestrator

	// Janitor for cleanup
	janitorCtx    chan struct{}
	closeDone     chan struct{}
	janitorClosed bool
}

// callState holds internal state for a tracked call.
type callState struct {
	info        CallInfo
	metadata    *CallMetadata
	lastUpdated time.Time
}

// New creates a new VoIPProcessor with the given configuration.
func New(cfg Config) *Processor {
	if cfg.MaxCalls <= 0 {
		cfg.MaxCalls = 10000
	}
	if cfg.MaxEndpointsPerCall <= 0 {
		cfg.MaxEndpointsPerCall = 32
	}
	if cfg.MaxEndpointAssociations <= 0 {
		cfg.MaxEndpointAssociations = cfg.MaxCalls * 4
	}
	if cfg.CallTimeout == 0 {
		cfg.CallTimeout = 30 * time.Minute
	}
	if cfg.SelectionPolicy == nil {
		cfg.SelectionPolicy = callregistry.StickySelectionPolicy{}
	}

	p := &Processor{
		config: cfg,
		calls:  make(map[string]*callState),
		registry: callregistry.New(callregistry.Config{
			MaxCalls: cfg.MaxCalls, MaxEndpointsPerCall: cfg.MaxEndpointsPerCall,
			MaxEndpointAssociations: cfg.MaxEndpointAssociations,
			Observers:               cfg.LifecycleObservers,
		}),
		appFilter:       cfg.ApplicationFilter,
		needFilterIDs:   cfg.NeedFilterIDs,
		selectionPolicy: cfg.SelectionPolicy,
		janitorCtx:      make(chan struct{}),
		closeDone:       make(chan struct{}),
	}
	p.sipFlow = newProcessorSIPFlow(p)

	// Start janitor goroutine for cleanup
	p.janitorWG.Add(1)
	go p.janitorLoop()

	return p
}

// AddLifecycleObserver subscribes an observer to future call lifecycle events.
// It is safe to call after construction, before packet processing starts.
func (p *Processor) AddLifecycleObserver(observer callregistry.LifecycleObserver) {
	if p == nil || observer == nil {
		return
	}
	p.registry.AddObserver(observer)
}

// Process analyzes a packet and returns VoIP metadata if applicable.
func (p *Processor) Process(packet gopacket.Packet) *ProcessResult {
	// Try UDP first (most common for VoIP)
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp := udpLayer.(*layers.UDP)
		return p.processUDP(packet, udp)
	}

	// TCP SIP: handles packets decapsulated from ESP-NULL transport mode (IMS/VoLTE).
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp := tcpLayer.(*layers.TCP)
		return p.processTCP(packet, tcp)
	}

	return nil
}

// ProcessReassembledSIP routes a complete synthesized TCP SIP message through
// the same registry and selection path as UDP SIP. Terminal completion is
// deliberately deferred to the injection callback so the final packet enters
// the downstream pipeline before lifecycle observers close session output.
func (p *Processor) ProcessReassembledSIP(packet gopacket.Packet) *data.PacketMetadata {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return nil
	}
	result := p.detectSIPWithCompletion(packet, nil, tcpLayer.(*layers.TCP).Payload, false)
	if result == nil {
		return nil
	}
	return result.Metadata
}

// ProcessReassembledSIPResult records an already parsed, reassembled TCP SIP
// message in the processor registry. Tap's TCP framer has already run the
// shared SIP parser and selection policy, so routing that result through
// detectSIPWithCompletion would parse and select the same message a second
// time.
func (p *Processor) ProcessReassembledSIPResult(result pipeline.SIPResult) (*data.PacketMetadata, error) {
	observation, err := (processorSIPRegistry{processor: p}).Observe(result)
	if err != nil {
		return nil, fmt.Errorf("observe reassembled SIP result: %w", err)
	}
	attachment, ok := observation.Attachment.(processorSIPAttachment)
	if !ok {
		return nil, fmt.Errorf("observe reassembled SIP result: unexpected attachment type %T", observation.Attachment)
	}
	return attachment.pbMetadata, nil
}

// processUDP processes a UDP packet for SIP/RTP content.
func (p *Processor) processUDP(packet gopacket.Packet, udp *layers.UDP) *ProcessResult {
	payload := udp.Payload

	// Try SIP detection first
	if result := p.detectSIP(packet, udp, payload); result != nil {
		return result
	}

	// Try RTP detection (check if port is tracked)
	if result := p.detectRTP(packet, udp); result != nil {
		return result
	}

	return nil
}

// processTCP processes a TCP packet for SIP content.
// TCP SIP is used in IMS/VoLTE networks where SIP runs over TCP inside ESP-NULL tunnels.
func (p *Processor) processTCP(packet gopacket.Packet, tcp *layers.TCP) *ProcessResult {
	return p.detectSIP(packet, nil, tcp.Payload)
}

// ActiveCalls returns information about currently tracked calls.
func (p *Processor) ActiveCalls() []CallInfo {
	p.mu.RLock()
	defer p.mu.RUnlock()

	calls := make([]CallInfo, 0, len(p.calls))
	for _, state := range p.calls {
		calls = append(calls, state.info)
	}
	return calls
}

// Close releases resources held by the processor.
func (p *Processor) Close() {
	if p.sipFlow != nil {
		p.sipFlow.Close()
	}
	p.eventMu.Lock()
	p.mu.Lock()
	if p.janitorClosed {
		p.mu.Unlock()
		p.eventMu.Unlock()
		<-p.closeDone
		return
	}
	close(p.janitorCtx)
	p.janitorClosed = true
	// Release every association on shutdown. The processor is the sole owner of
	// these maps, so retaining them after Close only prolongs endpoint/call data.
	clear(p.calls)
	p.mu.Unlock()
	p.registry.Close()
	p.eventMu.Unlock()
	p.janitorWG.Wait()
	close(p.closeDone)
}

// RegisterSDP associates RTP endpoints advertised by a reassembled TCP SIP
// message with this processor's call tracker. UDP SIP reaches the same logic via
// detectSIP; tap's TCP handler calls this method because injected messages bypass
// packet processing after reassembly.
func (p *Processor) RegisterSDP(callID, sdp string) {
	if callID == "" || sdp == "" {
		return
	}
	_ = p.getOrCreateCall(callID)
	for _, endpoint := range extractRTPPortsFromSDP(sdp) {
		p.registerRTPPort(callID, endpoint)
	}
}

// janitorLoop periodically cleans up expired calls.
func (p *Processor) janitorLoop() {
	defer p.janitorWG.Done()
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.janitorCtx:
			return
		case <-ticker.C:
			p.cleanupExpiredCalls()
		}
	}
}

// cleanupExpiredCalls removes calls that have exceeded the timeout.
func (p *Processor) cleanupExpiredCalls() {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()
	p.mu.Lock()

	now := time.Now()
	for callID, state := range p.calls {
		if now.Sub(state.lastUpdated) > p.config.CallTimeout {
			// Remove this callID from port mappings (multi-value for B2BUA)
			delete(p.calls, callID)
			p.registry.Remove(callID, callregistry.EndTimeout)
		}
	}
	p.mu.Unlock()
}

// getOrCreateCall gets or creates a call state for the given CallID.
func (p *Processor) getOrCreateCall(callID string) *callState {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()
	p.mu.Lock()

	state, exists := p.calls[callID]
	if !exists {
		if p.janitorClosed {
			p.mu.Unlock()
			return nil
		}
		now := time.Now()
		state = &callState{
			info: CallInfo{
				CallID:      callID,
				State:       "NEW",
				Created:     now,
				LastUpdated: now,
			},
			lastUpdated: now,
		}
		p.calls[callID] = state
		p.registry.Upsert(state.info)
		// Evict oldest call if at capacity
		if len(p.calls) > p.config.MaxCalls {
			p.evictOldestCallLocked()
		}
	}
	p.mu.Unlock()
	return state
}

// evictOldestCallLocked removes the oldest call (must hold mu lock).
func (p *Processor) evictOldestCallLocked() (CallInfo, bool) {
	var oldestID string
	var oldestTime time.Time

	for id, state := range p.calls {
		if oldestID == "" || state.lastUpdated.Before(oldestTime) {
			oldestID = id
			oldestTime = state.lastUpdated
		}
	}

	if oldestID != "" {
		state := p.calls[oldestID]
		delete(p.calls, oldestID)
		p.registry.Remove(oldestID, callregistry.EndEvicted)
		return state.info, true
	}
	return CallInfo{}, false
}

// registerRTPPort associates an RTP port with a call (multi-value for B2BUA).
func (p *Processor) registerRTPPort(callID, port string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	_, exists := p.calls[callID]
	if p.janitorClosed || !exists {
		return
	}

	p.registry.TryAssociateEndpoint(callID, port)
}

// getCallIDForPort looks up the first CallID for an RTP port.
// For B2BUA scenarios with multiple calls on same port, use getAllCallIDsForPort.
func (p *Processor) getCallIDForPort(port string) (string, bool) {
	callIDs := p.registry.CallIDsForEndpoint(port)
	if len(callIDs) > 0 {
		return callIDs[0], true
	}
	return "", false
}

// getAllCallIDsForPort returns all CallIDs associated with an RTP port.
// This supports B2BUA scenarios where multiple call legs share the same port.
func (p *Processor) getAllCallIDsForPort(port string) []string {
	return p.registry.CallIDsForEndpoint(port)
}

// Call returns a copy of the tracked call.
func (p *Processor) Call(callID string) (callregistry.Call, bool) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	state, ok := p.calls[callID]
	if !ok {
		return callregistry.Call{}, false
	}
	return state.info, true
}

// CallIDsForEndpoint returns a copy of all calls associated with endpoint.
func (p *Processor) CallIDsForEndpoint(endpoint string) []string {
	return p.getAllCallIDsForPort(endpoint)
}

// AssociateEndpoint associates a media endpoint with an existing call.
func (p *Processor) AssociateEndpoint(callID, endpoint string) {
	if callID == "" || endpoint == "" || p.getOrCreateCall(callID) == nil {
		return
	}
	p.registerRTPPort(callID, endpoint)
}

// CleanupCallPorts removes all port-to-callID mappings for a given callID.
// This should be called when a call ends to prevent port collisions with new calls.
func (p *Processor) CleanupCallPorts(callID string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	_, exists := p.calls[callID]
	if !exists {
		return
	}

	p.registry.DissociateEndpoints(callID)
}

// CompleteCall removes RTP associations once SIP confirms that a dialog has
// terminated. The call record is retained until normal timeout/eviction so
// callers can still inspect its final metadata, but reused media endpoints can
// no longer be attributed to the completed call.
func (p *Processor) CompleteCall(callID string) {
	p.removeCall(callID, callregistry.EndCompleted)
}

func (p *Processor) removeCall(callID string, reason callregistry.EndReason) {
	p.eventMu.Lock()
	defer p.eventMu.Unlock()
	p.mu.Lock()
	_, exists := p.calls[callID]
	if exists {
		delete(p.calls, callID)
	}
	p.mu.Unlock()
	if exists {
		p.registry.Remove(callID, reason)
	}
}

// touchCalls refreshes activity for valid RTP belonging to tracked calls.
func (p *Processor) touchCalls(callIDs []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	for _, callID := range callIDs {
		if state, ok := p.calls[callID]; ok {
			state.lastUpdated = now
			state.info.LastUpdated = now
			p.registry.Touch(callID, now)
		}
	}
}

// updateCallState updates the state and metadata for a call.
func (p *Processor) updateCallState(callID, state string, metadata *CallMetadata) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if callState, exists := p.calls[callID]; exists {
		callState.info.State = state
		callState.info.LastUpdated = time.Now()
		callState.lastUpdated = time.Now()
		if metadata != nil {
			callState.metadata = metadata
			callState.info.From = metadata.From
			callState.info.To = metadata.To
		}
		p.registry.Upsert(callState.info)
	}
}

// Ensure Processor implements VoIPProcessor.
var _ VoIPProcessor = (*Processor)(nil)
var _ callregistry.Registry = (*Processor)(nil)
