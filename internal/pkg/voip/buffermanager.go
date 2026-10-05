package voip

import (
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"sync"
	"time"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// BufferManager manages per-call packet buffers
type BufferManager struct {
	registry               *callregistry.Core
	sdpEndpointLimit       int
	sdpAssociationRejected uint64
	sdpParseCounters       sharedsip.SDPParseCounters
	sdpReporter            *sharedsip.SDPDiagnosticReporter
	matchedLifetimes       map[string]callregistry.Lifetime
	buffers                map[string]*CallBuffer // callID -> buffer (temporary until filter decision)
	matchedCalls           map[string]time.Time   // callID -> matchTime (persists after buffer cleanup)
	matchedIDs             map[string][]string    // callID -> direct filter IDs selecting the call
	mu                     sync.RWMutex
	maxAge                 time.Duration // Max time to buffer before decision
	maxSize                int           // Max packets per buffer
	matchedTTL             time.Duration // How long to remember matched calls (default: 24h)
	janitorCh              chan struct{} // Signal channel for janitor
	stopCh                 chan struct{} // Stop channel
	janitorDone            chan struct{}
	closeOnce              sync.Once
}

// DefaultMatchedTTL is how long to remember matched calls after filter decision.
// This allows BYE messages to be correctly associated with calls even after
// the temporary buffer has been cleaned up. 24 hours covers very long calls.
const DefaultMatchedTTL = 24 * time.Hour

// NewBufferManager creates a new buffer manager
func NewBufferManager(maxAge time.Duration, maxSize int) *BufferManager {
	bm := &BufferManager{
		sdpEndpointLimit: DefaultConfig().MaxEndpointsPerCall,
		buffers:          make(map[string]*CallBuffer),
		matchedLifetimes: make(map[string]callregistry.Lifetime),
		matchedCalls:     make(map[string]time.Time),
		matchedIDs:       make(map[string][]string),
		maxAge:           maxAge,
		maxSize:          maxSize,
		matchedTTL:       DefaultMatchedTTL,
		janitorCh:        make(chan struct{}),
		stopCh:           make(chan struct{}),
		janitorDone:      make(chan struct{}),
	}
	bm.sdpReporter = sharedsip.NewSDPDiagnosticReporter(&bm.sdpParseCounters, sharedsip.SDPBufferPath)

	// Start janitor goroutine for cleanup
	go bm.janitor()

	return bm
}

// AddSIPPacket records a SIP packet for a call.
//
// It returns true when the call has already been matched, in which case the
// packet is NOT buffered and the caller must write/forward it immediately.
// Buffering only exists to hold packets until the filter decision is made; once
// that decision is "matched", every further packet of the call must flow
// straight through. Gating that on the packet carrying SDP would silently drop
// all non-SDP signalling (100 Trying, 180 Ringing, ACK, BYE, 4xx/5xx).
//
// A nil packet is allowed: callers that have already delivered the packet
// themselves use it to seed the buffer's metadata and RTP ports.
func (bm *BufferManager) AddSIPPacket(callID string, packet gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) bool {
	return bm.addSIPPacket(callID, packet, pipeline.SIPResult{}, metadata, interfaceName, linkType)
}

// AddSIPResult records a SIP packet with the typed result from its original
// shared parse. The result is drained with the packet when the call matches.
func (bm *BufferManager) AddSIPResult(callID string, packet gopacket.Packet, result pipeline.SIPResult, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) bool {
	return bm.addSIPPacket(callID, packet, result, metadata, interfaceName, linkType)
}

func (bm *BufferManager) addSIPPacket(callID string, packet gopacket.Packet, result pipeline.SIPResult, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	bm.discardStaleMatchLocked(callID)
	alreadyMatched := bm.matchedValidLocked(callID)

	buffer, exists := bm.buffers[callID]
	if !exists {
		buffer = NewCallBuffer(callID, bm.sdpEndpointLimit)
		buffer.SetInterfaceName(interfaceName)
		buffer.SetLinkType(linkType)
		if alreadyMatched {
			// The janitor reaps buffers by age, so a long call outlives its
			// buffer. Restore the decision on the replacement buffer so RTP
			// association keeps working for the rest of the call.
			buffer.SetFilterResult(true)
		}
		bm.buffers[callID] = buffer
	}

	buffer.SetMetadata(metadata)

	// Extract RTP ports from SDP if present. Re-INVITEs and delayed-offer
	// answers can introduce new ports mid-call, so this runs for every packet
	// carrying SDP, matched or not.
	if metadata.SDPBody != "" {
		ports := bm.extractSDPEndpoints(metadata.SDPBody)
		for _, port := range ports {
			if !buffer.AddRTPPort(port) {
				bm.sdpAssociationRejected++
			}
		}
	}

	if alreadyMatched {
		return true // Caller writes/forwards immediately; nothing to buffer
	}

	if packet != nil {
		buffer.AddSIPResult(packet, result)
	}
	return false
}

// CheckFilterWithTypedCallback drains the original typed SIP results and RTP
// packets for a matched call. The callback runs after releasing bm.mu so it can
// safely dispatch through sinks that query call selection state.
func (bm *BufferManager) CheckFilterWithTypedCallback(
	callID string,
	filterFunc func(*CallMetadata) bool,
	onMatch func(string, []BufferedSIPPacket, []gopacket.Packet, *CallMetadata, string, layers.LinkType),
) bool {
	bm.mu.Lock()
	buffer, exists := bm.buffers[callID]
	if !exists || buffer.GetMetadata() == nil {
		bm.mu.Unlock()
		return false
	}

	metadata := buffer.GetMetadata()
	matched := filterFunc(metadata)
	buffer.SetFilterResult(matched)
	if !matched {
		delete(bm.buffers, callID)
		packetCount := buffer.GetPacketCount()
		bm.mu.Unlock()
		logger.Debug("Call did not match filter, discarding buffer",
			"call_id", SanitizeCallIDForLogging(callID), "packet_count", packetCount)
		return false
	}

	bm.recordMatchLocked(callID)
	sip, rtp := buffer.DrainTypedPackets()
	interfaceName, linkType := buffer.GetInterfaceName(), buffer.GetLinkType()
	bm.mu.Unlock()

	logger.Info("Call matched filter, invoking typed callback",
		"call_id", SanitizeCallIDForLogging(callID), "packet_count", len(sip)+len(rtp),
		"from", metadata.From, "to", metadata.To)
	if onMatch != nil {
		onMatch(callID, sip, rtp, metadata, interfaceName, linkType)
	}
	return true
}

// AddRTPPacket adds an RTP packet to the buffer if call is being tracked
// Returns true if packet should be forwarded immediately (call already matched)
func (bm *BufferManager) AddRTPPacket(callID string, port string, packet gopacket.Packet) bool {
	bm.mu.RLock()
	buffer, exists := bm.buffers[callID]
	bm.mu.RUnlock()

	if !exists || !buffer.IsRTPPort(port) {
		return false
	}

	// If filter already checked and matched, don't buffer (forward directly)
	if buffer.IsFilterChecked() && buffer.IsMatched() {
		return true // Caller should forward immediately
	}

	// Buffer the packet
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if bm.buffers[callID] != buffer {
		return false
	}
	buffer.AddRTPPacket(packet)

	return false // Buffered, don't forward yet
}

// AddRTPPacketForEndpoints adds media only when one of the packet's exact
// endpoints belongs to the already-authoritatively resolved call. The second
// return value distinguishes a buffered packet from an endpoint mismatch.
func (bm *BufferManager) AddRTPPacketForEndpoints(callID, sourceEndpoint, destinationEndpoint string, packet gopacket.Packet) (forward, accepted bool) {
	bm.mu.RLock()
	buffer, exists := bm.buffers[callID]
	bm.mu.RUnlock()
	if !exists || (!buffer.IsRTPPort(sourceEndpoint) && !buffer.IsRTPPort(destinationEndpoint)) {
		return false, false
	}
	if buffer.IsFilterChecked() && buffer.IsMatched() {
		return true, true
	}

	bm.mu.Lock()
	defer bm.mu.Unlock()
	if bm.buffers[callID] != buffer {
		return false, false
	}
	buffer.AddRTPPacket(packet)
	return false, true
}

// GetCallIDForRTPPort is retained for non-authoritative diagnostics. Its
// map-order result must not be used for filtering or packet attribution.
func (bm *BufferManager) GetCallIDForRTPPort(port string) (string, bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	for callID, buffer := range bm.buffers {
		if buffer.IsRTPPort(port) {
			return callID, true
		}
	}
	return "", false
}

// CheckFilter evaluates filter and returns decision + buffered packets if matched
func (bm *BufferManager) CheckFilter(callID string, filterFunc func(*CallMetadata) bool) (matched bool, packets []gopacket.Packet) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists || buffer.GetMetadata() == nil {
		return false, nil
	}

	// Check filter
	matched = filterFunc(buffer.GetMetadata())
	buffer.SetFilterResult(matched)

	if matched {
		// Record in matchedCalls so BYE can be processed even after buffer cleanup
		bm.recordMatchLocked(callID)

		// Hand over all buffered packets and empty the buffer, so a later
		// filter check for the same call cannot re-emit them.
		packets = buffer.DrainPackets()
		logger.Info("Call matched filter, flushing buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", len(packets),
			"from", buffer.GetMetadata().From,
			"to", buffer.GetMetadata().To)
	} else {
		// Discard buffer
		delete(bm.buffers, callID)
		logger.Debug("Call did not match filter, discarding buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", buffer.GetPacketCount())
	}

	return matched, packets
}

// CheckFilterWithCallback evaluates filter and calls callback for each packet if matched
// This allows different handling strategies (file write, gRPC forward, etc.)
func (bm *BufferManager) CheckFilterWithCallback(
	callID string,
	filterFunc func(*CallMetadata) bool,
	onMatch func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType),
) bool {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists || buffer.GetMetadata() == nil {
		return false
	}

	// Check filter
	matched := filterFunc(buffer.GetMetadata())
	buffer.SetFilterResult(matched)

	if matched {
		// Record in matchedCalls so BYE can be processed even after buffer cleanup
		bm.recordMatchLocked(callID)

		// Take all buffered packets and empty the buffer, so a later filter
		// check for the same call cannot re-emit them.
		packets := buffer.DrainPackets()
		logger.Info("Call matched filter, invoking callback",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", len(packets),
			"from", buffer.GetMetadata().From,
			"to", buffer.GetMetadata().To)

		// Call the handler callback
		if onMatch != nil {
			onMatch(callID, packets, buffer.GetMetadata(), buffer.GetInterfaceName(), buffer.GetLinkType())
		}
	} else {
		// Discard buffer
		delete(bm.buffers, callID)
		logger.Debug("Call did not match filter, discarding buffer",
			"call_id", SanitizeCallIDForLogging(callID),
			"packet_count", buffer.GetPacketCount())
	}

	return matched
}

// MarkCallMatched records a call as matched without buffering a packet.
//
// TCP paths deliver each SIP message as the reassembler completes it, so they
// have nothing to flush — but the call must still be remembered as matched, or
// later in-dialog messages (ACK, BYE, responses) and the call's RTP would be
// re-evaluated on their own headers and dropped when they carry no identity the
// filter matches.
func (bm *BufferManager) MarkCallMatched(callID string, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	buffer, exists := bm.buffers[callID]
	if !exists {
		buffer = NewCallBuffer(callID, bm.sdpEndpointLimit)
		buffer.SetInterfaceName(interfaceName)
		buffer.SetLinkType(linkType)
		bm.buffers[callID] = buffer
	}

	if metadata != nil {
		buffer.SetMetadata(metadata)
		if metadata.SDPBody != "" {
			for _, port := range bm.extractSDPEndpoints(metadata.SDPBody) {
				if !buffer.AddRTPPort(port) {
					bm.sdpAssociationRejected++
				}
			}
		}
	}

	buffer.SetFilterResult(true)
	bm.recordMatchLocked(callID)
}

// IsCallMatched checks if a call has been evaluated and matched the filter.
// The persistent decision is authoritative; a retained packet buffer cannot
// extend selection after expiry or registry retirement.
func (bm *BufferManager) IsCallMatched(callID string) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()

	return bm.matchedValidLocked(callID)
}

// StoreMatchedFilterIDs retains the direct filter evidence that selected one
// call. Media may inherit only this call-scoped snapshot after authoritative
// endpoint resolution.
func (bm *BufferManager) StoreMatchedFilterIDs(callID string, filterIDs []string) {
	if callID == "" || len(filterIDs) == 0 {
		return
	}
	bm.mu.Lock()
	bm.discardStaleMatchLocked(callID)
	combined := append(append([]string(nil), bm.matchedIDs[callID]...), filterIDs...)
	bm.matchedIDs[callID] = stableFilterIDs(combined)
	bm.mu.Unlock()
}

// MatchedFilterIDs returns a copy of the direct IDs that selected callID.
func (bm *BufferManager) MatchedFilterIDs(callID string) []string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if _, matched := bm.matchedCalls[callID]; matched && !bm.matchedValidLocked(callID) {
		return nil
	}
	return append([]string(nil), bm.matchedIDs[callID]...)
}

func stableFilterIDs(filterIDs []string) []string {
	result := make([]string, 0, len(filterIDs))
	seen := make(map[string]struct{}, len(filterIDs))
	for _, id := range filterIDs {
		if id == "" {
			continue
		}
		if _, exists := seen[id]; exists {
			continue
		}
		seen[id] = struct{}{}
		result = append(result, id)
	}
	return result
}

// DiscardBuffer removes a buffer without flushing
func (bm *BufferManager) DiscardBuffer(callID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	delete(bm.buffers, callID)
	if _, matched := bm.matchedCalls[callID]; !matched {
		delete(bm.matchedIDs, callID)
	}
}

// GetBufferCount returns the number of active buffers
func (bm *BufferManager) GetBufferCount() int {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return len(bm.buffers)
}

// janitor periodically cleans up old buffers
func (bm *BufferManager) janitor() {
	defer close(bm.janitorDone)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			bm.cleanupOldBuffers()
			bm.sdpReporter.Report(time.Now())
		case <-bm.stopCh:
			return
		}
	}
}

// cleanupOldBuffers removes buffers that are too old or too large,
// and cleans up old entries from the matchedCalls map.
func (bm *BufferManager) cleanupOldBuffers() {
	bm.mu.Lock()
	defer bm.mu.Unlock()

	now := time.Now()

	// Clean up old buffers (temporary packet storage before filter decision)
	for callID, buffer := range bm.buffers {
		age := buffer.GetAge()
		packetCount := buffer.GetPacketCount()

		// Check age
		if age > bm.maxAge {
			logger.Warn("Discarding buffer due to age",
				"call_id", SanitizeCallIDForLogging(callID),
				"age_seconds", int(age.Seconds()),
				"packet_count", packetCount)
			delete(bm.buffers, callID)
			if _, matched := bm.matchedCalls[callID]; !matched {
				delete(bm.matchedIDs, callID)
			}
			continue
		}

		// Check size
		if packetCount > bm.maxSize {
			logger.Warn("Discarding buffer due to size",
				"call_id", SanitizeCallIDForLogging(callID),
				"packet_count", packetCount,
				"max_size", bm.maxSize)
			delete(bm.buffers, callID)
			if _, matched := bm.matchedCalls[callID]; !matched {
				delete(bm.matchedIDs, callID)
			}
		}
	}

	// Clean up old matchedCalls entries (persistent call tracking)
	for callID, matchTime := range bm.matchedCalls {
		if now.Sub(matchTime) > bm.matchedTTL {
			logger.Debug("Removing expired matched call entry",
				"call_id", SanitizeCallIDForLogging(callID),
				"age_hours", int(now.Sub(matchTime).Hours()))
			delete(bm.matchedCalls, callID)
			delete(bm.matchedLifetimes, callID)
			delete(bm.matchedIDs, callID)
			delete(bm.buffers, callID)
		}
	}
}

// Close stops the buffer manager
// Safe to call multiple times (idempotent)
func (bm *BufferManager) Close() {
	bm.closeOnce.Do(func() {
		close(bm.stopCh)
		<-bm.janitorDone
		bm.sdpReporter.Flush()
	})
}

// extractRTPPortsFromSDP extracts RTP ports and IP:PORT endpoints from SDP body
// Returns exact IP:PORT endpoints. Port-only ownership is not authoritative.
func extractRTPPortsFromSDP(sdp string) []string {
	return extractAllRTPEndpoints(sdp)
}

// extractSDPEndpoints is called with bm.mu held. Exact endpoint keys precede
// legacy port diagnostics, so diagnostics never displace an attributable key.
func (bm *BufferManager) extractSDPEndpoints(body string) []string {
	parsed := sharedsip.ParseSDPResult(body, bm.sdpEndpointLimit)
	bm.sdpParseCounters.Observe(parsed)
	return legacySDPEndpointKeys(body, parsed, bm.sdpEndpointLimit)
}

// SDPParseStats reports sanitized aggregate parsing diagnostics for this manager.
func (bm *BufferManager) SDPParseStats() sharedsip.SDPParseStats {
	return bm.sdpParseCounters.Snapshot()
}

// SDPAssociationRejected counts bounded per-call diagnostic keys rejected after
// earlier SDP observations filled the configured association budget.
func (bm *BufferManager) SDPAssociationRejected() uint64 {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	return bm.sdpAssociationRejected
}

// BindRegistry binds the manager once at handler construction, before packet
// processing. The registry remains the sole owner of endpoint and call identity.
func (bm *BufferManager) BindRegistry(registry *callregistry.Core, endpointLimits ...int) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if bm.registry == registry {
		return
	}
	if bm.registry != nil {
		panic("buffer manager cannot change call registry")
	}
	bm.registry = registry
	if len(endpointLimits) > 0 && endpointLimits[0] > 0 {
		bm.sdpEndpointLimit = endpointLimits[0]
	}
	for callID := range bm.matchedCalls {
		if call, ok := registry.Call(callID); ok {
			bm.matchedLifetimes[callID] = call.Lifetime
		}
	}
}
func (bm *BufferManager) recordMatchLocked(callID string) {
	bm.matchedCalls[callID] = time.Now()
	if bm.registry != nil {
		if call, ok := bm.registry.Call(callID); ok {
			bm.matchedLifetimes[callID] = call.Lifetime
		} else {
			delete(bm.matchedLifetimes, callID)
		}
	}
}

// bindMatchedLifetime finishes a buffered decision whose first selected SIP
// observation creates the registry call. It never renews selection or transfers
// an existing decision to a reused Call-ID.
func (bm *BufferManager) bindMatchedLifetime(callID string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if bm.registry == nil {
		return
	}
	at, matched := bm.matchedCalls[callID]
	if !matched || time.Since(at) > bm.matchedTTL {
		return
	}
	if _, bound := bm.matchedLifetimes[callID]; bound {
		return
	}
	if call, ok := bm.registry.Call(callID); ok {
		bm.matchedLifetimes[callID] = call.Lifetime
	}
}
func (bm *BufferManager) matchedValidLocked(callID string) bool {
	at, ok := bm.matchedCalls[callID]
	if !ok || time.Since(at) > bm.matchedTTL {
		return false
	}
	if bm.registry == nil {
		return true
	}
	call, ok := bm.registry.Call(callID)
	return ok && call.Lifetime == bm.matchedLifetimes[callID]
}
func (bm *BufferManager) discardStaleMatchLocked(callID string) {
	if _, ok := bm.matchedCalls[callID]; ok && !bm.matchedValidLocked(callID) {
		delete(bm.matchedCalls, callID)
		delete(bm.matchedLifetimes, callID)
		delete(bm.matchedIDs, callID)
		delete(bm.buffers, callID)
	}
}

// MatchedFilterIDsForResolution revalidates the captured lifetime and exact
// endpoint ownership before returning identity provenance for media.
func (bm *BufferManager) MatchedFilterIDsForResolution(resolution callregistry.MediaResolution, source, destination string) []string {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if !bm.currentResolutionLocked(resolution, source, destination) || !bm.matchedValidLocked(resolution.CallID) {
		return nil
	}
	return append([]string(nil), bm.matchedIDs[resolution.CallID]...)
}
func (bm *BufferManager) currentResolutionLocked(resolution callregistry.MediaResolution, source, destination string) bool {
	if bm.registry == nil || resolution.Status != callregistry.MediaResolved {
		return false
	}
	current := bm.registry.ResolveMediaEndpoints(source, destination)
	return current.Status == callregistry.MediaResolved && current.CallID == resolution.CallID && current.Lifetime == resolution.Lifetime
}

// AddResolvedRTPPacket preserves matched forwarding after temporary packet
// storage expires. No packet payloads or endpoint copies are retained for this
// path: the live registry and the original selection lifetime authorize it.
func (bm *BufferManager) AddResolvedRTPPacket(resolution callregistry.MediaResolution, source, destination string, packet gopacket.Packet) (forward, accepted bool, filterIDs []string) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if !bm.currentResolutionLocked(resolution, source, destination) {
		return false, false, nil
	}
	if bm.matchedValidLocked(resolution.CallID) {
		return true, true, append([]string(nil), bm.matchedIDs[resolution.CallID]...)
	}
	// An expired or revoked match must not fall back to a stale matched buffer.
	if _, matched := bm.matchedCalls[resolution.CallID]; matched {
		return false, false, nil
	}
	buffer := bm.buffers[resolution.CallID]
	if buffer == nil || (!buffer.IsRTPPort(source) && !buffer.IsRTPPort(destination)) {
		return false, false, nil
	}
	buffer.AddRTPPacket(packet)
	return false, true, nil
}
