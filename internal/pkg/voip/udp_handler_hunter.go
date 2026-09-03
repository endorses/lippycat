//go:build hunter || all

package voip

import (
	"strconv"
	"sync"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/sipflow"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// ApplicationFilter is defined in application_filter.go (build tag
// hunter||tap||all) so both the hunter and tap packet handlers can use it.

// UDPPacketHandler processes UDP SIP/RTP packets for hunter mode with buffering
type UDPPacketHandler struct {
	tracker         *CallTracker
	forwarder       PacketForwarder
	bufferMgr       *BufferManager
	appFilter       ApplicationFilter // Optional: for proper filter matching (supports phone_number, sip_user, etc.)
	selectionPolicy *hunterSelectionPolicy
	orchestrator    *sipflow.Orchestrator
	analysisMu      sync.Mutex
	bufferedSIP     map[string][]bufferedSIPAnalysis
}

type bufferedSIPAnalysis struct {
	result sipflow.ProcessResult
	at     time.Time
}

type packetLevelFilterWithIDs interface {
	MatchPacketLevelWithIDs(gopacket.Packet) (bool, []string)
}

const maxBufferedSIPAnalysisCalls = 1024

// NewUDPPacketHandler creates a UDP packet handler for hunter mode
func NewUDPPacketHandler(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *UDPPacketHandler {
	h := &UDPPacketHandler{
		tracker:         tracker,
		forwarder:       forwarder,
		bufferMgr:       bufferMgr,
		selectionPolicy: newHunterSelectionPolicy(),
		bufferedSIP:     make(map[string][]bufferedSIPAnalysis),
	}
	h.orchestrator = newHunterSIPOrchestrator(forwarder, h.selectionPolicy)
	return h
}

func (h *UDPPacketHandler) Close() { h.orchestrator.Close() }

func (h *UDPPacketHandler) SIPStats() map[string]sipflow.SinkStats { return h.orchestrator.Stats() }

func (h *UDPPacketHandler) cacheAnalysis(callID string, result sipflow.ProcessResult) {
	h.analysisMu.Lock()
	evicted := make([]string, 0, 2)
	now := time.Now()
	for id, entries := range h.bufferedSIP {
		if len(entries) == 0 || now.Sub(entries[0].at) > h.bufferMgr.maxAge {
			delete(h.bufferedSIP, id)
			evicted = append(evicted, id)
		}
	}
	if _, exists := h.bufferedSIP[callID]; !exists && len(h.bufferedSIP) >= maxBufferedSIPAnalysisCalls {
		var oldestID string
		var oldest time.Time
		for id, entries := range h.bufferedSIP {
			if len(entries) != 0 && (oldestID == "" || entries[0].at.Before(oldest)) {
				oldestID, oldest = id, entries[0].at
			}
		}
		if oldestID != "" {
			delete(h.bufferedSIP, oldestID)
			evicted = append(evicted, oldestID)
		}
	}
	entries := h.bufferedSIP[callID]
	if len(entries) >= h.bufferMgr.maxSize {
		delete(h.bufferedSIP, callID)
		evicted = append(evicted, callID)
		entries = nil
	}
	h.bufferedSIP[callID] = append(entries, bufferedSIPAnalysis{result: result, at: now})
	h.analysisMu.Unlock()
	// Never acquire BufferManager.mu while holding analysisMu: its match
	// callback takes the locks in the opposite order when draining analyses.
	for _, id := range evicted {
		h.bufferMgr.DiscardBuffer(id)
	}
}

func (h *UDPPacketHandler) takeAnalyses(callID string) []sipflow.ProcessResult {
	h.analysisMu.Lock()
	defer h.analysisMu.Unlock()
	entries := h.bufferedSIP[callID]
	delete(h.bufferedSIP, callID)
	results := make([]sipflow.ProcessResult, len(entries))
	for i := range entries {
		results[i] = entries[i].result
	}
	return results
}

func (h *UDPPacketHandler) discardAnalyses(callID string) {
	h.analysisMu.Lock()
	delete(h.bufferedSIP, callID)
	h.analysisMu.Unlock()
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *UDPPacketHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

func (h *UDPPacketHandler) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	h.selectionPolicy.set(policy)
}

// matchesFilter checks if a packet matches any configured filter.
// Uses ApplicationFilter if available (supports phone_number, sip_user, etc.)
// Falls back to legacy containsUserInHeaders() if no ApplicationFilter is set.
func (h *UDPPacketHandler) matchesFilter(packet gopacket.Packet, headers map[string]string) bool {
	// Use ApplicationFilter if available (Phase 2: proper multi-filter support)
	if h.appFilter != nil {
		return h.appFilter.MatchPacket(packet)
	}

	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	// This only supports sip_user filters, not phone_number or other filter types
	return containsUserInHeaders(headers)
}

// matchesFilterWithMetadata checks if call metadata matches any configured filter.
// Used by the buffer manager callback when checking filter after SDP is received.
func (h *UDPPacketHandler) matchesFilterWithMetadata(packet gopacket.Packet, m *CallMetadata) bool {
	// Use ApplicationFilter if available (Phase 2: proper multi-filter support)
	// The packet is passed to get full header matching capability
	if h.appFilter != nil {
		return h.appFilter.MatchPacket(packet)
	}

	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	return containsUserInHeaders(map[string]string{
		"from":                m.From,
		"to":                  m.To,
		"p-asserted-identity": m.PAssertedIdentity,
	})
}

// HandleUDPPacket processes a UDP packet (SIP or RTP) with buffering
func (h *UDPPacketHandler) HandleUDPPacket(pkt capture.PacketInfo, layer *layers.UDP) bool {
	// Handle SIP packets (port 5060 or 5061)
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort ||
		layer.SrcPort == SIPPortTLS || layer.DstPort == SIPPortTLS {
		return h.handleSIPPacket(pkt, layer)
	}

	// Handle potential RTP packets
	return h.handleRTPPacket(pkt, layer)
}

// handleSIPPacket processes a SIP packet with buffering
func (h *UDPPacketHandler) handleSIPPacket(pkt capture.PacketInfo, layer *layers.UDP) bool {
	packet := pkt.Packet
	interfaceName := pkt.Interface
	payload := layer.Payload

	// Get LinkType from the packet
	linkType := layers.LinkTypeEthernet // Default
	if linkLayer := packet.LinkLayer(); linkLayer != nil {
		linkType = layers.LinkType(linkLayer.LayerType())
	}

	opts := sharedsip.ParseOptions{Timestamp: packet.Metadata().Timestamp, SourcePort: uint16(layer.SrcPort), DestinationPort: uint16(layer.DstPort)}
	if network := packet.NetworkLayer(); network != nil {
		opts.SourceIP, opts.DestinationIP = network.NetworkFlow().Src().String(), network.NetworkFlow().Dst().String()
	}
	directMatch := h.appFilter != nil && h.matchesFilter(packet, nil)
	analysis := h.orchestrator.Analyze(sipflow.Message{
		Payload: payload, Envelope: envelopeForHunterPacket(pkt), ParseOptions: opts,
		FilterConfigured: true, DirectMatch: directMatch,
		Match: func(event sharedsip.Event) bool {
			return h.appFilter == nil && containsUserInHeaders(event.Headers)
		},
		Validate: func(event sharedsip.Event) error {
			return ValidateCallIDForSecurity(event.CallID)
		},
	})
	if analysis.Stage.Outcome != pipeline.OutcomeAccepted {
		return false
	}
	result, callID := analysis.SIP, analysis.SIP.CallID

	// Create call locally for TUI display (before filter check)
	// This ensures the TUI shows all calls, not just matched ones
	call := h.tracker.GetOrCreateCall(callID, linkType)
	if call != nil {
		// Update call state based on SIP method
		call.SetCallInfoState(result.Method)
	}

	// Extract SIP metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              result.From,
		To:                result.To,
		FromTag:           result.FromTag,
		ToTag:             result.ToTag,
		PAssertedIdentity: result.PAssertedIdentity,
		Method:            result.Method,
		CSeqMethod:        result.CSeqMethod,
		ResponseCode:      uint32(result.ResponseCode),
		SDPBody:           string(result.SDP),
	}

	// Buffer the SIP packet with link type for proper PCAP writing.
	// Returns true once the call is matched, from which point every SIP packet
	// of the call is forwarded directly instead of buffered.
	wasMatched := h.bufferMgr.IsCallMatched(callID)
	if !wasMatched {
		h.cacheAnalysis(callID, analysis)
	}
	alreadyMatched := h.bufferMgr.AddSIPPacket(callID, packet, metadata, interfaceName, pkt.LinkType)

	hasSDP := BytesContains(result.SDP, []byte("m=audio"))
	method := metadata.Method

	if alreadyMatched {
		h.orchestrator.Dispatch(analysis)

		// A re-INVITE or delayed answer can move the media ports.
		if hasSDP {
			h.tracker.ExtractPortFromSDP(metadata.SDPBody, callID)
		}
		return true
	}

	// Call termination for a call that never matched: nothing to correlate it
	// with downstream, so discard rather than buffer it.
	if method == "BYE" || method == "CANCEL" {
		h.discardAnalyses(callID)
		logger.Debug("UDP call termination message for untracked call, discarding",
			"call_id", SanitizeCallIDForLogging(callID),
			"method", method)
		return false
	}

	// Check filter if we have SDP (INVITE or 200 OK with m=audio)
	if hasSDP {
		// Make the exact SDP endpoints visible to the shared authoritative
		// resolver before any media can be stamped or forwarded.
		h.tracker.ExtractPortFromSDP(metadata.SDPBody, callID)
		// Use callback-based filter check for flexible handling
		// Note: 'packet' is captured by the closure for ApplicationFilter matching
		matched := h.bufferMgr.CheckFilterWithCallback(
			callID,
			// Analyze already applied direct or sticky call-level selection. Do not
			// re-run a message-only filter against the SDP packet and lose an
			// identity that appeared only on the earlier INVITE.
			func(*CallMetadata) bool { return true },
			func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
				// Forward all buffered packets to processor
				h.forwardBufferedPackets(callID, packets, h.takeAnalyses(callID), metadata, interfaceName, linkType)

				// Extract RTP ports from SDP for future RTP association
				h.tracker.ExtractPortFromSDP(metadata.SDPBody, callID)
			},
		)

		if matched {
			logger.Info("UDP SIP call matched filter, packets forwarded",
				"call_id", SanitizeCallIDForLogging(callID),
				"from", metadata.From,
				"to", metadata.To)
		} else {
			logger.Debug("UDP SIP call filtered out",
				"call_id", SanitizeCallIDForLogging(callID))
		}

		return matched
	}

	// SIP packet buffered, waiting for SDP to check filter
	return false
}

// sipPacketMetadata builds the protobuf metadata carried alongside a forwarded
// SIP packet, so the processor can correlate it with the rest of the dialog.
func sipPacketMetadata(callID string, metadata *CallMetadata) *data.PacketMetadata {
	return &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          extractUserFromSIPURI(metadata.From),
			ToUser:            extractUserFromSIPURI(metadata.To),
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           extractFullSIPURI(metadata.From),
			ToUri:             extractFullSIPURI(metadata.To),
			Method:            metadata.Method,
			CseqMethod:        metadata.CSeqMethod,
			ResponseCode:      metadata.ResponseCode,
			PAssertedIdentity: metadata.PAssertedIdentity,
		},
	}
}

// handleRTPPacket processes a potential RTP packet with buffering
func (h *UDPPacketHandler) handleRTPPacket(pkt capture.PacketInfo, layer *layers.UDP) bool {
	packet := pkt.Packet
	interfaceName := pkt.Interface
	dstPort := strconv.Itoa(int(layer.DstPort))
	srcPort := strconv.Itoa(int(layer.SrcPort))

	// Extract IP addresses for IP:PORT endpoint lookups
	var dstIP, srcIP string
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		dstIP = netLayer.NetworkFlow().Dst().String()
		srcIP = netLayer.NetworkFlow().Src().String()
	}

	resolution := h.tracker.ResolveMediaPacket(packet)
	var directMatched bool
	var directFilterIDs []string
	if filter, ok := h.appFilter.(packetLevelFilterWithIDs); ok {
		directMatched, directFilterIDs = filter.MatchPacketLevelWithIDs(packet)
	}
	if resolution.Status != callregistry.MediaResolved {
		// Ambiguous or unresolved media cannot inherit identity selection, but a
		// direct packet-level IP/CIDR match remains authoritative on its own.
		if directMatched {
			h.forwardRTPPacket("", packet, layer, interfaceName, pkt.LinkType, directFilterIDs, nil)
			return true
		}
		return false
	}
	bufCallID := resolution.CallID
	if directMatched {
		// Direct evidence selects this packet independently. Do not also place it
		// in the call buffer, where a later identity decision could forward it a
		// second time under different provenance.
		h.forwardRTPPacket(bufCallID, packet, layer, interfaceName, pkt.LinkType, directFilterIDs, nil)
		return true
	}

	// Buffer only after the same resolved call owns one of these exact endpoints.
	shouldForward, accepted := h.bufferMgr.AddRTPPacketForEndpoints(
		bufCallID,
		srcIP+":"+srcPort,
		dstIP+":"+dstPort,
		packet,
	)
	if !accepted {
		return false
	}

	if shouldForward {
		// Call already matched, forward immediately with RTP metadata
		h.forwardRTPPacket(bufCallID, packet, layer, interfaceName, pkt.LinkType, directFilterIDs, nil)
		return true
	}

	// Packet is buffered, waiting for filter decision
	return false
}

// forwardBufferedPackets forwards all buffered packets for a matched call
func (h *UDPPacketHandler) forwardBufferedPackets(callID string, packets []gopacket.Packet, analyses []sipflow.ProcessResult, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
	// Forward all buffered packets (SIP + RTP) with appropriate metadata
	sipIndex := 0
	for _, pkt := range packets {
		// Check if this is an RTP packet by looking for UDP layer
		var packetMetadata *data.PacketMetadata

		if udpLayer := pkt.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp := udpLayer.(*layers.UDP)
			payload := udp.Payload

			// Try to parse as RTP (minimum 12 bytes, version 2)
			if len(payload) >= 12 {
				version := (payload[0] >> 6) & 0x03
				if version == 2 {
					// This is an RTP packet - extract RTP metadata
					payloadType := payload[1] & 0x7F
					sequence := uint32(payload[2])<<8 | uint32(payload[3])
					timestamp := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
					ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

					packetMetadata = &data.PacketMetadata{
						Sip: &data.SIPMetadata{
							CallId: callID,
						},
						Rtp: &data.RTPMetadata{
							Ssrc:        ssrc,
							PayloadType: uint32(payloadType),
							Sequence:    sequence,
							Timestamp:   timestamp,
						},
					}
				}
			}
		}

		// SIP packets re-enter the shared parser/selection path at release time so
		// every buffered message gets its own typed result and sink outcome.
		if packetMetadata == nil {
			if sipIndex >= len(analyses) {
				continue
			}
			analysis := analyses[sipIndex]
			sipIndex++
			if analysis.Stage.Outcome == pipeline.OutcomeAccepted {
				h.orchestrator.Dispatch(analysis)
			}
			continue
		}

		if err := h.forwarder.ForwardPacketWithMetadata(pkt, packetMetadata, interfaceName, linkType); err != nil {
			logger.Error("Failed to forward buffered UDP packet",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
		}
	}

	logger.Debug("Forwarded buffered UDP packets",
		"call_id", SanitizeCallIDForLogging(callID),
		"packet_count", len(packets))
}

// forwardRTPPacket forwards a single RTP packet immediately (call already matched)
func (h *UDPPacketHandler) forwardRTPPacket(callID string, packet gopacket.Packet, layer *layers.UDP, interfaceName string, linkType layers.LinkType, directFilterIDs, inheritedFilterIDs []string) {
	// Try to extract RTP header for metadata
	var pbMetadata *data.PacketMetadata

	payload := layer.Payload
	if len(payload) >= 12 { // Minimum RTP header size
		// Extract RTP header fields (basic validation)
		version := (payload[0] >> 6) & 0x03
		if version == 2 { // RTP version 2
			payloadType := payload[1] & 0x7F
			sequence := uint32(payload[2])<<8 | uint32(payload[3])
			timestamp := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
			ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

			pbMetadata = &data.PacketMetadata{
				// Include RTP metadata for quality calculations
				Rtp: &data.RTPMetadata{
					Ssrc:        ssrc,
					PayloadType: uint32(payloadType),
					Sequence:    sequence,
					Timestamp:   timestamp,
				},
			}
			if callID != "" {
				pbMetadata.Sip = &data.SIPMetadata{CallId: callID}
			}
		}
	}

	// Forward with RTP metadata if available
	if err := forwardPacketWithFilterProvenance(h.forwarder, packet, pbMetadata, interfaceName, linkType, directFilterIDs, inheritedFilterIDs); err != nil {
		logger.Error("Failed to forward RTP packet",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err)
	}
}
