//go:build hunter || all

package voip

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
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
	selectionPolicy callregistry.SelectionPolicy
}

// NewUDPPacketHandler creates a UDP packet handler for hunter mode
func NewUDPPacketHandler(tracker *CallTracker, forwarder PacketForwarder, bufferMgr *BufferManager) *UDPPacketHandler {
	return &UDPPacketHandler{
		tracker:         tracker,
		forwarder:       forwarder,
		bufferMgr:       bufferMgr,
		selectionPolicy: callregistry.StickySelectionPolicy{},
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *UDPPacketHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

func (h *UDPPacketHandler) SetSelectionPolicy(policy callregistry.SelectionPolicy) {
	if policy != nil {
		h.selectionPolicy = policy
	}
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
	event, err := sharedsip.Parse(payload, opts)
	if err != nil || event.CallID == "" {
		return false
	}
	headers, callID := event.Headers, event.CallID

	// Validate Call-ID for security
	if err := ValidateCallIDForSecurity(callID); err != nil {
		logger.Warn("Malicious Call-ID detected and rejected",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err,
			"source", "hunter_udp")
		return false
	}

	// Create call locally for TUI display (before filter check)
	// This ensures the TUI shows all calls, not just matched ones
	call := h.tracker.GetOrCreateCall(callID, linkType)
	if call != nil {
		// Update call state based on SIP method
		call.SetCallInfoState(event.Method)
	}

	// Check if the SIP message matches our filter (for forwarding decision)
	// Use ApplicationFilter if available (supports phone_number, sip_user, etc.)
	// Fall back to legacy containsUserInHeaders() if no ApplicationFilter is set
	directMatch := h.matchesFilter(packet, headers)
	previouslySelected := h.bufferMgr != nil && h.bufferMgr.IsCallMatched(callID)
	if !h.selectionPolicy.Select(callregistry.SelectionInput{
		FilterConfigured:   true,
		DirectMatch:        directMatch,
		PreviouslySelected: previouslySelected,
	}) {
		return false
	}

	// Extract SIP metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              headers["from"],
		To:                headers["to"],
		FromTag:           event.FromTag,
		ToTag:             event.ToTag,
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            event.Method,
		CSeqMethod:        event.CSeqMethod,
		ResponseCode:      uint32(event.ResponseCode),
		SDPBody:           string(event.SDP),
	}

	// Buffer the SIP packet with link type for proper PCAP writing.
	// Returns true once the call is matched, from which point every SIP packet
	// of the call is forwarded directly instead of buffered.
	alreadyMatched := h.bufferMgr.AddSIPPacket(callID, packet, metadata, interfaceName, pkt.LinkType)

	hasSDP := BytesContains(event.SDP, []byte("m=audio"))
	method := metadata.Method

	if alreadyMatched {
		// Call already passed the filter: forward this packet now, whether or
		// not it carries SDP. This covers in-dialog signalling (100 Trying,
		// 180 Ringing, ACK, BYE/CANCEL, 4xx/5xx) that has no SDP body.
		if err := h.forwarder.ForwardPacketWithMetadata(packet, sipPacketMetadata(callID, metadata), interfaceName, pkt.LinkType); err != nil {
			logger.Error("Failed to forward UDP SIP packet for matched call",
				"call_id", SanitizeCallIDForLogging(callID),
				"method", method,
				"error", err)
		}

		// A re-INVITE or delayed answer can move the media ports.
		if hasSDP {
			h.tracker.ExtractPortFromSDP(metadata.SDPBody, callID)
		}
		return true
	}

	// Call termination for a call that never matched: nothing to correlate it
	// with downstream, so discard rather than buffer it.
	if method == "BYE" || method == "CANCEL" {
		logger.Debug("UDP call termination message for untracked call, discarding",
			"call_id", SanitizeCallIDForLogging(callID),
			"method", method)
		return false
	}

	// Check filter if we have SDP (INVITE or 200 OK with m=audio)
	if hasSDP {
		// Use callback-based filter check for flexible handling
		// Note: 'packet' is captured by the closure for ApplicationFilter matching
		matched := h.bufferMgr.CheckFilterWithCallback(
			callID,
			func(m *CallMetadata) bool {
				// Use ApplicationFilter if available (supports phone_number, sip_user, etc.)
				// Falls back to legacy containsUserInHeaders() if no filter is set
				return h.matchesFilterWithMetadata(packet, m)
			},
			func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
				// Forward all buffered packets to processor
				h.forwardBufferedPackets(callID, packets, metadata, interfaceName, linkType)

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
	dstPort := layer.DstPort.String()
	srcPort := layer.SrcPort.String()

	// Extract IP addresses for IP:PORT endpoint lookups
	var dstIP, srcIP string
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		dstIP = netLayer.NetworkFlow().Dst().String()
		srcIP = netLayer.NetworkFlow().Src().String()
	}

	// Try to get CallID from buffer manager's port mapping
	// Check IP:PORT endpoints first (more specific), then fall back to port-only
	var bufCallID string
	var exists bool

	if dstIP != "" {
		bufCallID, exists = h.bufferMgr.GetCallIDForRTPPort(dstIP + ":" + dstPort)
	}
	if !exists && srcIP != "" {
		bufCallID, exists = h.bufferMgr.GetCallIDForRTPPort(srcIP + ":" + srcPort)
	}
	// Fall back to port-only lookups
	if !exists {
		bufCallID, exists = h.bufferMgr.GetCallIDForRTPPort(dstPort)
	}
	if !exists {
		bufCallID, exists = h.bufferMgr.GetCallIDForRTPPort(srcPort)
	}

	if !exists {
		// Not a tracked RTP port
		return false
	}

	// This RTP packet belongs to a call we're buffering or tracking
	// Use IP:PORT for the port parameter if available for more precise matching
	portKey := dstPort
	if dstIP != "" {
		portKey = dstIP + ":" + dstPort
	}
	shouldForward := h.bufferMgr.AddRTPPacket(bufCallID, portKey, packet)

	if shouldForward {
		// Call already matched, forward immediately with RTP metadata
		h.forwardRTPPacket(bufCallID, packet, layer, interfaceName, pkt.LinkType)
		return true
	}

	// Packet is buffered, waiting for filter decision
	return false
}

// forwardBufferedPackets forwards all buffered packets for a matched call
func (h *UDPPacketHandler) forwardBufferedPackets(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
	// Forward all buffered packets (SIP + RTP) with appropriate metadata
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

		// If not RTP, use SIP metadata only
		if packetMetadata == nil {
			packetMetadata = sipPacketMetadata(callID, metadata)
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
func (h *UDPPacketHandler) forwardRTPPacket(callID string, packet gopacket.Packet, layer *layers.UDP, interfaceName string, linkType layers.LinkType) {
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
				// Include SIP metadata with CallID so processor can associate RTP with call
				Sip: &data.SIPMetadata{
					CallId: callID,
				},
				// Include RTP metadata for quality calculations
				Rtp: &data.RTPMetadata{
					Ssrc:        ssrc,
					PayloadType: uint32(payloadType),
					Sequence:    sequence,
					Timestamp:   timestamp,
				},
			}
		}
	}

	// Forward with RTP metadata if available
	if err := h.forwarder.ForwardPacketWithMetadata(packet, pbMetadata, interfaceName, linkType); err != nil {
		logger.Error("Failed to forward RTP packet",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err)
	}
}
