//go:build hunter || all
// +build hunter all

package voip

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// PacketForwarder is an interface for forwarding packets (implemented by Hunter)
type PacketForwarder interface {
	// ForwardPacketWithMetadata forwards a packet with embedded metadata, interface name, and link type
	ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, interfaceName string, linkType layers.LinkType) error
}

// HunterForwardHandler handles SIP messages for hunter mode (lc hunt voip)
// It checks filters, extracts metadata, and forwards matched calls to processor
type HunterForwardHandler struct {
	forwarder PacketForwarder
	bufferMgr *BufferManager
	appFilter ApplicationFilter // Optional: for proper filter matching (supports phone_number, sip_user, etc.)
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	return &HunterForwardHandler{
		forwarder: forwarder,
		bufferMgr: bufferMgr,
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
// This supports all filter types including phone_number, sip_user, sipuri, ip_address, etc.
func (h *HunterForwardHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

// HandleSIPMessage processes a complete SIP message for hunter forwarding
func (h *HunterForwardHandler) HandleSIPMessage(sipMessage []byte, callID string, flow gopacket.Flow) bool {
	if callID == "" {
		return false
	}

	// Parse SIP headers
	headers, body := parseSipHeaders(sipMessage)

	// Detect SIP method
	method := detectSipMethod(string(sipMessage))

	// Check if this is a call termination message (BYE or CANCEL)
	if method == "BYE" || method == "CANCEL" {
		// For termination messages, only forward if call is already tracked
		if h.bufferMgr != nil && h.bufferMgr.IsCallMatched(callID) {
			metadata := &CallMetadata{
				CallID:            callID,
				From:              extractUserFromSIPURI(headers["from"]),
				To:                extractUserFromSIPURI(headers["to"]),
				FromTag:           extractTagFromHeader(headers["from"]),
				ToTag:             extractTagFromHeader(headers["to"]),
				PAssertedIdentity: headers["p-asserted-identity"],
				Method:            method,
				ResponseCode:      extractSipResponseCode(sipMessage),
				SDPBody:           body,
			}

			// Get buffered TCP packets for this message
			bufferedPackets := getTCPBufferedPackets(flow)

			pbMetadata := &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:            callID,
					FromUser:          metadata.From, // username only
					ToUser:            metadata.To,   // username only
					FromTag:           metadata.FromTag,
					ToTag:             metadata.ToTag,
					FromUri:           extractFullSIPURI(headers["from"]),
					ToUri:             extractFullSIPURI(headers["to"]),
					Method:            metadata.Method,
					ResponseCode:      metadata.ResponseCode,
					PAssertedIdentity: metadata.PAssertedIdentity,
				},
			}

			// Forward termination message
			for _, pkt := range bufferedPackets {
				if err := h.forwarder.ForwardPacketWithMetadata(pkt.Packet, pbMetadata, pkt.Interface, pkt.LinkType); err != nil {
					logger.Error("Failed to forward TCP call termination packet",
						"call_id", SanitizeCallIDForLogging(callID),
						"method", method,
						"error", err)
				}
			}

			logger.Info("Forwarded TCP call termination packet",
				"call_id", SanitizeCallIDForLogging(callID),
				"method", method)
			return true
		}
		// Call not tracked, discard
		discardTCPBufferedPackets(flow)
		return false
	}

	// Check if this call matches tracked users
	// Use ApplicationFilter if available (supports phone_number, sip_user, etc.)
	// Fall back to legacy containsUserInHeaders() if no ApplicationFilter is set
	if !h.matchesFilter(flow, headers) {
		// Call doesn't match filter - discard buffered TCP packets
		discardTCPBufferedPackets(flow)
		logger.Debug("TCP SIP call filtered out",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", flow.String())
		return false
	}

	// Call matched! Extract metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              extractUserFromSIPURI(headers["from"]),
		To:                extractUserFromSIPURI(headers["to"]),
		FromTag:           extractTagFromHeader(headers["from"]),
		ToTag:             extractTagFromHeader(headers["to"]),
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            method,
		ResponseCode:      extractSipResponseCode(sipMessage),
		SDPBody:           body,
	}

	// Get buffered TCP packets
	bufferedPackets := getTCPBufferedPackets(flow)

	logger.Info("TCP SIP call matched filter, forwarding to processor",
		"call_id", SanitizeCallIDForLogging(callID),
		"from", metadata.From,
		"to", metadata.To,
		"buffered_packets", len(bufferedPackets))

	// Create protobuf metadata for SIP
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          metadata.From, // username only
			ToUser:            metadata.To,   // username only
			FromTag:           metadata.FromTag,
			ToTag:             metadata.ToTag,
			FromUri:           extractFullSIPURI(headers["from"]),
			ToUri:             extractFullSIPURI(headers["to"]),
			Method:            metadata.Method,
			ResponseCode:      metadata.ResponseCode,
			PAssertedIdentity: metadata.PAssertedIdentity,
		},
	}

	// Forward all buffered TCP packets with metadata embedded
	for _, pkt := range bufferedPackets {
		if err := h.forwarder.ForwardPacketWithMetadata(pkt.Packet, pbMetadata, pkt.Interface, pkt.LinkType); err != nil {
			logger.Error("Failed to forward TCP SIP packet",
				"call_id", SanitizeCallIDForLogging(callID),
				"error", err)
		}
	}

	// Extract RTP ports from SDP for future RTP packet association
	if metadata.SDPBody != "" {
		ExtractPortFromSdp(metadata.SDPBody, callID)
	}

	// Register call in buffer manager for RTP buffering
	// Note: TCP handler doesn't track interface names per packet (TCP streams may cross interfaces)
	// Link type defaults to Ethernet; actual packets are forwarded with correct link types above
	if h.bufferMgr != nil {
		h.bufferMgr.AddSIPPacket(callID, nil, metadata, "", layers.LinkTypeEthernet)
		h.bufferMgr.CheckFilterWithCallback(callID,
			func(m *CallMetadata) bool { return true }, // already matched
			nil, // no callback needed - we already forwarded
		)
	}

	return true
}

// matchesFilter checks if a TCP SIP call matches any configured filter.
// Uses ApplicationFilter if available (supports phone_number, sip_user, etc.)
// Falls back to legacy containsUserInHeaders() if no ApplicationFilter is set.
func (h *HunterForwardHandler) matchesFilter(flow gopacket.Flow, headers map[string]string) bool {
	// Use ApplicationFilter if available (Phase 2: proper multi-filter support)
	if h.appFilter != nil {
		// For TCP SIP, we need a packet to pass to ApplicationFilter.
		// Use one of the buffered TCP packets if available.
		bufferedPackets := getTCPBufferedPackets(flow)
		if len(bufferedPackets) > 0 {
			// Use the first buffered packet for filter matching
			// The ApplicationFilter will extract SIP headers from the packet
			return h.appFilter.MatchPacket(bufferedPackets[0].Packet)
		}
		// No buffered packets - fall back to legacy method
		logger.Debug("TCP SIP: No buffered packets for ApplicationFilter, falling back to legacy filter")
	}

	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	// This only supports sip_user filters, not phone_number or other filter types
	return containsUserInHeaders(headers)
}
