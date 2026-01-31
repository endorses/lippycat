//go:build tap || all

package voip

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/google/gopacket"
)

// TapTCPHandler handles SIP messages for tap mode (lc tap voip).
// It extracts SIP metadata and sends processed TCP packets to a channel
// for integration with LocalSource's batch processing.
type TapTCPHandler struct {
	// packetChan receives TCP packets with metadata for batch processing
	packetChan chan<- source.InjectedPacket
	// appFilter is optional for proper filter matching
	appFilter ApplicationFilter
}

// NewTapTCPHandler creates a handler for tap mode TCP SIP processing.
// The packetChan receives TCP packets with metadata when SIP messages are matched.
func NewTapTCPHandler(packetChan chan<- source.InjectedPacket) *TapTCPHandler {
	return &TapTCPHandler{
		packetChan: packetChan,
	}
}

// SetApplicationFilter sets the application filter for proper filter matching.
// When set, this filter is used instead of the legacy sipusers.IsSurveiled() check.
func (h *TapTCPHandler) SetApplicationFilter(filter ApplicationFilter) {
	h.appFilter = filter
}

// HandleSIPMessage processes a complete SIP message for tap mode.
// srcEndpoint and dstEndpoint are in "IP:port" format (e.g., "192.168.1.1:5060").
// netFlow is used for TCP packet buffer lookup.
func (h *TapTCPHandler) HandleSIPMessage(sipMessage []byte, callID string, srcEndpoint, dstEndpoint string, netFlow gopacket.Flow) bool {
	if callID == "" {
		discardTCPBufferedPackets(netFlow)
		return false
	}

	// Parse SIP headers
	headers, body := parseSipHeaders(sipMessage)

	// Detect SIP method
	method := detectSipMethod(string(sipMessage))

	// Check if this call matches filters
	if !h.matchesFilter(netFlow, headers) {
		// Call doesn't match filter - discard buffered TCP packets
		discardTCPBufferedPackets(netFlow)
		logger.Debug("TCP SIP call filtered out (tap mode)",
			"call_id", SanitizeCallIDForLogging(callID),
			"flow", srcEndpoint+"->"+dstEndpoint)
		return false
	}

	// Call matched! Get buffered TCP packets
	bufferedPackets := getTCPBufferedPackets(netFlow)
	if len(bufferedPackets) == 0 {
		logger.Warn("TCP SIP matched but no buffered packets",
			"call_id", SanitizeCallIDForLogging(callID))
		return false
	}

	logger.Info("TCP SIP call matched filter (tap mode), processing",
		"call_id", SanitizeCallIDForLogging(callID),
		"from", headers["from"],
		"to", headers["to"],
		"method", method,
		"buffered_packets", len(bufferedPackets))

	// Create protobuf metadata for SIP
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId:            callID,
			FromUser:          extractUserFromSIPURI(headers["from"]),
			ToUser:            extractUserFromSIPURI(headers["to"]),
			FromTag:           extractTagFromHeader(headers["from"]),
			ToTag:             extractTagFromHeader(headers["to"]),
			FromUri:           extractFullSIPURI(headers["from"]),
			ToUri:             extractFullSIPURI(headers["to"]),
			Method:            method,
			ResponseCode:      extractSipResponseCode(sipMessage),
			PAssertedIdentity: headers["p-asserted-identity"],
		},
	}

	// Extract RTP ports from SDP for future RTP packet association
	if body != "" {
		ExtractPortFromSdp(body, callID)
	}

	// Send buffered TCP packets with metadata through the channel
	for _, pkt := range bufferedPackets {
		select {
		case h.packetChan <- source.InjectedPacket{PacketInfo: pkt, Metadata: pbMetadata}:
			// Sent successfully
		default:
			// Channel full - log warning but continue
			logger.Warn("TCP packet channel full, dropping packet",
				"call_id", SanitizeCallIDForLogging(callID))
		}
	}

	return true
}

// matchesFilter checks if a TCP SIP call matches any configured filter.
// Uses ApplicationFilter if available, falls back to legacy containsUserInHeaders().
func (h *TapTCPHandler) matchesFilter(netFlow gopacket.Flow, headers map[string]string) bool {
	// Use ApplicationFilter if available
	if h.appFilter != nil {
		bufferedPackets := getTCPBufferedPackets(netFlow)
		if len(bufferedPackets) > 0 {
			// Put packets back since we just want to check filter
			for _, pkt := range bufferedPackets {
				BufferTCPPacket(netFlow, pkt)
			}
			// Use the first buffered packet for filter matching
			return h.appFilter.MatchPacket(bufferedPackets[0].Packet)
		}
		logger.Debug("TCP SIP: No buffered packets for ApplicationFilter, falling back to legacy filter")
	}

	// Legacy fallback: use sipusers.IsSurveiled() via containsUserInHeaders()
	return containsUserInHeaders(headers)
}
