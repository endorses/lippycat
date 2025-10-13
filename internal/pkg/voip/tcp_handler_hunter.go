//go:build hunter || all
// +build hunter all

package voip

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// PacketForwarder is an interface for forwarding packets (implemented by Hunter)
type PacketForwarder interface {
	// ForwardPacketWithMetadata forwards a packet with embedded metadata
	ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata) error
}

// HunterForwardHandler handles SIP messages for hunter mode (lc hunt voip)
// It checks filters, extracts metadata, and forwards matched calls to processor
type HunterForwardHandler struct {
	forwarder PacketForwarder
	bufferMgr *BufferManager
}

// NewHunterForwardHandler creates a handler for hunter packet forwarding
func NewHunterForwardHandler(forwarder PacketForwarder, bufferMgr *BufferManager) *HunterForwardHandler {
	return &HunterForwardHandler{
		forwarder: forwarder,
		bufferMgr: bufferMgr,
	}
}

// HandleSIPMessage processes a complete SIP message for hunter forwarding
func (h *HunterForwardHandler) HandleSIPMessage(sipMessage []byte, callID string, flow gopacket.Flow) bool {
	if callID == "" {
		return false
	}

	// Parse SIP headers
	headers, body := parseSipHeaders(sipMessage)

	// Check if this call matches tracked users
	if !containsUserInHeaders(headers) {
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
		From:              headers["from"],
		To:                headers["to"],
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            detectSipMethod(string(sipMessage)),
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
			FromUser:          metadata.From,
			ToUser:            metadata.To,
			Method:            metadata.Method,
			PAssertedIdentity: metadata.PAssertedIdentity,
		},
	}

	// Forward all buffered TCP packets with metadata embedded
	for _, pkt := range bufferedPackets {
		if err := h.forwarder.ForwardPacketWithMetadata(pkt, pbMetadata); err != nil {
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
	if h.bufferMgr != nil {
		h.bufferMgr.AddSIPPacket(callID, nil, metadata)
		h.bufferMgr.CheckFilterWithCallback(callID,
			func(m *CallMetadata) bool { return true }, // already matched
			nil, // no callback needed - we already forwarded
		)
	}

	return true
}
