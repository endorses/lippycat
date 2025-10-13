package voip

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// UDPPacketHandler processes UDP SIP/RTP packets for hunter mode with buffering
type UDPPacketHandler struct {
	forwarder PacketForwarder
	bufferMgr *BufferManager
}

// NewUDPPacketHandler creates a UDP packet handler for hunter mode
func NewUDPPacketHandler(forwarder PacketForwarder, bufferMgr *BufferManager) *UDPPacketHandler {
	return &UDPPacketHandler{
		forwarder: forwarder,
		bufferMgr: bufferMgr,
	}
}

// HandleUDPPacket processes a UDP packet (SIP or RTP) with buffering
func (h *UDPPacketHandler) HandleUDPPacket(pkt capture.PacketInfo, layer *layers.UDP) bool {
	packet := pkt.Packet

	// Handle SIP packets (port 5060)
	if layer.SrcPort == SIPPort || layer.DstPort == SIPPort {
		return h.handleSIPPacket(packet, layer)
	}

	// Handle potential RTP packets
	return h.handleRTPPacket(packet, layer)
}

// handleSIPPacket processes a SIP packet with buffering
func (h *UDPPacketHandler) handleSIPPacket(packet gopacket.Packet, layer *layers.UDP) bool {
	payload := layer.Payload
	if !handleSipMessage(payload) {
		return false
	}

	headers, body := parseSipHeaders(payload)
	callID := headers["call-id"]
	if callID == "" {
		return false
	}

	// Validate Call-ID for security
	if err := ValidateCallIDForSecurity(callID); err != nil {
		logger.Warn("Malicious Call-ID detected and rejected",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err,
			"source", "hunter_udp")
		return false
	}

	// Extract SIP metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              headers["from"],
		To:                headers["to"],
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            detectSipMethod(string(payload)),
		SDPBody:           body,
	}

	// Buffer the SIP packet
	h.bufferMgr.AddSIPPacket(callID, packet, metadata)

	// Check filter if we have SDP (INVITE or 200 OK with m=audio)
	bodyBytes := StringToBytes(body)
	if BytesContains(bodyBytes, []byte("m=audio")) {
		// Use callback-based filter check for flexible handling
		matched := h.bufferMgr.CheckFilterWithCallback(
			callID,
			func(m *CallMetadata) bool {
				// Check if From, To, or P-Asserted-Identity matches tracked users
				return containsUserInHeaders(map[string]string{
					"from":                m.From,
					"to":                  m.To,
					"p-asserted-identity": m.PAssertedIdentity,
				})
			},
			func(callID string, packets []gopacket.Packet, metadata *CallMetadata) {
				// Forward all buffered packets to processor
				h.forwardBufferedPackets(callID, packets, metadata)

				// Extract RTP ports from SDP for future RTP association
				ExtractPortFromSdp(metadata.SDPBody, callID)
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

// handleRTPPacket processes a potential RTP packet with buffering
func (h *UDPPacketHandler) handleRTPPacket(packet gopacket.Packet, layer *layers.UDP) bool {
	dstPort := layer.DstPort.String()
	srcPort := layer.SrcPort.String()

	// Try to get CallID from buffer manager's port mapping
	bufCallID, exists := h.bufferMgr.GetCallIDForRTPPort(dstPort)
	if !exists {
		bufCallID, exists = h.bufferMgr.GetCallIDForRTPPort(srcPort)
	}

	if !exists {
		// Not a tracked RTP port
		return false
	}

	// This RTP packet belongs to a call we're buffering or tracking
	shouldForward := h.bufferMgr.AddRTPPacket(bufCallID, dstPort, packet)

	if shouldForward {
		// Call already matched, forward immediately with RTP metadata
		h.forwardRTPPacket(bufCallID, packet, layer)
		return true
	}

	// Packet is buffered, waiting for filter decision
	return false
}

// forwardBufferedPackets forwards all buffered packets for a matched call
func (h *UDPPacketHandler) forwardBufferedPackets(callID string, packets []gopacket.Packet, metadata *CallMetadata) {
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

	// Forward all buffered packets (SIP + RTP) with metadata
	for _, pkt := range packets {
		if err := h.forwarder.ForwardPacketWithMetadata(pkt, pbMetadata); err != nil {
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
func (h *UDPPacketHandler) forwardRTPPacket(callID string, packet gopacket.Packet, layer *layers.UDP) {
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
	if err := h.forwarder.ForwardPacketWithMetadata(packet, pbMetadata); err != nil {
		logger.Error("Failed to forward RTP packet",
			"call_id", SanitizeCallIDForLogging(callID),
			"error", err)
	}
}
