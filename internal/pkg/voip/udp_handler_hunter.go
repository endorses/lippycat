//go:build hunter || all
// +build hunter all

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

	// Parse headers for metadata first
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

	// Create call locally for TUI display (before filter check)
	// This ensures the TUI shows all calls, not just matched ones
	call := GetOrCreateCall(callID, linkType)
	if call != nil {
		// Update call state based on SIP method
		method := detectSipMethod(string(payload))
		call.SetCallInfoState(method)
	}

	// Check if the SIP message matches our filter (for forwarding decision)
	if !handleSipMessage(payload, linkType) {
		return false
	}

	// Extract SIP metadata
	metadata := &CallMetadata{
		CallID:            callID,
		From:              headers["from"],
		To:                headers["to"],
		FromTag:           extractTagFromHeader(headers["from"]),
		ToTag:             extractTagFromHeader(headers["to"]),
		PAssertedIdentity: headers["p-asserted-identity"],
		Method:            detectSipMethod(string(payload)),
		ResponseCode:      extractSipResponseCode(payload),
		SDPBody:           body,
	}

	// Buffer the SIP packet with link type for proper PCAP writing
	h.bufferMgr.AddSIPPacket(callID, packet, metadata, interfaceName, pkt.LinkType)

	// Check if this is a call termination message (BYE or CANCEL)
	method := metadata.Method
	if method == "BYE" || method == "CANCEL" {
		// For termination messages, only forward if call is already tracked
		if h.bufferMgr != nil && h.bufferMgr.IsCallMatched(callID) {
			// Create protobuf metadata for termination message
			pbMetadata := &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:            callID,
					FromUser:          extractUserFromSIPURI(metadata.From),
					ToUser:            extractUserFromSIPURI(metadata.To),
					FromTag:           metadata.FromTag,
					ToTag:             metadata.ToTag,
					FromUri:           extractFullSIPURI(metadata.From),
					ToUri:             extractFullSIPURI(metadata.To),
					Method:            metadata.Method,
					ResponseCode:      metadata.ResponseCode,
					PAssertedIdentity: metadata.PAssertedIdentity,
				},
			}

			// Forward termination message immediately
			if err := h.forwarder.ForwardPacketWithMetadata(packet, pbMetadata, interfaceName, pkt.LinkType); err != nil {
				logger.Error("Failed to forward UDP call termination packet",
					"call_id", SanitizeCallIDForLogging(callID),
					"method", method,
					"error", err)
			} else {
				logger.Info("Forwarded UDP call termination packet",
					"call_id", SanitizeCallIDForLogging(callID),
					"method", method)
			}
			return true
		}
		// Call not tracked, discard termination message
		logger.Debug("UDP call termination message for untracked call, discarding",
			"call_id", SanitizeCallIDForLogging(callID),
			"method", method)
		return false
	}

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
			func(callID string, packets []gopacket.Packet, metadata *CallMetadata, interfaceName string, linkType layers.LinkType) {
				// Forward all buffered packets to processor
				h.forwardBufferedPackets(callID, packets, metadata, interfaceName, linkType)

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
func (h *UDPPacketHandler) handleRTPPacket(pkt capture.PacketInfo, layer *layers.UDP) bool {
	packet := pkt.Packet
	interfaceName := pkt.Interface
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
			packetMetadata = &data.PacketMetadata{
				Sip: &data.SIPMetadata{
					CallId:            callID,
					FromUser:          extractUserFromSIPURI(metadata.From),
					ToUser:            extractUserFromSIPURI(metadata.To),
					FromTag:           metadata.FromTag,
					ToTag:             metadata.ToTag,
					FromUri:           extractFullSIPURI(metadata.From),
					ToUri:             extractFullSIPURI(metadata.To),
					Method:            metadata.Method,
					ResponseCode:      metadata.ResponseCode,
					PAssertedIdentity: metadata.PAssertedIdentity,
				},
			}
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
