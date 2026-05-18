package processor

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// detectRTP checks if a UDP packet is RTP for a tracked call.
func (p *Processor) detectRTP(packet gopacket.Packet, udp *layers.UDP) *ProcessResult {
	// Check if the destination or source port is tracked
	// Use numeric port values to avoid service name suffixes (e.g., "20000(dnp)")
	dstPort := strconv.Itoa(int(udp.DstPort))
	srcPort := strconv.Itoa(int(udp.SrcPort))

	// Extract IP addresses for IP:PORT endpoint lookups
	var dstIP, srcIP string
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		dstIP = netLayer.NetworkFlow().Dst().String()
		srcIP = netLayer.NetworkFlow().Src().String()
	}

	// Match only on IP:PORT endpoints. Port-only matching is intentionally
	// disabled — on busy networks ports get reused across unrelated calls and
	// a port-only fallback stamps the wrong CallID on RTP from a different
	// host. SDP carries the c= connection address; we require it.
	var callID string
	var exists bool

	if dstIP != "" {
		callID, exists = p.getCallIDForPort(dstIP + ":" + dstPort)
	}
	if !exists && srcIP != "" {
		callID, exists = p.getCallIDForPort(srcIP + ":" + srcPort)
	}

	if !exists {
		return nil
	}

	// Validate RTP header
	payload := udp.Payload
	if !isValidRTP(payload) {
		return nil
	}

	// Extract RTP header fields
	rtpMeta := extractRTPMetadata(payload)

	// Build protobuf metadata
	pbMetadata := &data.PacketMetadata{
		Sip: &data.SIPMetadata{
			CallId: callID,
		},
		Rtp: rtpMeta,
	}

	return &ProcessResult{
		IsVoIP:     true,
		PacketType: PacketTypeRTP,
		CallID:     callID,
		Metadata:   pbMetadata,
	}
}

// isValidRTP checks if a payload looks like a valid RTP packet.
func isValidRTP(payload []byte) bool {
	// Minimum RTP header size is 12 bytes
	if len(payload) < 12 {
		return false
	}

	// Check RTP version (must be 2)
	version := (payload[0] >> 6) & 0x03
	return version == 2
}

// extractRTPMetadata extracts RTP header fields from payload.
func extractRTPMetadata(payload []byte) *data.RTPMetadata {
	if len(payload) < 12 {
		return nil
	}

	payloadType := payload[1] & 0x7F
	sequence := uint32(payload[2])<<8 | uint32(payload[3])
	timestamp := uint32(payload[4])<<24 | uint32(payload[5])<<16 | uint32(payload[6])<<8 | uint32(payload[7])
	ssrc := uint32(payload[8])<<24 | uint32(payload[9])<<16 | uint32(payload[10])<<8 | uint32(payload[11])

	return &data.RTPMetadata{
		Ssrc:        ssrc,
		PayloadType: uint32(payloadType),
		Sequence:    sequence,
		Timestamp:   timestamp,
	}
}

// extractRTPPortsFromSDP extracts IP:PORT RTP endpoints from an SDP body.
// Media lines without an accompanying c= connection address are skipped —
// port-only entries cause false correlations on busy networks where the same
// RTP port is reused across unrelated calls.
func extractRTPPortsFromSDP(sdp string) []string {
	endpoints := make([]string, 0, 4)

	// First, extract the session-level connection address (c= line)
	// Can be overridden per media line
	sessionIP := ""
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				sessionIP = fields[2]
				break
			}
		}
	}

	currentIP := sessionIP
	for _, line := range lines {
		line = strings.TrimSpace(line)

		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				currentIP = fields[2]
			}
			continue
		}

		// Format: m=audio <port> RTP/AVP <payload_types>
		if strings.HasPrefix(line, "m=audio ") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port := fields[1]
				if isValidPort(port) && currentIP != "" {
					endpoints = append(endpoints, currentIP+":"+port)
				}
			}
		}
	}

	return endpoints
}

// isValidPort validates that a string represents a valid port number.
func isValidPort(portStr string) bool {
	if portStr == "" {
		return false
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	return port >= 1 && port <= 65535
}
