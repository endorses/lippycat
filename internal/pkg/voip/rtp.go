package voip

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// portToCallID is now managed by the CallTracker

func ExtractPortFromSdp(sdpBody string, callID string) {
	// Extract all RTP ports from SDP body (supports multi-stream calls)
	ports := extractAllRTPPorts(sdpBody)

	if len(ports) == 0 {
		return
	}

	// Register all ports with the CallTracker
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	for _, port := range ports {
		tracker.portToCallID[port] = callID
		logger.Debug("Registered RTP port mapping",
			"port", port,
			"call_id", SanitizeCallIDForLogging(callID))
	}
}

// extractAllRTPPorts extracts all RTP ports from SDP body
// Supports multi-stream calls (conference calls, multiple audio streams)
func extractAllRTPPorts(sdp string) []string {
	ports := make([]string, 0, 2)

	// Look for m=audio lines
	// Format: m=audio <port> RTP/AVP <payload_types>
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Check for m=audio
		if strings.HasPrefix(line, "m=audio ") {
			// Extract port (second field)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port := fields[1]
				// Validate port
				if isValidPort(port) {
					ports = append(ports, port)
				}
			}
		}
	}

	return ports
}

func IsTracked(packet gopacket.Packet) bool {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return false
	}
	dst := transportLayer.TransportFlow().Dst().String()
	src := transportLayer.TransportFlow().Src().String()
	tracker := getTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()
	_, dstOk := tracker.portToCallID[dst]
	_, srcOk := tracker.portToCallID[src]
	return dstOk || srcOk
}

func GetCallIDForPacket(packet gopacket.Packet) string {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return ""
	}
	dst := transportLayer.TransportFlow().Dst().String()
	src := transportLayer.TransportFlow().Src().String()
	tracker := getTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	// Check both destination and source ports
	if callID, ok := tracker.portToCallID[dst]; ok {
		return callID
	}
	if callID, ok := tracker.portToCallID[src]; ok {
		return callID
	}
	return ""
}

// isValidPort validates that a string represents a valid UDP/TCP port number
func isValidPort(portStr string) bool {
	if portStr == "" {
		return false
	}

	// Parse as integer to validate format and range
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return false
	}

	// Valid port range is 1-65535 (0 is reserved)
	if port < 1 || port > 65535 {
		return false
	}

	return true
}
