package voip

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// portToCallID is now managed by the CallTracker

func ExtractPortFromSdp(sdpBody string, callID string) {
	// Extract all RTP endpoints (IP:port) from SDP body (supports multi-stream calls)
	endpoints := extractAllRTPEndpoints(sdpBody)

	if len(endpoints) == 0 {
		return
	}

	// Register all endpoints with the CallTracker
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	for _, endpoint := range endpoints {
		tracker.portToCallID[endpoint] = callID
		logger.Debug("Registered RTP endpoint mapping",
			"endpoint", endpoint,
			"call_id", SanitizeCallIDForLogging(callID))
	}
}

// extractAllRTPEndpoints extracts all RTP endpoints (IP:port) from SDP body
// Uses the connection address (c= line) combined with media port (m= line)
// Supports multi-stream calls (conference calls, multiple audio streams)
func extractAllRTPEndpoints(sdp string) []string {
	endpoints := make([]string, 0, 2)

	// First, extract the session-level connection address (c= line)
	// Can be overridden per media line
	sessionIP := ""
	lines := strings.Split(sdp, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			// Format: c=IN IP4 <ip> or c=IN IP6 <ip>
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				sessionIP = fields[2]
				break // Use first c= line as session-level
			}
		}
	}

	// Now extract media ports and combine with IP
	currentIP := sessionIP
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Update connection IP if we see a media-level c= line
		if strings.HasPrefix(line, "c=IN IP4 ") || strings.HasPrefix(line, "c=IN IP6 ") {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				currentIP = fields[2]
			}
			continue
		}

		// Check for m=audio
		if strings.HasPrefix(line, "m=audio ") {
			// Extract port (second field)
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				port := fields[1]
				// Validate port
				if isValidPort(port) {
					if currentIP != "" {
						// Register IP:port endpoint
						endpoint := currentIP + ":" + port
						endpoints = append(endpoints, endpoint)
						logger.Debug("Extracted RTP endpoint from SDP",
							"ip", currentIP,
							"port", port,
							"endpoint", endpoint)
					}
					// Also register port-only for backward compatibility
					// (some RTP may come from unexpected IPs due to NAT)
					endpoints = append(endpoints, port)
				}
			}
		}
	}

	return endpoints
}

// extractAllRTPPorts extracts all RTP ports from SDP body (legacy, port-only)
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
	networkLayer := packet.NetworkLayer()

	dstPort := transportLayer.TransportFlow().Dst().String()
	srcPort := transportLayer.TransportFlow().Src().String()

	tracker := getTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	// Try IP:PORT lookups first (more specific)
	if networkLayer != nil {
		dstIP := networkLayer.NetworkFlow().Dst().String()
		srcIP := networkLayer.NetworkFlow().Src().String()

		dstEndpoint := dstIP + ":" + dstPort
		srcEndpoint := srcIP + ":" + srcPort

		if _, ok := tracker.portToCallID[dstEndpoint]; ok {
			return true
		}
		if _, ok := tracker.portToCallID[srcEndpoint]; ok {
			return true
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	_, dstOk := tracker.portToCallID[dstPort]
	_, srcOk := tracker.portToCallID[srcPort]
	return dstOk || srcOk
}

func GetCallIDForPacket(packet gopacket.Packet) string {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return ""
	}
	networkLayer := packet.NetworkLayer()

	dstPort := transportLayer.TransportFlow().Dst().String()
	srcPort := transportLayer.TransportFlow().Src().String()

	tracker := getTracker()
	tracker.mu.RLock()
	defer tracker.mu.RUnlock()

	// Try IP:PORT lookups first (more specific)
	if networkLayer != nil {
		dstIP := networkLayer.NetworkFlow().Dst().String()
		srcIP := networkLayer.NetworkFlow().Src().String()

		dstEndpoint := dstIP + ":" + dstPort
		srcEndpoint := srcIP + ":" + srcPort

		if callID, ok := tracker.portToCallID[dstEndpoint]; ok {
			return callID
		}
		if callID, ok := tracker.portToCallID[srcEndpoint]; ok {
			return callID
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	if callID, ok := tracker.portToCallID[dstPort]; ok {
		return callID
	}
	if callID, ok := tracker.portToCallID[srcPort]; ok {
		return callID
	}
	return ""
}

// CleanupPortMappings removes all port-to-callID mappings for a given callID.
// This should be called when a call ends (after grace period) to prevent
// port collisions with new calls.
func CleanupPortMappings(callID string) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	// Find and remove all port mappings for this callID
	var removed []string
	for key, cid := range tracker.portToCallID {
		if cid == callID {
			removed = append(removed, key)
			delete(tracker.portToCallID, key)
		}
	}

	if len(removed) > 0 {
		logger.Debug("Cleaned up RTP port mappings for ended call",
			"call_id", SanitizeCallIDForLogging(callID),
			"removed_endpoints", len(removed))
	}
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
