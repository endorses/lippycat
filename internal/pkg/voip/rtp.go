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
		// Append to slice, avoiding duplicates (supports B2BUA with shared ports)
		existing := tracker.portToCallID[endpoint]
		alreadyRegistered := false
		for _, cid := range existing {
			if cid == callID {
				alreadyRegistered = true
				break
			}
		}
		if !alreadyRegistered {
			tracker.portToCallID[endpoint] = append(existing, callID)
			logger.Debug("Registered RTP endpoint mapping",
				"endpoint", endpoint,
				"call_id", SanitizeCallIDForLogging(callID),
				"total_calls_on_port", len(tracker.portToCallID[endpoint]))
		}
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

		if callIDs := tracker.portToCallID[dstEndpoint]; len(callIDs) > 0 {
			return true
		}
		if callIDs := tracker.portToCallID[srcEndpoint]; len(callIDs) > 0 {
			return true
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	dstCallIDs := tracker.portToCallID[dstPort]
	srcCallIDs := tracker.portToCallID[srcPort]
	return len(dstCallIDs) > 0 || len(srcCallIDs) > 0
}

// GetCallIDForPacket returns the first call ID associated with a packet's port.
// For B2BUA scenarios where multiple calls share a port, use GetAllCallIDsForPacket.
func GetCallIDForPacket(packet gopacket.Packet) string {
	callIDs := GetAllCallIDsForPacket(packet)
	if len(callIDs) > 0 {
		return callIDs[0]
	}
	return ""
}

// GetAllCallIDsForPacket returns all call IDs associated with a packet's port.
// This supports B2BUA scenarios where multiple call legs share the same RTP port.
func GetAllCallIDsForPacket(packet gopacket.Packet) []string {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil
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

		if callIDs := tracker.portToCallID[dstEndpoint]; len(callIDs) > 0 {
			return callIDs
		}
		if callIDs := tracker.portToCallID[srcEndpoint]; len(callIDs) > 0 {
			return callIDs
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	if callIDs := tracker.portToCallID[dstPort]; len(callIDs) > 0 {
		return callIDs
	}
	if callIDs := tracker.portToCallID[srcPort]; len(callIDs) > 0 {
		return callIDs
	}
	return nil
}

// CleanupPortMappings removes all port-to-callID mappings for a given callID.
// This should be called when a call ends (after grace period) to prevent
// port collisions with new calls.
func CleanupPortMappings(callID string) {
	tracker := getTracker()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()

	// Find and remove this callID from all port mappings
	var removed []string
	for key, callIDs := range tracker.portToCallID {
		for i, cid := range callIDs {
			if cid == callID {
				// Remove this call ID from the slice
				tracker.portToCallID[key] = append(callIDs[:i], callIDs[i+1:]...)
				removed = append(removed, key)
				break
			}
		}
		// Clean up empty slices
		if len(tracker.portToCallID[key]) == 0 {
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
