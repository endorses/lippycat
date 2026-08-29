package voip

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

func (tracker *CallTracker) endpointCallIDs(endpoint string) []string {
	return tracker.registry.CallIDsForEndpoint(endpoint)
}

// ExtractPortFromSDP registers every RTP endpoint advertised by SDP on this tracker.
func (tracker *CallTracker) ExtractPortFromSDP(sdpBody string, callID string) {
	// Extract all RTP endpoints (IP:port) from SDP body (supports multi-stream calls)
	endpoints := extractAllRTPEndpoints(sdpBody)

	if len(endpoints) == 0 {
		return
	}

	// Register all endpoints with the CallTracker
	for _, endpoint := range endpoints {
		tracker.registerEndpoint(endpoint, callID)
		if len(tracker.registry.CallIDsForEndpoint(endpoint)) > 0 {
			logger.Debug("Registered RTP endpoint mapping",
				"endpoint", endpoint,
				"call_id", SanitizeCallIDForLogging(callID),
				"total_calls_on_port", len(tracker.registry.CallIDsForEndpoint(endpoint)))
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

// IsTracked reports whether a packet matches an RTP endpoint on this tracker.
func (tracker *CallTracker) IsTracked(packet gopacket.Packet) bool {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return false
	}
	networkLayer := packet.NetworkLayer()

	dstPort := transportLayer.TransportFlow().Dst().String()
	srcPort := transportLayer.TransportFlow().Src().String()

	// Try IP:PORT lookups first (more specific)
	if networkLayer != nil {
		dstIP := networkLayer.NetworkFlow().Dst().String()
		srcIP := networkLayer.NetworkFlow().Src().String()

		dstEndpoint := dstIP + ":" + dstPort
		srcEndpoint := srcIP + ":" + srcPort

		if callIDs := tracker.endpointCallIDs(dstEndpoint); len(callIDs) > 0 {
			return true
		}
		if callIDs := tracker.endpointCallIDs(srcEndpoint); len(callIDs) > 0 {
			return true
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	dstCallIDs := tracker.endpointCallIDs(dstPort)
	srcCallIDs := tracker.endpointCallIDs(srcPort)
	return len(dstCallIDs) > 0 || len(srcCallIDs) > 0
}

// GetCallIDForPacket returns the first call ID associated with a packet's port.
// For B2BUA scenarios where multiple calls share a port, use GetAllCallIDsForPacket.
// GetCallIDForPacket returns the first call associated with a packet.
func (tracker *CallTracker) GetCallIDForPacket(packet gopacket.Packet) string {
	callIDs := tracker.GetAllCallIDsForPacket(packet)
	if len(callIDs) > 0 {
		return callIDs[0]
	}
	return ""
}

// GetAllCallIDsForPacket returns all call IDs associated with a packet's port.
// This supports B2BUA scenarios where multiple call legs share the same RTP port.
// GetAllCallIDsForPacket returns all calls associated with a packet.
func (tracker *CallTracker) GetAllCallIDsForPacket(packet gopacket.Packet) []string {
	transportLayer := packet.TransportLayer()
	if transportLayer == nil {
		return nil
	}
	networkLayer := packet.NetworkLayer()

	dstPort := transportLayer.TransportFlow().Dst().String()
	srcPort := transportLayer.TransportFlow().Src().String()

	var matched []string

	// Try IP:PORT lookups first (more specific)
	if networkLayer != nil {
		dstIP := networkLayer.NetworkFlow().Dst().String()
		srcIP := networkLayer.NetworkFlow().Src().String()

		dstEndpoint := dstIP + ":" + dstPort
		srcEndpoint := srcIP + ":" + srcPort

		if callIDs := tracker.endpointCallIDs(dstEndpoint); len(callIDs) > 0 {
			matched = append([]string(nil), callIDs...)
		}
		if len(matched) == 0 {
			if callIDs := tracker.endpointCallIDs(srcEndpoint); len(callIDs) > 0 {
				matched = append([]string(nil), callIDs...)
			}
		}
	}

	// Fall back to port-only lookups (for NAT scenarios)
	if len(matched) == 0 {
		if callIDs := tracker.endpointCallIDs(dstPort); len(callIDs) > 0 {
			matched = append([]string(nil), callIDs...)
		}
	}
	if len(matched) == 0 {
		if callIDs := tracker.endpointCallIDs(srcPort); len(callIDs) > 0 {
			matched = append([]string(nil), callIDs...)
		}
	}

	// Valid endpoint attribution is call activity even when per-call packet
	// output is disabled, so it must participate in timeout decisions.
	for _, callID := range matched {
		tracker.touchCall(callID)
	}
	return matched
}

// CleanupPortMappings removes all port-to-callID mappings for a given callID.
// This should be called when a call ends (after grace period) to prevent
// port collisions with new calls.
// CleanupPortMappings removes this call from every endpoint on this tracker.
func (tracker *CallTracker) CleanupPortMappings(callID string) {
	removed := tracker.registry.EndpointsForCall(callID)
	tracker.registry.DissociateEndpoints(callID)

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
