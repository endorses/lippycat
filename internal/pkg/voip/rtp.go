package voip

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
					// Retain the port-only association for diagnostics and legacy
					// detection. Authoritative attribution never consults it.
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

// IsTracked is a non-authoritative detection helper. It may use legacy
// port-only candidates; attribution callers must use ResolveMediaPacket.
func (tracker *CallTracker) IsTracked(packet gopacket.Packet) bool {
	return len(tracker.GetAllCallIDsForPacket(packet)) > 0
}

// GetCallIDForPacket is a compatibility wrapper that returns a Call-ID only
// for authoritative resolution. Ambiguous and unresolved packets return empty.
func (tracker *CallTracker) GetCallIDForPacket(packet gopacket.Packet) string {
	return tracker.ResolveMediaPacket(packet).CallID
}

// ResolveMediaPacket attributes media only from exact IP:port endpoints. It
// deliberately excludes the legacy port-only diagnostic fallback.
func (tracker *CallTracker) ResolveMediaPacket(packet gopacket.Packet) callregistry.MediaResolution {
	network := packet.NetworkLayer()
	udpLayer := packet.Layer(layers.LayerTypeUDP)
	if udpLayer == nil || network == nil {
		return callregistry.MediaResolution{Status: callregistry.MediaUnresolved}
	}
	udp := udpLayer.(*layers.UDP)
	source := network.NetworkFlow().Src().String() + ":" + strconv.Itoa(int(udp.SrcPort))
	destination := network.NetworkFlow().Dst().String() + ":" + strconv.Itoa(int(udp.DstPort))
	resolution := tracker.registry.ResolveMediaEndpoints(source, destination)
	if resolution.Status == callregistry.MediaResolved {
		tracker.touchCall(resolution.CallID)
	}
	return resolution
}

// GetAllCallIDsForPacket is a diagnostic candidate API and is unsuitable for
// filtering, output attribution, or LI correlation.
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
