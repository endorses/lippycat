package voip

import (
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/google/gopacket"
)

// portToCallID is now managed by the CallTracker

func ExtractPortFromSdp(line string, callID string) {
	_, partThatContainsPort, hasPort := strings.Cut(line, "m=audio")
	if !hasPort {
		return
	}
	parts := strings.Fields(partThatContainsPort)
	if len(parts) >= 1 {
		port := strings.TrimSpace(parts[0])

		// Validate port number to prevent integer overflow and invalid mappings
		if !isValidPort(port) {
			logger.Debug("Invalid port number in SDP",
				"port", port,
				"call_id", callID)
			return
		}

		tracker := getTracker()
		tracker.mu.Lock()
		defer tracker.mu.Unlock()
		tracker.portToCallID[port] = callID
	}
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
