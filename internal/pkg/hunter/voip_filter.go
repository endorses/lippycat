package hunter

import (
	"bytes"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/simd"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
)

// VoIPFilter handles GPU-accelerated VoIP packet filtering
type VoIPFilter struct {
	gpuAccel     *voip.GPUAccelerator
	detector     *detector.Detector // Protocol detector for accurate VoIP detection
	config       *voip.GPUConfig
	sipUsers     []string
	phoneNumbers []string
	patterns     []voip.GPUPattern
	mu           sync.RWMutex
	enabled      bool
}

// NewVoIPFilter creates a new VoIP filter with optional GPU acceleration
func NewVoIPFilter(config *voip.GPUConfig) (*VoIPFilter, error) {
	vf := &VoIPFilter{
		config:       config,
		detector:     detector.InitDefault(), // Use centralized detector for accurate VoIP detection
		sipUsers:     make([]string, 0),
		phoneNumbers: make([]string, 0),
		patterns:     make([]voip.GPUPattern, 0),
		enabled:      config != nil && config.Enabled,
	}

	// Initialize GPU accelerator if enabled
	if vf.enabled {
		gpuAccel, err := voip.NewGPUAccelerator(config)
		if err != nil {
			logger.Warn("Failed to initialize GPU accelerator for VoIP filtering, falling back to CPU", "error", err)
			vf.enabled = false
		} else {
			vf.gpuAccel = gpuAccel
		}
	}

	logger.Info("VoIP filter initialized with centralized detector")
	return vf, nil
}

// UpdateFilters updates the filter list from processor
func (vf *VoIPFilter) UpdateFilters(filters []*management.Filter) {
	vf.mu.Lock()
	defer vf.mu.Unlock()

	// Clear existing
	vf.sipUsers = vf.sipUsers[:0]
	vf.phoneNumbers = vf.phoneNumbers[:0]
	vf.patterns = vf.patterns[:0]

	// Build new filter lists
	for _, filter := range filters {
		switch filter.Type {
		case management.FilterType_FILTER_SIP_USER:
			vf.sipUsers = append(vf.sipUsers, filter.Pattern)
			// Create GPU pattern for SIP user matching
			vf.patterns = append(vf.patterns, voip.GPUPattern{
				ID:            len(vf.patterns),
				Pattern:       []byte(filter.Pattern),
				PatternLen:    len(filter.Pattern),
				Type:          voip.PatternTypeContains,
				CaseSensitive: false,
			})

		case management.FilterType_FILTER_PHONE_NUMBER:
			vf.phoneNumbers = append(vf.phoneNumbers, filter.Pattern)
			// Create GPU pattern for phone number matching
			vf.patterns = append(vf.patterns, voip.GPUPattern{
				ID:            len(vf.patterns),
				Pattern:       []byte(filter.Pattern),
				PatternLen:    len(filter.Pattern),
				Type:          voip.PatternTypeContains,
				CaseSensitive: false,
			})
		}
	}

	logger.Info("Updated VoIP filters",
		"sip_users", len(vf.sipUsers),
		"phone_numbers", len(vf.phoneNumbers),
		"gpu_enabled", vf.enabled)
}

// MatchPacket checks if a packet matches any of the filters
func (vf *VoIPFilter) MatchPacket(packet gopacket.Packet) bool {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	// If no filters, match everything
	if len(vf.sipUsers) == 0 && len(vf.phoneNumbers) == 0 {
		return true
	}

	// Check if this is a SIP or RTP packet
	if !vf.isVoIPPacket(packet) {
		return false
	}

	// Get payload - use LayerContents() to get full message including headers
	// Payload() only returns the body (e.g., SDP for SIP), missing critical info
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false
	}

	payload := appLayer.LayerContents()

	// Use GPU if enabled and we have patterns
	if vf.enabled && vf.gpuAccel != nil && len(vf.patterns) > 0 {
		return vf.matchWithGPU([]byte(payload))
	}

	// CPU fallback
	return vf.matchWithCPU(string(payload))
}

// MatchBatch checks multiple packets using GPU acceleration
func (vf *VoIPFilter) MatchBatch(packets []gopacket.Packet) []bool {
	vf.mu.RLock()
	defer vf.mu.RUnlock()

	results := make([]bool, len(packets))

	// If no filters, match everything
	if len(vf.sipUsers) == 0 && len(vf.phoneNumbers) == 0 {
		for i := range results {
			results[i] = true
		}
		return results
	}

	// Extract VoIP packets and payloads
	voipPackets := make([][]byte, 0, len(packets))
	voipIndices := make([]int, 0, len(packets))

	for i, packet := range packets {
		if vf.isVoIPPacket(packet) {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				// Use LayerContents() to get full message with headers
				voipPackets = append(voipPackets, appLayer.LayerContents())
				voipIndices = append(voipIndices, i)
			}
		}
	}

	// If we have GPU and multiple packets, use batch processing
	if vf.enabled && vf.gpuAccel != nil && len(voipPackets) > 1 && len(vf.patterns) > 0 {
		gpuResults, err := vf.gpuAccel.ProcessBatch(voipPackets, vf.patterns)
		if err == nil {
			// Map GPU results back to packet indices
			matchedPackets := make(map[int]bool)
			for _, result := range gpuResults {
				if result.Matched && result.PacketIndex < len(voipIndices) {
					matchedPackets[voipIndices[result.PacketIndex]] = true
				}
			}

			for i := range results {
				results[i] = matchedPackets[i]
			}
			return results
		}
		// GPU failed, fall back to CPU
	}

	// CPU fallback
	for _, idx := range voipIndices {
		packet := packets[idx]
		results[idx] = vf.MatchPacket(packet)
	}

	return results
}

// matchWithGPU uses GPU acceleration for pattern matching
func (vf *VoIPFilter) matchWithGPU(payload []byte) bool {
	if vf.gpuAccel == nil || len(vf.patterns) == 0 {
		return false
	}

	// Process single packet as batch of 1
	results, err := vf.gpuAccel.ProcessBatch([][]byte{payload}, vf.patterns)
	if err != nil {
		// Fall back to CPU on error
		return vf.matchWithCPU(string(payload))
	}

	// Check if any pattern matched
	for _, result := range results {
		if result.Matched && result.PacketIndex == 0 {
			return true
		}
	}

	return false
}

// matchWithCPU uses CPU for pattern matching with SIMD optimization
func (vf *VoIPFilter) matchWithCPU(payload string) bool {
	// Convert to bytes for SIMD operations (zero-copy)
	payloadBytes := []byte(payload)

	// Extract SIP headers for proper matching
	sipHeaders := extractSIPHeaders(payloadBytes)

	// Check SIP users in proper headers (From, To, P-Asserted-Identity)
	for _, user := range vf.sipUsers {
		userBytes := []byte(strings.ToLower(user))

		// Check in From header
		if len(sipHeaders.from) > 0 {
			fromLower := bytes.ToLower(sipHeaders.from)
			if simd.BytesContains(fromLower, userBytes) {
				return true
			}
		}

		// Check in To header
		if len(sipHeaders.to) > 0 {
			toLower := bytes.ToLower(sipHeaders.to)
			if simd.BytesContains(toLower, userBytes) {
				return true
			}
		}

		// Check in P-Asserted-Identity header
		if len(sipHeaders.pAssertedIdentity) > 0 {
			paiLower := bytes.ToLower(sipHeaders.pAssertedIdentity)
			if simd.BytesContains(paiLower, userBytes) {
				return true
			}
		}
	}

	// Check phone numbers in proper headers
	for _, number := range vf.phoneNumbers {
		numberBytes := []byte(number)

		// Check in From header
		if len(sipHeaders.from) > 0 && simd.BytesContains(sipHeaders.from, numberBytes) {
			return true
		}

		// Check in To header
		if len(sipHeaders.to) > 0 && simd.BytesContains(sipHeaders.to, numberBytes) {
			return true
		}

		// Check in P-Asserted-Identity header
		if len(sipHeaders.pAssertedIdentity) > 0 && simd.BytesContains(sipHeaders.pAssertedIdentity, numberBytes) {
			return true
		}
	}

	return false
}

// sipHeaders holds parsed SIP header values
type sipHeaders struct {
	from              []byte
	to                []byte
	pAssertedIdentity []byte
}

// extractSIPHeaders extracts From, To, and P-Asserted-Identity headers from SIP message
// This is a fast, zero-allocation parser for filtering
func extractSIPHeaders(payload []byte) sipHeaders {
	var headers sipHeaders

	// Parse line by line - handle both \r\n (SIP standard) and \n (for tests/compatibility)
	var lines [][]byte
	if bytes.Contains(payload, []byte("\r\n")) {
		lines = bytes.Split(payload, []byte("\r\n"))
	} else {
		lines = bytes.Split(payload, []byte("\n"))
	}

	for _, line := range lines {
		if len(line) == 0 {
			// Empty line marks end of headers
			break
		}

		// Check for From header (case-insensitive)
		if len(line) >= 5 {
			lineUpper := bytes.ToUpper(line[:5])
			if bytes.Equal(lineUpper, []byte("FROM:")) {
				headers.from = extractHeaderValue(line)
				continue
			}
		}
		// Short form: f:
		if len(line) >= 2 && (line[0] == 'f' || line[0] == 'F') && line[1] == ':' {
			headers.from = extractHeaderValue(line)
			continue
		}

		// Check for To header (case-insensitive)
		if len(line) >= 3 {
			lineUpper := bytes.ToUpper(line[:3])
			if bytes.Equal(lineUpper, []byte("TO:")) {
				headers.to = extractHeaderValue(line)
				continue
			}
		}
		// Short form: t:
		if len(line) >= 2 && (line[0] == 't' || line[0] == 'T') && line[1] == ':' {
			headers.to = extractHeaderValue(line)
			continue
		}

		// Check for P-Asserted-Identity header (case-insensitive)
		if len(line) >= 20 {
			lineUpper := bytes.ToUpper(line[:20])
			if bytes.Equal(lineUpper, []byte("P-ASSERTED-IDENTITY:")) {
				headers.pAssertedIdentity = extractHeaderValue(line)
				continue
			}
		}
	}

	return headers
}

// extractHeaderValue extracts the value part of a SIP header (after the colon)
func extractHeaderValue(line []byte) []byte {
	colonIdx := bytes.IndexByte(line, ':')
	if colonIdx == -1 || colonIdx >= len(line)-1 {
		return nil
	}

	// Skip colon and any leading whitespace
	value := line[colonIdx+1:]

	// Trim leading/trailing whitespace
	return bytes.TrimSpace(value)
}

// isVoIPPacket checks if a packet is SIP or RTP using centralized detector
func (vf *VoIPFilter) isVoIPPacket(packet gopacket.Packet) bool {
	// Use centralized detector for accurate protocol detection
	// This replaces unreliable port-based heuristics
	result := vf.detector.Detect(packet)
	if result == nil {
		return false
	}

	// Check if detected protocol is VoIP-related
	switch result.Protocol {
	case "SIP", "RTP", "RTCP":
		return true
	default:
		return false
	}
}

// Close cleans up GPU resources
func (vf *VoIPFilter) Close() {
	if vf.gpuAccel != nil {
		// GPU cleanup would happen here
		logger.Info("VoIP filter closed")
	}
}
