package hunter

import (
	"bytes"
	"net"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/simd"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
)

// parsedFilter holds a parsed pattern with its type for matching
type parsedFilter struct {
	original    string                // Original pattern from user (for logging)
	pattern     string                // Parsed pattern (wildcards stripped)
	patternType filtering.PatternType // Type of matching (prefix, suffix, contains)
	gpuType     voip.PatternType      // GPU pattern type for SIMD matching
}

// ApplicationFilter handles GPU-accelerated application-layer packet filtering
// Supports multiple protocols via the detector and can be extended with protocol-specific filters
type ApplicationFilter struct {
	gpuAccel       *voip.GPUAccelerator
	detector       *detector.Detector // Protocol detector for accurate protocol detection
	config         *voip.GPUConfig
	sipUsers       []parsedFilter // Parsed SIP user patterns
	phoneNumbers   []parsedFilter // Parsed phone number patterns
	ipAddresses    []string       // IP addresses as strings (for display/logging)
	ipAddressBytes [][]byte       // Parsed IP addresses as bytes (for SIMD comparison)
	patterns       []voip.GPUPattern
	mu             sync.RWMutex
	enabled        bool
}

// NewApplicationFilter creates a new application-layer filter with optional GPU acceleration
// This filter is protocol-agnostic and uses the detector to identify protocols
func NewApplicationFilter(config *voip.GPUConfig) (*ApplicationFilter, error) {
	af := &ApplicationFilter{
		config:         config,
		detector:       detector.InitDefault(), // Use centralized detector for accurate protocol detection
		sipUsers:       make([]parsedFilter, 0),
		phoneNumbers:   make([]parsedFilter, 0),
		ipAddresses:    make([]string, 0),
		ipAddressBytes: make([][]byte, 0),
		patterns:       make([]voip.GPUPattern, 0),
		enabled:        config != nil && config.Enabled,
	}

	// Initialize GPU accelerator if enabled
	if af.enabled {
		gpuAccel, err := voip.NewGPUAccelerator(config)
		if err != nil {
			logger.Warn("Failed to initialize GPU accelerator for application-layer filtering, falling back to CPU", "error", err)
			af.enabled = false
		} else {
			af.gpuAccel = gpuAccel
		}
	}

	logger.Info("Application filter initialized with centralized protocol detector")
	return af, nil
}

// NewVoIPFilter is a deprecated alias for NewApplicationFilter
// Maintained for backward compatibility
func NewVoIPFilter(config *voip.GPUConfig) (*ApplicationFilter, error) {
	logger.Warn("NewVoIPFilter is deprecated, use NewApplicationFilter instead")
	return NewApplicationFilter(config)
}

// filteringToGPUPatternType converts filtering.PatternType to voip.PatternType
func filteringToGPUPatternType(pt filtering.PatternType) voip.PatternType {
	switch pt {
	case filtering.PatternTypePrefix:
		return voip.PatternTypePrefix
	case filtering.PatternTypeSuffix:
		return voip.PatternTypeSuffix
	case filtering.PatternTypeContains:
		return voip.PatternTypeContains
	default:
		return voip.PatternTypeContains
	}
}

// UpdateFilters updates the filter list from processor
// This method supports hot-reload without restarting capture for application-level filters
func (af *ApplicationFilter) UpdateFilters(filters []*management.Filter) {
	af.mu.Lock()
	defer af.mu.Unlock()

	// Clear existing
	af.sipUsers = af.sipUsers[:0]
	af.phoneNumbers = af.phoneNumbers[:0]
	af.ipAddresses = af.ipAddresses[:0]
	af.ipAddressBytes = af.ipAddressBytes[:0]
	af.patterns = af.patterns[:0]

	// Build new filter lists
	// Note: BPF filters are NOT handled here - they require capture restart
	// and are managed by filtering.Manager
	for _, filter := range filters {
		switch filter.Type {
		case management.FilterType_FILTER_SIP_USER:
			// Parse pattern for wildcard support (e.g., "alice*", "*456789")
			pattern, patternType := filtering.ParsePattern(filter.Pattern)
			gpuType := filteringToGPUPatternType(patternType)

			af.sipUsers = append(af.sipUsers, parsedFilter{
				original:    filter.Pattern,
				pattern:     pattern,
				patternType: patternType,
				gpuType:     gpuType,
			})

			// Create GPU pattern for SIP user matching
			af.patterns = append(af.patterns, voip.GPUPattern{
				ID:            len(af.patterns),
				Pattern:       []byte(pattern),
				PatternLen:    len(pattern),
				Type:          gpuType,
				CaseSensitive: false,
			})

		case management.FilterType_FILTER_PHONE_NUMBER:
			// Parse pattern for wildcard support (e.g., "*456789" for suffix match)
			pattern, patternType := filtering.ParsePattern(filter.Pattern)
			gpuType := filteringToGPUPatternType(patternType)

			af.phoneNumbers = append(af.phoneNumbers, parsedFilter{
				original:    filter.Pattern,
				pattern:     pattern,
				patternType: patternType,
				gpuType:     gpuType,
			})

			// Create GPU pattern for phone number matching
			af.patterns = append(af.patterns, voip.GPUPattern{
				ID:            len(af.patterns),
				Pattern:       []byte(pattern),
				PatternLen:    len(pattern),
				Type:          gpuType,
				CaseSensitive: false,
			})

		case management.FilterType_FILTER_IP_ADDRESS:
			af.ipAddresses = append(af.ipAddresses, filter.Pattern)
			// Parse and normalize IP address to bytes for comparison
			// IP addresses are matched at network layer (headers), not payload
			// GPU acceleration doesn't apply here
			if ip := net.ParseIP(filter.Pattern); ip != nil {
				// Convert to 4-byte form for IPv4 (gopacket uses 4-byte representation)
				// or 16-byte form for IPv6
				if ipv4 := ip.To4(); ipv4 != nil {
					af.ipAddressBytes = append(af.ipAddressBytes, []byte(ipv4))
				} else {
					af.ipAddressBytes = append(af.ipAddressBytes, []byte(ip))
				}
			} else {
				logger.Warn("Failed to parse IP address filter", "pattern", filter.Pattern)
			}

			// Future: Add other protocol-specific filters here
			// case management.FilterType_FILTER_HTTP_PATH:
			// case management.FilterType_FILTER_DNS_QUERY:
		}
	}

	logger.Info("Updated application-level filters (hot-reload, no restart)",
		"sip_users", len(af.sipUsers),
		"phone_numbers", len(af.phoneNumbers),
		"ip_addresses", len(af.ipAddresses),
		"gpu_enabled", af.enabled)
}

// MatchPacket checks if a packet matches any of the filters
func (af *ApplicationFilter) MatchPacket(packet gopacket.Packet) bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	// If no filters, match everything
	if len(af.sipUsers) == 0 && len(af.phoneNumbers) == 0 && len(af.ipAddresses) == 0 {
		return true
	}

	// Check IP addresses first (applies to all protocols)
	if len(af.ipAddresses) > 0 {
		if af.matchIPAddress(packet) {
			return true
		}
		// If we have ONLY IP filters (no VoIP filters), don't continue to VoIP checks
		if len(af.sipUsers) == 0 && len(af.phoneNumbers) == 0 {
			return false
		}
	}

	// Check if this is a SIP or RTP packet
	if !af.isVoIPPacket(packet) {
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
	if af.enabled && af.gpuAccel != nil && len(af.patterns) > 0 {
		return af.matchWithGPU([]byte(payload))
	}

	// CPU fallback
	return af.matchWithCPU(string(payload))
}

// MatchBatch checks multiple packets using GPU acceleration
func (af *ApplicationFilter) MatchBatch(packets []gopacket.Packet) []bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	results := make([]bool, len(packets))

	// If no filters, match everything
	if len(af.sipUsers) == 0 && len(af.phoneNumbers) == 0 {
		for i := range results {
			results[i] = true
		}
		return results
	}

	// Extract VoIP packets and payloads
	voipPackets := make([][]byte, 0, len(packets))
	voipIndices := make([]int, 0, len(packets))

	for i, packet := range packets {
		if af.isVoIPPacket(packet) {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				// Use LayerContents() to get full message with headers
				voipPackets = append(voipPackets, appLayer.LayerContents())
				voipIndices = append(voipIndices, i)
			}
		}
	}

	// If we have GPU and multiple packets, use batch processing
	if af.enabled && af.gpuAccel != nil && len(voipPackets) > 1 && len(af.patterns) > 0 {
		gpuResults, err := af.gpuAccel.ProcessBatch(voipPackets, af.patterns)
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
		results[idx] = af.MatchPacket(packet)
	}

	return results
}

// matchWithGPU uses GPU acceleration for pattern matching
func (af *ApplicationFilter) matchWithGPU(payload []byte) bool {
	if af.gpuAccel == nil || len(af.patterns) == 0 {
		return false
	}

	// Process single packet as batch of 1
	results, err := af.gpuAccel.ProcessBatch([][]byte{payload}, af.patterns)
	if err != nil {
		// Fall back to CPU on error
		return af.matchWithCPU(string(payload))
	}

	// Check if any pattern matched
	for _, result := range results {
		if result.Matched && result.PacketIndex == 0 {
			return true
		}
	}

	return false
}

// matchWithCPU uses CPU for pattern matching with wildcard support
// Extracts usernames from SIP headers and matches against parsed patterns
func (af *ApplicationFilter) matchWithCPU(payload string) bool {
	// Convert to bytes for header extraction
	payloadBytes := []byte(payload)

	// Extract SIP headers for proper matching
	sipHeaders := extractSIPHeaders(payloadBytes)

	// Extract usernames from each header (the user part of the SIP URI)
	var fromUser, toUser, paiUser string
	if len(sipHeaders.from) > 0 {
		fromUser = voip.ExtractUserFromHeaderBytes(sipHeaders.from)
	}
	if len(sipHeaders.to) > 0 {
		toUser = voip.ExtractUserFromHeaderBytes(sipHeaders.to)
	}
	if len(sipHeaders.pAssertedIdentity) > 0 {
		paiUser = voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity)
	}

	// Check SIP users against extracted usernames
	for _, filter := range af.sipUsers {
		// Match against extracted username from From header
		if fromUser != "" && filtering.Match(fromUser, filter.pattern, filter.patternType) {
			return true
		}

		// Match against extracted username from To header
		if toUser != "" && filtering.Match(toUser, filter.pattern, filter.patternType) {
			return true
		}

		// Match against extracted username from P-Asserted-Identity header
		if paiUser != "" && filtering.Match(paiUser, filter.pattern, filter.patternType) {
			return true
		}
	}

	// Check phone numbers against extracted usernames
	// Phone numbers are typically in the user part of the SIP URI
	for _, filter := range af.phoneNumbers {
		// Match against extracted username from From header
		if fromUser != "" && filtering.Match(fromUser, filter.pattern, filter.patternType) {
			return true
		}

		// Match against extracted username from To header
		if toUser != "" && filtering.Match(toUser, filter.pattern, filter.patternType) {
			return true
		}

		// Match against extracted username from P-Asserted-Identity header
		if paiUser != "" && filtering.Match(paiUser, filter.pattern, filter.patternType) {
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

// matchIPAddress checks if packet source or destination IP matches any filter
// Uses SIMD-optimized byte comparison for high-performance network layer filtering
func (af *ApplicationFilter) matchIPAddress(packet gopacket.Packet) bool {
	// Get network layer
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		// Get raw IP bytes (4 bytes for IPv4, 16 bytes for IPv6)
		// This avoids string conversion overhead
		srcIPBytes := netLayer.NetworkFlow().Src().Raw()
		dstIPBytes := netLayer.NetworkFlow().Dst().Raw()

		// Check if source or destination matches any IP filter
		// Use SIMD-optimized comparison (AVX2/SSE2) for maximum performance
		for _, filterIPBytes := range af.ipAddressBytes {
			// SIMD comparison is much faster than string comparison
			// Especially for high packet rates
			if simd.BytesEqual(srcIPBytes, filterIPBytes) || simd.BytesEqual(dstIPBytes, filterIPBytes) {
				return true
			}
		}
	}
	return false
}

// isVoIPPacket checks if a packet is SIP or RTP using centralized detector
func (af *ApplicationFilter) isVoIPPacket(packet gopacket.Packet) bool {
	// Use centralized detector for accurate protocol detection
	// This replaces unreliable port-based heuristics
	result := af.detector.Detect(packet)
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
func (af *ApplicationFilter) Close() {
	if af.gpuAccel != nil {
		// GPU cleanup would happen here
		logger.Info("Application filter closed")
	}
}
