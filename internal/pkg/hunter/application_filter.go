package hunter

import (
	"bytes"
	"net"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
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
	sipUsers       []parsedFilter // Parsed SIP user patterns (user part only, suffix matching)
	sipURIs        []parsedFilter // Parsed SIP URI patterns (user@domain, exact/contains matching)
	phoneNumbers   []parsedFilter // Parsed phone number patterns
	ipAddresses    []string       // IP addresses as strings (for display/logging)
	ipAddressBytes [][]byte       // Parsed IP addresses as bytes (for SIMD comparison)
	patterns       []voip.GPUPattern
	acPatterns     []ahocorasick.Pattern        // AC patterns for GPU backend (SIP users + phone numbers)
	acMatcher      *ahocorasick.BufferedMatcher // Aho-Corasick matcher for SIP user/phone number matching
	sipURIPatterns []ahocorasick.Pattern        // AC patterns for SIPURI matching (user@domain)
	sipURIMatcher  *ahocorasick.BufferedMatcher // Separate Aho-Corasick matcher for SIPURI matching
	mu             sync.RWMutex
	enabled        bool
	gpuACBuilt     bool // Whether GPU has AC automaton built
}

// NewApplicationFilter creates a new application-layer filter with optional GPU acceleration
// This filter is protocol-agnostic and uses the detector to identify protocols
func NewApplicationFilter(config *voip.GPUConfig) (*ApplicationFilter, error) {
	// Convert voip.PatternAlgorithm to ahocorasick.Algorithm
	acAlgorithm := ahocorasick.AlgorithmAuto
	if config != nil {
		switch config.PatternAlgorithm {
		case voip.PatternAlgorithmLinear:
			acAlgorithm = ahocorasick.AlgorithmLinear
		case voip.PatternAlgorithmAhoCorasick:
			acAlgorithm = ahocorasick.AlgorithmAhoCorasick
		case voip.PatternAlgorithmAuto:
			acAlgorithm = ahocorasick.AlgorithmAuto
		}
	}

	af := &ApplicationFilter{
		config:         config,
		detector:       detector.InitDefault(), // Use centralized detector for accurate protocol detection
		sipUsers:       make([]parsedFilter, 0),
		sipURIs:        make([]parsedFilter, 0),
		phoneNumbers:   make([]parsedFilter, 0),
		ipAddresses:    make([]string, 0),
		ipAddressBytes: make([][]byte, 0),
		patterns:       make([]voip.GPUPattern, 0),
		acPatterns:     make([]ahocorasick.Pattern, 0),
		acMatcher:      ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Aho-Corasick for SIP user/phone
		sipURIPatterns: make([]ahocorasick.Pattern, 0),
		sipURIMatcher:  ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Separate AC for SIPURI
		enabled:        config != nil && config.Enabled,
		gpuACBuilt:     false,
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

	logger.Info("Application filter initialized",
		"protocol_detector", "centralized",
		"pattern_algorithm", string(acAlgorithm),
		"gpu_enabled", af.enabled)
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
	af.sipURIs = af.sipURIs[:0]
	af.phoneNumbers = af.phoneNumbers[:0]
	af.ipAddresses = af.ipAddresses[:0]
	af.ipAddressBytes = af.ipAddressBytes[:0]
	af.patterns = af.patterns[:0]
	af.acPatterns = af.acPatterns[:0]
	af.sipURIPatterns = af.sipURIPatterns[:0]
	af.gpuACBuilt = false

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

		case management.FilterType_FILTER_SIP_URI:
			// SIPURI filter: extracts user@domain for exact/pattern matching
			// Different from SIPUser which only extracts user part for suffix matching
			pattern, patternType := filtering.ParsePattern(filter.Pattern)
			gpuType := filteringToGPUPatternType(patternType)

			af.sipURIs = append(af.sipURIs, parsedFilter{
				original:    filter.Pattern,
				pattern:     pattern,
				patternType: patternType,
				gpuType:     gpuType,
			})

			// Future: Add other protocol-specific filters here
			// case management.FilterType_FILTER_HTTP_PATH:
			// case management.FilterType_FILTER_DNS_QUERY:
		}
	}

	logger.Info("Updated application-level filters (hot-reload, no restart)",
		"sip_users", len(af.sipUsers),
		"sip_uris", len(af.sipURIs),
		"phone_numbers", len(af.phoneNumbers),
		"ip_addresses", len(af.ipAddresses),
		"gpu_enabled", af.enabled)

	// Build Aho-Corasick patterns for CPU matching
	// Combines SIP users and phone numbers into a single AC automaton
	af.acPatterns = make([]ahocorasick.Pattern, 0, len(af.sipUsers)+len(af.phoneNumbers))
	for i, f := range af.sipUsers {
		af.acPatterns = append(af.acPatterns, ahocorasick.Pattern{
			ID:   i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}
	// Phone numbers get IDs starting after SIP users
	baseID := len(af.sipUsers)
	for i, f := range af.phoneNumbers {
		af.acPatterns = append(af.acPatterns, ahocorasick.Pattern{
			ID:   baseID + i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}

	// Trigger background rebuild of AC automaton for CPU (SIP users + phone numbers)
	// This is non-blocking - matching continues with old automaton or linear scan
	af.acMatcher.UpdatePatterns(af.acPatterns)

	// Build SIPURI AC patterns (separate automaton for user@domain matching)
	af.sipURIPatterns = make([]ahocorasick.Pattern, 0, len(af.sipURIs))
	for i, f := range af.sipURIs {
		af.sipURIPatterns = append(af.sipURIPatterns, ahocorasick.Pattern{
			ID:   i,
			Text: f.pattern,
			Type: f.patternType,
		})
	}

	// Trigger background rebuild of SIPURI AC automaton
	af.sipURIMatcher.UpdatePatterns(af.sipURIPatterns)

	// Build AC automaton in GPU backend if enabled
	// Uses the same patterns but built inside GPU backend (SIMD/CUDA/OpenCL)
	if af.enabled && af.gpuAccel != nil && len(af.acPatterns) > 0 {
		if backend := af.gpuAccel.Backend(); backend != nil {
			if err := backend.BuildAutomaton(af.acPatterns); err != nil {
				logger.Warn("Failed to build GPU AC automaton, will use CPU fallback",
					"error", err,
					"pattern_count", len(af.acPatterns))
			} else {
				af.gpuACBuilt = true
				logger.Debug("GPU AC automaton built successfully",
					"pattern_count", len(af.acPatterns))
			}
		}
	}
}

// MatchPacket checks if a packet matches any of the filters
func (af *ApplicationFilter) MatchPacket(packet gopacket.Packet) bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	// If no filters, match everything
	if len(af.sipUsers) == 0 && len(af.sipURIs) == 0 && len(af.phoneNumbers) == 0 && len(af.ipAddresses) == 0 {
		return true
	}

	// Check IP addresses first (applies to all protocols)
	if len(af.ipAddresses) > 0 {
		if af.matchIPAddress(packet) {
			return true
		}
		// If we have ONLY IP filters (no VoIP filters), don't continue to VoIP checks
		if len(af.sipUsers) == 0 && len(af.sipURIs) == 0 && len(af.phoneNumbers) == 0 {
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

	// Use GPU if enabled, AC automaton is built, and we have patterns
	if af.enabled && af.gpuACBuilt && af.gpuAccel != nil && len(af.acPatterns) > 0 {
		return af.matchWithGPU([]byte(payload))
	}

	// CPU fallback
	return af.matchWithCPU(string(payload))
}

// MatchBatch checks multiple packets using GPU acceleration
// Uses Aho-Corasick automaton for O(n) username matching
func (af *ApplicationFilter) MatchBatch(packets []gopacket.Packet) []bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	results := make([]bool, len(packets))

	// If no filters, match everything
	if len(af.sipUsers) == 0 && len(af.sipURIs) == 0 && len(af.phoneNumbers) == 0 {
		for i := range results {
			results[i] = true
		}
		return results
	}

	// Extract VoIP packets and payloads
	voipPayloads := make([][]byte, 0, len(packets))
	voipIndices := make([]int, 0, len(packets))

	for i, packet := range packets {
		if af.isVoIPPacket(packet) {
			if appLayer := packet.ApplicationLayer(); appLayer != nil {
				// Use LayerContents() to get full message with headers
				voipPayloads = append(voipPayloads, appLayer.LayerContents())
				voipIndices = append(voipIndices, i)
			}
		}
	}

	// If we have GPU with AC automaton and multiple packets, use batch processing
	if af.enabled && af.gpuACBuilt && af.gpuAccel != nil && len(voipPayloads) > 1 && len(af.acPatterns) > 0 {
		backend := af.gpuAccel.Backend()
		if backend != nil {
			// Extract usernames from all VoIP payloads
			allUsernames := make([][]byte, 0, len(voipPayloads)*3)
			usernameToPacket := make([]int, 0, len(voipPayloads)*3) // Maps username index to voipPayload index

			for payloadIdx, payload := range voipPayloads {
				sipHeaders := extractSIPHeaders(payload)
				if len(sipHeaders.from) > 0 {
					if user := voip.ExtractUserFromHeaderBytes(sipHeaders.from); user != "" {
						allUsernames = append(allUsernames, []byte(user))
						usernameToPacket = append(usernameToPacket, payloadIdx)
					}
				}
				if len(sipHeaders.to) > 0 {
					if user := voip.ExtractUserFromHeaderBytes(sipHeaders.to); user != "" {
						allUsernames = append(allUsernames, []byte(user))
						usernameToPacket = append(usernameToPacket, payloadIdx)
					}
				}
				if len(sipHeaders.pAssertedIdentity) > 0 {
					if user := voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity); user != "" {
						allUsernames = append(allUsernames, []byte(user))
						usernameToPacket = append(usernameToPacket, payloadIdx)
					}
				}
			}

			if len(allUsernames) > 0 {
				// Use GPU backend's MatchUsernames with pre-built AC automaton
				gpuResults, err := backend.MatchUsernames(allUsernames)
				if err == nil {
					// Map GPU results back to packet indices
					matchedPayloads := make(map[int]bool)
					for usernameIdx, patternIDs := range gpuResults {
						if len(patternIDs) > 0 && usernameIdx < len(usernameToPacket) {
							matchedPayloads[usernameToPacket[usernameIdx]] = true
						}
					}

					for payloadIdx, packetIdx := range voipIndices {
						results[packetIdx] = matchedPayloads[payloadIdx]
					}
					return results
				}
			}
			// GPU failed or no usernames, fall back to CPU
		}
	}

	// CPU fallback
	for _, idx := range voipIndices {
		packet := packets[idx]
		results[idx] = af.MatchPacket(packet)
	}

	return results
}

// matchWithGPU uses GPU acceleration for pattern matching
// Uses Aho-Corasick automaton (BuildAutomaton/MatchUsernames) for O(n) matching
// Note: SIPURI matching is handled via CPU (separate AC automaton)
func (af *ApplicationFilter) matchWithGPU(payload []byte) bool {
	// If GPU AC automaton not built or no patterns, fall back to CPU
	if af.gpuAccel == nil || !af.gpuACBuilt || len(af.acPatterns) == 0 {
		return af.matchWithCPU(string(payload))
	}

	backend := af.gpuAccel.Backend()
	if backend == nil {
		return af.matchWithCPU(string(payload))
	}

	// Extract SIP headers for matching
	sipHeaders := extractSIPHeaders(payload)

	// SIPUser/PhoneNumber matching via GPU (if we have those filters)
	if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		usernames := make([][]byte, 0, 3)
		if len(sipHeaders.from) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.from); user != "" {
				usernames = append(usernames, []byte(user))
			}
		}
		if len(sipHeaders.to) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.to); user != "" {
				usernames = append(usernames, []byte(user))
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity); user != "" {
				usernames = append(usernames, []byte(user))
			}
		}

		if len(usernames) > 0 {
			// Use GPU backend's MatchUsernames with pre-built AC automaton
			results, err := backend.MatchUsernames(usernames)
			if err != nil {
				// Fall back to CPU on error for SIPUser matching
				usernameStrs := make([]string, len(usernames))
				for i, u := range usernames {
					usernameStrs[i] = string(u)
				}
				if af.acMatcher.MatchUsernames(usernameStrs) {
					return true
				}
			} else {
				// Check if any username matched
				for _, patternIDs := range results {
					if len(patternIDs) > 0 {
						return true
					}
				}
			}
		}
	}

	// SIPURI matching via CPU (separate AC automaton, not on GPU)
	if len(af.sipURIs) > 0 {
		sipURIValues := make([]string, 0, 3)
		if len(sipHeaders.from) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.from); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}
		if len(sipHeaders.to) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.to); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.pAssertedIdentity); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}

		if af.sipURIMatcher.MatchUsernames(sipURIValues) {
			return true
		}
	}

	return false
}

// matchWithCPU uses Aho-Corasick for O(n) pattern matching
// Runs separate matching passes for SIPUser/phoneNumber (user part) and SIPURI (user@domain)
// Only runs each pass if filters of that type exist (typical case: single pass)
func (af *ApplicationFilter) matchWithCPU(payload string) bool {
	// Convert to bytes for header extraction
	payloadBytes := []byte(payload)

	// Extract SIP headers for proper matching
	sipHeaders := extractSIPHeaders(payloadBytes)

	// SIPUser/PhoneNumber matching: extract user part, use suffix matching
	// Only run if we have SIPUser or phoneNumber filters
	if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		usernames := make([]string, 0, 3)
		if len(sipHeaders.from) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.from); user != "" {
				usernames = append(usernames, user)
			}
		}
		if len(sipHeaders.to) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.to); user != "" {
				usernames = append(usernames, user)
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity); user != "" {
				usernames = append(usernames, user)
			}
		}

		// Use Aho-Corasick matcher for O(n) matching against SIP users + phone numbers
		if af.acMatcher.MatchUsernames(usernames) {
			return true
		}
	}

	// SIPURI matching: extract user@domain, use exact/contains matching
	// Only run if we have SIPURI filters
	if len(af.sipURIs) > 0 {
		sipURIValues := make([]string, 0, 3)
		if len(sipHeaders.from) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.from); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}
		if len(sipHeaders.to) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.to); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.pAssertedIdentity); uri != "" {
				sipURIValues = append(sipURIValues, uri)
			}
		}

		// Use separate Aho-Corasick matcher for SIPURI matching
		if af.sipURIMatcher.MatchUsernames(sipURIValues) {
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
