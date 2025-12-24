package hunter

import (
	"bytes"
	"net"
	"net/netip"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/kentik/patricia"
	"github.com/kentik/patricia/generics_tree"
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
	patterns       []voip.GPUPattern
	acPatterns     []ahocorasick.Pattern        // AC patterns for GPU backend (SIP users + phone numbers)
	acMatcher      *ahocorasick.BufferedMatcher // Aho-Corasick matcher for SIP user/phone number matching
	sipURIPatterns []ahocorasick.Pattern        // AC patterns for SIPURI matching (user@domain)
	sipURIMatcher  *ahocorasick.BufferedMatcher // Separate Aho-Corasick matcher for SIPURI matching

	// IP filter data structures for O(1) exact matching and O(prefix) CIDR matching
	exactIPv4      map[netip.Addr]struct{}         // Hash map for O(1) exact IPv4 lookup
	exactIPv6      map[netip.Addr]struct{}         // Hash map for O(1) exact IPv6 lookup
	cidrTreeV4     *generics_tree.TreeV4[struct{}] // Radix tree for IPv4 CIDR matching
	cidrTreeV6     *generics_tree.TreeV6[struct{}] // Radix tree for IPv6 CIDR matching
	hasCIDRFilters bool                            // Whether any CIDR filters are present

	mu               sync.RWMutex
	enabled          bool
	gpuACBuilt       bool // Whether GPU has default (SIPUser+PhoneNumber) AC automaton built
	gpuSIPURIACBuilt bool // Whether GPU has SIPURI AC automaton built
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
		patterns:       make([]voip.GPUPattern, 0),
		acPatterns:     make([]ahocorasick.Pattern, 0),
		acMatcher:      ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Aho-Corasick for SIP user/phone
		sipURIPatterns: make([]ahocorasick.Pattern, 0),
		sipURIMatcher:  ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Separate AC for SIPURI
		exactIPv4:      make(map[netip.Addr]struct{}),
		exactIPv6:      make(map[netip.Addr]struct{}),
		cidrTreeV4:     generics_tree.NewTreeV4[struct{}](),
		cidrTreeV6:     generics_tree.NewTreeV6[struct{}](),
		hasCIDRFilters: false,
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
	af.patterns = af.patterns[:0]
	af.acPatterns = af.acPatterns[:0]
	af.sipURIPatterns = af.sipURIPatterns[:0]
	af.gpuACBuilt = false
	af.gpuSIPURIACBuilt = false

	// Reset IP filter data structures
	af.exactIPv4 = make(map[netip.Addr]struct{})
	af.exactIPv6 = make(map[netip.Addr]struct{})
	af.cidrTreeV4 = generics_tree.NewTreeV4[struct{}]()
	af.cidrTreeV6 = generics_tree.NewTreeV6[struct{}]()
	af.hasCIDRFilters = false

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
			// Parse IP address or CIDR range
			// IP addresses are matched at network layer (headers), not payload
			// GPU acceleration doesn't apply here

			// First try parsing as CIDR (e.g., "10.0.0.0/8", "2001:db8::/32")
			if prefix, err := netip.ParsePrefix(filter.Pattern); err == nil {
				// CIDR filter - add to radix tree for O(prefix) lookup
				if prefix.Addr().Is4() {
					ipv4Addr, _, _ := patricia.ParseFromNetIPPrefix(prefix)
					if ipv4Addr != nil {
						af.cidrTreeV4.Set(*ipv4Addr, struct{}{})
						af.hasCIDRFilters = true
					}
				} else {
					_, ipv6Addr, _ := patricia.ParseFromNetIPPrefix(prefix)
					if ipv6Addr != nil {
						af.cidrTreeV6.Set(*ipv6Addr, struct{}{})
						af.hasCIDRFilters = true
					}
				}
			} else if addr, err := netip.ParseAddr(filter.Pattern); err == nil {
				// Exact IP address - add to hash map for O(1) lookup
				if addr.Is4() {
					af.exactIPv4[addr] = struct{}{}
				} else {
					af.exactIPv6[addr] = struct{}{}
				}
			} else {
				// Legacy fallback: try net.ParseIP for non-standard formats
				if ip := net.ParseIP(filter.Pattern); ip != nil {
					if addr, ok := netip.AddrFromSlice(ip); ok {
						if addr.Is4() {
							af.exactIPv4[addr.Unmap()] = struct{}{}
						} else {
							af.exactIPv6[addr] = struct{}{}
						}
					}
				} else {
					logger.Warn("Failed to parse IP address filter", "pattern", filter.Pattern)
				}
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
	if af.enabled && af.gpuAccel != nil {
		backend := af.gpuAccel.Backend()
		if backend != nil {
			// Build default automaton for SIPUser+PhoneNumber patterns
			if len(af.acPatterns) > 0 {
				if err := backend.BuildNamedAutomaton("default", af.acPatterns); err != nil {
					logger.Warn("Failed to build GPU AC automaton for SIPUser/PhoneNumber, will use CPU fallback",
						"error", err,
						"pattern_count", len(af.acPatterns))
				} else {
					af.gpuACBuilt = true
					logger.Debug("GPU AC automaton built successfully for SIPUser/PhoneNumber",
						"pattern_count", len(af.acPatterns))
				}
			}

			// Build separate automaton for SIPURI patterns
			if len(af.sipURIPatterns) > 0 {
				if err := backend.BuildNamedAutomaton("sipuri", af.sipURIPatterns); err != nil {
					logger.Warn("Failed to build GPU AC automaton for SIPURI, will use CPU fallback",
						"error", err,
						"pattern_count", len(af.sipURIPatterns))
				} else {
					af.gpuSIPURIACBuilt = true
					logger.Debug("GPU AC automaton built successfully for SIPURI",
						"pattern_count", len(af.sipURIPatterns))
				}
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

	// Use GPU if enabled and at least one GPU automaton is built
	if af.enabled && af.gpuAccel != nil && (af.gpuACBuilt || af.gpuSIPURIACBuilt) {
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

	// Use GPU batch processing if enabled and at least one GPU automaton is built
	if af.enabled && af.gpuAccel != nil && len(voipPayloads) > 1 && (af.gpuACBuilt || af.gpuSIPURIACBuilt) {
		backend := af.gpuAccel.Backend()
		if backend != nil {
			matchedPayloads := make(map[int]bool)

			// SIPUser/PhoneNumber batch matching via GPU
			if af.gpuACBuilt && (len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0) {
				allUsernames := make([][]byte, 0, len(voipPayloads)*3)
				usernameToPacket := make([]int, 0, len(voipPayloads)*3)

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
					gpuResults, err := backend.MatchWithAutomaton("default", allUsernames)
					if err == nil {
						for usernameIdx, patternIDs := range gpuResults {
							if len(patternIDs) > 0 && usernameIdx < len(usernameToPacket) {
								matchedPayloads[usernameToPacket[usernameIdx]] = true
							}
						}
					}
				}
			}

			// SIPURI batch matching via GPU
			if af.gpuSIPURIACBuilt && len(af.sipURIs) > 0 {
				allURIs := make([][]byte, 0, len(voipPayloads)*3)
				uriToPacket := make([]int, 0, len(voipPayloads)*3)

				for payloadIdx, payload := range voipPayloads {
					// Skip already matched packets
					if matchedPayloads[payloadIdx] {
						continue
					}
					sipHeaders := extractSIPHeaders(payload)
					if len(sipHeaders.from) > 0 {
						if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.from); uri != "" {
							allURIs = append(allURIs, []byte(uri))
							uriToPacket = append(uriToPacket, payloadIdx)
						}
					}
					if len(sipHeaders.to) > 0 {
						if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.to); uri != "" {
							allURIs = append(allURIs, []byte(uri))
							uriToPacket = append(uriToPacket, payloadIdx)
						}
					}
					if len(sipHeaders.pAssertedIdentity) > 0 {
						if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.pAssertedIdentity); uri != "" {
							allURIs = append(allURIs, []byte(uri))
							uriToPacket = append(uriToPacket, payloadIdx)
						}
					}
				}

				if len(allURIs) > 0 {
					gpuResults, err := backend.MatchWithAutomaton("sipuri", allURIs)
					if err == nil {
						for uriIdx, patternIDs := range gpuResults {
							if len(patternIDs) > 0 && uriIdx < len(uriToPacket) {
								matchedPayloads[uriToPacket[uriIdx]] = true
							}
						}
					}
				}
			}

			// Map results back to packet indices
			for payloadIdx, packetIdx := range voipIndices {
				results[packetIdx] = matchedPayloads[payloadIdx]
			}
			return results
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
// Uses Aho-Corasick automaton (BuildNamedAutomaton/MatchWithAutomaton) for O(n) matching
// Both SIPUser/PhoneNumber and SIPURI have their own GPU automatons
func (af *ApplicationFilter) matchWithGPU(payload []byte) bool {
	backend := af.gpuAccel.Backend()
	if backend == nil {
		return af.matchWithCPU(string(payload))
	}

	// Extract SIP headers for matching
	sipHeaders := extractSIPHeaders(payload)

	// SIPUser/PhoneNumber matching via GPU (if we have those filters and GPU automaton is built)
	if (len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0) && af.gpuACBuilt {
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
			// Use GPU backend's MatchWithAutomaton with pre-built default AC automaton
			results, err := backend.MatchWithAutomaton("default", usernames)
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
	} else if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		// GPU automaton not built, use CPU
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
		if af.acMatcher.MatchUsernames(usernames) {
			return true
		}
	}

	// SIPURI matching via GPU (if we have those filters and GPU automaton is built)
	if len(af.sipURIs) > 0 && af.gpuSIPURIACBuilt {
		sipURIValues := make([][]byte, 0, 3)
		if len(sipHeaders.from) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.from); uri != "" {
				sipURIValues = append(sipURIValues, []byte(uri))
			}
		}
		if len(sipHeaders.to) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.to); uri != "" {
				sipURIValues = append(sipURIValues, []byte(uri))
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if uri := voip.ExtractURIFromHeaderBytes(sipHeaders.pAssertedIdentity); uri != "" {
				sipURIValues = append(sipURIValues, []byte(uri))
			}
		}

		if len(sipURIValues) > 0 {
			// Use GPU backend's MatchWithAutomaton with pre-built SIPURI AC automaton
			results, err := backend.MatchWithAutomaton("sipuri", sipURIValues)
			if err != nil {
				// Fall back to CPU on error
				uriStrs := make([]string, len(sipURIValues))
				for i, u := range sipURIValues {
					uriStrs[i] = string(u)
				}
				if af.sipURIMatcher.MatchUsernames(uriStrs) {
					return true
				}
			} else {
				// Check if any URI matched
				for _, patternIDs := range results {
					if len(patternIDs) > 0 {
						return true
					}
				}
			}
		}
	} else if len(af.sipURIs) > 0 {
		// GPU automaton not built, use CPU
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
// Uses O(1) hash map lookup for exact IPs and O(prefix) radix tree for CIDRs
func (af *ApplicationFilter) matchIPAddress(packet gopacket.Packet) bool {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return false
	}

	// Get raw IP bytes (4 bytes for IPv4, 16 bytes for IPv6)
	srcIPBytes := netLayer.NetworkFlow().Src().Raw()
	dstIPBytes := netLayer.NetworkFlow().Dst().Raw()

	// Convert to netip.Addr for hash map and radix tree lookups
	srcAddr, srcOk := netip.AddrFromSlice(srcIPBytes)
	dstAddr, dstOk := netip.AddrFromSlice(dstIPBytes)

	// Check source IP
	if srcOk {
		if af.matchSingleIP(srcAddr) {
			return true
		}
	}

	// Check destination IP
	if dstOk {
		if af.matchSingleIP(dstAddr) {
			return true
		}
	}

	return false
}

// matchSingleIP checks if a single IP address matches any filter (exact or CIDR)
// Uses O(1) hash map lookup for exact matches, O(prefix) radix tree for CIDRs
func (af *ApplicationFilter) matchSingleIP(addr netip.Addr) bool {
	// Normalize IPv4-mapped IPv6 addresses to plain IPv4
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	if addr.Is4() {
		// O(1) exact match check
		if _, found := af.exactIPv4[addr]; found {
			return true
		}

		// O(prefix) CIDR match check via radix tree
		if af.hasCIDRFilters {
			ipv4Addr, _, _ := patricia.ParseFromNetIPAddr(addr)
			if ipv4Addr != nil {
				if found, _ := af.cidrTreeV4.FindDeepestTag(*ipv4Addr); found {
					return true
				}
			}
		}
	} else {
		// O(1) exact match check
		if _, found := af.exactIPv6[addr]; found {
			return true
		}

		// O(prefix) CIDR match check via radix tree
		if af.hasCIDRFilters {
			_, ipv6Addr, _ := patricia.ParseFromNetIPAddr(addr)
			if ipv6Addr != nil {
				if found, _ := af.cidrTreeV6.FindDeepestTag(*ipv6Addr); found {
					return true
				}
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
