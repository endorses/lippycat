//go:build hunter || tap || all

package hunter

import (
	"bytes"
	"net"
	"net/netip"
	"strings"
	"sync"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/ahocorasick"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/hunter/filter"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/phonematcher"
	"github.com/endorses/lippycat/internal/pkg/tls"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/kentik/patricia"
	"github.com/kentik/patricia/generics_tree"
)

// NoFilterPolicy controls behavior when no filters are configured
type NoFilterPolicy string

const (
	// NoFilterPolicyAllow allows all packets when no filters are set (default, current behavior)
	NoFilterPolicyAllow NoFilterPolicy = "allow"
	// NoFilterPolicyDeny blocks all packets when no filters are set (useful for remote-configured nodes)
	NoFilterPolicyDeny NoFilterPolicy = "deny"
)

// parsedFilter holds a parsed pattern with its type for matching
type parsedFilter struct {
	id          string                // Filter ID from management.Filter (for LI correlation)
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
	acPatterns     []ahocorasick.Pattern        // AC patterns for GPU backend (SIP users only)
	acMatcher      *ahocorasick.BufferedMatcher // Aho-Corasick matcher for SIP user matching (alphanumeric)
	phoneMatcher   *phonematcher.Matcher        // Bloom+hash matcher for phone numbers (LI-optimized)
	sipURIPatterns []ahocorasick.Pattern        // AC patterns for SIPURI matching (user@domain)
	sipURIMatcher  *ahocorasick.BufferedMatcher // Separate Aho-Corasick matcher for SIPURI matching

	// Protocol-specific matchers
	dnsMatcher   *filter.DNSMatcher   // DNS domain pattern matcher
	emailMatcher *filter.EmailMatcher // Email address/subject pattern matcher
	tlsMatcher   *filter.TLSMatcher   // TLS SNI/JA3/JA3S/JA4 matcher
	tlsParser    *tls.Parser          // TLS handshake parser for metadata extraction

	// Filter ID mappings for LI correlation
	acPatternToFilterID     map[int]string    // AC pattern ID -> filter ID (for SIPUser/PhoneNumber AC patterns)
	phoneNumberToFilterID   map[string]string // Normalized phone number -> filter ID (for PhoneNumberMatcher)
	sipURIPatternToFilterID map[int]string    // SIPURI AC pattern ID -> filter ID

	// IP filter data structures for O(1) exact matching and O(prefix) CIDR matching
	exactIPv4      map[netip.Addr]string         // Hash map for O(1) exact IPv4 lookup (value = filter ID)
	exactIPv6      map[netip.Addr]string         // Hash map for O(1) exact IPv6 lookup (value = filter ID)
	cidrTreeV4     *generics_tree.TreeV4[string] // Radix tree for IPv4 CIDR matching (tag = filter ID)
	cidrTreeV6     *generics_tree.TreeV6[string] // Radix tree for IPv6 CIDR matching (tag = filter ID)
	hasCIDRFilters bool                          // Whether any CIDR filters are present

	mu               sync.RWMutex
	enabled          bool
	gpuACBuilt       bool           // Whether GPU has default (SIPUser+PhoneNumber) AC automaton built
	gpuSIPURIACBuilt bool           // Whether GPU has SIPURI AC automaton built
	noFilterPolicy   NoFilterPolicy // Policy when no filters are configured (allow/deny)
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
		config:                  config,
		detector:                detector.InitDefault(), // Use centralized detector for accurate protocol detection
		sipUsers:                make([]parsedFilter, 0),
		sipURIs:                 make([]parsedFilter, 0),
		phoneNumbers:            make([]parsedFilter, 0),
		ipAddresses:             make([]string, 0),
		patterns:                make([]voip.GPUPattern, 0),
		acPatterns:              make([]ahocorasick.Pattern, 0),
		acMatcher:               ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Aho-Corasick for SIP users
		phoneMatcher:            phonematcher.New(),                                       // Bloom+hash for phone numbers (LI-optimized)
		sipURIPatterns:          make([]ahocorasick.Pattern, 0),
		sipURIMatcher:           ahocorasick.NewBufferedMatcherWithAlgorithm(acAlgorithm), // Separate AC for SIPURI
		dnsMatcher:              filter.NewDNSMatcher(),                                   // DNS domain matcher
		emailMatcher:            filter.NewEmailMatcher(),                                 // Email address/subject matcher
		tlsMatcher:              filter.NewTLSMatcher(),                                   // TLS SNI/JA3/JA3S/JA4 matcher
		tlsParser:               tls.NewParser(),                                          // TLS handshake parser
		acPatternToFilterID:     make(map[int]string),
		phoneNumberToFilterID:   make(map[string]string),
		sipURIPatternToFilterID: make(map[int]string),
		exactIPv4:               make(map[netip.Addr]string),
		exactIPv6:               make(map[netip.Addr]string),
		cidrTreeV4:              generics_tree.NewTreeV4[string](),
		cidrTreeV6:              generics_tree.NewTreeV6[string](),
		hasCIDRFilters:          false,
		enabled:                 config != nil && config.Enabled,
		gpuACBuilt:              false,
		noFilterPolicy:          NoFilterPolicyAllow, // Default: allow all when no filters
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

// SetNoFilterPolicy sets the policy for when no filters are configured.
// NoFilterPolicyAllow (default) allows all packets when no filters are set.
// NoFilterPolicyDeny blocks all packets when no filters are set.
func (af *ApplicationFilter) SetNoFilterPolicy(policy NoFilterPolicy) {
	af.mu.Lock()
	defer af.mu.Unlock()
	af.noFilterPolicy = policy
	logger.Info("No-filter policy updated", "policy", string(policy))
}

// GetNoFilterPolicy returns the current no-filter policy.
func (af *ApplicationFilter) GetNoFilterPolicy() NoFilterPolicy {
	af.mu.RLock()
	defer af.mu.RUnlock()
	return af.noFilterPolicy
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
	af.exactIPv4 = make(map[netip.Addr]string)
	af.exactIPv6 = make(map[netip.Addr]string)
	af.cidrTreeV4 = generics_tree.NewTreeV4[string]()
	af.cidrTreeV6 = generics_tree.NewTreeV6[string]()
	af.hasCIDRFilters = false

	// Reset filter ID mappings
	af.acPatternToFilterID = make(map[int]string)
	af.phoneNumberToFilterID = make(map[string]string)
	af.sipURIPatternToFilterID = make(map[int]string)

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
				id:          filter.Id,
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
				id:          filter.Id,
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
						af.cidrTreeV4.Set(*ipv4Addr, filter.Id)
						af.hasCIDRFilters = true
					}
				} else {
					_, ipv6Addr, _ := patricia.ParseFromNetIPPrefix(prefix)
					if ipv6Addr != nil {
						af.cidrTreeV6.Set(*ipv6Addr, filter.Id)
						af.hasCIDRFilters = true
					}
				}
			} else if addr, err := netip.ParseAddr(filter.Pattern); err == nil {
				// Exact IP address - add to hash map for O(1) lookup
				if addr.Is4() {
					af.exactIPv4[addr] = filter.Id
				} else {
					af.exactIPv6[addr] = filter.Id
				}
			} else {
				// Legacy fallback: try net.ParseIP for non-standard formats
				if ip := net.ParseIP(filter.Pattern); ip != nil {
					if addr, ok := netip.AddrFromSlice(ip); ok {
						if addr.Is4() {
							af.exactIPv4[addr.Unmap()] = filter.Id
						} else {
							af.exactIPv6[addr] = filter.Id
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
				id:          filter.Id,
				original:    filter.Pattern,
				pattern:     pattern,
				patternType: patternType,
				gpuType:     gpuType,
			})

			// DNS domain filters are handled by the dedicated DNS matcher
			// case management.FilterType_FILTER_DNS_DOMAIN: handled below

			// Future: Add other protocol-specific filters here
			// case management.FilterType_FILTER_HTTP_HOST:
			// case management.FilterType_FILTER_HTTP_URL:
		}
	}

	// Update DNS matcher with all filters (it extracts DNS domain filters internally)
	if af.dnsMatcher != nil {
		af.dnsMatcher.UpdateFilters(filters)
	}

	// Update email matcher with all filters (it extracts email address/subject filters internally)
	if af.emailMatcher != nil {
		af.emailMatcher.UpdateFilters(filters)
	}

	// Update TLS matcher with all filters (it extracts TLS SNI/JA3/JA3S/JA4 filters internally)
	if af.tlsMatcher != nil {
		af.tlsMatcher.UpdateFilters(filters)
	}

	logger.Info("Updated application-level filters (hot-reload, no restart)",
		"sip_users", len(af.sipUsers),
		"sip_uris", len(af.sipURIs),
		"phone_numbers", len(af.phoneNumbers),
		"ip_addresses", len(af.ipAddresses),
		"dns_domains", af.dnsMatcher.HasFilters(),
		"email_filters", af.emailMatcher.HasFilters(),
		"tls_filters", af.tlsMatcher.HasFilters(),
		"gpu_enabled", af.enabled)

	// Build Aho-Corasick patterns for CPU matching
	// - SIP users: always use AC (alphanumeric usernames)
	// - Phone numbers with wildcards (*): use AC (suffix/prefix/contains matching)
	// - Phone numbers without wildcards (exact): use PhoneNumberMatcher (LI-optimized)
	af.acPatterns = make([]ahocorasick.Pattern, 0, len(af.sipUsers)+len(af.phoneNumbers))
	exactPhonePatterns := make([]string, 0, len(af.phoneNumbers))

	// Add SIP user patterns to AC
	for i, f := range af.sipUsers {
		patternID := i
		af.acPatterns = append(af.acPatterns, ahocorasick.Pattern{
			ID:   patternID,
			Text: f.pattern,
			Type: f.patternType,
		})
		// Map AC pattern ID to filter ID for LI correlation
		af.acPatternToFilterID[patternID] = f.id
	}

	// Separate phone numbers:
	// - Wildcard patterns (prefix/suffix) → AC
	// - Non-digit patterns (contains letters, +, etc.) → AC (substring matching)
	// - Pure digit patterns → PhoneNumberMatcher (LI-optimized suffix matching)
	baseID := len(af.sipUsers)
	for i, f := range af.phoneNumbers {
		if f.patternType != filtering.PatternTypeContains || !phonematcher.IsDigitsOnly(f.pattern) {
			// Wildcard pattern OR non-digit pattern - use AC for substring/wildcard matching
			patternID := baseID + i
			af.acPatterns = append(af.acPatterns, ahocorasick.Pattern{
				ID:   patternID,
				Text: f.pattern,
				Type: f.patternType,
			})
			// Map AC pattern ID to filter ID for LI correlation
			af.acPatternToFilterID[patternID] = f.id
		} else {
			// Pure digit pattern (LI use case) - use PhoneNumberMatcher
			exactPhonePatterns = append(exactPhonePatterns, f.pattern)
			// Map normalized phone number to filter ID for LI correlation
			af.phoneNumberToFilterID[f.pattern] = f.id
		}
	}

	// Trigger background rebuild of AC automaton for CPU
	af.acMatcher.UpdatePatterns(af.acPatterns)

	// Update PhoneNumberMatcher with exact phone number patterns
	// Uses bloom filter + hash set for O(1) suffix matching (LI-optimized)
	af.phoneMatcher.UpdatePatterns(exactPhonePatterns)

	// Build SIPURI AC patterns (separate automaton for user@domain matching)
	af.sipURIPatterns = make([]ahocorasick.Pattern, 0, len(af.sipURIs))
	for i, f := range af.sipURIs {
		patternID := i
		af.sipURIPatterns = append(af.sipURIPatterns, ahocorasick.Pattern{
			ID:   patternID,
			Text: f.pattern,
			Type: f.patternType,
		})
		// Map SIPURI AC pattern ID to filter ID for LI correlation
		af.sipURIPatternToFilterID[patternID] = f.id
	}

	// Trigger background rebuild of SIPURI AC automaton
	af.sipURIMatcher.UpdatePatterns(af.sipURIPatterns)

	// Build AC automaton in GPU backend if enabled (SIP users only)
	// Phone numbers use CPU PhoneNumberMatcher (bloom+hash) which is already O(1) and ~90ns
	if af.enabled && af.gpuAccel != nil {
		backend := af.gpuAccel.Backend()
		if backend != nil {
			// Build default automaton for SIPUser patterns only
			if len(af.acPatterns) > 0 {
				if err := backend.BuildNamedAutomaton("default", af.acPatterns); err != nil {
					logger.Warn("Failed to build GPU AC automaton for SIPUser, will use CPU fallback",
						"error", err,
						"pattern_count", len(af.acPatterns))
				} else {
					af.gpuACBuilt = true
					logger.Debug("GPU AC automaton built successfully for SIPUser",
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

	// Check if we have any filters at all
	hasDNSFilters := af.dnsMatcher != nil && af.dnsMatcher.HasFilters()
	hasEmailFilters := af.emailMatcher != nil && af.emailMatcher.HasFilters()
	hasTLSFilters := af.tlsMatcher != nil && af.tlsMatcher.HasFilters()
	hasVoIPFilters := len(af.sipUsers) > 0 || len(af.sipURIs) > 0 || len(af.phoneNumbers) > 0
	hasIPFilters := len(af.ipAddresses) > 0

	// If no filters, use the no-filter policy
	if !hasIPFilters && !hasVoIPFilters && !hasDNSFilters && !hasEmailFilters && !hasTLSFilters {
		return af.noFilterPolicy == NoFilterPolicyAllow
	}

	// Check IP addresses first (applies to all protocols)
	if hasIPFilters {
		if af.matchIPAddressBool(packet) {
			return true
		}
		// If we have ONLY IP filters (no other protocol filters), no match
		if !hasVoIPFilters && !hasDNSFilters && !hasTLSFilters {
			return false
		}
	}

	// Check DNS packets
	if hasDNSFilters {
		if matched, _ := af.matchDNSPacket(packet); matched {
			return true
		}
	}

	// Check email packets
	if hasEmailFilters {
		if matched, _ := af.matchEmailPacket(packet); matched {
			return true
		}
	}

	// Check TLS packets
	if hasTLSFilters {
		if matched, _ := af.matchTLSPacket(packet); matched {
			return true
		}
	}

	// Check VoIP packets
	if hasVoIPFilters {
		// Check if this is a SIP or RTP packet
		if af.isVoIPPacket(packet) {
			// Get payload - use LayerContents() to get full message including headers
			// Payload() only returns the body (e.g., SDP for SIP), missing critical info
			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				payload := appLayer.LayerContents()

				// Use GPU if enabled and at least one GPU automaton is built
				if af.enabled && af.gpuAccel != nil && (af.gpuACBuilt || af.gpuSIPURIACBuilt) {
					return af.matchWithGPU([]byte(payload))
				}

				// CPU fallback
				return af.matchWithCPU(string(payload))
			}
		}
	}

	return false
}

// MatchPacketWithIDs checks if a packet matches any filters and returns the matched filter IDs.
// This method is used for LI correlation - it returns which specific filters matched
// so the LI Manager can look up the corresponding intercept task XIDs.
func (af *ApplicationFilter) MatchPacketWithIDs(packet gopacket.Packet) (bool, []string) {
	af.mu.RLock()
	defer af.mu.RUnlock()

	var matchedFilterIDs []string

	// Check if we have any filters at all
	hasDNSFilters := af.dnsMatcher != nil && af.dnsMatcher.HasFilters()
	hasEmailFilters := af.emailMatcher != nil && af.emailMatcher.HasFilters()
	hasTLSFilters := af.tlsMatcher != nil && af.tlsMatcher.HasFilters()
	hasVoIPFilters := len(af.sipUsers) > 0 || len(af.sipURIs) > 0 || len(af.phoneNumbers) > 0
	hasIPFilters := len(af.ipAddresses) > 0

	// If no filters, use the no-filter policy (but no specific filter IDs)
	if !hasIPFilters && !hasVoIPFilters && !hasDNSFilters && !hasEmailFilters && !hasTLSFilters {
		return af.noFilterPolicy == NoFilterPolicyAllow, nil
	}

	// Check IP addresses first (applies to all protocols)
	if hasIPFilters {
		ipFilterIDs := af.matchIPAddress(packet)
		if len(ipFilterIDs) > 0 {
			matchedFilterIDs = append(matchedFilterIDs, ipFilterIDs...)
		}
	}

	// Check DNS packets
	if hasDNSFilters {
		if matched, dnsFilterIDs := af.matchDNSPacket(packet); matched {
			matchedFilterIDs = append(matchedFilterIDs, dnsFilterIDs...)
		}
	}

	// Check email packets
	if hasEmailFilters {
		if matched, emailFilterIDs := af.matchEmailPacket(packet); matched {
			matchedFilterIDs = append(matchedFilterIDs, emailFilterIDs...)
		}
	}

	// Check TLS packets
	if hasTLSFilters {
		if matched, tlsFilterIDs := af.matchTLSPacket(packet); matched {
			matchedFilterIDs = append(matchedFilterIDs, tlsFilterIDs...)
		}
	}

	// Check VoIP packets
	if hasVoIPFilters {
		// Check if this is a SIP or RTP packet
		if af.isVoIPPacket(packet) {
			// Get payload - use LayerContents() to get full message including headers
			appLayer := packet.ApplicationLayer()
			if appLayer != nil {
				payload := appLayer.LayerContents()

				// Match VoIP filters and collect filter IDs
				voipFilterIDs := af.matchWithCPUAndReturnIDs(payload)
				matchedFilterIDs = append(matchedFilterIDs, voipFilterIDs...)
			}
		}
	}

	return len(matchedFilterIDs) > 0, matchedFilterIDs
}

// matchWithCPUAndReturnIDs uses CPU matching and returns matched filter IDs.
// This is used by MatchPacketWithIDs for LI correlation.
func (af *ApplicationFilter) matchWithCPUAndReturnIDs(payload []byte) []string {
	var matchedFilterIDs []string
	seen := make(map[string]bool) // Deduplicate filter IDs

	// Extract SIP headers for proper matching
	sipHeaders := extractSIPHeaders(payload)

	// Extract usernames for SIPUser and PhoneNumber matching
	var usernames []string
	if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		usernames = make([]string, 0, 3)
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
	}

	// SIPUser + wildcard PhoneNumber matching: use Aho-Corasick with ID tracking
	if len(af.acPatterns) > 0 && len(usernames) > 0 {
		for _, username := range usernames {
			results := af.acMatcher.Match([]byte(username))
			for _, result := range results {
				if filterID, ok := af.acPatternToFilterID[result.PatternID]; ok && filterID != "" {
					if !seen[filterID] {
						seen[filterID] = true
						matchedFilterIDs = append(matchedFilterIDs, filterID)
					}
				}
			}
		}
	}

	// Exact PhoneNumber matching: use PhoneNumberMatcher
	if af.phoneMatcher.Size() > 0 && len(usernames) > 0 {
		for _, username := range usernames {
			if matchedPhone, ok := af.phoneMatcher.Match(username); ok {
				if filterID, found := af.phoneNumberToFilterID[matchedPhone]; found && filterID != "" {
					if !seen[filterID] {
						seen[filterID] = true
						matchedFilterIDs = append(matchedFilterIDs, filterID)
					}
				}
			}
		}
	}

	// SIPURI matching: extract user@domain, use exact/contains matching
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

		for _, uri := range sipURIValues {
			results := af.sipURIMatcher.Match([]byte(uri))
			for _, result := range results {
				if filterID, ok := af.sipURIPatternToFilterID[result.PatternID]; ok && filterID != "" {
					if !seen[filterID] {
						seen[filterID] = true
						matchedFilterIDs = append(matchedFilterIDs, filterID)
					}
				}
			}
		}
	}

	return matchedFilterIDs
}

// MatchBatch checks multiple packets using GPU acceleration
// Uses Aho-Corasick automaton for O(n) username matching
func (af *ApplicationFilter) MatchBatch(packets []gopacket.Packet) []bool {
	af.mu.RLock()
	defer af.mu.RUnlock()

	results := make([]bool, len(packets))

	// If no filters, use the no-filter policy
	if len(af.sipUsers) == 0 && len(af.sipURIs) == 0 && len(af.phoneNumbers) == 0 {
		matchAll := af.noFilterPolicy == NoFilterPolicyAllow
		for i := range results {
			results[i] = matchAll
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

// matchWithGPU uses GPU acceleration for SIP user matching and CPU for phone numbers
// SIP users use GPU Aho-Corasick, phone numbers use CPU PhoneNumberMatcher (bloom+hash)
// SIPURI patterns use a separate GPU Aho-Corasick automaton
func (af *ApplicationFilter) matchWithGPU(payload []byte) bool {
	backend := af.gpuAccel.Backend()
	if backend == nil {
		return af.matchWithCPU(string(payload))
	}

	// Extract SIP headers for matching
	sipHeaders := extractSIPHeaders(payload)

	// Extract usernames once for both SIPUser and PhoneNumber matching
	var usernameStrs []string
	if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		usernameStrs = make([]string, 0, 3)
		if len(sipHeaders.from) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.from); user != "" {
				usernameStrs = append(usernameStrs, user)
			}
		}
		if len(sipHeaders.to) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.to); user != "" {
				usernameStrs = append(usernameStrs, user)
			}
		}
		if len(sipHeaders.pAssertedIdentity) > 0 {
			if user := voip.ExtractUserFromHeaderBytes(sipHeaders.pAssertedIdentity); user != "" {
				usernameStrs = append(usernameStrs, user)
			}
		}
	}

	// SIPUser + wildcard PhoneNumber matching via GPU (if we have AC patterns and GPU automaton is built)
	if len(af.acPatterns) > 0 && len(usernameStrs) > 0 {
		if af.gpuACBuilt {
			usernames := make([][]byte, len(usernameStrs))
			for i, u := range usernameStrs {
				usernames[i] = []byte(u)
			}
			results, err := backend.MatchWithAutomaton("default", usernames)
			if err != nil {
				// Fall back to CPU on error
				if af.acMatcher.MatchUsernames(usernameStrs) {
					return true
				}
			} else {
				for _, patternIDs := range results {
					if len(patternIDs) > 0 {
						return true
					}
				}
			}
		} else {
			// GPU automaton not built, use CPU
			if af.acMatcher.MatchUsernames(usernameStrs) {
				return true
			}
		}
	}

	// Exact PhoneNumber matching: use CPU PhoneNumberMatcher (bloom+hash, O(1) ~90ns)
	// Only for exact phone number patterns (no wildcards) - LI use case
	if af.phoneMatcher.Size() > 0 && len(usernameStrs) > 0 {
		for _, username := range usernameStrs {
			if _, ok := af.phoneMatcher.Match(username); ok {
				return true
			}
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

// matchWithCPU uses Aho-Corasick for SIP users and PhoneNumberMatcher for phone numbers
// Runs separate matching passes for SIPUser, PhoneNumber, and SIPURI
// Only runs each pass if filters of that type exist (typical case: single pass)
func (af *ApplicationFilter) matchWithCPU(payload string) bool {
	// Convert to bytes for header extraction
	payloadBytes := []byte(payload)

	// Extract SIP headers for proper matching
	sipHeaders := extractSIPHeaders(payloadBytes)

	// Extract usernames once for both SIPUser and PhoneNumber matching
	var usernames []string
	if len(af.sipUsers) > 0 || len(af.phoneNumbers) > 0 {
		usernames = make([]string, 0, 3)
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
	}

	// SIPUser + wildcard PhoneNumber matching: use Aho-Corasick
	// AC handles: all SIP users + phone numbers with wildcards (prefix/suffix patterns)
	if len(af.acPatterns) > 0 && len(usernames) > 0 {
		if af.acMatcher.MatchUsernames(usernames) {
			return true
		}
	}

	// Exact PhoneNumber matching: use PhoneNumberMatcher for LI-optimized suffix matching
	// Uses bloom filter for fast rejection (99%+ of non-matches in ~10ns)
	// Only for exact phone number patterns (no wildcards) - LI use case
	if af.phoneMatcher.Size() > 0 && len(usernames) > 0 {
		for _, username := range usernames {
			if _, ok := af.phoneMatcher.Match(username); ok {
				return true
			}
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
// Returns matched filter IDs
func (af *ApplicationFilter) matchIPAddress(packet gopacket.Packet) []string {
	netLayer := packet.NetworkLayer()
	if netLayer == nil {
		return nil
	}

	// Get raw IP bytes (4 bytes for IPv4, 16 bytes for IPv6)
	srcIPBytes := netLayer.NetworkFlow().Src().Raw()
	dstIPBytes := netLayer.NetworkFlow().Dst().Raw()

	// Convert to netip.Addr for hash map and radix tree lookups
	srcAddr, srcOk := netip.AddrFromSlice(srcIPBytes)
	dstAddr, dstOk := netip.AddrFromSlice(dstIPBytes)

	var matchedIDs []string

	// Check source IP
	if srcOk {
		if filterID, matched := af.matchSingleIP(srcAddr); matched {
			matchedIDs = append(matchedIDs, filterID)
		}
	}

	// Check destination IP
	if dstOk {
		if filterID, matched := af.matchSingleIP(dstAddr); matched {
			// Avoid duplicates if same filter matches both src and dst
			if len(matchedIDs) == 0 || matchedIDs[0] != filterID {
				matchedIDs = append(matchedIDs, filterID)
			}
		}
	}

	return matchedIDs
}

// matchIPAddressBool checks if packet source or destination IP matches any filter
// Returns true if any filter matches (for backward compatibility)
func (af *ApplicationFilter) matchIPAddressBool(packet gopacket.Packet) bool {
	return len(af.matchIPAddress(packet)) > 0
}

// matchSingleIP checks if a single IP address matches any filter (exact or CIDR)
// Uses O(1) hash map lookup for exact matches, O(prefix) radix tree for CIDRs
// Returns the matched filter ID if found, empty string otherwise
func (af *ApplicationFilter) matchSingleIP(addr netip.Addr) (string, bool) {
	// Normalize IPv4-mapped IPv6 addresses to plain IPv4
	if addr.Is4In6() {
		addr = addr.Unmap()
	}

	if addr.Is4() {
		// O(1) exact match check
		if filterID, found := af.exactIPv4[addr]; found {
			return filterID, true
		}

		// O(prefix) CIDR match check via radix tree
		if af.hasCIDRFilters {
			ipv4Addr, _, _ := patricia.ParseFromNetIPAddr(addr)
			if ipv4Addr != nil {
				if found, filterID := af.cidrTreeV4.FindDeepestTag(*ipv4Addr); found {
					return filterID, true
				}
			}
		}
	} else {
		// O(1) exact match check
		if filterID, found := af.exactIPv6[addr]; found {
			return filterID, true
		}

		// O(prefix) CIDR match check via radix tree
		if af.hasCIDRFilters {
			_, ipv6Addr, _ := patricia.ParseFromNetIPAddr(addr)
			if ipv6Addr != nil {
				if found, filterID := af.cidrTreeV6.FindDeepestTag(*ipv6Addr); found {
					return filterID, true
				}
			}
		}
	}

	return "", false
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

// matchDNSPacket checks if a packet is DNS and matches domain filters.
// Returns true if the packet is DNS and matches at least one filter, along with matched filter IDs.
func (af *ApplicationFilter) matchDNSPacket(packet gopacket.Packet) (bool, []string) {
	// First check if this is a DNS packet using the detector
	result := af.detector.Detect(packet)
	if result == nil || result.Protocol != "DNS" {
		return false, nil
	}

	// Parse DNS layer to get query/response domains
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return false, nil
	}

	dns, ok := dnsLayer.(*layers.DNS)
	if !ok {
		return false, nil
	}

	// Collect all domain names from queries and answers
	var domains []string

	// Extract query names
	for _, question := range dns.Questions {
		if len(question.Name) > 0 {
			domains = append(domains, string(question.Name))
		}
	}

	// Extract answer names (for responses)
	for _, answer := range dns.Answers {
		if len(answer.Name) > 0 {
			domains = append(domains, string(answer.Name))
		}
		// Also extract CNAME targets
		if answer.Type == layers.DNSTypeCNAME && len(answer.CNAME) > 0 {
			domains = append(domains, string(answer.CNAME))
		}
	}

	if len(domains) == 0 {
		return false, nil
	}

	// Match domains against filters
	var matchedFilterIDs []string
	seen := make(map[string]bool) // Deduplicate filter IDs

	for _, domain := range domains {
		if matched, filterIDs := af.dnsMatcher.MatchDomain(domain); matched {
			for _, id := range filterIDs {
				if !seen[id] {
					seen[id] = true
					matchedFilterIDs = append(matchedFilterIDs, id)
				}
			}
		}
	}

	return len(matchedFilterIDs) > 0, matchedFilterIDs
}

// matchEmailPacket checks if a packet is an email protocol (SMTP, POP3, IMAP) and matches email filters.
// Returns true if the packet is email and matches at least one filter, along with matched filter IDs.
func (af *ApplicationFilter) matchEmailPacket(packet gopacket.Packet) (bool, []string) {
	// First check if this is an email protocol packet using the detector
	result := af.detector.Detect(packet)
	if result == nil {
		return false, nil
	}

	// Check for email protocols
	switch result.Protocol {
	case "SMTP", "POP3", "IMAP":
		// Email protocol detected
	default:
		return false, nil
	}

	// Get packet payload for field extraction
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		return false, nil
	}
	payload := appLayer.LayerContents()
	if len(payload) == 0 {
		return false, nil
	}

	// Extract email fields based on protocol
	var sender, recipient, subject string

	switch result.Protocol {
	case "SMTP":
		sender, recipient, subject = af.extractSMTPFields(payload, result.Metadata)
	case "POP3", "IMAP":
		// POP3/IMAP field extraction can be added later
		// For now, just match based on detected protocol
	}

	// If no fields extracted, check if this is a protocol we should pass through
	// when we have email filters (to support session-based filtering at processor)
	if sender == "" && recipient == "" && subject == "" {
		return false, nil
	}

	// Match against email filters
	var matchedFilterIDs []string
	seen := make(map[string]bool)

	// Match sender address
	if sender != "" {
		if matched, filterIDs := af.emailMatcher.MatchAddress(sender); matched {
			for _, id := range filterIDs {
				if !seen[id] {
					seen[id] = true
					matchedFilterIDs = append(matchedFilterIDs, id)
				}
			}
		}
	}

	// Match recipient address
	if recipient != "" {
		if matched, filterIDs := af.emailMatcher.MatchAddress(recipient); matched {
			for _, id := range filterIDs {
				if !seen[id] {
					seen[id] = true
					matchedFilterIDs = append(matchedFilterIDs, id)
				}
			}
		}
	}

	// Match subject
	if subject != "" {
		if matched, filterIDs := af.emailMatcher.MatchSubject(subject); matched {
			for _, id := range filterIDs {
				if !seen[id] {
					seen[id] = true
					matchedFilterIDs = append(matchedFilterIDs, id)
				}
			}
		}
	}

	return len(matchedFilterIDs) > 0, matchedFilterIDs
}

// matchTLSPacket checks if a packet is TLS and matches TLS filters (SNI, JA3, JA3S, JA4).
// Returns true if the packet is TLS and matches at least one filter, along with matched filter IDs.
func (af *ApplicationFilter) matchTLSPacket(packet gopacket.Packet) (bool, []string) {
	// First check if this is a TLS packet using the detector
	result := af.detector.Detect(packet)
	if result == nil || result.Protocol != "TLS" {
		return false, nil
	}

	// Parse TLS handshake to extract metadata
	if af.tlsParser == nil {
		return false, nil
	}

	tlsMetadata := af.tlsParser.Parse(packet)
	if tlsMetadata == nil {
		return false, nil
	}

	// Only match on ClientHello and ServerHello (where we have fingerprints)
	if tlsMetadata.HandshakeType != "ClientHello" && tlsMetadata.HandshakeType != "ServerHello" {
		return false, nil
	}

	// Match against TLS filters using the TLS matcher
	// ClientHello: has SNI, JA3, JA4
	// ServerHello: has JA3S
	matched, filterIDs := af.tlsMatcher.MatchTLSHandshake(
		tlsMetadata.SNI,
		tlsMetadata.JA3Fingerprint,
		tlsMetadata.JA3SFingerprint,
		tlsMetadata.JA4Fingerprint,
	)

	return matched, filterIDs
}

// extractSMTPFields extracts sender, recipient, and subject from SMTP packet payload.
// Uses detector metadata when available, falls back to payload parsing.
func (af *ApplicationFilter) extractSMTPFields(payload []byte, metadata map[string]interface{}) (sender, recipient, subject string) {
	payloadStr := string(payload)

	// Check detector metadata for command type and args
	if metadata != nil {
		if msgType, ok := metadata["type"].(string); ok && msgType == "command" {
			if cmd, ok := metadata["command"].(string); ok {
				if args, ok := metadata["args"].(string); ok {
					switch cmd {
					case "MAIL", "MAIL FROM":
						sender = extractEmailAddress(args)
					case "RCPT", "RCPT TO":
						recipient = extractEmailAddress(args)
					}
				}
			}
			return
		}
	}

	// Parse payload directly for commands
	upperPayload := bytes.ToUpper(payload[:min(20, len(payload))])

	if bytes.HasPrefix(upperPayload, []byte("MAIL FROM:")) {
		// Extract sender from MAIL FROM:<addr>
		colonIdx := bytes.IndexByte(payload, ':')
		if colonIdx != -1 && colonIdx < len(payload)-1 {
			sender = extractEmailAddress(string(payload[colonIdx+1:]))
		}
	} else if bytes.HasPrefix(upperPayload, []byte("RCPT TO:")) {
		// Extract recipient from RCPT TO:<addr>
		colonIdx := bytes.IndexByte(payload, ':')
		if colonIdx != -1 && colonIdx < len(payload)-1 {
			recipient = extractEmailAddress(string(payload[colonIdx+1:]))
		}
	} else if isSubjectHeader(payloadStr) {
		// Extract subject from Subject: header line
		subject = extractSubjectLine(payloadStr)
	}

	return
}

// extractEmailAddress extracts an email address from an SMTP command argument.
// Handles formats like: <user@example.com>, "Name" <user@example.com>, user@example.com
func extractEmailAddress(arg string) string {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		return ""
	}

	// Look for angle brackets first: <user@example.com>
	ltIdx := strings.IndexByte(arg, '<')
	if ltIdx != -1 {
		gtIdx := strings.IndexByte(arg[ltIdx:], '>')
		if gtIdx != -1 {
			return strings.TrimSpace(arg[ltIdx+1 : ltIdx+gtIdx])
		}
	}

	// No angle brackets - might be bare address or have trailing params
	// Split on whitespace and take first part
	parts := strings.Fields(arg)
	if len(parts) > 0 {
		addr := parts[0]
		// Remove any trailing >
		addr = strings.TrimSuffix(addr, ">")
		if strings.Contains(addr, "@") {
			return addr
		}
	}

	return ""
}

// isSubjectHeader checks if the payload line is a Subject header.
func isSubjectHeader(payload string) bool {
	upper := strings.ToUpper(payload)
	return strings.HasPrefix(upper, "SUBJECT:")
}

// extractSubjectLine extracts the subject value from a Subject header line.
func extractSubjectLine(payload string) string {
	colonIdx := strings.IndexByte(payload, ':')
	if colonIdx == -1 || colonIdx >= len(payload)-1 {
		return ""
	}

	// Get value after colon, trim whitespace
	subject := strings.TrimSpace(payload[colonIdx+1:])

	// Handle CRLF - take only first line
	if crlfIdx := strings.Index(subject, "\r\n"); crlfIdx != -1 {
		subject = subject[:crlfIdx]
	} else if lfIdx := strings.IndexByte(subject, '\n'); lfIdx != -1 {
		subject = subject[:lfIdx]
	}

	return strings.TrimSpace(subject)
}

// Close cleans up GPU resources
func (af *ApplicationFilter) Close() {
	if af.gpuAccel != nil {
		// GPU cleanup would happen here
		logger.Info("Application filter closed")
	}
}
