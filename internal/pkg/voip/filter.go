package voip

import (
	"fmt"
	"strconv"
	"strings"
)

// Default RTP port range constants (exported for documentation/testing)
const (
	DefaultRTPPortRangeStart = 10000
	DefaultRTPPortRangeEnd   = 32768
)

// IPFragmentClause is a BPF expression that matches IP fragments.
// This is critical for capturing fragmented SIP packets (e.g., large INVITEs
// with SDP bodies that exceed MTU). Without this clause, BPF filters like
// "port 5060 or udp" will drop the second fragment of fragmented UDP packets
// because subsequent fragments have no UDP header - only IP header with
// fragment offset > 0. The BPF "udp" primitive checks Protocol=17 in IP header
// but the port check requires a UDP header, causing "port X" to reject fragments.
//
// The expression (ip[6:2] & 0x1fff > 0) matches packets where:
// - ip[6:2] reads the 16-bit flags/fragment offset field at IP header offset 6
// - & 0x1fff masks out the flags bits, keeping only the 13-bit fragment offset
// - > 0 matches any packet with non-zero fragment offset (i.e., not the first fragment)
//
// Combined with "udp", this also captures first fragments (which have MF=1, offset=0).
const IPFragmentClause = "(ip[6:2] & 0x1fff > 0)"

// PortRange represents a port range with start and end values
type PortRange struct {
	Start int
	End   int
}

// VoIPFilterConfig holds configuration for VoIP-optimized BPF filter building
type VoIPFilterConfig struct {
	SIPPorts      []int       // Specific SIP ports (empty = any port)
	RTPPortRanges []PortRange // Custom RTP port ranges (empty = use default)
	UDPOnly       bool        // If true, capture UDP only (no TCP)
	BaseFilter    string      // User-provided base filter to combine with
}

// VoIPFilterBuilder builds optimized BPF filters for VoIP capture
type VoIPFilterBuilder struct{}

// NewVoIPFilterBuilder creates a new filter builder
func NewVoIPFilterBuilder() *VoIPFilterBuilder {
	return &VoIPFilterBuilder{}
}

// DefaultRTPPortRange returns the default RTP port range
func DefaultRTPPortRange() PortRange {
	return PortRange{Start: DefaultRTPPortRangeStart, End: DefaultRTPPortRangeEnd}
}

// Build constructs a BPF filter string from the configuration.
//
// Algorithm:
// 1. If no SIP ports and no RTP ranges specified, return base filter with optional udp prefix
// 2. Build SIP port filter (captures both TCP and UDP unless --udp-only)
// 3. Build RTP port range filter (always UDP)
// 4. Combine SIP and RTP with OR
// 5. Apply UDP-only constraint if requested
// 6. Add IP fragment clause to capture fragmented SIP packets
// 7. Combine with base filter if present
//
// IMPORTANT: All filters include the IP fragment clause (ip[6:2] & 0x1fff > 0) to
// capture subsequent fragments of fragmented UDP packets. Without this, BPF filters
// like "port 5060" or "udp" will drop the second fragment of large SIP packets because
// subsequent fragments have no UDP header - only IP header with fragment offset > 0.
func (b *VoIPFilterBuilder) Build(config VoIPFilterConfig) string {
	// No VoIP-specific filtering requested
	if len(config.SIPPorts) == 0 && len(config.RTPPortRanges) == 0 {
		if config.UDPOnly {
			if config.BaseFilter != "" {
				// Add fragment clause to capture fragmented UDP packets
				return fmt.Sprintf("((%s) and udp) or %s", config.BaseFilter, IPFragmentClause)
			}
			// udp alone won't capture subsequent fragments - add fragment clause
			return fmt.Sprintf("udp or %s", IPFragmentClause)
		}
		if config.BaseFilter != "" {
			// Add fragment clause to base filter
			return fmt.Sprintf("(%s) or %s", config.BaseFilter, IPFragmentClause)
		}
		return ""
	}

	var parts []string

	// 1. Build SIP port filter
	if len(config.SIPPorts) > 0 {
		sipParts := make([]string, len(config.SIPPorts))
		for i, port := range config.SIPPorts {
			sipParts[i] = fmt.Sprintf("port %d", port)
		}
		if len(sipParts) == 1 {
			parts = append(parts, fmt.Sprintf("(%s)", sipParts[0]))
		} else {
			parts = append(parts, fmt.Sprintf("(%s)", strings.Join(sipParts, " or ")))
		}
	}

	// 2. Build RTP port range filter (always UDP)
	// Use custom ranges if provided, otherwise default to 10000-32768
	rtpRanges := config.RTPPortRanges
	if len(rtpRanges) == 0 {
		rtpRanges = []PortRange{DefaultRTPPortRange()}
	}

	for _, r := range rtpRanges {
		// When UDP-only is set, we don't need to specify "udp" for portrange
		// because the whole filter will be wrapped with "udp and (...)"
		if config.UDPOnly {
			parts = append(parts, fmt.Sprintf("(portrange %d-%d)", r.Start, r.End))
		} else {
			parts = append(parts, fmt.Sprintf("(udp portrange %d-%d)", r.Start, r.End))
		}
	}

	// 3. Combine SIP and RTP with OR
	voipFilter := strings.Join(parts, " or ")

	// 4. Apply UDP-only constraint if requested
	if config.UDPOnly {
		voipFilter = fmt.Sprintf("udp and (%s)", voipFilter)
	}

	// 5. Add IP fragment clause to capture fragmented SIP packets
	// This is critical for large SIP INVITEs that exceed MTU - the second fragment
	// has no UDP header and would be dropped by port-based filters
	voipFilter = fmt.Sprintf("(%s) or %s", voipFilter, IPFragmentClause)

	// 6. Combine with base filter if present
	if config.BaseFilter != "" {
		return fmt.Sprintf("(%s) and (%s)", config.BaseFilter, voipFilter)
	}

	return voipFilter
}

// ParsePortRanges parses a comma-separated list of port ranges (e.g., "8000-9000,40000-50000")
func ParsePortRanges(s string) ([]PortRange, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	ranges := make([]PortRange, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Parse range "start-end"
		rangeParts := strings.Split(part, "-")
		if len(rangeParts) != 2 {
			return nil, fmt.Errorf("invalid port range format: %q (expected start-end)", part)
		}

		start, err := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
		if err != nil {
			return nil, fmt.Errorf("invalid start port in range %q: %w", part, err)
		}

		end, err := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
		if err != nil {
			return nil, fmt.Errorf("invalid end port in range %q: %w", part, err)
		}

		if err := validatePortRange(start, end); err != nil {
			return nil, fmt.Errorf("invalid port range %q: %w", part, err)
		}

		ranges = append(ranges, PortRange{Start: start, End: end})
	}

	return ranges, nil
}

// ParsePorts parses a comma-separated list of ports (e.g., "5060,5061,5080")
func ParsePorts(s string) ([]int, error) {
	if s == "" {
		return nil, nil
	}

	parts := strings.Split(s, ",")
	ports := make([]int, 0, len(parts))

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		port, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}

		if err := validatePort(port); err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}

		ports = append(ports, port)
	}

	return ports, nil
}

// validatePort checks if a port number is valid (1-65535)
func validatePort(port int) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", port)
	}
	return nil
}

// validatePortRange checks if a port range is valid
func validatePortRange(start, end int) error {
	if err := validatePort(start); err != nil {
		return fmt.Errorf("start %w", err)
	}
	if err := validatePort(end); err != nil {
		return fmt.Errorf("end %w", err)
	}
	if start > end {
		return fmt.Errorf("start port (%d) must be less than or equal to end port (%d)", start, end)
	}
	return nil
}
