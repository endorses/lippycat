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
// 6. Combine with base filter if present
func (b *VoIPFilterBuilder) Build(config VoIPFilterConfig) string {
	// No VoIP-specific filtering requested
	if len(config.SIPPorts) == 0 && len(config.RTPPortRanges) == 0 {
		if config.UDPOnly {
			if config.BaseFilter != "" {
				return fmt.Sprintf("(%s) and udp", config.BaseFilter)
			}
			return "udp"
		}
		return config.BaseFilter
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

	// 5. Combine with base filter if present
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
