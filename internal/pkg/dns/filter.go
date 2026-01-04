package dns

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/endorses/lippycat/internal/pkg/filtering"
)

// FilterBuilder builds BPF filters for DNS capture.
type FilterBuilder struct{}

// NewFilterBuilder creates a new DNS filter builder.
func NewFilterBuilder() *FilterBuilder {
	return &FilterBuilder{}
}

// FilterConfig holds DNS filter configuration.
type FilterConfig struct {
	// Ports is a list of DNS ports to capture (default: 53)
	Ports []uint16

	// UDPOnly captures only UDP DNS (ignores TCP DNS)
	UDPOnly bool

	// TCPOnly captures only TCP DNS (ignores UDP DNS)
	TCPOnly bool

	// BaseFilter is an additional filter to combine with DNS filter
	BaseFilter string
}

// DefaultFilterConfig returns the default filter configuration.
func DefaultFilterConfig() FilterConfig {
	return FilterConfig{
		Ports:   []uint16{53},
		UDPOnly: false,
		TCPOnly: false,
	}
}

// Build creates a BPF filter string for DNS capture.
func (fb *FilterBuilder) Build(config FilterConfig) string {
	if len(config.Ports) == 0 {
		config.Ports = []uint16{53}
	}

	var parts []string

	// Build port filter
	portFilter := fb.buildPortFilter(config.Ports)

	// Apply transport filter
	if config.UDPOnly {
		parts = append(parts, fmt.Sprintf("udp and (%s)", portFilter))
	} else if config.TCPOnly {
		parts = append(parts, fmt.Sprintf("tcp and (%s)", portFilter))
	} else {
		// Both UDP and TCP
		parts = append(parts, fmt.Sprintf("(udp or tcp) and (%s)", portFilter))
	}

	filter := strings.Join(parts, " or ")

	// Combine with base filter if provided
	if config.BaseFilter != "" {
		filter = fmt.Sprintf("(%s) and (%s)", filter, config.BaseFilter)
	}

	return filter
}

// buildPortFilter builds port matching expression.
func (fb *FilterBuilder) buildPortFilter(ports []uint16) string {
	if len(ports) == 1 {
		return fmt.Sprintf("port %d", ports[0])
	}

	var portStrs []string
	for _, p := range ports {
		portStrs = append(portStrs, fmt.Sprintf("port %d", p))
	}
	return strings.Join(portStrs, " or ")
}

// BuildDomainFilter creates a filter expression for matching specific domains.
// Note: BPF cannot directly filter by domain content, so this returns an
// empty string. Domain filtering must be done in application layer.
func (fb *FilterBuilder) BuildDomainFilter(domains []string) string {
	// BPF cannot filter by DNS query content
	// Domain filtering must be done at application level
	return ""
}

// ParsePorts parses a comma-separated list of ports.
func ParsePorts(portsStr string) ([]uint16, error) {
	if portsStr == "" {
		return []uint16{53}, nil
	}

	var ports []uint16
	for _, p := range strings.Split(portsStr, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		port, err := strconv.ParseUint(p, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", p, err)
		}
		if port == 0 || port > 65535 {
			return nil, fmt.Errorf("port %d out of range", port)
		}
		ports = append(ports, uint16(port))
	}

	if len(ports) == 0 {
		return []uint16{53}, nil
	}
	return ports, nil
}

// DNSPort is the standard DNS port.
const DNSPort = 53

// CommonDNSPorts includes standard and common alternate DNS ports.
var CommonDNSPorts = []uint16{
	53,   // Standard DNS
	5353, // mDNS
	5355, // LLMNR
}

// DoHPorts includes DNS-over-HTTPS ports.
var DoHPorts = []uint16{
	443, // Standard HTTPS
}

// DoTPorts includes DNS-over-TLS ports.
var DoTPorts = []uint16{
	853, // DNS-over-TLS
}

// LoadDomainsFromFile loads domain patterns from a file.
// Each line is a domain pattern. Empty lines and lines starting with # are ignored.
func LoadDomainsFromFile(filename string) ([]string, error) {
	return filtering.LoadPatternsFromFile(filename)
}
