//go:build hunter || all

package http

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// Processor processes HTTP packets for hunter mode.
// It implements forwarding.PacketProcessor to filter packets before forwarding.
type Processor struct {
	parser *Parser

	// Filtering
	hostPatterns  []string // Host patterns to match (glob-style)
	pathPatterns  []string // Path patterns to match (glob-style)
	methods       []string // HTTP methods to match
	contentFilter *ContentFilter
}

// ProcessorConfig holds configuration for the HTTP processor.
type ProcessorConfig struct {
	// HostPatterns are glob-style patterns to match hosts
	HostPatterns []string

	// PathPatterns are glob-style patterns to match paths
	PathPatterns []string

	// Methods are HTTP methods to match
	Methods []string

	// ContentFilter for advanced filtering
	ContentFilter *ContentFilter
}

// DefaultProcessorConfig returns the default processor configuration.
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{}
}

// NewProcessor creates a new HTTP packet processor.
func NewProcessor(config ProcessorConfig) *Processor {
	return &Processor{
		parser:        NewParser(),
		hostPatterns:  config.HostPatterns,
		pathPatterns:  config.PathPatterns,
		methods:       config.Methods,
		contentFilter: config.ContentFilter,
	}
}

// ProcessPacket processes an HTTP packet.
// Returns true if the packet should be forwarded, false otherwise.
// Implements forwarding.PacketProcessor interface.
func (p *Processor) ProcessPacket(pktInfo capture.PacketInfo) bool {
	packet := pktInfo.Packet

	// Check for network and transport layers
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return false
	}

	// Only process TCP
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return false
	}

	tcp, ok := tcpLayer.(*layers.TCP)
	if !ok {
		return false
	}

	// Check if this is on an HTTP port
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	if !IsHTTPPort(srcPort) && !IsHTTPPort(dstPort) {
		return false
	}

	// Get payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		// Forward TCP control packets (SYN, FIN, etc.) for HTTP ports
		return true
	}

	payload := appLayer.Payload()
	if len(payload) == 0 {
		// Forward empty payload packets for HTTP ports
		return true
	}

	// Parse the HTTP message
	metadata := p.parser.ParsePayload(payload)
	if metadata == nil {
		// Not a recognized HTTP message, but on HTTP port - forward it
		return true
	}

	// Apply filters
	if !p.matchesFilters(metadata) {
		logger.Debug("HTTP packet does not match filters",
			"host", metadata.Host,
			"method", metadata.Method,
			"path", metadata.Path)
		return false
	}

	logger.Debug("HTTP packet matches filters",
		"type", metadata.Type,
		"method", metadata.Method,
		"path", metadata.Path,
		"host", metadata.Host,
		"status", metadata.StatusCode)

	return true
}

// matchesFilters checks if the metadata matches the configured filters.
func (p *Processor) matchesFilters(metadata *types.HTTPMetadata) bool {
	// If content filter is configured, use it
	if p.contentFilter != nil {
		return p.contentFilter.Match(metadata)
	}

	// If no filters configured, match everything
	if len(p.hostPatterns) == 0 && len(p.pathPatterns) == 0 && len(p.methods) == 0 {
		return true
	}

	// Check host patterns
	if len(p.hostPatterns) > 0 {
		matched := false
		for _, pattern := range p.hostPatterns {
			if matchGlob(pattern, metadata.Host) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check path patterns
	if len(p.pathPatterns) > 0 {
		matched := false
		for _, pattern := range p.pathPatterns {
			if matchGlob(pattern, metadata.Path) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check methods
	if len(p.methods) > 0 {
		matched := false
		for _, method := range p.methods {
			if method == metadata.Method {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	return true
}

// matchGlob performs simple glob matching with * wildcard.
func matchGlob(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}

	// Handle * at the start (suffix match)
	if pattern[0] == '*' {
		suffix := pattern[1:]
		if suffix == "" {
			return true
		}
		return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
	}

	// Handle * at the end (prefix match)
	if pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(s) >= len(prefix) && s[:len(prefix)] == prefix
	}

	// Handle * in the middle
	for i, c := range pattern {
		if c == '*' {
			prefix := pattern[:i]
			suffix := pattern[i+1:]
			return len(s) >= len(prefix)+len(suffix) &&
				s[:len(prefix)] == prefix &&
				s[len(s)-len(suffix):] == suffix
		}
	}

	// Exact match
	return pattern == s
}

// IsHTTPPort checks if the port is a known HTTP port.
func IsHTTPPort(port uint16) bool {
	for _, p := range DefaultHTTPPorts {
		if p == port {
			return true
		}
	}
	return false
}

// Stats returns processor statistics.
func (p *Processor) Stats() ProcessorStats {
	return ProcessorStats{}
}

// ProcessorStats holds processor statistics.
type ProcessorStats struct {
	PacketsProcessed int
	PacketsForwarded int
	PacketsFiltered  int
}

// Stop stops the processor and releases resources.
func (p *Processor) Stop() {
	// No resources to release
}
