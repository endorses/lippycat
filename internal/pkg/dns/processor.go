//go:build hunter || all

package dns

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/filtering"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// Import layers for link type constant

// PacketForwarder is the interface for forwarding packets (used by hunter).
type PacketForwarder interface {
	Forward(pktInfo capture.PacketInfo) error
}

// Processor processes DNS packets for hunter mode.
type Processor struct {
	parser    *Parser
	tracker   *QueryTracker
	tunneling *TunnelingDetector
	forwarder PacketForwarder

	// Filtering
	domainPatterns []string // Domain patterns to match (glob-style)
}

// ProcessorConfig holds configuration for the DNS processor.
type ProcessorConfig struct {
	// DomainPatterns are glob-style patterns to match (e.g., "*.example.com")
	DomainPatterns []string

	// TrackQueries enables query/response correlation
	TrackQueries bool

	// DetectTunneling enables DNS tunneling detection
	DetectTunneling bool

	// TunnelingConfig is the tunneling detection configuration
	TunnelingConfig TunnelingConfig
}

// DefaultProcessorConfig returns the default processor configuration.
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{
		TrackQueries:    true,
		DetectTunneling: true,
		TunnelingConfig: DefaultTunnelingConfig(),
	}
}

// NewProcessor creates a new DNS packet processor.
func NewProcessor(forwarder PacketForwarder, config ProcessorConfig) *Processor {
	p := &Processor{
		parser:         NewParser(),
		forwarder:      forwarder,
		domainPatterns: config.DomainPatterns,
	}

	if config.TrackQueries {
		p.tracker = NewQueryTracker(DefaultTrackerConfig())
	}

	if config.DetectTunneling {
		p.tunneling = NewTunnelingDetector(config.TunnelingConfig)
	}

	return p
}

// ProcessPacket processes a DNS packet.
// Returns true if the packet was forwarded, false otherwise.
func (p *Processor) ProcessPacket(pktInfo capture.PacketInfo) bool {
	packet := pktInfo.Packet

	// Check for network and transport layers
	if packet.NetworkLayer() == nil || packet.TransportLayer() == nil {
		return false
	}

	// Only process UDP/TCP
	var srcPort, dstPort uint16
	switch layer := packet.TransportLayer().(type) {
	case *layers.UDP:
		srcPort = uint16(layer.SrcPort)
		dstPort = uint16(layer.DstPort)
	case *layers.TCP:
		srcPort = uint16(layer.SrcPort)
		dstPort = uint16(layer.DstPort)
	default:
		return false
	}

	// Check if this looks like DNS (port 53)
	if srcPort != DNSPort && dstPort != DNSPort {
		// Not standard DNS port, skip
		return false
	}

	// Parse DNS
	metadata := p.parser.Parse(packet)
	if metadata == nil {
		logger.Debug("Failed to parse DNS packet")
		return false
	}

	// Apply domain filters if configured
	if len(p.domainPatterns) > 0 && !p.matchesDomainPattern(metadata.QueryName) {
		logger.Debug("DNS query does not match domain patterns",
			"query", metadata.QueryName)
		return false
	}

	// Track query/response correlation
	if p.tracker != nil {
		if metadata.IsResponse {
			// Create packet display for correlation
			pktDisplay := p.createPacketDisplay(pktInfo, metadata)
			p.tracker.CorrelateResponse(pktDisplay, metadata)
		} else {
			pktDisplay := p.createPacketDisplay(pktInfo, metadata)
			p.tracker.TrackQuery(pktDisplay, metadata)
		}
	}

	// Analyze for tunneling
	if p.tunneling != nil {
		p.tunneling.Analyze(metadata)
	}

	// Forward the packet
	if p.forwarder != nil {
		if err := p.forwarder.Forward(pktInfo); err != nil {
			logger.Debug("Failed to forward DNS packet", "error", err)
			return false
		}
	}

	logger.Debug("Processed DNS packet",
		"query", metadata.QueryName,
		"type", metadata.QueryType,
		"response", metadata.IsResponse)

	return true
}

// matchesDomainPattern checks if a domain matches any configured pattern.
// Uses filtering.MatchAnyGlob for case-insensitive glob pattern matching.
func (p *Processor) matchesDomainPattern(domain string) bool {
	return filtering.MatchAnyGlob(p.domainPatterns, domain)
}

// createPacketDisplay creates a PacketDisplay from packet info and metadata.
func (p *Processor) createPacketDisplay(pktInfo capture.PacketInfo, metadata *types.DNSMetadata) *types.PacketDisplay {
	packet := pktInfo.Packet

	var srcIP, dstIP, srcPort, dstPort string

	if netLayer := packet.NetworkLayer(); netLayer != nil {
		flow := netLayer.NetworkFlow()
		srcIP = flow.Src().String()
		dstIP = flow.Dst().String()
	}

	if transLayer := packet.TransportLayer(); transLayer != nil {
		flow := transLayer.TransportFlow()
		srcPort = flow.Src().String()
		dstPort = flow.Dst().String()
	}

	return &types.PacketDisplay{
		Timestamp: packet.Metadata().Timestamp,
		SrcIP:     srcIP,
		DstIP:     dstIP,
		SrcPort:   srcPort,
		DstPort:   dstPort,
		Protocol:  "DNS",
		Length:    len(packet.Data()),
		Info:      formatDNSInfo(metadata),
		RawData:   packet.Data(),
		NodeID:    "Local",
		Interface: pktInfo.Interface,
		DNSData:   metadata,
		LinkType:  layers.LinkTypeEthernet, // Default to Ethernet
	}
}

// formatDNSInfo creates a human-readable DNS info string.
func formatDNSInfo(metadata *types.DNSMetadata) string {
	if metadata.IsResponse {
		if len(metadata.Answers) > 0 {
			return metadata.QueryType + " " + metadata.QueryName + " -> " + metadata.Answers[0].Data
		}
		return metadata.QueryType + " " + metadata.QueryName + " " + metadata.ResponseCode
	}
	return metadata.QueryType + " " + metadata.QueryName + "?"
}

// Stats returns processor statistics.
func (p *Processor) Stats() ProcessorStats {
	stats := ProcessorStats{}
	if p.tracker != nil {
		trackerStats := p.tracker.Stats()
		stats.PendingQueries = trackerStats.PendingQueries
	}
	return stats
}

// ProcessorStats holds processor statistics.
type ProcessorStats struct {
	PendingQueries int
}

// Stop stops the processor and releases resources.
func (p *Processor) Stop() {
	if p.tunneling != nil {
		p.tunneling.Stop()
	}
}
