//go:build hunter || all

package email

import (
	"fmt"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/logger"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
)

// PacketForwarder is the interface for forwarding packets (used by hunter).
type PacketForwarder interface {
	Forward(pktInfo capture.PacketInfo) error
}

// Processor processes email packets for hunter mode.
type Processor struct {
	parser    *Parser
	tracker   *SessionTracker
	forwarder PacketForwarder

	// Filtering
	addressPatterns []string // Address patterns to match (glob-style)
}

// ProcessorConfig holds configuration for the email processor.
type ProcessorConfig struct {
	// AddressPatterns are glob-style patterns to match email addresses
	AddressPatterns []string

	// TrackSessions enables session tracking
	TrackSessions bool
}

// DefaultProcessorConfig returns the default processor configuration.
func DefaultProcessorConfig() ProcessorConfig {
	return ProcessorConfig{
		TrackSessions: true,
	}
}

// NewProcessor creates a new email packet processor.
func NewProcessor(forwarder PacketForwarder, config ProcessorConfig) *Processor {
	p := &Processor{
		parser:          NewParser(),
		forwarder:       forwarder,
		addressPatterns: config.AddressPatterns,
	}

	if config.TrackSessions {
		p.tracker = NewSessionTracker(DefaultTrackerConfig())
	}

	return p
}

// ProcessPacket processes an email packet.
// Returns true if the packet was forwarded, false otherwise.
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

	// Check if this is on an email port
	srcPort := uint16(tcp.SrcPort)
	dstPort := uint16(tcp.DstPort)

	if !IsSMTPPort(srcPort) && !IsSMTPPort(dstPort) {
		return false
	}

	// Get payload
	appLayer := packet.ApplicationLayer()
	if appLayer == nil {
		// Still forward TCP control packets (SYN, FIN, etc.)
		if p.forwarder != nil {
			if err := p.forwarder.Forward(pktInfo); err != nil {
				logger.Debug("Failed to forward email packet", "error", err)
				return false
			}
		}
		return true
	}

	payload := string(appLayer.Payload())
	if len(payload) == 0 {
		return false
	}

	// Determine direction
	isFromServer := IsSMTPPort(srcPort)

	// Parse the first line of payload
	metadata := &types.EmailMetadata{}
	if !p.parser.ParseLine(payload, metadata, isFromServer) {
		// Not a recognized SMTP line, but still forward
		if p.forwarder != nil {
			if err := p.forwarder.Forward(pktInfo); err != nil {
				logger.Debug("Failed to forward email packet", "error", err)
				return false
			}
		}
		return true
	}

	// Apply address filters if configured
	if len(p.addressPatterns) > 0 {
		if !p.matchesAddressPattern(metadata) {
			logger.Debug("Email packet does not match address patterns",
				"from", metadata.MailFrom,
				"to", metadata.RcptTo)
			return false
		}
	}

	// Track session
	if p.tracker != nil {
		sessionID := createSessionIDFromPorts(srcPort, dstPort, packet.NetworkLayer().NetworkFlow())
		p.tracker.UpdateSession(sessionID, metadata)
	}

	// Forward the packet
	if p.forwarder != nil {
		if err := p.forwarder.Forward(pktInfo); err != nil {
			logger.Debug("Failed to forward email packet", "error", err)
			return false
		}
	}

	logger.Debug("Processed email packet",
		"command", metadata.Command,
		"response_code", metadata.ResponseCode,
		"from", metadata.MailFrom)

	return true
}

// matchesAddressPattern checks if the metadata matches any configured pattern.
func (p *Processor) matchesAddressPattern(metadata *types.EmailMetadata) bool {
	for _, pattern := range p.addressPatterns {
		// Check MAIL FROM
		if metadata.MailFrom != "" && matchGlob(pattern, metadata.MailFrom) {
			return true
		}
		// Check RCPT TO addresses
		for _, rcpt := range metadata.RcptTo {
			if matchGlob(pattern, rcpt) {
				return true
			}
		}
	}
	return false
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

// createSessionIDFromPorts creates a session ID from ports and flow.
func createSessionIDFromPorts(srcPort, dstPort uint16, flow interface{ String() string }) string {
	// Normalize port order for consistent session IDs regardless of direction
	if srcPort > dstPort {
		srcPort, dstPort = dstPort, srcPort
	}
	return fmt.Sprintf("%s:%d-%d", flow.String(), srcPort, dstPort)
}

// Stats returns processor statistics.
func (p *Processor) Stats() ProcessorStats {
	stats := ProcessorStats{}
	if p.tracker != nil {
		trackerStats := p.tracker.Stats()
		stats.ActiveSessions = trackerStats.ActiveSessions
		stats.TotalMessages = trackerStats.TotalMessages
	}
	return stats
}

// ProcessorStats holds processor statistics.
type ProcessorStats struct {
	ActiveSessions int
	TotalMessages  int
}

// Stop stops the processor and releases resources.
func (p *Processor) Stop() {
	if p.tracker != nil {
		p.tracker.Stop()
	}
}
