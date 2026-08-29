package dns

import (
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
)

// Analyzer parses DNS packets and optionally applies stateful tunneling
// detection. It returns domain metadata; topology adapters own transport
// conversion.
type Analyzer struct {
	parser    *Parser
	tunneling *TunnelingDetector
}

// NewAnalyzer creates a shared DNS analyzer.
func NewAnalyzer(detectTunneling bool) *Analyzer {
	analyzer := &Analyzer{parser: NewParser()}
	if detectTunneling {
		analyzer.tunneling = NewTunnelingDetector(DefaultTunnelingConfig())
	}
	return analyzer
}

// ProcessPacket parses and analyzes one packet. It returns nil when the packet
// does not contain a valid DNS message.
func (a *Analyzer) ProcessPacket(packet gopacket.Packet) *types.DNSMetadata {
	if packet == nil {
		return nil
	}
	metadata := a.parser.Parse(packet)
	if metadata != nil && a.tunneling != nil {
		a.tunneling.Analyze(metadata)
	}
	return metadata
}

// GetSuspiciousDomains returns domains whose tunneling score meets threshold.
func (a *Analyzer) GetSuspiciousDomains(threshold float64, limit int) []TunnelingReport {
	if a.tunneling == nil {
		return nil
	}
	return a.tunneling.GetSuspiciousDomains(threshold, limit)
}

// Stop releases stateful analyzer resources.
func (a *Analyzer) Stop() {
	if a.tunneling != nil {
		a.tunneling.Stop()
	}
}
