//go:build hunter || all

package hunter

import (
	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket"
	"github.com/spf13/viper"
)

// DNSProcessor handles DNS packet parsing and tunneling detection at the hunter edge.
type DNSProcessor struct {
	parser    *dns.Parser
	tunneling *dns.TunnelingDetector
}

// NewDNSProcessor creates a new DNS processor for hunter-side analysis.
// If detectTunneling is true, tunneling detection is enabled.
func NewDNSProcessor(detectTunneling bool) *DNSProcessor {
	p := &DNSProcessor{
		parser: dns.NewParser(),
	}

	if detectTunneling {
		p.tunneling = dns.NewTunnelingDetector(dns.DefaultTunnelingConfig())
	}

	return p
}

// NewDNSProcessorFromViper creates a DNS processor using viper configuration.
// Reads dns.detect_tunneling from viper (default: true).
func NewDNSProcessorFromViper() *DNSProcessor {
	detectTunneling := viper.GetBool("dns.detect_tunneling")
	// Default to true if not set
	if !viper.IsSet("dns.detect_tunneling") {
		detectTunneling = true
	}
	return NewDNSProcessor(detectTunneling)
}

// ProcessPacket parses a DNS packet and returns proto-ready metadata.
// Returns nil if the packet is not a DNS packet or parsing fails.
func (p *DNSProcessor) ProcessPacket(packet gopacket.Packet) *data.DNSMetadata {
	if packet == nil {
		return nil
	}

	// Parse DNS packet
	metadata := p.parser.Parse(packet)
	if metadata == nil {
		return nil
	}

	// Run tunneling analysis if enabled
	if p.tunneling != nil {
		p.tunneling.Analyze(metadata)
	}

	// Convert to proto format
	return convertToProtoDNSMetadata(metadata)
}

// Stop stops the DNS processor and releases resources.
func (p *DNSProcessor) Stop() {
	if p.tunneling != nil {
		p.tunneling.Stop()
	}
}

// GetSuspiciousDomains returns domains with high tunneling scores.
// Returns nil if tunneling detection is not enabled.
func (p *DNSProcessor) GetSuspiciousDomains(threshold float64, limit int) []dns.TunnelingReport {
	if p.tunneling == nil {
		return nil
	}
	return p.tunneling.GetSuspiciousDomains(threshold, limit)
}

// convertToProtoDNSMetadata converts types.DNSMetadata to data.DNSMetadata (proto).
func convertToProtoDNSMetadata(m *types.DNSMetadata) *data.DNSMetadata {
	if m == nil {
		return nil
	}

	proto := &data.DNSMetadata{
		// Header fields
		TransactionId: uint32(m.TransactionID),
		IsResponse:    m.IsResponse,
		Opcode:        m.Opcode,
		ResponseCode:  m.ResponseCode,

		// Header flags
		Authoritative:      m.Authoritative,
		Truncated:          m.Truncated,
		RecursionDesired:   m.RecursionDesired,
		RecursionAvailable: m.RecursionAvailable,
		AuthenticatedData:  m.AuthenticatedData,
		CheckingDisabled:   m.CheckingDisabled,

		// Record counts
		QuestionCount:   uint32(m.QuestionCount),
		AnswerCount:     uint32(m.AnswerCount),
		AuthorityCount:  uint32(m.AuthorityCount),
		AdditionalCount: uint32(m.AdditionalCount),

		// Query information
		QueryName:  m.QueryName,
		QueryType:  m.QueryType,
		QueryClass: m.QueryClass,

		// Correlation and timing
		QueryResponseTimeMs: m.QueryResponseTimeMs,
		CorrelatedQuery:     m.CorrelatedQuery,

		// Security analysis
		TunnelingScore: m.TunnelingScore,
		EntropyScore:   m.EntropyScore,
	}

	// Convert answers
	if len(m.Answers) > 0 {
		proto.Answers = make([]*data.DNSAnswer, len(m.Answers))
		for i, a := range m.Answers {
			proto.Answers[i] = &data.DNSAnswer{
				Name:  a.Name,
				Type:  a.Type,
				Class: a.Class,
				Ttl:   a.TTL,
				Data:  a.Data,
			}
		}
	}

	return proto
}
