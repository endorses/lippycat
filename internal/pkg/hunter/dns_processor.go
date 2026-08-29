//go:build hunter || all

package hunter

import "github.com/endorses/lippycat/internal/pkg/dns"

// DNSProcessor is the shared domain DNS analyzer used at the hunter edge.
type DNSProcessor = dns.Analyzer

// NewDNSProcessor creates the hunter's shared DNS analyzer.
func NewDNSProcessor(detectTunneling bool) *DNSProcessor {
	return dns.NewAnalyzer(detectTunneling)
}
