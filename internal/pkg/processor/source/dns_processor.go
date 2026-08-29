//go:build tap || all

package source

import (
	"github.com/endorses/lippycat/internal/pkg/dns"
	"github.com/spf13/viper"
)

// NewDNSProcessor creates the shared domain DNS analyzer used by local sources.
func NewDNSProcessor(detectTunneling bool) DNSProcessor {
	return dns.NewAnalyzer(detectTunneling)
}

// NewDNSProcessorFromViper snapshots the tap DNS tunneling setting.
func NewDNSProcessorFromViper() DNSProcessor {
	detectTunneling := viper.GetBool("dns.detect_tunneling")
	if !viper.IsSet("dns.detect_tunneling") {
		detectTunneling = true
	}
	return NewDNSProcessor(detectTunneling)
}
