package dns

import (
	"testing"

	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

func TestAnalyzerReturnsDomainMetadata(t *testing.T) {
	analyzer := NewAnalyzer(false)
	t.Cleanup(analyzer.Stop)

	metadata := analyzer.ProcessPacket(createDNSQueryPacket("example.test"))
	require.NotNil(t, metadata)
	require.Equal(t, uint16(0x1234), metadata.TransactionID)
	require.Equal(t, "example.test", metadata.QueryName)
	require.Equal(t, "A", metadata.QueryType)
}

func TestAnalyzerRejectsMissingOrNonDNSPacket(t *testing.T) {
	analyzer := NewAnalyzer(false)
	t.Cleanup(analyzer.Stop)

	require.Nil(t, analyzer.ProcessPacket(nil))
	require.Nil(t, analyzer.ProcessPacket(gopacket.NewPacket([]byte{0}, gopacket.LayerTypePayload, gopacket.Default)))
}

func TestAnalyzerWithTunnelingDetectionStopsIdempotently(t *testing.T) {
	analyzer := NewAnalyzer(true)
	require.NotNil(t, analyzer.ProcessPacket(createDNSQueryPacket("subdomain.example.test")))
	analyzer.Stop()
	analyzer.Stop()
}
