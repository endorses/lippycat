//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/endorses/lippycat/internal/pkg/processor/source"
	"github.com/stretchr/testify/require"
)

type sipTelemetrySignature struct {
	*voip.SIPSignature
}

func (*sipTelemetrySignature) SIPIPPairTelemetry() voip.SIPIPPairTelemetry {
	return voip.SIPIPPairTelemetry{Entries: 7, MaxEntries: 100, TTLEvictions: 2, CapEvictions: 3}
}

func TestVirtualHunterIncludesSIPIPPairTelemetry(t *testing.T) {
	d := detector.New()
	d.RegisterSignature(&sipTelemetrySignature{SIPSignature: voip.NewSIPSignature()})
	previous := detector.DefaultDetector
	detector.DefaultDetector = d
	t.Cleanup(func() {
		detector.DefaultDetector = previous
		d.Shutdown()
	})

	p := &Processor{
		packetSource:         source.NewLocalSource(source.DefaultLocalSourceConfig()),
		config:               Config{ProcessorID: "tap"},
		sessionOutputManager: newSessionOutputManager(nil, nil),
	}
	got := p.SynthesizeVirtualHunter()
	require.NotNil(t, got)
	require.NotNil(t, got.Stats)
	require.NotNil(t, got.Stats.Detector)
	require.Equal(t, uint64(7), got.Stats.Detector.SipIpPairEntries)
	require.Equal(t, uint64(100), got.Stats.Detector.SipIpPairMaxEntries)
	require.Equal(t, uint64(2), got.Stats.Detector.SipIpPairTtlEvictions)
	require.Equal(t, uint64(3), got.Stats.Detector.SipIpPairCapEvictions)
}
