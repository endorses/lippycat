//go:build hunter || all

package stats

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/stretchr/testify/require"
)

type sipTelemetrySignature struct {
	*voip.SIPSignature
}

func (*sipTelemetrySignature) SIPIPPairTelemetry() voip.SIPIPPairTelemetry {
	return voip.SIPIPPairTelemetry{Entries: 7, MaxEntries: 100, TTLEvictions: 2, CapEvictions: 3}
}

func TestToProtoIncludesSIPIPPairTelemetry(t *testing.T) {
	d := detector.New()
	d.RegisterSignature(&sipTelemetrySignature{SIPSignature: voip.NewSIPSignature()})
	previous := detector.DefaultDetector
	detector.DefaultDetector = d
	t.Cleanup(func() {
		detector.DefaultDetector = previous
		d.Shutdown()
	})

	got := New().ToProto(0).Detector
	require.NotNil(t, got)
	require.Equal(t, uint64(7), got.SipIpPairEntries)
	require.Equal(t, uint64(100), got.SipIpPairMaxEntries)
	require.Equal(t, uint64(2), got.SipIpPairTtlEvictions)
	require.Equal(t, uint64(3), got.SipIpPairCapEvictions)
}
