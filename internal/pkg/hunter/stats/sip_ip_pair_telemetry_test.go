//go:build hunter || all

package stats

import (
	"os"
	"os/exec"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/endorses/lippycat/internal/pkg/detector/signatures/voip"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type sipTelemetrySignature struct {
	*voip.SIPSignature
}

func (*sipTelemetrySignature) SIPIPPairTelemetry() voip.SIPIPPairTelemetry {
	return voip.SIPIPPairTelemetry{Entries: 7, MaxEntries: 100, TTLEvictions: 2, CapEvictions: 3}
}

// Select the test provider ahead of the built-in SIP signature.
func (*sipTelemetrySignature) Priority() int { return 1000 }

func TestToProtoDetectorLifecycle(t *testing.T) {
	// Isolate the real singleton lifecycle from other tests in this package.
	if os.Getenv("LIPPYCAT_DETECTOR_TELEMETRY_TEST") != t.Name() {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LIPPYCAT_DETECTOR_TELEMETRY_TEST="+t.Name())
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	require.Nil(t, detector.GetDefaultIfInitialized())

	c := New()
	for range 3 {
		got := c.ToProto(0).Detector
		require.NotNil(t, got)
		require.True(t, proto.Equal(&management.DetectorTelemetry{}, got), "absent detector must report zero telemetry: %v", got)
		require.Nil(t, detector.GetDefaultIfInitialized(), "status reporting must not enable detection")
	}

	d := detector.InitDefault()
	t.Cleanup(d.Shutdown)
	d.RegisterSignature(&sipTelemetrySignature{SIPSignature: voip.NewSIPSignature()})
	got := c.ToProto(0).Detector
	require.NotNil(t, got)
	require.Equal(t, uint64(7), got.SipIpPairEntries)
	require.Equal(t, uint64(100), got.SipIpPairMaxEntries)
	require.Equal(t, uint64(2), got.SipIpPairTtlEvictions)
	require.Equal(t, uint64(3), got.SipIpPairCapEvictions)
	require.Same(t, d, detector.GetDefaultIfInitialized())
}
