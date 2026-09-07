package capture

import (
	"os"
	"os/exec"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/stretchr/testify/require"
)

func TestSIPIPPairHeartbeatFields(t *testing.T) {
	require.Equal(t, []any{
		"sip_ip_pair_entries", uint64(10),
		"sip_ip_pair_max_entries", uint64(12),
		"sip_ip_pair_ttl_evictions", uint64(3),
		"sip_ip_pair_cap_evictions", uint64(7),
	}, sipIPPairHeartbeatFields(detector.Telemetry{
		SIPIPPairEntries: 10, SIPIPPairMaxEntries: 12,
		SIPIPPairTTLEvictions: 3, SIPIPPairCapEvictions: 7,
	}))
}

func TestHeartbeatDetectorLifecycle(t *testing.T) {
	// Isolate the real singleton lifecycle from other tests in this package.
	if os.Getenv("LIPPYCAT_DETECTOR_TELEMETRY_TEST") != t.Name() {
		cmd := exec.Command(os.Args[0], "-test.run=^"+t.Name()+"$", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "LIPPYCAT_DETECTOR_TELEMETRY_TEST="+t.Name())
		output, err := cmd.CombinedOutput()
		require.NoError(t, err, "%s", output)
		return
	}
	require.Nil(t, detector.GetDefaultIfInitialized())

	for range 3 {
		require.Empty(t, defaultSIPIPPairHeartbeatFields())
		require.Nil(t, detector.GetDefaultIfInitialized(), "heartbeat must not enable detection")
	}

	d := detector.InitDefault()
	t.Cleanup(d.Shutdown)
	require.Equal(t, sipIPPairHeartbeatFields(d.Telemetry()), defaultSIPIPPairHeartbeatFields())
	require.Same(t, d, detector.GetDefaultIfInitialized())
}
