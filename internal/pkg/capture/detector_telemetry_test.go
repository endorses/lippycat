package capture

import (
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

func TestHeartbeatDoesNotInitializeDetector(t *testing.T) {
	previous := detector.DefaultDetector
	detector.DefaultDetector = nil
	t.Cleanup(func() { detector.DefaultDetector = previous })

	for range 3 {
		require.Empty(t, defaultSIPIPPairHeartbeatFields())
		require.Nil(t, detector.GetDefaultIfInitialized(), "heartbeat must not enable detection")
	}
}

func TestHeartbeatUsesExistingDetector(t *testing.T) {
	previous := detector.DefaultDetector
	d := detector.New()
	detector.DefaultDetector = d
	t.Cleanup(func() {
		detector.DefaultDetector = previous
		d.Shutdown()
	})
	require.Equal(t, sipIPPairHeartbeatFields(d.Telemetry()), defaultSIPIPPairHeartbeatFields())
	require.Same(t, d, detector.GetDefaultIfInitialized())
}
