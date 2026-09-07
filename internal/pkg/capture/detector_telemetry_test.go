package capture

import (
	"github.com/endorses/lippycat/internal/pkg/detector"
	"github.com/stretchr/testify/require"
	"testing"
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
