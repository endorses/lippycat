package statusclient

import (
	"encoding/json"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSIPIPPairTelemetrySurvivesWireAndHunterJSON(t *testing.T) {
	hunter := &management.ConnectedHunter{
		HunterId: "edge",
		Stats: &management.HunterStats{Detector: &management.DetectorTelemetry{
			SipIpPairEntries:      7,
			SipIpPairMaxEntries:   100,
			SipIpPairTtlEvictions: 2,
			SipIpPairCapEvictions: 3,
		}},
	}
	wire, err := proto.Marshal(hunter)
	require.NoError(t, err)
	var received management.ConnectedHunter
	require.NoError(t, proto.Unmarshal(wire, &received))

	for _, pretty := range []bool{false, true} {
		body, err := HunterToJSON(&received, pretty)
		require.NoError(t, err)
		var got struct {
			Stats struct {
				Detector map[string]uint64 `json:"detector"`
			} `json:"stats"`
		}
		require.NoError(t, json.Unmarshal(body, &got))
		require.Equal(t, map[string]uint64{
			"sip_ip_pair_entries":       7,
			"sip_ip_pair_max_entries":   100,
			"sip_ip_pair_ttl_evictions": 2,
			"sip_ip_pair_cap_evictions": 3,
		}, got.Stats.Detector)
	}
}
