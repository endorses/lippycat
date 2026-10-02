package voip

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestBuildAdmissionFilterPreservesExplicitIntent(t *testing.T) {
	filter, err := BuildAdmissionFilter(VoIPFilterConfig{BaseFilter: "host 192.0.2.1", SIPPorts: []int{5060, 5080, 5060}, UDPOnly: true})
	require.NoError(t, err)
	require.Equal(t, "host 192.0.2.1", filter.Expression)
	require.Equal(t, []uint16{5060, 5080}, filter.SIPPorts)
	require.Empty(t, filter.RTPPortRanges)
	require.True(t, filter.UDPOnly)
	filter, err = BuildAdmissionFilter(VoIPFilterConfig{RTPPortRanges: []PortRange{{Start: 40000, End: 50000}}})
	require.NoError(t, err)
	require.Empty(t, filter.Expression)
	require.Equal(t, []AdmissionPortRange{{Start: 40000, End: 50000}}, filter.RTPPortRanges)
	filter, err = BuildAdmissionFilter(VoIPFilterConfig{})
	require.NoError(t, err)
	require.Empty(t, filter.SIPPorts)
	require.Empty(t, filter.RTPPortRanges)
	require.Empty(t, filter.Expression)
	for _, config := range []VoIPFilterConfig{{SIPPorts: []int{0}}, {SIPPorts: []int{65536}}, {RTPPortRanges: []PortRange{{Start: 10, End: 9}}}} {
		_, err := BuildAdmissionFilter(config)
		require.Error(t, err)
	}
}
