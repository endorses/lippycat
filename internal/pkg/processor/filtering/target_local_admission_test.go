package filtering

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestAdmissionIPSelectorsUpdateApplicationWithoutCaptureRestart(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "udp and not port 53", ApplicationIPSelectors: true})
	kernel := &mockBPFUpdater{}
	app := &mockAppFilterUpdater{}
	target.SetBPFUpdater(kernel)
	target.SetApplicationFilter(app)
	_, err := target.ApplyFilter(&management.Filter{Id: "sip", Type: management.FilterType_FILTER_SIP_USER, Pattern: "selected", Enabled: true})
	require.NoError(t, err)
	baseline := kernel.FilterCount()
	for _, pattern := range []string{"192.0.2.2", "192.0.2.0/24"} {
		_, err = target.ApplyFilter(&management.Filter{Id: "ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true})
		require.NoError(t, err)
		require.Equal(t, baseline, kernel.FilterCount())
		require.Equal(t, "udp and not port 53", kernel.LastFilter())
		require.Len(t, app.GetFilters(), 2)
		require.Equal(t, pattern, app.GetFilters()[0].Pattern)
	}
	_, err = target.RemoveFilter("ip")
	require.NoError(t, err)
	require.Equal(t, baseline, kernel.FilterCount())
	require.Len(t, app.GetFilters(), 1)
	_, err = target.ApplyFilter(&management.Filter{Id: "explicit", Type: management.FilterType_FILTER_BPF, Pattern: "not port 54", Enabled: true})
	require.NoError(t, err)
	require.Greater(t, kernel.FilterCount(), baseline, "explicit capture policy still follows its capture boundary")
	require.Contains(t, kernel.LastFilter(), "not port 54")
}
