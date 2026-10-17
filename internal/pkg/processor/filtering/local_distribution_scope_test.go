package filtering

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestLocalOnlyCentralFiltersDoNotAlterTapCapture(t *testing.T) {
	updater := &mockBPFUpdater{}
	app := &mockAppFilterUpdater{}
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "udp", CentralOnlyFilters: true, ProcessorMedia: true})
	target.SetBPFUpdater(updater)
	target.SetApplicationFilter(app)
	_, err := target.ApplyFilter(&management.Filter{Id: "local", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.0/24", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	require.Empty(t, app.GetFilters())
	require.Zero(t, updater.FilterCount(), "a central selector must not mutate a running capture filter")
	require.Len(t, target.GetActiveFilters(), 1)
	_, err = target.ApplyFilter(&management.Filter{Id: "distributed", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "198.51.100.0/24", Enabled: true})
	require.ErrorIs(t, err, ErrLocalFilterCapability, "processor-only media cannot acquire an independent broad IP selector")
	require.Len(t, target.GetActiveFilters(), 1)
}
