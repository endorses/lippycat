package filtering

import (
	"errors"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestSharedLocalSnapshotUsesOneCoordinatedReplacementAndPreservesOperatorFilters(t *testing.T) {
	target := NewLocalTarget(LocalTargetConfig{BaseBPF: "udp"})
	coordinator := &recordingLocalFilterCoordinator{}
	target.SetCoordinator(coordinator)
	_, err := target.ApplyFilter(&management.Filter{Id: "operator-local", Type: management.FilterType_FILTER_BPF, Pattern: "port 53", Enabled: true})
	require.NoError(t, err)
	require.NoError(t, target.ReplaceSharedSnapshot("shared/capture/", []*management.Filter{
		{Id: "shared/capture/a", Type: management.FilterType_FILTER_BPF, Pattern: "port 5060", Enabled: true},
		{Id: "shared/capture/b", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.1", Enabled: true},
	}))
	changes := coordinator.Changes()
	require.Len(t, changes, 2, "a full shared snapshot crosses exactly one capture/session boundary")
	require.Len(t, changes[1].Next.Filters, 3)
	require.NoError(t, target.ReplaceSharedSnapshot("shared/capture/", nil))
	require.Len(t, target.GetActiveFilters(), 1)
	require.Equal(t, "operator-local", target.GetActiveFilters()[0].Id)
	coordinator.err = errors.New("producer drain failed")
	err = target.ReplaceSharedSnapshot("shared/capture/", []*management.Filter{{Id: "shared/capture/a", Type: management.FilterType_FILTER_BPF, Pattern: "tcp", Enabled: true}})
	require.Error(t, err)
	require.Len(t, target.GetActiveFilters(), 1, "failed coordinated replacement cannot publish partial matchers")
	coordinator.err = nil
	require.NoError(t, target.ReplaceSharedSnapshot("shared/capture/", nil))
}
