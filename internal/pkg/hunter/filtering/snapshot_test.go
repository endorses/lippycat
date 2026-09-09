//go:build hunter || all

package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSnapshotReconcilesRegistrationGapAndReconnect(t *testing.T) {
	restart := &recordingRestarter{}
	updater := &recordingApplicationUpdater{}
	m := New("hunter", restart, noopDisconnectMarker{})
	m.SetApplicationFilterUpdater(updater)
	old := &management.Filter{Id: "radius", Type: management.FilterType_FILTER_RADIUS_USERNAME, Revision: 1, Pattern: "alice"}
	gone := &management.Filter{Id: "deleted", Type: management.FilterType_FILTER_BPF, Pattern: "udp"}
	m.SetInitialFilters([]*management.Filter{old, gone})
	current := &management.Filter{Id: "radius", Type: old.Type, Revision: 2, Pattern: "bob"}
	m.handleUpdate(&management.FilterUpdate{Snapshot: true, Filters: []*management.Filter{current}})
	require.Equal(t, []*management.Filter{current}, m.GetFilters())
	require.Equal(t, 1, restart.calls)
	require.Equal(t, []*management.Filter{current}, updater.filters[len(updater.filters)-1])
	// A live update following the snapshot must win.
	live := &management.Filter{Id: "radius", Type: old.Type, Revision: 3, Pattern: "carol"}
	m.handleUpdate(&management.FilterUpdate{UpdateType: management.FilterUpdateType_UPDATE_MODIFY, Filter: live})
	require.Equal(t, uint64(3), m.GetFilters()[0].Revision)
	// Reconnect to a processor whose entire policy was removed while offline.
	m.handleUpdate(&management.FilterUpdate{Snapshot: true})
	require.Empty(t, m.GetFilters())
	require.Empty(t, updater.filters[len(updater.filters)-1])
	require.Equal(t, 3, restart.calls)
}

func TestLegacySnapshotAddReplacesExistingRevision(t *testing.T) {
	m := New("hunter", &recordingRestarter{}, noopDisconnectMarker{})
	m.SetInitialFilters([]*management.Filter{{Id: "radius", Type: management.FilterType_FILTER_RADIUS_USERNAME, Revision: 1}})
	current := &management.Filter{Id: "radius", Type: management.FilterType_FILTER_RADIUS_USERNAME, Revision: 2}
	m.handleUpdate(&management.FilterUpdate{UpdateType: management.FilterUpdateType_UPDATE_ADD, Filter: current})
	m.handleUpdate(&management.FilterUpdate{UpdateType: management.FilterUpdateType_UPDATE_ADD, Filter: current})
	require.Equal(t, []*management.Filter{current}, m.GetFilters())
}
