package filtering

import (
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRADIUSTypeChangeRemovesLegacyFilter(t *testing.T) {
	caps := radiusCapabilities{"modern": {FilterTypes: []string{"radius_username", "bpf"}, RadiusFilterVersion: 1}, "legacy": {FilterTypes: []string{"bpf"}}}
	m := NewManager("", nil, caps, nil, nil)
	legacy := m.AddChannel("legacy")
	defer m.RemoveChannel("legacy", legacy)
	_, err := m.Update(&management.Filter{Id: "shared", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
	require.NoError(t, err)
	require.Equal(t, management.FilterUpdateType_UPDATE_ADD, (<-legacy).UpdateType)
	_, err = m.Update(&management.Filter{Id: "shared", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Revision: 1, Enabled: true})
	require.NoError(t, err)
	select {
	case update := <-legacy:
		require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, update.UpdateType)
		require.Equal(t, management.FilterType_FILTER_BPF, update.Filter.Type)
	default:
		t.Fatal("legacy hunter retains old broad BPF filter after it was replaced by unsupported RADIUS filter")
	}
}

func TestRADIUSTypeChangeRemovesIncompatibleHunters(t *testing.T) {
	for _, targeted := range []bool{false, true} {
		name := "global"
		if targeted {
			name = "targeted"
		}
		t.Run(name, func(t *testing.T) {
			caps := radiusCapabilities{
				"username": {FilterTypes: []string{"radius_username"}, RadiusFilterVersion: 1},
				"both":     {FilterTypes: []string{"radius_username", "radius_attribute"}, RadiusFilterVersion: 1},
			}
			m := NewManager("", nil, caps, nil, nil)
			username := m.AddChannel("username")
			both := m.AddChannel("both")
			defer m.RemoveChannel("username", username)
			defer m.RemoveChannel("both", both)
			old := &management.Filter{Id: "shared", Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Revision: 1, Enabled: true}
			if targeted {
				old.TargetHunters = []string{"username", "both"}
			}
			_, err := m.Update(old)
			require.NoError(t, err)
			<-username
			<-both
			next := &management.Filter{Id: "shared", Type: management.FilterType_FILTER_RADIUS_ATTRIBUTE, Pattern: "0107616c696365", Revision: 2, Enabled: true}
			if targeted {
				next.TargetHunters = []string{"both"}
			}
			_, err = m.Update(next)
			require.NoError(t, err)
			select {
			case update := <-username:
				require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, update.UpdateType)
				require.Equal(t, management.FilterType_FILTER_RADIUS_USERNAME, update.Filter.Type)
			default:
				t.Fatal("hunter retains obsolete RADIUS filter after type or scope change")
			}
			require.Equal(t, management.FilterUpdateType_UPDATE_MODIFY, (<-both).UpdateType)
		})
	}
}
