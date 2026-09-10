package filtering

import (
	"fmt"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestRADIUSCapabilityRequiresVersionAndType(t *testing.T) {
	ft := management.FilterType_FILTER_RADIUS_USERNAME
	for _, caps := range []*management.HunterCapabilities{nil, {}, {FilterTypes: []string{"radius_username"}}, {RadiusFilterVersion: 1}, {FilterTypes: []string{"radius_username"}, RadiusFilterVersion: 2}} {
		require.False(t, hunterSupportsFilterType(caps, ft))
	}
	require.True(t, hunterSupportsFilterType(&management.HunterCapabilities{FilterTypes: []string{"radius_username"}, RadiusFilterVersion: 1}, ft))
	require.True(t, hunterSupportsFilterType(nil, management.FilterType_FILTER_BPF))
	require.True(t, hunterSupportsFilterType(nil, management.FilterType_FILTER_IP_ADDRESS))
	m := NewManager("", nil, nil, nil, nil)
	_, err := m.Update(&management.Filter{Id: "radius", Revision: 1, Type: ft, Pattern: "alice", TargetHunters: []string{"legacy"}})
	require.Error(t, err)
	require.Zero(t, m.Count())
	require.Contains(t, err.Error(), "capability")
	local := NewLocalTarget(LocalTargetConfig{})
	_, err = local.ApplyFilter(&management.Filter{Id: "radius", Revision: 1, Type: ft, Pattern: "alice"})
	require.Error(t, err)
	require.Zero(t, local.FilterCount())
}

type radiusCapabilities map[string]*management.HunterCapabilities

func (c radiusCapabilities) GetCapabilities(id string) *management.HunterCapabilities { return c[id] }

func TestRADIUSDistributionAndPersistence(t *testing.T) {
	caps := radiusCapabilities{"modern": {FilterTypes: []string{"radius_username", "bpf"}, RadiusFilterVersion: 1}, "legacy": {FilterTypes: []string{"radius_username", "bpf"}}}
	path := t.TempDir() + "/filters.yaml"
	m := NewManager(path, NewYAMLPersistence(), caps, nil, nil)
	modern := m.AddChannel("modern")
	legacy := m.AddChannel("legacy")
	defer m.RemoveChannel("modern", modern)
	defer m.RemoveChannel("legacy", legacy)
	f := &management.Filter{Id: "radius", Revision: 1, Enabled: true, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice", Radius: &management.RadiusFilterCriteria{Scope: &management.RadiusScopeBinding{OperatorScope: "operator", ProfileRevision: "v1"}}}
	count, err := m.Update(f)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Equal(t, "radius", (<-modern).Filter.Id)
	select {
	case <-legacy:
		t.Fatal("legacy hunter received unsupported filter")
	default:
	}
	require.Len(t, m.GetForHunter("modern"), 1)
	f.Pattern = "bob"
	_, err = m.Update(f)
	require.Error(t, err)
	f.Revision++
	_, err = m.Update(f)
	require.NoError(t, err)
	require.Equal(t, "bob", (<-modern).Filter.Pattern)
	snapshot := m.GetForHunter("modern")
	snapshot[0].Radius.Scope.OperatorScope = "mutated"
	require.Equal(t, "operator", m.GetForHunter("modern")[0].Radius.Scope.OperatorScope)
	f.Radius.Scope.OperatorScope = "caller-mutated"
	require.Equal(t, "operator", m.GetForHunter("modern")[0].Radius.Scope.OperatorScope)
	require.Empty(t, m.GetForHunter("legacy"))
	restored := NewManager(path, NewYAMLPersistence(), caps, nil, nil)
	require.NoError(t, restored.Load())
	require.Equal(t, "operator", restored.GetForHunter("modern")[0].Radius.Scope.OperatorScope)
	require.EqualValues(t, 2, restored.GetForHunter("modern")[0].Revision)
	_, err = m.Update(&management.Filter{Id: "raw", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true})
	require.NoError(t, err)
	require.Equal(t, "raw", (<-legacy).Filter.Id)
	require.Len(t, m.GetForHunter("legacy"), 1)
}

func TestRADIUSDeletedRevisionCannotBeReused(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	f := &management.Filter{Id: "radius", Revision: 1, Enabled: true, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice"}
	_, err := m.Update(f)
	require.NoError(t, err)
	_, err = m.Delete(f.Id)
	require.NoError(t, err)
	_, err = m.Update(f)
	require.Error(t, err)
	f.Revision++
	_, err = m.Update(f)
	require.NoError(t, err)
}

func TestRADIUSRevisionHistoryBoundAndTypeSwitch(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	f := &management.Filter{Id: "radius", Revision: 1, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice"}
	_, err := m.Update(f)
	require.NoError(t, err)
	f.Type = management.FilterType_FILTER_BPF
	f.Revision = 2
	f.Pattern = "udp"
	_, err = m.Update(f)
	require.NoError(t, err)
	f.Type = management.FilterType_FILTER_RADIUS_USERNAME
	f.Revision = 1
	f.Pattern = "alice"
	_, err = m.Update(f)
	require.Error(t, err)
	for i := 0; i < 65536; i++ {
		m.radiusRevisions[fmt.Sprintf("id-%d", i)] = 1
	}
	f.Id = "new-id"
	_, err = m.Update(f)
	require.Error(t, err)
}

func TestRADIUSLoadCannotResetRevisionHistory(t *testing.T) {
	path := t.TempDir() + "/filters.yaml"
	m := NewManager(path, NewYAMLPersistence(), nil, nil, nil)
	f := &management.Filter{Id: "radius", Revision: 1, Type: management.FilterType_FILTER_RADIUS_USERNAME, Pattern: "alice"}
	_, err := m.Update(f)
	require.NoError(t, err)
	_, err = m.Delete(f.Id)
	require.NoError(t, err)
	require.ErrorContains(t, m.Load(), "startup-only")
	_, err = m.Update(f)
	require.Error(t, err)
	require.EqualValues(t, 1, m.radiusRevisions[f.Id])
	require.Empty(t, m.GetAll())
	fresh := NewManager(path, NewYAMLPersistence(), nil, nil, nil)
	require.NoError(t, fresh.Load())
	require.ErrorContains(t, fresh.Load(), "startup-only")
}
