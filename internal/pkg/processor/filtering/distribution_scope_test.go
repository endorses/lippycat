package filtering

import (
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLocalOnlyScopeExcludesSnapshotsAndWithdrawsOldCopies(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	a, initial := m.SubscribeSnapshot("a")
	require.Empty(t, initial)
	b, _ := m.SubscribeSnapshot("b")
	defer m.RemoveChannel("a", a)
	defer m.RemoveChannel("b", b)
	f := &management.Filter{Id: "target", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}
	count, err := m.Update(f)
	require.NoError(t, err)
	require.EqualValues(t, 2, count)
	require.Equal(t, management.FilterUpdateType_UPDATE_ADD, (<-a).UpdateType)
	require.Equal(t, management.FilterUpdateType_UPDATE_ADD, (<-b).UpdateType)
	local := proto.Clone(f).(*management.Filter)
	local.DistributionScope = management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY
	count, err = m.Update(local)
	require.NoError(t, err)
	require.Zero(t, count)
	for _, ch := range []chan *management.FilterUpdate{a, b} {
		withdrawal := <-ch
		require.Equal(t, management.FilterUpdateType_UPDATE_DELETE, withdrawal.UpdateType)
		require.True(t, proto.Equal(f, withdrawal.Filter), "legacy hunters receive the original recognizable filter, never local-only selection")
		require.Empty(t, ch)
	}
	require.Empty(t, m.GetForHunter("a"))
	require.True(t, proto.Equal(local, m.GetAll()[0]), "local matching retains complete policy")
	c, snapshot := m.SubscribeSnapshot("c")
	require.Empty(t, snapshot)
	defer m.RemoveChannel("c", c)
	local.Pattern = "tcp"
	_, err = m.Update(local)
	require.NoError(t, err)
	require.Empty(t, a)
	require.Empty(t, b)
	require.Empty(t, c)
	// Moving back to distributed keeps TargetHunters' existing meaning.
	local.DistributionScope = management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_DISTRIBUTED
	local.TargetHunters = []string{"b"}
	count, err = m.Update(local)
	require.NoError(t, err)
	require.EqualValues(t, 1, count)
	require.Equal(t, "tcp", (<-b).Filter.Pattern)
	require.Empty(t, a)
	require.Empty(t, c)
}

func TestLocalOnlyScopePersistsAndWorksWithLocalTarget(t *testing.T) {
	path := filepath.Join(privateStoreTestDir(t), "filters.yaml")
	m := NewManager(path, NewYAMLPersistence(), nil, nil, nil)
	f := &management.Filter{Id: "target", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY}
	_, err := m.Update(f)
	require.NoError(t, err)
	require.NoError(t, m.Close())
	recovered := NewManager(path, NewYAMLPersistence(), nil, nil, nil)
	defer func() { require.NoError(t, recovered.Close()) }()
	require.NoError(t, recovered.Load())
	require.True(t, proto.Equal(f, recovered.GetAll()[0]))
	require.Empty(t, recovered.GetForHunter("edge"))
	app := &mockAppFilterUpdater{}
	target := NewLocalTarget(LocalTargetConfig{})
	target.SetApplicationFilter(app)
	_, err = target.ApplyFilter(recovered.GetAll()[0])
	require.NoError(t, err)
	require.Len(t, app.GetFilters(), 1)
	require.Equal(t, "alice", app.GetFilters()[0].Pattern)
}

func TestSharedPolicyPreservesIndependentLocalOnlyFilters(t *testing.T) {
	m := NewManager("", nil, nil, nil, nil)
	require.NoError(t, m.SetSharedNamespace("shared/capture/"))
	_, err := m.Update(&management.Filter{Id: "operator-local", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, DistributionScope: management.FilterDistributionScope_FILTER_DISTRIBUTION_SCOPE_LOCAL_ONLY})
	require.NoError(t, err)
	require.NoError(t, m.ReplaceSharedSnapshot("shared/capture/", []*management.Filter{{Id: "shared/capture/bpf", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}}))
	require.Len(t, m.GetAll(), 2)
	require.Len(t, m.GetForHunter("edge"), 1)
	require.NoError(t, m.ReplaceSharedSnapshot("shared/capture/", nil))
	require.Len(t, m.GetAll(), 1)
	require.Empty(t, m.GetForHunter("edge"))
}
