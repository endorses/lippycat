//go:build hunter || all

package filtering

import (
	"context"
	"errors"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type snapshotConnection struct {
	snapshot *management.SignedPolicySnapshot
}

func (c snapshotConnection) Invoke(_ context.Context, method string, _ any, result any, _ ...grpc.CallOption) error {
	if method != management.FilterPolicyService_GetSnapshot_FullMethodName {
		return errors.New("unexpected RPC")
	}
	proto.Merge(result.(proto.Message), c.snapshot)
	return nil
}
func (c snapshotConnection) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("not used")
}

func TestSharedPolicyRejectsUnsignedAndReconcilesEmptyAcrossEventBoundary(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	verifier, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	first, err := verifier.Sign(key, 1, []*management.Filter{
		{Id: "shared/capture/a", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true, TargetHunters: []string{"edge"}},
		{Id: "shared/capture/b", Type: management.FilterType_FILTER_SIP_USER, Pattern: "alice", Enabled: true, TargetHunters: []string{"other-edge"}},
	})
	require.NoError(t, err)
	empty, err := verifier.Sign(key, 2, nil)
	require.NoError(t, err)
	cfg.SigningKeyFile = ""
	restarter := &recordingRestarter{}
	coordinator := &recordingPolicyCoordinator{}
	updater := &recordingApplicationUpdater{}
	m := New("edge", restarter, noopDisconnectMarker{})
	require.NoError(t, m.InitializeSharedPolicy(cfg, []string{"bpf"}))
	m.SetPolicyChangeCoordinator(coordinator)
	m.SetApplicationFilterUpdater(updater)
	require.False(t, m.SharedStartupReady())
	require.NoError(t, m.InitializePolicy(t.Context(), snapshotConnection{first}))
	require.True(t, m.SharedStartupReady())
	require.Len(t, m.GetFilters(), 1)
	require.NoError(t, m.SetInitialFilters([]*management.Filter{{Id: "unsigned", Type: management.FilterType_FILTER_BPF, Pattern: "tcp"}}))
	require.Equal(t, "shared/capture/a", m.GetFilters()[0].Id)
	require.NoError(t, m.InitializePolicy(t.Context(), snapshotConnection{empty}))
	require.Len(t, m.GetFilters(), 1, "changed event policy waits for transport drain boundary")
	require.NoError(t, m.ApplyPendingInitialE())
	require.Empty(t, m.GetFilters())
	require.Equal(t, 1, coordinator.calls)
	require.Empty(t, updater.filters[len(updater.filters)-1])
	require.ErrorIs(t, m.InitializePolicy(t.Context(), snapshotConnection{first}), filterpolicy.ErrRollback)
	require.NoError(t, m.CloseSharedPolicy())
	cfg.Startup = "cached"
	recovered := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.NoError(t, recovered.InitializeSharedPolicy(cfg, []string{"bpf"}))
	defer func() { require.NoError(t, recovered.CloseSharedPolicy()) }()
	cachedUpdater := &recordingApplicationUpdater{}
	recovered.SetApplicationFilterUpdater(cachedUpdater)
	require.True(t, recovered.SharedStartupReady())
	require.Empty(t, recovered.GetFilters())
	require.Equal(t, 1, cachedUpdater.calls)
}

type rejectingCoordinator struct{}

func (rejectingCoordinator) ApplyPolicyChange(func() error) error {
	return errors.New("old producer cannot drain")
}

func TestSharedPolicyFailedEventBoundaryDoesNotPublishReadiness(t *testing.T) {
	cfg, key := policyfixture.Config(t)
	verifier, err := filterpolicy.NewVerifier(cfg)
	require.NoError(t, err)
	first, err := verifier.Sign(key, 1, []*management.Filter{{Id: "shared/capture/ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: "192.0.2.1", Enabled: true}})
	require.NoError(t, err)
	empty, err := verifier.Sign(key, 2, nil)
	require.NoError(t, err)
	cfg.SigningKeyFile = ""
	m := New("edge", &recordingRestarter{}, noopDisconnectMarker{})
	require.NoError(t, m.InitializeSharedPolicy(cfg, []string{"ip_address"}))
	defer func() { require.NoError(t, m.CloseSharedPolicy()) }()
	m.SetApplicationFilterUpdater(&recordingApplicationUpdater{})
	require.NoError(t, m.InitializePolicy(t.Context(), snapshotConnection{first}))
	m.SetPolicyChangeCoordinator(rejectingCoordinator{})
	require.NoError(t, m.InitializePolicy(t.Context(), snapshotConnection{empty}))
	require.ErrorIs(t, m.ApplyPendingInitialE(), filterpolicy.ErrNotReady)
	require.False(t, m.sharedPolicy.state.Ready())
	require.Len(t, m.GetFilters(), 1, "failed boundary keeps previous effective matchers")
	require.Equal(t, uint64(2), m.sharedPolicy.state.Latest().Snapshot.Revision, "durable authority must still reject rollback")
	require.ErrorIs(t, m.InitializePolicy(t.Context(), snapshotConnection{first}), filterpolicy.ErrRollback)
}
