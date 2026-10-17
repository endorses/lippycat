//go:build processor || tap || all

package processor

import (
	"context"
	"crypto/tls"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	"github.com/endorses/lippycat/internal/pkg/processor/filtering"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

func sharedPolicyTestProcessor(t *testing.T, pki relayTestPKI, id, authorityCert, signingKey string, replicas []failover.Endpoint) (*Processor, tls.Certificate) {
	t.Helper()
	pair, cert, key := pki.identity(t, id)
	p, err := newTestProcessor(t, Config{ProcessorID: id, ListenAddr: "127.0.0.1:0", TLSEnabled: true, TLSClientAuth: true, TLSCAFile: pki.caFile, TLSCertFile: cert, TLSKeyFile: key, FilterPolicy: filterpolicy.Config{Mode: "shared", Domain: "capture", AuthorityID: "authority", TrustedCertFile: authorityCert, SigningKeyFile: signingKey, StateFile: filepath.Join(t.TempDir(), "policy-private", "snapshot.pb"), Startup: "local", Replicas: replicas, SyncInterval: 10 * time.Millisecond}})
	require.NoError(t, err)
	require.NoError(t, p.filterManager.Initialize())
	require.NoError(t, p.startSharedPolicy(t.Context()))
	return p, pair
}
func sharedPolicyTestClient(t *testing.T, pki relayTestPKI, address string, pair tls.Certificate) management.FilterPolicyServiceClient {
	t.Helper()
	connection, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: pki.pool})))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, connection.Close()) })
	return management.NewFilterPolicyServiceClient(connection)
}

func TestSharedPolicyPublicationRequiresPinnedAuthorityAndReconcilesColdReplicas(t *testing.T) {
	pki := newRelayTestPKI(t)
	authorityPair, authorityCert, authorityKey := pki.identity(t, "authority")
	ordinaryPair, _, _ := pki.identity(t, "ordinary-client")
	replicaA, pairA := sharedPolicyTestProcessor(t, pki, "replica-a", authorityCert, "", nil)
	replicaB, pairB := sharedPolicyTestProcessor(t, pki, "replica-b", authorityCert, "", nil)
	local := &management.Filter{Id: "operator-local", Type: management.FilterType_FILTER_BPF, Pattern: "icmp", Enabled: true}
	_, err := replicaA.updateManagedFilter(local)
	require.NoError(t, err)
	addressA := serveRelayTestProcessor(t, replicaA, pairA, pki.pool)
	addressB := serveRelayTestProcessor(t, replicaB, pairB, pki.pool)
	central, centralPair := sharedPolicyTestProcessor(t, pki, "central", authorityCert, authorityKey, []failover.Endpoint{{Address: addressA}, {Address: addressB}})
	address := serveRelayTestProcessor(t, central, centralPair, pki.pool)
	publisher := sharedPolicyTestClient(t, pki, address, authorityPair)
	ordinary := sharedPolicyTestClient(t, pki, address, ordinaryPair)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	publication := &management.PolicyPublication{Domain: "capture", AuthorityId: "authority", Filters: []*management.Filter{{Id: "shared/capture/bpf", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}}}
	_, err = ordinary.PublishSnapshot(ctx, publication)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "transport trust alone must not grant permission to mint authority snapshots")
	first, err := publisher.PublishSnapshot(ctx, publication)
	require.NoError(t, err)
	require.Equal(t, uint64(1), first.Snapshot.Revision)
	require.Eventually(t, func() bool { return replicaA.sharedPolicy.state.Ready() && replicaB.sharedPolicy.state.Ready() }, 3*time.Second, time.Millisecond, "cold backups receive policy without hunter registration")
	require.Len(t, replicaA.filterManager.GetAll(), 2, "relay-local operator filter remains independent")
	require.Len(t, replicaB.filterManager.GetAll(), 1)
	_, _, err = replicaA.filterManager.UpdateCommitted(&management.Filter{Id: "shared/capture/forged", Type: management.FilterType_FILTER_BPF, Pattern: "tcp", Enabled: true})
	require.Error(t, err, "local operator writes cannot enter the reserved owner namespace")
	// A lagging backup is reconciled by complete desired state, including deletion.
	empty, err := publisher.PublishSnapshot(ctx, &management.PolicyPublication{Domain: "capture", AuthorityId: "authority", ExpectedRevision: 1})
	require.NoError(t, err)
	require.Equal(t, uint64(2), empty.Snapshot.Revision)
	require.Eventually(t, func() bool {
		a := replicaA.sharedPolicy.state.Latest()
		b := replicaB.sharedPolicy.state.Latest()
		return a != nil && b != nil && a.Snapshot.Revision == 2 && b.Snapshot.Revision == 2 && len(replicaA.filterManager.GetAll()) == 1 && len(replicaB.filterManager.GetAll()) == 0
	}, 3*time.Second, time.Millisecond)
	require.Equal(t, "operator-local", replicaA.filterManager.GetAll()[0].Id)
	replicaClient := sharedPolicyTestClient(t, pki, addressA, ordinaryPair)
	_, err = replicaClient.ApplySnapshot(ctx, first)
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "replicas reject stale signed restoration")
	_, err = replicaClient.PublishSnapshot(ctx, &management.PolicyPublication{Domain: "capture", AuthorityId: "authority", ExpectedRevision: 2})
	require.Equal(t, codes.FailedPrecondition, status.Code(err), "replicas have no signing authority")
}

type rejectingSharedTarget struct{ *filtering.LocalTarget }

func (t rejectingSharedTarget) ReplaceSharedSnapshot(string, []*management.Filter) error {
	return errors.New("local shared snapshot installation failed")
}

func TestSharedPolicyCommittedInstallationFaultBlocksAndReconcilesOnRestart(t *testing.T) {
	pki := newRelayTestPKI(t)
	_, authorityCert, authorityKey := pki.identity(t, "authority")
	p, _ := sharedPolicyTestProcessor(t, pki, "capture", authorityCert, authorityKey, nil)
	snapshot, err := p.sharedPolicy.state.Verifier().Sign(p.sharedPolicy.signer, 1, []*management.Filter{{Id: "shared/capture/bpf", Type: management.FilterType_FILTER_BPF, Pattern: "udp", Enabled: true}})
	require.NoError(t, err)
	p.SetFilterTarget(rejectingSharedTarget{filtering.NewLocalTarget(filtering.LocalTargetConfig{})})
	require.Error(t, p.sharedPolicy.install(snapshot))
	require.True(t, p.filterProcessingBlocked())
	require.False(t, p.sharedPolicy.state.Ready())
	require.Equal(t, uint64(1), p.sharedPolicy.state.Latest().Snapshot.Revision)
	cfg := p.config
	require.NoError(t, p.Shutdown())
	recovered, err := newTestProcessor(t, cfg)
	require.NoError(t, err)
	require.NoError(t, recovered.filterManager.Initialize())
	require.NoError(t, recovered.startSharedPolicy(t.Context()))
	require.True(t, recovered.sharedPolicy.state.Ready())
	require.False(t, recovered.filterProcessingBlocked())
	require.Equal(t, "shared/capture/bpf", recovered.filterManager.GetAll()[0].Id)
}
