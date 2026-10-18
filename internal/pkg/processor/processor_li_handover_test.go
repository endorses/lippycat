//go:build (processor || tap || all) && li && linux

package processor

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/failover"
	"github.com/endorses/lippycat/internal/pkg/filterpolicy"
	policyfixture "github.com/endorses/lippycat/internal/pkg/filterpolicy/testutil"
	"github.com/endorses/lippycat/internal/pkg/li"
	"github.com/endorses/lippycat/internal/pkg/securestore"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestLIHandoverSignedPolicyAdmissionUsesActualCentralOwner(t *testing.T) {
	f := newPersistentProcessorFixture(t)
	p := f.open(t)
	require.NoError(t, p.startLIManager())
	config, signer := policyfixture.Config(t)
	config.Owner = "li"
	config.StorageProtection = "encrypted"
	config.StorageKeys = securestore.KeyConfig{Active: storageKeyRef(t, "handover-policy", 23)}
	require.NoError(t, filterpolicy.Initialize(config))
	state, err := filterpolicy.Open(config)
	require.NoError(t, err)
	p.sharedPolicy = &processorPolicy{processor: p, config: config, state: state, signer: signer, ready: make(chan struct{})}
	p.config.LIHandover = li.HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{"edge-a"}}
	filters, err := p.liCapturePolicyFilters()
	require.NoError(t, err)
	require.Len(t, filters, 1)
	issued := time.Now().Add(-time.Second)
	snapshot := &management.PolicySnapshot{ProtocolVersion: 1, Domain: config.Domain, AuthorityId: config.AuthorityID, Revision: 1, OwnerKind: "li", Filters: filters}
	require.NoError(t, p.buildLICapturePolicy(snapshot, issued))
	require.False(t, snapshot.AllowOfflineCapture)
	require.Equal(t, filters[0].Id, snapshot.Filters[0].Id, "the owner must not rewrite LI filter IDs")
	signed, err := state.Verifier().SignSnapshot(signer, snapshot)
	require.NoError(t, err)
	require.NoError(t, p.sharedPolicy.install(signed))
	// Startup has a verified cache but has not reconciled/published the local
	// task owner yet. Even a configured replica must not receive cached target
	// selectors from the preceding distribution setting during that interval.
	require.False(t, p.sharedPolicy.localAuthorityReady.Load())
	attempt, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	require.NoError(t, p.sharedPolicy.replicateOnce(attempt, failover.Endpoint{Address: "127.0.0.1:0"}))
	require.NoError(t, p.publishLIHandoverPolicy(time.Now()))
	require.True(t, p.sharedPolicy.localAuthorityReady.Load())
	require.Error(t, p.sharedPolicy.replicateOnce(attempt, failover.Endpoint{Address: "127.0.0.1:0"}), "fresh publication enables the replica transport path")
	encoded, err := proto.Marshal(signed)
	require.NoError(t, err)
	batch := &data.PacketBatch{HunterId: "edge-a", SignedCapturePolicy: encoded, Packets: []*data.CapturedPacket{{TimestampNs: time.Now().UnixNano(), MatchedFilterIds: []string{filters[0].Id}}}}
	require.NoError(t, p.validateLICapturePolicy(batch))
	wrong := proto.Clone(batch).(*data.PacketBatch)
	wrong.HunterId = "revoked-edge"
	require.ErrorIs(t, p.validateLICapturePolicy(wrong), li.ErrCaptureAuthority)
	unsigned := proto.Clone(batch).(*data.PacketBatch)
	unsigned.SignedCapturePolicy = nil
	require.ErrorIs(t, p.validateLICapturePolicy(unsigned), li.ErrCaptureAuthority)
	tampered := proto.Clone(signed).(*management.SignedPolicySnapshot)
	tampered.Snapshot.AllowOfflineCapture = true
	wrong.SignedCapturePolicy, err = proto.Marshal(tampered)
	require.NoError(t, err)
	wrong.HunterId = batch.HunterId
	require.ErrorIs(t, p.validateLICapturePolicy(wrong), li.ErrCaptureAuthority)
	// A valid signature cannot restore a task that was subsequently deactivated.
	require.NoError(t, p.liManager.DeactivateTask(f.xid))
	require.ErrorIs(t, p.validateLICapturePolicy(batch), li.ErrCaptureAuthority)
}

func TestLIHandoverConfigurationCannotMintWithoutEnabledLIManager(t *testing.T) {
	p := &Processor{config: Config{LIHandover: li.HandoverConfig{Enabled: true, LeaseDuration: time.Minute, SourceIDs: []string{"edge-a"}}}}
	require.Error(t, p.buildLICapturePolicy(&management.PolicySnapshot{OwnerKind: "li"}, time.Now()))
	require.Error(t, p.startLIHandoverPolicy(t.Context()))
	require.Error(t, p.rejectLIOwnedFilterMutation("li-task-target"))
	require.NoError(t, p.rejectLIOwnedFilterMutation("operator-filter"))
}
