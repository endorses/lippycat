package admission

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestForkSecondSuccessRestoresExpiredOwnership(t *testing.T) {
	for _, winnerFirst := range []bool{false, true} {
		for _, withSDP := range []bool{false, true} {
			for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
				t.Run(fmt.Sprintf("winner-first=%t/sdp=%t/%s", winnerFirst, withSDP, policy), func(t *testing.T) {
					bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
					bridge.mu.Lock()
					bridge.cfg.RetirementGrace = time.Hour
					bridge.mu.Unlock()
					invite, winner, prack := reliableSequence("second-fork-success")
					loser := winner
					loser.ToTag = "losing-peer"
					loser.SDP = derivationSDP("192.0.2.9", 25000, false)
					_ = submitDerivation(t, bridge, registry, invite)
					if winnerFirst {
						_ = submitDerivation(t, bridge, registry, winner)
						_ = submitDerivation(t, bridge, registry, loser)
					} else {
						_ = submitDerivation(t, bridge, registry, loser)
						_ = submitDerivation(t, bridge, registry, winner)
					}
					_ = submitDerivation(t, bridge, registry, prack)
					final := winner
					final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
					require.NoError(t, submitDerivation(t, bridge, registry, final))
					original, _ := registry.Call(invite.CallID)
					registry.Upsert(callregistry.Call{CallID: "other-owner"})
					other, _ := registry.Call("other-owner")
					require.True(t, registry.TryAssociateEndpointForLifetime(other.CallID, other.Lifetime, "192.0.2.9:25000"))
					bridge.mu.Lock()
					state := bridge.selected[invite.CallID]
					archive := state.derivations[derivationSide{"from", "losing-peer", "from", false}]
					require.True(t, archive.forkRetired)
					require.NotEmpty(t, archive.retirementEndpoints, "charged watermark retains independently safe losing media")
					bytes, endpoints := derivationCost(derivationSide{"from", "losing-peer", "from", false}, archive)
					require.Greater(t, bytes, 528)
					require.Positive(t, endpoints)
					bridge.mu.Unlock()
					bridge.publicationMu.Lock()
					require.NoError(t, bridge.expireRetirements(time.Now().Add(2*time.Hour)))
					bridge.publicationMu.Unlock()
					before, _ := registry.EndpointSnapshot(invite.CallID)
					require.NotContains(t, before.Endpoints, "192.0.2.9:25000")
					second := loser
					second.ResponseCode, second.SDP, second.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
					if withSDP {
						second.SDP = derivationSDP("192.0.2.10", 26000, false)
					}
					_ = submitDerivation(t, bridge, registry, second)
					assertDerivationState(t, bridge, controller, policy, true)
					restored, _ := registry.EndpointSnapshot(invite.CallID)
					require.Equal(t, original.Lifetime, restored.Call.Lifetime)
					require.Contains(t, restored.Endpoints, "192.0.2.9:25000")
					if withSDP {
						require.Contains(t, restored.Endpoints, "192.0.2.10:26000")
					}
					result := registry.ResolveMediaEndpoints("192.0.2.1:10000", "192.0.2.9:25000")
					require.Equal(t, callregistry.MediaResolved, result.Status)
					require.Equal(t, original.CallID, result.CallID)
					require.Equal(t, original.Lifetime, result.Lifetime)
					otherSnapshot, _ := registry.EndpointSnapshot(other.CallID)
					require.Contains(t, otherSnapshot.Endpoints, "192.0.2.9:25000")
					bridge.mu.Lock()
					require.True(t, state.forkAmbiguous)
					require.Empty(t, state.retirements)
					bridge.mu.Unlock()
				})
			}
		}
	}
}

func TestForkOwnershipArchiveUsesAtomicBoundedReservation(t *testing.T) {
	bridge, _, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	cfg := bridge.cfg.Limits
	cfg.PendingEndpointCapacity = 2
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	bridge.mu.Lock()
	defer bridge.mu.Unlock()
	bridge.cfg.Metadata = metadata
	call := &selectedCall{}
	requestSide := derivationSide{"from", "losing", "from", false}
	responseSide := derivationSide{"losing", "from", "from", false}
	first, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.9:25000")
	require.NoError(t, err)
	second, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.9:25001")
	require.NoError(t, err)
	require.True(t, bridge.putDerivation(call, requestSide, &derivationState{cseq: 1, branch: "initial", method: "INVITE", complete: true, prackCSeq: 3}))
	require.True(t, bridge.putDerivation(call, responseSide, &derivationState{cseq: 1, branch: "initial", method: "INVITE", complete: true, hasSDP: true, endpoints: []mediaadmission.EndpointKey{first, second}}))
	key := mediaadmission.DialogKey{FromTag: "from", ToTag: "losing", CSeq: 1, CSeqValid: true, CSeqMethod: "INVITE", Branch: "initial"}
	require.Equal(t, 2, metadata.Stats().SelectedEndpoints)
	require.True(t, bridge.archiveForkLocked(call, key, "losing", []mediaadmission.EndpointKey{first, second}), "replacement fits without temporary double reservation")
	require.Equal(t, 1, metadata.Stats().SelectedContexts)
	require.Equal(t, 2, metadata.Stats().SelectedEndpoints)
	require.Equal(t, uint64(3), call.derivations[requestSide].prackCSeq, "archive retains sender acknowledgment watermark")
	extra, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.10:26000")
	require.NoError(t, err)
	require.False(t, bridge.archiveForkLocked(call, key, "losing", []mediaadmission.EndpointKey{first, second, extra}))
	require.True(t, call.contextLost)
	require.Equal(t, 2, metadata.Stats().SelectedEndpoints)
	require.Len(t, call.derivations[requestSide].retirementEndpoints, 2)
	bridge.releaseDerivations(call)
	require.Zero(t, metadata.Stats().SelectedEndpoints)
}
