package admission

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestForkWinnerGraceKeepsOnlyExclusiveLosingOwnershipPending(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			t.Run(fmt.Sprintf("%s/%s", mode, policy), func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mode, policy)
				bridge.mu.Lock()
				bridge.cfg.RetirementGrace = time.Hour
				bridge.mu.Unlock()
				invite, winner, prack := reliableSequence("fork-grace")
				losing := winner
				losing.ToTag = "losing-peer"
				losing.SDP = derivationSDP("192.0.2.9", 25000, false)
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, losing)
				_ = submitDerivation(t, bridge, registry, winner)
				_ = submitDerivation(t, bridge, registry, prack)
				final := winner
				final.ResponseCode, final.SDP, final.Headers = 200, nil, map[string]string{"cseq": "1 INVITE"}
				require.NoError(t, submitDerivation(t, bridge, registry, final))
				if mode == mediaadmission.ModeEnforce {
					assertDerivationState(t, bridge, controller, policy, false)
				} else {
					require.Zero(t, bridge.Stats().UnknownDerivations)
				}
				retirementOwns(t, registry, invite.CallID, "192.0.2.9:25000", "192.0.2.9:25001", "192.0.2.1:10000", "192.0.2.2:20000")
				bridge.mu.Lock()
				state := bridge.selected[invite.CallID]
				loserKey := derivationSide{"from", "losing-peer", "from", false}
				require.True(t, state.derivations[loserKey].forkRetired)
				require.False(t, state.derivations[loserKey].hasSDP)
				require.Equal(t, mode == mediaadmission.ModeEnforce, len(state.retirements) > 0)
				bridge.mu.Unlock()
				bridge.publicationMu.Lock()
				require.NoError(t, bridge.expireRetirements(time.Now().Add(2*time.Hour)))
				bridge.publicationMu.Unlock()
				snapshot, _ := registry.EndpointSnapshot(invite.CallID)
				if mode == mediaadmission.ModeEnforce {
					require.NotContains(t, snapshot.Endpoints, "192.0.2.9:25000")
				} else {
					require.Contains(t, snapshot.Endpoints, "192.0.2.9:25000")
				}
				retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
				replay := prack
				replay.ToTag = "losing-peer"
				_ = submitDerivation(t, bridge, registry, replay)
				if mode == mediaadmission.ModeEnforce {
					assertDerivationState(t, bridge, controller, policy, false)
				} else {
					require.Zero(t, bridge.Stats().UnknownDerivations)
				}
			})
		}
	}
}
