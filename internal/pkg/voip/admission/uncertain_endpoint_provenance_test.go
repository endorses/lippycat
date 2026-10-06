package admission

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func TestConflictingReofferRecoveryPreservesOnlyHealthyProvenance(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, shared := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/shared-%v", mode, policy, shared), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					bridge.cfg.RetirementGrace = time.Minute
					invite := retirementHealthyCall(t, bridge, registry, "invite-answer")
					faulty, answer := recoveryAtSequence(invite, "caller", "INVITE", 3)
					faulty.SDP = derivationSDP("192.0.2.1", 50000, false)
					answer.SDP = derivationSDP("192.0.2.2", 60000, false)
					faulty = recoveryDuplicateCSeq(t, faulty, "3 INVITE", "4 INVITE")
					_ = submitDerivation(t, bridge, registry, faulty)
					_ = submitDerivation(t, bridge, registry, answer)
					require.Equal(t, 1, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:50000", "192.0.2.2:60000")
					if shared {
						registry.Upsert(callregistry.Call{CallID: "independent-owner"})
						other, _ := registry.Call("independent-owner")
						require.True(t, registry.TryAssociateEndpointForLifetime(other.CallID, other.Lifetime, "192.0.2.1:50000"))
					}
					repair, repaired := recoveryAtSequence(invite, "caller", "INVITE", 5)
					_ = submitDerivation(t, bridge, registry, repair)
					require.NoError(t, submitDerivation(t, bridge, registry, repaired))
					require.Zero(t, bridge.Stats().UnknownDerivations)
					snapshotBefore, _ := registry.EndpointSnapshot(invite.CallID)
					require.Contains(t, snapshotBefore.Endpoints, "192.0.2.1:50000")
					retirementOwns(t, registry, invite.CallID, "192.0.2.2:60000")
					resolved := registry.ResolveMediaEndpoints("192.0.2.1:50000", "192.0.2.2:60000")
					require.Equal(t, invite.CallID, resolved.CallID)
					require.Equal(t, snapshotBefore.Call.Lifetime, resolved.Lifetime)
					bridge.mu.Lock()
					state := bridge.selected[invite.CallID]
					var due time.Time
					for _, deadline := range state.retirements {
						due = deadline
						break
					}
					bridge.mu.Unlock()
					if mode == mediaadmission.ModeEnforce {
						require.False(t, due.IsZero())
						bridge.publicationMu.Lock()
						require.NoError(t, bridge.expireRetirements(due.Add(-time.Nanosecond)))
						bridge.publicationMu.Unlock()
						require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:50000", "192.0.2.2:60000").CallID)
						bridge.publicationMu.Lock()
						require.NoError(t, bridge.expireRetirements(due))
						bridge.publicationMu.Unlock()
						snapshot, _ := registry.EndpointSnapshot(invite.CallID)
						require.NotContains(t, snapshot.Endpoints, "192.0.2.1:50000")
						require.NotContains(t, snapshot.Endpoints, "192.0.2.2:60000")
						require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:60000", "").CallID)
						if shared {
							retirementOwns(t, registry, "independent-owner", "192.0.2.1:50000")
						}
					} else {
						require.True(t, due.IsZero())
						require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:50000", "192.0.2.2:60000").CallID)
					}
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:30000", "192.0.2.2:40000")
				})
			}
		}
	}
}
