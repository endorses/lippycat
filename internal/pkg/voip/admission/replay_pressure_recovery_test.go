package admission

import (
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

// Complete pressure-only proof stays quarantined until the replay deadline.
func TestReplayPressureExpiryPromotesQuarantinedCompleteExchange(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, established := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/established-%v", mode, policy, established), func(t *testing.T) {
					bridge, registry, controller := retirementFixture(t, mode, policy)
					assertState := func(unknown bool) {
						t.Helper()
						if mode == mediaadmission.ModeEnforce || unknown {
							assertDerivationState(t, bridge, controller, policy, unknown)
							return
						}
						count := 0
						if unknown {
							count = 1
						}
						require.Equal(t, count, bridge.Stats().UnknownDerivations)
						require.Equal(t, mediaadmission.StateShadow, controller.Status()[0].State)
					}
					cfg := bridge.cfg.Limits
					cfg.ReplayGuardCapacity = 2
					store, err := mediaadmission.NewMetadataStore(cfg)
					require.NoError(t, err)
					bridge.cfg.Metadata = store
					bridge.cfg.Limits.ReplayGuardCapacity = cfg.ReplayGuardCapacity
					invite := offer("pressure-active")
					invite.Headers = map[string]string{"cseq": "1 INVITE"}
					if established {
						request, answer := recoveryAtSequence(invite, "caller", "INVITE", 1)
						require.NoError(t, submitDerivation(t, bridge, registry, request))
						require.NoError(t, submitDerivation(t, bridge, registry, answer))
						assertState(false)
					}
					// Retirement goes through actual registry lifecycle callbacks, with the
					// second independent identity exceeding simultaneous replay capacity.
					for _, id := range []string{"pressure-guard", "pressure-overflow"} {
						request, answer := recoveryAtSequence(offer(id), "caller", "INVITE", 1)
						require.NoError(t, submitDerivation(t, bridge, registry, request))
						require.NoError(t, submitDerivation(t, bridge, registry, answer))
						require.True(t, registry.Remove(id, callregistry.EndCompleted))
					}
					require.Equal(t, 2, store.Stats().ReplayContexts)
					rejected, answer := recoveryAtSequence(invite, "caller", "INVITE", 2)
					_ = submitDerivation(t, bridge, registry, rejected)
					_ = submitDerivation(t, bridge, registry, answer)
					var state *selectedCall
					func() {
						bridge.mu.Lock()
						defer bridge.mu.Unlock()
						state = bridge.selected[invite.CallID]
						require.NotNil(t, state)
						require.True(t, state.replayEvidenceMissing)
						deadline := bridge.proofHistory.blockedUntil
						require.True(t, time.Now().Before(deadline))
						bridge.expireLifetimeProofLocked(deadline)
						require.True(t, state.replayBlockedUntil.IsZero())
						require.False(t, state.replayEvidenceMissing)
						require.False(t, state.unknown)
						require.NotEmpty(t, state.mediaSet)
					}()
					require.NoError(t, bridge.retrySelected())
					assertState(false)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
				})
			}
		}
	}
}

// Capacity can become available while a later unrecorded retirement still
// blocks the domain. Retirement of a pressure-affected lifetime must retain
// unavailable sequence bounds for its own full window, not the older deadline.
func TestReplayPressureAffectedRetirementProtectsDiscardedSequence(t *testing.T) {
	bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	cfg := bridge.cfg.Limits
	cfg.ReplayGuardCapacity = 1
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	bridge.cfg.Metadata = store
	bridge.cfg.Limits.ReplayGuardCapacity = 1
	invite := offer("pressure-retiring")
	request, answer := recoveryAtSequence(invite, "caller", "INVITE", 1)
	require.NoError(t, submitDerivation(t, bridge, registry, request))
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
	for _, id := range []string{"earlier-guard", "later-overflow"} {
		first, accepted := recoveryAtSequence(offer(id), "caller", "INVITE", 1)
		require.NoError(t, submitDerivation(t, bridge, registry, first))
		require.NoError(t, submitDerivation(t, bridge, registry, accepted))
		require.True(t, registry.Remove(id, callregistry.EndCompleted))
	}
	discarded, discardedAnswer := recoveryAtSequence(invite, "caller", "INVITE", 999)
	_ = submitDerivation(t, bridge, registry, discarded)
	_ = submitDerivation(t, bridge, registry, discardedAnswer)
	var oldLife callregistry.Lifetime
	func() {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		require.True(t, bridge.selected[invite.CallID].replayEvidenceMissing)
		oldLife = bridge.selected[invite.CallID].lifetime
		// Move only the earlier guard's expiry to simulate that retirement aging
		// out before the later overload deadline, without a wall-clock sleep.
		for hash, guard := range bridge.proofHistory.initiators {
			guard.expires = time.Now().Add(-time.Nanosecond)
			bridge.proofHistory.initiators[hash] = guard
		}
		bridge.expireLifetimeProofLocked(time.Now())
		require.Zero(t, store.Stats().ReplayContexts)
		require.True(t, time.Now().Before(bridge.proofHistory.blockedUntil))
	}()
	require.True(t, registry.Remove(invite.CallID, callregistry.EndCompleted))
	func() {
		bridge.mu.Lock()
		defer bridge.mu.Unlock()
		marker, exists := bridge.proofHistory.initiators[lifetimeInitiatorHash(invite.CallID, "")]
		require.True(t, exists, "missing bounds require full-call replay protection")
		require.True(t, marker.blocked)
		require.True(t, marker.expires.After(bridge.proofHistory.blockedUntil))
		bridge.expireLifetimeProofLocked(bridge.proofHistory.blockedUntil)
		require.True(t, bridge.proofHistory.blockedUntil.IsZero())
		reused := &selectedCall{lifetime: callregistry.Lifetime{Session: oldLife.Session, Generation: oldLife.Generation + 1}}
		key := mediaadmission.DialogKey{CallID: invite.CallID, FromTag: discarded.FromTag, CSeq: discarded.CSeqNumber, CSeqMethod: "INVITE", CSeqValid: true}
		require.False(t, bridge.checkKeyLifetimeLocked(reused, key), "discarded high sequence remains protected until this retirement's own deadline")
	}()
}
