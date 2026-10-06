package admission

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/stretchr/testify/require"
)

func graceOwnedEndpoint(t *testing.T, bridge *Bridge, registry *callregistry.Core) (*selectedCall, mediaadmission.EndpointKey) {
	t.Helper()
	request := offer("grace-synthetic")
	require.NoError(t, submitDerivation(t, bridge, registry, request))
	call, ok := registry.Call(request.CallID)
	require.True(t, ok)
	require.True(t, registry.TryAssociateEndpointForLifetime(call.CallID, call.Lifetime, "192.0.2.10:9000"))
	key, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.10:9000")
	require.NoError(t, err)
	bridge.mu.Lock()
	state := bridge.selected[call.CallID]
	bridge.cfg.RetirementGrace = time.Minute
	bridge.mu.Unlock()
	return state, key
}

func TestRetirementGraceBoundaryAndSharedOwnership(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, policy)
			state, key := graceOwnedEndpoint(t, bridge, registry)
			registry.Upsert(callregistry.Call{CallID: "other-synthetic"})
			other, _ := registry.Call("other-synthetic")
			require.True(t, registry.TryAssociateEndpointForLifetime(other.CallID, other.Lifetime, "192.0.2.10:9000"))
			original, _ := registry.Call("grace-synthetic")
			require.True(t, registry.TryAssociateEndpointForLifetime(original.CallID, original.Lifetime, "192.0.2.11:9001"))
			now := time.Now()
			before := bridge.cfg.Metadata.Stats()
			bridge.mu.Lock()
			require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
			bridge.mu.Unlock()
			charged := bridge.cfg.Metadata.Stats()
			require.Equal(t, before.SelectedEndpoints+1, charged.SelectedEndpoints)
			require.Equal(t, before.SelectedContexts+1, charged.SelectedContexts)
			bridge.publicationMu.Lock()
			require.NoError(t, bridge.expireRetirements(now.Add(time.Minute-time.Nanosecond)))
			bridge.publicationMu.Unlock()
			resolution := registry.ResolveMediaEndpoints("192.0.2.10:9000", "192.0.2.11:9001")
			require.Equal(t, original.CallID, resolution.CallID)
			require.Equal(t, original.Lifetime, resolution.Lifetime)
			bridge.publicationMu.Lock()
			require.NoError(t, bridge.expireRetirements(now.Add(time.Minute)))
			bridge.publicationMu.Unlock()
			snapshot, _ := registry.EndpointSnapshot(original.CallID)
			require.NotContains(t, snapshot.Endpoints, "192.0.2.10:9000")
			otherSnapshot, _ := registry.EndpointSnapshot(other.CallID)
			require.Contains(t, otherSnapshot.Endpoints, "192.0.2.10:9000")
			require.Equal(t, before.SelectedEndpoints, bridge.cfg.Metadata.Stats().SelectedEndpoints)
		})
	}
}

func TestRetirementGraceReuseAndCompletionCancellation(t *testing.T) {
	for _, cancel := range []string{"reuse", "completion", "final-removal", "shutdown"} {
		t.Run(cancel, func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			state, key := graceOwnedEndpoint(t, bridge, registry)
			now := time.Now()
			bridge.mu.Lock()
			require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
			bridge.mu.Unlock()
			original, _ := registry.Call("grace-synthetic")
			switch cancel {
			case "reuse":
				bridge.mu.Lock()
				state.derivations[derivationSide{"a", "b", "a", false}] = &derivationState{complete: true, accepted: true, endpoints: []mediaadmission.EndpointKey{key}}
				require.NoError(t, bridge.cancelRequiredRetirementsLocked(state))
				// This synthetic proof is not installed through derivation reservation.
				delete(state.derivations, derivationSide{"a", "b", "a", false})
				bridge.mu.Unlock()
			case "completion":
				bridge.OnCallCompleting(original)
				bridge.mu.Lock()
				require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
				bridge.mu.Unlock()
			case "final-removal":
				require.True(t, registry.Remove(original.CallID, callregistry.EndCompleted))
			case "shutdown":
				require.NoError(t, bridge.Close())
			}
			require.Empty(t, state.retirements)
			bridge.publicationMu.Lock()
			require.NoError(t, bridge.expireRetirements(now.Add(2*time.Minute)))
			bridge.publicationMu.Unlock()
			if cancel == "reuse" || cancel == "completion" {
				snapshot, _ := registry.EndpointSnapshot(original.CallID)
				require.Contains(t, snapshot.Endpoints, "192.0.2.10:9000")
			}
		})
	}
}

func TestRetirementGraceShadowAndExhaustion(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		t.Run(string(mode), func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mode, mediaadmission.FailureClosed)
			state, key := graceOwnedEndpoint(t, bridge, registry)
			bridge.mu.Lock()
			require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, time.Now()))
			if mode == mediaadmission.ModeShadow {
				require.Empty(t, state.retirements)
			} else {
				// Per-owner hard cap is exercised without changing the shared store cap.
				bridge.cfg.Limits.MaxEndpointsPerOwner = 1
				second, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.20:9010")
				require.NoError(t, err)
				require.ErrorIs(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{second}, time.Now()), mediaadmission.ErrCapacity)
				require.Len(t, state.retirements, 1)
				require.True(t, state.contextLost)
			}
			bridge.mu.Unlock()
		})
	}
}

type graceRejectRegistry struct {
	*callregistry.Core
	reject bool
}

func (r *graceRejectRegistry) TryDissociateEndpointsForLifetime(id string, lifetime callregistry.Lifetime, endpoints []string) bool {
	if r.reject {
		return false
	}
	return r.Core.TryDissociateEndpointsForLifetime(id, lifetime, endpoints)
}

func TestRetirementGraceMutationRetryAndRepeatedScheduling(t *testing.T) {
	bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	state, key := graceOwnedEndpoint(t, bridge, registry)
	failing := &graceRejectRegistry{Core: registry, reject: true}
	now := time.Now()
	bridge.mu.Lock()
	bridge.cfg.Registry = failing
	require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
	require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now.Add(time.Minute)))
	require.Equal(t, now.Add(time.Minute), state.retirements[key], "repeated repair cannot postpone previously scheduled ownership indefinitely")
	before := bridge.cfg.Metadata.Stats()
	bridge.mu.Unlock()
	bridge.publicationMu.Lock()
	require.ErrorIs(t, bridge.expireRetirements(now.Add(time.Minute)), ErrCallUnavailable)
	bridge.publicationMu.Unlock()
	require.Len(t, state.retirements, 1)
	bridge.mu.Lock()
	require.True(t, state.retirementFailed)
	require.Error(t, bridge.recoverLocked(), "registry snapshot cannot erase a failed delayed-mutation obligation")
	bridge.mu.Unlock()
	require.Equal(t, before.SelectedEndpoints, bridge.cfg.Metadata.Stats().SelectedEndpoints)
	failing.reject = false
	bridge.publicationMu.Lock()
	require.NoError(t, bridge.expireRetirements(now.Add(time.Minute)))
	bridge.publicationMu.Unlock()
	require.Empty(t, state.retirements)
	bridge.mu.Lock()
	require.False(t, state.retirementFailed)
	require.NoError(t, bridge.recoverLocked(), "successful delayed mutation permits current snapshot reconciliation")
	bridge.mu.Unlock()
	require.Equal(t, before.SelectedEndpoints-1, bridge.cfg.Metadata.Stats().SelectedEndpoints)
}

func TestRetirementGraceOldLifetimeCannotRemoveReplacement(t *testing.T) {
	bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	state, key := graceOwnedEndpoint(t, bridge, registry)
	original, _ := registry.Call("grace-synthetic")
	now := time.Now()
	bridge.mu.Lock()
	require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
	bridge.mu.Unlock()
	require.True(t, registry.Remove(original.CallID, callregistry.EndCompleted))
	registry.Upsert(callregistry.Call{CallID: original.CallID})
	current, _ := registry.Call(original.CallID)
	require.NotEqual(t, original.Lifetime, current.Lifetime)
	require.True(t, registry.TryAssociateEndpointForLifetime(current.CallID, current.Lifetime, "192.0.2.10:9000"))
	bridge.OnCallCompleting(original)
	bridge.publicationMu.Lock()
	require.NoError(t, bridge.expireRetirements(now.Add(2*time.Minute)))
	bridge.publicationMu.Unlock()
	snapshot, _ := registry.EndpointSnapshot(current.CallID)
	require.Contains(t, snapshot.Endpoints, "192.0.2.10:9000")
	require.Equal(t, current.Lifetime, snapshot.Call.Lifetime)
	require.Empty(t, state.retirements)
}

func TestRetirementFailedCancellationPreservesFutureWork(t *testing.T) {
	bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	state, key := graceOwnedEndpoint(t, bridge, registry)
	failing := &graceRejectRegistry{Core: registry, reject: true}
	now := time.Now()
	bridge.mu.Lock()
	bridge.cfg.Registry = failing
	require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
	bridge.mu.Unlock()
	bridge.publicationMu.Lock()
	require.Error(t, bridge.expireRetirements(now.Add(time.Minute)))
	bridge.publicationMu.Unlock()
	future, err := parseEndpoint(bridge.cfg.Domain, "192.0.2.21:9011")
	require.NoError(t, err)
	bridge.mu.Lock()
	require.True(t, state.retirementFailed)
	require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{future}, now.Add(2*time.Minute)))
	protected := derivationSide{"a", "b", "a", false}
	state.derivations[protected] = &derivationState{complete: true, accepted: true, endpoints: []mediaadmission.EndpointKey{key}}
	require.NoError(t, bridge.cancelRequiredRetirementsLocked(state))
	delete(state.derivations, protected) // Synthetic proof has no reservation.
	require.False(t, state.retirementFailed, "valid reuse clears the failed obligation")
	require.Len(t, state.retirements, 1, "future cleanup remains independently scheduled")
	require.Contains(t, state.retirements, future)
	require.NoError(t, bridge.recoverLocked())
	bridge.mu.Unlock()
}
