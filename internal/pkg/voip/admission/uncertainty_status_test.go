package admission

import (
	"context"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func uncertaintySnapshot(t *testing.T, bridge *Bridge, controller *mediaadmission.Controller) mediaadmission.UncertaintyStats {
	t.Helper()
	_ = bridge.Stats()
	for _, scope := range controller.Status() {
		if scope.Domain == bridge.cfg.Domain {
			return scope.Uncertainty
		}
	}
	t.Fatal("missing admission domain")
	return mediaadmission.UncertaintyStats{}
}

func TestBridgeUncertaintyHealthyReliableAndIndependentPartial(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
			invite := retirementHealthyCall(t, bridge, registry, "reliable-prack")
			request, _ := recoveryAtSequence(invite, "callee", "UPDATE", 40)
			request.SDP = derivationSDP("192.0.2.2", 40000, true)
			_ = submitDerivation(t, bridge, registry, request)
			stats := uncertaintySnapshot(t, bridge, controller)
			require.Equal(t, uint64(1), stats.UnknownCalls)
			require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonPartialSDP])
			require.Zero(t, stats.Reasons[mediaadmission.ReasonFaultyPRACK], "a retained healthy PRACK is not the cause of unrelated partial SDP")
			require.Zero(t, stats.Reasons[mediaadmission.ReasonDelayedOffer], "the reliable delayed offer has already been answered")
			request, answer := recoveryAtSequence(invite, "callee", "UPDATE", 41)
			_ = submitDerivation(t, bridge, registry, request)
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			require.Zero(t, uncertaintySnapshot(t, bridge, controller).UnknownCalls)
			require.Equal(t, [mediaadmission.UncertaintyReasonCount]uint64{}, uncertaintySnapshot(t, bridge, controller).Reasons)
		})
	}
}

func TestBridgeUncertaintyCountsOverlapUniqueCallsAndRetirement(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite, response, prack := faultyReliableSequence("faulty-partial", "partial-prack")
	for _, message := range []pipeline.SIPResult{invite, response, prack} {
		_ = submitDerivation(t, bridge, registry, message)
	}
	stats := uncertaintySnapshot(t, bridge, controller)
	require.Equal(t, uint64(1), stats.UnknownCalls)
	require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonFaultyPRACK])
	require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonPartialSDP])
	require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonDelayedOffer])
	second := offer("ordinary-partial-diagnostic")
	second.SDP = derivationSDP("192.0.2.3", 30000, true)
	_ = submitDerivation(t, bridge, registry, second)
	stats = uncertaintySnapshot(t, bridge, controller)
	require.Equal(t, uint64(2), stats.UnknownCalls)
	require.Equal(t, uint64(2), stats.Reasons[mediaadmission.ReasonPartialSDP])
	require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonFaultyPRACK])
	require.True(t, registry.Remove(invite.CallID, callregistry.EndCompleted))
	stats = uncertaintySnapshot(t, bridge, controller)
	require.Equal(t, uint64(1), stats.UnknownCalls)
	require.Zero(t, stats.Reasons[mediaadmission.ReasonFaultyPRACK])
	require.Zero(t, stats.Reasons[mediaadmission.ReasonDelayedOffer])
	require.True(t, registry.Remove(second.CallID, callregistry.EndCompleted))
	require.Zero(t, uncertaintySnapshot(t, bridge, controller).UnknownCalls)
}

func TestBridgeUncertaintyDuplicateGroupCountersSeparateFromActiveCalls(t *testing.T) {
	bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
	invite := offer("duplicate-diagnostic")
	invite.Headers = map[string]string{"cseq": "1 INVITE"}
	invite = recoveryDuplicateCSeq(t, invite, "01 INVITE", "1 INVITE", "1 INVITE")
	require.NoError(t, submitDerivation(t, bridge, registry, invite))
	stats := uncertaintySnapshot(t, bridge, controller)
	require.Zero(t, stats.UnknownCalls)
	require.Equal(t, uint64(1), stats.IdenticalDuplicates, "a singleton group counts once regardless of repeated-line count")
	conflicting := recoveryDuplicateCSeq(t, invite, "3 INVITE", "9 INVITE")
	conflicting.CSeqMethod = "INVITE"
	_ = submitDerivation(t, bridge, registry, conflicting)
	stats = uncertaintySnapshot(t, bridge, controller)
	require.Equal(t, uint64(1), stats.UnknownCalls)
	require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonConflictingHeaders])
	require.Equal(t, uint64(1), stats.IdenticalDuplicates)
	require.Equal(t, uint64(1), stats.ConflictingDuplicates)
	require.True(t, registry.Remove(invite.CallID, callregistry.EndCompleted))
	stats = uncertaintySnapshot(t, bridge, controller)
	require.Zero(t, stats.UnknownCalls)
	require.Equal(t, uint64(1), stats.IdenticalDuplicates)
	require.Equal(t, uint64(1), stats.ConflictingDuplicates)
	// Reliable singleton groups are independently counted even when unselected.
	event, err := sip.Parse([]byte("SIP/2.0 183 Progress\r\nCSeq: 1 INVITE\r\nCSeq: 1 INVITE\r\nRSeq: 7\r\nRSeq: 9\r\nRAck: 9 1 INVITE\r\nRAck: 9 1 INVITE\r\nContent-Length: 0\r\n\r\n"), sip.ParseOptions{})
	require.NoError(t, err)
	_ = bridge.ObserveValidated(pipeline.SIPResultFromEvent(event, invite.Packet))
	stats = uncertaintySnapshot(t, bridge, controller)
	require.Equal(t, uint64(3), stats.IdenticalDuplicates)
	require.Equal(t, uint64(2), stats.ConflictingDuplicates)
}

func TestBridgeUncertaintyMultipleDomainsRemainIndependent(t *testing.T) {
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.RetryInterval = time.Hour
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"a": 1, "b": 2}
	controller, err := mediaadmission.NewController(context.Background(), cfg, &backend{keys: make(map[mediaadmission.EndpointKey]bool)})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, controller.Close(context.Background())) })
	bridges := make([]*Bridge, 0, 2)
	registries := make([]*callregistry.Core, 0, 2)
	for _, domain := range []mediaadmission.DomainID{1, 2} {
		registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 64, MaxEndpointAssociations: 256})
		store, err := mediaadmission.NewMetadataStore(cfg)
		require.NoError(t, err)
		bridge, err := New(Config{Domain: domain, Limits: cfg, Registry: registry, Metadata: store, Controller: controller})
		require.NoError(t, err)
		t.Cleanup(func() { registry.Close(); require.NoError(t, bridge.Close()) })
		bridges = append(bridges, bridge)
		registries = append(registries, registry)
	}
	partial := offer("domain-partial")
	partial.SDP = derivationSDP("192.0.2.1", 10000, true)
	partial.Packet.Source.InterfaceName = "a"
	_ = submitDerivation(t, bridges[0], registries[0], partial)
	require.Equal(t, uint64(1), uncertaintySnapshot(t, bridges[0], controller).Reasons[mediaadmission.ReasonPartialSDP])
	require.Zero(t, uncertaintySnapshot(t, bridges[1], controller).UnknownCalls)
	delayed := offer("domain-delayed")
	delayed.SDP = nil
	delayed.Packet.Source.InterfaceName = "b"
	_ = submitDerivation(t, bridges[1], registries[1], delayed)
	require.Equal(t, uint64(1), uncertaintySnapshot(t, bridges[1], controller).Reasons[mediaadmission.ReasonDelayedOffer])
	require.Zero(t, uncertaintySnapshot(t, bridges[1], controller).Reasons[mediaadmission.ReasonPartialSDP])
	require.Zero(t, uncertaintySnapshot(t, bridges[0], controller).Reasons[mediaadmission.ReasonDelayedOffer])
}

func TestBridgeUncertaintyRetirementFailureAndRetry(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, resolve := range []string{"retry", "complete"} {
			t.Run(string(policy)+"/"+resolve, func(t *testing.T) {
				bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
				state, key := graceOwnedEndpoint(t, bridge, registry)
				failure := &graceRejectRegistry{Core: registry, reject: true}
				now := time.Now()
				bridge.mu.Lock()
				bridge.cfg.Registry = failure
				require.NoError(t, bridge.scheduleRetirementsLocked(state, []mediaadmission.EndpointKey{key}, now))
				bridge.mu.Unlock()
				bridge.publicationMu.Lock()
				require.ErrorIs(t, bridge.expireRetirements(now.Add(time.Minute)), ErrCallUnavailable)
				bridge.publicationMu.Unlock()
				stats := uncertaintySnapshot(t, bridge, controller)
				require.Equal(t, uint64(1), stats.UnknownCalls)
				require.Equal(t, uint64(1), stats.Reasons[mediaadmission.ReasonEvidenceLoss])
				require.Equal(t, 1, bridge.Stats().UnknownDerivations)
				failure.reject = false
				if resolve == "retry" {
					bridge.publicationMu.Lock()
					require.NoError(t, bridge.expireRetirements(now.Add(time.Minute)))
					bridge.publicationMu.Unlock()
				} else {
					call, exists := registry.Call("grace-synthetic")
					require.True(t, exists)
					bridge.OnCallCompleting(call)
				}
				bridge.mu.Lock()
				require.NoError(t, bridge.recoverLocked())
				bridge.mu.Unlock()
				stats = uncertaintySnapshot(t, bridge, controller)
				require.Zero(t, stats.UnknownCalls)
				require.Zero(t, stats.Reasons[mediaadmission.ReasonEvidenceLoss])
				require.Zero(t, bridge.Stats().UnknownDerivations)
			})
		}
	}
}
