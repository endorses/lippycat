package admission

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/stretchr/testify/require"
)

func TestReliableExpiredUnmatchedProofRemainsUnknown(t *testing.T) {
	for _, first := range []string{"response", "answer"} {
		t.Run(first, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence("expired-" + first)
			_ = submitDerivation(t, bridge, registry, invite)
			if first == "response" {
				_ = submitDerivation(t, bridge, registry, response)
			} else {
				_ = submitDerivation(t, bridge, registry, prack)
			}
			bridge.mu.Lock()
			for _, state := range bridge.selected[invite.CallID].derivations {
				state.proofExpires = time.Now().Add(-time.Second)
			}
			bridge.mu.Unlock()
			if first == "response" {
				_ = submitDerivation(t, bridge, registry, prack)
			} else {
				_ = submitDerivation(t, bridge, registry, response)
			}
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
		})
	}
}

func TestReliableContextBudgetsAndRetirement(t *testing.T) {
	for _, limit := range []string{"contexts", "bytes", "endpoints"} {
		t.Run(limit, func(t *testing.T) {
			cfg := mediaadmission.DefaultConfig()
			cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, mediaadmission.FailureClosed, time.Hour
			switch limit {
			case "contexts":
				cfg.PendingDialogCapacity = 2
			case "bytes":
				cfg.PendingBytes = 1200
			case "endpoints":
				cfg.PendingEndpointCapacity = 3
			}
			maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
			controller, err := mediaadmission.NewController(t.Context(), cfg, maps)
			require.NoError(t, err)
			store, err := mediaadmission.NewMetadataStore(cfg)
			require.NoError(t, err)
			registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 100})
			bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
			require.NoError(t, err)
			t.Cleanup(func() { registry.Close(); check(t, bridge.Close()); check(t, controller.Close(context.Background())) })
			invite, response, prack := reliableSequence("budget-" + limit)
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			require.Error(t, submitDerivation(t, bridge, registry, prack))
			assertDerivationState(t, bridge, controller, cfg.FailurePolicy, true)
			usage := store.Stats()
			require.LessOrEqual(t, usage.SelectedContexts, cfg.PendingDialogCapacity)
			require.LessOrEqual(t, usage.SelectedBytes, cfg.PendingBytes)
			require.LessOrEqual(t, usage.SelectedEndpoints, cfg.PendingEndpointCapacity)
			require.NotZero(t, usage.SelectedRejected)
			registry.Remove(invite.CallID, callregistry.EndCompleted)
			require.NoError(t, bridge.retrySelected())
			assertRetiredLifetimeCharges(t, bridge, 1)
			assertClosedLifetimeCharges(t, bridge)
		})
	}
}

func TestReliableRetirementReuseAndWrongDomainCannotBorrowProof(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := reliableSequence("reliable-reuse")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	require.NoError(t, submitDerivation(t, bridge, registry, prack))
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	require.NoError(t, bridge.retrySelected())
	assertRetiredLifetimeCharges(t, bridge, 1)
	_ = submitDerivation(t, bridge, registry, invite)
	// This old answer cannot use the previous lifetime's discarded response.
	_ = submitDerivation(t, bridge, registry, prack)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	bridge.cfg.Limits.InterfaceDomains = map[string]mediaadmission.DomainID{"eth0": 0, "another-interface": 1}
	foreign := response
	foreign.Packet = &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: "another-interface"}}
	require.NoError(t, bridge.ObserveValidatedReceipt(&foreign))
	require.NoError(t, bridge.Selected(foreign))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	foreign.Packet.Source.Kind, foreign.Packet.Source.InterfaceName = pipeline.SourcePCAPReplay, "eth0"
	require.NoError(t, bridge.ObserveValidatedReceipt(&foreign))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestReliableConcurrentRetransmissionsPreserveBoundedProof(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureOpen, nil)
	invite, response, prack := reliableSequence("concurrent-reliable")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	require.NoError(t, submitDerivation(t, bridge, registry, prack))
	var workers sync.WaitGroup
	errors := make(chan error, 40)
	for worker := 0; worker < 4; worker++ {
		message := response
		if worker%2 != 0 {
			message = prack
		}
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := 0; index < 10; index++ {
				errors <- submitDerivation(t, bridge, registry, message)
			}
		}()
	}
	workers.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
	assertDerivationState(t, bridge, controller, mediaadmission.FailureOpen, false)
	require.Equal(t, 3, bridge.cfg.Metadata.Stats().SelectedContexts)
	require.Equal(t, 6, bridge.cfg.Metadata.Stats().SelectedEndpoints)
}

func TestReliableControlWriteFailureBlocksRecovery(t *testing.T) {
	bridge, registry, maps, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := reliableSequence("control-failure")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	maps.mu.Lock()
	maps.failControl = true
	maps.mu.Unlock()
	require.Error(t, submitDerivation(t, bridge, registry, prack))
	require.NotEqual(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
	maps.mu.Lock()
	maps.failControl = false
	maps.mu.Unlock()
	require.NoError(t, bridge.retrySelected())
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
}

func TestReliableCompleteAnswerSurvivesRejectedUPDATE(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := reliableSequence("reliable-rollback")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	require.NoError(t, submitDerivation(t, bridge, registry, prack))
	update := prack
	update.Method, update.CSeqMethod, update.CSeqNumber, update.ViaBranch, update.Headers = "UPDATE", "UPDATE", 3, "update", map[string]string{"cseq": "3 UPDATE"}
	update.SDP = derivationSDP("192.0.2.1", 30000, true)
	require.Error(t, submitDerivation(t, bridge, registry, update))
	failure := update
	failure.Method, failure.ResponseCode, failure.SDP = "RESPONSE", 486, nil
	_ = submitDerivation(t, bridge, registry, failure)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, false)
	assertDerivationMedia(t, bridge, invite.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
}

func TestRejectedPRACKRemainsUnknown(t *testing.T) {
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
	invite, response, prack := reliableSequence("rejected-prack")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	require.NoError(t, submitDerivation(t, bridge, registry, prack))
	failure := prack
	failure.Method, failure.ResponseCode, failure.SDP = "RESPONSE", 481, nil
	require.Error(t, submitDerivation(t, bridge, registry, failure))
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	_ = submitDerivation(t, bridge, registry, prack)
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
}

func TestReliableAssociationCapacityBlocksRecoveryUntilRetry(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			cfg := mediaadmission.DefaultConfig()
			cfg.Enabled, cfg.FailurePolicy, cfg.RetryInterval = true, policy, time.Hour
			maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
			controller, err := mediaadmission.NewController(t.Context(), cfg, maps)
			require.NoError(t, err)
			store, err := mediaadmission.NewMetadataStore(cfg)
			require.NoError(t, err)
			registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 32, MaxEndpointAssociations: 4})
			bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
			require.NoError(t, err)
			t.Cleanup(func() { registry.Close(); check(t, bridge.Close()); check(t, controller.Close(context.Background())) })
			invite, response, prack := reliableSequence("association-capacity")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			registry.Upsert(callregistry.Call{CallID: "other-unselected"})
			blocker, ok := registry.Call("other-unselected")
			require.True(t, ok)
			for _, endpoint := range []string{"192.0.2.9:30000", "192.0.2.9:30001"} {
				require.True(t, registry.TryAssociateEndpointForLifetime(blocker.CallID, blocker.Lifetime, endpoint))
			}
			require.Error(t, submitDerivation(t, bridge, registry, prack))
			require.Zero(t, bridge.Stats().UnknownDerivations)
			require.NotEqual(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
			info := prack
			info.Method, info.CSeqMethod, info.CSeqNumber, info.ViaBranch, info.Headers = "INFO", "INFO", 3, "info", map[string]string{"cseq": "3 INFO"}
			info.SDP = response.SDP
			require.Error(t, submitDerivation(t, bridge, registry, info))
			require.NotEqual(t, mediaadmission.StateEnforcing, controller.Status()[0].State)
			registry.Remove(blocker.CallID, callregistry.EndCompleted)
			require.NoError(t, bridge.retrySelected())
			assertDerivationState(t, bridge, controller, policy, false)
			require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
		})
	}
}

func TestReliableConcurrentLifetimeMutationCannotPublishOldProof(t *testing.T) {
	var source *pausedSnapshotRegistry
	bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, func(core *callregistry.Core) Registry {
		source = &pausedSnapshotRegistry{Core: core, entered: make(chan struct{}), release: make(chan struct{})}
		return source
	})
	invite, response, prack := reliableSequence("concurrent-lifetime")
	_ = submitDerivation(t, bridge, registry, invite)
	_ = submitDerivation(t, bridge, registry, response)
	require.NoError(t, submitDerivation(t, bridge, registry, prack))
	source.armed.Store(true)
	var released sync.Once
	t.Cleanup(func() { released.Do(func() { close(source.release) }) })
	done := make(chan error, 1)
	go func() { done <- submitDerivation(t, bridge, registry, prack) }()
	select {
	case <-source.entered:
	case <-time.After(time.Second):
		t.Fatal("registry snapshot was not reached")
	}
	registry.Remove(invite.CallID, callregistry.EndCompleted)
	replacement := invite
	replacement.FromTag, replacement.ViaBranch = "new-origin", "new-invite"
	_ = submitDerivation(t, bridge, registry, replacement)
	released.Do(func() { close(source.release) })
	_ = <-done
	assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
	require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
}

func TestReliablePendingProofExpiryAndEvictionCannotSupplyMissingResponse(t *testing.T) {
	for _, loss := range []string{"expiry", "eviction"} {
		t.Run(loss, func(t *testing.T) {
			bridge, registry, _, controller := recoveryFixture(t, mediaadmission.FailureClosed, nil)
			invite, response, prack := reliableSequence("lost-pending-" + loss)
			require.NoError(t, bridge.ObserveValidatedReceipt(&invite))
			require.NoError(t, bridge.ObserveValidatedReceipt(&response))
			if loss == "expiry" {
				bridge.cfg.Metadata.Expire(time.Now().Add(bridge.cfg.Limits.PendingTTL + time.Second))
			} else {
				// Use the same configured bound as production rather than forcing
				// deletion; unrelated staged descriptors evict old pending proof.
				for index := 0; index <= bridge.cfg.Limits.PendingDialogCapacity; index++ {
					other := offer(fmt.Sprintf("pending-pressure-%d", index))
					other.SDP = nil
					require.NoError(t, bridge.ObserveValidatedReceipt(&other))
				}
				require.NotZero(t, bridge.cfg.Metadata.Stats().Evicted)
			}
			_ = submitDerivation(t, bridge, registry, prack)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			final := response
			final.ResponseCode, final.SDP = 200, nil
			_ = submitDerivation(t, bridge, registry, final)
			assertDerivationState(t, bridge, controller, mediaadmission.FailureClosed, true)
			require.Equal(t, invite.CallID, registry.ResolveMediaEndpoints("192.0.2.1:10000", "").CallID)
			require.Empty(t, registry.ResolveMediaEndpoints("192.0.2.2:20000", "").CallID)
		})
	}
}

// Final removal releases live proof and endpoint reservations. A bounded hash
// watermark remains in the separately bounded replay pool until window expiry.
func assertRetiredLifetimeCharges(t *testing.T, bridge *Bridge, historyCount int) {
	t.Helper()
	bridge.mu.Lock()
	contexts, bytes, endpoints := bridge.derivationCount, bridge.derivationBytes, bridge.derivationEndpoints
	bridge.mu.Unlock()
	require.Zero(t, contexts)
	require.Zero(t, bytes)
	require.Zero(t, endpoints)
	usage := bridge.cfg.Metadata.Stats()
	require.Zero(t, usage.SelectedContexts)
	require.Zero(t, usage.SelectedBytes)
	require.Len(t, bridge.proofHistory.initiators, historyCount)
	require.Zero(t, usage.SelectedEndpoints)
}

func assertClosedLifetimeCharges(t *testing.T, bridge *Bridge) {
	t.Helper()
	require.NoError(t, bridge.Close())
	usage := bridge.cfg.Metadata.Stats()
	require.Zero(t, usage.SelectedContexts)
	require.Zero(t, usage.SelectedBytes)
	require.Zero(t, usage.SelectedEndpoints)
}
