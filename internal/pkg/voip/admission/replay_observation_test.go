package admission

import (
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type replayTestClock struct{ value atomic.Pointer[time.Time] }

func (c *replayTestClock) now() time.Time    { return *c.value.Load() }
func (c *replayTestClock) set(now time.Time) { c.value.Store(&now) }
func observationFixture(t *testing.T, mode mediaadmission.Mode, policy mediaadmission.FailurePolicy, count, bytes int) (*Bridge, *callregistry.Core, *mediaadmission.Controller, *replayTestClock) {
	t.Helper()
	clock := &replayTestClock{}
	clock.set(time.Now())
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled, cfg.Mode, cfg.FailurePolicy, cfg.RetryInterval = true, mode, policy, time.Hour
	cfg.ReplayGuardCapacity, cfg.ReplayGuardBytes = count, bytes
	cfg.ReplayWindow = time.Second
	cfg.PendingTTL = time.Minute
	b, r, controller := retirementConfiguredFixture(t, cfg, clock.now)
	return b, r, controller, clock
}
func retireObservationPair(t *testing.T, b *Bridge, r *callregistry.Core, id string) (pipeline.SIPResult, pipeline.SIPResult) {
	t.Helper()
	request, response := recoveryAtSequence(offer(id), "caller", "INVITE", 1)
	_ = submitDerivation(t, b, r, request)
	_ = submitDerivation(t, b, r, response)
	require.True(t, r.Remove(id, callregistry.EndCompleted))
	return request, response
}
func advanceObservationPressure(t *testing.T, b *Bridge, clock *replayTestClock) {
	t.Helper()
	clock.set(b.proofHistory.blockedUntil)
	b.mu.Lock()
	b.expireLifetimeProofLocked(clock.now())
	b.mu.Unlock()
	_ = b.retrySelected()
}
func TestReplayObservationRetiredIdentityNeverPromotesAfterExpiry(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, bound := range []string{"count", "bytes"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, bound), func(t *testing.T) {
					count, bytes := 2, 4096
					if bound == "bytes" {
						count, bytes = 64, 256
					}
					b, r, _, clock := observationFixture(t, mode, policy, count, bytes)
					guarded, guardedAnswer := retireObservationPair(t, b, r, "synthetic-exact")
					retired, answer := retireObservationPair(t, b, r, "synthetic-unrecorded")
					require.Len(t, b.proofHistory.overflow, 1)
					require.Equal(t, 2, b.cfg.Metadata.Stats().ReplayContexts)
					for _, message := range []pipeline.SIPResult{guarded, guardedAnswer, retired, answer} {
						_ = submitDerivation(t, b, r, message)
					}
					advanceObservationPressure(t, b, clock)
					for _, id := range []string{guarded.CallID, retired.CallID} {
						b.mu.Lock()
						state := b.selected[id]
						assert.True(t, state.unknown)
						assert.Nil(t, state.quarantine)
						b.mu.Unlock()
						snapshot, ok := r.EndpointSnapshot(id)
						require.True(t, ok)
						require.Empty(t, snapshot.Endpoints)
					}
					require.Zero(t, b.cfg.Metadata.Stats().ReplayContexts)
					// Newly observed identical wire proof is the deliberate finite-window
					// boundary. Rejection of earlier observations remains permanent.
					_ = submitDerivation(t, b, r, retired)
					_ = submitDerivation(t, b, r, answer)
					b.mu.Lock()
					unknown := b.selected[retired.CallID].unknown
					b.mu.Unlock()
					require.False(t, unknown)
					retirementOwns(t, r, retired.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
					old := mediaadmission.DialogKey{CallID: retired.CallID, FromTag: retired.FromTag, CSeq: 1, CSeqMethod: "INVITE", CSeqValid: true, LifetimeSession: 99, LifetimeGeneration: 99}
					b.mu.Lock()
					assert.False(t, b.checkKeyLifetimeLocked(b.selected[retired.CallID], old))
					b.mu.Unlock()
				})
			}
		}
	}
}
func TestReplayObservationGenuineAndDeadlineCrossingExchanges(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, kind := range []string{"complete", "crossing", "update", "reliable", "delayed"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, kind), func(t *testing.T) {
					b, r, _, clock := observationFixture(t, mode, policy, 2, 4096)
					var request, response, completion pipeline.SIPResult
					request, response = recoveryAtSequence(offer("synthetic-eligible"), "caller", "INVITE", 1)
					if kind == "update" {
						require.NoError(t, submitDerivation(t, b, r, request))
						require.NoError(t, submitDerivation(t, b, r, response))
						request, response = recoveryAtSequence(request, "caller", "UPDATE", 2)
						request.ToTag = response.ToTag
					}
					if kind == "reliable" {
						request, response, completion = reliableSequence(request.CallID)
					}
					if kind == "delayed" {
						request.SDP = nil
						response.SDP = derivationSDP("192.0.2.2", 40000, false)
						completion = request
						completion.Method = "ACK"
						completion.CSeqMethod = "ACK"
						completion.ToTag = response.ToTag
						completion.ViaBranch = "ack-branch"
						completion.Headers = map[string]string{"cseq": "1 ACK"}
						completion.SDP = derivationSDP("192.0.2.1", 30000, false)
					}
					retireObservationPair(t, b, r, "synthetic-exact")
					retireObservationPair(t, b, r, "synthetic-overflow")
					_ = submitDerivation(t, b, r, request)
					if kind == "complete" {
						_ = submitDerivation(t, b, r, response)
					}
					advanceObservationPressure(t, b, clock)
					if kind != "complete" {
						_ = submitDerivation(t, b, r, response)
					}
					if kind == "reliable" || kind == "delayed" {
						_ = submitDerivation(t, b, r, completion)
					}
					if kind == "reliable" {
						final := response
						final.ResponseCode = 200
						final.SDP = nil
						final.Headers = map[string]string{"cseq": "1 INVITE"}
						_ = submitDerivation(t, b, r, final)
					}
					require.Zero(t, b.Stats().UnknownDerivations)
					snapshot, ok := r.EndpointSnapshot(request.CallID)
					require.True(t, ok)
					require.NotEmpty(t, snapshot.Endpoints)
					b.mu.Lock()
					assert.Nil(t, b.selected[request.CallID].quarantine)
					b.mu.Unlock()
				})
			}
		}
	}
}
func TestReplayObservationHistoryLossInvalidatesEarlierQuarantineAndDelayedMetadata(t *testing.T) {
	for _, budget := range []int{1, 2} {
		t.Run(fmt.Sprint(budget), func(t *testing.T) {
			b, r, _, clock := observationFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed, budget, 4096)
			retireObservationPair(t, b, r, "synthetic-first")
			retireObservationPair(t, b, r, "synthetic-overflow")
			request, response := recoveryAtSequence(offer("synthetic-genuine"), "caller", "INVITE", 1)
			_ = submitDerivation(t, b, r, request)
			_ = submitDerivation(t, b, r, response)
			delayed, delayedResponse := recoveryAtSequence(offer("synthetic-delayed-selection"), "caller", "INVITE", 1)
			require.NoError(t, b.ObserveValidatedReceipt(&delayed))
			require.NoError(t, b.ObserveValidatedReceipt(&delayedResponse))
			if budget == 2 {
				retireObservationPair(t, b, r, "synthetic-overflow-again")
			}
			require.Equal(t, b.proofHistory.generation, b.proofHistory.invalidThrough)
			b.mu.Lock()
			assert.Nil(t, b.selected[request.CallID].quarantine)
			b.mu.Unlock()
			advanceObservationPressure(t, b, clock)
			r.Upsert(callregistry.Call{CallID: delayed.CallID})
			_ = b.Selected(delayed)
			_ = b.Selected(delayedResponse)
			for _, id := range []string{request.CallID, delayed.CallID} {
				snapshot, ok := r.EndpointSnapshot(id)
				require.True(t, ok)
				require.Empty(t, snapshot.Endpoints)
			}
			// A second pressure interval cannot revive the invalid first generation.
			retireObservationPair(t, b, r, "synthetic-next-guard")
			retireObservationPair(t, b, r, "synthetic-next-overflow")
			advanceObservationPressure(t, b, clock)
			for _, message := range []pipeline.SIPResult{request, response} {
				_ = submitDerivation(t, b, r, message)
			}
			retirementOwns(t, r, request.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
		})
	}
}
func TestReplayObservationRetainedBodylessMessagesAndNegativeCases(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, kind := range []string{"ack", "late-180", "changed-sdp", "reliable", "malformed-reliable", "wrong-fork", "wrong-sequence", "conflict"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, kind), func(t *testing.T) {
					b, r, _, clock := observationFixture(t, mode, policy, 2, 4096)
					request, response := recoveryAtSequence(offer("synthetic-healthy"), "caller", "INVITE", 1)
					require.NoError(t, submitDerivation(t, b, r, request))
					require.NoError(t, submitDerivation(t, b, r, response))
					retireObservationPair(t, b, r, "synthetic-guard")
					retireObservationPair(t, b, r, "synthetic-overflow")
					message := response
					message.SDP = nil
					message.ResponseCode = 180
					if kind == "ack" || kind == "wrong-fork" || kind == "wrong-sequence" {
						message = request
						message.SDP = nil
						message.Method = "ACK"
						message.CSeqMethod = "ACK"
						message.ToTag = response.ToTag
						message.ViaBranch = "separate-ack"
						message.Headers = map[string]string{"cseq": "1 ACK"}
					}
					switch kind {
					case "changed-sdp":
						message.SDP = derivationSDP("192.0.2.9", 50000, false)
					case "reliable":
						message.ResponseCode = 183
						message.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "101"}
					case "malformed-reliable":
						message.ResponseCode = 183
						message.Headers = map[string]string{"cseq": "1 INVITE", "require": "100rel", "rseq": "bad"}
					case "wrong-fork":
						message.ToTag = "other-fork"
					case "wrong-sequence":
						message.CSeqNumber = 2
						message.Headers = map[string]string{"cseq": "2 ACK"}
					case "conflict":
						message.ReliableHeaderEvidence.Conflicts = sip.ReliableHeaderConflicts{CSeq: true}
					}
					_ = submitDerivation(t, b, r, message)
					good := kind == "ack" || kind == "late-180"
					b.mu.Lock()
					assert.Equal(t, !good, b.selected[request.CallID].replayEvidenceMissing)
					b.mu.Unlock()
					advanceObservationPressure(t, b, clock)
					if good {
						require.Zero(t, b.Stats().UnknownDerivations)
					} else {
						require.Equal(t, 1, b.Stats().UnknownDerivations)
					}
				})
			}
		}
	}
}

func TestReplayObservationExactBoundaryAndGenerationSaturation(t *testing.T) {
	b, r, _, clock := observationFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed, 2, 4096)
	b.mu.Lock()
	b.proofHistory.generation = ^uint64(0)
	b.mu.Unlock()
	retireObservationPair(t, b, r, "synthetic-guard")
	retired, answer := retireObservationPair(t, b, r, "synthetic-overflow")
	require.Equal(t, ^uint64(0), b.proofHistory.generation)
	require.Equal(t, ^uint64(0), b.proofHistory.invalidThrough)
	deadline := b.proofHistory.blockedUntil
	clock.set(deadline.Add(-time.Nanosecond))
	require.NoError(t, b.ObserveValidatedReceipt(&retired))
	require.NoError(t, b.ObserveValidatedReceipt(&answer))
	b.mu.Lock()
	records := b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, retired.CallID, clock.now())
	b.mu.Unlock()
	require.NotEmpty(t, records)
	for _, record := range records {
		require.True(t, record.Key.ReplayRejected)
		require.Equal(t, ^uint64(0), record.Key.ReplayPressureGeneration)
	}
	advanceObservationPressure(t, b, clock)
	r.Upsert(callregistry.Call{CallID: retired.CallID})
	_ = b.Selected(retired)
	_ = b.Selected(answer)
	snapshot, ok := r.EndpointSnapshot(retired.CallID)
	require.True(t, ok)
	require.Empty(t, snapshot.Endpoints)
	// Counter saturation never wraps. Fresh post-window observations still use
	// generation zero and are eligible, without reviving their rejected predecessors.
	_ = submitDerivation(t, b, r, retired)
	_ = submitDerivation(t, b, r, answer)
	retirementOwns(t, r, retired.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
}

func TestReplayObservationHistoryLossPreservesMalformedObligation(t *testing.T) {
	b, r, _, clock := observationFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed, 1, 4096)
	retireObservationPair(t, b, r, "synthetic-first")
	retireObservationPair(t, b, r, "synthetic-overflow")
	malformed, _ := recoveryAtSequence(offer("synthetic-malformed"), "caller", "INVITE", 1)
	malformed.ReliableHeaderEvidence.Conflicts = sip.ReliableHeaderConflicts{CSeq: true}
	malformed.ReliableHeaderEvidence.CSeqBoundsValid = false
	_ = submitDerivation(t, b, r, malformed)
	advanceObservationPressure(t, b, clock)
	fresh, answer := recoveryAtSequence(offer(malformed.CallID), "caller", "INVITE", 2)
	_ = submitDerivation(t, b, r, fresh)
	_ = submitDerivation(t, b, r, answer)
	require.Equal(t, 1, b.Stats().UnknownDerivations, "history loss cannot discharge unbounded malformed evidence")
}

func TestReplayObservationDomainsShareOverflowCapacityWithoutCrossInvalidation(t *testing.T) {
	clock := &replayTestClock{}
	clock.set(time.Now())
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled = true
	cfg.RetryInterval = time.Hour
	cfg.ReplayWindow = time.Second
	cfg.ReplayGuardCapacity = 4
	cfg.InterfaceDomains = map[string]mediaadmission.DomainID{"eth0": 0, "eth1": 1}
	metadata, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	var bridges [2]*Bridge
	var registries [2]*callregistry.Core
	for domain := range 2 {
		controller, err := mediaadmission.NewController(t.Context(), cfg, &backend{keys: make(map[mediaadmission.EndpointKey]bool)})
		require.NoError(t, err)
		registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 64, MaxEndpointAssociations: 256})
		b, err := New(Config{Now: clock.now, Domain: mediaadmission.DomainID(domain), Limits: cfg, Registry: registry, Controller: controller, Metadata: metadata})
		require.NoError(t, err)
		bridges[domain], registries[domain] = b, registry
		t.Cleanup(func() {
			registry.Close()
			require.NoError(t, b.Close())
			require.NoError(t, controller.Close(t.Context()))
		})
	}
	exchange := func(domain int, id string, retire bool) {
		t.Helper()
		request, response := recoveryAtSequence(offer(id), "caller", "INVITE", 1)
		packet := &pipeline.PacketEnvelope{Source: pipeline.SourceProvenance{Kind: pipeline.SourceLiveCapture, InterfaceName: fmt.Sprintf("eth%d", domain)}}
		request.Packet, response.Packet = packet, packet
		_ = submitDerivation(t, bridges[domain], registries[domain], request)
		_ = submitDerivation(t, bridges[domain], registries[domain], response)
		if retire {
			require.True(t, registries[domain].Remove(id, callregistry.EndCompleted))
		}
	}
	exchange(0, "synthetic-domain-zero-first", true)
	exchange(0, "synthetic-domain-zero-second", true)
	exchange(1, "synthetic-domain-one-first", true)
	exchange(0, "synthetic-domain-zero-overflow", true)
	exchange(0, "synthetic-domain-zero-genuine", false)
	exchange(1, "synthetic-domain-one-overflow", true)
	exchange(1, "synthetic-domain-one-genuine", false)
	require.Equal(t, 4, metadata.Stats().ReplayContexts)
	require.Zero(t, bridges[0].proofHistory.invalidThrough)
	require.Equal(t, bridges[1].proofHistory.generation, bridges[1].proofHistory.invalidThrough)
	advanceObservationPressure(t, bridges[0], clock)
	advanceObservationPressure(t, bridges[1], clock)
	require.Zero(t, bridges[0].Stats().UnknownDerivations)
	require.Equal(t, 1, bridges[1].Stats().UnknownDerivations)
	require.NotEmpty(t, registries[0].CallIDsForEndpoint("192.0.2.1:30000"))
	require.Empty(t, registries[1].CallIDsForEndpoint("192.0.2.1:30000"))
	require.Zero(t, metadata.Stats().ReplayContexts)
}

func TestReplayObservationPRACKRetainsReferencedInitiatorRejection(t *testing.T) {
	b, r, _, clock := observationFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed, 4, 4096)
	_, _, prack := reliableSequence("synthetic-retired-reliable")
	retireObservationPair(t, b, r, prack.CallID)
	prack.CSeqNumber = 99
	prack.Headers = map[string]string{"cseq": "99 PRACK", "rack": "101 1 INVITE"}
	require.NoError(t, b.ObserveValidatedReceipt(&prack))
	records := b.cfg.Metadata.Candidates(b.cfg.Domain, b.session, prack.CallID, clock.now())
	require.Len(t, records, 1)
	require.True(t, records[0].Key.ReplayRejected, "RAck sequence, not PRACK's own CSeq, controls replay freshness")
	clock.set(clock.now().Add(b.cfg.Limits.ReplayWindow))
	b.mu.Lock()
	b.expireLifetimeProofLocked(clock.now())
	b.mu.Unlock()
	r.Upsert(callregistry.Call{CallID: prack.CallID})
	_ = b.Selected(prack)
	snapshot, ok := r.EndpointSnapshot(prack.CallID)
	require.True(t, ok)
	require.Empty(t, snapshot.Endpoints)
}
