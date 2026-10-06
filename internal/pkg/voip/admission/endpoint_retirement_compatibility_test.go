package admission

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/stretchr/testify/require"
)

func retirementFixture(t *testing.T, mode mediaadmission.Mode, policy mediaadmission.FailurePolicy) (*Bridge, *callregistry.Core, *mediaadmission.Controller) {
	t.Helper()
	cfg := mediaadmission.DefaultConfig()
	cfg.Enabled, cfg.Mode, cfg.FailurePolicy, cfg.RetryInterval = true, mode, policy, time.Hour
	maps := &backend{keys: make(map[mediaadmission.EndpointKey]bool)}
	controller, err := mediaadmission.NewController(context.Background(), cfg, maps)
	require.NoError(t, err)
	store, err := mediaadmission.NewMetadataStore(cfg)
	require.NoError(t, err)
	registry := callregistry.New(callregistry.Config{MaxCalls: 10, MaxEndpointsPerCall: 64, MaxEndpointAssociations: 256})
	bridge, err := New(Config{Limits: cfg, Registry: registry, Controller: controller, Metadata: store})
	require.NoError(t, err)
	t.Cleanup(func() {
		registry.Close()
		require.NoError(t, bridge.Close())
		require.NoError(t, controller.Close(context.Background()))
	})
	return bridge, registry, controller
}

func retirementHealthyCall(t *testing.T, bridge *Bridge, registry *callregistry.Core, kind string) pipeline.SIPResult {
	t.Helper()
	invite := offer("healthy-" + kind)
	invite.Headers = map[string]string{"cseq": "1 INVITE"}
	if kind == "reliable-prack" {
		request, response, prack := reliableSequence(invite.CallID)
		_ = submitDerivation(t, bridge, registry, request)
		_ = submitDerivation(t, bridge, registry, response)
		require.NoError(t, submitDerivation(t, bridge, registry, prack))
		establishFaultyReliable(t, bridge, registry, response, request, false)
		invite = request
	} else {
		if kind == "delayed-ack" {
			invite.SDP = nil
		}
		_ = submitDerivation(t, bridge, registry, invite)
		answer := invite
		answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
		answer.SDP = derivationSDP("192.0.2.2", 20000, false)
		_ = submitDerivation(t, bridge, registry, answer)
		if kind == "delayed-ack" {
			ack := invite
			ack.Method, ack.CSeqMethod, ack.ToTag, ack.ViaBranch = "ACK", "ACK", "to", "ack-branch"
			ack.Headers = map[string]string{"cseq": "1 ACK"}
			ack.SDP = derivationSDP("192.0.2.1", 10000, false)
			require.NoError(t, submitDerivation(t, bridge, registry, ack))
		}
	}
	require.Zero(t, bridge.Stats().UnknownDerivations)
	retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
	return invite
}

func retirementExchange(t *testing.T, bridge *Bridge, registry *callregistry.Core, invite pipeline.SIPResult, method string, cseq uint64, callerPort, peerPort int) {
	t.Helper()
	request, answer := reliableReplacement(invite, method)
	request.CSeqNumber, answer.CSeqNumber = cseq, cseq
	request.ViaBranch, answer.ViaBranch = fmt.Sprintf("replacement-%d", cseq), fmt.Sprintf("replacement-%d", cseq)
	request.Headers, answer.Headers = map[string]string{"cseq": fmt.Sprintf("%d %s", cseq, method)}, map[string]string{"cseq": fmt.Sprintf("%d %s", cseq, method)}
	request.SDP, answer.SDP = derivationSDP("192.0.2.1", callerPort, false), derivationSDP("192.0.2.2", peerPort, false)
	require.NoError(t, submitDerivation(t, bridge, registry, request))
	require.NoError(t, submitDerivation(t, bridge, registry, answer))
}

func retirementOwns(t *testing.T, registry *callregistry.Core, callID string, endpoints ...string) {
	t.Helper()
	snapshot, exists := registry.EndpointSnapshot(callID)
	require.True(t, exists)
	for _, endpoint := range endpoints {
		require.Contains(t, snapshot.Endpoints, endpoint, "historical ownership of %s", callID)
		resolved := registry.ResolveMediaEndpoints(endpoint, "")
		require.Equal(t, callID, resolved.CallID)
		require.Equal(t, snapshot.Call.Lifetime, resolved.Lifetime)
	}
}

func TestHealthyNegotiationRetainsHistoricalEndpointOwnership(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, kind := range []string{"invite-answer", "reliable-prack", "delayed-ack"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, kind), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					invite := retirementHealthyCall(t, bridge, registry, kind)
					retirementExchange(t, bridge, registry, invite, "INVITE", 3, 30000, 40000)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:30000", "192.0.2.2:40000")
					retirementExchange(t, bridge, registry, invite, "UPDATE", 4, 50000, 60000)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:30000", "192.0.2.2:40000", "192.0.2.1:50000", "192.0.2.2:60000")
					retirementExchange(t, bridge, registry, invite, "INVITE", 5, 10000, 20000)
					require.Zero(t, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000", "192.0.2.1:50000", "192.0.2.2:60000")
				})
			}
		}
	}
}

func TestHealthyHoldResumeRetainsHistoricalEndpointOwnership(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, hold := range []string{"inactive", "disabled"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, hold), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					invite := retirementHealthyCall(t, bridge, registry, "invite-answer")
					before, _ := registry.EndpointSnapshot(invite.CallID)
					request, answer := reliableReplacement(invite, "INVITE")
					if hold == "inactive" {
						request.SDP = append(derivationSDP("192.0.2.1", 30000, false), []byte("a=inactive\r\n")...)
						answer.SDP = append(derivationSDP("192.0.2.2", 40000, false), []byte("a=inactive\r\n")...)
					} else {
						request.SDP, answer.SDP = derivationSDP("192.0.2.1", 0, false), derivationSDP("192.0.2.2", 0, false)
					}
					require.NoError(t, submitDerivation(t, bridge, registry, request))
					require.NoError(t, submitDerivation(t, bridge, registry, answer))
					after, _ := registry.EndpointSnapshot(invite.CallID)
					require.Equal(t, before.Endpoints, after.Endpoints, "hold must neither erase attribution nor contribute endpoints")
					retirementExchange(t, bridge, registry, invite, "UPDATE", 4, 50000, 60000)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:50000", "192.0.2.2:60000")
				})
			}
		}
	}
}

func TestFaultyRecoveryRetirementRespectsModeAndDoesNotLeakEligibility(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, fault := range []string{"mismatched-rack", "unreliable-provisional", "partial-prack", "bodyless-prack-ack-answer"} {
				for _, method := range []string{"INVITE", "UPDATE"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", mode, policy, fault, method), func(t *testing.T) {
						bridge, registry, _ := retirementFixture(t, mode, policy)
						invite, response, prack := faultyReliableSequence("faulty-recovery", fault)
						_ = submitDerivation(t, bridge, registry, invite)
						_ = submitDerivation(t, bridge, registry, response)
						_ = submitDerivation(t, bridge, registry, prack)
						establishFaultyReliable(t, bridge, registry, response, invite, fault == "bodyless-prack-ack-answer")
						prior, _ := registry.EndpointSnapshot(invite.CallID)
						require.NotEmpty(t, prior.Endpoints)
						require.Equal(t, 1, bridge.Stats().UnknownDerivations)
						request, answer := reliableReplacement(invite, method)
						_ = submitDerivation(t, bridge, registry, request)
						require.NoError(t, submitDerivation(t, bridge, registry, answer))
						require.Zero(t, bridge.Stats().UnknownDerivations)
						if mode == mediaadmission.ModeShadow {
							retirementOwns(t, registry, invite.CallID, prior.Endpoints...)
						} else {
							for _, endpoint := range prior.Endpoints {
								require.Empty(t, registry.ResolveMediaEndpoints(endpoint, "").CallID)
							}
						}
						retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000")
						retirementExchange(t, bridge, registry, invite, "UPDATE", 4, 50000, 60000)
						retirementOwns(t, registry, invite.CallID, "192.0.2.1:30000", "192.0.2.2:40000", "192.0.2.1:50000", "192.0.2.2:60000")
					})
				}
			}
		}
	}
}

func TestCalleeReofferDoesNotRepairCallerPRACKUncertainty(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		t.Run(string(policy), func(t *testing.T) {
			bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
			invite, response, prack := faultyReliableSequence("callee-limitation", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			establishFaultyReliable(t, bridge, registry, response, invite, false)
			request, answer := reliableReplacement(invite, "INVITE")
			request.FromTag, request.ToTag, answer.FromTag, answer.ToTag = "to", "from", "to", "from"
			_ = submitDerivation(t, bridge, registry, request)
			_ = submitDerivation(t, bridge, registry, answer)
			assertDerivationState(t, bridge, controller, policy, true)
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000")
		})
	}
}

func TestDuplicateCSeqOrdinaryNegotiationUncertaintyPersists(t *testing.T) {
	for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
		for _, duplicate := range []string{"identical", "conflicting"} {
			for _, location := range []string{"request", "response"} {
				t.Run(fmt.Sprintf("%s/%s/%s", policy, duplicate, location), func(t *testing.T) {
					bridge, registry, controller := retirementFixture(t, mediaadmission.ModeEnforce, policy)
					invite := offer("duplicate-cseq")
					invite.Headers = map[string]string{"cseq": "1 INVITE"}
					answer := invite
					answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
					answer.SDP = derivationSDP("192.0.2.2", 20000, false)
					target := &invite
					if location == "response" {
						target = &answer
					}
					// Parse wire duplicates so identical/conflicting values exercise the same
					// parser-to-proof contract as actual packet input.
					first := "1 INVITE"
					if duplicate == "conflicting" {
						first = "9 UPDATE"
					}
					wire := fmt.Sprintf("INVITE sip:service@example.test SIP/2.0\r\nCall-ID: duplicate-cseq\r\nCSeq: %s\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n", first)
					parsed, err := sip.Parse([]byte(wire), sip.ParseOptions{})
					require.NoError(t, err)
					target.Headers, target.DuplicateReliableHeaders = parsed.Headers, parsed.DuplicateReliableHeaders
					require.Equal(t, uint64(1), parsed.CSeqNumber)
					require.Equal(t, "INVITE", parsed.CSeqMethod)
					_ = submitDerivation(t, bridge, registry, invite)
					_ = submitDerivation(t, bridge, registry, answer)
					assertDerivationState(t, bridge, controller, policy, true)
					request, response := reliableReplacement(invite, "INVITE")
					request.DuplicateReliableHeaders, response.DuplicateReliableHeaders = sip.ReliableHeaderDuplicates{}, sip.ReliableHeaderDuplicates{}
					_ = submitDerivation(t, bridge, registry, request)
					_ = submitDerivation(t, bridge, registry, response)
					assertDerivationState(t, bridge, controller, policy, true)
				})
			}
		}
	}
}

func TestFaultyRecoveryRetirementPreservesIndependentDialogHistory(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, shared := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/shared-%v", mode, shared), func(t *testing.T) {
				bridge, registry, _ := retirementFixture(t, mode, mediaadmission.FailureClosed)
				invite, response, prack := faultyReliableSequence("independent-provenance", "partial-prack")
				independent := offer(invite.CallID)
				independent.FromTag, independent.ToTag, independent.ViaBranch = "other-caller", "other-peer", "other-initial"
				independent.SDP = derivationSDP("192.0.2.8", 11000, false)
				if shared {
					independent.SDP = derivationSDP("192.0.2.1", 10000, false)
				}
				answer := independent
				answer.Method, answer.ResponseCode = "RESPONSE", 200
				answer.SDP = derivationSDP("192.0.2.9", 21000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, independent))
				require.NoError(t, submitDerivation(t, bridge, registry, answer))
				update, updated := reliableReplacement(independent, "UPDATE")
				update.FromTag, update.ToTag, updated.FromTag, updated.ToTag = independent.FromTag, independent.ToTag, independent.FromTag, independent.ToTag
				update.SDP, updated.SDP = derivationSDP("192.0.2.8", 31000, false), derivationSDP("192.0.2.9", 41000, false)
				require.NoError(t, submitDerivation(t, bridge, registry, update))
				require.NoError(t, submitDerivation(t, bridge, registry, updated))
				// The old endpoint pair now belongs to healthy historical attribution,
				// independently of the faulty dialog being repaired below.
				historical, _ := registry.EndpointSnapshot(invite.CallID)
				require.Len(t, historical.Endpoints, 8)
				_ = submitDerivation(t, bridge, registry, invite)
				_ = submitDerivation(t, bridge, registry, response)
				_ = submitDerivation(t, bridge, registry, prack)
				establishFaultyReliable(t, bridge, registry, response, invite, false)
				request, replacement := reliableReplacement(invite, "INVITE")
				_ = submitDerivation(t, bridge, registry, request)
				require.NoError(t, submitDerivation(t, bridge, registry, replacement))
				require.Zero(t, bridge.Stats().UnknownDerivations)
				retirementOwns(t, registry, invite.CallID, historical.Endpoints...)
				snapshot, _ := registry.EndpointSnapshot(invite.CallID)
				if mode == mediaadmission.ModeEnforce {
					require.NotContains(t, snapshot.Endpoints, "192.0.2.2:20000")
					if !shared {
						require.NotContains(t, snapshot.Endpoints, "192.0.2.1:10000")
					}
				}
			})
		}
	}
}

func TestChainedPartialFaultyRecoveryReleasesBoundedProvenance(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		t.Run(string(mode), func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mode, mediaadmission.FailureClosed)
			invite, response, prack := faultyReliableSequence("chained-provenance", "partial-prack")
			_ = submitDerivation(t, bridge, registry, invite)
			_ = submitDerivation(t, bridge, registry, response)
			_ = submitDerivation(t, bridge, registry, prack)
			establishFaultyReliable(t, bridge, registry, response, invite, false)
			request, answer := reliableReplacement(invite, "INVITE")
			request.SDP = derivationSDP("192.0.2.1", 30000, true)
			_ = submitDerivation(t, bridge, registry, request)
			_ = submitDerivation(t, bridge, registry, answer)
			require.Equal(t, 1, bridge.Stats().UnknownDerivations)
			partial, _ := registry.EndpointSnapshot(invite.CallID)
			require.Len(t, partial.Endpoints, 8, "retirement must wait for complete replacement")
			before := bridge.cfg.Metadata.Stats()
			request, answer = reliableReplacement(invite, "UPDATE")
			request.CSeqNumber, answer.CSeqNumber = 4, 4
			request.ViaBranch, answer.ViaBranch = "confirmed-later", "confirmed-later"
			request.Headers, answer.Headers = map[string]string{"cseq": "4 UPDATE"}, map[string]string{"cseq": "4 UPDATE"}
			request.SDP, answer.SDP = derivationSDP("192.0.2.1", 50000, false), derivationSDP("192.0.2.2", 60000, false)
			_ = submitDerivation(t, bridge, registry, request)
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			require.Zero(t, bridge.Stats().UnknownDerivations)
			after := bridge.cfg.Metadata.Stats()
			require.Less(t, after.SelectedBytes, before.SelectedBytes, "supersession must release charged faulty proof/provenance")
			if mode == mediaadmission.ModeShadow {
				retirementOwns(t, registry, invite.CallID, partial.Endpoints...)
			} else {
				for _, endpoint := range partial.Endpoints {
					require.Empty(t, registry.ResolveMediaEndpoints(endpoint, "").CallID)
				}
			}
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:50000", "192.0.2.2:60000")
			registry.Close()
			require.NoError(t, bridge.Close())
			retired := bridge.cfg.Metadata.Stats()
			require.Zero(t, retired.SelectedContexts)
			require.Zero(t, retired.SelectedBytes)
			require.Zero(t, retired.SelectedEndpoints)
		})
	}
}

func TestOrdinaryPartialSDPRecoveryDoesNotAuthorizeRetirement(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			t.Run(fmt.Sprintf("%s/%s", mode, policy), func(t *testing.T) {
				bridge, registry, _ := retirementFixture(t, mode, policy)
				invite := offer("ordinary-partial")
				invite.Headers = map[string]string{"cseq": "1 INVITE"}
				invite.SDP = derivationSDP("192.0.2.1", 10000, true)
				_ = submitDerivation(t, bridge, registry, invite)
				answer := invite
				answer.Method, answer.ResponseCode, answer.ToTag = "RESPONSE", 200, "to"
				answer.SDP = derivationSDP("192.0.2.2", 20000, false)
				_ = submitDerivation(t, bridge, registry, answer)
				require.Equal(t, 1, bridge.Stats().UnknownDerivations)
				request, replacement := reliableReplacement(invite, "INVITE")
				_ = submitDerivation(t, bridge, registry, request)
				require.NoError(t, submitDerivation(t, bridge, registry, replacement))
				require.Zero(t, bridge.Stats().UnknownDerivations)
				retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:30000", "192.0.2.2:40000")
			})
		}
	}
}

func TestLaterFaultyPRACKRecoveryPreservesEarlierHealthyDialogEndpoints(t *testing.T) {
	for _, kind := range []string{"invite-answer", "reliable-prack", "delayed-ack"} {
		t.Run(kind, func(t *testing.T) {
			bridge, registry, _ := retirementFixture(t, mediaadmission.ModeEnforce, mediaadmission.FailureClosed)
			invite := retirementHealthyCall(t, bridge, registry, kind)
			// Advance once through a healthy exchange to move prior endpoints from
			// current proof into historical attribution, including the PRACK answer.
			retirementExchange(t, bridge, registry, invite, "INVITE", 3, 30000, 40000)
			faulty, provisional, prack := faultyReliableSequence(invite.CallID, "partial-prack")
			faulty.CSeqNumber, faulty.ToTag, faulty.ViaBranch = 5, "to", "later-fault"
			faulty.Headers = map[string]string{"cseq": "5 INVITE", "supported": "100rel"}
			provisional.CSeqNumber, provisional.ViaBranch = 5, "later-fault"
			provisional.Headers = map[string]string{"cseq": "5 INVITE", "require": "100rel", "rseq": "101"}
			provisional.SDP = derivationSDP("192.0.2.2", 20000, false)
			prack.CSeqNumber = 6
			prack.Headers = map[string]string{"cseq": "6 PRACK", "rack": "101 5 INVITE"}
			// The faulty episode reuses endpoints of the earlier healthy negotiation.
			_ = submitDerivation(t, bridge, registry, faulty)
			_ = submitDerivation(t, bridge, registry, provisional)
			_ = submitDerivation(t, bridge, registry, prack)
			final := provisional
			final.ResponseCode, final.SDP = 200, nil
			final.Headers = map[string]string{"cseq": "5 INVITE"}
			_ = submitDerivation(t, bridge, registry, final)
			require.Equal(t, 1, bridge.Stats().UnknownDerivations)
			request, answer := reliableReplacement(invite, "INVITE")
			request.CSeqNumber, answer.CSeqNumber = 7, 7
			request.Headers, answer.Headers = map[string]string{"cseq": "7 INVITE"}, map[string]string{"cseq": "7 INVITE"}
			request.SDP, answer.SDP = derivationSDP("192.0.2.1", 50000, false), derivationSDP("192.0.2.2", 60000, false)
			_ = submitDerivation(t, bridge, registry, request)
			require.NoError(t, submitDerivation(t, bridge, registry, answer))
			require.Zero(t, bridge.Stats().UnknownDerivations)
			retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.2:20000", "192.0.2.1:30000", "192.0.2.2:40000", "192.0.2.1:50000", "192.0.2.2:60000")
		})
	}
}

func TestHealthyPRACKResponseFirstReplacementPreservesOwnership(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, method := range []string{"INVITE", "UPDATE"} {
				t.Run(fmt.Sprintf("%s/%s/%s", mode, policy, method), func(t *testing.T) {
					bridge, registry, _ := retirementFixture(t, mode, policy)
					invite := retirementHealthyCall(t, bridge, registry, "reliable-prack")
					request, answer := reliableReplacement(invite, method)
					_ = submitDerivation(t, bridge, registry, answer)
					require.NoError(t, submitDerivation(t, bridge, registry, request))
					require.Zero(t, bridge.Stats().UnknownDerivations)
					retirementOwns(t, registry, invite.CallID, "192.0.2.1:10000", "192.0.2.1:10001", "192.0.2.2:20000", "192.0.2.2:20001")
				})
			}
		}
	}
}
