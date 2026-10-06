//go:build tap || all

package tap

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	voipprocessor "github.com/endorses/lippycat/internal/pkg/voip/processor"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Confirm faulty-PRACK repair retains the original shared pair during the
// role's existing trailing-media grace and valid endpoint reuse cancels cleanup.
func TestTapRecoveryGraceSharedAttribution(t *testing.T) {
	for _, mode := range []mediaadmission.Mode{mediaadmission.ModeEnforce, mediaadmission.ModeShadow} {
		for _, policy := range []mediaadmission.FailurePolicy{mediaadmission.FailureOpen, mediaadmission.FailureClosed} {
			for _, transport := range []string{"udp", "tcp"} {
				for _, method := range []string{"INVITE", "UPDATE"} {
					t.Run(fmt.Sprintf("%s/%s/%s/%s", mode, policy, transport, method), func(t *testing.T) {
						cfg := mediaadmission.DefaultConfig()
						cfg.Enabled = true
						cfg.Mode = mode
						cfg.FailurePolicy = policy
						cfg.RetryInterval = time.Hour
						controller, err := mediaadmission.NewController(t.Context(), cfg, &tapAdmissionMaps{keys: make(map[mediaadmission.EndpointKey]bool)})
						require.NoError(t, err)
						metadata, err := mediaadmission.NewMetadataStore(cfg)
						require.NoError(t, err)
						session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
						t.Cleanup(func() { require.NoError(t, session.Close()) })
						pc := voipprocessor.DefaultConfig()
						pc.ApplicationFilter = tapAdmissionFilter{}
						routing, err := newTapVoIPRouting(pc, *voip.DefaultConfig(), 1, session, time.Hour, []string{"example0"})
						require.NoError(t, err)
						t.Cleanup(routing.Close)
						registry := routing.children[0]
						seq := uint32(1)
						send := func(callID, start, tag, branch, cseq, extra, body string) {
							t.Helper()
							raw := retirementMessage(callID, start, tag, branch, cseq, extra, body)
							if transport == "udp" {
								require.NotNil(t, routing.adapter.ProcessPacketInfo(tapAdmissionPacket(t, "example0", raw, false)))
							} else {
								cut := len(raw) / 2
								require.True(t, routing.AssemblePacket(tapTCPPacket(t, "example0", seq, raw[:cut], time.Now())))
								seq += uint32(cut)
								require.True(t, routing.AssemblePacket(tapTCPPacket(t, "example0", seq, raw[cut:], time.Now())))
								seq += uint32(len(raw) - cut)
								select {
								case result := <-routing.injection:
									require.Equal(t, callID, result.Metadata.GetSip().GetCallId())
									require.NotZero(t, result.CallLifetime.Session)
								case <-time.After(time.Second):
									t.Fatal("fragmented TCP message missing")
								}
							}
						}
						exchange := func(callID, method string, number, caller, peer int) {
							tag := "peer"
							if number == 1 {
								tag = ""
							}
							branch := fmt.Sprintf("z9hG4bK-%s-%d", callID, number)
							send(callID, method+" sip:peer@example.invalid SIP/2.0", tag, branch, fmt.Sprintf("%d %s", number, method), "", retirementSDP("192.0.2.1", caller))
							send(callID, "SIP/2.0 200 OK", "peer", branch, fmt.Sprintf("%d %s", number, method), "", retirementSDP("192.0.2.2", peer))
						}
						send("original-call", "INVITE sip:peer@example.invalid SIP/2.0", "", "z9hG4bK-initial", "1 INVITE", "Supported: 100rel\r\n", "")
						send("original-call", "SIP/2.0 183 Progress", "peer", "z9hG4bK-initial", "1 INVITE", "Require: 100rel\r\nRSeq: 101\r\n", retirementSDP("192.0.2.2", 20000))
						rack := "RAck: 102 1 INVITE\r\n"
						send("original-call", "PRACK sip:peer@example.invalid SIP/2.0", "peer", "z9hG4bK-prack", "2 PRACK", rack, retirementSDP("192.0.2.1", 10000))
						send("original-call", "SIP/2.0 200 OK", "peer", "z9hG4bK-initial", "1 INVITE", "", "")
						var call callregistry.Call
						for _, candidate := range registry.ActiveCalls() {
							if candidate.CallID == "original-call" {
								call = candidate
							}
						}
						require.Equal(t, "original-call", call.CallID)
						exchange("other-call", "INVITE", 1, 10000, 22000)
						check := func() {
							t.Helper()
							result := routing.adapter.ProcessPacketInfo(retirementRTPPacket(t))
							require.NotNil(t, result)
							require.Equal(t, callregistry.MediaResolved, result.GetMediaResolution().Status)
							require.Equal(t, "original-call", result.GetCallID())
							require.Equal(t, call.Lifetime, result.GetCallLifetime())
							require.Equal(t, "original-call", result.GetMetadata().GetSip().GetCallId())
						}
						check()
						caller, peer := 30000, 40000
						exchange("original-call", method, 3, caller, peer)
						check()
						exchange("original-call", method, 4, 10000, 20000)
						check()
					})
				}
			}
		}
	}
}
