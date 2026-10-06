//go:build hunter || all

package hunt

import (
	"fmt"
	"github.com/endorses/lippycat/internal/pkg/callregistry"
	"github.com/endorses/lippycat/internal/pkg/capture/admissionintegration"
	"github.com/endorses/lippycat/internal/pkg/mediaadmission"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

// Confirm faulty-PRACK repair retains the original shared pair during the
// role's existing trailing-media grace and valid endpoint reuse cancels cleanup.
func TestHuntRecoveryGraceSharedAttribution(t *testing.T) {
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
						controller, err := mediaadmission.NewController(t.Context(), cfg, &hunterAdmissionMap{entries: make(map[mediaadmission.EndpointKey]struct{})})
						require.NoError(t, err)
						metadata, err := mediaadmission.NewMetadataStore(cfg)
						require.NoError(t, err)
						session := &admissionintegration.Session{Config: cfg, Controller: controller, Metadata: metadata}
						t.Cleanup(func() { require.NoError(t, session.Close()) })
						sink := &retirementForwarder{}
						roleConfig := *voip.DefaultConfig()
						roleConfig.PCAPGracePeriod = time.Hour
						router, err := newAdmissionHunterRouter(t.Context(), sink, session, []string{"example0"}, roleConfig)
						require.NoError(t, err)
						t.Cleanup(func() { require.NoError(t, router.Close()) })
						router.SetApplicationFilter(&admissionMatch{selected: true})
						registry := router.domains[0].tracker.AdmissionRegistry()
						seq := uint32(1)
						send := func(callID, start, tag, branch, cseq, extra, body string) {
							t.Helper()
							raw := retirementMessage(callID, start, tag, branch, cseq, extra, body)
							if transport == "udp" {
								router.ProcessPacket(admissionUDPPacket(t, "example0", raw))
							} else {
								// Feed fragmented bytes into the same reassembly engine used by the router.
								cut := len(raw) / 2
								router.ProcessPacket(retirementTCPPacket(t, seq, raw[:cut]))
								seq += uint32(cut)
								router.ProcessPacket(retirementTCPPacket(t, seq, raw[cut:]))
								seq += uint32(len(raw) - cut)
								require.Eventually(t, func() bool { call, ok := registry.Call(callID); return ok && call.CallID == callID }, time.Second, time.Millisecond)
							}
							// A selected UDP bodyless initial INVITE remains buffered until SDP arrives.
							if transport != "udp" || body != "" || cseq != "1 INVITE" || start != "INVITE sip:peer@example.invalid SIP/2.0" {
								require.Eventually(t, func() bool { return sink.hasSIP(callID, cseq, start) }, time.Second, time.Millisecond)
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
						call, exists := registry.Call("original-call")
						require.True(t, exists)
						exchange("other-call", "INVITE", 1, 10000, 22000)
						check := func() {
							t.Helper()
							packet := retirementRTPPacket(t)
							resolution := registry.ResolveMediaEndpoints("192.0.2.1:10000", "192.0.2.2:20000")
							require.Equal(t, callregistry.MediaResolved, resolution.Status)
							require.Equal(t, "original-call", resolution.CallID)
							require.Equal(t, call.Lifetime, resolution.Lifetime)
							before := sink.mediaCount()
							router.ProcessPacket(packet)
							require.Eventually(t, func() bool { return sink.mediaCount() > before }, time.Second, time.Millisecond)
							require.Equal(t, "original-call", sink.lastMediaCall())
							direct, inherited := sink.lastMediaProvenance()
							require.Empty(t, direct)
							require.Equal(t, []string{"selected"}, inherited)
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
