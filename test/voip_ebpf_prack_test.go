//go:build linux && all

package test

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// Transport selection covers UDP and framed TCP in each role and policy across
// four process fixtures. Derivation tests separately cover the full policy and
// parser matrix; transport does not change the socket's RTP failure policy.
func TestVoIPEBPFCommandReliableProvisionalAnswer(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf for privileged command tests")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		for _, policy := range []string{"open", "closed"} {
			transport := "UDP"
			if (topology == "tap" && policy == "closed") || (topology == "hunter" && policy == "open") {
				transport = "TCP"
			}
			t.Run(topology+"/"+policy+"/"+transport, func(t *testing.T) {
				settings := fmt.Sprintf("%s:\n  voip:\n    rtp_ebpf:\n      failure_policy: %s\n", topology, policy)
				f := newAdmissionCommandFixture(t, binary, topology, "enforce", settings, "--filter", "(udp or tcp) and not port 53")
				t.Cleanup(func() {
					if t.Failed() {
						t.Logf("last admission scope: %v", f.snapshot())
					}
				})
				sendSIP := func(payload []byte) error {
					if transport == "TCP" {
						return f.tcpSender(5062, 5060, payload)
					}
					return f.sender(5060, 5060, payload)
				}
				callID := "reliable-selected-call"
				invite := admissionReliableTransaction(callID, transport, 0, "INVITE", 1, "invite", "", "Supported: 100rel\r\n", "", "")
				require.Eventually(t, func() bool {
					require.NoError(t, sendSIP(invite))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.Owners == 1 && s.InstalledEndpoints == 0
				}, 20*time.Second, 100*time.Millisecond, "selected bodyless INVITE retains missing-answer uncertainty")

				offer := admissionReliableTransaction(callID, transport, 183, "INVITE", 1, "invite", "destination", "Require: 100rel\r\nRSeq: 101\r\n", "192.0.2.2", "m=audio 42002 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, sendSIP(offer))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.InstalledEndpoints == 2 && s.PendingUpdates > 0
				}, 20*time.Second, 100*time.Millisecond, "reliable provisional offer learns safe endpoints while unresolved desired state remains pending")

				// A mismatched, bodyless PRACK is selected signaling, but supplies
				// neither matching proof nor an answer. SDP-bearing mismatches are
				// separately tested as unresolved contexts, not erased by a later
				// unrelated PRACK transaction in this successful command scenario.
				wrong := admissionReliableTransaction(callID, transport, 0, "PRACK", 2, "wrong-prack", "destination", "RAck: 102 1 INVITE\r\n", "", "")
				require.Eventually(t, func() bool {
					require.NoError(t, sendSIP(wrong))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.InstalledEndpoints == 2 && bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("RAck: 102 1 INVITE"))
				}, 20*time.Second, 100*time.Millisecond, "mismatched PRACK does not restore enforcement")

				before := f.snapshot()
				require.NotNil(t, before)
				require.Len(t, before.DecisionCounters, 16)
				unknownReason, knownReason := 0, 1
				if policy == "open" {
					unknownReason, knownReason = 10, 10
				}
				// Neither endpoint matches the observed offer. Open reception is
				// therefore evidence of uncertainty, not hidden either-endpoint
				// admission through the independently safe SDP endpoint.
				require.NoError(t, f.sender(44000, 44002, admissionNegotiationRTP("PRACK-MISSING-ANSWER")))
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("PRACK-SAFE-OFFER")))
				require.NoError(t, f.sender(46000, 46002, admissionNegotiationRTP("PRACK-UNSELECTED")))
				require.NoError(t, f.sender(47000, 53, admissionNegotiationRTP("PRACK-RESTRICTED")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && len(s.DecisionCounters) == 16 && s.State == "degraded-"+policy && s.DecisionCounters[unknownReason] > before.DecisionCounters[unknownReason] && s.DecisionCounters[knownReason] > before.DecisionCounters[knownReason] && s.DecisionCounters[12] > before.DecisionCounters[12]
				}, 20*time.Second, 100*time.Millisecond, "kernel policy receives unknown media only under open and preserves explicit capture restrictions")
				require.Eventually(t, func() bool {
					return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("PRACK-SAFE-OFFER"))
				}, 15*time.Second, 100*time.Millisecond, "validated provisional-offer endpoint remains authorized before recovery")

				// PRACK answers the exact RSeq/CSeq tuple while using its own CSeq
				// and Via branch. Its source endpoint differs from the offer's.
				answer := admissionReliableTransaction(callID, transport, 0, "PRACK", 3, "answer-prack", "destination", "RAck: 101 1 INVITE\r\n", "192.0.2.1", "m=audio 43000 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, sendSIP(answer))
					s := f.snapshot()
					return s != nil && s.State == "enforcing" && s.Recoveries > 0 && s.Owners == 1 && s.InstalledEndpoints == 4 && s.PendingUpdates == 0 && s.InstalledGeneration == s.DesiredGeneration
				}, 20*time.Second, 100*time.Millisecond, "matching complete PRACK answer reconciles the current-lifetime registry snapshot")

				final := admissionReliableTransaction(callID, transport, 200, "INVITE", 1, "invite", "destination", "", "", "")
				ack := admissionReliableTransaction(callID, transport, 0, "ACK", 1, "final-ack", "destination", "", "", "")
				require.Eventually(t, func() bool {
					require.NoError(t, sendSIP(final))
					require.NoError(t, sendSIP(ack))
					s := f.snapshot()
					captured := readAdmissionPCAPs(t, f.out)
					return s != nil && s.State == "enforcing" && s.InstalledEndpoints == 4 && bytes.Contains(captured, []byte("SIP/2.0 200 OK")) && bytes.Contains(captured, []byte("CSeq: 1 ACK"))
				}, 20*time.Second, 100*time.Millisecond, "bodyless final response and ACK preserve the validated PRACK answer")

				recovered := f.snapshot()
				require.NotNil(t, recovered)
				require.Len(t, recovered.DecisionCounters, 16)
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("PRACK-RETAINED-OFFER")))
				require.NoError(t, f.sender(43000, 45002, admissionNegotiationRTP("PRACK-ANSWER-MEDIA")))
				require.NoError(t, f.sender(46000, 46002, admissionNegotiationRTP("PRACK-AFTER-UNSELECTED")))
				require.NoError(t, f.sender(47000, 53, admissionNegotiationRTP("PRACK-AFTER-RESTRICTED")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && len(s.DecisionCounters) == 16 && s.State == "enforcing" && s.DecisionCounters[1] >= recovered.DecisionCounters[1]+2 && s.DecisionCounters[0] > recovered.DecisionCounters[0] && s.DecisionCounters[12] > recovered.DecisionCounters[12]
				}, 20*time.Second, 100*time.Millisecond, "recovered kernel admits both proven sides and rejects unrelated or explicitly restricted media")
				require.Eventually(t, func() bool {
					captured := readAdmissionPCAPs(t, f.out)
					return bytes.Contains(captured, []byte("PRACK-RETAINED-OFFER")) && bytes.Contains(captured, []byte("PRACK-ANSWER-MEDIA"))
				}, 15*time.Second, 100*time.Millisecond, "both exact selected media endpoints reach userspace output")
				f.stop()
				captured := string(readAdmissionPCAPs(t, f.out))
				require.NotContains(t, captured, "PRACK-MISSING-ANSWER", "kernel reception never grants userspace endpoint authority")
				for _, marker := range []string{"PRACK-UNSELECTED", "PRACK-RESTRICTED", "PRACK-AFTER-UNSELECTED", "PRACK-AFTER-RESTRICTED"} {
					require.NotContains(t, captured, marker)
				}
			})
		}
	}
}

func admissionReliableTransaction(callID, transport string, status int, method string, cseq uint64, branch, toTag, headers, address, media string) []byte {
	message := string(admissionNegotiationTransaction(callID, status, method, cseq, branch, toTag, address, media))
	message = strings.Replace(message, "SIP/2.0/UDP", "SIP/2.0/"+transport, 1)
	if status == 183 {
		message = strings.Replace(message, method+" sip:receiver@example.test SIP/2.0", "SIP/2.0 183 Session Progress", 1)
	}
	return []byte(strings.Replace(message, "Content-Length:", headers+"Content-Length:", 1))
}
