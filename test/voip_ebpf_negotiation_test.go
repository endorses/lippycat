//go:build linux && all

package test

import (
	"bytes"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// A complete answer describes the responder's media. It cannot repair the
// offerer's unresolved section, even when both messages select the same call.
func TestVoIPEBPFCommandNegotiationRecovery(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf for privileged command tests")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		for _, policy := range []string{"open", "closed"} {
			t.Run(topology+"/"+policy, func(t *testing.T) {
				settings := fmt.Sprintf("%s:\n  voip:\n    rtp_ebpf:\n      failure_policy: %s\n", topology, policy)
				f := newAdmissionCommandFixture(t, binary, topology, "enforce", settings)
				callID := "negotiation-selected-call"
				partial := admissionNegotiationSIP(callID, false, 1, "offer", "", "192.0.2.2", "m=audio 42002 RTP/AVP 0\r\nm=audio invalid RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, partial))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.Owners == 1 && s.InstalledEndpoints == 2
				}, 20*time.Second, 100*time.Millisecond, "partial selected offer installs its safe endpoints while applying the configured uncertainty policy")

				// The response advertises the source endpoint of answer-side media.
				// The unknown-offer probe below deliberately uses a different source,
				// so either-endpoint matching cannot hide the unresolved offer.
				answer := admissionNegotiationSIP(callID, true, 1, "offer", "destination", "192.0.2.1", "m=audio 43000 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, answer))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.Owners == 1 && s.InstalledEndpoints == 4
				}, 20*time.Second, 100*time.Millisecond, "complete opposite-side answer learns safe media without clearing offer uncertainty")
				before := f.snapshot()
				require.NotNil(t, before)
				require.Len(t, before.DecisionCounters, 16)
				unknownReason := 0
				if policy == "open" {
					unknownReason = 10
				}
				require.NoError(t, f.sender(44000, 44002, admissionNegotiationRTP("NEGOTIATION-UNKNOWN-OFFER")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && len(s.DecisionCounters) == 16 && s.State == "degraded-"+policy && s.DecisionCounters[unknownReason] > before.DecisionCounters[unknownReason]
				}, 20*time.Second, 100*time.Millisecond, "unknown offer media is received broadly only under open policy and rejected under closed policy")

				before = f.snapshot()
				require.NotNil(t, before)
				require.Len(t, before.DecisionCounters, 16)
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("NEGOTIATION-SAFE-OFFER")))
				require.NoError(t, f.sender(43000, 45002, admissionNegotiationRTP("NEGOTIATION-SAFE-ANSWER")))
				require.NoError(t, f.sender(46000, 46002, admissionNegotiationRTP("NEGOTIATION-UNSELECTED")))
				require.NoError(t, f.sender(47000, 53, admissionNegotiationRTP("NEGOTIATION-RESTRICTED")))
				knownReason := 1
				if policy == "open" {
					knownReason = 10
				}
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && len(s.DecisionCounters) == 16 && s.DecisionCounters[knownReason] >= before.DecisionCounters[knownReason]+2 && s.DecisionCounters[12] > before.DecisionCounters[12]
				}, 20*time.Second, 100*time.Millisecond, "safe endpoints remain receivable and uncertainty preserves the explicit capture predicate")
				require.Eventually(t, func() bool {
					captured := readAdmissionPCAPs(t, f.out)
					return bytes.Contains(captured, []byte("NEGOTIATION-SAFE-OFFER")) && bytes.Contains(captured, []byte("NEGOTIATION-SAFE-ANSWER"))
				}, 15*time.Second, 100*time.Millisecond, "both independently safe signaling sides remain authorized for userspace output")

				// SDP carried by INFO does not negotiate replacement media. Its
				// higher sequence number cannot repair the unresolved INVITE offer.
				info := admissionNegotiationTransaction(callID, 0, "INFO", 2, "info", "destination", "192.0.2.2", "m=audio 42002 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, info))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.InstalledEndpoints == 4 && bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("CSeq: 2 INFO"))
				}, 20*time.Second, 100*time.Millisecond, "selected INFO reaches output without repairing the outstanding media negotiation")
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("NEGOTIATION-AFTER-INFO-SAFE")))
				require.Eventually(t, func() bool {
					return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("NEGOTIATION-AFTER-INFO-SAFE"))
				}, 15*time.Second, 100*time.Millisecond, "independently safe selected media survives the unrelated SDP update")

				// A complete request adds safe endpoints but cannot supersede the
				// partial negotiation until its complete matching answer is confirmed.
				temporary := admissionNegotiationSIP(callID, false, 3, "temporary", "destination", "192.0.2.2", "m=audio 42002 RTP/AVP 0\r\nm=audio 44002 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, temporary))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.Owners == 1 && s.InstalledEndpoints == 6
				}, 20*time.Second, 100*time.Millisecond, "complete request adds safe endpoints while retaining unconfirmed negotiation uncertainty")
				rejected := admissionNegotiationTransaction(callID, 486, "INVITE", 3, "temporary", "destination", "", "")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, rejected))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.Owners == 1 && s.InstalledEndpoints == 6
				}, 20*time.Second, 100*time.Millisecond, "exact rejected offer preserves the prior partial negotiation and its failure policy")
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("NEGOTIATION-ROLLBACK-SAFE")))
				require.Eventually(t, func() bool {
					return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("NEGOTIATION-ROLLBACK-SAFE"))
				}, 15*time.Second, 100*time.Millisecond, "safe selected output survives rejected replacement rollback")

				// A subsequent complete, accepted offer repairs the original side.
				// Observing its matching success also retires the rollback predecessor.
				repair := admissionNegotiationSIP(callID, false, 4, "repair", "destination", "192.0.2.2", "m=audio 42002 RTP/AVP 0\r\nm=audio 44002 RTP/AVP 0\r\n")
				accepted := admissionNegotiationTransaction(callID, 200, "INVITE", 4, "repair", "destination", "192.0.2.1", "m=audio 43000 RTP/AVP 0\r\n")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, repair))
					require.NoError(t, f.sender(5060, 5060, accepted))
					s := f.snapshot()
					acceptedOutput := bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-repair"))
					return s != nil && s.State == "enforcing" && s.Recoveries > 0 && s.Owners == 1 && s.PendingUpdates == 0 && s.InstalledEndpoints == 6 && s.InstalledGeneration == s.DesiredGeneration && acceptedOutput
				}, 20*time.Second, 100*time.Millisecond, "accepted same-side repair confirms a complete current-lifetime snapshot and restores enforcement")
				// A retransmission of the earlier answer must not replace the repaired
				// offer context or make the same call incomplete again.
				require.NoError(t, f.sender(5060, 5060, answer))
				recovered := f.snapshot()
				require.NotNil(t, recovered)
				require.Len(t, recovered.DecisionCounters, 16)
				require.NoError(t, f.sender(44000, 44002, admissionNegotiationRTP("NEGOTIATION-REPAIRED-OFFER")))
				require.NoError(t, f.sender(41000, 42002, admissionNegotiationRTP("NEGOTIATION-RETAINED-OFFER")))
				require.NoError(t, f.sender(43000, 45002, admissionNegotiationRTP("NEGOTIATION-RETAINED-ANSWER")))
				require.NoError(t, f.sender(46000, 46002, admissionNegotiationRTP("NEGOTIATION-AFTER-UNSELECTED")))
				require.NoError(t, f.sender(47000, 53, admissionNegotiationRTP("NEGOTIATION-AFTER-RESTRICTED")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && len(s.DecisionCounters) == 16 && s.State == "enforcing" && s.DecisionCounters[1] >= recovered.DecisionCounters[1]+3 && s.DecisionCounters[0] > recovered.DecisionCounters[0] && s.DecisionCounters[12] > recovered.DecisionCounters[12]
				}, 20*time.Second, 100*time.Millisecond, "the restored session admits current endpoints and rejects unrelated and explicitly restricted media")
				require.Eventually(t, func() bool {
					captured := readAdmissionPCAPs(t, f.out)
					return bytes.Contains(captured, []byte("NEGOTIATION-REPAIRED-OFFER")) && bytes.Contains(captured, []byte("NEGOTIATION-RETAINED-OFFER")) && bytes.Contains(captured, []byte("NEGOTIATION-RETAINED-ANSWER"))
				}, 15*time.Second, 100*time.Millisecond, "newly established and previously safe endpoints reach selected output")
				f.stop()
				captured := string(readAdmissionPCAPs(t, f.out))
				require.NotContains(t, captured, "NEGOTIATION-UNKNOWN-OFFER", "kernel reception does not authorize an unresolved endpoint for output")
				require.NotContains(t, captured, "NEGOTIATION-UNSELECTED")
				require.NotContains(t, captured, "NEGOTIATION-RESTRICTED")
				require.NotContains(t, captured, "NEGOTIATION-AFTER-UNSELECTED")
				require.NotContains(t, captured, "NEGOTIATION-AFTER-RESTRICTED")
			})
		}
	}
}

func admissionNegotiationSIP(callID string, response bool, cseq uint64, branch, toTag, address, media string) []byte {
	status := 0
	if response {
		status = 200
	}
	return admissionNegotiationTransaction(callID, status, "INVITE", cseq, branch, toTag, address, media)
}

func admissionNegotiationTransaction(callID string, status int, method string, cseq uint64, branch, toTag, address, media string) []byte {
	start := method + " sip:receiver@example.test SIP/2.0"
	if status == 200 {
		start = "SIP/2.0 200 OK"
	} else if status == 486 {
		start = "SIP/2.0 486 Busy Here"
	}
	to := "<sip:receiver@example.test>"
	if toTag != "" {
		to += ";tag=" + toTag
	}
	body, contentType := "", ""
	if media != "" {
		body = fmt.Sprintf("v=0\r\no=- 1 %d IN IP4 %s\r\ns=test\r\nc=IN IP4 %s\r\nt=0 0\r\n%s", cseq, address, address, media)
		contentType = "Content-Type: application/sdp\r\n"
	}
	return []byte(fmt.Sprintf("%s\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-%s\r\nFrom: <sip:selected@example.test>;tag=origin\r\nTo: %s\r\nCall-ID: %s\r\nCSeq: %d %s\r\n%sContent-Length: %d\r\n\r\n%s", start, branch, to, callID, cseq, method, contentType, len(body), body))
}

func admissionNegotiationRTP(marker string) []byte {
	return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
}
