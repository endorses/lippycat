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

// Resource limits are deliberately tiny to exercise real controller degradation
// through command composition. No production fault-injection switch is needed.
func TestVoIPEBPFCommandRecovery(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf for privileged command tests")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		for _, policy := range []string{"open", "closed"} {
			t.Run(topology+"/"+policy, func(t *testing.T) {
				prefix := topology
				settings := fmt.Sprintf("%s:\n  voip:\n    rtp_ebpf:\n      endpoint_capacity: 2\n      max_endpoints_per_owner: 2\n      failure_policy: %s\n", prefix, policy)
				f := newAdmissionCommandFixture(t, binary, topology, "enforce", settings)
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, admissionSIP("retained-call", "selected", 42002)))
					s := f.snapshot()
					return s != nil && s.InstalledEndpoints == 2 && s.State == "enforcing"
				}, 20*time.Second, 100*time.Millisecond, "first owner is installed")
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(5060, 5060, admissionSIP("overflow-call", "selected", 43002)))
					s := f.snapshot()
					return s != nil && s.State == "degraded-"+policy && s.UpdateErrors > 0
				}, 20*time.Second, 100*time.Millisecond, "configured capacity failure state is visible")
				before := f.snapshot()
				require.NotNil(t, before)
				payload := func(marker string) []byte {
					return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
				}
				require.NoError(t, f.sender(42000, 42002, payload("RECOVERY-RETAINED")))
				require.NoError(t, f.sender(43000, 43002, payload("RECOVERY-OVERFLOW")))
				require.NoError(t, f.sender(44000, 44002, payload("RECOVERY-UNSELECTED")))
				require.NoError(t, f.sender(45000, 53, payload("RECOVERY-RESTRICTED")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					if s == nil || len(s.DecisionCounters) != 16 {
						return false
					}
					reason := 0
					if policy == "open" {
						reason = 10
					}
					return s.DecisionCounters[reason] > before.DecisionCounters[reason] && s.DecisionCounters[12] > before.DecisionCounters[12]
				}, 20*time.Second, 100*time.Millisecond, "degradation cannot bypass explicit predicate")
				require.Eventually(t, func() bool { return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("RECOVERY-RETAINED")) }, 15*time.Second, 100*time.Millisecond)
				if policy == "open" {
					require.Eventually(t, func() bool { return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("RECOVERY-OVERFLOW")) }, 15*time.Second, 100*time.Millisecond, "selected overflow media still reaches output while open")
				}
				// A confirmed terminal response starts the existing trailing-media grace in
				// both topologies. Send once: retransmitted completion would extend grace.
				terminal := []byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-end\r\nFrom: <sip:selected@example.test>;tag=origin\r\nTo: <sip:receiver@example.test>;tag=destination\r\nCall-ID: overflow-call\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n")
				bye := []byte(strings.Replace(string(terminal), "SIP/2.0 200 OK", "BYE sip:receiver@example.test SIP/2.0", 1))
				require.NoError(t, f.sender(5060, 5060, bye))
				require.NoError(t, f.sender(5060, 5060, terminal))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && s.State == "enforcing" && s.Recoveries > 0 && s.Owners == 1 && s.PendingUpdates == 0 && s.InstalledEndpoints == 2
				}, 25*time.Second, 100*time.Millisecond, "complete current state reconciles after overflow owner finalizes")
				recovered := f.snapshot()
				require.NoError(t, f.sender(44000, 44002, payload("RECOVERY-AFTER-UNSELECTED")))
				require.NoError(t, f.sender(42000, 42002, payload("RECOVERY-AFTER-SELECTED")))
				require.Eventually(t, func() bool {
					s := f.snapshot()
					return s != nil && s.DecisionCounters[0] > recovered.DecisionCounters[0] && s.DecisionCounters[1] > recovered.DecisionCounters[1]
				}, 20*time.Second, 100*time.Millisecond, "same session enforces again")
				require.Eventually(t, func() bool { return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("RECOVERY-AFTER-SELECTED")) }, 15*time.Second, 100*time.Millisecond)
				f.stop()
				captured := string(readAdmissionPCAPs(t, f.out))
				require.NotContains(t, captured, "RECOVERY-UNSELECTED")
				require.NotContains(t, captured, "RECOVERY-RESTRICTED")
				require.NotContains(t, captured, "RECOVERY-AFTER-UNSELECTED")
				if policy == "closed" {
					require.NotContains(t, captured, "RECOVERY-OVERFLOW")
				}
			})
		}
	}
}
