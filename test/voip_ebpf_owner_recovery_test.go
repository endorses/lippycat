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

// A selected dialog that could not acquire an owner token must recover from
// current registry metadata after capacity frees, without another SIP message.
func TestVoIPEBPFCommandOwnerCapacityRecovery(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf for privileged command tests")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		t.Run(topology, func(t *testing.T) {
			settings := fmt.Sprintf("%s:\n  voip:\n    rtp_ebpf:\n      owner_capacity: 1\n      endpoint_capacity: 8\n      max_endpoints_per_owner: 2\n      failure_policy: closed\n", topology)
			f := newAdmissionCommandFixture(t, binary, topology, "enforce", settings)
			require.Eventually(t, func() bool {
				require.NoError(t, f.sender(5060, 5060, admissionSIP("owner-first", "selected", 42002)))
				s := f.snapshot()
				return s != nil && s.State == "enforcing" && s.Owners == 1 && s.InstalledEndpoints == 2 && s.PendingUpdates == 0
			}, 20*time.Second, 100*time.Millisecond, "first dialog occupies the only owner token")

			// Send the pending dialog exactly once. Everything after this point must
			// recover from retained selected metadata, never from a SIP retransmission.
			require.NoError(t, f.sender(5060, 5060, admissionSIP("owner-pending", "selected", 43002)))
			require.Eventually(t, func() bool {
				s := f.snapshot()
				return s != nil && s.State == "degraded-closed" && s.UpdateErrors > 0 && s.Owners == 1 && s.PendingUpdates > 0
			}, 20*time.Second, 100*time.Millisecond, "owner capacity is exhausted while endpoint capacity remains available")
			payload := func(marker string) []byte {
				return append([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}, []byte(marker)...)
			}
			before := f.snapshot()
			require.NotNil(t, before)
			require.Len(t, before.DecisionCounters, 16)
			require.NoError(t, f.sender(43000, 43002, payload("OWNER-PENDING-BEFORE-RECOVERY")))
			require.Eventually(t, func() bool {
				s := f.snapshot()
				return s != nil && len(s.DecisionCounters) == 16 && s.DecisionCounters[0] > before.DecisionCounters[0]
			}, 20*time.Second, 100*time.Millisecond, "pending media stays closed before owner recovery")

			terminal := []byte("SIP/2.0 200 OK\r\nVia: SIP/2.0/UDP 192.0.2.1:5060;branch=z9hG4bK-owner-end\r\nFrom: <sip:selected@example.test>;tag=origin\r\nTo: <sip:receiver@example.test>;tag=destination\r\nCall-ID: owner-first\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n")
			bye := []byte(strings.Replace(string(terminal), "SIP/2.0 200 OK", "BYE sip:receiver@example.test SIP/2.0", 1))
			require.NoError(t, f.sender(5060, 5060, bye))
			require.NoError(t, f.sender(5060, 5060, terminal))
			require.Eventually(t, func() bool {
				s := f.snapshot()
				return s != nil && s.State == "enforcing" && s.Recoveries > 0 && s.Owners == 1 && s.PendingUpdates == 0 && s.InstalledEndpoints == 2 && s.InstalledGeneration == s.DesiredGeneration
			}, 25*time.Second, 100*time.Millisecond, "pending owner publishes its complete desired snapshot after the first dialog retires")
			recovered := f.snapshot()
			require.NotNil(t, recovered)
			require.Len(t, recovered.DecisionCounters, 16)
			require.NoError(t, f.sender(43000, 43002, payload("OWNER-PENDING-AFTER-RECOVERY")))
			require.NoError(t, f.sender(44000, 44002, payload("OWNER-RECOVERY-UNRELATED")))
			require.NoError(t, f.sender(42000, 42002, payload("OWNER-RECOVERY-RETIRED")))
			require.Eventually(t, func() bool {
				s := f.snapshot()
				return s != nil && len(s.DecisionCounters) == 16 && s.DecisionCounters[1] > recovered.DecisionCounters[1] && s.DecisionCounters[0] >= recovered.DecisionCounters[0]+2
			}, 20*time.Second, 100*time.Millisecond, "only the recovered owner's endpoint is admitted")
			require.Eventually(t, func() bool {
				return bytes.Contains(readAdmissionPCAPs(t, f.out), []byte("OWNER-PENDING-AFTER-RECOVERY"))
			}, 15*time.Second, 100*time.Millisecond, "recovered selected media reaches output without more SIP")
			f.stop()
			captured := string(readAdmissionPCAPs(t, f.out))
			require.Contains(t, captured, "OWNER-PENDING-AFTER-RECOVERY")
			require.NotContains(t, captured, "OWNER-PENDING-BEFORE-RECOVERY")
			require.NotContains(t, captured, "OWNER-RECOVERY-UNRELATED")
			require.NotContains(t, captured, "OWNER-RECOVERY-RETIRED")
		})
	}
}
