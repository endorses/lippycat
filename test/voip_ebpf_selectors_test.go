//go:build linux && all

package test

import (
	"os"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestVoIPEBPFCommandIndependentSelectors(t *testing.T) {
	if os.Getenv("LIPPYCAT_EBPF_TEST") != "1" {
		t.Skip("not exercised: run make test-ebpf")
	}
	binary := os.Getenv("LIPPYCAT_EBPF_BINARY")
	require.NotEmpty(t, binary)
	for _, topology := range []string{"tap", "hunter"} {
		t.Run(topology, func(t *testing.T) {
			f := newAdmissionCommandFixture(t, binary, topology, "enforce", "{}\n", "--no-filter-policy", "allow")
			media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
			stats := func() *management.HunterStats {
				for _, h := range f.status().GetHunters() {
					if h.GetStats().GetRtpEbpf().GetEnabled() {
						return h.Stats
					}
				}
				return nil
			}
			exercise := func(reason int) {
				before := f.snapshot()
				require.NotNil(t, before)
				delivered := stats().GetPacketsForwarded()
				require.Eventually(t, func() bool {
					require.NoError(t, f.sender(44000, 44002, media))
					current := f.snapshot()
					return current != nil && current.DecisionCounters[reason] > before.DecisionCounters[reason] && stats().GetPacketsForwarded() > delivered
				}, 20*time.Second, 100*time.Millisecond, "independent admission reaches userspace forwarding")
				require.Zero(t, f.snapshot().InstalledEndpoints, "independent selectors do not invent a selected call")
				excludedBefore := f.snapshot().DecisionCounters[12]
				require.NoError(t, f.sender(44000, 53, media))
				require.Eventually(t, func() bool { return f.snapshot().DecisionCounters[12] > excludedBefore }, 15*time.Second, 100*time.Millisecond, "explicit restriction still applies")
			}
			for _, pattern := range []string{"192.0.2.2", "192.0.2.0/24"} {
				updated, err := f.client.UpdateFilter(t.Context(), &management.Filter{Id: "independent-ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true})
				require.NoError(t, err)
				require.True(t, updated.Success, updated.Error)
				exercise(3)
			}
			for _, id := range []string{"independent-ip", "selected-identity"} {
				deleted, err := f.client.DeleteFilter(t.Context(), &management.FilterDeleteRequest{FilterId: id})
				require.NoError(t, err)
				require.True(t, deleted.Success, deleted.Error)
			}
			exercise(4)
			f.stop()
		})
	}
}
