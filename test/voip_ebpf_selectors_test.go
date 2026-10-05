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
		for _, mode := range []string{"enforce", "shadow", "broad"} {
			t.Run(topology+"/"+mode, func(t *testing.T) {
				f := newAdmissionCommandFixture(t, binary, topology, mode, "{}\n", "--no-filter-policy", "allow")
				media := []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
				stats := func() *management.HunterStats {
					for _, h := range f.status().GetHunters() {
						if mode == "broad" || h.GetStats().GetRtpEbpf().GetEnabled() {
							return h.Stats
						}
					}
					return nil
				}
				exercise := func(reason int) {
					before := f.snapshot()
					if mode != "broad" {
						require.NotNil(t, before)
					}
					delivered := stats().GetPacketsForwarded()
					require.Eventually(t, func() bool {
						require.NoError(t, f.sender(19000, 19002, media))
						current := f.snapshot()
						if stats().GetPacketsForwarded() <= delivered {
							return false
						}
						if mode == "broad" {
							return true
						}
						return current != nil && current.DecisionCounters[reason] > before.DecisionCounters[reason]
					}, 20*time.Second, 100*time.Millisecond, "independent admission reaches userspace forwarding")
					if mode == "broad" {
						return
					} // Classic predicate restriction is checked by LocalTarget packet fixtures.
					require.Zero(t, f.snapshot().InstalledEndpoints, "independent selectors do not invent a selected call")
					excludedBefore := f.snapshot().DecisionCounters[12]
					require.NoError(t, f.sender(44000, 53, media))
					require.Eventually(t, func() bool { return f.snapshot().DecisionCounters[12] > excludedBefore }, 15*time.Second, 100*time.Millisecond, "explicit restriction still applies")
				}
				for _, pattern := range []string{"192.0.2.2", "192.0.2.0/24"} {
					updated, err := f.client.UpdateFilter(t.Context(), &management.Filter{Id: "independent-ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true})
					require.NoError(t, err)
					require.True(t, updated.Success, updated.Error)
					if topology == "tap" && mode == "broad" {
						// The disabled tap puts IP matching in classic BPF while
						// its remaining identity filter controls userspace output.
						captured, forwarded := stats().GetPacketsCaptured(), stats().GetPacketsForwarded()
						require.Eventually(t, func() bool {
							require.NoError(t, f.sender(19000, 19002, media))
							return stats().GetPacketsCaptured() > captured
						}, 20*time.Second, 100*time.Millisecond)
						require.Never(t, func() bool { return stats().GetPacketsForwarded() > forwarded }, time.Second, 100*time.Millisecond,
							"mixed disabled tap captures candidates without identity authorization")
					} else {
						exercise(3)
					}
				}
				deleteFilter := func(id string) {
					deleted, err := f.client.DeleteFilter(t.Context(), &management.FilterDeleteRequest{FilterId: id})
					require.NoError(t, err)
					require.True(t, deleted.Success, deleted.Error)
				}
				deleteFilter("selected-identity")
				// Keep the IP selector installed to prove actual IP-only output,
				// including the tap fixture's static --sip-user initialization.
				exercise(3)
				deleteFilter("independent-ip")
				exercise(4)
				f.stop()
			})
		}
	}
}
