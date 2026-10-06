//go:build tui || all

package components

import (
	"testing"

	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestNodesViewAdmissionSelectedStatusBothLayouts(t *testing.T) {
	status := &management.MediaAdmissionStatus{Enabled: true, Scopes: []*management.MediaAdmissionScope{{Domain: 1, State: "degraded-closed", DegradedDurationNs: 2000000000, Reason: "private raw error", Uncertainty: &management.MediaAdmissionUncertainty{UnknownCalls: 2, FaultyPrack: 2, PartialSdp: 1, IdenticalDuplicates: 8, ConflictingDuplicates: 3}}}}
	for _, mode := range []string{"table", "graph"} {
		t.Run(mode, func(t *testing.T) {
			n := NewNodesView()
			n.SetSize(160, 40)
			n.viewMode = mode
			n.SetProcessors([]ProcessorInfo{{Address: "example:5555", ConnectionState: ProcessorConnectionStateConnected}})
			n.selectedProcessorAddr = "example:5555"
			n.selectedIndex = -1
			n.UpdateMediaAdmission("example:5555", status)
			status.Scopes[0].Reason = "still private"
			output := ansi.Strip(n.View())
			require.Contains(t, output, "unknown calls 2")
			require.Contains(t, output, "degraded 2s")
			require.Contains(t, output, "Reasons (overlap)")
			require.Contains(t, output, "PRACK 2")
			require.Contains(t, output, "identical 8, conflicting 3")
			require.NotContains(t, output, "private")
			n.UpdateMediaAdmission("unconnected", status)
			require.Len(t, n.mediaAdmission, 1)
			n.SetProcessors(nil)
			require.Empty(t, n.mediaAdmission)
			n.SetProcessors([]ProcessorInfo{{Address: "example:5555", Hunters: []types.HunterInfo{{ID: "edge", MediaAdmission: status}}}})
			n.selectedIndex = 0
			n.updateViewportContent()
			require.Contains(t, ansi.Strip(n.View()), "unknown calls 2")
		})
	}
}
