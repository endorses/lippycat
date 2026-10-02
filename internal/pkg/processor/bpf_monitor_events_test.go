//go:build processor || tap || all

package processor

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/stretchr/testify/require"
)

func TestMonitoringBPFFilterPreservesEventAnalysisSource(t *testing.T) {
	filter, err := NewBPFFilter("port 53")
	require.NoError(t, err)
	batch := &data.PacketBatch{
		HunterId: "hunter", MonitorEventAnalysis: data.MonitorEventAnalysis_MONITOR_EVENT_ANALYSIS_CLIENT_REQUIRED,
		Packets: []*data.CapturedPacket{
			{Metadata: &data.PacketMetadata{DstPort: 53}},
			{Metadata: &data.PacketMetadata{DstPort: 80}},
		},
	}
	filtered := filter.FilterBatch(batch)
	require.Len(t, filtered.Packets, 1)
	require.Equal(t, batch.MonitorEventAnalysis, filtered.MonitorEventAnalysis)
	require.Equal(t, "hunter", filtered.HunterId)
}
