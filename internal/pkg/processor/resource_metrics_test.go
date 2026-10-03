//go:build processor || tap || all

package processor

import (
	"context"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestResourceMetricsSurviveProcessorStatusAndTopology(t *testing.T) {
	p, err := newTestProcessor(t, Config{ProcessorID: "resources", ListenAddr: "localhost:55555", MaxHunters: 1})
	require.NoError(t, err)
	_, err = p.RegisterHunter(context.Background(), &management.HunterRegistration{HunterId: "edge", Hostname: "host"})
	require.NoError(t, err)
	for _, stats := range []*management.HunterStats{
		{CpuPercent: 240, CpuCapacityCores: 3.5, MetricsSampleTimeNs: 123, MemoryRssBytes: 750, MemoryLimitBytes: 1000},
		{CpuPercent: 120, MemoryRssBytes: 500, MemoryLimitBytes: 1000}, // Older peer after reconnect/downgrade.
	} {
		p.hunterManager.UpdateHeartbeat("edge", 1000, management.HunterStatus_STATUS_HEALTHY, stats)
		status, err := p.GetHunterStatus(context.Background(), &management.StatusRequest{HunterId: "edge"})
		require.NoError(t, err)
		require.Len(t, status.Hunters, 1)
		topology, err := p.GetTopology(context.Background(), &management.TopologyRequest{})
		require.NoError(t, err)
		require.Len(t, topology.Processor.Hunters, 1)
		for _, got := range []*management.HunterStats{status.Hunters[0].Stats, topology.Processor.Hunters[0].Stats} {
			require.Equal(t, stats.CpuPercent, got.CpuPercent)
			require.Equal(t, stats.CpuCapacityCores, got.CpuCapacityCores)
			require.Equal(t, stats.MetricsSampleTimeNs, got.MetricsSampleTimeNs, "status query must preserve actual sample identity")
			require.Equal(t, stats.MemoryRssBytes, got.MemoryRssBytes)
			require.Equal(t, stats.MemoryLimitBytes, got.MemoryLimitBytes)
		}
	}
}
