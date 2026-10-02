//go:build hunter || all

package stats

import (
	"sync"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
	"github.com/stretchr/testify/require"
)

func TestResourceMetricsRemainOneSampleInHeartbeat(t *testing.T) {
	c := New()
	require.Zero(t, c.ToProto(0).CpuCapacityCores)
	require.Zero(t, c.ToProto(0).MetricsSampleTimeNs)
	a := sysmetrics.Metrics{CPUPercent: 120, CPUCapacityCores: 1.5, MemoryRSSBytes: 750, MemoryLimitBytes: 1000, SampleTimeNS: 123}
	b := sysmetrics.Metrics{CPUPercent: 240, CPUCapacityCores: 3, MemoryRSSBytes: 1500, MemoryLimitBytes: 2000, SampleTimeNS: 456}
	c.SetSystemMetrics(a)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 1000 {
			c.SetSystemMetrics(b)
			c.SetSystemMetrics(a)
		}
	}()
	defer wg.Wait()
	for range 1000 {
		got := c.ToProto(0)
		want := a
		if got.MetricsSampleTimeNs == b.SampleTimeNS {
			want = b
		}
		require.Equal(t, want.SampleTimeNS, got.MetricsSampleTimeNs)
		require.Equal(t, float32(want.CPUPercent), got.CpuPercent)
		require.Equal(t, want.CPUCapacityCores, got.CpuCapacityCores)
		require.Equal(t, want.MemoryRSSBytes, got.MemoryRssBytes)
		require.Equal(t, want.MemoryLimitBytes, got.MemoryLimitBytes)
	}
}
