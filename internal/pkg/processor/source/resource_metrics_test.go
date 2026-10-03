package source

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/sysmetrics"
	"github.com/stretchr/testify/require"
)

func TestResourceMetricsSampleSurvivesSourceSnapshots(t *testing.T) {
	s := NewAtomicStats()
	require.Zero(t, s.Snapshot().CPUCapacityCores)
	require.Zero(t, s.Snapshot().MetricsSampleTimeNS)
	want := sysmetrics.Metrics{CPUPercent: 120, CPUCapacityCores: 1.5, MemoryRSSBytes: 750, MemoryLimitBytes: 1000, SampleTimeNS: 123}
	s.SetSystemMetrics(want)
	for range 3 {
		s.AddCaptured()
		got := s.Snapshot()
		require.Equal(t, want.CPUPercent, got.CPUPercent)
		require.Equal(t, want.CPUCapacityCores, got.CPUCapacityCores)
		require.Equal(t, want.SampleTimeNS, got.MetricsSampleTimeNS, "packet activity and queries must not fabricate a fresh resource sample")
		require.Equal(t, want.MemoryRSSBytes, got.MemoryRSSBytes)
		require.Equal(t, want.MemoryLimitBytes, got.MemoryLimitBytes)
	}
}
