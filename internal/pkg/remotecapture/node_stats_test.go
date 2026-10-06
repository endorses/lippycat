package remotecapture

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestHunterStatsAvailability(t *testing.T) {
	c := &Client{addr: "processor"}
	missing := c.convertToHunterInfo(&management.ConnectedHunter{HunterId: "edge"})
	require.True(t, missing.StatsUnavailable)
	require.Equal(t, float64(-1), missing.CPUPercent)
	zero := c.convertToHunterInfo(&management.ConnectedHunter{HunterId: "edge", Stats: &management.HunterStats{}})
	require.False(t, zero.StatsUnavailable, "reported zero is distinct from unavailable")
	require.Zero(t, zero.CPUPercent)
	require.Zero(t, zero.CPUCapacityCores, "older senders have unknown capacity")
	require.Zero(t, zero.MetricsSampleTimeNS)
}

func TestResourceMetricsConversion(t *testing.T) {
	c := &Client{addr: "processor"}
	got := c.convertToHunterInfo(&management.ConnectedHunter{HunterId: "edge", Stats: &management.HunterStats{
		CpuPercent: 240, CpuCapacityCores: 3.5, MetricsSampleTimeNs: 123,
		MemoryRssBytes: 750, MemoryLimitBytes: 1000,
	}})
	require.Equal(t, float64(240), got.CPUPercent)
	require.Equal(t, 3.5, got.CPUCapacityCores)
	require.Equal(t, int64(123), got.MetricsSampleTimeNS)
	require.Equal(t, uint64(750), got.MemoryRSSBytes)
	require.Equal(t, uint64(1000), got.MemoryLimitBytes)
}

func TestHunterAdmissionDiagnosticsOwnSnapshot(t *testing.T) {
	status := &management.MediaAdmissionStatus{Enabled: true, Scopes: []*management.MediaAdmissionScope{{Uncertainty: &management.MediaAdmissionUncertainty{UnknownCalls: 2}}}}
	c := &Client{addr: "example:5555"}
	got := c.convertToHunterInfo(&management.ConnectedHunter{Stats: &management.HunterStats{RtpEbpf: status}})
	require.Equal(t, uint64(2), got.MediaAdmission.Scopes[0].Uncertainty.UnknownCalls)
	status.Scopes[0].Uncertainty.UnknownCalls = 99
	require.Equal(t, uint64(2), got.MediaAdmission.Scopes[0].Uncertainty.UnknownCalls)
	require.Nil(t, c.convertToHunterInfo(&management.ConnectedHunter{}).MediaAdmission)
}
