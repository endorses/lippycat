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
	status := &management.MediaAdmissionStatus{Enabled: true, Scopes: []*management.MediaAdmissionScope{{Uncertainty: &management.MediaAdmissionUncertainty{UnknownCalls: 2, MalformedRseq: 4, MalformedRack: 5, ReplayGuards: 6, ReplayGuardCapacity: 10, ReplayGuardBytes: 768, ReplayGuardByteLimit: 1280, ReplayWindowNs: 32000000000, ReplayUnrecorded: 7, ReplayDegradedNs: 8000000000}}}}
	c := &Client{addr: "example:5555"}
	got := c.convertToHunterInfo(&management.ConnectedHunter{Stats: &management.HunterStats{RtpEbpf: status}})
	require.Equal(t, uint64(2), got.MediaAdmission.Scopes[0].Uncertainty.UnknownCalls)
	require.Equal(t, status.Scopes[0].Uncertainty, got.MediaAdmission.Scopes[0].Uncertainty)
	status.Scopes[0].Uncertainty.UnknownCalls = 99
	status.Scopes[0].Uncertainty.ReplayGuards = 99
	status.Scopes[0].Uncertainty.MalformedRseq = 99
	require.Equal(t, uint64(2), got.MediaAdmission.Scopes[0].Uncertainty.UnknownCalls)
	require.Equal(t, uint64(6), got.MediaAdmission.Scopes[0].Uncertainty.ReplayGuards)
	require.Equal(t, uint64(4), got.MediaAdmission.Scopes[0].Uncertainty.MalformedRseq)
	require.Nil(t, c.convertToHunterInfo(&management.ConnectedHunter{}).MediaAdmission)
	older := c.convertToHunterInfo(&management.ConnectedHunter{Stats: &management.HunterStats{RtpEbpf: &management.MediaAdmissionStatus{Enabled: true, Scopes: []*management.MediaAdmissionScope{{Domain: 1}}}}})
	require.Zero(t, older.MediaAdmission.Scopes[0].GetUncertainty().GetReplayWindowNs(), "older peer optional diagnostics remain absent")
}
