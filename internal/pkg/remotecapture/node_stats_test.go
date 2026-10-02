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
}
