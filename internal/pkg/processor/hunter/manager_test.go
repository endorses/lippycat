package hunter

import (
	"fmt"
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestManagerRegisterZeroMaxHuntersIsUnlimited(t *testing.T) {
	manager := NewManager("test-processor", 0, nil)

	for i := 0; i < 256; i++ {
		hunterID := fmt.Sprintf("hunter-%d", i)
		_, _, err := manager.Register(hunterID, "test-host", []string{"eth0"}, nil)
		require.NoError(t, err)
	}

	require.Len(t, manager.GetAll(""), 256)
}

func TestManagerHeartbeatPreservesNamedLossCounters(t *testing.T) {
	manager := NewManager("test-processor", 1, nil)
	_, _, err := manager.Register("hunter-1", "test-host", []string{"eth0"}, nil)
	require.NoError(t, err)

	stats := &management.HunterStats{
		PacketsDropped:            9,
		CaptureBufferRegularDrops: 4,
		CaptureBufferSipDrops:     2,
		BatchChannelDrops:         3,
		Detector: &management.DetectorTelemetry{
			FlowEntries: 42,
		},
	}
	manager.UpdateHeartbeat("hunter-1", 123, management.HunterStatus_STATUS_WARNING, stats)

	hunter, ok := manager.Get("hunter-1")
	require.True(t, ok)
	require.Equal(t, uint64(9), hunter.PacketsDropped)
	require.Equal(t, uint64(4), hunter.CaptureBufferRegularDrops)
	require.Equal(t, uint64(2), hunter.CaptureBufferSIPDrops)
	require.Equal(t, uint64(3), hunter.BatchChannelDrops)
	require.Equal(t, uint64(42), hunter.Detector.FlowEntries)
	stats.Detector.FlowEntries = 99
	require.Equal(t, uint64(42), hunter.Detector.FlowEntries, "heartbeat telemetry must be snapshotted")
}
