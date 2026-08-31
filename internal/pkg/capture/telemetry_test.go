package capture

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTelemetryCollectorAggregatesInterfacesWithoutDuplicatingBufferDrops(t *testing.T) {
	var snapshots []Telemetry
	collector := newTelemetryCollector(func(snapshot Telemetry) {
		snapshots = append(snapshots, snapshot)
	})

	collector.report("eth0", 100, 2, 1, 7)
	collector.report("eth1", 200, 3, 4, 7)
	collector.report("eth0", 150, 5, 2, 9)

	require.Len(t, snapshots, 3)
	require.Equal(t, Telemetry{
		PacketsReceived:   350,
		KernelDrops:       8,
		InterfaceDrops:    6,
		PacketBufferDrops: 9,
	}, snapshots[2])
}

func TestTelemetryCollectorNilCallbackIsSafe(t *testing.T) {
	collector := newTelemetryCollector(nil)
	require.Nil(t, collector)
	require.Equal(t, Telemetry{}, collector.report("eth0", 1, 2, 3, 4))
}
