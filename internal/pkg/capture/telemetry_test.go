package capture

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestTelemetryCollectorAggregatesInterfacesWithoutDuplicatingBufferDrops(t *testing.T) {
	var snapshots []Telemetry
	collector := newTelemetryCollector(func(snapshot Telemetry) {
		snapshots = append(snapshots, snapshot)
	})

	buffer := &PacketBuffer{sipFlows: newTCPSIPFlowClassifier()}
	atomic.StoreInt64(&buffer.dropped, 7)
	collector.report("eth0", 100, 2, 1, buffer)
	collector.report("eth1", 200, 3, 4, buffer)
	atomic.StoreInt64(&buffer.dropped, 8)
	atomic.StoreInt64(&buffer.sipDropped, 1)
	collector.report("eth0", 150, 5, 2, buffer)

	require.Len(t, snapshots, 3)
	require.Equal(t, Telemetry{
		PacketsReceived:          350,
		KernelDrops:              8,
		InterfaceDrops:           6,
		PacketBufferDrops:        9,
		PacketBufferRegularDrops: 8,
		PacketBufferSIPDrops:     1,
	}, snapshots[2])
}

func TestTelemetryCollectorIncludesSIPClassifierState(t *testing.T) {
	buffer := &PacketBuffer{sipFlows: newTCPSIPFlowClassifier()}
	now := time.Now()
	ip := &layers.IPv4{SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	tcp := testTCP(41000, 5060, "INVITE sip:x@example.invalid SIP/2.0\r\n")
	require.True(t, buffer.sipFlows.classify(ip, tcp, now))
	atomic.StoreInt64(&buffer.sipClassified, 1)

	snapshot := newTelemetryCollector(nil).report("eth0", 1, 0, 0, buffer)
	require.Equal(t, int64(1), snapshot.SIPClassified)
	require.Equal(t, uint64(1), snapshot.SIPFlowPromotions)
	require.Equal(t, 1, snapshot.SIPFlowActive)
}

func TestTelemetryCollectorNilCallbackIsSafe(t *testing.T) {
	collector := newTelemetryCollector(nil)
	require.NotNil(t, collector)
	require.Equal(t, Telemetry{
		PacketsReceived: 1,
		KernelDrops:     2,
		InterfaceDrops:  3,
	}, collector.report("eth0", 1, 2, 3, nil))
}
