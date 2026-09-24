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
	atomic.StoreInt64(&buffer.sipDemoted, 2)
	collector.report("eth0", 150, 5, 2, buffer)

	require.Len(t, snapshots, 3)
	require.Equal(t, Telemetry{
		PacketsReceived:          350,
		KernelDrops:              8,
		InterfaceDrops:           6,
		PacketBufferDrops:        9,
		PacketBufferRegularDrops: 8,
		PacketBufferSIPDrops:     1,
		PacketBufferSIPDemotions: 2,
	}, snapshots[2])
}

func TestTelemetryCollectorSamplesLaneStateOncePerSharedBuffer(t *testing.T) {
	buffer := &PacketBuffer{
		ch:       make(chan PacketInfo, 3),
		sipCh:    make(chan PacketInfo, 2),
		mergedCh: make(chan PacketInfo, 4),
		sipFlows: newTCPSIPFlowClassifier(),
	}
	buffer.ch <- PacketInfo{}
	buffer.sipCh <- PacketInfo{}
	buffer.mergedCh <- PacketInfo{}
	atomic.StoreInt64(&buffer.sipDemoted, 5)

	collector := newTelemetryCollector(nil)
	collector.report("eth0", 10, 0, 0, buffer)
	snapshot := collector.report("eth1", 20, 0, 0, buffer)
	require.Equal(t, int64(5), snapshot.PacketBufferSIPDemotions)
	require.Equal(t, 1, snapshot.PacketBufferRegularLength)
	require.Equal(t, 3, snapshot.PacketBufferRegularCap)
	require.Equal(t, 1, snapshot.PacketBufferSIPLength)
	require.Equal(t, 2, snapshot.PacketBufferSIPCap)
	require.Equal(t, 1, snapshot.PacketBufferOutputLength)
	require.Equal(t, 4, snapshot.PacketBufferOutputCap)
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

func TestTelemetryCollectorSeparatesIngressFromSharedIPv4Outcome(t *testing.T) {
	collector := newTelemetryCollector(nil)
	collector.ipv4 = NewIPv4Defragmenter()
	first := createIPv4Fragment("192.0.2.1", "198.51.100.1", 7, 0, true, []byte("AAAAAAAA"))
	last := createIPv4Fragment("192.0.2.1", "198.51.100.1", 7, 8, false, []byte("BBBB"))
	collector.observeFragment("eth0", true, true)
	_, err := collector.ipv4.DefragIPv4(first)
	require.NoError(t, err)
	collector.observeFragment("eth1", true, true)
	completed, err := collector.ipv4.DefragIPv4(last)
	require.NoError(t, err)
	require.NotNil(t, completed)
	collector.observeFragment("eth0", false, false) // IPv6 observed with reassembly disabled.
	collector.observeFragment("eth1", false, true)
	firstSnapshot := collector.report("eth0", 10, 0, 0, nil)
	secondSnapshot := collector.report("eth1", 10, 0, 0, nil)
	require.Equal(t, FragmentIngress{IPv4Observed: 1, IPv4Attempted: 1, IPv6Observed: 1}, secondSnapshot.FragmentIngress["eth0"])
	require.Equal(t, FragmentIngress{IPv4Observed: 1, IPv4Attempted: 1, IPv6Observed: 1, IPv6Attempted: 1}, secondSnapshot.FragmentIngress["eth1"])
	require.Equal(t, uint64(2), secondSnapshot.IPv4Defrag.ObservedFragments)
	require.Equal(t, uint64(1), secondSnapshot.IPv4Defrag.CompletedDatagrams)
	require.Equal(t, firstSnapshot.IPv4Defrag, secondSnapshot.IPv4Defrag)
}
