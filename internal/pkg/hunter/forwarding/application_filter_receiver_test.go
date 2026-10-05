//go:build hunter || all

package forwarding_test

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/hunter"
	"github.com/endorses/lippycat/internal/pkg/hunter/forwarding"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type receiverPacketForwarder struct {
	count int
	ids   []string
}

func (f *receiverPacketForwarder) ForwardPacketWithMetadata(gopacket.Packet, *data.PacketMetadata, string, layers.LinkType) error {
	f.count++
	return nil
}

func (f *receiverPacketForwarder) ForwardPacketWithFilterProvenance(_ gopacket.Packet, _ *data.PacketMetadata, _ string, _ layers.LinkType, direct, inherited []string) error {
	f.count++
	f.ids = append(append([]string(nil), direct...), inherited...)
	return nil
}

func TestVoIPApplicationFilterReceiverDirectIPAndDeny(t *testing.T) {
	filter, err := hunter.NewApplicationFilter(nil)
	require.NoError(t, err)
	t.Cleanup(filter.Close)
	filter.SetNoFilterPolicy(hunter.NoFilterPolicyDeny)
	tracker := voip.NewCallTrackerWithConfig(voip.DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	buffers := voip.NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	sink := &receiverPacketForwarder{}
	processor := voip.NewVoIPPacketProcessor(tracker, sink, buffers)
	t.Cleanup(processor.Close)
	// This is the same dynamic receiver assertion used by Hunter.Start.
	var packetProcessor forwarding.PacketProcessor = processor
	receiver, ok := packetProcessor.(forwarding.ApplicationFilterReceiver)
	require.True(t, ok)
	receiver.SetApplicationFilter(filter)

	ip := &layers.IPv4{Version: 4, TTL: 64, Protocol: layers.IPProtocolUDP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	udp := &layers.UDP{SrcPort: 19000, DstPort: 19002}
	require.NoError(t, udp.SetNetworkLayerForChecksum(ip))
	buf := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(buf, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, udp,
		gopacket.Payload([]byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})))
	packet := capture.PacketInfo{Packet: gopacket.NewPacket(buf.Bytes(), layers.LayerTypeIPv4, gopacket.Default), LinkType: layers.LinkTypeRaw}
	update := func(pattern string) {
		filter.UpdateFilters([]*management.Filter{
			{Id: "direct-ip", Type: management.FilterType_FILTER_IP_ADDRESS, Pattern: pattern, Enabled: true},
			{Id: "identity", Type: management.FilterType_FILTER_SIP_USER, Pattern: "selected", Enabled: true},
		})
	}
	update("192.0.2.2")
	require.False(t, processor.ProcessPacket(packet), "the handler owns accepted forwarding")
	require.Equal(t, 1, sink.count, "direct IP authorizes RTP without a selected call")
	require.Equal(t, []string{"direct-ip"}, sink.ids)
	update("198.51.100.2")
	require.False(t, processor.ProcessPacket(packet))
	require.Equal(t, 1, sink.count, "a nonmatching identity does not authorize unknown media")
	update("192.0.2.0/24")
	require.False(t, processor.ProcessPacket(packet))
	require.Equal(t, 2, sink.count, "receiver retains the subscribed mutable filter")
	require.Equal(t, []string{"direct-ip"}, sink.ids)
	filter.UpdateFilters(nil)
	require.False(t, processor.ProcessPacket(packet))
	require.Equal(t, 2, sink.count, "empty deny policy still applies")
}
