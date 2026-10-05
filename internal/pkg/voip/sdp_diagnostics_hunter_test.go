//go:build hunter || all

package voip

import (
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestSDPDiagnosticsHunterOwnerWithoutAdmissionOrLogs(t *testing.T) {
	logs := sdpDiagnosticsCapture(t)
	tracker := NewCallTrackerWithConfig(DefaultConfig())
	t.Cleanup(tracker.Shutdown)
	buffers := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffers.Close)
	forwarder := &recordingHunterForwarder{}
	handler := NewUDPPacketHandler(tracker, forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&hunterIdentityFilter{needle: "selected", ids: []string{"synthetic-filter"}})
	packetHarness := &udpSelectionHarness{t: t, ip: "192.0.2.1", peer: "192.0.2.2", family: "IP4"}
	body := "c=IN IP4 192.0.2.1\r\nm=audio 10000 RTP/AVP 0\r\nm=invalid\r\n"
	packet := packetHarness.packet(5060, 5060, diagnosticSIPMessage("synthetic-hunter", body))
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: packet, Interface: "test0", LinkType: layers.LinkTypeEthernet}, packet.Layer(layers.LayerTypeUDP).(*layers.UDP)))
	require.Eventually(t, func() bool { return forwarder.count() == 1 }, time.Second, time.Millisecond)
	require.Equal(t, []string{"synthetic-hunter"}, tracker.endpointCallIDs("192.0.2.1:10000"))
	media := packetHarness.media()
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: media, Interface: "test0", LinkType: layers.LinkTypeEthernet}, media.Layer(layers.LayerTypeUDP).(*layers.UDP)))
	require.Equal(t, 2, forwarder.count())
	handler.Close()
	buffers.Close()
	tracker.Shutdown()
	warnings := logs.warnings(t)
	require.Len(t, warnings, 1)
	require.Equal(t, "voip-buffer", warnings[0]["reporting_path"])
}
