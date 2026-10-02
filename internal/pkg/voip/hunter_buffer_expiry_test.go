//go:build hunter || all

package voip

import (
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func TestHunterMatchedMediaForwardingAfterBufferExpiry(t *testing.T) {
	tracker := TestCallTracker(t)
	buffers := NewBufferManager(time.Second, 10)
	defer buffers.Close()
	forwarder := &recordingHunterForwarder{}
	handler := NewUDPPacketHandler(tracker, forwarder, buffers)
	defer handler.Close()
	tracker.GetOrCreateCall("call", layers.LinkTypeEthernet)
	tracker.ExtractPortFromSDP("v=0\r\nc=IN IP4 192.168.1.200\r\nm=audio 20000 RTP/AVP 0\r\n", "call")
	buffers.MarkCallMatched("call", &CallMetadata{CallID: "call"}, "eth0", layers.LinkTypeEthernet)
	buffers.StoreMatchedFilterIDs("call", []string{"identity"})
	ageMatchedBuffer(t, buffers)
	packet := createUDPPacket(30000, 20000, []byte{0x80, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1})
	require.True(t, handler.handleRTPPacket(capture.PacketInfo{Packet: packet, Interface: "eth0", LinkType: layers.LinkTypeEthernet}, packet.TransportLayer().(*layers.UDP)))
	require.Equal(t, 1, forwarder.count())
	forwarder.mu.Lock()
	record := forwarder.records[0]
	forwarder.mu.Unlock()
	require.Equal(t, "call", record.meta.GetSip().CallId)
	require.Equal(t, []string{"identity"}, record.inheritedIDs)
	require.Zero(t, buffers.GetBufferCount())
}
