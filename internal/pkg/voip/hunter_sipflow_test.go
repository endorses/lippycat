//go:build hunter || all

package voip

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/api/gen/data"
	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

type hunterForwardRecord struct {
	packet gopacket.Packet
	meta   *data.PacketMetadata
	iface  string
	link   layers.LinkType
}

type recordingHunterForwarder struct {
	mu      sync.Mutex
	records []hunterForwardRecord
	err     error
}

func (f *recordingHunterForwarder) ForwardPacketWithMetadata(packet gopacket.Packet, metadata *data.PacketMetadata, iface string, link layers.LinkType) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records = append(f.records, hunterForwardRecord{packet: packet, meta: metadata, iface: iface, link: link})
	return f.err
}

func (f *recordingHunterForwarder) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.records)
}

type mutablePayloadFilter struct {
	mu     sync.RWMutex
	needle string
}

func (f *mutablePayloadFilter) MatchPacket(packet gopacket.Packet) bool {
	f.mu.RLock()
	defer f.mu.RUnlock()
	app := packet.ApplicationLayer()
	return app != nil && BytesContains(app.LayerContents(), []byte(f.needle))
}

func (f *mutablePayloadFilter) set(needle string) {
	f.mu.Lock()
	f.needle = needle
	f.mu.Unlock()
}

func hunterFlow(t *testing.T) (gopacket.Flow, gopacket.Flow) {
	t.Helper()
	netFlow := gopacket.NewFlow(layers.EndpointIPv4, net.ParseIP("192.0.2.1").To4(), net.ParseIP("198.51.100.2").To4())
	src, dst := layers.NewTCPPortEndpoint(5060), layers.NewTCPPortEndpoint(5060)
	return netFlow, gopacket.NewFlow(layers.EndpointTCPPort, src.Raw(), dst.Raw())
}

func TestHunterTCPSharedFlowStickyTerminationAndSynthesis(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffers.Close)
	handler := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	filter := &mutablePayloadFilter{needle: "alice"}
	handler.SetApplicationFilter(filter)
	netFlow, transportFlow := hunterFlow(t)
	captured := time.Unix(1700000000, 1234)

	invite := []byte("INVITE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:bob@example.test>\r\nCall-ID: sticky\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	require.True(t, handler.HandleSIPMessageAt(invite, "sticky", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, captured))
	filter.set("never-present")
	bye := []byte("BYE sip:bob@example.test SIP/2.0\r\nFrom: <sip:anonymous@example.test>\r\nTo: <sip:bob@example.test>\r\nCall-ID: sticky\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n")
	require.True(t, handler.HandleSIPMessageAt(bye, "sticky", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, captured.Add(time.Second)))
	require.Eventually(t, func() bool { return forwarder.count() == 2 }, time.Second, time.Millisecond)

	forwarder.mu.Lock()
	defer forwarder.mu.Unlock()
	require.Equal(t, invite, forwarder.records[0].packet.ApplicationLayer().LayerContents())
	require.Equal(t, captured, forwarder.records[0].packet.Metadata().Timestamp)
	require.Equal(t, "sticky", forwarder.records[1].meta.Sip.CallId)
	require.Equal(t, "BYE", forwarder.records[1].meta.Sip.Method)
	require.Equal(t, layers.LinkTypeEthernet, forwarder.records[0].link)
}

func TestHunterTCPSinkReportsRetryableForwardFailure(t *testing.T) {
	forwarder := &recordingHunterForwarder{err: errors.New("temporary transport failure")}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	handler := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	handler.SetApplicationFilter(&mutablePayloadFilter{needle: "Call-ID: failed"})
	netFlow, transportFlow := hunterFlow(t)
	msg := []byte("CANCEL sip:b@example.test SIP/2.0\r\nCall-ID: failed\r\nCSeq: 1 CANCEL\r\nContent-Length: 0\r\n\r\n")
	require.True(t, handler.HandleSIPMessageAt(msg, "failed", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, time.Unix(1, 0)))
	require.Eventually(t, func() bool {
		return handler.SIPStats()[hunterSIPSinkName].RetryableFailures == 1
	}, time.Second, time.Millisecond)
}

func TestHunterTCPStickySelectionIncludesCancel(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 10)
	t.Cleanup(buffers.Close)
	handler := NewHunterForwardHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	filter := &mutablePayloadFilter{needle: "alice"}
	handler.SetApplicationFilter(filter)
	netFlow, transportFlow := hunterFlow(t)
	invite := []byte("INVITE sip:b@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>\r\nCall-ID: cancelled\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	require.True(t, handler.HandleSIPMessageAt(invite, "cancelled", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, time.Unix(1, 0)))
	filter.set("not-in-cancel")
	cancel := []byte("CANCEL sip:b@example.test SIP/2.0\r\nCall-ID: cancelled\r\nCSeq: 2 CANCEL\r\nContent-Length: 0\r\n\r\n")
	require.True(t, handler.HandleSIPMessageAt(cancel, "cancelled", "192.0.2.1:5060", "198.51.100.2:5060", netFlow, transportFlow, time.Unix(2, 0)))
	require.Eventually(t, func() bool { return forwarder.count() == 2 }, time.Second, time.Millisecond)
}

func TestHunterUDPBuffersUntilSDPThenForwardsStickyDialog(t *testing.T) {
	forwarder := &recordingHunterForwarder{}
	buffers := NewBufferManager(time.Minute, 100)
	t.Cleanup(buffers.Close)
	handler := NewUDPPacketHandler(TestCallTracker(t), forwarder, buffers)
	t.Cleanup(handler.Close)
	filter := &mutablePayloadFilter{needle: "alice"}
	handler.SetApplicationFilter(filter)

	invite := []byte("INVITE sip:bob@example.test SIP/2.0\r\nFrom: <sip:alice@example.test>\r\nTo: <sip:bob@example.test>\r\nCall-ID: udp-sticky\r\nCSeq: 1 INVITE\r\nContent-Length: 0\r\n\r\n")
	p1 := createUDPPacket(5060, 5060, invite)
	p1.Metadata().Timestamp = time.Unix(100, 0)
	require.False(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: p1, Interface: "eth-test", LinkType: layers.LinkTypeEthernet}, p1.TransportLayer().(*layers.UDP)))
	require.Equal(t, 0, forwarder.count(), "pre-SDP signalling must remain buffered")

	filter.set("never-present")
	sdp := "v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 20000 RTP/AVP 0\r\n"
	answer := []byte(fmt.Sprintf("SIP/2.0 200 OK\r\nFrom: <sip:anonymous@example.test>\r\nTo: <sip:bob@example.test>\r\nCall-ID: udp-sticky\r\nCSeq: 1 INVITE\r\nContent-Type: application/sdp\r\nContent-Length: %d\r\n\r\n%s", len(sdp), sdp))
	p2 := createUDPPacket(5060, 5060, answer)
	p2.Metadata().Timestamp = time.Unix(101, 0)
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: p2, Interface: "eth-test", LinkType: layers.LinkTypeEthernet}, p2.TransportLayer().(*layers.UDP)))
	require.Eventually(t, func() bool { return forwarder.count() == 2 }, time.Second, time.Millisecond)

	bye := []byte("BYE sip:bob@example.test SIP/2.0\r\nCall-ID: udp-sticky\r\nCSeq: 2 BYE\r\nContent-Length: 0\r\n\r\n")
	p3 := createUDPPacket(5060, 5060, bye)
	require.True(t, handler.HandleUDPPacket(capture.PacketInfo{Packet: p3, Interface: "eth-test", LinkType: layers.LinkTypeEthernet}, p3.TransportLayer().(*layers.UDP)))
	require.Eventually(t, func() bool { return forwarder.count() == 3 }, time.Second, time.Millisecond)
}
