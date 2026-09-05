//go:build tui || all

package tui

import (
	"net"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	sharedsip "github.com/endorses/lippycat/internal/pkg/sip"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func offlineSIPPacket(t *testing.T, seq uint32, payload []byte, at time.Time) *pipeline.PacketEnvelope {
	t.Helper()
	ip := &layers.IPv4{Version: 4, IHL: 5, TTL: 64, Protocol: layers.IPProtocolTCP, SrcIP: net.ParseIP("192.0.2.1"), DstIP: net.ParseIP("192.0.2.2")}
	tcp := &layers.TCP{SrcPort: 5060, DstPort: 5060, Seq: seq, ACK: true, Window: 65535}
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(payload)))
	pkt := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(b.Bytes()), Length: len(b.Bytes())}
	return captureadapter.FromPacketInfo(capture.PacketInfo{Packet: pkt}, pipeline.SourcePCAPReplay)
}
func TestOfflineSIPSynchronousSegmentCompletion(t *testing.T) {
	tracker := NewCallTracker()
	handler := NewTUISIPHandler(tracker, nil)
	defer handler.Close()
	flows := newOfflineSIPFlows()
	handler.markFlow = flows.markTCP
	factory := newOfflineSIPFactory(handler)
	engine := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	defer func() { require.NoError(t, engine.Close()) }()
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: sync-call\r\nContent-Length: 44\r\n\r\nc=IN IP4 192.0.2.1\r\nm=audio 4000 RTP/AVP 0\r\n")
	// Derive length to make the SDP independent of line-ending edits.
	split := len(message) / 2
	at := time.Unix(100, 0)
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 100, message[:split], at)))
	require.Nil(t, factory.LastEvent)
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, uint32(100+split), message[split:], at.Add(time.Second))))
	require.NoError(t, factory.Err())
	require.NotNil(t, factory.LastEvent)
	require.Equal(t, "sync-call", factory.LastEvent.CallID)
	require.Equal(t, at.Add(time.Second), factory.LastEvent.Timestamp)
	require.Equal(t, "sync-call", tracker.GetCallIDForRTPPacket("192.0.2.1", "4000", "192.0.2.2", "5000"))
}

func TestOfflineSIPUsesFrozenLimitsAndReleasesBuffers(t *testing.T) {
	tracker := NewCallTracker()
	handler := NewTUISIPHandler(tracker, nil)
	defer handler.Close()
	cfg := *voip.GetConfig()
	cfg.Security.MaxContentLength = 8
	factory := newOfflineSIPFactory(handler, cfg)
	engine := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: large\r\nContent-Length: 9\r\n\r\n123456789")
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 100, message, time.Unix(100, 0))))
	require.ErrorContains(t, factory.Err(), "exceeds")
	require.Error(t, engine.Close())
	require.Zero(t, factory.buffered)
	require.Zero(t, factory.streams)
}

func TestOfflineSIPQueuedEOFCompletionKeepsPacketIdentity(t *testing.T) {
	tracker := NewCallTracker()
	handler := NewTUISIPHandler(tracker, nil)
	defer handler.Close()
	factory := newOfflineSIPFactory(handler)
	engine := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	at := time.Unix(100, 0)
	factory.CurrentID = 3
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 100, []byte("ignored\r\n"), at)))
	factory.CurrentID = 7
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: eof-call\r\nContent-Length: 0\r\n\r\n")
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 200, message, at.Add(time.Second))))
	require.Nil(t, factory.LastEvent)
	var packetID offline.PacketID
	factory.OnEvent = func(id offline.PacketID, event sharedsip.Event) error { packetID = id; return nil }
	require.NoError(t, engine.Close())
	require.NotNil(t, factory.LastEvent)
	require.Equal(t, offline.PacketID(7), packetID)
	require.Equal(t, at.Add(time.Second), factory.LastEvent.Timestamp)
	require.Zero(t, factory.buffered)
}

func TestOfflineSIPEOFUsesEachMessageOriginDespiteRetransmission(t *testing.T) {
	handler := NewTUISIPHandler(NewCallTracker(), nil)
	defer handler.Close()
	factory := newOfflineSIPFactory(handler)
	engine := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	at := time.Unix(100, 0)
	feed := func(id offline.PacketID, seq uint32, payload []byte) {
		factory.CurrentID = id
		env := offlineSIPPacket(t, seq, payload, at) // Deliberately identical timestamps.
		require.NoError(t, engine.AssembleWithContext(env, offlineSIPContext(env.Packet().Metadata().CaptureInfo, id)))
	}
	feed(1, 100, []byte("ignored\r\n"))
	first := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: first\r\nContent-Length: 0\r\n\r\n")
	second := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: second\r\nContent-Length: 0\r\n\r\n")
	feed(2, 200, first)
	feed(3, 400, second)
	feed(4, 100, []byte("ignored\r\n")) // Old retransmission must not own EOF metadata.
	got := map[string]offline.PacketID{}
	factory.OnEvent = func(id offline.PacketID, event sharedsip.Event) error { got[event.CallID] = id; return nil }
	factory.Flushing = true
	require.NoError(t, engine.Close())
	require.Equal(t, map[string]offline.PacketID{"first": 2, "second": 3}, got)
	require.Zero(t, factory.buffered)
}
