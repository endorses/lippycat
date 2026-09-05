//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/pipeline/captureadapter"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func writeOfflineSIPExpiryCapture(t *testing.T, packets ...*pipeline.PacketEnvelope) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "expiry.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	for _, env := range packets {
		p := env.Packet()
		require.NoError(t, w.WritePacket(p.Metadata().CaptureInfo, p.Data()))
	}
	require.NoError(t, f.Close())
	return path
}

func TestOfflineIndexerDoesNotJoinSIPAcrossIdleTimeout(t *testing.T) {
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: stale-framing\r\nContent-Length: 0\r\n\r\n")
	split := len(message) / 2
	at := time.Unix(100, 0)
	path := writeOfflineSIPExpiryCapture(t,
		offlineSIPPacket(t, 100, message[:split], at),
		offlineSIPPacket(t, uint32(100+split), message[split:], at.Add(time.Hour)),
	)
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 42, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 42}, 1)
	require.NoError(t, err)
	if detail.Packet.VoIPData != nil {
		require.NotEqual(t, "stale-framing", detail.Packet.VoIPData.CallID, "expired SIP prefix must not complete using later bytes")
	}
	require.Empty(t, session.Calls)
}

func TestOfflineIndexerExpiryPreservesQueuedSIPPacketIdentity(t *testing.T) {
	at := time.Unix(100, 0)
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: expiry-call\r\nContent-Length: 0\r\n\r\n")
	split := len(message) / 2
	path := writeOfflineSIPExpiryCapture(t,
		offlineSIPPacket(t, 100, []byte("ignored\r\n"), at),
		offlineSIPPacket(t, 200, message[:split], at), // Gap keeps these queued until expiry.
		offlineSIPPacket(t, uint32(200+split), message[split:], at),
		offlineSIPPacket(t, 100, []byte("ignored\r\n"), at), // Same timestamp, old retransmission.
		offlineSIPPacket(t, 1000, []byte("later\r\n"), at.Add(time.Hour)),
	)
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 43, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	for _, id := range []offline.PacketID{2, 3, 4} {
		detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 43}, id)
		require.NoError(t, err)
		if id == 2 {
			require.NotNil(t, detail.Packet.VoIPData)
			require.Equal(t, "expiry-call", detail.Packet.VoIPData.CallID)
			require.True(t, at.Equal(detail.Packet.Timestamp))
		} else if detail.Packet.VoIPData != nil {
			require.NotEqual(t, "expiry-call", detail.Packet.VoIPData.CallID)
		}
	}
	require.Len(t, session.Calls, 1)
	require.Equal(t, uint64(5), session.Dataset.Statistics().Packets)
}

func TestOfflineIndexerExpiryReclaimsSIPStreamCapacity(t *testing.T) {
	at := time.Unix(100, 0)
	first := offlineSIPPacket(t, 100, []byte("incomplete"), at)
	second := offlineSIPPacket(t, 100, []byte("different stream"), at.Add(time.Hour))
	p := second.Packet()
	ip := p.NetworkLayer().(*layers.IPv4)
	tcp := p.TransportLayer().(*layers.TCP)
	tcp.SrcPort = 5061
	require.NoError(t, tcp.SetNetworkLayerForChecksum(ip))
	b := gopacket.NewSerializeBuffer()
	require.NoError(t, gopacket.SerializeLayers(b, gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}, ip, tcp, gopacket.Payload(tcp.Payload)))
	pkt := gopacket.NewPacket(b.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	pkt.Metadata().CaptureInfo = p.Metadata().CaptureInfo
	second = captureadapter.FromPacketInfo(capture.PacketInfo{Packet: pkt}, pipeline.SourcePCAPReplay)
	path := writeOfflineSIPExpiryCapture(t, first, second)
	cfg := *voip.GetConfig()
	cfg.MaxStreams = 1
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 44, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: cfg}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	require.Equal(t, uint64(2), session.Dataset.Count())
}
