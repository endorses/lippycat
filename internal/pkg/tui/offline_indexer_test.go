//go:build tui || all

package tui

import (
	"context"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/stretchr/testify/require"
)

func testOfflineStorage(t *testing.T) *offline.Storage {
	t.Helper()
	s, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 64 << 20, CacheBytes: 16 << 20, MaxRecordBytes: 1 << 20, MaxSources: 64})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}
func TestOfflineIndexerCompleteIsolatedAndBounded(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	storage := testOfflineStorage(t)
	before := GetBridgeStats()
	session, err := indexOfflineDataset(context.Background(), storage, 7, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 8, SIPConfig: *voip.GetConfig()}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	require.Equal(t, uint64(1077), session.Dataset.Count())
	require.Equal(t, uint64(1077), session.Dataset.Statistics().Packets)
	require.LessOrEqual(t, len(session.EventStore.Events()), 8)
	require.Zero(t, session.EventStore.Stats().TransportLost)
	require.Equal(t, before, GetBridgeStats())
	first, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 7}, 0)
	require.NoError(t, err)
	require.Contains(t, paths, first.Source.Path)
	require.NotEmpty(t, first.Packet.RawData)
}
func TestOfflineIndexerFailureRemovesUnpublishedStorage(t *testing.T) {
	storage := testOfflineStorage(t)
	paths := writeOrderedBridgeFixtures(t)
	bad := filepath.Join(t.TempDir(), "bad.pcap")
	require.NoError(t, os.WriteFile(bad, []byte("bad capture"), 0600))
	paths = append(paths, bad)
	session, err := indexOfflineDataset(context.Background(), storage, 8, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 8}, nil)
	require.Error(t, err)
	require.Nil(t, session)
	require.Zero(t, storage.Resources().DiskBytes)
}
func TestOfflineIndexerCancellationDuringIndexing(t *testing.T) {
	storage := testOfflineStorage(t)
	paths := writeOrderedBridgeFixtures(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session, err := indexOfflineDataset(ctx, storage, 9, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 8}, func(p offline.Progress) {
		if p.LogicalPackets > 0 {
			cancel()
		}
	})
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, session)
	require.Zero(t, storage.Resources().DiskBytes)
}

func TestOfflineIndexerRepeatIdentityAndEOFFlush(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	storage := testOfflineStorage(t)
	cfg := OfflineAnalysisConfig{Inputs: paths, EventCapacity: 32}
	a, err := indexOfflineDataset(context.Background(), storage, 11, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, a.Close()) }()
	b, err := indexOfflineDataset(context.Background(), storage, 12, cfg, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, b.Close()) }()
	ae, be := a.EventStore.Events(), b.EventStore.Events()
	require.Len(t, be, len(ae))
	for i := range ae {
		require.Equal(t, ae[i].Event.Envelope().EventID, be[i].Event.Envelope().EventID)
		require.Equal(t, ae[i].Event.Envelope().EventSequence, be[i].Event.Envelope().EventSequence)
	}
	require.Positive(t, a.EventStore.Stats().Arrived)
	require.NotSame(t, a.Tracker, b.Tracker)
	require.NotSame(t, a.EventStore, b.EventStore)
}

func TestOfflineIndexerDrainsEOFBeyondEventQueueCapacity(t *testing.T) {
	// Ordinary UDP produces connection events only at EOF. More distinct flows
	// than either dispatcher queue can hold must all reach the published store.
	const count = 2049
	path := filepath.Join(t.TempDir(), "eof-flows.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i := 0; i < count; i++ {
		raw := goldenUDPPacket(t, layers.UDPPort(20000+i), 32001, []byte("offline EOF flow"))
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{
			Timestamp: time.Unix(1700000000, int64(i)*1000), CaptureLength: len(raw), Length: len(raw),
		}, raw))
	}
	require.NoError(t, f.Close())
	session, err := indexOfflineDataset(context.Background(), testOfflineStorage(t), 1, OfflineAnalysisConfig{Inputs: []string{path}, EventCapacity: count + 1}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	require.Equal(t, uint64(count), session.Dataset.Count())
	require.Len(t, session.EventStore.Events(), count)
	require.Zero(t, session.EventStore.Stats().TransportLost)
}

func TestOfflineTLSKeySnapshotAndRepeatedClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "keys.log")
	require.NoError(t, os.WriteFile(path, []byte("# immutable offline keys\n"), 0600))
	d, err := newOfflineTLSDecryptor(context.Background(), path)
	require.NoError(t, err)
	require.Nil(t, d.keyWatcher)
	require.NoError(t, os.WriteFile(path, []byte("CLIENT_RANDOM invalid invalid\n"), 0600))
	require.Zero(t, d.keyStore.Size())
	d.Stop()
	d.Stop()
	_, err = newOfflineTLSDecryptor(context.Background(), path)
	require.Error(t, err)
}

func TestOfflineIndexerPersistsSIPReleasedAtEOF(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gap.pcap")
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriter(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeRaw))
	at := time.Unix(100, 0)
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nFrom: <sip:alice@example.com>\r\nTo: <sip:bob@example.com>\r\nCall-ID: eof-call\r\nContent-Length: 0\r\n\r\n")
	split := len(message) / 2
	for _, env := range []*pipeline.PacketEnvelope{offlineSIPPacket(t, 100, []byte("x\r\n"), at), offlineSIPPacket(t, 200, message[:split], at.Add(time.Second)), offlineSIPPacket(t, uint32(200+split), message[split:], at.Add(2*time.Second))} {
		packet := env.Packet()
		require.NoError(t, writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()))
	}
	require.NoError(t, file.Close())
	storage := testOfflineStorage(t)
	session, err := indexOfflineDataset(context.Background(), storage, 30, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 32, SIPConfig: *voip.GetConfig()}, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, session.Close()) }()
	detail, err := session.Dataset.Detail(context.Background(), offline.Token{Dataset: 30}, 2)
	require.NoError(t, err)
	require.NotNil(t, detail.Packet.VoIPData)
	require.Equal(t, "eof-call", detail.Packet.VoIPData.CallID)
	require.True(t, at.Add(2*time.Second).Equal(detail.Packet.Timestamp))
	require.Equal(t, uint64(3), session.Dataset.Statistics().Packets)
	require.Equal(t, uint64(2), session.Dataset.Statistics().Protocols["SIP"])
	require.Len(t, session.Calls, 1)
	require.Equal(t, "eof-call", session.Calls[0].CallID)
}
