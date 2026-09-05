//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/pipeline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineReleaseAnalyzerFinalizationFailureNeverPublishes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "eof-failure.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeRaw))
	at := time.Unix(100, 0)
	// The oversized SIP message is queued behind a TCP sequence gap. Only EOF
	// flushing can expose it to the analyzer, after all packet records were stored.
	message := []byte("INVITE sip:bob@example.com SIP/2.0\r\nX-Padding: " + strings.Repeat("a", 512) + "\r\nContent-Length: 0\r\n\r\n")
	for _, env := range []*pipeline.PacketEnvelope{offlineSIPPacket(t, 100, []byte("x\r\n"), at), offlineSIPPacket(t, 200, message, at.Add(time.Second))} {
		p := env.Packet()
		require.NoError(t, w.WritePacket(p.Metadata().CaptureInfo, p.Data()))
	}
	require.NoError(t, f.Close())
	storage := testOfflineStorage(t)
	cfg := *voip.GetConfig()
	cfg.Security.MaxMessageSize = 128
	// Independently establish that this exact input fails at finalization, not
	// during either Assemble call, before exercising the complete indexer.
	handler := NewTUISIPHandler(NewCallTracker(), nil)
	factory := newOfflineSIPFactory(handler, cfg)
	engine := pipeline.NewReassemblyEngine(factory, pipeline.DefaultReassemblyConfig())
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 100, []byte("x\r\n"), at)))
	require.NoError(t, engine.Assemble(offlineSIPPacket(t, 200, message, at.Add(time.Second))))
	require.NoError(t, factory.Err())
	require.ErrorContains(t, engine.Close(), "offline SIP frame exceeds")
	handler.Close()
	var ready bool
	session, err := indexOfflineDataset(context.Background(), storage, 71, OfflineAnalysisConfig{Inputs: []string{path}, VoIP: true, EventCapacity: 8, SIPConfig: cfg}, func(p offline.Progress) { ready = ready || p.State == offline.Ready })
	require.ErrorContains(t, err, "offline SIP frame exceeds")
	require.Nil(t, session)
	require.False(t, ready)
	require.Zero(t, storage.Resources().DiskBytes)
}

func TestOfflineReleaseLateSourceTruncationNeverPublishes(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	// Preserve valid headers and most records: this is a late source failure,
	// unlike an invalid header rejected before any packets are indexed.
	info, err := os.Stat(paths[0])
	require.NoError(t, err)
	require.NoError(t, os.Truncate(paths[0], info.Size()-1))
	storage := testOfflineStorage(t)
	var ready bool
	session, err := indexOfflineDataset(context.Background(), storage, 72, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 8}, func(p offline.Progress) { ready = ready || p.State == offline.Ready })
	require.Error(t, err)
	require.Nil(t, session)
	require.False(t, ready)
	require.Zero(t, storage.Resources().DiskBytes)
}
