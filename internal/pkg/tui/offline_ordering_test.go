//go:build tui || all

package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineOrderingPublishesSortedDatasetAndCancelsReplacement(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	// Both files regress, with ties within and across sources. Unique payloads
	// let us verify source identity and raw data independently of display order.
	timestamps := [][]int64{{3, 1, 1}, {2, 1, 0}}
	var paths []string
	raw := make([][][]byte, len(timestamps))
	for source, times := range timestamps {
		path := filepath.Join(t.TempDir(), fmt.Sprintf("source-%d.pcap", source))
		f, err := os.Create(path)
		require.NoError(t, err)
		writer := pcapgo.NewWriterNanos(f)
		require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for sequence, timestamp := range times {
			packet := goldenUDPPacket(t, 32000, 32001, []byte(fmt.Sprintf("source=%d sequence=%d", source, sequence)))
			raw[source] = append(raw[source], packet)
			require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{
				Timestamp: time.Unix(1700000000, timestamp), CaptureLength: len(packet), Length: len(packet),
			}, packet))
		}
		require.NoError(t, f.Close())
		paths = append(paths, path)
	}
	open.Config.Inputs = paths
	var phases []offline.State
	m.offlineController.index = func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		return indexOfflineDataset(ctx, storage, generation, cfg, func(p offline.Progress) {
			if len(phases) == 0 || phases[len(phases)-1] != p.State {
				phases = append(phases, p.State)
			}
			report(p)
		})
	}
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	require.Nil(t, m.offlineSession, "no publication before successful completion")
	require.Equal(t, []offline.State{offline.Reading, offline.Sorting, offline.Indexing, offline.Finalizing, offline.Ready}, phases)
	m, cleanup := m.completeOffline(result)
	cleanup()
	require.False(t, m.offlineOpening)
	require.EqualValues(t, 6, m.uiState.PacketList.LogicalCount())
	dataset := m.offlineSession.Dataset
	for id, sourceSequence := range [][2]int{{1, 2}, {0, 1}, {0, 2}, {1, 1}, {1, 0}, {0, 0}} {
		source, sequence := sourceSequence[0], sourceSequence[1]
		detail, err := dataset.Detail(context.Background(), offline.Token{Dataset: dataset.Generation()}, offline.PacketID(id))
		require.NoError(t, err)
		require.Equal(t, raw[source][sequence], detail.Packet.RawData)
		require.Equal(t, offline.SourcePosition{ArgumentIndex: uint32(source), Path: paths[source], Sequence: uint64(sequence)}, detail.Source)
		require.Equal(t, time.Unix(1700000000, timestamps[source][sequence]).UTC(), detail.Packet.Timestamp)
		require.Equal(t, layers.LinkTypeEthernet, detail.Packet.LinkType)
		require.EqualValues(t, len(raw[source][sequence]), detail.CapturedLength)
		require.Equal(t, detail.CapturedLength, detail.OriginalLength)
	}
	require.Equal(t, time.Unix(1700000000, 0).UTC(), dataset.Statistics().First)
	require.Equal(t, time.Unix(1700000000, 3).UTC(), dataset.Statistics().Last)

	// Cancel the real replacement indexer at the sorting phase. It must reclaim
	// its temporary sort storage while leaving the published session intact.
	ready, events, statistics := m.offlineSession, m.eventStore, *m.statistics
	diskBytes := dataset.Resources().DiskBytes
	sorting := make(chan struct{})
	m.offlineController.index = func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		return indexOfflineDataset(ctx, storage, generation, cfg, func(p offline.Progress) {
			report(p)
			if p.State == offline.Sorting {
				select {
				case <-sorting:
				default:
					close(sorting)
				}
				<-ctx.Done()
			}
		})
	}
	m, cmd = m.openOffline(open)
	select {
	case <-sorting:
	case <-time.After(5 * time.Second):
		t.Fatal("replacement did not reach sorting")
	}
	m, _ = m.cancelOffline()
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.ErrorIs(t, result.err, context.Canceled)
	m, cleanup = m.completeOffline(result)
	updated, _ := m.update(cleanup())
	m = updated.(Model)
	require.False(t, m.offlineOpening)
	require.Same(t, ready, m.offlineSession)
	require.Same(t, events, m.eventStore)
	require.Equal(t, statistics, *m.statistics)
	require.Equal(t, diskBytes, dataset.Resources().DiskBytes)
	require.Equal(t, paths, m.pcapFiles)
}
