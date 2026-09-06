//go:build tui || all

package tui

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventanalysis"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/voip"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func analysisWorkerStorage(t *testing.T, cache uint64) *offline.Storage {
	t.Helper()
	s, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 128 << 20, CacheBytes: cache, MaxRecordBytes: 1 << 20, MaxSources: 4})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func analysisWorkerPacket(raw []byte, sequence uint64) capture.PacketInfo {
	packet := gopacket.NewPacket(raw, layers.LinkTypeEthernet, gopacket.NoCopy)
	packet.Metadata().CaptureInfo = gopacket.CaptureInfo{Timestamp: time.Unix(100+int64(sequence), 123), CaptureLength: len(raw), Length: len(raw) + 2}
	return capture.PacketInfo{Packet: packet, LinkType: layers.LinkTypeEthernet, SourceSequence: sequence, SourcePath: "fixture.pcap", Interface: "fixture.pcap"}
}

func TestOfflineAnalysisWorkerSnapshotsOrderAndResources(t *testing.T) {
	s := analysisWorkerStorage(t, 64<<20)
	var got []uint64
	w, err := newOfflineAnalysisWorker(context.Background(), s, func(source eventanalysis.Source, info capture.PacketInfo) error {
		if info.Packet.Data()[0] != byte(info.SourceSequence) || source.ProcessorNodeIDs[0] != "original" {
			return errors.New("borrowed snapshot mutated")
		}
		if info.Packet.Metadata().Timestamp != time.Unix(100+int64(info.SourceSequence), 123) {
			return errors.New("capture timestamp changed")
		}
		got = append(got, info.SourceSequence)
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, w)
	baseline := s.Resources().InFlightBytes
	for i := uint64(0); i < 100; i++ {
		raw := make([]byte, 5<<10)
		raw[0] = byte(i)
		source := eventanalysis.Source{ProcessorNodeIDs: []string{"original"}}
		require.NoError(t, w.Submit(source, analysisWorkerPacket(raw, i)))
		raw[0] = 255
		source.ProcessorNodeIDs[0] = "mutated"
	}
	require.Greater(t, s.Resources().InFlightBytes, baseline)
	require.NoError(t, w.Drain())
	require.Len(t, got, 100)
	for i := range got {
		require.EqualValues(t, i, got[i])
	}
	require.Equal(t, baseline, s.Resources().InFlightBytes)
	require.NoError(t, w.Close())
	require.NoError(t, w.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestOfflineAnalysisWorkerCancellationAndErrorsReleasePending(t *testing.T) {
	for _, cancelEarly := range []bool{false, true} {
		s := analysisWorkerStorage(t, 64<<20)
		ctx, cancel := context.WithCancel(context.Background())
		sentinel := errors.New("analysis failed")
		w, err := newOfflineAnalysisWorker(ctx, s, func(eventanalysis.Source, capture.PacketInfo) error { return sentinel })
		require.NoError(t, err)
		require.NoError(t, w.Submit(eventanalysis.Source{}, analysisWorkerPacket(make([]byte, 64), 0)))
		if cancelEarly {
			cancel()
			require.ErrorIs(t, w.Close(), context.Canceled)
		} else {
			require.ErrorIs(t, w.Drain(), sentinel)
			require.ErrorIs(t, w.Submit(eventanalysis.Source{}, analysisWorkerPacket(nil, 1)), sentinel)
			require.ErrorIs(t, w.Close(), sentinel)
		}
		cancel()
		require.Zero(t, s.Resources().InFlightBytes)
	}
}

func TestOfflineAnalysisWorkerSynchronousFallbacks(t *testing.T) {
	small := analysisWorkerStorage(t, 8<<20)
	w, err := newOfflineAnalysisWorker(context.Background(), small, nil)
	require.NoError(t, err)
	require.Nil(t, w)
	s := analysisWorkerStorage(t, 64<<20)
	var got []uint64
	w, err = newOfflineAnalysisWorker(context.Background(), s, func(_ eventanalysis.Source, info capture.PacketInfo) error {
		got = append(got, info.SourceSequence)
		return nil
	})
	require.NoError(t, err)
	require.NoError(t, w.Submit(eventanalysis.Source{}, analysisWorkerPacket(make([]byte, 64), 0)))
	require.NoError(t, w.Submit(eventanalysis.Source{}, analysisWorkerPacket(make([]byte, 70<<10), 1)))
	require.Equal(t, []uint64{0, 1}, got, "large packet must drain preceding work")
	held, err := s.ReserveTransient(context.Background(), s.MemoryLimit()-s.Resources().InFlightBytes)
	require.NoError(t, err)
	require.NoError(t, w.Submit(eventanalysis.Source{ProcessorNodeIDs: []string{"needs-reservation"}}, analysisWorkerPacket(make([]byte, 64), 2)))
	require.Equal(t, []uint64{0, 1, 2}, got, "admission failure uses ordered synchronous path")
	require.NoError(t, held.Close())
	require.NoError(t, w.Close())
	require.Zero(t, s.Resources().InFlightBytes)
}

func TestOfflineAnalysisWorkerFullOracle(t *testing.T) {
	cfg := OfflineAnalysisConfig{Inputs: append(writeLocatorSIPFixtures(t, "external"), writeCompactProtocolFixture(t)), VoIP: true, EventCapacity: 128, MaxCalls: 64, SIPConfig: *voip.GetConfig()}
	runOfflineCompactOracle(t, cfg, func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress)) (*offlineIndexedSession, error) {
		return indexOfflineDatasetBackendWithWorkers(ctx, storage, generation, cfg, report, nil, true, true, true, true)
	})
}
