package capture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func compareLocatorSorter(t *testing.T, ctx context.Context, paths []string, filter, mode string) {
	t.Helper()
	storage := sortTestStorage(t, 32<<20)
	devices := offlineTestDevices(t, paths...)
	var want, got []PacketInfo
	collect := func(dst *[]PacketInfo) func(context.Context, <-chan PacketInfo) error {
		return func(_ context.Context, packets <-chan PacketInfo) error {
			for p := range packets {
				*dst = append(*dst, p)
			}
			return nil
		}
	}
	cleanup, err := RunOfflineSortedStream(ctx, devices, filter, storage, nil, collect(&want))
	require.NoError(t, err)
	require.Nil(t, cleanup)
	stream, err := PrepareOfflineLocatorStream(ctx, devices, filter, storage, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	require.Equal(t, mode, stream.Ordering())
	require.NoError(t, stream.Replay(ctx, collect(&got)))
	require.Len(t, got, len(want))
	for i, p := range got {
		w := want[i]
		require.Equal(t, w.Packet.Data(), p.Packet.Data(), "packet %d", i)
		require.Equal(t, w.Packet.Metadata().CaptureInfo, p.Packet.Metadata().CaptureInfo)
		require.Equal(t, w.LinkType, p.LinkType)
		require.Equal(t, w.SourcePath, p.SourcePath)
		require.Equal(t, w.SourceIndex, p.SourceIndex)
		require.Equal(t, w.SourceSequence, p.SourceSequence)
		require.Equal(t, w.SourceInterfaceID, p.SourceInterfaceID)
		require.NotNil(t, p.Provenance)
	}
}
func TestOfflineLocatorOrderingPaths(t *testing.T) {
	for _, mode := range []string{"direct", "heap", "external"} {
		t.Run(mode, func(t *testing.T) {
			times := make([]time.Time, 10013)
			for i := range times {
				times[i] = time.Unix(100+int64(i/3), 123)
			}
			if mode == "external" {
				times[len(times)-1] = time.Unix(1, 99)
			}
			path := writeTimestampedTestPCAP(t, times)
			paths := []string{path}
			if mode == "heap" {
				paths = append(paths, path, writeTimestampedTestPCAP(t, []time.Time{time.Unix(5, 0), time.Unix(100, 0)}))
			}
			compareLocatorSorter(t, context.Background(), paths, "", mode)
		})
	}
}

func compareLocatorTransform(t *testing.T, ctx context.Context, link layers.LinkType, frames [][]byte, filter string) {
	t.Helper()
	for _, mode := range []string{"direct", "heap", "external"} {
		t.Run("ordering-"+mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "normalized.pcap")
			f, err := os.Create(path)
			require.NoError(t, err)
			writer := pcapgo.NewWriterNanos(f)
			require.NoError(t, writer.WriteFileHeader(65535, link))
			all := append(append([][]byte(nil), frames...), frames...)
			for i, data := range all {
				sec := int64(100 + i)
				if mode == "external" && i == len(all)-1 {
					sec = 1
				}
				require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(sec, 123), CaptureLength: len(data), Length: len(data)}, data))
			}
			require.NoError(t, f.Close())
			paths := []string{path}
			if mode == "heap" {
				paths = append(paths, path)
			}
			compareLocatorSorter(t, ctx, paths, filter, mode)
		})
	}
}

func TestOfflineLocatorFailures(t *testing.T) {
	for _, scenario := range []string{"disk", "scan-cancel", "sort-cancel", "consumer-error", "consumer-stop", "header", "key"} {
		t.Run(scenario, func(t *testing.T) {
			times := make([]time.Time, 5000)
			for i := range times {
				times[i] = time.Unix(int64(len(times)-i), 0)
			}
			path := writeTimestampedTestPCAP(t, times)
			disk := uint64(8 << 20)
			if scenario == "disk" {
				disk = 64 << 10
			}
			storage := sortTestStorage(t, disk)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			stream, err := PrepareOfflineLocatorStream(ctx, offlineTestDevices(t, path), "", storage, func(p OfflineSortProgress) {
				if scenario == "scan-cancel" && p.Phase == "Reading" {
					cancel()
				}
				if scenario == "sort-cancel" && p.Phase == "Sorting" {
					cancel()
				}
			})
			if scenario == "disk" || scenario == "scan-cancel" || scenario == "sort-cancel" {
				require.Error(t, err)
				if stream != nil {
					require.NoError(t, stream.Close())
				}
				require.Zero(t, storage.Resources().DiskBytes)
				require.Zero(t, storage.Resources().InFlightBytes)
				return
			}
			require.NoError(t, err)
			if scenario == "header" || scenario == "key" {
				var data []byte
				if scenario == "header" {
					data = make([]byte, locatorHeaderBytes)
				} else {
					data = append(append([]byte(nil), locatorHeader[:]...), make([]byte, locatorKeyBytes)...)
				}
				require.NoError(t, stream.index.Reset())
				_, err = stream.index.Write(data)
				require.NoError(t, err)
			}
			sentinel := errors.New("consumer failed")
			err = stream.Replay(ctx, func(_ context.Context, ch <-chan PacketInfo) error {
				if scenario == "consumer-error" {
					return sentinel
				}
				if scenario == "consumer-stop" {
					return nil
				}
				for range ch {
				}
				return nil
			})
			require.Error(t, err)
			if scenario == "consumer-error" {
				require.ErrorIs(t, err, sentinel)
			}
			if scenario == "consumer-stop" {
				require.ErrorIs(t, err, ErrOfflineConsumerStopped)
			}
			require.NoError(t, stream.Close())
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}

func TestOfflineLocatorKeyRoundTrip(t *testing.T) {
	path := writeTimestampedTestPCAP(t, []time.Time{time.Unix(-1, 123)})
	storage := sortTestStorage(t, 1<<20)
	s, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, s.Close()) }()
	require.NoError(t, s.Replay(context.Background(), func(_ context.Context, ch <-chan PacketInfo) error {
		for p := range ch {
			k, err := encodeLocatorKey(p)
			if err != nil {
				return err
			}
			if err = k.validate(1); err != nil {
				return err
			}
			again := k.packet(p.Packet.Data(), s.devices)
			if fmt.Sprint(p.Provenance) != fmt.Sprint(again.Provenance) {
				return errors.New("provenance roundtrip mismatch")
			}
		}
		return nil
	}))
	var key locatorKey
	_, err = s.index.ReadAt(key[:], locatorHeaderBytes)
	require.NoError(t, err)
	_, err = s.index.ReadAt(key[:], locatorHeaderBytes+locatorKeyBytes)
	require.ErrorIs(t, err, io.EOF)
}

func TestOfflineLocatorEmptyAndFiltered(t *testing.T) {
	for _, inputs := range [][]string{nil, {writeTimestampedTestPCAP(t, nil)}, {writeTimestampedTestPCAP(t, []time.Time{time.Unix(10, 0)})}} {
		compareLocatorSorter(t, context.Background(), inputs, "tcp port 1", "direct")
	}
}
