package capture

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

func TestOfflineLocatorVisitorOrderAndObserverOwnership(t *testing.T) {
	const count = 160 // Cross the default 64-record replay lease boundary.
	frames := make([][]byte, count)
	for i := range frames {
		frames[i] = bytes.Repeat([]byte{byte(i)}, 4096)
	}
	path := filepath.Join(t.TempDir(), "source.pcap")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, frames, false, false), 0600))
	storage := sortTestStorage(t, 64<<10)
	stream, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, stream.Close()) }()
	var retained []PacketInfo
	var borrowed *byte
	restore := SetPacketObserver(func(info *PacketInfo) {
		require.NotSame(t, borrowed, &info.Packet.Data()[0], "observers must receive owned raw bytes")
		retained = append(retained, *info)
	})
	defer restore()
	visited := 0
	require.NoError(t, stream.ReplayPackets(context.Background(), func(_ context.Context, info PacketInfo) error {
		require.EqualValues(t, visited, info.SourceSequence)
		require.Equal(t, frames[visited], info.Packet.Data())
		borrowed = &info.Packet.Data()[0]
		visited++
		return nil
	}))
	require.NoError(t, stream.Close())
	require.Equal(t, count, visited)
	require.Len(t, retained, count)
	for i, info := range retained {
		require.Equal(t, frames[i], info.Packet.Data())
		require.EqualValues(t, i, info.Provenance.LogicalSequence)
	}
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineLocatorVisitorCancellationAndFailureReleaseLease(t *testing.T) {
	for _, cancelVisit := range []bool{false, true} {
		t.Run(map[bool]string{false: "visitor error", true: "cancellation"}[cancelVisit], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source.pcap")
			frames := make([][]byte, 160)
			for i := range frames {
				frames[i] = make([]byte, 128)
			}
			require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, frames, false, false), 0600))
			storage := sortTestStorage(t, 64<<10)
			stream, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
			require.NoError(t, err)
			defer func() { require.NoError(t, stream.Close()) }()
			baseline := storage.Resources().InFlightBytes
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			failure := errors.New("visitor failed")
			visited := 0
			err = stream.ReplayPackets(ctx, func(_ context.Context, _ PacketInfo) error {
				visited++
				if cancelVisit {
					cancel()
					return nil
				}
				return failure
			})
			if cancelVisit {
				require.ErrorIs(t, err, context.Canceled)
			} else {
				require.ErrorIs(t, err, failure)
			}
			require.Equal(t, 1, visited)
			require.Equal(t, baseline, storage.Resources().InFlightBytes)
			require.NoError(t, stream.Close())
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
		})
	}
}
