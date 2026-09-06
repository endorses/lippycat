package capture

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// Independent review: a small sorting budget must hold a source whose packet
// bytes would exhaust it, and packets retained across batch boundaries must own
// their bytes even after all source handles and replay leases close.
func TestOfflineLocatorReviewRetainedBytesAndReplacement(t *testing.T) {
	const count = 160
	frames := make([][]byte, count)
	for i := range frames {
		frames[i] = make([]byte, 4096)
		copy(frames[i][20:], bytes.Repeat([]byte{byte(i)}, 4000))
	}
	path := filepath.Join(t.TempDir(), "source.pcap")
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, frames, false, false), 0600))
	storage := sortTestStorage(t, 64<<10)
	stream, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, stream.Close()) })
	require.Equal(t, "direct", stream.Ordering())
	require.Less(t, storage.Resources().DiskBytes, uint64(64<<10), "ordinary bytes must remain in the source")
	require.NoError(t, os.Rename(path, path+".old"))
	require.NoError(t, os.WriteFile(path, []byte("replacement is not a capture"), 0600))
	var retained []PacketInfo
	require.NoError(t, stream.Replay(context.Background(), func(_ context.Context, packets <-chan PacketInfo) error {
		for packet := range packets {
			retained = append(retained, packet)
		}
		return nil
	}))
	require.NoError(t, stream.Close())
	require.Len(t, retained, count)
	for i, packet := range retained {
		require.Equal(t, frames[i], packet.Packet.Data())
		require.EqualValues(t, i, packet.SourceSequence)
		require.Equal(t, path, packet.SourcePath)
	}
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineLocatorReviewMutationWithRestoredMetadata(t *testing.T) {
	path := filepath.Join(t.TempDir(), "source.pcap")
	frame := make([]byte, 128)
	require.NoError(t, os.WriteFile(path, provenanceCapture(t, layers.LinkTypeEthernet, [][]byte{frame}, false, false), 0600))
	storage := sortTestStorage(t, 64<<10)
	stream, err := PrepareOfflineLocatorStream(context.Background(), offlineTestDevices(t, path), "", storage, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, stream.Close()) })
	info, err := os.Stat(path)
	require.NoError(t, err)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	require.NoError(t, err)
	_, writeErr := f.WriteAt([]byte{1}, 24+16+100)
	closeErr := f.Close()
	require.NoError(t, writeErr)
	require.NoError(t, closeErr)
	require.NoError(t, os.Chtimes(path, info.ModTime(), info.ModTime()))
	count := 0
	err = stream.Replay(context.Background(), func(_ context.Context, packets <-chan PacketInfo) error {
		for range packets {
			count++
		}
		return nil
	})
	require.ErrorIs(t, err, offline.ErrSourceChanged)
	require.Zero(t, count, "a corrupt batch must expose no bytes")
	require.NoError(t, stream.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.Zero(t, storage.Resources().InFlightBytes)
}

func TestOfflineLocatorReviewPCAPNGOrdering(t *testing.T) {
	for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
		for _, packetType := range []uint32{2, 3, 6} {
			for _, mode := range []string{"direct", "heap", "external"} {
				t.Run(fmt.Sprintf("%s/type%d/%s", order, packetType, mode), func(t *testing.T) {
					resolution := byte(0x8a)
					ticks := []uint64{1023, 2047, 3071}
					wantMode := mode
					if mode == "external" {
						ticks[2] = 1
						if packetType == 3 {
							wantMode = "direct" // Simple packet blocks have no timestamps.
						}
					}
					path := filepath.Join(t.TempDir(), "source.pcapng")
					require.NoError(t, os.WriteFile(path, readerTestNGCapture(order, &resolution, -4, 1, packetType, ticks, 8193), 0600))
					paths := []string{path}
					if mode == "heap" {
						paths = append(paths, path)
					}
					compareLocatorSorter(t, context.Background(), paths, "", wantMode)
				})
			}
		}
	}
}
