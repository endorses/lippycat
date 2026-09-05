package offline

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestBuilderUpdateDetailPersistsLatestFramesAndStatistics(t *testing.T) {
	ctx := context.Background()
	storage := newTestStorage(t)
	b, err := storage.NewBuilder(12, nil)
	require.NoError(t, err)
	require.NoError(t, b.Append(ctx, Detail{Source: SourcePosition{Path: "source.pcap"}, Packet: types.PacketDisplay{Length: 3, RawData: []byte{1, 2, 3}, Protocol: "TCP"}}))
	require.NoError(t, b.Append(ctx, Detail{Packet: types.PacketDisplay{Length: 7, Protocol: "UDP"}}))
	initial := storage.Resources().DiskBytes
	for _, callID := range []string{"first", "final"} {
		require.NoError(t, b.UpdateDetail(ctx, 0, func(d *Detail) error {
			d.ID = 999 // Identity cannot be changed by finalization.
			d.Packet.Protocol = "SIP"
			d.Packet.Length = 5
			d.Packet.VoIPData = &types.VoIPMetadata{CallID: callID}
			return nil
		}))
	}
	// A normal append after amendments must preserve the offset table position.
	require.NoError(t, b.Append(ctx, Detail{Packet: types.PacketDisplay{Length: 2, Protocol: "DNS"}}))
	require.Greater(t, storage.Resources().DiskBytes, initial)
	dataset, err := b.Finish(ctx)
	require.NoError(t, err)
	require.Equal(t, uint64(3), dataset.Count())
	stats := dataset.Statistics()
	require.Equal(t, uint64(14), stats.Bytes)
	require.Equal(t, uint64(2), stats.MinPacketSize)
	require.Equal(t, uint64(7), stats.MaxPacketSize)
	require.Equal(t, map[string]uint64{"SIP": 1, "UDP": 1, "DNS": 1}, stats.Protocols)
	detail, err := dataset.Detail(ctx, Token{Dataset: 12}, 0)
	require.NoError(t, err)
	require.Equal(t, PacketID(0), detail.ID)
	require.Equal(t, "final", detail.Packet.VoIPData.CallID)
	require.Equal(t, "source.pcap", detail.Source.Path)
	require.Equal(t, []byte{1, 2, 3}, detail.Packet.RawData)
	for id := PacketID(0); id < 3; id++ {
		_, err := dataset.Detail(ctx, Token{Dataset: 12}, id)
		require.NoError(t, err)
	}
	entries, err := os.ReadDir(b.d.dir)
	require.NoError(t, err)
	var physical uint64
	for _, entry := range entries {
		info, err := entry.Info()
		require.NoError(t, err)
		physical += uint64(info.Size())
	}
	require.Equal(t, physical, storage.Resources().DiskBytes)
	require.NoError(t, dataset.Close())
	require.Zero(t, storage.Resources().DiskBytes)
	require.NoError(t, storage.Close())
}

func TestBuilderUpdateDetailFailureNeverPublishes(t *testing.T) {
	for _, stage := range []string{"callback", "cancel", "disk", "write", "out-of-range", "oversize"} {
		t.Run(stage, func(t *testing.T) {
			storage := newTestStorage(t)
			b, err := storage.NewBuilder(1, nil)
			require.NoError(t, err)
			require.NoError(t, b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: 3, Protocol: "TCP"}}))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			id := PacketID(0)
			if stage == "cancel" {
				cancel()
			}
			if stage == "disk" {
				storage.limits.DiskBytes = storage.Resources().DiskBytes
			}
			if stage == "out-of-range" {
				id = 1
			}
			if stage == "write" {
				require.NoError(t, b.d.summaries.Close())
			}
			err = b.UpdateDetail(ctx, id, func(d *Detail) error {
				if stage == "callback" {
					return errors.New("analyzer finalization failed")
				}
				if stage == "oversize" {
					d.Packet.RawData = make([]byte, 32<<10)
				}
				d.Packet.Protocol = "SIP"
				return nil
			})
			require.Error(t, err)
			_, err = b.Finish(context.Background())
			require.Error(t, err)
			_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
			require.True(t, os.IsNotExist(err))
			if stage == "write" {
				require.Error(t, b.Close())
			} else {
				require.NoError(t, b.Close())
			}
			require.Zero(t, storage.Resources().DiskBytes)
			require.Zero(t, storage.Resources().InFlightBytes)
			require.NoError(t, storage.Close())
		})
	}
}
