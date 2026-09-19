package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func sortTestStorage(t *testing.T, disk uint64) *offline.Storage {
	t.Helper()
	s, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: disk, CacheBytes: 1 << 20, MaxRecordBytes: 64 << 10, MaxSources: 64})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	return s
}

func TestOfflineSortExternalMergePreservesRecords(t *testing.T) {
	type record struct {
		source uint32
		seq    uint64
		ci     gopacket.CaptureInfo
		raw    []byte
	}
	var reference []record
	var paths []string
	for source, count := range []int{10013, 9007} {
		path := filepath.Join(t.TempDir(), "same.pcap")
		paths = append(paths, path)
		f, err := os.Create(path)
		require.NoError(t, err)
		w := pcapgo.NewWriterNanos(f)
		require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
		for i := range count {
			data := make([]byte, 64+i%17)
			copy(data, fmt.Sprintf("source%d/packet%d", source, i))
			ci := gopacket.CaptureInfo{Timestamp: time.Unix(100+int64((count-i)%47), int64(i%3)).UTC(), CaptureLength: len(data), Length: len(data) + i%7}
			require.NoError(t, w.WritePacket(ci, data))
			reference = append(reference, record{uint32(source), uint64(i), ci, data})
		}
		require.NoError(t, f.Close())
	}
	sort.SliceStable(reference, func(i, j int) bool { return reference[i].ci.Timestamp.Before(reference[j].ci.Timestamp) })
	s := sortTestStorage(t, 16<<20)
	var phases []string
	i := 0
	cleanup, err := RunOfflineSortedStream(context.Background(), offlineTestDevices(t, paths...), "", s, func(p OfflineSortProgress) {
		if len(phases) == 0 || phases[len(phases)-1] != p.Phase {
			phases = append(phases, p.Phase)
		}
	}, func(_ context.Context, packets <-chan PacketInfo) error {
		for packet := range packets {
			want := reference[i]
			if packet.SourceIndex != want.source || packet.SourceSequence != want.seq || packet.SourcePath != paths[want.source] || packet.Interface != "same.pcap" {
				return fmt.Errorf("source identity mismatch at %d", i)
			}
			if string(packet.Packet.Data()) != string(want.raw) || !packet.Packet.Metadata().Timestamp.Equal(want.ci.Timestamp) || packet.Packet.Metadata().CaptureLength != want.ci.CaptureLength || packet.Packet.Metadata().Length != want.ci.Length || packet.LinkType != layers.LinkTypeEthernet {
				return fmt.Errorf("record mismatch at %d", i)
			}
			i++
		}
		return nil
	})
	require.NoError(t, err)
	require.Nil(t, cleanup)
	require.Equal(t, len(reference), i)
	require.Equal(t, []string{"Reading", "Sorting", "Replaying"}, phases)
	require.Zero(t, s.Resources().DiskBytes)
}

func TestOfflineSortFailureAndCancellationCleanup(t *testing.T) {
	for _, scenario := range []string{"disk", "truncation", "reading cancellation", "sorting cancellation", "consumer failure", "early consumer"} {
		t.Run(scenario, func(t *testing.T) {
			times := make([]time.Time, 10000)
			for i := range times {
				times[i] = time.Unix(int64(len(times)-i), 0)
			}
			path := writeTimestampedTestPCAP(t, times)
			if scenario == "truncation" {
				st, err := os.Stat(path)
				require.NoError(t, err)
				require.NoError(t, os.Truncate(path, st.Size()-1))
			}
			disk := uint64(8 << 20)
			if scenario == "disk" {
				disk = 64 << 10
			}
			s := sortTestStorage(t, disk)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			called := false
			cleanup, err := RunOfflineSortedStream(ctx, offlineTestDevices(t, path), "", s, func(p OfflineSortProgress) {
				if (scenario == "reading cancellation" && p.Phase == "Reading") || (scenario == "sorting cancellation" && p.Phase == "Sorting") {
					cancel()
				}
			}, func(_ context.Context, packets <-chan PacketInfo) error {
				called = true
				if scenario == "consumer failure" {
					return errors.New("injected consumer failure")
				}
				if scenario == "early consumer" {
					return nil
				}
				for range packets {
				}
				return nil
			})
			require.Error(t, err)
			require.Nil(t, cleanup)
			require.Zero(t, s.Resources().DiskBytes)
			if scenario != "consumer failure" && scenario != "early consumer" {
				require.False(t, called, "failed source must never start analysis")
			}
			if scenario == "early consumer" {
				require.ErrorIs(t, err, ErrOfflineConsumerStopped)
			}
		})
	}
}

func TestOfflineSortEmptyInputs(t *testing.T) {
	s := sortTestStorage(t, 1<<20)
	cleanup, err := RunOfflineSortedStream(context.Background(), nil, "", s, nil, func(_ context.Context, packets <-chan PacketInfo) error {
		for range packets {
			return errors.New("unexpected packet")
		}
		return nil
	})
	require.NoError(t, err)
	require.Nil(t, cleanup)
	require.Zero(t, s.Resources().DiskBytes)
}

func TestOfflineSortSignedTimestampComparison(t *testing.T) {
	var keys []offlineSortKey
	for _, at := range []time.Time{time.Date(12000, 1, 1, 0, 0, 0, 0, time.UTC), {}, time.Unix(-1, 999), time.Unix(0, 0)} {
		var key offlineSortKey
		binary.LittleEndian.PutUint64(key[:], uint64(at.Unix()))
		binary.LittleEndian.PutUint32(key[8:], uint32(at.Nanosecond()))
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].less(keys[j]) })
	require.Equal(t, time.Time{}.Unix(), int64(binary.LittleEndian.Uint64(keys[0][:])))
	require.EqualValues(t, -1, int64(binary.LittleEndian.Uint64(keys[1][:])))
	require.EqualValues(t, 0, int64(binary.LittleEndian.Uint64(keys[2][:])))
}

func TestOfflineSortNormalizesBeforeOrdering(t *testing.T) {
	// File order is required for fragment assembly, even though its timestamps
	// regress. Sorting the original fragments first would assign the wrong
	// completion timestamp. The sorter must preserve the normalizer's result.
	udp := make([]byte, 32)
	binary.BigEndian.PutUint16(udp[:2], 4000)
	binary.BigEndian.PutUint16(udp[2:4], 4001)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], "fragmented-payload")
	src, dst := net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")
	frames := [][]byte{
		fragFrame(t, src, dst, 42, 0, true, udp[:16]),
		fragFrame(t, src, dst, 99, 0, false, udp),
		fragFrame(t, src, dst, 42, 2, false, udp[16:]),
	}
	path := filepath.Join(t.TempDir(), "fragments.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	w := pcapgo.NewWriter(f)
	require.NoError(t, w.WriteFileHeader(65535, layers.LinkTypeEthernet))
	for i, data := range frames {
		require.NoError(t, w.WritePacket(gopacket.CaptureInfo{Timestamp: time.Unix(int64(4-i), 0), CaptureLength: len(data), Length: len(data)}, data))
	}
	require.NoError(t, f.Close())
	s := sortTestStorage(t, 1<<20)
	var got []PacketInfo
	cleanup, err := RunOfflineSortedStream(context.Background(), offlineTestDevices(t, path), "ip6", s, nil, func(_ context.Context, packets <-chan PacketInfo) error {
		for p := range packets {
			got = append(got, p)
		}
		return nil
	})
	require.NoError(t, err)
	require.Nil(t, cleanup)
	require.Len(t, got, 2)
	require.EqualValues(t, 1, got[0].SourceSequence)
	require.Equal(t, time.Unix(2, 0).UTC(), got[0].Packet.Metadata().Timestamp)
	require.EqualValues(t, 0, got[1].SourceSequence)
	require.Equal(t, time.Unix(3, 0).UTC(), got[1].Packet.Metadata().Timestamp)
	for _, p := range got {
		require.Nil(t, p.Packet.Layer(layers.LayerTypeIPv6Fragment))
		require.Equal(t, string(udp[8:]), string(p.Packet.Layer(layers.LayerTypeUDP).LayerPayload()))
		require.Equal(t, len(p.Packet.Data()), p.Packet.Metadata().CaptureLength)
	}
}
