package offline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/google/gopacket/layers"
	"github.com/stretchr/testify/require"
)

// The reference reads fixture values directly, without Summary, query iteration,
// or the production statistics accumulator. It covers every statistics field.
func TestReleaseStatisticsAndDetailsFullScanReference(t *testing.T) {
	const count = 12017
	ctx := context.Background()
	s, err := NewStorage(ResourceLimits{Directory: t.TempDir(), DiskBytes: 128 << 20, CacheBytes: 128 << 10, MaxRecordBytes: 32 << 10, MaxSources: 3})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, s.Close()) })
	fixture := func(i int) Detail {
		raw := make([]byte, 128+i%193)
		for j := range raw {
			raw[j] = byte(i + j*7)
		}
		return Detail{ID: PacketID(i), Source: SourcePosition{ArgumentIndex: uint32(i % 3), Path: fmt.Sprintf("/source/%d/capture.pcap", i%3), Sequence: uint64(i / 3)}, CapturedLength: uint32(len(raw)), OriginalLength: uint32(len(raw) + i%5), Packet: types.PacketDisplay{Timestamp: time.Unix(1700000000+int64(i/7), int64(i%7)*100).UTC(), SrcIP: fmt.Sprintf("192.0.2.%d", i%17+1), DstIP: fmt.Sprintf("198.51.100.%d", i%11+1), SrcPort: "12345", DstPort: "53", Protocol: []string{"UDP", "DNS", "TCP", "TLS"}[i%4], Transport: []uint8{17, 17, 6, 6}[i%4], Length: len(raw) + i%5, RawData: raw, LinkType: layers.LinkTypeRaw, Info: fmt.Sprintf("packet %d", i)}}
	}
	reference := func(match func(int) bool) Statistics {
		st := Statistics{Protocols: map[string]uint64{}, SourceCounts: map[string]uint64{}, DestinationCounts: map[string]uint64{}}
		for i := 0; i < count; i++ {
			if !match(i) {
				continue
			}
			p := fixture(i).Packet
			st.Packets++
			st.Bytes += uint64(p.Length)
			st.Protocols[p.Protocol]++
			st.SourceCounts[p.SrcIP]++
			st.DestinationCounts[p.DstIP]++
			if st.Packets == 1 {
				st.First = p.Timestamp
				st.MinPacketSize = uint64(p.Length)
			}
			st.Last = p.Timestamp
			if uint64(p.Length) < st.MinPacketSize {
				st.MinPacketSize = uint64(p.Length)
			}
			if uint64(p.Length) > st.MaxPacketSize {
				st.MaxPacketSize = uint64(p.Length)
			}
		}
		st.Sources = uint64(len(st.SourceCounts))
		st.Destinations = uint64(len(st.DestinationCounts))
		return st
	}
	b, err := s.NewBuilder(61, nil)
	require.NoError(t, err)
	for i := 0; i < count; i++ {
		require.NoError(t, b.Append(ctx, fixture(i)))
	}
	ds, err := b.Finish(ctx)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, ds.Close()) })
	wantGlobal := reference(func(int) bool { return true })
	require.Equal(t, wantGlobal, ds.Statistics())
	token := Token{Dataset: 61, Query: 1, Request: 7}
	q, err := ds.Query(ctx, QuerySpec{Token: token, Match: func(s Summary) bool { return s.ID%4 == 1 }})
	require.NoError(t, err)
	defer func() { require.NoError(t, q.Close()) }()
	require.Equal(t, reference(func(i int) bool { return i%4 == 1 }), q.Statistics())
	d := ds.(*diskDataset)
	for _, id := range []PacketID{0, count / 2, count - 1} {
		got, err := ds.Detail(ctx, token, id)
		require.NoError(t, err)
		expected := fixture(int(id))
		expected.Token = token
		require.Equal(t, expected, got)
		// Populate substantially more than the fixed cache budget, then prove that
		// the selected frame has actually left the cache before checking its reload.
		for j := 1; j <= 400; j++ {
			_, err := ds.Detail(ctx, token, PacketID((int(id)+j)%count))
			require.NoError(t, err)
		}
		s.mu.Lock()
		_, cached := s.cache[cacheKey{d, id, recordKindDetail}]
		s.mu.Unlock()
		require.False(t, cached, "selected detail must be evicted")
		got, err = ds.Detail(ctx, token, id)
		require.NoError(t, err)
		require.Equal(t, expected, got)
	}
	require.Equal(t, wantGlobal, ds.Statistics(), "cache traffic must not alter totals")
}

func TestReleaseStorageOSDiskFullNeverPublishes(t *testing.T) {
	full, err := os.OpenFile("/dev/full", os.O_WRONLY, 0)
	if os.IsNotExist(err) {
		t.Skip("OS disk-full injection requires /dev/full")
	}
	require.NoError(t, err)
	s := newTestStorage(t)
	b, err := s.NewBuilder(1, nil)
	require.NoError(t, err)
	require.NoError(t, b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: 1}}))
	original := b.d.summaries
	b.d.summaries = full
	err = b.Append(context.Background(), Detail{Packet: types.PacketDisplay{Length: 1}})
	require.ErrorIs(t, err, syscall.ENOSPC)
	b.d.summaries = original
	require.NoError(t, full.Close())
	ds, err := b.Finish(context.Background())
	require.Error(t, err)
	require.Nil(t, ds)
	_, err = os.Stat(filepath.Join(b.d.dir, "manifest"))
	require.True(t, os.IsNotExist(err))
	require.NoError(t, b.Close())
	require.Zero(t, s.Resources().DiskBytes)
	require.NoError(t, s.Close())
}

func TestReleaseStoragePermissionDenied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	directory := t.TempDir()
	s, err := NewStorage(ResourceLimits{Directory: directory, DiskBytes: 8 << 20, CacheBytes: 1 << 20, MaxRecordBytes: 16 << 10, MaxSources: 1})
	require.NoError(t, err)
	require.NoError(t, os.Chmod(directory, 0500))
	t.Cleanup(func() { require.NoError(t, os.Chmod(directory, 0700)); require.NoError(t, s.Close()) })
	b, err := s.NewBuilder(1, nil)
	require.ErrorIs(t, err, os.ErrPermission)
	require.Nil(t, b)
	require.Zero(t, s.Resources().DiskBytes)
	entries, err := os.ReadDir(directory)
	require.NoError(t, err)
	require.Empty(t, entries)
}
