//go:build tui || all

package tui

import (
	"context"
	"io"
	"os"
	"sort"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Read sources independently with pcapgo and stable-sort the small test-only
// reference. This deliberately bypasses the production cursor/merge, indexer,
// summary adapter and statistics accumulator.
func TestOfflineReleaseIndexerFullScanReference(t *testing.T) {
	paths := writeOrderedBridgeFixtures(t)
	type referenceRecord struct {
		raw    []byte
		ci     gopacket.CaptureInfo
		source offline.SourcePosition
		link   layers.LinkType
	}
	var reference []referenceRecord
	for source, path := range paths {
		f, err := os.Open(path)
		require.NoError(t, err)
		r, err := pcapgo.NewReader(f)
		require.NoError(t, err)
		for seq := uint64(0); ; seq++ {
			raw, ci, err := r.ReadPacketData()
			if err == io.EOF {
				break
			}
			require.NoError(t, err)
			reference = append(reference, referenceRecord{raw: raw, ci: ci, source: offline.SourcePosition{ArgumentIndex: uint32(source), Path: path, Sequence: seq}, link: r.LinkType()})
		}
		require.NoError(t, f.Close())
	}
	sort.SliceStable(reference, func(i, j int) bool { return reference[i].ci.Timestamp.Before(reference[j].ci.Timestamp) })
	statistics := func(filtered bool) offline.Statistics {
		st := offline.Statistics{Protocols: map[string]uint64{}, SourceCounts: map[string]uint64{}, DestinationCounts: map[string]uint64{}}
		for i, ref := range reference {
			if filtered && i%3 != 1 {
				continue
			}
			p := gopacket.NewPacket(ref.raw, ref.link, gopacket.Default)
			ip := p.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
			n := uint64(ref.ci.Length)
			st.Packets++
			st.Bytes += n
			st.Protocols["UDP"]++
			st.SourceCounts[ip.SrcIP.String()]++
			st.DestinationCounts[ip.DstIP.String()]++
			if st.Packets == 1 {
				st.First = ref.ci.Timestamp
				st.MinPacketSize = n
			}
			st.Last = ref.ci.Timestamp
			st.MinPacketSize = min(st.MinPacketSize, n)
			st.MaxPacketSize = max(st.MaxPacketSize, n)
		}
		st.Sources = uint64(len(st.SourceCounts))
		st.Destinations = uint64(len(st.DestinationCounts))
		return st
	}
	ctx := context.Background()
	storage, err := offline.NewStorage(offline.ResourceLimits{Directory: t.TempDir(), DiskBytes: 16 << 20, CacheBytes: 128 << 10, MaxRecordBytes: 16 << 10, MaxSources: 2})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, storage.Close()) })
	session, err := indexOfflineDataset(ctx, storage, 81, OfflineAnalysisConfig{Inputs: paths, EventCapacity: 8}, nil)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, session.Close()) })
	ds := session.Dataset
	require.EqualValues(t, len(reference), ds.Count())
	require.Equal(t, statistics(false), ds.Statistics())
	token := offline.Token{Dataset: 81, Query: 1}
	q, err := ds.Query(ctx, offline.QuerySpec{Token: token, Match: func(s offline.Summary) bool { return s.ID%3 == 1 }})
	require.NoError(t, err)
	defer func() { require.NoError(t, q.Close()) }()
	require.Equal(t, statistics(true), q.Statistics())
	check := func(id int) {
		got, err := ds.Detail(ctx, token, offline.PacketID(id))
		require.NoError(t, err)
		ref := reference[id]
		require.Equal(t, ref.raw, got.Packet.RawData)
		require.True(t, ref.ci.Timestamp.Equal(got.Packet.Timestamp))
		require.EqualValues(t, ref.ci.Length, got.Packet.Length)
		require.EqualValues(t, ref.ci.CaptureLength, got.CapturedLength)
		require.EqualValues(t, ref.ci.Length, got.OriginalLength)
		require.Equal(t, ref.source, got.Source)
		require.Equal(t, ref.link, got.Packet.LinkType)
	}
	for _, id := range []int{0, len(reference) / 2, len(reference) - 1} {
		check(id)
		// Read hundreds of distinct frames, far exceeding the 128 KiB cache. The
		// offline package acceptance test additionally asserts actual LRU eviction.
		for j := 1; j <= 600; j++ {
			_, err := ds.Detail(ctx, token, offline.PacketID((id+j)%len(reference)))
			require.NoError(t, err)
		}
		check(id)
	}
	require.Equal(t, statistics(false), ds.Statistics())
	require.Equal(t, statistics(true), q.Statistics())
}
