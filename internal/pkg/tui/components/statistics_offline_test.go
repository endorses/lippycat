//go:build tui || all

package components

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineStatisticsScopesAndEmptyMatches(t *testing.T) {
	s := NewStatisticsView()
	global := offline.Statistics{Packets: 10000, Bytes: 640000, Protocols: map[string]uint64{"UDP": 9997, "TCP": 3}}
	matching := offline.Statistics{Packets: 3, Bytes: 192, Protocols: map[string]uint64{"TCP": 3}, TruncatedCardinality: []string{"sources"}}
	s.SetOfflineStatistics(global, matching)
	s.SetOfflineResources(84, offline.ResourceUsage{DiskBytes: 694475447, CachedBytes: 1000, PinnedBytes: 200})
	require.Contains(t, s.renderOfflineStatistics(), "Cached rows: 84 | Cache: 1200 B | Index: 694475447 B")
	text := s.renderContent()
	require.Contains(t, text, "Global dataset: 10000 packets | 640000 bytes")
	require.Contains(t, text, "Matching query: 3 packets | 192 bytes")
	require.Contains(t, text, "Bounded cardinality estimates: sources")
	s.SetOfflineStatistics(global, offline.Statistics{})
	text = s.renderContent()
	require.Contains(t, text, "Global dataset: 10000 packets")
	require.Contains(t, text, "Matching query: 0 packets | 0 bytes")
	s.ClearOfflineStatistics()
	require.Empty(t, s.renderOfflineStatistics())
}

func TestOfflineEmptyDatasetStatisticsRemainVisible(t *testing.T) {
	s := NewStatisticsView()
	s.SetSize(100, 30)
	s.SetOfflineStatistics(offline.Statistics{}, offline.Statistics{})
	require.Contains(t, s.View(), "Global dataset: 0 packets")
	require.Contains(t, s.View(), "Matching query: 0 packets")
}

func TestClearOfflineStatisticsImmediatelyRemovesScope(t *testing.T) {
	s := NewStatisticsView()
	s.SetSize(100, 30)
	s.SetOfflineStatistics(offline.Statistics{Packets: 10000}, offline.Statistics{Packets: 3})
	require.Contains(t, s.View(), "Global dataset: 10000 packets")
	s.ClearOfflineStatistics()
	s.SetStatistics(&Statistics{
		TotalPackets:   1,
		ProtocolCounts: NewBoundedCounter(1000),
		SourceCounts:   NewBoundedCounter(10000),
		DestCounts:     NewBoundedCounter(10000),
	})
	require.NotContains(t, s.View(), "Global dataset")
	require.NotContains(t, s.View(), "Matching query")
}
