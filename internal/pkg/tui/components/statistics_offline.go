//go:build tui || all

package components

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/endorses/lippycat/internal/pkg/offline"
)

// SetOfflineStatistics installs completed snapshots. Query scans never update
// these values incrementally, so the matching scope always agrees with the rows.
func (s *StatisticsView) SetOfflineStatistics(global, matching offline.Statistics) {
	s.offlineGlobal, s.offlineMatching = &global, &matching
	s.dirty = true
	s.lastRender = time.Time{}
}

// SetOfflineResources keeps storage diagnostics in Statistics, leaving the
// capture view's bottom area reserved for filters and toast notifications.
func (s *StatisticsView) SetOfflineResources(rows int, usage offline.ResourceUsage) {
	if s.offlineCachedRows == rows && s.offlineResources == usage {
		return
	}
	s.offlineCachedRows, s.offlineResources = rows, usage
	s.dirty = true
	s.lastRender = time.Time{}
}

func (s *StatisticsView) ClearOfflineStatistics() {
	s.offlineGlobal, s.offlineMatching = nil, nil
	s.offlineCachedRows, s.offlineResources = 0, offline.ResourceUsage{}
	s.dirty = true
	s.lastRender = time.Time{}
}

func (s *StatisticsView) renderOfflineStatistics() string {
	if s.offlineGlobal == nil || s.offlineMatching == nil {
		return ""
	}
	var out strings.Builder
	u := s.offlineResources
	fmt.Fprintf(&out, "Cached rows: %d | Cache: %d B | Index: %d B\n", s.offlineCachedRows, u.CachedBytes+u.PinnedBytes+u.PrefetchBytes+u.InFlightBytes, u.DiskBytes)
	for i, stats := range []*offline.Statistics{s.offlineGlobal, s.offlineMatching} {
		scope := "Global dataset"
		if i == 1 {
			scope = "Matching query"
		}
		fmt.Fprintf(&out, "%s: %d packets | %d bytes\n", scope, stats.Packets, stats.Bytes)
		fmt.Fprintf(&out, "  Packet size: %d–%d B | Sources: %d | Destinations: %d\n", stats.MinPacketSize, stats.MaxPacketSize, stats.Sources, stats.Destinations)
		if stats.Packets > 0 {
			fmt.Fprintf(&out, "  Capture interval: %s – %s\n", stats.First.Format("2006-01-02 15:04:05.999999999"), stats.Last.Format("2006-01-02 15:04:05.999999999"))
		}
		keys := make([]string, 0, len(stats.Protocols))
		for protocol := range stats.Protocols {
			keys = append(keys, protocol)
		}
		sort.Strings(keys)
		for _, protocol := range keys {
			fmt.Fprintf(&out, "  %s: %d\n", protocol, stats.Protocols[protocol])
		}
		if len(stats.TruncatedCardinality) > 0 {
			fmt.Fprintf(&out, "  Bounded cardinality estimates: %s\n", strings.Join(stats.TruncatedCardinality, ", "))
		}
	}
	out.WriteString("\nOverview below: global dataset; events/calls: bounded retained history.\n\n")
	return out.String()
}
