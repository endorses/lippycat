//go:build tui || all

package tui

import "github.com/endorses/lippycat/internal/pkg/offline"

func (m *Model) publishOfflineStatistics(query offline.Query) {
	global := m.offlineDataset().Statistics()
	matching := global
	revision := m.offlineRevision()
	if query != nil {
		matching = query.Statistics()
		revision = query.Token().Revision
	}
	m.uiState.StatisticsView.SetOfflineStatistics(global, matching)
	m.uiState.StatisticsView.SetOfflineQueryRevision(revision)
	m.uiState.StatisticsView.SetAnalysisPending(m.offlineAnalysisPending())
}

func (m *Model) installOfflineGlobalStatistics() {
	stats := m.offlineDataset().Statistics()
	m.uiState.PacketList.SetCaptureStartTime(stats.First)
	convert := func(in map[string]uint64) map[string]int64 {
		out := make(map[string]int64, len(in))
		for k, v := range in {
			out[k] = int64(v)
		}
		return out
	}
	m.statistics.ProtocolCounts.Replace(convert(stats.Protocols))
	m.statistics.SourceCounts.Replace(convert(stats.SourceCounts))
	m.statistics.DestCounts.Replace(convert(stats.DestinationCounts))
	m.statistics.TotalPackets = int64(stats.Packets)
	m.statistics.TotalBytes = int64(stats.Bytes)
	m.statistics.MinPacketSize = int(stats.MinPacketSize)
	m.statistics.MaxPacketSize = int(stats.MaxPacketSize)
	m.uiState.StatisticsView.SetStatistics(m.statistics)
	m.uiState.StatisticsView.SetAnalysisPending(m.offlineAnalysisPending())
	// The dataset bypasses the live bridge. Publish its statistics without
	// carrying capture loss or bridge health from the previous session.
	m.uiState.StatisticsView.GetDropStats().Reset()
	m.uiState.StatisticsView.SetBridgeStats(nil)
}
