//go:build tui || all

package tui

import "github.com/endorses/lippycat/internal/pkg/offline"

func (m *Model) publishOfflineStatistics(query offline.Query) {
	global := m.offlineSession.Dataset.Statistics()
	matching := global
	if query != nil {
		matching = query.Statistics()
	}
	m.uiState.StatisticsView.SetOfflineStatistics(global, matching)
}
