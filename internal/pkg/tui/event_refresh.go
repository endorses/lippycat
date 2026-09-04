//go:build tui || all

package tui

import "time"

// presentationRefreshPolicy preserves the packet list's adaptive cadence for
// both packet and event views. Drop rates use the bridge's 0–1000 scale.
func presentationRefreshPolicy(base time.Duration, recentDropRate int64) (interval time.Duration, suppressDetails bool) {
	switch {
	case recentDropRate > 300:
		return 500 * time.Millisecond, true
	case recentDropRate > 100:
		return 250 * time.Millisecond, true
	case recentDropRate > 10:
		return base * 2, false
	default:
		return base, false
	}
}

// refreshEventsView performs at most one presentation sync per refresh window.
// Ingestion marks dirty even while another tab/view is active; entering the
// event view explicitly synchronizes that retained state.
func (m *Model) refreshEventsView(now time.Time) {
	if !m.eventViewDirty || m.uiState.Tabs.GetActive() != 0 || m.uiState.ViewMode != "events" {
		return
	}
	interval, _ := presentationRefreshPolicy(m.packetListUpdateInterval, GetBridgeStats().RecentDropRate)
	if !m.lastEventViewUpdate.IsZero() && now.Sub(m.lastEventViewUpdate) < interval {
		return
	}
	m.syncEventsViewAt(now)
}
