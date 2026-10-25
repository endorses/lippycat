//go:build tui || all

package tui

import (
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

func TestNoticeLocalAndRemoteEventsRemainAvailableInAllAndDNSScope(t *testing.T) {
	for _, remote := range []bool{false, true} {
		m := NewModel(8, 8, "fixture", "", nil, false, remote, "", remote)
		m, _ = m.handleEventBatchMsg(EventBatchMsg{Local: !remote, Batch: types.EventBatch{Events: []events.Event{noticefixture.Event()}}})
		require.Len(t, m.eventStore.Events(), 1)
		require.Nil(t, eventKindsForProtocol("All"))
		m.eventStore.SetKindFilter(eventKindsForProtocol("DNS"))
		require.Len(t, m.eventStore.Events(), 1)
		require.NoError(t, m.eventStore.AddUserFilter("kind:notice AND severity:warning"))
		m.syncEventsView()
		selected, ok := m.uiState.EventsView.Selected()
		require.True(t, ok)
		require.Equal(t, events.KindNotice, selected.Event.Kind())
		require.True(t, eventScopeAvailable("DNS"))
		require.NotEqual(t, components.CaptureModeOffline, m.captureMode)
	}
}
