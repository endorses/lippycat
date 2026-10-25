//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/testutil/noticefixture"
	"github.com/stretchr/testify/require"
)

// The complete event dataset intentionally exceeds the eight-row compatibility
// ring. The last two snapshots share a delivery ID but remain separate rows.
func readyCompleteOfflineEvents(t *testing.T, count int) Model {
	t.Helper()
	m := readyOfflineBrowser(t)
	require.NoError(t, m.offlineSession.EventDataset.Close())
	builder, err := m.offlineController.storage.NewEventBuilder(m.offlineSession.Dataset.Generation())
	require.NoError(t, err)
	for i := 1; i <= count; i++ {
		env := noticefixture.Event().Envelope()
		env.EventSequence = uint64(i)
		if i >= count-1 {
			env.EventSequence = 1
		}
		env.EventID = events.DeliveryEventID(env.NodeID, env.ProducerSessionID, env.EventSequence)
		event := events.NewDNSEvent(env)
		event.Query, event.QType, event.QClass = fmt.Sprintf("row-%d.example.test", i), 1, 1
		require.NoError(t, builder.Append(context.Background(), event))
		m.eventStore.AddEvent(event)
	}
	m.offlineSession.EventDataset, err = builder.Finish(context.Background())
	require.NoError(t, err)
	m.uiState.ViewMode = "events"
	m.uiState.Header.SetWidth(m.uiState.Width)
	m.syncEventsView()
	m.prepareViewChrome()
	return m
}

func loadCompleteOfflineEvents(t *testing.T, m Model) Model {
	t.Helper()
	cmd := m.syncOfflineEventBrowser()
	require.NotNil(t, cmd)
	msg := cmd().(offlineEventBrowseMsg)
	require.NoError(t, msg.result.err)
	m, cleanup := m.handleOfflineEventBrowse(msg)
	if cleanup != nil {
		require.NoError(t, cleanup().(offlineCleanupMsg).err)
	}
	return m
}

func completeOfflineEventFilter(t *testing.T, m Model, cmd tea.Cmd) Model {
	t.Helper()
	require.NotNil(t, cmd)
	message := cmd().(tea.BatchMsg)[0]().(offlineEventFilterMsg)
	require.NoError(t, message.err)
	m, cleanup := m.handleOfflineEventFilter(message)
	if cleanup != nil {
		require.NoError(t, cleanup().(offlineCleanupMsg).err)
	}
	return m
}

func TestCompleteOfflineEventsDistantRowsAndRepeatedAmendments(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 4099))
	require.Len(t, m.eventStore.Events(), 8)
	require.EqualValues(t, 4099, m.offlineEventCount())
	first, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 1, first.ArrivalSequence)
	require.Equal(t, "row-1.example.test", first.Event.(events.DNSEvent).Query)
	m, _ = m.handleJumpToBottom()
	m = loadCompleteOfflineEvents(t, m)
	last, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 4099, last.ArrivalSequence)
	require.Equal(t, first.Event.Envelope().EventID, last.Event.Envelope().EventID)
	require.Equal(t, "row-4099.example.test", last.Event.(events.DNSEvent).Query)
	m.moveEventSelection(-1)
	if cmd := m.syncOfflineEventBrowser(); cmd != nil {
		msg := cmd().(offlineEventBrowseMsg)
		require.NoError(t, msg.result.err)
		m, _ = m.handleOfflineEventBrowse(msg)
	}
	previous, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 4098, previous.ArrivalSequence)
	require.Equal(t, last.Event.Envelope().EventID, previous.Event.Envelope().EventID)
	require.Equal(t, "row-4098.example.test", previous.Event.(events.DNSEvent).Query)
	m.prepareViewChrome()
	require.Contains(t, m.uiState.Header.View(), "4099 total")
	require.Contains(t, m.uiState.Header.View(), "4099 matching")
	require.Contains(t, m.uiState.Header.View(), "cached")
	require.LessOrEqual(t, len(m.offlineEventBrowse.current.items), 2*m.uiState.EventsView.VisibleRows())
	require.Nil(t, m.syncOfflineEventBrowser(), "completed selection does not reload on every tick")
}

func TestCompleteOfflineEventFiltersFindEvictedAndDistantRows(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 4099))
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"query:row-1.example.test OR query:row-4099.example.test"}, "DNS"))
	require.EqualValues(t, 2, m.offlineEventCount())
	require.Equal(t, []string{"query:row-1.example.test OR query:row-4099.example.test"}, m.eventFilterDescriptions())
	// Preserve the global protocol selection used by the ordinary UI scope hook.
	m.uiState.SelectedProtocol.Name = "DNS"
	m = loadCompleteOfflineEvents(t, m)
	first, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 1, first.ArrivalSequence)
	m, _ = m.handleJumpToBottom()
	if cmd := m.syncOfflineEventBrowser(); cmd != nil {
		msg := cmd().(offlineEventBrowseMsg)
		m, _ = m.handleOfflineEventBrowse(msg)
	}
	last, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 4099, last.ArrivalSequence)
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"query:row-4099.example.test"}, "DNS"))
	require.EqualValues(t, 1, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	last, ok = m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 4099, last.ArrivalSequence)
}

type controlledEventDataset struct {
	offline.EventDataset
	started chan struct{}
	release chan struct{}
	err     error
}

func (d controlledEventDataset) Query(ctx context.Context, spec offline.EventQuerySpec) (offline.EventQuery, error) {
	if d.started != nil {
		d.started <- struct{}{}
	}
	if d.release != nil {
		<-d.release // Exercise a late error/success even after cancellation.
	}
	if d.err != nil {
		return nil, d.err
	}
	return d.EventDataset.Query(context.Background(), spec)
}

func TestCompleteOfflineEventFilterCancelFailureAndStaleResults(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 257))
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"query:row-1.example.test"}, "All"))
	installed := m.offlineEventBrowse.owner.query
	base := m.offlineEventBrowse.owner.dataset
	started, gate := make(chan struct{}, 1), make(chan struct{})
	m.offlineEventBrowse.owner.dataset = controlledEventDataset{EventDataset: base, started: started, release: gate}
	cancelled := m.startOfflineEventFilter([]string{"query:row-257.example.test"}, "All")
	<-started
	m.cancelOfflineEventFilter()
	require.True(t, m.offlineEventFilter.cancelled)
	close(gate)
	cancelledMessage := cancelled().(tea.BatchMsg)[0]().(offlineEventFilterMsg)
	require.ErrorIs(t, cancelledMessage.err, context.Canceled)
	m, cleanup := m.handleOfflineEventFilter(cancelledMessage)
	require.NoError(t, cleanup().(offlineCleanupMsg).err)
	require.Same(t, installed, m.offlineEventBrowse.owner.query)
	require.Equal(t, []string{"query:row-1.example.test"}, m.eventFilterDescriptions())
	started, gate = make(chan struct{}, 1), make(chan struct{})
	m.offlineEventBrowse.owner.dataset = controlledEventDataset{EventDataset: base, started: started, release: gate, err: errors.New("stale query error")}
	old := m.startOfflineEventFilter([]string{"query:row-2.example.test"}, "All")
	<-started
	m.offlineEventBrowse.owner.dataset = base
	latest := m.startOfflineEventFilter([]string{"query:row-257.example.test"}, "All")
	current := m.offlineEventFilter
	close(gate)
	stale := old().(tea.BatchMsg)[0]().(offlineEventFilterMsg)
	require.ErrorContains(t, stale.err, "stale query error")
	m, cleanup = m.handleOfflineEventFilter(stale)
	require.Same(t, current, m.offlineEventFilter, "stale errors must not clear the current progress owner")
	require.NoError(t, cleanup().(offlineCleanupMsg).err)
	m = completeOfflineEventFilter(t, m, latest)
	require.Equal(t, []string{"query:row-257.example.test"}, m.eventFilterDescriptions())
	require.EqualValues(t, 1, m.offlineEventCount())
	m.offlineEventBrowse.owner.dataset = controlledEventDataset{EventDataset: base, err: errors.New("query failed")}
	failed := m.startOfflineEventFilter([]string{"query:row-3.example.test"}, "All")
	msg := failed().(tea.BatchMsg)[0]().(offlineEventFilterMsg)
	m, _ = m.handleOfflineEventFilter(msg)
	require.Equal(t, []string{"query:row-257.example.test"}, m.eventFilterDescriptions())
	require.EqualValues(t, 1, m.offlineEventCount())
}

func TestCompleteOfflineEventOwnersCloseAbandonedResults(t *testing.T) {
	m := readyCompleteOfflineEvents(t, 257)
	cmd := m.syncOfflineEventBrowser()
	require.NotNil(t, cmd)
	owner := m.offlineEventBrowse.owner
	<-owner.done // Tea never executes the returned command or sees its result.
	for i := uint64(1); i < 40; i++ {
		m.uiState.EventsView.SetLogicalCursor(i)
		require.NotNil(t, m.syncOfflineEventBrowser())
		<-owner.done
	}
	owner.mu.Lock()
	require.LessOrEqual(t, len(owner.results), 1)
	owner.mu.Unlock()
	filter := m.startOfflineEventFilter([]string{"query:row-257.example.test"}, "All")
	require.NotNil(t, filter)
	<-owner.done
	require.NoError(t, m.CloseOffline())
	owner.mu.Lock()
	require.Empty(t, owner.results)
	require.Empty(t, owner.queries)
	owner.mu.Unlock()
	require.Zero(t, m.offlineController.storage.Resources().DiskBytes)
	require.Zero(t, m.offlineController.storage.Resources().InFlightBytes)
}

func TestCompleteOfflineEventsReopenRejectsOldResultsAndQuitJoins(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 257))
	m.uiState.EventsView.SetLogicalCursor(200)
	staleCommand := m.syncOfflineEventBrowser()
	require.NotNil(t, staleCommand)
	stale := staleCommand().(offlineEventBrowseMsg)
	oldOwner := m.offlineEventBrowse.owner
	m, opening := m.openOffline(m.offlineInstalled)
	result := offlineWorker(t, opening)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, cleanup := m.completeOffline(result)
	require.NoError(t, cleanup().(offlineCleanupMsg).err)
	require.True(t, oldOwner.closed)
	require.Empty(t, oldOwner.results)
	m, cleanup = m.handleOfflineEventBrowse(stale)
	require.NoError(t, cleanup().(offlineCleanupMsg).err)
	require.Nil(t, m.offlineEventBrowse)
	m = loadCompleteOfflineEvents(t, m)
	require.NotSame(t, oldOwner, m.offlineEventBrowse.owner)
	require.Equal(t, result.session.EventDataset.Count(), m.offlineEventCount())
	owner := m.offlineEventBrowse.owner
	filter := m.startOfflineEventFilter([]string{"kind:conn"}, "All")
	require.NotNil(t, filter)
	m, quit := m.leaveOffline(nil, true)
	require.Nil(t, m.offlineEventBrowse)
	require.Nil(t, m.offlineEventFilter)
	joined := make(chan offlineCleanupMsg, 1)
	go func() { joined <- quit().(offlineCleanupMsg) }()
	select {
	case msg := <-joined:
		require.NoError(t, msg.err)
	case <-time.After(5 * time.Second):
		t.Fatal("quit did not join event queries/readers")
	}
	require.True(t, owner.closed)
	require.Empty(t, owner.results)
	require.Empty(t, owner.queries)
	require.Zero(t, m.offlineController.storage.Resources().DiskBytes)
}

func TestCompleteOfflineEventSelectionUsesBoundedRelatedPacketLookup(t *testing.T) {
	m := readyOfflineBrowser(t)
	m.uiState.ViewMode = "events"
	m.syncEventsView()
	m = loadCompleteOfflineEvents(t, m)
	selected, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	lookup := m.requestOfflineRelated()
	require.NotNil(t, lookup)
	result := lookup().(offlineRelatedMsg)
	require.NoError(t, result.err)
	require.True(t, result.available)
	m, _ = m.handleOfflineRelated(result)
	require.True(t, m.hasRelatedPacket(selected.Event))
	m, _ = m.navigateOfflineRelated()
	require.Equal(t, "packets", m.uiState.ViewMode)
	require.Equal(t, uint64(result.first), m.uiState.PacketList.LogicalCursor())
	if cleanup := m.syncOfflineEventBrowser(); cleanup != nil {
		require.NoError(t, cleanup().(offlineCleanupMsg).err)
	}
	m = loadOfflineBrowser(t, m)
	require.Equal(t, result.first, m.offlineBrowse.current.detail.Value.ID)
	require.Nil(t, m.offlineEventBrowse.current, "event pages are released when changing to packets")
}

func TestCompleteOfflineEventFilterInputAndMouseUseArrivalRows(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 257))
	m, _ = m.handleEnterEventFilterMode()
	for _, r := range "query:row-257.example.test" {
		updated, _ := m.handleEventFilterInput(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
		m = updated.(Model)
	}
	updated, filter := m.handleEventFilterInput(tea.KeyMsg{Type: tea.KeyEnter})
	m = completeOfflineEventFilter(t, updated.(Model), filter)
	require.EqualValues(t, 1, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	selected, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 257, selected.ArrivalSequence)
	m, clear := m.handleRemoveLastEventFilter()
	m = completeOfflineEventFilter(t, m, clear)
	require.EqualValues(t, 257, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	layout := m.captureLayout()
	click := tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: layout.List.X + 5, Y: m.captureContentOrigin() + layout.List.Y + 4}
	m, _ = m.handleEventsViewClick(click, 0)
	require.EqualValues(t, 1, m.uiState.EventsView.LogicalCursor())
	if cmd := m.syncOfflineEventBrowser(); cmd != nil {
		msg := cmd().(offlineEventBrowseMsg)
		require.NoError(t, msg.result.err)
		m, _ = m.handleOfflineEventBrowse(msg)
	}
	selected, ok = m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.EqualValues(t, 2, selected.ArrivalSequence)
}

func TestCompleteOfflineEventsUpdateRoutesNavigationAndResize(t *testing.T) {
	m := loadCompleteOfflineEvents(t, readyCompleteOfflineEvents(t, 4099))
	m.uiState.FocusedPane = "left"
	for _, message := range []tea.Msg{
		tea.KeyMsg{Type: tea.KeyEnd},
		tea.KeyMsg{Type: tea.KeyPgUp},
		tea.KeyMsg{Type: tea.KeyPgDown},
		tea.WindowSizeMsg{Width: 145, Height: 27},
		tea.KeyMsg{Type: tea.KeyHome},
	} {
		updated, _ := m.Update(message)
		m = updated.(Model)
		owner := m.offlineEventBrowse.owner
		<-owner.done
		owner.mu.Lock()
		var result *offlineEventBrowseResult
		for pending := range owner.results {
			if pending.token.Request == m.offlineEventBrowse.request {
				result = pending
			}
		}
		owner.mu.Unlock()
		if result != nil && result != m.offlineEventBrowse.current {
			require.NoError(t, result.err)
			var cleanup tea.Cmd
			m, cleanup = m.handleOfflineEventBrowse(offlineEventBrowseMsg{owner, result})
			if cleanup != nil {
				require.NoError(t, cleanup().(offlineCleanupMsg).err)
			}
		}
		selected, ok := m.uiState.EventsView.DetailSelection()
		require.True(t, ok)
		require.Equal(t, m.uiState.EventsView.LogicalCursor()+1, selected.ArrivalSequence)
		page := m.offlineEventBrowse.current.page
		start := m.uiState.EventsView.LogicalOffset()
		end := min(m.offlineEventCount(), start+uint64(m.uiState.EventsView.VisibleRows()))
		require.LessOrEqual(t, page.Row, start)
		require.GreaterOrEqual(t, page.Row+uint64(len(page.Rows)), end)
		require.Nil(t, m.syncOfflineEventBrowser())
	}
}

func TestCompleteOfflineEventDetailScrollSurvivesHiddenPageRelease(t *testing.T) {
	m := readyCompleteOfflineEvents(t, 257)
	m.uiState.Height = 20
	m.uiState.EventShowDetails = true
	m.prepareCaptureLayout()
	m = loadCompleteOfflineEvents(t, m)
	m.uiState.EventsView.SetDetailsScrollOffset(5)
	_, _, offset := m.uiState.EventsView.DetailsScrollState()
	require.Equal(t, 5, offset)
	m.uiState.ViewMode = "packets"
	cleanup := m.syncOfflineEventBrowser()
	require.NotNil(t, cleanup)
	require.NoError(t, cleanup().(offlineCleanupMsg).err)
	require.Nil(t, m.offlineEventBrowse.current)
	m.uiState.ViewMode = "events"
	m = loadCompleteOfflineEvents(t, m)
	_, _, offset = m.uiState.EventsView.DetailsScrollState()
	require.Equal(t, 5, offset, "same arrival row must retain reading position when its leased page is released while hidden")
}
