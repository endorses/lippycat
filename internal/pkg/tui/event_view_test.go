//go:build tui || all

package tui

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

type cursorClientStub struct {
	closed bool
}

func (c *cursorClientStub) Close()                        { c.closed = true }
func (c *cursorClientStub) EventCursor() (string, uint64) { return "previous-stream", 42 }

func TestCaptureViewCycleIncludesEventsForRemoteAndLocalCapture(t *testing.T) {
	remote := NewModel(8, 8, "", "", nil, false, true, "", true)
	remote.uiState.Tabs.SetActive(0)
	require.Equal(t, []string{"packets", "events"}, remote.captureViewsForSelectedProtocol())
	remote, _ = remote.handleToggleView()
	require.Equal(t, "events", remote.uiState.ViewMode)

	local := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	local.uiState.Tabs.SetActive(0)
	require.Equal(t, []string{"packets", "events"}, local.captureViewsForSelectedProtocol())
	local, _ = local.handleToggleView()
	require.Equal(t, "events", local.uiState.ViewMode)

	offline := NewModel(8, 8, "", "", []string{"fixture.pcap"}, false, false, "", false)
	offline.uiState.Tabs.SetActive(0)
	require.Equal(t, []string{"packets", "events"}, offline.captureViewsForSelectedProtocol())
}

func TestLocalCaptureRestartResetsEventAnalysisView(t *testing.T) {
	m := NewModel(8, 8, "old0", "", nil, false, false, "", false)
	m.eventStore.AddEvent(events.NewDNSEvent(testEventEnvelope("old-event", 1)))
	require.NoError(t, m.eventStore.AddUserFilter("kind:dns"))

	m, _ = m.handleRestartCaptureMsg(components.RestartCaptureMsg{
		Mode:       components.CaptureModeLive,
		Interface:  "new0",
		BufferSize: 8,
	})

	require.Empty(t, m.eventStore.Events())
	require.Zero(t, m.eventStore.UserFilterCount())
	require.Equal(t, "new0", m.interfaceName)
}

func TestEventBatchOriginIsGatedByCaptureMode(t *testing.T) {
	remoteEvent := events.NewDNSEvent(testEventEnvelope("remote", 1))
	localEvent := events.NewDNSEvent(testEventEnvelope("local", 2))

	local := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	local, _ = local.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{remoteEvent}}})
	local, _ = local.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{localEvent}}, Local: true})
	require.Len(t, local.eventStore.Events(), 1)
	require.Equal(t, "local", local.eventStore.Events()[0].Event.Envelope().EventID)

	remote := NewModel(8, 8, "", "", nil, false, true, "", true)
	remote, _ = remote.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{localEvent}}, Local: true})
	remote, _ = remote.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{remoteEvent}}})
	require.Len(t, remote.eventStore.Events(), 1)
	require.Equal(t, "remote", remote.eventStore.Events()[0].Event.Envelope().EventID)
}

func TestTickPullsLocalEventsWithoutProgramSend(t *testing.T) {
	pendingLocalEvents.clear()
	t.Cleanup(pendingLocalEvents.clear)
	m := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	m.uiState.Capturing = true
	pendingLocalEvents.addBatch(types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("local", 1)),
	}})

	m, _ = m.handleTickMsg(TickMsg{})
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, "local", m.eventStore.Events()[0].Event.Envelope().EventID)
}

func TestEventsViewPreservedAcrossCompatibleScopeChange(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("dns-1", 1)),
		events.NewHTTPEvent(testEventEnvelope("http-2", 2)),
	})
	m, _ = m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "DNS", BPFFilter: "port 53"}})
	require.Equal(t, "events", m.uiState.ViewMode)
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, events.KindDNS, m.eventStore.Events()[0].Event.Kind())

	m, _ = m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "HTTP", BPFFilter: "port 80"}})
	require.Equal(t, "events", m.uiState.ViewMode)
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, events.KindHTTP, m.eventStore.Events()[0].Event.Kind())

	m, _ = m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "VoIP (SIP/RTP)", BPFFilter: "has:voip"}})
	require.Equal(t, "calls", m.uiState.ViewMode)
}

func TestLocalEventsViewPreservedAcrossCompatibleScopeChange(t *testing.T) {
	m := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	m.uiState.ViewMode = "events"
	m, _ = m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "DNS", BPFFilter: "port 53"}})
	require.Equal(t, "events", m.uiState.ViewMode)
}

func TestEventBatchFilteringNavigationAndMissingPacketNotice(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = true
	m.uiState.Width, m.uiState.Height = 160, 30

	dns := events.NewDNSEvent(testEventEnvelope("dns-1", 1))
	http := events.NewHTTPEvent(testEventEnvelope("http-2", 2))
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{dns, http}}})
	require.Equal(t, "http-2", m.eventStore.SelectedID())
	m, _ = m.handleMoveUp()
	require.Equal(t, "dns-1", m.eventStore.SelectedID())

	m.uiState.SelectedProtocol = components.Protocol{Name: "DNS"}
	m.setCaptureView("events")
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, "dns-1", m.eventStore.SelectedID())
	require.Contains(t, m.renderCaptureTab(20), "Related packets are no longer buffered")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	require.NotNil(t, updated)
}

func TestEventFiltersUseIndependentContextSensitiveInput(t *testing.T) {
	m := NewModel(8, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.eventStore.AddBatch([]events.Event{events.NewDNSEvent(testEventEnvelope("dns", 1)), events.NewHTTPEvent(testEventEnvelope("http", 2))})

	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	require.True(t, m.uiState.EventFilterMode)
	require.False(t, m.uiState.FilterMode)
	require.False(t, m.uiState.CallFilterMode)
	for _, r := range "kind:http" {
		m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{r}})
	}
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyEnter})
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, 1, m.eventStore.UserFilterCount())
	require.False(t, m.packetStore.HasFilter())
	require.False(t, m.callStore.HasFilter())

	m.uiState.ViewMode = "packets"
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'/'}})
	require.True(t, m.uiState.FilterMode)
	require.Equal(t, 1, m.eventStore.UserFilterCount(), "cycling views preserves event filters")
}

func TestEventListMouseWheelMovesSelection(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = false
	m.uiState.Width, m.uiState.Height = 120, 30
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("one", 1)),
		events.NewDNSEvent(testEventEnvelope("two", 2)),
	})
	m.syncEventsView()
	require.Equal(t, "two", m.eventStore.SelectedID())

	m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelUp, X: 20, Y: 10})
	require.Equal(t, "one", m.eventStore.SelectedID())
	m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown, X: 20, Y: 10})
	require.Equal(t, "two", m.eventStore.SelectedID())
}

func TestEventListMouseClickSelectsVisibleRow(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.Width, m.uiState.Height = 120, 30
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("one", 1)),
		events.NewDNSEvent(testEventEnvelope("two", 2)),
	})
	m.syncEventsView()
	_ = m.renderCaptureTab(20)

	// Capture content begins at Y=6; the border and header put row 0 at Y=8.
	m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 20, Y: 8})
	require.Equal(t, "one", m.eventStore.SelectedID())
}

func TestClickingBottomEventReenablesAutoScroll(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.Width, m.uiState.Height = 120, 30
	m.eventStore.AddBatch([]events.Event{
		events.NewDNSEvent(testEventEnvelope("one", 1)),
		events.NewDNSEvent(testEventEnvelope("two", 2)),
	})
	m.eventStore.SelectPrevious()
	m.syncEventsView()
	_ = m.renderCaptureTab(20)

	// Row 1 is the last visible event.
	m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 20, Y: 9})
	require.Equal(t, "two", m.eventStore.SelectedID())
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("three", 3)),
	}}})
	require.Equal(t, "three", m.eventStore.SelectedID())
}

func TestEventListDoubleClickTogglesEventDetails(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.Width, m.uiState.Height = 180, 30
	m.eventStore.AddEvent(events.NewDNSEvent(testEventEnvelope("one", 1)))
	m.syncEventsView()
	_ = m.renderCaptureTab(20)
	click := tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonLeft, X: 20, Y: 8}

	m, _ = m.handleMouse(click)
	require.False(t, m.uiState.EventShowDetails)
	m, _ = m.handleMouse(click)
	require.True(t, m.uiState.EventShowDetails)
	require.False(t, m.uiState.ShowDetails)

	m, _ = m.handleMouse(click)
	require.True(t, m.uiState.EventShowDetails, "a third click starts a new double-click sequence")
}

func TestPacketAndEventDetailsToggleIndependently(t *testing.T) {
	m := NewModel(10, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ShowDetails = true
	m.uiState.EventShowDetails = false
	m.uiState.ViewMode = "events"

	m, _ = m.handleDKey()
	require.True(t, m.uiState.ShowDetails)
	require.True(t, m.uiState.EventShowDetails)

	m.uiState.ViewMode = "packets"
	m, _ = m.handleDKey()
	require.False(t, m.uiState.ShowDetails)
	require.True(t, m.uiState.EventShowDetails)
}

func testEventEnvelope(id string, sequence uint64) events.Envelope {
	return events.Envelope{
		Timestamp:         time.Unix(int64(sequence), 0),
		EventID:           id,
		ProducerSessionID: "session",
		EventSequence:     sequence,
		NodeID:            "processor",
		Flow: events.FlowTuple{
			Protocol:           6,
			SourceAddress:      netip.MustParseAddr("192.0.2.1"),
			DestinationAddress: netip.MustParseAddr("198.51.100.2"),
			SourcePort:         12345,
			DestinationPort:    80,
		},
	}
}

func TestEventsDetailsRecognizesBufferedRelatedPacket(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = true
	m.uiState.Width = 120
	m.packetStore.AddPacket(components.PacketDisplay{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "80", NodeID: "processor"})
	m.eventStore.AddEvent(events.NewHTTPEvent(testEventEnvelope("http-1", 1)))
	m.syncEventsView()
	require.False(t, strings.Contains(m.renderCaptureTab(20), "no longer buffered"))
}

func TestEventDetailsScrollSurvivesRenderSynchronization(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = true
	m.uiState.Width = 180
	m.uiState.Height = 30
	event := events.NewDNSEvent(testEventEnvelope("dns-scroll", 1))
	event.Query = "example.org"
	m.eventStore.AddEvent(event)

	// Initialize the viewport, then exercise the same focus-aware keyboard
	// path used by packet details.
	m.renderCaptureTab(20)
	m.uiState.FocusedPane = "right"
	m, _ = m.handleJumpToBottom()
	details := m.renderCaptureTab(20)
	require.Contains(t, details, "Event Identity")
	require.Equal(t, "dns-scroll", m.eventStore.SelectedID())

	// Mouse-wheel scrolling over the right pane must likewise survive the
	// synchronization performed by the following render.
	m, _ = m.handleJumpToTop()
	for range 50 {
		m, _ = m.handleMouse(tea.MouseMsg{Action: tea.MouseActionPress, Button: tea.MouseButtonWheelDown, X: 170, Y: 10})
	}
	details = m.renderCaptureTab(20)
	require.Contains(t, details, "Event Identity")
	require.Equal(t, "dns-scroll", m.eventStore.SelectedID())
}

func TestEventLossCountSurfacesCountlessGaps(t *testing.T) {
	require.Equal(t, uint64(1), eventLossCount(types.EventLoss{}))
	require.Equal(t, uint64(5), eventLossCount(types.EventLoss{SequenceRanges: []types.EventSequenceRange{{First: 4, Last: 8}}}))
	require.Equal(t, uint64(7), eventLossCount(types.EventLoss{Count: 7, SequenceRanges: []types.EventSequenceRange{{First: 4, Last: 8}}}))
}

func TestSettingsTabPauseAlsoPausesEventStore(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(3)

	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeySpace})
	require.True(t, m.uiState.Paused)
	require.True(t, m.eventStore.Paused())

	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{
		events.NewDNSEvent(testEventEnvelope("paused", 1)),
	}}})
	require.Empty(t, m.eventStore.Events())
	require.Equal(t, uint64(1), m.eventStore.Stats().Paused)

	// Restore the process-global capture signal for other tests.
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeySpace})
	require.False(t, m.eventStore.Paused())
}

func TestProcessorDisconnectRetainsEventCursor(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	client := &cursorClientStub{}
	m.connectionMgr.AddProcessor("processor:55555", &store.ProcessorConnection{
		Address: "processor:55555",
		State:   store.ProcessorStateConnected,
		Client:  client,
	})

	m, _ = m.handleProcessorDisconnectedMsg(ProcessorDisconnectedMsg{
		Address: "processor:55555",
		Error:   errors.New("connection lost"),
	})

	processor, ok := m.connectionMgr.GetProcessor("processor:55555")
	require.True(t, ok)
	require.Equal(t, "previous-stream", processor.EventStreamID)
	require.Equal(t, uint64(42), processor.EventDeliverySeq)
	require.True(t, client.closed)
}
