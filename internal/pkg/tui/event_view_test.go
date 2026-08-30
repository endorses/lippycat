//go:build tui || all

package tui

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestCaptureViewCycleIncludesEventsOnlyForRemote(t *testing.T) {
	remote := NewModel(8, 8, "", "", nil, false, true, "", true)
	remote.uiState.Tabs.SetActive(0)
	require.Equal(t, []string{"packets", "events"}, remote.captureViewsForSelectedProtocol())
	remote, _ = remote.handleToggleView()
	require.Equal(t, "events", remote.uiState.ViewMode)

	local := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	local.uiState.Tabs.SetActive(0)
	require.Equal(t, []string{"packets"}, local.captureViewsForSelectedProtocol())
	local, _ = local.handleToggleView()
	require.Equal(t, "packets", local.uiState.ViewMode)
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

func TestEventBatchFilteringNavigationAndMissingPacketNotice(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.Tabs.SetActive(0)
	m.uiState.ViewMode = "events"
	m.uiState.ShowDetails = true
	m.uiState.Width, m.uiState.Height = 120, 30

	dns := events.NewDNSEvent(testEventEnvelope("dns-1", 1))
	http := events.NewHTTPEvent(testEventEnvelope("http-2", 2))
	m, _ = m.handleEventBatchMsg(EventBatchMsg{Batch: types.EventBatch{Events: []events.Event{dns, http}}})
	require.Equal(t, "dns-1", m.eventStore.SelectedID())
	m, _ = m.handleMoveDown()
	require.Equal(t, "http-2", m.eventStore.SelectedID())

	m.uiState.SelectedProtocol = components.Protocol{Name: "DNS"}
	m.setCaptureView("events")
	require.Len(t, m.eventStore.Events(), 1)
	require.Equal(t, "dns-1", m.eventStore.SelectedID())
	require.Contains(t, m.renderCaptureTab(20), "Related packets are no longer buffered")

	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'v'}})
	require.NotNil(t, updated)
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
	m.uiState.ViewMode = "events"
	m.uiState.ShowDetails = true
	m.uiState.Width = 120
	m.packetStore.AddPacket(components.PacketDisplay{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "80", NodeID: "processor"})
	m.eventStore.AddEvent(events.NewHTTPEvent(testEventEnvelope("http-1", 1)))
	m.syncEventsView()
	require.False(t, strings.Contains(m.renderCaptureTab(20), "no longer buffered"))
}

func TestEventLossCountSurfacesCountlessGaps(t *testing.T) {
	require.Equal(t, uint64(1), eventLossCount(types.EventLoss{}))
	require.Equal(t, uint64(5), eventLossCount(types.EventLoss{SequenceRanges: []types.EventSequenceRange{{First: 4, Last: 8}}}))
	require.Equal(t, uint64(7), eventLossCount(types.EventLoss{Count: 7, SequenceRanges: []types.EventSequenceRange{{First: 4, Last: 8}}}))
}
