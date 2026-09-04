//go:build tui || all

package tui

import (
	"fmt"
	"strconv"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/types"
)

func (m Model) handleEventBatchMsg(msg EventBatchMsg) (Model, tea.Cmd) {
	if m.eventStore == nil {
		return m, nil
	}
	if msg.Local == (m.captureMode == components.CaptureModeRemote) {
		return m, nil
	}
	batches := msg.Batches
	if batches == nil {
		batches = []types.EventBatch{msg.Batch}
	}
	hasLoss := false
	for _, batch := range batches {
		if m.eventStore.AddBatch(batch.Events) > 0 {
			m.eventViewDirty = true
		}
		for _, loss := range batch.Losses {
			m.eventStore.RecordTransportLoss(loss.Kind.String(), eventLossCount(loss))
		}
		if batch.CompatibilityOmissions > 0 {
			m.eventStore.RecordTransportLoss("compatibility_omission", batch.CompatibilityOmissions)
		}
		hasLoss = hasLoss || len(batch.Losses) > 0 || batch.CompatibilityOmissions > 0
	}
	if hasLoss {
		stats := m.eventStore.Stats()
		return m, m.uiState.Toast.Show(
			fmt.Sprintf("Event stream reported %d lost or omitted event(s)", stats.TransportLost),
			components.ToastWarning,
			components.ToastDurationShort,
		)
	}
	return m, nil
}

func eventLossCount(loss types.EventLoss) uint64 {
	if loss.Count > 0 {
		return loss.Count
	}
	var count uint64
	for _, sequenceRange := range loss.SequenceRanges {
		if sequenceRange.Last < sequenceRange.First {
			continue
		}
		span := sequenceRange.Last - sequenceRange.First + 1
		if span == 0 || ^uint64(0)-count < span {
			return ^uint64(0)
		}
		count += span
	}
	if count == 0 {
		// Count-less controls still represent one observable gap occurrence.
		return 1
	}
	return count
}

// captureViewsForSelectedProtocol returns the stable view cycle for the
// selected traffic scope. Specialized views remain available alongside the
// common event timeline.
func (m Model) captureViewsForSelectedProtocol() []string {
	views := []string{"packets"}
	if eventScopeAvailable(m.uiState.SelectedProtocol.Name) {
		views = append(views, "events")
	}
	switch m.uiState.SelectedProtocol.Name {
	case "VoIP (SIP/RTP)":
		views = append(views, "calls")
	case "DNS":
		views = append(views, "queries")
	case "Email":
		views = append(views, "emails")
	case "HTTP":
		views = append(views, "http")
	}
	return views
}

// eventKindsForProtocol deliberately uses exact normalized event kinds. Nil
// means all kinds; callers use eventScopeAvailable to distinguish unsupported
// packet-only scopes.
func eventKindsForProtocol(protocol string) []events.Kind {
	switch protocol {
	case "All":
		return nil
	case "DNS":
		return []events.Kind{events.KindDNS}
	case "HTTP":
		return []events.Kind{events.KindHTTP, events.KindFileMetadata}
	case "HTTPS/TLS":
		return []events.Kind{events.KindTLS}
	case "Email":
		return []events.Kind{events.KindSMTP, events.KindFileMetadata}
	case "TCP":
		return []events.Kind{events.KindConn}
	default:
		return nil
	}
}

func eventScopeAvailable(protocol string) bool {
	switch protocol {
	case "All", "DNS", "HTTP", "HTTPS/TLS", "Email", "TCP":
		return true
	default:
		return false
	}
}

func (m *Model) setCaptureView(view string) {
	m.uiState.ViewMode = view
	if view == "events" {
		m.eventStore.SetKindFilter(eventKindsForProtocol(m.uiState.SelectedProtocol.Name))
		m.syncEventsView()
		return
	}
	if view == "packets" {
		if !m.packetStore.HasFilter() {
			m.uiState.PacketList.SetPackets(m.getPacketsInOrder())
		} else {
			m.uiState.PacketList.SetPackets(m.packetStore.FilteredPackets)
		}
	}
}

func (m *Model) syncEventsView() {
	m.syncEventsViewAt(time.Now())
}

func (m *Model) syncEventsViewAt(now time.Time) {
	if m.eventStore == nil || m.uiState.EventsView == nil {
		return
	}
	m.eventViewDirty = false
	m.lastEventViewUpdate = now
	m.eventViewSyncCount++
	m.uiState.EventsView.SetEvents(m.eventStore.Events())
	m.uiState.EventsView.SetSelectedID(m.eventStore.SelectedID())
	if selected, ok := m.eventStore.Selected(); ok {
		m.uiState.EventsView.SetRelatedPacketsAvailable(m.hasRelatedPacket(selected.Event))
	}
}

func (m Model) hasRelatedPacket(event events.Event) bool {
	env := event.Envelope()
	srcPort := strconv.Itoa(int(env.Flow.SourcePort))
	dstPort := strconv.Itoa(int(env.Flow.DestinationPort))
	for _, packet := range m.getPacketsInOrder() {
		if env.NodeID != "" && packet.NodeID != "" && packet.NodeID != env.NodeID {
			continue
		}
		forward := packet.SrcIP == env.Flow.SourceAddress.String() && packet.DstIP == env.Flow.DestinationAddress.String() && packet.SrcPort == srcPort && packet.DstPort == dstPort
		reverse := packet.SrcIP == env.Flow.DestinationAddress.String() && packet.DstIP == env.Flow.SourceAddress.String() && packet.SrcPort == dstPort && packet.DstPort == srcPort
		if forward || reverse {
			return true
		}
	}
	return false
}

func eventMatchesProtocol(event events.Event, protocol string) bool {
	if !eventScopeAvailable(protocol) {
		return false
	}
	kinds := eventKindsForProtocol(protocol)
	if len(kinds) == 0 {
		return true
	}
	for _, kind := range kinds {
		if event.Kind() == kind {
			return true
		}
	}
	return false
}
