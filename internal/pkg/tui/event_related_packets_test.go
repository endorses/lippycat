//go:build tui || all

package tui

import (
	"net/netip"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/stretchr/testify/require"
)

func relatedTestPacket() components.PacketDisplay {
	return components.PacketDisplay{SrcIP: "192.0.2.1", DstIP: "198.51.100.2", SrcPort: "12345", DstPort: "80", Protocol: "TCP", NodeID: "processor"}
}

func TestModelRelatedPacketIdentity(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*events.Envelope, *components.PacketDisplay)
		want   bool
	}{
		{"forward", func(*events.Envelope, *components.PacketDisplay) {}, true},
		{"reverse", func(_ *events.Envelope, p *components.PacketDisplay) {
			p.SrcIP, p.DstIP = p.DstIP, p.SrcIP
			p.SrcPort, p.DstPort = p.DstPort, p.SrcPort
		}, true},
		{"different node", func(_ *events.Envelope, p *components.PacketDisplay) { p.NodeID = "other" }, false},
		{"absent packet node", func(_ *events.Envelope, p *components.PacketDisplay) { p.NodeID = "" }, true},
		{"absent event node", func(e *events.Envelope, _ *components.PacketDisplay) { e.NodeID = "" }, true},
		{"reused ports different transport", func(_ *events.Envelope, p *components.PacketDisplay) { p.Protocol = "UDP" }, false},
		{"different port", func(_ *events.Envelope, p *components.PacketDisplay) { p.SrcPort = "54321" }, false},
		{"missing event address", func(e *events.Envelope, _ *components.PacketDisplay) { e.Flow.SourceAddress = netip.Addr{} }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(2, 8, "", "", nil, false, true, "", true)
			env, packet := testEventEnvelope("selected", 1), relatedTestPacket()
			tc.change(&env, &packet)
			m.packetStore.AddPacket(packet)
			require.Equal(t, tc.want, m.hasRelatedPacket(events.NewHTTPEvent(env)))
		})
	}
}

func TestModelRelatedPacketCaptureIdentity(t *testing.T) {
	for _, tc := range []struct {
		name                          string
		mode                          components.CaptureMode
		eventNode, source, packetNode string
		want                          bool
	}{
		{"live", components.CaptureModeLive, "watch-local", "live", "Local", true},
		{"offline", components.CaptureModeOffline, "watch-local", "pcap", "Local", true},
		{"custom local producer", components.CaptureModeLive, "custom", "live", "Local", true},
		{"tap", components.CaptureModeRemote, "tap", "tap-local", "tap-local", true},
		{"other tap", components.CaptureModeRemote, "tap", "tap-local", "other-local", false},
		{"hunter shares processor ID", components.CaptureModeRemote, "tap", "tap-local", "tap", false},
		{"hunter", components.CaptureModeRemote, "hunter", "hunter", "hunter", true},
		{"interface provenance", components.CaptureModeRemote, "hunter", "hunter:eth0", "hunter", true},
		{"unrelated provenance", components.CaptureModeRemote, "hunter", "other", "other", false},
		{"missing event node", components.CaptureModeRemote, "", "-local", "hunter", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := NewModel(2, 8, "", "", nil, false, true, "", true)
			m.captureMode = tc.mode
			env, packet := testEventEnvelope("selected", 1), relatedTestPacket()
			env.NodeID, env.Provenance.CaptureSource = tc.eventNode, tc.source
			packet.NodeID = tc.packetNode
			event := events.NewHTTPEvent(env)
			m, _ = m.handlePacketMsg(PacketMsg{Packet: packet})
			require.Equal(t, tc.want, m.hasRelatedPacket(event))
			require.Equal(t, env, event.Envelope(), "lookup must preserve event identity")
			m.packetStore.Clear()
			require.False(t, m.hasRelatedPacket(event))
		})
	}
}

func TestModelRelatedPacketNoticeFollowsRetentionAndSelection(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	m.uiState.ViewMode = "events"
	m.uiState.EventShowDetails = true
	m.uiState.Width, m.uiState.Height = 160, 30
	first := events.NewHTTPEvent(testEventEnvelope("first", 1))
	env := testEventEnvelope("second", 2)
	env.Flow.SourcePort++
	second := events.NewHTTPEvent(env)
	m.eventStore.AddBatch([]events.Event{first, second})
	m.eventStore.SelectByID("first")
	m.packetStore.AddPacket(relatedTestPacket())
	check := func(available bool) {
		t.Helper()
		m.syncEventsView()
		rendered := m.renderCaptureTab(20)
		if available {
			require.NotContains(t, rendered, "Related packets are no longer buffered")
		} else {
			require.Contains(t, rendered, "Related packets are no longer buffered")
		}
	}
	check(true)
	// Display filters do not remove the raw packet retained for this event.
	m.packetStore.AddFilter(filters.NewNodeFilter("other"))
	m.packetStore.ReapplyFilters()
	require.Empty(t, m.packetStore.FilteredPackets)
	check(true)
	m.eventStore.SelectByID("second")
	check(false)
	m.eventStore.SelectByID("first")
	check(true)
	unrelated := relatedTestPacket()
	unrelated.SrcPort = "54321"
	m.packetStore.AddPacket(unrelated)
	check(true)
	m.packetStore.AddPacket(unrelated)
	check(false)
	m.packetStore.AddPacket(relatedTestPacket())
	check(true)
	m.packetStore = store.NewPacketStore(2)
	check(false)
}

func TestModelPacketClearInvalidatesRelatedPackets(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	event := events.NewHTTPEvent(testEventEnvelope("selected", 1))
	m.eventStore.AddEvent(event)
	m.packetStore.AddPacket(relatedTestPacket())
	m.uiState.ViewMode = "events"
	m.syncEventsView()
	require.True(t, m.hasRelatedPacket(event))
	m.uiState.ViewMode = "packets"
	m, _ = m.handleClearPackets()
	require.True(t, m.eventViewDirty)
	require.False(t, m.hasRelatedPacket(event))
	m.packetStore.AddPacket(relatedTestPacket())
	require.True(t, m.hasRelatedPacket(event))
}

func TestModelCaptureRestartInvalidatesRelatedPacketsAndResizesRing(t *testing.T) {
	m := NewModel(2, 8, "", "", nil, false, true, "", true)
	event := events.NewHTTPEvent(testEventEnvelope("selected", 1))
	m.packetStore.AddPacket(relatedTestPacket())
	require.True(t, m.hasRelatedPacket(event))
	m, _ = m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: components.CaptureModeRemote, BufferSize: 3})
	require.False(t, m.hasRelatedPacket(event))
	require.Equal(t, 3, m.packetStore.MaxPackets)
	m.packetStore.AddPacket(relatedTestPacket())
	require.True(t, m.hasRelatedPacket(event))
	unrelated := relatedTestPacket()
	unrelated.SrcPort = "54321"
	m.packetStore.AddPacketBatch([]components.PacketDisplay{unrelated, unrelated})
	require.True(t, m.hasRelatedPacket(event))
	m.packetStore.AddPacket(unrelated)
	require.False(t, m.hasRelatedPacket(event))
}
