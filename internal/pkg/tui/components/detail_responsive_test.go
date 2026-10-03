//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/stretchr/testify/require"
)

func assertDetailFits(t *testing.T, rendered string, width, height int) {
	t.Helper()
	lines := strings.Split(rendered, "\n")
	require.Len(t, lines, height)
	for _, line := range lines {
		require.LessOrEqual(t, ansi.StringWidth(line), width, "%q", ansi.Strip(line))
	}
}

func TestResponsiveDetailsFitOuterPane(t *testing.T) {
	for _, size := range [][2]int{{100, 28}, {77, 16}, {48, 12}, {40, 10}, {20, 5}, {12, 3}, {2, 2}, {1, 1}} {
		t.Run(fmt.Sprintf("%dx%d", size[0], size[1]), func(t *testing.T) {
			width, height := size[0], size[1]
			packet := NewDetailsPanel()
			packet.SetSize(width, height)
			packet.SetPacket(&PacketDisplay{Timestamp: time.Now(), SrcIP: "2001:db8:1234:5678:abcd:ef01:2345:6789", RawData: []byte(strings.Repeat("payload", 20))})
			assertDetailFits(t, packet.View(true), width, height)
			event := NewEventsView()
			event.SetEvents([]EventItem{{Event: dnsEvent("long-event-identity", strings.Repeat("host", 30)+".example")}})
			event.PrepareLayout(100, 20, width, height)
			assertDetailFits(t, event.RenderDetails(width, height, true), width, height)
			calls := NewCallsView()
			calls.SetCalls([]Call{{CallID: strings.Repeat("identity", 30), From: "sip:from@example.test", To: "sip:to@example.test"}})
			calls.PrepareDetails(width, height)
			assertDetailFits(t, calls.RenderDetails(width, height, true), width, height)
		})
	}
}

func TestResponsiveDetailValuesAndHexRemainComplete(t *testing.T) {
	packet := NewDetailsPanel()
	packet.SetSize(28, 8)
	address := "2001:db8:1234:5678:abcd:ef01:2345:6789"
	packet.SetPacket(&PacketDisplay{Timestamp: time.Now(), SrcIP: address, SrcPort: "65535"})
	content := ansi.Strip(packet.renderContent())
	require.Contains(t, strings.ReplaceAll(content, "\n", ""), address+":65535")
	require.NotContains(t, content, "...")
	for _, width := range []int{100, 77, 48, 28, 18, 13} {
		packet.SetSize(width, 16)
		dump := ansi.Strip(packet.renderHexDump([]byte("abcdefghijklmnopqrstuvwxyz012345")))
		_, _, cw, _ := DetailPaneGeometry(width, 16)
		for _, line := range strings.Split(dump, "\n") {
			require.LessOrEqual(t, ansi.StringWidth(line), cw)
		}
		n, _, _ := packet.HexDumpColumns(32)
		require.Contains(t, dump, fmt.Sprintf("%04x", n))
	}
	require.Equal(t, []string{"界界", "界"}, wrapEventValue("界界界", 4))
}

func TestResponsiveDetailsRetainScrollAcrossResizeAndHiding(t *testing.T) {
	packet := NewDetailsPanel()
	packet.SetSize(48, 12)
	packet.SetPacket(&PacketDisplay{Timestamp: time.Now(), RawData: []byte(strings.Repeat("A", 400))})
	packet.SetScrollOffset(5)
	packet.SetSize(0, 0)
	packet.SetSize(28, 8)
	_, _, offset := packet.ScrollState()
	require.Equal(t, 5, offset)
	calls := NewCallsView()
	calls.SetCalls([]Call{{CallID: strings.Repeat("call-id", 50)}})
	calls.PrepareDetails(48, 12)
	calls.SetDetailsScrollOffset(5)
	calls.PrepareDetails(0, 0)
	calls.PrepareDetails(28, 8)
	_, _, offset = calls.DetailsScrollState()
	require.Equal(t, 5, offset)
	before := calls.detailsViewport
	calls.RenderDetails(28, 8, true)
	calls.RenderDetails(100, 30, false)
	require.Equal(t, before, calls.detailsViewport, "render must not mutate viewport")
	event := NewEventsView()
	event.SetEvents([]EventItem{{Event: dnsEvent("event", strings.Repeat("host", 30)+".example")}})
	event.PrepareLayout(100, 20, 48, 12)
	event.SetDetailsScrollOffset(5)
	event.PrepareLayout(100, 20, 0, 0)
	event.PrepareLayout(100, 20, 28, 8)
	_, _, offset = event.DetailsScrollState()
	require.Equal(t, 5, offset)
}

func TestDetailsInspectionRetainsEvictedPacketAndCall(t *testing.T) {
	packet := NewDetailsPanel()
	packet.SetSize(48, 12)
	packet.SetPacket(&PacketDisplay{Timestamp: time.Unix(1, 0), Info: "inspected"})
	packet.SetInspecting(true)
	packet.SetPacket(&PacketDisplay{Timestamp: time.Unix(2, 0), Info: "replacement"})
	require.Equal(t, "inspected", packet.packet.Info)
	packet.SetInspecting(false)
	packet.SetPacket(&PacketDisplay{Timestamp: time.Unix(2, 0), Info: "replacement"})
	require.Equal(t, "replacement", packet.packet.Info)
	calls := NewCallsView()
	calls.SetCalls([]Call{{CallID: "inspected"}})
	calls.SetInspecting(true)
	calls.SetCalls([]Call{{CallID: "older"}, {CallID: "inspected"}, {CallID: "newer"}})
	require.Equal(t, "inspected", calls.GetSelected().CallID)
	calls.SetCalls([]Call{{CallID: "replacement"}})
	calls.PrepareDetails(48, 12)
	require.Equal(t, "inspected", calls.lastSelectedCallID)
	calls.SetInspecting(false)
	calls.PrepareDetails(48, 12)
	require.Equal(t, "replacement", calls.lastSelectedCallID)
}

func TestEventInspectionRetainsEvictedDetails(t *testing.T) {
	view := NewEventsView()
	view.SetEvents([]EventItem{{Event: dnsEvent("inspected", "inspected.example")}})
	view.PrepareLayout(100, 20, 48, 12)
	view.SetInspecting(true)
	view.SetDetailsScrollOffset(5)
	view.SetEvents([]EventItem{{Event: dnsEvent("replacement", "replacement.example")}})
	view.PrepareLayout(100, 20, 48, 12)
	require.Equal(t, "inspected", view.detailsSelectedID)
	inspected, found := view.DetailSelection()
	require.True(t, found)
	require.Equal(t, "inspected", inspected.Event.Envelope().EventID)
	_, _, offset := view.DetailsScrollState()
	require.Equal(t, 5, offset)
	view.PrepareLayout(100, 20, 28, 8)
	require.Equal(t, "inspected", view.detailsSelectedID)
	view.SetInspecting(false)
	view.PrepareLayout(100, 20, 28, 8)
	require.Equal(t, "replacement", view.detailsSelectedID)
}

func TestDetailsInspectionAcceptsPendingPacket(t *testing.T) {
	panel := NewDetailsPanel()
	panel.SetSize(48, 12)
	panel.SetLoading()
	panel.SetInspecting(true)
	require.Nil(t, panel.packet)
	require.True(t, panel.loading)
	pending := PacketDisplay{Timestamp: time.Unix(1, 0), Info: "loaded"}
	panel.SetPacket(&pending)
	require.NotNil(t, panel.packet)
	require.False(t, panel.loading)
	require.Equal(t, "loaded", panel.packet.Info)
	pending.Info = "mutated"
	require.Equal(t, "loaded", panel.packet.Info, "asynchronous initial packet becomes a snapshot")
	panel.SetLoading()
	require.False(t, panel.loading, "subsequent loading cannot replace the inspected snapshot")
	require.Equal(t, "loaded", panel.packet.Info)
}
