//go:build tui || all

package components

import (
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestOfflineReadinessPresentationDoesNotFabricatePacketMetadata(t *testing.T) {
	packet := PacketDisplay{SrcIP: "192.0.2.1", DstIP: "192.0.2.2", SrcPort: "12345", DstPort: "443", Length: 64}
	list := NewPacketList()
	list.SetSize(180, 20)
	list.SetVirtualPackets(1, 0, []PacketDisplay{packet})
	list.SetAnalysisPending(true)
	require.Contains(t, list.View(false, false), "Pending")
	require.Empty(t, list.GetSelectedPacket().Protocol)
	require.Empty(t, list.GetSelectedPacket().Info)
	details := NewDetailsPanel()
	details.SetSize(100, 30)
	details.SetPacket(&packet)
	details.SetAnalysisPending(true)
	text := details.renderContent()
	require.Contains(t, text, "Pending ordered analysis")
	require.Contains(t, text, "Application metadata and decrypted content pending")
	require.Contains(t, text, "192.0.2.1")
	require.Empty(t, packet.Protocol)
	require.Empty(t, packet.Info)
	list.SetPackets([]PacketDisplay{{Protocol: "UDP", Info: "Completed"}})
	require.NotContains(t, list.View(false, false), "Pending")
}

func TestOfflineReadinessStatisticsDistinguishCompleteGlobalAndBaseQuery(t *testing.T) {
	view := NewStatisticsView()
	view.SetSize(180, 40)
	view.SetOfflineStatistics(offline.Statistics{Packets: 1077}, offline.Statistics{Packets: 3})
	view.SetOfflineQueryRevision(offline.BaseRevision)
	view.SetAnalysisPending(true)
	require.Contains(t, view.renderContent(), "Protocol statistics, Events, Calls and application metadata pending")
	view.SetAnalysisPending(false)
	text := view.renderOfflineStatistics()
	require.Contains(t, text, "Global dataset: 1077 packets")
	require.Contains(t, text, "Matching query: 3 packets | 0 bytes | revision 0; application statistics pending")
	view.SetSelectedProtocol("HTTPS/TLS")
	view.SetOfflineTLSObservations(10000, 42)
	require.Contains(t, view.renderProtocolStats(), "42 / 10000")
	require.Contains(t, view.renderProtocolStats(), "complete offline canonical analysis")
	view.SetTLSObservations(TLSObservationStats{Rows: 1, ClientHellos: 2, ECHOffered: 1, Unavailable: 1})
	require.Contains(t, view.renderProtocolStats(), "retained canonical TLS events")
	require.NotContains(t, view.renderProtocolStats(), "complete offline")
}
