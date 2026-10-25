//go:build tui || all

package tui

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/endorses/lippycat/internal/pkg/capture"
	"github.com/endorses/lippycat/internal/pkg/eventquery"
	"github.com/endorses/lippycat/internal/pkg/events"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/testutil/eventfixture"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

// Replicate a real controlled SSH exchange over distinct tuples. The original
// generated negotiation bytes stay unchanged; only checksummed packet headers
// and stable capture timestamps differ. A final flow ends during its first KEX.
func writeSSHEventHistory(t *testing.T, count int) string {
	t.Helper()
	packets, err := eventfixture.SSHMessages()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ssh-history.pcap")
	file, err := os.Create(path)
	require.NoError(t, err)
	writer := pcapgo.NewWriterNanos(file)
	require.NoError(t, writer.WriteFileHeader(65535, layers.LinkTypeEthernet))
	index := 0
	write := func(info capture.PacketInfo, clientPort layers.TCPPort) {
		t.Helper()
		eth := *info.Packet.LinkLayer().(*layers.Ethernet)
		ip := *info.Packet.NetworkLayer().(*layers.IPv4)
		tcp := *info.Packet.TransportLayer().(*layers.TCP)
		if tcp.SrcPort == eventfixture.SSHClientPort {
			tcp.SrcPort = clientPort
		}
		if tcp.DstPort == eventfixture.SSHClientPort {
			tcp.DstPort = clientPort
		}
		require.NoError(t, tcp.SetNetworkLayerForChecksum(&ip))
		raw := goldenSerialize(t, &eth, &ip, &tcp, gopacket.Payload(tcp.Payload))
		at := eventfixture.BaseTime.Add(time.Duration(index) * time.Millisecond)
		index++
		require.NoError(t, writer.WritePacket(gopacket.CaptureInfo{Timestamp: at, CaptureLength: len(raw), Length: len(raw)}, raw))
	}
	for flow := 0; flow < count; flow++ {
		for _, packet := range packets {
			write(packet, layers.TCPPort(eventfixture.SSHClientPort+flow))
		}
	}
	partial := []byte("SSH-2.0-partial_ui\r\n")
	// A valid initial packet header, followed only by its message byte.
	partial = binary.BigEndian.AppendUint32(partial, 36)
	partial = append(partial, 8, 20)
	for _, segment := range []struct {
		client  bool
		tcp     layers.TCP
		payload []byte
	}{
		{true, layers.TCP{Seq: 1000, SYN: true}, nil},
		{false, layers.TCP{Seq: 5000, Ack: 1001, SYN: true, ACK: true}, nil},
		{true, layers.TCP{Seq: 1001, Ack: 5001, ACK: true, PSH: true}, partial},
		{true, layers.TCP{Seq: 1001 + uint32(len(partial)), Ack: 5001, ACK: true, FIN: true}, nil},
	} {
		packet, err := eventfixture.SSHSegment(segment.client, segment.tcp, segment.payload, eventfixture.BaseTime)
		require.NoError(t, err)
		write(packet, layers.TCPPort(eventfixture.SSHClientPort+count))
	}
	// The same genuine negotiation without SYN/SYNACK retains full KEX
	// evidence while neither first-seen direction nor the port proves a role.
	for _, packet := range packets {
		if !packet.Packet.TransportLayer().(*layers.TCP).SYN {
			write(packet, layers.TCPPort(eventfixture.SSHClientPort+count+1))
		}
	}
	require.NoError(t, file.Close())
	return path
}

func progressiveSSHEventView(t *testing.T, path string) (Model, offlineBaseReadyMsg, func()) {
	t.Helper()
	m, open := offlineLifecycleModel(t)
	open.Config.Inputs = []string{path}
	m.offlineController.index = nil
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	m.offlineController.progressive = func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), onBase func(*offlineIndexedSession) error) (*offlineIndexedSession, *offlineRevisionSnapshot, error) {
		return indexOfflineProgressiveDataset(ctx, storage, generation, cfg, report, func(session *offlineIndexedSession) error {
			if err := onBase(session); err != nil {
				return err
			}
			<-gate
			return nil
		})
	}
	m, openCmd := m.openOffline(open)
	message := offlineWorker(t, openCmd)()
	if failure, ok := message.(offlineOpenCompleteMsg); ok {
		t.Fatalf("SSH base failed: %v", failure.err)
	}
	base := message.(offlineBaseReadyMsg)
	m, _ = m.completeOfflineBase(base)
	m.uiState.Width, m.uiState.Height = 200, 36
	m.uiState.ViewMode = "events"
	m.prepareViewChrome()
	return m, base, release
}

func TestSSHCompleteOfflineHistoryPublishesFromSharedRuntime(t *testing.T) {
	const flows = 65
	path := writeSSHEventHistory(t, flows)
	m, base, release := progressiveSSHEventView(t, path)
	require.Equal(t, offline.BaseRevision, m.offlineRevision())
	require.Nil(t, m.offlineEvents())
	require.Contains(t, m.renderCaptureTab(24), "analysis pending")
	release()
	result := <-base.analysis
	require.NoError(t, result.err)
	m, refresh := m.completeOfflineAnalysis(result)
	m = finishOfflineFilter(t, m, refresh)
	require.Equal(t, offline.CompletedRevision, m.offlineRevision())
	require.NotNil(t, m.offlineEvents())
	require.EqualValues(t, 8, m.eventStore.Stats().Retained)
	require.Greater(t, m.offlineEvents().Count(), uint64(m.eventStore.Stats().Retained))
	m, scope := m.handleProtocolSelectedMsg(components.ProtocolSelectedMsg{Protocol: components.Protocol{Name: "SSH", BPFFilter: "protocol:SSH"}})
	m = finishOfflineFilter(t, m, scope)
	// This query scans complete typed history, including events already evicted
	// from the bounded compatibility ring and beyond the first UI viewport.
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"kind:ssh AND status:complete AND role:client"}, "SSH"))
	require.EqualValues(t, flows, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	first, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	client := first.Event.(events.SSHEvent)
	require.Equal(t, events.SSHRoleClient, client.Role)
	require.Equal(t, events.SSHRoleEvidenceTCPSYN, client.RoleEvidence)
	require.Equal(t, events.SSHStatusComplete, client.Status)
	require.Equal(t, events.SSHReasonKEXComplete, client.Reason)
	require.EqualValues(t, eventfixture.SSHClientPort, client.Envelope().Flow.SourcePort)
	require.Equal(t, "2.0", client.ProtocolVersion)
	require.Equal(t, "lippycat_fixture_client", client.SoftwareVersion)
	require.NotEmpty(t, client.HASSH)
	require.NotEmpty(t, client.HASSHAlgorithms)
	require.Equal(t, "1.0", client.HASSHVersion)
	require.True(t, events.HasValidDeliveryIdentity(client.Envelope()))
	m.prepareEventsViewLayout()
	m.uiState.EventsView.PrepareDetails(180, 80)
	details := m.uiState.EventsView.RenderDetails(180, 80, true)
	require.Contains(t, details, client.HASSH)
	require.Contains(t, details, client.KEXAlgorithms)
	require.Contains(t, details, "tcp_syn")
	m.uiState.EventsView.SetLogicalCursor(flows - 1)
	m = loadCompleteOfflineEvents(t, m)
	last, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	require.Greater(t, last.ArrivalSequence, first.ArrivalSequence)
	require.EqualValues(t, eventfixture.SSHClientPort+flows-1, last.Event.Envelope().Flow.SourcePort)
	require.LessOrEqual(t, len(m.offlineEventBrowse.current.items), 2*m.uiState.EventsView.VisibleRows())
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"kind:ssh AND status:complete AND role:server"}, "SSH"))
	require.EqualValues(t, flows, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	serverItem, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	server := serverItem.Event.(events.SSHEvent)
	require.Equal(t, events.SSHRoleServer, server.Role)
	require.EqualValues(t, eventfixture.SSHServerPort, server.Envelope().Flow.SourcePort)
	require.Equal(t, "lippycat_fixture_server", server.SoftwareVersion)
	require.Equal(t, client.Envelope().UID, server.Envelope().UID)
	require.NotEmpty(t, server.HASSH)
	require.NotEqual(t, client.HASSH, server.HASSH)
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"kind:ssh AND status:banner AND role:client"}, "SSH"))
	require.EqualValues(t, flows+1, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	bannerItem, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	banner := bannerItem.Event.(events.SSHEvent)
	require.Equal(t, client.Banner, banner.Banner)
	require.Equal(t, client.Envelope().UID, banner.Envelope().UID)
	require.NotEqual(t, client.Envelope().EventID, banner.Envelope().EventID)
	require.Empty(t, banner.HASSH)
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"kind:ssh AND software_version:partial_ui AND status:partial"}, "SSH"))
	require.EqualValues(t, 1, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	partial, _ := m.uiState.EventsView.DetailSelection()
	partialSSH := partial.Event.(events.SSHEvent)
	require.Empty(t, partialSSH.HASSH)
	require.Equal(t, events.SSHReasonIncomplete, partialSSH.Reason)
	predicate, err := eventquery.Compile("hassh:" + client.HASSH)
	require.NoError(t, err)
	require.False(t, predicate(partialSSH))
	m.prepareEventsViewLayout()
	m.uiState.EventsView.PrepareDetails(180, 80)
	require.Contains(t, m.uiState.EventsView.RenderDetails(180, 80, true), "Unavailable")
	m = completeOfflineEventFilter(t, m, m.startOfflineEventFilter([]string{"kind:ssh AND status:complete AND role:unknown"}, "SSH"))
	require.EqualValues(t, 2, m.offlineEventCount())
	m = loadCompleteOfflineEvents(t, m)
	unprovenItem, ok := m.uiState.EventsView.DetailSelection()
	require.True(t, ok)
	unproven := unprovenItem.Event.(events.SSHEvent)
	require.Empty(t, unproven.HASSH)
	require.NotEmpty(t, unproven.KEXAlgorithms)
	m.uiState.EventsView.PrepareDetails(180, 80)
	require.Contains(t, m.uiState.EventsView.RenderDetails(180, 80, true), "endpoint role unavailable")
	// Reanalyzing identical bytes with the same frozen policy preserves delivery
	// identity and ordered fingerprint evidence across progressive/sync paths.
	baseline, err := indexOfflineDataset(context.Background(), m.offlineController.storage, 700, m.offlineInstalled.Config, nil)
	require.NoError(t, err)
	defer func() { require.NoError(t, baseline.Close()) }()
	match, err := eventquery.Compile("event_id:" + client.Envelope().EventID)
	require.NoError(t, err)
	query, err := baseline.EventDataset.Query(context.Background(), offline.EventQuerySpec{Token: offline.Token{Dataset: 700, Revision: offline.CompletedRevision, Query: 77}, Match: match})
	require.NoError(t, err)
	defer func() { require.NoError(t, query.Close()) }()
	require.EqualValues(t, 1, query.Count())
	require.NoError(t, query.Iterate(context.Background(), func(record offline.EventRecord) error {
		repeated := record.Event.(events.SSHEvent)
		require.Equal(t, client.Envelope().EventID, repeated.Envelope().EventID)
		require.Equal(t, client.HASSH, repeated.HASSH)
		require.Equal(t, client.HASSHAlgorithms, repeated.HASSHAlgorithms)
		return nil
	}))
}

func TestSSHEventScopeUsesCanonicalKindAcrossPorts(t *testing.T) {
	require.True(t, eventScopeAvailable("SSH"))
	event := events.NewSSHEvent(testEventEnvelope("ssh-scope", 1))
	event.EventEnvelope.Flow.DestinationPort = 2222
	require.True(t, eventMatchesProtocol(event, "SSH"))
	require.True(t, eventMatchesProtocol(event, "All"))
	require.False(t, eventMatchesProtocol(events.NewDNSEvent(testEventEnvelope("dns", 2)), "SSH"))
	m := NewModel(8, 8, "test0", "", nil, false, false, "", false)
	t.Cleanup(m.Shutdown)
	m.uiState.SelectedProtocol = components.Protocol{Name: "SSH", BPFFilter: "protocol:SSH"}
	require.Equal(t, []string{"packets", "events"}, m.captureViewsForSelectedProtocol())
	require.Equal(t, []events.Kind{events.KindSSH}, eventKindsForProtocol("SSH"))
	require.Equal(t, "ssh", fmt.Sprint(event.Kind()))
}
