//go:build tui || all

package tui

import (
	"testing"
	"time"

	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/store"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/stretchr/testify/require"
)

func nodeChangeModel() Model {
	m := Model{uiState: store.NewUIState(themes.Solarized()), connectionMgr: store.NewConnectionManager(), captureMode: components.CaptureModeRemote}
	m.uiState.NodesView.SetRemoteChanges(true)
	m.uiState.NodesView.SetSize(140, 20)
	m.connectionMgr.Processors["root"] = &store.ProcessorConnection{Address: "root", ProcessorID: "root-id", State: store.ProcessorStateConnected}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	return m
}

func nodeJoin(owner, id string) TopologyUpdateMsg {
	return TopologyUpdateMsg{ProcessorAddr: "root", Update: &management.TopologyUpdate{
		ProcessorId: owner, UpdateType: management.TopologyUpdateType_TOPOLOGY_HUNTER_CONNECTED,
		Event: &management.TopologyUpdate_HunterConnected{HunterConnected: &management.HunterConnectedEvent{Hunter: &management.ConnectedHunter{HunterId: id}}},
	}}
}

func TestNodeChangesTopologyAndPollingDeduplicate(t *testing.T) {
	m := nodeChangeModel()
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
	require.Contains(t, m.uiState.NodesView.View(), "edge joined")
	require.Contains(t, m.uiState.NodesView.View(), "NEW")
	require.True(t, m.connectionMgr.HuntersByProcessor["root"][0].StatsUnavailable)

	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "edge", CPUPercent: 24, ActiveFilters: 5}}})
	require.NotContains(t, m.uiState.NodesView.View(), "↑", "first metrics establish a quiet baseline")
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
	require.NotContains(t, m.uiState.NodesView.View(), "more)", "duplicate join is not a second event")

	msg := TopologyUpdateMsg{ProcessorAddr: "root", Update: &management.TopologyUpdate{ProcessorId: "root-id", UpdateType: management.TopologyUpdateType_TOPOLOGY_HUNTER_DISCONNECTED,
		Event: &management.TopologyUpdate_HunterDisconnected{HunterDisconnected: &management.HunterDisconnectedEvent{HunterId: "edge"}}}}
	m, _ = m.handleTopologyUpdateMsg(msg)
	require.Empty(t, m.connectionMgr.HuntersByProcessor["root"])
	require.Contains(t, m.uiState.NodesView.View(), "edge disconnected")
	require.Contains(t, m.uiState.NodesView.View(), "+1 more")
	m, _ = m.handleTopologyUpdateMsg(msg)
	require.Contains(t, m.uiState.NodesView.View(), "+1 more")
	require.NotContains(t, m.uiState.NodesView.View(), "+2 more")
}

func TestNodeChangesPollFirstJoinAndSnapshotBaseline(t *testing.T) {
	m := nodeChangeModel()
	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "edge", CPUPercent: 24}}})
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
	require.Contains(t, m.uiState.NodesView.View(), "NEW")
	require.Contains(t, m.uiState.NodesView.View(), "edge joined")
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
	require.NotContains(t, m.uiState.NodesView.View(), "more)")

	m = nodeChangeModel()
	m, _ = m.handleTopologyReceivedMsg(TopologyReceivedMsg{Address: "root", Topology: &management.ProcessorNode{
		Address: "root", ProcessorId: "root-id", Hunters: []*management.ConnectedHunter{{HunterId: "initial"}},
	}})
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "initial"))
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
	require.NotContains(t, m.uiState.NodesView.View(), "joined")
}

func TestNodeChangesEstablishmentWithoutTopologyRemainsBaseline(t *testing.T) {
	for _, statusFirst := range []bool{false, true} {
		m := nodeChangeModel()
		m.connectionMgr.Processors["root"].State = store.ProcessorStateConnecting
		if statusFirst {
			m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "edge"}}})
		} else {
			m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
		}
		m, _ = m.handleProcessorConnectedMsg(ProcessorConnectedMsg{Address: "root"})
		m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "edge"))
		require.NotContains(t, m.uiState.NodesView.View(), "NEW")
		require.NotContains(t, m.uiState.NodesView.View(), "joined")
	}
	m := nodeChangeModel()
	m.connectionMgr.Processors["root"].State = store.ProcessorStateConnecting
	msg := TopologyUpdateMsg{ProcessorAddr: "root", Update: &management.TopologyUpdate{ProcessorId: "root-id", UpdateType: management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		Event: &management.TopologyUpdate_ProcessorConnected{ProcessorConnected: &management.ProcessorConnectedEvent{Processor: &management.ProcessorNode{Address: "child", ProcessorId: "child-id"}}}}}
	m, _ = m.handleTopologyUpdateMsg(msg)
	m, _ = m.handleProcessorConnectedMsg(ProcessorConnectedMsg{Address: "root"})
	m, _ = m.handleTopologyUpdateMsg(msg)
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
	require.NotContains(t, m.uiState.NodesView.View(), "joined")
}

func TestNodeChangesProcessorRegistrationAndSelfOriginReconnect(t *testing.T) {
	m := nodeChangeModel()
	msg := TopologyUpdateMsg{ProcessorAddr: "root", Update: &management.TopologyUpdate{
		ProcessorId: "root-id", UpdateType: management.TopologyUpdateType_TOPOLOGY_PROCESSOR_CONNECTED,
		Event: &management.TopologyUpdate_ProcessorConnected{ProcessorConnected: &management.ProcessorConnectedEvent{Processor: &management.ProcessorNode{Address: "child", ProcessorId: "child-id", Reachable: true}}},
	}}
	m, _ = m.handleTopologyUpdateMsg(msg)
	require.Equal(t, "root", m.connectionMgr.Processors["child"].UpstreamAddr)
	msg.Update.ProcessorId = "child-id" // downstream manager reconnect producer
	m, _ = m.handleTopologyUpdateMsg(msg)
	require.Equal(t, "root", m.connectionMgr.Processors["child"].UpstreamAddr)
	require.True(t, m.nodeWithinSource("child", "root"))
	require.Contains(t, m.uiState.NodesView.View(), "child")
	require.NotContains(t, m.uiState.NodesView.View(), "more)", "same processor reconnect snapshot is not a second join")
}

func TestNodeChangesFreshMetricsBaselineAfterReconnect(t *testing.T) {
	m := nodeChangeModel()
	m.connectionMgr.HuntersByProcessor["root"] = []components.HunterInfo{{ID: "edge", CPUPercent: 12, MemoryRSSBytes: 1000, PacketsCaptured: 10, ActiveFilters: 1}}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	m, _ = m.handleProcessorDisconnectedMsg(ProcessorDisconnectedMsg{Address: "root"})
	require.True(t, m.connectionMgr.HuntersByProcessor["root"][0].StatsUnavailable)
	m, _ = m.handleProcessorConnectedMsg(ProcessorConnectedMsg{Address: "root"})
	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "edge", CPUPercent: 80, MemoryRSSBytes: 3000, PacketsCaptured: 100, ActiveFilters: 8}}})
	view := m.uiState.NodesView.View()
	require.Contains(t, view, "80%")
	require.NotContains(t, view, "↑")
	require.NotContains(t, view, "+7")
	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "edge", CPUPercent: 90, MemoryRSSBytes: 3000, PacketsCaptured: 110, ActiveFilters: 8}}})
	require.Contains(t, m.uiState.NodesView.View(), "↑")
}

func TestNodeChangesSubscriptionsAndInitialSnapshotsStayQuiet(t *testing.T) {
	m := nodeChangeModel()
	m.connectionMgr.Processors["root"].State = store.ProcessorStateConnecting
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "initial"))
	require.NotContains(t, m.uiState.NodesView.View(), "joined")
	m.connectionMgr.Processors["root"].State = store.ProcessorStateConnected
	m.connectionMgr.Processors["root"].SubscribedHunters = []string{}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("root-id", "hidden"))
	require.NotContains(t, m.uiState.NodesView.View(), "joined")
	m.connectionMgr.Processors["root"].SubscribedHunters = nil
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
	require.NotContains(t, m.uiState.NodesView.View(), "disconnected")
}

func TestNodeChangesScopedIdentityAndForwardedOrigin(t *testing.T) {
	m := nodeChangeModel()
	m.connectionMgr.Processors["child"] = &store.ProcessorConnection{Address: "child", ProcessorID: "child-id", UpstreamAddr: "root", State: store.ProcessorStateUnknown}
	m.connectionMgr.Processors["other"] = &store.ProcessorConnection{Address: "other", State: store.ProcessorStateConnected}
	m.connectionMgr.HuntersByProcessor["other"] = []components.HunterInfo{{ID: "same", ProcessorAddr: "other", CPUPercent: 81}}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("child-id", "same"))
	require.Len(t, m.connectionMgr.HuntersByProcessor["child"], 1)
	require.Empty(t, m.connectionMgr.HuntersByProcessor["root"])
	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "same", ProcessorAddr: "root", CPUPercent: 24}}})
	require.Equal(t, float64(24), m.connectionMgr.HuntersByProcessor["child"][0].CPUPercent)
	require.Equal(t, float64(81), m.connectionMgr.HuntersByProcessor["other"][0].CPUPercent)

	// An aggregated response without an owner or unique remote address cannot
	// safely distinguish duplicate IDs within one subtree.
	m.connectionMgr.HuntersByProcessor["root"] = []components.HunterInfo{{ID: "same", CPUPercent: 12}}
	m, _ = m.handleHunterStatusMsg(HunterStatusMsg{ProcessorAddr: "root", Hunters: []components.HunterInfo{{ID: "same", CPUPercent: 99}}})
	require.Equal(t, float64(12), m.connectionMgr.HuntersByProcessor["root"][0].CPUPercent)
	require.Equal(t, float64(24), m.connectionMgr.HuntersByProcessor["child"][0].CPUPercent)
}

func TestNodeChangesParentLossAndRecovery(t *testing.T) {
	m := nodeChangeModel()
	m.connectionMgr.HuntersByProcessor["root"] = []components.HunterInfo{{ID: "edge", CPUPercent: 12}}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	m, _ = m.handleProcessorDisconnectedMsg(ProcessorDisconnectedMsg{Address: "root"})
	view := ansi.Strip(m.uiState.NodesView.View())
	require.Contains(t, view, "root disconnected")
	require.NotContains(t, view, "edge disconnected")
	require.Len(t, m.connectionMgr.HuntersByProcessor["root"], 1)
	m, _ = m.handleProcessorDisconnectedMsg(ProcessorDisconnectedMsg{Address: "root"})
	require.NotContains(t, m.uiState.NodesView.View(), "more)")
	m, _ = m.handleProcessorConnectedMsg(ProcessorConnectedMsg{Address: "root"})
	require.Contains(t, m.uiState.NodesView.View(), "RECOVERED")
	require.Contains(t, m.uiState.NodesView.View(), "root recovered")
}

func TestNodeChangesExpireOnPausedTickInAnotherTab(t *testing.T) {
	m := NewModel(32, 8, "", "", nil, false, true, "", true)
	m.uiState.NodesView.SetSize(140, 20)
	m.connectionMgr.Processors["root"] = &store.ProcessorConnection{Address: "root", State: store.ProcessorStateConnected}
	m.uiState.NodesView.SetProcessors(m.getProcessorInfoList())
	m, _ = m.handleTopologyUpdateMsg(nodeJoin("", "edge"))
	require.Contains(t, m.uiState.NodesView.View(), "NEW")
	m.uiState.Paused = true
	m.uiState.Tabs.SetActive(2)
	m, cmd := m.handleTickMsg(TickMsg{Time: time.Now().Add(31 * time.Second)})
	require.NotNil(t, cmd, "the existing idle tick chain continues")
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
	require.NotContains(t, m.uiState.NodesView.View(), "joined")
	m.uiState.Tabs.SetActive(1)
	require.NotContains(t, m.uiState.NodesView.View(), "NEW")
}
