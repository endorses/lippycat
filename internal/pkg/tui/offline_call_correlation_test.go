//go:build tui || all

package tui

import (
	"path/filepath"
	"testing"

	"github.com/endorses/lippycat/internal/pkg/types"
	"github.com/stretchr/testify/require"
)

func TestOfflinePublicationClearsForeignCallCorrelation(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	foreign := CorrelatedCallUpdateMsg{CorrelatedCalls: []types.CorrelatedCallInfo{{CorrelationID: "foreign", Legs: []types.CallLegInfo{{CallID: "shared-call", HunterID: "foreign-hunter"}, {CallID: "second-leg", HunterID: "other-hunter"}}}}}
	m, _ = m.handleCorrelatedCallUpdateMsg(foreign)
	m, _ = m.handleCallUpdateMsg(CallUpdateMsg{Calls: []types.CallInfo{{CallID: "shared-call", Hunters: []string{"remote"}}}})
	require.Contains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter")
	failed := open
	failed.Config.Inputs = []string{filepath.Join(t.TempDir(), "missing.pcap")}
	m, failedCmd := m.openOffline(failed)
	failedResult := offlineWorker(t, failedCmd)().(offlineOpenCompleteMsg)
	require.Error(t, failedResult.err)
	m, _ = m.completeOffline(failedResult)
	require.Contains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter", "failed replacement must preserve previous details")
	m, cmd := m.openOffline(open)
	require.Contains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter", "pending replacement must preserve previous details")
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	result.session.Calls = []types.CallInfo{{CallID: "shared-call", Hunters: []string{"Local"}}}
	m, cleanup := m.completeOffline(result)
	cleanup()
	require.NotContains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter")
}

func TestOfflineOpeningRejectsForeignCallCorrelation(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, _ = m.handleCallUpdateMsg(CallUpdateMsg{Calls: []types.CallInfo{{CallID: "shared-call", Hunters: []string{"Local"}}}})
	m, cmd := m.openOffline(open)
	next, _ := m.update(CorrelatedCallUpdateMsg{CorrelatedCalls: []types.CorrelatedCallInfo{{CorrelationID: "foreign", Legs: []types.CallLegInfo{{CallID: "shared-call", HunterID: "foreign-hunter"}, {CallID: "second-leg", HunterID: "other-hunter"}}}}})
	m = next.(Model)
	require.NotContains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter")
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, cleanup := m.completeOffline(result)
	cleanup()
}

func TestOfflineRejectsForeignCallCorrelation(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	result.session.Calls = []types.CallInfo{{CallID: "shared-call", Hunters: []string{"Local"}}}
	m, cleanup := m.completeOffline(result)
	cleanup()
	next, _ := m.update(CorrelatedCallUpdateMsg{CorrelatedCalls: []types.CorrelatedCallInfo{{CorrelationID: "foreign", Legs: []types.CallLegInfo{{CallID: "shared-call", HunterID: "foreign-hunter"}, {CallID: "second-leg", HunterID: "other-hunter"}}}}})
	m = next.(Model)
	require.NotContains(t, m.uiState.CallsView.RenderDetails(120, 50, true), "foreign-hunter")
}
