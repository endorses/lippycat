//go:build tui || all

package tui

import (
	"context"
	"errors"
	"fmt"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/endorses/lippycat/internal/pkg/tui/filters"
)

type offlineBaseReadyMsg struct {
	offlineOpenCompleteMsg
	analysis <-chan offlineAnalysisCompleteMsg
}

type offlineAnalysisCompleteMsg struct {
	generation offline.DatasetGeneration
	revision   offline.AnalysisRevision
	session    *offlineIndexedSession
	snapshot   *offlineRevisionSnapshot
	err        error
}

type offlinePendingFilter struct {
	chain    *filters.FilterChain
	protocol *components.Protocol
}

func (m Model) offlineDataset() offline.Dataset {
	if m.offlineView != nil {
		return m.offlineView.Dataset
	}
	if m.offlineSession != nil {
		return m.offlineSession.Dataset
	}
	return nil
}

func (m Model) offlineEvents() offline.EventDataset {
	if m.offlineView != nil {
		return m.offlineView.EventDataset
	}
	if m.offlineSession != nil {
		return m.offlineSession.EventDataset
	}
	return nil
}

func (m Model) offlineRevision() offline.AnalysisRevision {
	if dataset := m.offlineDataset(); dataset != nil {
		return dataset.Revision()
	}
	return offline.BaseRevision
}

func (m Model) offlineDisplayedRevision() offline.AnalysisRevision {
	if m.offlineBrowse != nil {
		return m.offlineBrowse.owner.dataset.Revision()
	}
	return m.offlineRevision()
}

func (m Model) offlineAnalysisPending() bool {
	return m.offlineSession != nil && m.offlineRevision() == offline.BaseRevision
}

func (m *Model) packetBrowserFor(dataset offline.Dataset) (*offlineBrowserState, error) {
	if dataset == nil || m.offlineSession == nil {
		return nil, errors.New("offline packet dataset unavailable")
	}
	if m.offlinePacketViews == nil {
		m.offlinePacketViews = make(map[offline.AnalysisRevision]*offlineBrowserState)
	}
	if state := m.offlinePacketViews[dataset.Revision()]; state != nil {
		return state, nil
	}
	owner := &offlineBrowser{dataset: dataset, results: make(map[*offlineBrowseResult]struct{})}
	if err := m.offlineSession.registerViewCloser(owner, owner.Cancel); err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	state := &offlineBrowserState{owner: owner}
	m.offlinePacketViews[dataset.Revision()] = state
	return state, nil
}

func (m *Model) filterOwnerFor(revision offline.AnalysisRevision) (*offlineFilterOwner, error) {
	if m.offlineFilterOwners == nil {
		m.offlineFilterOwners = make(map[offline.AnalysisRevision]*offlineFilterOwner)
	}
	if owner := m.offlineFilterOwners[revision]; owner != nil {
		return owner, nil
	}
	owner := &offlineFilterOwner{queries: make(map[offline.Query]struct{})}
	if err := m.offlineSession.registerViewCloser(owner, owner.Cancel); err != nil {
		return nil, errors.Join(err, owner.Close())
	}
	m.offlineFilterOwners[revision] = owner
	return owner, nil
}

func (m Model) completeOfflineBase(msg offlineBaseReadyMsg) (Model, tea.Cmd) {
	m, install := m.completeOffline(msg.offlineOpenCompleteMsg)
	if m.offlineSession != msg.session || m.offlineOpening || m.offlineLeaving {
		return m, install
	}
	m.offlineAnalysisCancelled = false
	m.offlineAnalysisState = "Analysis running"
	m.offlineAnalysisError = ""
	return m, tea.Batch(install, func() tea.Msg { return <-msg.analysis }, offlineProgressCmd(msg.generation, offline.BaseRevision))
}

func (m Model) completeOfflineAnalysis(msg offlineAnalysisCompleteMsg) (Model, tea.Cmd) {
	if msg.revision != offline.CompletedRevision || m.offlineSession != msg.session || msg.generation != m.offlineGeneration || m.offlineOpening || m.offlineLeaving || m.offlineRevision() != offline.BaseRevision {
		return m, nil // The session owns unclaimed completed candidates.
	}
	if m.offlineAnalysisCancelled {
		// Ctrl+X remains authoritative until publication, even if the worker
		// finished before its queued completion reached this Update.
		m.offlineAnalysisState = "Analysis cancelled; complete base retained"
		m.offlineAnalysisError = ""
		session := msg.session
		return m, func() tea.Msg { return offlineCleanupMsg{err: session.discardAnalysisCandidate()} }
	}
	if msg.err != nil {
		if errors.Is(msg.err, context.Canceled) {
			m.offlineAnalysisState = "Analysis cancelled; complete base retained"
			return m, nil
		}
		m.offlineAnalysisState = "Analysis failed; complete base retained"
		m.offlineAnalysisError = msg.err.Error()
		return m, m.uiState.Toast.Show(m.offlineAnalysisState+": "+msg.err.Error(), components.ToastError, components.ToastDurationLong)
	}
	if msg.snapshot == nil || msg.snapshot.Dataset == nil || msg.snapshot.Dataset.Revision() != offline.CompletedRevision || msg.snapshot.Dataset.Generation() != msg.generation || msg.snapshot.EventDataset == nil || msg.snapshot.EventDataset.Revision() != offline.CompletedRevision {
		m.offlineAnalysisState = "Analysis failed; complete base retained"
		return m, m.uiState.Toast.Show("Invalid completed offline analysis snapshot", components.ToastError, components.ToastDurationLong)
	}
	m.cancelOfflineBrowserReads()
	if m.offlineFilter != nil {
		m.offlineFilter.owner.Cancel()
		m.offlineFilter = nil
	}
	m.cancelOfflineRelated()
	m.offlineRelatedOwner = nil
	m.detachOfflineEvents()
	m.offlineView = msg.snapshot
	m.offlineAnalysisState, m.offlineAnalysisError = "Analysis complete", ""
	m.eventStore = msg.snapshot.EventStore
	m.eventStore.SetKindFilter(eventKindsForProtocol(m.uiState.SelectedProtocol.Name))
	m.callTracker = msg.snapshot.Tracker
	m.callStore.Clear()
	m.uiState.CallsView.ClearCorrelatedCalls()
	m, _ = m.handleCallUpdateMsg(CallUpdateMsg{Calls: msg.snapshot.Calls})
	m.eventViewStore = nil
	m.syncEventsView()
	m.installOfflineGlobalStatistics()
	var installedQuery offline.Query
	if m.offlineBrowse != nil {
		m.offlineBrowse.owner.mu.Lock()
		installedQuery = m.offlineBrowse.owner.query
		m.offlineBrowse.owner.mu.Unlock()
	}
	m.publishOfflineStatistics(installedQuery)
	decryptor := msg.snapshot.TLSDecryptor
	m.uiState.DetailsPanel.SetDecryptedDataGetter(func(a, b, c, d string) ([]byte, []byte) {
		if decryptor == nil {
			return nil, nil
		}
		return decryptor.GetDecryptedData(a, b, c, d)
	})
	chain, protocol := m.packetStore.FilterChain.Clone(), (*components.Protocol)(nil)
	if m.offlinePendingPacketFilter != nil {
		chain, protocol = m.offlinePendingPacketFilter.chain, m.offlinePendingPacketFilter.protocol
		m.offlinePendingPacketFilter = nil
	}
	return m, m.startOfflineFilter(chain, protocol)
}

func (m *Model) cancelOfflineAnalysis() tea.Cmd {
	if m.offlineSession == nil || !m.offlineAnalysisPending() || m.offlineAnalysisState != "Analysis running" {
		return nil
	}
	m.offlineAnalysisCancelled = true
	m.offlineSession.CancelAnalysis()
	m.offlineAnalysisState = "Cancelling analysis; complete base remains available"
	return m.uiState.Toast.Show("Cancelling analysis; complete base remains available", components.ToastInfo, components.ToastDurationShort)
}

func (m Model) offlineAnalysisSummary() string {
	if m.offlineSession == nil {
		return ""
	}
	state := m.offlineAnalysisState
	if state == "" {
		state = "Analysis complete"
	}
	if m.offlineAnalysisState == "Analysis running" {
		state += " (Ctrl+X cancels analysis)"
	}
	return fmt.Sprintf("%s | view revision %d", state, m.offlineDisplayedRevision())
}
