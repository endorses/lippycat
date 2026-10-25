//go:build tui || all

package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/stretchr/testify/require"
)

// Hold the production pipeline at the publication boundary, without replacing
// its normalization, backing ownership, ordered analysis or query code.
func progressiveOfflineView(t *testing.T, fail error) (Model, offlineBaseReadyMsg, func()) {
	t.Helper()
	m, open := offlineLifecycleModel(t)
	open.Config.Inputs = writeOrderedBridgeFixtures(t)
	m.offlineController.index = nil
	gate := make(chan struct{})
	var once sync.Once
	release := func() { once.Do(func() { close(gate) }) }
	t.Cleanup(release)
	m.offlineController.progressive = func(ctx context.Context, storage *offline.Storage, generation offline.DatasetGeneration, cfg OfflineAnalysisConfig, report func(offline.Progress), onBase func(*offlineIndexedSession) error) (*offlineIndexedSession, *offlineRevisionSnapshot, error) {
		return indexOfflineProgressiveDataset(ctx, storage, generation, cfg, report, func(s *offlineIndexedSession) error {
			if err := onBase(s); err != nil {
				return err
			}
			<-gate
			return fail
		})
	}
	m, cmd := m.openOffline(open)
	message := offlineWorker(t, cmd)()
	if failed, ok := message.(offlineOpenCompleteMsg); ok {
		t.Fatalf("progressive base failed: %v", failed.err)
	}
	base := message.(offlineBaseReadyMsg)
	require.NoError(t, base.err)
	m, _ = m.completeOfflineBase(base)
	m.uiState.Width, m.uiState.Height = 180, 35
	m.prepareViewChrome()
	return m, base, release
}

func TestOfflineProgressiveBaseReadinessAndPublicationPreservesSelection(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	require.False(t, m.offlineOpening)
	require.True(t, m.offlineAnalysisPending())
	require.Equal(t, offline.BaseRevision, m.offlineDataset().Revision())
	require.Equal(t, uint64(1077), m.offlineDataset().Count())
	require.Nil(t, m.offlineEvents())
	m = loadOfflineBrowser(t, m)
	require.Empty(t, m.uiState.PacketList.GetSelectedPacket().Protocol)
	require.Contains(t, m.renderCaptureTab(20), "Pending")
	m.uiState.ViewMode = "events"
	require.Contains(t, m.renderCaptureTab(20), "analysis pending")
	m.uiState.ViewMode = "packets"
	m = finishOfflineFilter(t, m, m.parseAndApplyFilter("port 32000"))
	require.True(t, m.packetStore.HasFilter())
	descriptions := m.packetStore.FilterChain.GetFilterDescriptions()
	old := m.offlineBrowse.owner.query
	m.parseAndApplyFilter("protocol:DNS")
	require.Nil(t, m.offlineFilter)
	require.NotNil(t, m.offlinePendingPacketFilter)
	require.Same(t, old, m.offlineBrowse.owner.query)
	require.Equal(t, descriptions, m.packetStore.FilterChain.GetFilterDescriptions())
	// Restore the installed B-only query as the desired refresh.
	m.offlinePendingPacketFilter = nil
	m.uiState.PacketList.SetLogicalCursor(900)
	// The selected row is deliberately outside the loaded viewport. Publication
	// resolves PacketID through the old query and Position in the new query.
	require.Nil(t, m.uiState.PacketList.GetSelectedPacket())
	release()
	complete := <-base.analysis
	require.NoError(t, complete.err)
	m, cmd := m.completeOfflineAnalysis(complete)
	require.Equal(t, offline.CompletedRevision, m.offlineDataset().Revision())
	require.Equal(t, offline.BaseRevision, m.offlineDisplayedRevision())
	require.NotNil(t, m.offlineEvents())
	m = finishOfflineFilter(t, m, cmd)
	require.Equal(t, offline.CompletedRevision, m.offlineDisplayedRevision())
	require.Equal(t, uint64(900), m.uiState.PacketList.LogicalCursor())
	m = loadOfflineBrowser(t, m)
	require.Equal(t, uint64(901), m.uiState.PacketList.GetSelectedPacket().CaptureID)
	require.Equal(t, descriptions, m.packetStore.FilterChain.GetFilterDescriptions())
	require.Equal(t, offline.BaseRevision, m.offlineSession.Dataset.Revision())
	require.Contains(t, m.offlineAnalysisSummary(), "Analysis complete")
}

func TestOfflineProgressiveFailureAndCancellationRetainBase(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "failure"}[failure], func(t *testing.T) {
			var injected error
			if failure {
				injected = errors.New("ordered analyzer failed")
			}
			m, base, release := progressiveOfflineView(t, injected)
			m = loadOfflineBrowser(t, m)
			installed := m.offlineSession
			if !failure {
				m.cancelOfflineAnalysis()
			}
			release()
			result := <-base.analysis
			if failure {
				require.ErrorContains(t, result.err, "ordered analyzer failed")
			} else {
				require.ErrorIs(t, result.err, context.Canceled)
			}
			m, _ = m.completeOfflineAnalysis(result)
			require.Same(t, installed, m.offlineSession)
			require.Equal(t, offline.BaseRevision, m.offlineDisplayedRevision())
			require.Contains(t, m.offlineAnalysisState, "complete base retained")
			m = finishOfflineFilter(t, m, m.parseAndApplyFilter("port 32000"))
			m.startOfflineExport(filepath.Join(t.TempDir(), "base.pcap"))
			<-m.offlineExport.done
			require.NoError(t, m.offlineExport.result.Error)
			require.Equal(t, uint64(1077), m.offlineExport.result.PacketsSaved)
		})
	}
}

func TestOfflineProgressiveRefreshFailureRetainsExplicitBaseQuery(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	query := m.offlineBrowse.owner.query
	release()
	result := <-base.analysis
	require.NoError(t, result.err)
	result.snapshot.Dataset = failingOfflineQueryDataset{result.snapshot.Dataset}
	m, cmd := m.completeOfflineAnalysis(result)
	message := cmd().(tea.BatchMsg)[0]().(offlineFilterMsg)
	require.ErrorContains(t, message.err, "injected")
	m, _ = m.handleOfflineFilter(message)
	require.Same(t, query, m.offlineBrowse.owner.query)
	require.Equal(t, offline.BaseRevision, m.offlineDisplayedRevision())
	require.Equal(t, offline.CompletedRevision, m.offlineRevision())
	require.Contains(t, m.offlineAnalysisSummary(), "view revision 0")
}

func TestOfflineProgressiveRejectsWrongRevisionSuccessErrorAndProgress(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	m.uiState.PacketList.SetLogicalCursor(100)
	stale := m.syncOfflineBrowser()().(offlineBrowseMsg)
	require.NoError(t, stale.result.err)
	release()
	complete := <-base.analysis
	require.NoError(t, complete.err)
	m, cmd := m.completeOfflineAnalysis(complete)
	m = finishOfflineFilter(t, m, cmd)
	current := m.offlineBrowse
	for _, err := range []error{nil, errors.New("obsolete base read")} {
		stale.result.err = err
		m, _ = m.handleOfflineBrowse(stale)
		require.Same(t, current, m.offlineBrowse)
	}
	oldProgress := m.offlineProgress
	updated, _ := m.update(offlineProgressMsg{generation: m.offlineGeneration, revision: offline.BaseRevision})
	m = updated.(Model)
	require.Equal(t, oldProgress, m.offlineProgress)
	// Related errors also require the exact revision, even within one generation.
	state := &offlineRelatedState{generation: m.offlineGeneration, revision: offline.BaseRevision}
	m.offlineRelated = state
	m, relatedCmd := m.handleOfflineRelated(offlineRelatedMsg{state: state, err: errors.New("obsolete lookup")})
	require.Nil(t, relatedCmd)
	require.False(t, state.failed)
}

func TestOfflineProgressiveExportCompletionKeepsItsBaseToken(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	path := filepath.Join(t.TempDir(), "base-export.pcap")
	pin, _, err := m.pinOfflineMarkQuery()
	require.NoError(t, err)
	exportGate := make(chan struct{})
	var exportOnce sync.Once
	unblock := func() { exportOnce.Do(func() { close(exportGate) }) }
	t.Cleanup(unblock)
	cmd := m.startOfflinePinnedExport(path, pin, func(ctx context.Context, visit func(offline.RawRecord) error) error {
		select {
		case <-exportGate:
			return pin.IterateRaw(ctx, visit)
		case <-ctx.Done():
			return ctx.Err()
		}
	}, "Saving base export")
	export := m.offlineExport
	require.Equal(t, offline.BaseRevision, export.token.Revision)
	release()
	complete := <-base.analysis
	m, refresh := m.completeOfflineAnalysis(complete)
	filterResult := refresh().(tea.BatchMsg)[0]().(offlineFilterMsg)
	require.NoError(t, filterResult.err)
	m, cleanup := m.handleOfflineFilter(filterResult)
	retired := make(chan tea.Msg, 1)
	go func() { retired <- cleanup() }()
	require.Equal(t, offline.CompletedRevision, m.offlineDisplayedRevision())
	select {
	case <-export.done:
		t.Fatal("publication cancelled a base export")
	default:
	}
	unblock()
	<-export.done
	require.NoError(t, export.result.Error)
	<-retired
	require.Same(t, export, m.offlineExport)
	message := cmd().(tea.BatchMsg)[1]().(offlineExportCompleteMsg)
	updated, _ := m.update(message)
	m = updated.(Model)
	require.False(t, m.uiState.SaveInProgress)
	require.Equal(t, uint64(1077), message.state.result.PacketsSaved)
	// A same-session stale operation cannot complete a later save.
	newer := &offlineExportState{token: offline.Token{Dataset: m.offlineGeneration, Revision: offline.CompletedRevision}, done: make(chan struct{}), cancel: func() {}}
	m.offlineExport = newer
	m.uiState.SaveInProgress = true
	updated, _ = m.update(message)
	require.True(t, updated.(Model).uiState.SaveInProgress)
	m.offlineExport = export
}

func TestOfflineProgressiveCancelKeyKeepsBaseUsable(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m, _ = m.handleKeyboard(tea.KeyMsg{Type: tea.KeyCtrlX})
	require.Contains(t, m.offlineAnalysisState, "Cancelling")
	require.False(t, m.offlineOpening)
	release()
	m, _ = m.completeOfflineAnalysis(<-base.analysis)
	require.Equal(t, components.CaptureModeOffline, m.captureMode)
	require.Equal(t, offline.BaseRevision, m.offlineRevision())
}

func TestOfflineProgressiveReplacementRejectsPriorAnalysis(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	old := m.offlineSession
	next := m.offlineInstalled
	next.Config.Inputs = next.Config.Inputs[:1]
	m.offlineController.progressive = nil
	m, cmd := m.openOffline(next)
	release()
	obsolete := <-base.analysis
	require.ErrorIs(t, obsolete.err, context.Canceled)
	message := offlineWorker(t, cmd)()
	ready, ok := message.(offlineBaseReadyMsg)
	require.True(t, ok, "replacement message %T: %+v", message, message)
	m, _ = m.completeOfflineBase(ready)
	require.NotSame(t, old, m.offlineSession)
	installed := m.offlineSession
	before := m.offlineAnalysisState
	m, _ = m.completeOfflineAnalysis(obsolete)
	require.Same(t, installed, m.offlineSession)
	require.Equal(t, before, m.offlineAnalysisState)
	result := <-ready.analysis
	require.NoError(t, result.err)
	m, refresh := m.completeOfflineAnalysis(result)
	m = finishOfflineFilter(t, m, refresh)
	require.Equal(t, offline.CompletedRevision, m.offlineDisplayedRevision())
	require.Equal(t, uint64(1023), m.offlinePacketCount())
}

func TestOfflineProgressiveQuitCancelsPinnedExportBeforeQueryJoin(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	pin, _, err := m.pinOfflineMarkQuery()
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "interrupted.pcap")
	m.startOfflinePinnedExport(path, pin, func(ctx context.Context, _ func(offline.RawRecord) error) error {
		<-ctx.Done()
		return ctx.Err()
	}, "Waiting export")
	export := m.offlineExport
	release()
	result := <-base.analysis
	require.NoError(t, result.err)
	m, refresh := m.completeOfflineAnalysis(result)
	filtered := refresh().(tea.BatchMsg)[0]().(offlineFilterMsg)
	require.NoError(t, filtered.err)
	m, retire := m.handleOfflineFilter(filtered)
	retired := make(chan tea.Msg, 1)
	go func() { retired <- retire() }()
	m, quit := m.leaveOffline(nil, true)
	done := make(chan tea.Msg, 1)
	go func() { done <- quit() }()
	select {
	case message := <-done:
		cleanup := message.(offlineCleanupMsg)
		require.NoError(t, cleanup.err)
		require.True(t, cleanup.quit)
	case <-time.After(10 * time.Second):
		t.Fatal("session cleanup waited for query pins before cancelling export")
	}
	<-retired
	<-export.done
	require.ErrorIs(t, export.result.Error, context.Canceled)
	_, err = os.Stat(path)
	require.ErrorIs(t, err, os.ErrNotExist)
}

func TestOfflineProgressiveQueuedFiltersApplyAfterPublication(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	m.parseAndApplyFilter("protocol:UDP")
	m.parseAndApplyFilter("NOT impossible")
	require.NotNil(t, m.offlinePendingPacketFilter)
	require.Len(t, m.offlinePendingPacketFilter.chain.GetFilterDescriptions(), 2)
	require.False(t, m.packetStore.HasFilter())
	release()
	result := <-base.analysis
	require.NoError(t, result.err)
	// Exact error identity remains significant even with the same session/generation.
	wrong := result
	wrong.revision = offline.BaseRevision
	wrong.err = errors.New("obsolete revision failure")
	m, _ = m.completeOfflineAnalysis(wrong)
	require.True(t, m.offlineAnalysisPending())
	m, refresh := m.completeOfflineAnalysis(result)
	m = finishOfflineFilter(t, m, refresh)
	require.Nil(t, m.offlinePendingPacketFilter)
	require.Len(t, m.packetStore.FilterChain.GetFilterDescriptions(), 2)
	require.Equal(t, uint64(1077), m.offlinePacketCount())
}

func TestOfflineProgressiveReplacementClearsOldExportPresentation(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	pin, _, err := m.pinOfflineMarkQuery()
	require.NoError(t, err)
	delivery := m.startOfflinePinnedExport(filepath.Join(t.TempDir(), "replaced.pcap"), pin, func(ctx context.Context, _ func(offline.RawRecord) error) error {
		<-ctx.Done()
		return ctx.Err()
	}, "Saving previous capture")
	export := m.offlineExport
	next := m.offlineInstalled
	next.Config.Inputs = next.Config.Inputs[:1]
	m.offlineController.progressive = nil
	m, open := m.openOffline(next)
	release()
	<-base.analysis
	ready := offlineWorker(t, open)().(offlineBaseReadyMsg)
	m, install := m.completeOfflineBase(ready)
	require.Nil(t, m.offlineExport)
	require.False(t, m.uiState.SaveInProgress)
	// Installation owns disposal of the prior session, which cancels its export.
	installBatch := install().(tea.BatchMsg)
	cleanupBatch := installBatch[0]().(tea.BatchMsg)
	cleanup := cleanupBatch[0]().(offlineCleanupMsg)
	require.NoError(t, cleanup.err)
	<-export.done
	require.ErrorIs(t, export.result.Error, context.Canceled)
	obsolete := delivery().(tea.BatchMsg)[1]().(offlineExportCompleteMsg)
	updated, _ := m.update(obsolete)
	require.False(t, updated.(Model).uiState.SaveInProgress)
}

func TestOfflineProgressiveFailedReplacementRetainsAccurateBaseStatus(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	previous := m.offlineSession
	next := m.offlineInstalled
	next.Config.Inputs = []string{filepath.Join(t.TempDir(), "missing.pcap")}
	m.offlineController.progressive = nil
	m, open := m.openOffline(next)
	release()
	<-base.analysis
	failed := offlineWorker(t, open)().(offlineOpenCompleteMsg)
	require.Error(t, failed.err)
	m, cleanup := m.completeOffline(failed)
	message := cleanup().(tea.BatchMsg)[1]().(offlineCleanupMsg)
	updated, _ := m.update(message)
	m = updated.(Model)
	require.False(t, m.offlineOpening)
	require.Same(t, previous, m.offlineSession)
	require.Equal(t, "Analysis cancelled; complete base retained", m.offlineAnalysisState)
	require.NotContains(t, m.offlineAnalysisSummary(), "Ctrl+X")
	m = finishOfflineFilter(t, m, m.parseAndApplyFilter("port 32000"))
	require.Equal(t, uint64(1077), m.offlinePacketCount())
}

func TestOfflineProgressiveCancellationWinsBeforeQueuedSuccessDelivery(t *testing.T) {
	m, base, release := progressiveOfflineView(t, nil)
	m = loadOfflineBrowser(t, m)
	baseDataset, baseQuery := m.offlineDataset(), m.offlineBrowse.owner.query
	release()
	complete := <-base.analysis
	require.NoError(t, complete.err)
	require.True(t, m.offlineAnalysisPending())
	// The real worker has finished, but its successful completion is still queued.
	cancelledModel, _ := m.Update(tea.KeyMsg{Type: tea.KeyCtrlX})
	m = cancelledModel.(Model)
	require.Contains(t, m.offlineAnalysisState, "Cancelling")
	completedModel, cleanup := m.Update(complete)
	m = completedModel.(Model)
	require.Equal(t, offline.BaseRevision, m.offlineRevision(), "accepted analysis cancellation must win before success publication")
	require.Equal(t, "Analysis cancelled; complete base retained", m.offlineAnalysisState)
	require.Same(t, baseDataset, m.offlineDataset())
	require.Same(t, baseQuery, m.offlineBrowse.owner.query)
	require.Nil(t, m.offlineView)
	require.Nil(t, m.offlineFilter)
	// The Update command owns asynchronous disposal. If delivery is abandoned,
	// the session still owns the unclaimed candidate until whole-session cleanup.
	m.offlineSession.analysisMu.Lock()
	candidate := m.offlineSession.analysisCandidate
	m.offlineSession.analysisMu.Unlock()
	require.NotNil(t, candidate)
	require.NotNil(t, cleanup)
	cleaned := false
	var run func(tea.Cmd)
	run = func(cmd tea.Cmd) {
		if cmd == nil {
			return
		}
		switch msg := cmd().(type) {
		case tea.BatchMsg:
			for _, child := range msg {
				run(child)
			}
		case offlineCleanupMsg:
			require.NoError(t, msg.err)
			cleaned = true
		}
	}
	run(cleanup)
	require.True(t, cleaned)
	m.offlineSession.analysisMu.Lock()
	candidate = m.offlineSession.analysisCandidate
	m.offlineSession.analysisMu.Unlock()
	require.Nil(t, candidate)
	m = finishOfflineFilter(t, m, m.parseAndApplyFilter("port 32000"))
	require.Equal(t, uint64(1077), m.offlinePacketCount())
}
