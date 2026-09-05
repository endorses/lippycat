//go:build tui || all

package tui

import (
	"context"
	"errors"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/stretchr/testify/require"
)

func TestOfflineCancelCleanupRetryPreservesReadySession(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	first := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, first.err)
	m, cleanup := m.completeOffline(first)
	cleanup()
	ready := m.offlineSession
	events, calls := m.eventStore, m.callStore

	m, cmd = m.openOffline(open)
	candidate := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, candidate.err)
	candidate.session.Dataset = &offlineCloseAfterReleaseFailure{Dataset: candidate.session.Dataset}
	m, _ = m.cancelOffline()
	m, cleanup = m.completeOffline(candidate)
	next, _ := m.update(cleanup())
	m = next.(Model)
	require.True(t, m.offlineOpening, "cancel cleanup failure must retain modal")
	require.Contains(t, m.offlineModal(), "Retry cleanup")
	require.Same(t, ready, m.offlineSession)

	next, retry := m.update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	require.NotNil(t, retry)
	next, _ = m.update(retry())
	m = next.(Model)
	require.False(t, m.offlineOpening)
	require.Same(t, ready, m.offlineSession)
	require.Same(t, events, m.eventStore)
	require.Same(t, calls, m.callStore)
	query, err := ready.Dataset.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: first.generation}})
	require.NoError(t, err, "retry must not close the installed ready dataset")
	require.NoError(t, query.Close())
	m.offlineController.mu.Lock()
	_, owned := m.offlineController.sessions[candidate.session]
	m.offlineController.mu.Unlock()
	require.False(t, owned, "retry must release abandoned replacement")
}

func TestOfflineCancelSurfacesJoinedWorkerError(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	started := make(chan struct{})
	m.offlineController.index = func(ctx context.Context, _ *offline.Storage, _ offline.DatasetGeneration, _ OfflineAnalysisConfig, _ func(offline.Progress)) (*offlineIndexedSession, error) {
		close(started)
		<-ctx.Done()
		return nil, errors.Join(ctx.Err(), errors.New("injected analyzer cleanup error"))
	}
	m, cmd := m.openOffline(open)
	worker := offlineWorker(t, cmd)
	<-started
	m, _ = m.cancelOffline()
	result := worker().(offlineOpenCompleteMsg)
	require.ErrorContains(t, result.err, "injected analyzer cleanup error")
	m, cleanup := m.completeOffline(result)
	next, _ := m.update(cleanup())
	m = next.(Model)
	require.True(t, m.uiState.Toast.IsActive(), "cancellation must not silently discard joined worker errors")
	require.Contains(t, m.uiState.Toast.View(), "injected analyzer cleanup error")
}

func TestOfflineCancelCleanupReopenFailurePreservesReadySession(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	first := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, first.err)
	m, cleanup := m.completeOffline(first)
	cleanup()
	ready := m.offlineSession
	m, cmd = m.openOffline(open)
	candidate := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, candidate.err)
	candidate.session.Dataset = &offlineCloseAfterReleaseFailure{Dataset: candidate.session.Dataset}
	m, _ = m.cancelOffline()
	m, cleanup = m.completeOffline(candidate)
	next, _ := m.update(cleanup())
	m = next.(Model)
	require.True(t, m.offlineCleanupFailed)

	failed := open
	failed.Config.Inputs = []string{open.Limits.Directory + "/missing.pcap"}
	m, retry := m.openOffline(failed)
	require.NotNil(t, retry)
	latest := failed
	latest.Config.Inputs = []string{open.Limits.Directory + "/latest-missing.pcap"}
	m, cmd = m.openOffline(latest)
	require.Nil(t, cmd, "reopens during cancellation cleanup must queue")
	next, cmd = m.update(retry())
	m = next.(Model)
	require.True(t, m.offlineOpening)
	require.Same(t, ready, m.offlineSession)
	require.Equal(t, latest.Config.Inputs, m.offlinePending.Config.Inputs)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.Error(t, result.err)
	m, _ = m.completeOffline(result)
	require.False(t, m.offlineOpening)
	require.Same(t, ready, m.offlineSession)
	require.Equal(t, open.Config.Inputs, m.pcapFiles)
	query, err := ready.Dataset.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: first.generation}})
	require.NoError(t, err)
	require.NoError(t, query.Close())
}

func TestOfflineFailedOpenCleanupRetainsRetryModal(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	first := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, first.err)
	m, cleanup := m.completeOffline(first)
	cleanup()
	ready := m.offlineSession

	m, cmd = m.openOffline(open)
	candidate := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, candidate.err)
	candidate.session.Dataset = &offlineCloseAfterReleaseFailure{Dataset: candidate.session.Dataset}
	candidate.err = errors.New("injected finalization failure")
	m, cmd = m.completeOffline(candidate)
	batch := cmd().(tea.BatchMsg)
	next, _ := m.update(batch[1]())
	m = next.(Model)
	require.True(t, m.offlineOpening, "failed candidate cleanup must retain modal")
	require.True(t, m.offlineCleanupFailed)
	require.Contains(t, m.offlineModal(), "Retry cleanup")
	require.Same(t, ready, m.offlineSession)
	next, retry := m.update(tea.KeyMsg{Type: tea.KeyEnter})
	m = next.(Model)
	require.NotNil(t, retry)
	next, _ = m.update(retry())
	m = next.(Model)
	require.False(t, m.offlineOpening)
	require.Same(t, ready, m.offlineSession)
	m.offlineController.mu.Lock()
	_, owned := m.offlineController.sessions[candidate.session]
	m.offlineController.mu.Unlock()
	require.False(t, owned)
}

func TestOfflineReopenRetainsObsoleteCleanupCandidate(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	obsolete := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, obsolete.err)
	obsolete.session.Dataset = &offlineCloseAfterReleaseFailure{Dataset: obsolete.session.Dataset}

	// Reopen before the original completion is delivered. The next worker
	// owns disposal of that abandoned result, including a failed disposal.
	m, cmd = m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.ErrorContains(t, result.err, "injected cleanup failure")
	require.Same(t, obsolete.session, result.session)
	m, cmd = m.completeOffline(result)
	require.True(t, m.offlineOpening)
	batch := cmd().(tea.BatchMsg)
	next, _ := m.update(batch[1]())
	m = next.(Model)
	require.False(t, m.offlineOpening)
	m.offlineController.mu.Lock()
	_, owned := m.offlineController.sessions[obsolete.session]
	m.offlineController.mu.Unlock()
	require.False(t, owned)
}
