//go:build tui || all

package tui

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

func offlineLifecycleModel(t *testing.T) (Model, OpenOfflineDatasetMsg) {
	t.Helper()
	previousConfig := viper.ConfigFileUsed()
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { viper.SetConfigFile(previousConfig) })
	path := filepath.Join(t.TempDir(), "empty.pcap")
	f, err := os.Create(path)
	require.NoError(t, err)
	require.NoError(t, pcapgo.NewWriter(f).WriteFileHeader(65535, layers.LinkTypeEthernet))
	require.NoError(t, f.Close())
	m := NewModel(8, 8, "", "", []string{path}, false, false, "", false)
	t.Cleanup(func() { require.NoError(t, m.CloseOffline()); m.Shutdown() })
	msg := FreezeOfflineOpen([]string{path}, "", 8)
	msg.Limits.Directory = t.TempDir()
	return m, msg
}
func offlineWorker(t *testing.T, cmd tea.Cmd) tea.Cmd {
	t.Helper()
	batch, ok := cmd().(tea.BatchMsg)
	require.True(t, ok)
	return batch[0]
}
func TestOfflineLifecycleAtomicReplacementAndFailure(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	previousEvents := m.eventStore
	previousCalls := m.callStore
	m, cmd := m.openOffline(open)
	require.Same(t, previousEvents, m.eventStore)
	require.Same(t, previousCalls, m.callStore)
	require.True(t, m.offlineOpening)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, cleanup := m.completeOffline(result)
	require.NotNil(t, m.offlineSession)
	require.False(t, m.offlineOpening)
	cleanup()
	ready := m.offlineSession
	events := m.eventStore
	calls := m.callStore
	stats := *m.statistics
	failed := open
	failed.Config.Inputs = []string{filepath.Join(t.TempDir(), "missing.pcap")}
	m, cmd = m.openOffline(failed)
	result = offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.Error(t, result.err)
	m, _ = m.completeOffline(result)
	require.Same(t, ready, m.offlineSession)
	require.Same(t, events, m.eventStore)
	require.Same(t, calls, m.callStore)
	require.Equal(t, stats, *m.statistics)
	require.Equal(t, open.Config.Inputs, m.pcapFiles)
}
func TestOfflineLifecycleCancelWaitsForWorkerCleanup(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	started := make(chan struct{})
	release := make(chan struct{})
	m.offlineController.index = func(ctx context.Context, _ *offline.Storage, _ offline.DatasetGeneration, _ OfflineAnalysisConfig, _ func(offline.Progress)) (*offlineIndexedSession, error) {
		close(started)
		<-ctx.Done()
		<-release
		return nil, ctx.Err()
	}
	m, cmd := m.openOffline(open)
	worker := offlineWorker(t, cmd)
	result := make(chan tea.Msg, 1)
	go func() { result <- worker() }()
	<-started
	before := time.Now()
	m, _ = m.cancelOffline()
	require.Less(t, time.Since(before), 100*time.Millisecond)
	require.True(t, m.offlineOpening)
	require.Equal(t, offline.Cancelling, m.offlineProgress.State)
	close(release)
	complete := (<-result).(offlineOpenCompleteMsg)
	m, cleanup := m.completeOffline(complete)
	require.True(t, m.offlineOpening)
	updated, _ := m.update(cleanup())
	m = updated.(Model)
	require.False(t, m.offlineOpening)
}
func TestOfflineLifecycleRapidOpenDisposesStaleSuccess(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, first := m.openOffline(open)
	result := offlineWorker(t, first)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	pathResources := result.session.Dataset.Resources().DiskBytes
	require.Positive(t, pathResources)
	m, second := m.openOffline(open)
	m, cleanup := m.completeOffline(result)
	require.Nil(t, m.offlineSession)
	require.True(t, m.offlineOpening)
	cleanup()
	m.offlineController.mu.Lock()
	_, owned := m.offlineController.sessions[result.session]
	m.offlineController.mu.Unlock()
	require.False(t, owned)
	newer := offlineWorker(t, second)().(offlineOpenCompleteMsg)
	require.NoError(t, newer.err)
	m, _ = m.completeOffline(newer)
	require.Same(t, newer.session, m.offlineSession)
}
func TestOfflineLifecycleQuitDuringCleanup(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	started := make(chan struct{})
	release := make(chan struct{})
	m.offlineController.index = func(ctx context.Context, _ *offline.Storage, _ offline.DatasetGeneration, _ OfflineAnalysisConfig, _ func(offline.Progress)) (*offlineIndexedSession, error) {
		close(started)
		<-ctx.Done()
		<-release
		return nil, errors.New("cancelled analyzer")
	}
	m, cmd := m.openOffline(open)
	worker := offlineWorker(t, cmd)
	go worker()
	<-started
	m, quit := m.leaveOffline(nil, true)
	require.True(t, m.offlineOpening)
	require.False(t, m.uiState.Quitting)
	done := make(chan tea.Msg, 1)
	go func() { done <- quit() }()
	select {
	case <-done:
		t.Fatal("quit returned before analyzer joined")
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	updated, quitCmd := m.update(<-done)
	m = updated.(Model)
	require.True(t, m.uiState.Quitting)
	require.IsType(t, tea.QuitMsg{}, quitCmd())
}
func TestOfflineLifecycleModeSwitchJoinsAndPreservesOwner(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	owner := m.offlineController
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	m, cmd = m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: components.CaptureModeRemote, BufferSize: 8})
	require.True(t, m.offlineOpening)
	updated, _ := m.update(cmd())
	m = updated.(Model)
	require.Same(t, owner, m.offlineController)
	require.Nil(t, m.offlineSession)
	require.Equal(t, components.CaptureModeRemote, m.captureMode)
}
func TestOfflineLifecycleRejectsLegacyMessages(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	before := *m.statistics
	for _, msg := range []tea.Msg{PacketMsg{}, PacketBatchMsg{}, CallUpdateMsg{}, EventBatchMsg{}, CaptureCompleteMsg{PacketsReceived: 100}, TickMsg{}} {
		next, _ := m.update(msg)
		m = next.(Model)
	}
	require.Equal(t, before, *m.statistics)
	_, count, _, _ := m.packetStore.GetBufferInfo()
	require.Zero(t, count)
}

func TestOfflineLifecycleStartupAndFileDialogUseFrozenController(t *testing.T) {
	viper.Reset()
	t.Cleanup(viper.Reset)
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	m, open := offlineLifecycleModel(t)
	viper.Set("watch.offline.session_dir", open.Limits.Directory)
	initBatch := m.Init()().(tea.BatchMsg)
	startup := initBatch[len(initBatch)-1]().(OpenOfflineDatasetMsg)
	require.Equal(t, open, startup)
	m.uiState.Tabs.SetActive(3)
	// The dialog supports multiple exact identities, including whitespace.
	files := []string{open.Config.Inputs[0], filepath.Join(t.TempDir(), "second file.pcap")}
	data, err := os.ReadFile(files[0])
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(files[1], data, 0600))
	m, cmd := m.handleFileSelectedMsg(components.FileSelectedMsg{Paths: files})
	restart := cmd().(components.RestartCaptureMsg)
	require.Equal(t, files, restart.PCAPFiles)
	m, cmd = m.handleRestartCaptureMsg(restart)
	require.Equal(t, FreezeOfflineOpen(files, restart.Filter, restart.BufferSize), m.offlinePending)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, _ = m.completeOffline(result)
	require.Equal(t, files, m.uiState.SettingsView.GetPCAPFiles())
}
func TestOfflineLifecycleRestoresSettingsWhileReplacementPending(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	changed := components.RestartCaptureMsg{Mode: components.CaptureModeOffline, PCAPFiles: []string{filepath.Join(t.TempDir(), "missing.pcap")}, BufferSize: 123, Filter: "tcp"}
	m.uiState.SettingsView.InstallCaptureConfiguration(changed)
	m, cmd = m.handleRestartCaptureMsg(changed)
	require.Equal(t, open.Config.Inputs, m.uiState.SettingsView.GetPCAPFiles())
	require.Equal(t, open.Config.EventCapacity, m.uiState.SettingsView.GetBufferSize())
	require.Equal(t, open.Config.BPFFilter, m.uiState.SettingsView.GetBPFFilter())
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.Error(t, result.err)
	m, _ = m.completeOffline(result)
	require.Equal(t, open.Config.Inputs, m.uiState.SettingsView.GetPCAPFiles())
}
func TestOfflineLifecycleDuplicateCompletionCannotClosePublishedSession(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	m, _ = m.completeOffline(result)
	m, cmd = m.completeOffline(result)
	require.Nil(t, cmd)
	require.Same(t, result.session, m.offlineSession)
	q, err := m.offlineSession.Dataset.Query(context.Background(), offline.QuerySpec{Token: offline.Token{Dataset: result.generation}})
	require.NoError(t, err)
	require.NoError(t, q.Close())
}

type offlineCloseFailure struct {
	offline.Dataset
	calls int
}

func (d *offlineCloseFailure) Close() error {
	d.calls++
	if d.calls == 1 {
		return errors.New("injected cleanup failure")
	}
	return d.Dataset.Close()
}
func TestOfflineLifecycleCancelSurfacesCleanupFailure(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	result.session.Dataset = &offlineCloseFailure{Dataset: result.session.Dataset}
	m, _ = m.cancelOffline()
	m, cmd = m.completeOffline(result)
	cleanup := cmd().(offlineCleanupMsg)
	require.ErrorContains(t, cleanup.err, "injected cleanup failure")
	updated, _ := m.update(cleanup)
	m = updated.(Model)
	require.True(t, m.uiState.Toast.IsActive())
	require.Nil(t, m.offlineSession)
}
func TestOfflineLifecyclePreviewIsBoundedAndTotalsComplete(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	open.Config.Inputs = writeOrderedBridgeFixtures(t)
	m, cmd := m.openOffline(open)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, _ = m.completeOffline(result)
	_, count, _, _ := m.packetStore.GetBufferInfo()
	require.Equal(t, 8, count)
	require.Equal(t, int64(1077), m.statistics.TotalPackets)
	require.Equal(t, uint64(1077), m.offlineSession.Dataset.Count())
	require.LessOrEqual(t, m.offlineSession.Dataset.Resources().PinnedBytes, open.Limits.CacheBytes/4)
	m.uiState.Width = 180
	m.prepareViewChrome()
	require.Contains(t, m.uiState.OfflinePacketNotice, "Indexed: 1077 packets | Preview: 8")
}
func TestOfflineLifecycleOpenDuringModeCleanupQueuesLatest(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	owner := m.offlineController
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	m, cleanup := m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: components.CaptureModeRemote, BufferSize: 8})
	m, cmd = m.openOffline(open)
	require.Nil(t, cmd)
	require.NotNil(t, m.offlineQueued)
	updated, cmd := m.update(cleanup())
	m = updated.(Model)
	require.Same(t, owner, m.offlineController)
	require.True(t, m.offlineOpening)
	result := offlineWorker(t, cmd)().(offlineOpenCompleteMsg)
	require.NoError(t, result.err)
	m, _ = m.completeOffline(result)
	require.Equal(t, components.CaptureModeOffline, m.captureMode)
	require.NotNil(t, m.offlineSession)
}

func TestOfflineLifecycleExternalShutdownOwnsUndeliveredResult(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, _ = m.openOffline(open)
	// The Bubble Tea command and completion message may both be abandoned by Run.
	require.NoError(t, m.CloseOffline())
	entries, err := os.ReadDir(open.Limits.Directory)
	require.NoError(t, err)
	require.Empty(t, entries)
}
func TestOfflineLifecycleFilterTypingQDoesNotQuit(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	m.uiState.FilterMode = true
	m.uiState.FilterInput.Activate()
	updated, _ := m.update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'q'}})
	m = updated.(Model)
	require.False(t, m.offlineLeaving)
	require.False(t, m.uiState.Quitting)
}
func TestOfflineLifecycleQuitUpgradesModeCleanup(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m, cmd := m.openOffline(open)
	m, _ = m.completeOffline(offlineWorker(t, cmd)().(offlineOpenCompleteMsg))
	m, cleanup := m.handleRestartCaptureMsg(components.RestartCaptureMsg{Mode: components.CaptureModeRemote, BufferSize: 8})
	m, cmd = m.leaveOffline(nil, true)
	require.Nil(t, cmd)
	updated, quit := m.update(cleanup())
	m = updated.(Model)
	require.True(t, m.uiState.Quitting)
	require.IsType(t, tea.QuitMsg{}, quit())
}
