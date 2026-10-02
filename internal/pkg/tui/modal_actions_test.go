//go:build tui || all

package tui

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/offline"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
)

// Resolve real rendered labels rather than consulting the modal hit rectangles.
func modalActionPress(t *testing.T, m Model, label string) tea.MouseMsg {
	t.Helper()
	lines := strings.Split(ansi.Strip(m.View()), "\n")
	for y := len(lines) - 1; y >= 0; y-- {
		line := lines[y]
		if index := strings.Index(line, label); index >= 0 {
			return selectionPress(ansi.StringWidth(line[:index])+ansi.StringWidth(label)/2, y)
		}
	}
	t.Fatalf("modal label %q missing from:\n%s", label, ansi.Strip(m.View()))
	return tea.MouseMsg{}
}

func pressModalAction(t *testing.T, m Model, label string) (Model, tea.Cmd) {
	t.Helper()
	next, cmd := m.Update(modalActionPress(t, m, label))
	return next.(Model), cmd
}

func TestModalActionsAllFileHosts(t *testing.T) {
	previousConfig := viper.ConfigFileUsed()
	viper.SetConfigFile(filepath.Join(t.TempDir(), "config.yaml"))
	t.Cleanup(func() { viper.SetConfigFile(previousConfig) })
	for _, host := range []string{"settings-pcap", "settings-nodes", "export"} {
		t.Run(host, func(t *testing.T) {
			tab := 3
			if host == "export" {
				tab = 0
			}
			m := footerMouseModel(t, tab)
			dir := t.TempDir()
			name := "selected.pcap"
			if host == "settings-nodes" {
				name = "nodes.yaml"
			}
			path := filepath.Join(dir, name)
			if host != "export" {
				require.NoError(t, os.WriteFile(path, nil, 0600))
			}
			var fd *components.FileDialog
			switch host {
			case "settings-pcap":
				m.uiState.SettingsView.SetCaptureMode(components.CaptureModeOffline)
				fd = m.uiState.SettingsView.GetPcapFileDialog()
				*fd = components.NewOpenFileDialog(dir, []string{".pcap"}, false)
			case "settings-nodes":
				m.uiState.SettingsView.SetCaptureMode(components.CaptureModeRemote)
				fd = m.uiState.SettingsView.GetNodesFileDialog()
				*fd = components.NewOpenFileDialog(dir, []string{".yaml"}, false)
			default:
				fd = &m.uiState.FileDialog
				*fd = components.NewSaveFileDialog(dir, name, []string{".pcap"})
				m.uiState.Paused = true
			}
			fd.SetSize(m.uiState.Width, m.uiState.Height)
			fd.Activate()
			m.prepareViewChrome()
			label := "Open · Enter"
			if host == "export" {
				label = "Save"
			} else {
				m, _ = pressModalAction(t, m, name)
			}
			m, cmd := pressModalAction(t, m, label)
			require.NotNil(t, cmd)
			selected, ok := cmd().(components.FileSelectedMsg)
			require.True(t, ok)
			require.Equal(t, path, selected.Path())
			require.False(t, selected.OverwriteConfirmed)
			require.Nil(t, m.activeModal())
			updated, followup := m.Update(selected)
			m = updated.(Model)
			require.NotNil(t, followup)
			if host == "export" {
				require.True(t, m.uiState.SaveInProgress)
				require.False(t, m.uiState.ConfirmDialog.IsActive())
				return
			}
			restart, ok := followup().(components.RestartCaptureMsg)
			require.True(t, ok)
			if host == "settings-pcap" {
				require.Equal(t, []string{path}, restart.PCAPFiles)
				require.Equal(t, components.CaptureModeOffline, restart.Mode)
			} else {
				require.Equal(t, path, restart.NodesFile)
				require.Equal(t, components.CaptureModeRemote, restart.Mode)
			}
		})
	}
}

func TestModalActionsNestedOverwriteKeepsDraftAndConfirmsOnce(t *testing.T) {
	m := footerMouseModel(t, 0)
	m.uiState.Paused = true
	dir := t.TempDir()
	path := filepath.Join(dir, "existing.pcap")
	require.NoError(t, os.WriteFile(path, []byte("original"), 0600))
	m.uiState.FileDialog = components.NewSaveFileDialog(dir, "existing.pcap", []string{".pcap"})
	m.uiState.FileDialog.SetSize(m.uiState.Width, m.uiState.Height)
	m.uiState.FileDialog.Activate()
	m.prepareViewChrome()
	m, cmd := pressModalAction(t, m, "Save")
	require.Nil(t, cmd)
	require.Contains(t, ansi.Strip(m.View()), "Replace existing file?")
	m, cmd = pressModalAction(t, m, "Keep editing")
	require.Nil(t, cmd)
	require.True(t, m.uiState.FileDialog.IsActive())
	require.Equal(t, "existing.pcap", m.uiState.FileDialog.GetFilename())
	require.NotContains(t, ansi.Strip(m.View()), "Replace existing file?")
	m, _ = pressModalAction(t, m, "Save")
	m, cmd = pressModalAction(t, m, "Replace · Enter")
	require.NotNil(t, cmd)
	selected, ok := cmd().(components.FileSelectedMsg)
	require.True(t, ok)
	require.True(t, selected.OverwriteConfirmed)
	require.Equal(t, path, selected.Path())
	require.False(t, m.uiState.FileDialog.IsActive())
	updated, save := m.Update(selected)
	m = updated.(Model)
	require.NotNil(t, save)
	require.True(t, m.uiState.SaveInProgress)
	require.False(t, m.uiState.ConfirmDialog.IsActive(), "confirmed file result must not display a duplicate host confirmation")
	data, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, "original", string(data), "save command has not yet run")
}

func TestModalActionsApplyConsumesRemainingGesture(t *testing.T) {
	m := footerMouseModel(t, 0)
	underlying := footerMousePress(t, m, "Space: pause")
	m.uiState.ProtocolSelector.Activate()
	m.prepareViewChrome()
	m, cmd := pressModalAction(t, m, "Apply · Enter")
	require.NotNil(t, cmd)
	require.IsType(t, components.ProtocolSelectedMsg{}, cmd())
	require.False(t, m.uiState.ProtocolSelector.IsActive())
	for _, action := range []tea.MouseAction{tea.MouseActionMotion, tea.MouseActionRelease} {
		underlying.Action = action
		m = updateEventRenderModel(t, m, underlying)
		require.False(t, m.uiState.Paused)
		require.Equal(t, 0, m.uiState.Tabs.GetActive())
	}
	underlying.Action = tea.MouseActionPress
	m = updateEventRenderModel(t, m, underlying)
	require.True(t, m.uiState.Paused, "a new press works after the modal gesture is consumed")
}

func TestModalActionsOfflineCancelRetainsCleanupOwnership(t *testing.T) {
	for _, filter := range []bool{false, true} {
		t.Run(map[bool]string{false: "opening", true: "filter"}[filter], func(t *testing.T) {
			m := footerMouseModel(t, 0)
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			cancellations := 0
			trackedCancel := func() { cancellations++; cancel() }
			if filter {
				m.offlineFilter = &offlineFilterState{owner: &offlineFilterOwner{cancel: trackedCancel}}
			} else {
				m.offlineOpening = true
				m.offlineController.cancel = trackedCancel
				m.offlineProgress.State = offline.Reading
			}
			m, cmd := pressModalAction(t, m, "Cancel · Esc")
			require.Nil(t, cmd)
			require.ErrorIs(t, ctx.Err(), context.Canceled)
			require.Equal(t, 1, cancellations)
			if filter {
				require.NotNil(t, m.offlineFilter)
				require.True(t, m.offlineFilter.cancelled)
			} else {
				require.True(t, m.offlineOpening)
				require.Equal(t, offline.Cancelling, m.offlineProgress.State)
			}
			// Disabled cancellation stays visible and a repeated click cannot call cancel again.
			m, cmd = pressModalAction(t, m, "Cancelling")
			require.Nil(t, cmd)
			require.Equal(t, 1, cancellations)
			require.NotNil(t, m.activeModal(), "cleanup still owns the modal")
		})
	}
}

func TestModalActionsOfflineCleanupRetryAndQuit(t *testing.T) {
	for _, quit := range []bool{false, true} {
		t.Run(map[bool]string{false: "retry", true: "quit"}[quit], func(t *testing.T) {
			m, _ := failOfflineLeaving(t, false)
			m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 120, Height: 32})
			label := "Retry cleanup · Enter"
			if quit {
				label = "Retry and quit"
			}
			m, retry := pressModalAction(t, m, label)
			require.NotNil(t, retry)
			require.True(t, m.offlineOpening)
			require.False(t, m.offlineCleanupFailed)
			require.False(t, m.uiState.Quitting, "quit must wait for cleanup")
			// Pressing the disabled pending control cannot launch another cleanup command.
			m, duplicate := pressModalAction(t, m, "Cancelling")
			require.Nil(t, duplicate)
			result := retry()
			require.IsType(t, offlineCleanupMsg{}, result)
			updated, done := m.Update(result)
			m = updated.(Model)
			require.False(t, m.offlineOpening)
			require.Nil(t, m.offlineSession)
			if quit {
				require.True(t, m.uiState.Quitting)
				require.NotNil(t, done)
				require.IsType(t, tea.QuitMsg{}, done())
			} else {
				require.False(t, m.uiState.Quitting)
				require.Equal(t, components.CaptureModeRemote, m.captureMode)
			}
		})
	}
}

func TestModalActionsOfflineCancelWaitsForWorker(t *testing.T) {
	m, open := offlineLifecycleModel(t)
	m = updateEventRenderModel(t, m, tea.WindowSizeMsg{Width: 120, Height: 32})
	started, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	releaseWorker := func() { releaseOnce.Do(func() { close(release) }) }
	t.Cleanup(releaseWorker)
	m.offlineController.index = func(ctx context.Context, _ *offline.Storage, _ offline.DatasetGeneration, _ OfflineAnalysisConfig, _ func(offline.Progress)) (*offlineIndexedSession, error) {
		close(started)
		<-ctx.Done()
		<-release
		return nil, ctx.Err()
	}
	m, cmd := m.openOffline(open)
	worker := offlineWorker(t, cmd)
	completed := make(chan tea.Msg, 1)
	go func() { completed <- worker() }()
	<-started
	m, cmd = pressModalAction(t, m, "Cancel · Esc")
	require.Nil(t, cmd)
	require.True(t, m.offlineOpening)
	select {
	case <-completed:
		t.Fatal("worker must retain cleanup ownership until released")
	default:
	}
	m, cmd = pressModalAction(t, m, "Cancelling")
	require.Nil(t, cmd)
	releaseWorker()
	updated, cleanup := m.Update(<-completed)
	m = updated.(Model)
	require.True(t, m.offlineOpening)
	require.NotNil(t, cleanup)
	updated, _ = m.Update(cleanup())
	m = updated.(Model)
	require.False(t, m.offlineOpening)
	require.Nil(t, m.activeModal())
}
