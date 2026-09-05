//go:build tui || all

package tui

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/internal/pkg/tui/components"
	"github.com/google/gopacket/pcapgo"
	"github.com/stretchr/testify/require"
)

func TestOfflineExportSaveKeyOpensDialogAndSavesDataset(t *testing.T) {
	m := readyOfflineBrowser(t)
	updated, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'w'}})
	m = updated.(Model)
	require.True(t, m.uiState.FileDialog.IsActive())
	path := filepath.Join(t.TempDir(), "keyboard.pcap")
	m.uiState.FileDialog.Deactivate()
	updated, _ = m.Update(components.FileSelectedMsg{Paths: []string{path}})
	m = updated.(Model)
	require.NotNil(t, m.offlineExport)
	<-m.offlineExport.done
	require.NoError(t, m.offlineExport.result.Error)
	require.Equal(t, m.offlineSession.Dataset.Count(), m.offlineExport.result.PacketsSaved)
	f, err := os.Open(path)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, f.Close()) })
	r, err := pcapgo.NewReader(f)
	require.NoError(t, err)
	var count uint64
	for {
		_, _, err := r.ReadPacketData()
		if err == io.EOF {
			break
		}
		require.NoError(t, err)
		count++
	}
	require.Equal(t, m.offlineSession.Dataset.Count(), count)
}
