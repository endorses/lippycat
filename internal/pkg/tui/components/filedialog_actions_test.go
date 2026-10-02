//go:build tui || all

package components

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/stretchr/testify/require"
)

func fileDialogFixture(t *testing.T, save bool) FileDialog {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(dir, "folder"), 0750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "one.pcap"), []byte("capture"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "two.pcap"), nil, 0600))
	config := FileDialogConfig{Type: FileDialogTypeOpen, InitialPath: dir, AllowedTypes: []string{".pcap"}}
	if save {
		config.Type = FileDialogTypeSave
		config.DefaultFilename = "new.pcap"
	}
	fd := NewFileDialog(config)
	fd.SetSize(100, 32)
	fd.Activate()
	return fd
}

func clickFileControl(t *testing.T, fd *FileDialog, id string) tea.Cmd {
	t.Helper()
	for _, hit := range LayoutModal(fd.ModalOptions()).Hits {
		if hit.ID == id {
			return fd.Update(tea.MouseMsg{X: hit.Bounds.Min.X, Y: hit.Bounds.Min.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
		}
	}
	t.Fatalf("missing visible file control %q", id)
	return nil
}

func fileIndex(t *testing.T, fd *FileDialog, name string) int {
	t.Helper()
	for i, entry := range fd.filteredFiles {
		if entry.Name() == name {
			return i
		}
	}
	t.Fatalf("missing %s", name)
	return -1
}

func TestFileDialogMouseOpenAndNavigation(t *testing.T) {
	fd := fileDialogFixture(t, false)
	original := fd.currentDir
	clickFileControl(t, &fd, "entry:0")
	require.Equal(t, original, fd.currentDir, "one click only selects")
	clickFileControl(t, &fd, "accept")
	require.Equal(t, filepath.Join(original, "folder"), fd.currentDir)
	require.True(t, fd.IsActive())
	clickFileControl(t, &fd, "up")
	require.Equal(t, original, fd.currentDir)
	index := fileIndex(t, &fd, "one.pcap")
	fd.selectEntry(index, time.Unix(10, 0))
	cmd := clickFileControl(t, &fd, "accept")
	require.NotNil(t, cmd)
	require.Equal(t, filepath.Join(original, "one.pcap"), cmd().(FileSelectedMsg).Path())
	require.False(t, fd.IsActive())
}

func TestFileDialogSaveSelectionAndOverwriteConfirmation(t *testing.T) {
	fd := fileDialogFixture(t, true)
	index := fileIndex(t, &fd, "one.pcap")
	now := time.Unix(10, 0)
	require.Nil(t, fd.selectEntry(index, now))
	require.Equal(t, "one.pcap", fd.GetFilename())
	fd.selectEntry(index, now.Add(100*time.Millisecond))
	require.Equal(t, ModeFilename, fd.mode)
	require.True(t, fd.IsActive(), "double click in save mode must not save")
	require.Nil(t, clickFileControl(t, &fd, "accept"))
	require.True(t, fd.overwrite.IsActive())
	require.True(t, fd.IsActive())
	require.Nil(t, clickFileControl(t, &fd, "cancel"))
	require.False(t, fd.overwrite.IsActive())
	require.Equal(t, "one.pcap", fd.GetFilename())
	clickFileControl(t, &fd, "accept")
	cmd := clickFileControl(t, &fd, "confirm")
	require.NotNil(t, cmd)
	require.Equal(t, filepath.Join(fd.currentDir, "one.pcap"), cmd().(FileSelectedMsg).Path())
	require.False(t, fd.IsActive())
}

func TestFileDialogKeyboardOverwriteAndBackdropCancel(t *testing.T) {
	fd := fileDialogFixture(t, true)
	fd.filename.SetValue("one.pcap")
	fd.modalState.Focus = "filename"
	fd.HandleModalFocus("filename")
	require.Nil(t, fd.Update(tea.KeyMsg{Type: tea.KeyEnter}))
	require.True(t, fd.overwrite.IsActive())
	fd.Dismiss()
	require.True(t, fd.IsActive())
	require.False(t, fd.overwrite.IsActive())
	require.Equal(t, "one.pcap", fd.GetFilename())
	fd.Update(tea.KeyMsg{Type: tea.KeyEnter})
	cmd := fd.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.NotNil(t, cmd)
	require.True(t, cmd().(FileSelectedMsg).OverwriteConfirmed)
}

func TestFileDialogDoubleClickReset(t *testing.T) {
	fd := fileDialogFixture(t, false)
	now := time.Unix(10, 0)
	index := fileIndex(t, &fd, "one.pcap")
	require.Nil(t, fd.selectEntry(index, now))
	fd.ScrollModal(1)
	require.Nil(t, fd.selectEntry(index, now.Add(100*time.Millisecond)))
	fd.SetSize(90, 30)
	require.Nil(t, fd.selectEntry(index, now.Add(200*time.Millisecond)))
	cmd := fd.selectEntry(index, now.Add(300*time.Millisecond))
	require.NotNil(t, cmd)
	require.IsType(t, FileSelectedMsg{}, cmd())
}

func TestFileDialogFocusTypingAndInlineCancel(t *testing.T) {
	fd := fileDialogFixture(t, true)
	fd.Update(tea.KeyMsg{Type: tea.KeyTab})
	require.Equal(t, ModeFilename, fd.mode)
	before := fd.GetFilename()
	fd.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("nd/")})
	require.Equal(t, before+"nd/", fd.GetFilename())
	require.Equal(t, ModeFilename, fd.mode)
	require.True(t, fd.showDetails)
	clickFileControl(t, &fd, "filter")
	fd.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("one")})
	require.Len(t, fd.filteredFiles, 1)
	clickFileControl(t, &fd, "apply-filter")
	require.Equal(t, ModeNavigation, fd.mode)
	clickFileControl(t, &fd, "clear-filter")
	require.Len(t, fd.filteredFiles, 3)
	clickFileControl(t, &fd, "new-folder")
	require.Equal(t, ModeCreateFolder, fd.mode)
	clickFileControl(t, &fd, "cancel-edit")
	require.Equal(t, ModeNavigation, fd.mode)
	require.True(t, fd.IsActive())
	require.Equal(t, before+"nd/", fd.GetFilename())
}

func TestFileDialogFolderErrorsAndRecovery(t *testing.T) {
	fd := fileDialogFixture(t, true)
	fd.HandleModalAction("new-folder")
	for _, name := range []string{"..", "bad/name", "one.pcap"} {
		fd.folderInput.SetValue(name)
		fd.HandleModalAction("create-folder")
		require.NotEmpty(t, fd.errorMessage, name)
		require.Equal(t, ModeCreateFolder, fd.mode)
	}
	fd.folderInput.SetValue("created")
	fd.HandleModalAction("create-folder")
	require.Empty(t, fd.errorMessage)
	require.DirExists(t, filepath.Join(fd.currentDir, "created"))
	require.Equal(t, "created", fd.filteredFiles[fd.cursor].Name())
}

func TestFileDialogValidationAndConfiguredExtension(t *testing.T) {
	fd := fileDialogFixture(t, true)
	for _, name := range []string{"", "..", "bad/name", "CON"} {
		fd.filename.SetValue(name)
		require.Nil(t, fd.acceptFile())
		require.NotEmpty(t, fd.errorMessage)
	}
	fd.config.AllowedTypes = []string{".yaml"}
	fd.filename.SetValue("nodes")
	cmd := fd.acceptFile()
	require.NotNil(t, cmd)
	require.Equal(t, filepath.Join(fd.currentDir, "nodes.yaml"), cmd().(FileSelectedMsg).Path())
}

func TestFileDialogBreadcrumbsAndReadErrors(t *testing.T) {
	fd := fileDialogFixture(t, false)
	dir := fd.currentDir
	fd.changeDirectory(filepath.Join(dir, "missing"))
	require.Equal(t, dir, fd.currentDir)
	require.NotEmpty(t, fd.errorMessage)
	labels, targets := fd.breadcrumbs(18)
	require.NotEmpty(t, labels)
	require.NotEmpty(t, targets)
	require.Equal(t, "path:/", targets[0].ID)
	for _, target := range targets {
		require.True(t, filepath.IsAbs(strings.TrimPrefix(target.ID, "path:")))
	}
	fd.HandleModalAction("path:/")
	require.Equal(t, "/", fd.currentDir)
	for _, action := range fd.actions() {
		if action.ID == "up" {
			require.True(t, action.Disabled)
		}
	}
}

func TestFileDialogLayoutBeforeRenderAndWheelTarget(t *testing.T) {
	fd := fileDialogFixture(t, true)
	fd.SetSize(70, 20)
	before := fd.modalState
	fd.View()
	fd.View()
	require.Equal(t, before, fd.modalState)
	clickFileControl(t, &fd, "filename")
	require.Equal(t, ModeFilename, fd.mode)
	fd.listHeight = 1
	fd.ScrollModalAt(1, 0, 1)
	require.Zero(t, fd.viewOffset, "wheel over search does not scroll files")
	fd.ScrollModalAt(1, 0, 2)
	require.Equal(t, 1, fd.viewOffset)
	fd.SetSize(12, 4)
	require.True(t, LayoutModal(fd.ModalOptions()).Fallback)
	fd.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.True(t, fd.IsActive(), "first Esc leaves filename mode")
	fd.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.False(t, fd.IsActive())
}

func TestFileDialogRepeatedSizePreservesDoubleClick(t *testing.T) {
	fd := fileDialogFixture(t, false)
	index := fileIndex(t, &fd, "one.pcap")
	now := time.Unix(10, 0)
	fd.selectEntry(index, now)
	fd.SetSize(fd.width, fd.height)
	cmd := fd.selectEntry(index, now.Add(100*time.Millisecond))
	require.NotNil(t, cmd)
	require.False(t, cmd().(FileSelectedMsg).OverwriteConfirmed)
}

func TestFileDialogRepeatedSizePreservesWheelOffset(t *testing.T) {
	fd := fileDialogFixture(t, false)
	fd.listHeight = 1
	fd.ScrollModal(1)
	require.Equal(t, 1, fd.viewOffset)
	fd.SetSize(fd.width, fd.height)
	require.Equal(t, 1, fd.viewOffset)
}

func TestFileDialogEnterHintsFollowEditingMode(t *testing.T) {
	for _, typ := range []FileDialogType{FileDialogTypeOpen, FileDialogTypeSave} {
		fd := NewFileDialog(FileDialogConfig{Type: typ, InitialPath: t.TempDir(), DefaultFilename: "output.pcap"})
		fd.SetSize(100, 30)
		fd.Activate()
		for _, mode := range []FileDialogInputMode{ModeFilter, ModeCreateFolder} {
			fd.mode = mode
			for _, action := range fd.actions() {
				if action.ID == "accept" {
					require.Empty(t, action.Shortcut, "Enter belongs to inline editing")
				}
			}
		}
		if typ == FileDialogTypeOpen {
			fd.mode = ModeNavigation
		} else {
			fd.mode = ModeFilename
		}
		require.Equal(t, "Enter", fd.actions()[0].Shortcut)
	}
}
