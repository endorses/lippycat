//go:build tui || all

package components

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/stretchr/testify/require"
)

func TestFileDialogDismissClosesInputModes(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode FileDialogInputMode
	}{
		{"navigation", ModeNavigation},
		{"filename", ModeFilename},
		{"filter", ModeFilter},
		{"create folder", ModeCreateFolder},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dialog := NewFileDialog(FileDialogConfig{
				Type:        FileDialogTypeSave,
				InitialPath: t.TempDir(),
			})
			dialog.Activate()
			dialog.mode = tc.mode
			switch tc.mode {
			case ModeFilename:
				dialog.filename.Focus()
			case ModeFilter:
				dialog.filterInput.Focus()
			case ModeCreateFolder:
				dialog.folderInput.Focus()
			}

			require.Nil(t, dialog.Dismiss(), "dismissal must not select a file")
			require.False(t, dialog.IsActive())
			require.False(t, dialog.filename.Focused())
			require.False(t, dialog.filterInput.Focused())
			require.False(t, dialog.folderInput.Focused())
		})
	}
}

func TestConfirmDialogDismissPreservesCancellationResult(t *testing.T) {
	for _, action := range []string{"dismiss", "esc", "n"} {
		t.Run(action, func(t *testing.T) {
			dialog := NewConfirmDialog()
			context := &struct{ ID string }{ID: "pending-operation"}
			dialog.Show(ConfirmDialogOptions{UserData: context})
			var cmd tea.Cmd
			switch action {
			case "dismiss":
				cmd = dialog.Dismiss()
			case "esc":
				cmd = dialog.Update(tea.KeyMsg{Type: tea.KeyEsc})
			case "n":
				cmd = dialog.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune{'n'}})
			}
			require.False(t, dialog.IsActive())
			require.NotNil(t, cmd)
			result, ok := cmd().(ConfirmDialogResult)
			require.True(t, ok)
			require.False(t, result.Confirmed)
			require.Same(t, context, result.UserData)
			require.Nil(t, dialog.Dismiss(), "closed dialogs must not emit another result")
		})
	}
}

func TestFilterManagerDismissNestedLayers(t *testing.T) {
	manager := NewFilterManager()
	manager.Activate("processor", "processor:55555", NodeTypeProcessor)
	manager.initializeAddForm()
	manager.formState.patternInput.SetValue("draft")
	manager.selectingHunters = true

	require.Nil(t, manager.Dismiss())
	require.True(t, manager.IsActive())
	require.False(t, manager.selectingHunters)
	require.Equal(t, ModeAdd, manager.mode)
	require.Equal(t, "draft", manager.formState.patternInput.Value())

	require.Nil(t, manager.Dismiss())
	require.True(t, manager.IsActive())
	require.Equal(t, ModeList, manager.mode)
	require.Nil(t, manager.formState, "cancelled drafts must be discarded")

	require.Nil(t, manager.Dismiss())
	require.False(t, manager.IsActive())
}

func TestFilterManagerDismissInlineSearch(t *testing.T) {
	manager := NewFilterManager()
	manager.Activate("processor", "processor:55555", NodeTypeProcessor)
	manager.EnterSearchMode()
	manager.searchInput.SetValue("draft")

	require.Nil(t, manager.Dismiss())
	require.False(t, manager.IsActive(), "inline search must not trap modal dismissal")
	require.False(t, manager.searchMode)
}

func TestFilterManagerDismissNestedConfirmation(t *testing.T) {
	manager := NewFilterManager()
	manager.Activate("processor", "processor:55555", NodeTypeProcessor)
	filter := &management.Filter{Id: "keep-filter"}
	manager.SetFilters([]*management.Filter{filter})
	manager.confirmDialog.Show(ConfirmDialogOptions{UserData: filter})

	cmd := manager.Dismiss()
	require.NotNil(t, cmd)
	require.True(t, manager.IsActive())
	require.False(t, manager.confirmDialog.IsActive())
	result, ok := cmd().(ConfirmDialogResult)
	require.True(t, ok)
	require.False(t, result.Confirmed)
	require.Same(t, filter, result.UserData)
	require.Nil(t, manager.Update(result))
	require.Equal(t, []*management.Filter{filter}, manager.allFilters)
}
