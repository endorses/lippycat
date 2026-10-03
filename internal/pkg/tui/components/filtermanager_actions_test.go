//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"
)

func clickableFilterManager() FilterManager {
	fm := NewFilterManager()
	fm.SetSize(100, 32)
	fm.Activate("processor", "localhost:55555", NodeTypeProcessor)
	fm.SetFilters([]*management.Filter{
		{Id: "one", Pattern: "one", Type: management.FilterType_FILTER_BPF, Enabled: true},
		{Id: "two", Pattern: "two", Type: management.FilterType_FILTER_BPF, Enabled: false},
	})
	return fm
}

func TestFilterModalEditorColoredNavigation(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })

	for _, mode := range []string{"new", "edit"} {
		for _, width := range []int{100, 48} {
			t.Run(fmt.Sprintf("%s/width-%d", mode, width), func(t *testing.T) {
				fm := clickableFilterManager()
				fm.SetSize(width, 32)
				fm.ActivateAction(mode)
				initialBounds := LayoutModal(fm.ModalOptions()).Bounds
				check := func() {
					t.Helper()
					opts := fm.ModalOptions()
					rows := strings.Split(ansi.Strip(opts.Content), "\n")
					require.Len(t, rows, 5)
					// Styling a focused row must preserve the input's visible text,
					// including its cursor, placeholder, and viewport padding.
					require.Equal(t, "Pattern: "+ansi.Strip(fm.formState.patternInput.View()), rows[0])
					require.Equal(t, "Description: "+ansi.Strip(fm.formState.descInput.View()), rows[1])
					layout := LayoutModal(opts)
					require.Equal(t, 5, layout.FullContentHeight)
					require.Equal(t, initialBounds, layout.Bounds)
					lines := strings.Split(ansi.Strip(layout.View), "\n")
					require.Len(t, lines, 32)
					for _, line := range lines {
						require.Equal(t, width, ansi.StringWidth(line))
					}
					for i, label := range []string{"Pattern:", "Description:", "Type:", "Status:", "Targets:"} {
						require.Contains(t, lines[layout.ContentBounds.Min.Y+i], label)
					}
				}
				check()
				for _, key := range []tea.KeyType{tea.KeyDown, tea.KeyUp, tea.KeyTab, tea.KeyShiftTab} {
					for i := 0; i < 20; i++ {
						fm.Update(tea.KeyMsg{Type: key})
						check()
					}
				}
			})
		}
	}
}

func TestFilterModalPatternExamplesFollowType(t *testing.T) {
	fm := clickableFilterManager()
	fm.ActivateAction("new")
	require.Equal(t, management.FilterType_FILTER_BPF, fm.formState.filterType)
	require.Equal(t, "e.g., port 5060", fm.formState.patternInput.Placeholder)

	// Both keyboard cycling and the clickable type control refresh the example.
	fm.Update(tea.KeyMsg{Type: tea.KeyCtrlT})
	require.Equal(t, management.FilterType_FILTER_IP_ADDRESS, fm.formState.filterType)
	require.Equal(t, "e.g., 192.168.1.0/24", fm.formState.patternInput.Placeholder)
	fm.ActivateAction("form-type")
	require.Equal(t, "e.g., port 5060", fm.formState.patternInput.Placeholder)
	fm.HandleModalFocus("form-type")
	fm.Update(tea.KeyMsg{Type: tea.KeyLeft})
	require.Equal(t, "e.g., 192.168.1.0/24", fm.formState.patternInput.Placeholder)
	fm.Update(tea.KeyMsg{Type: tea.KeyRight})
	require.Equal(t, "e.g., port 5060", fm.formState.patternInput.Placeholder)

	fm.ActivateAction("cancel")
	fm.allFilters[0].Type = management.FilterType_FILTER_IP_ADDRESS
	fm.ActivateAction("edit")
	require.Equal(t, "e.g., 192.168.1.0/24", fm.formState.patternInput.Placeholder)
	require.Equal(t, "one", fm.formState.patternInput.Value())
}

func TestFilterModalValidationClearsAfterEditing(t *testing.T) {
	fm := clickableFilterManager()
	fm.ActivateAction("new")
	require.Nil(t, fm.ActivateAction("save"))
	require.Contains(t, fm.ModalOptions().Content, "Pattern cannot be empty")

	// Navigation alone does not dismiss the error.
	fm.Update(tea.KeyMsg{Type: tea.KeyLeft})
	require.Contains(t, fm.ModalOptions().Content, "Pattern cannot be empty")
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("port 5060")})
	require.NotContains(t, fm.ModalOptions().Content, "Pattern cannot be empty")
	cmd := fm.ActivateAction("save")
	require.NotNil(t, cmd)
	require.Equal(t, "port 5060", cmd().(FilterOperationMsg).Filter.Pattern)
}

func TestFilterModalValidationClearsAfterTypeChange(t *testing.T) {
	for _, useMouse := range []bool{false, true} {
		fm := clickableFilterManager()
		fm.ActivateAction("new")
		fm.ActivateAction("save")
		if useMouse {
			clickFilterTarget(t, &fm, "form-type")
		} else {
			fm.Update(tea.KeyMsg{Type: tea.KeyCtrlT})
		}
		require.Empty(t, fm.statusText)
		// The next save still validates the empty pattern.
		require.Nil(t, fm.ActivateAction("save"))
		require.Contains(t, fm.ModalOptions().Content, "Pattern cannot be empty")
	}
}

func TestFilterModalInputSizingAfterResize(t *testing.T) {
	fm := clickableFilterManager()
	fm.ActivateAction("new")
	fm.formState.patternInput.SetValue(strings.Repeat("p", 100))
	fm.formState.descInput.SetValue(strings.Repeat("d", 200))
	for _, width := range []int{48, 100, 60} {
		fm.SetSize(width, 32)
		for _, field := range []string{"pattern", "description"} {
			fm.HandleModalFocus(field)
			opts := fm.ModalOptions()
			rows := strings.Split(ansi.Strip(opts.Content), "\n")
			require.Equal(t, "Pattern: "+ansi.Strip(fm.formState.patternInput.View()), rows[0])
			require.Equal(t, "Description: "+ansi.Strip(fm.formState.descInput.View()), rows[1])
			require.NotContains(t, rows[1], "…")
			require.LessOrEqual(t, ansi.StringWidth(rows[1]), ModalContentWidth(opts))
		}
	}
}
func clickFilterTarget(t *testing.T, fm *FilterManager, id string) tea.Cmd {
	t.Helper()
	for _, hit := range LayoutModal(fm.ModalOptions()).Hits {
		if hit.ID == id {
			if strings.HasPrefix(id, "filter:") {
				hit.Bounds.Min.X += 5
			}
			return fm.Update(tea.MouseMsg{X: hit.Bounds.Min.X, Y: hit.Bounds.Min.Y, Action: tea.MouseActionPress, Button: tea.MouseButtonLeft})
		}
	}
	t.Fatalf("missing visible target %q", id)
	return nil
}

func TestFilterModalRowsCheckboxAndPending(t *testing.T) {
	fm := clickableFilterManager()
	clickFilterTarget(t, &fm, "filter:two")
	// Selecting a row does not toggle its checkbox or open the editor.
	require.False(t, fm.pending)
	require.False(t, fm.GetSelectedFilter().Enabled)
	for _, hit := range LayoutModal(fm.ModalOptions()).Hits {
		if hit.ID == "filter:one" {
			fm.Update(tea.MouseMsg{X: hit.Bounds.Min.X + 5, Y: hit.Bounds.Min.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
		}
	}
	require.Equal(t, "one", fm.GetSelectedFilter().Id)
	require.Equal(t, ModeList, fm.mode)
	cmd := clickFilterTarget(t, &fm, "toggle:one")
	require.NotNil(t, cmd)
	require.False(t, fm.GetSelectedFilter().Enabled)
	require.True(t, fm.pending)
	require.Equal(t, "toggle", cmd().(FilterOperationMsg).Operation)
	require.Nil(t, clickFilterTarget(t, &fm, "toggle:one"))
	require.False(t, fm.GetSelectedFilter().Enabled)
	require.Nil(t, fm.ActivateAction("delete"))
	require.False(t, fm.confirmDialog.IsActive())
	fm.Update(FilterOperationResultMsg{Success: false, Operation: "toggle", Error: "offline"})
	require.False(t, fm.pending)
	require.Contains(t, fm.ModalOptions().Content, "offline")
}

func TestFilterModalSearchControlsAndStableIdentity(t *testing.T) {
	fm := clickableFilterManager()
	fm.ActivateAction("filter:two")
	fm.SetFilters([]*management.Filter{fm.allFilters[1], fm.allFilters[0]})
	require.Equal(t, "two", fm.GetSelectedFilter().Id)
	clickFilterTarget(t, &fm, "search")
	require.True(t, fm.searchMode)
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("two")})
	require.Equal(t, "two", fm.searchInput.Value())
	require.Len(t, fm.filteredFilters, 1)
	require.Equal(t, ModeList, fm.mode)
	clickFilterTarget(t, &fm, "clear-search")
	require.Len(t, fm.filteredFilters, 2)
	clickFilterTarget(t, &fm, "type")
	require.NotNil(t, fm.filterByType)
	clickFilterTarget(t, &fm, "status")
	require.NotNil(t, fm.filterByEnabled)
	require.True(t, *fm.filterByEnabled)
}

func TestFilterModalEditorMouseKeyboardAndValidation(t *testing.T) {
	fm := clickableFilterManager()
	clickFilterTarget(t, &fm, "new")
	require.Equal(t, ModeAdd, fm.mode)
	require.Nil(t, fm.ActivateAction("save"))
	require.Contains(t, strings.ToLower(fm.ModalOptions().Content), "pattern")
	clickFilterTarget(t, &fm, "pattern")
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("udp")})
	clickFilterTarget(t, &fm, "description")
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s typed normally")})
	require.Equal(t, "s typed normally", fm.formState.descInput.Value())
	clickFilterTarget(t, &fm, "form-enabled")
	require.False(t, fm.formState.enabled)
	cmd := clickFilterTarget(t, &fm, "save")
	require.NotNil(t, cmd)
	result := cmd().(FilterOperationMsg)
	require.Equal(t, "udp", result.Filter.Pattern)
	require.Equal(t, "s typed normally", result.Filter.Description)
	require.False(t, result.Filter.Enabled)
	require.True(t, fm.pending)
	require.Equal(t, ModeList, fm.mode)
	require.Nil(t, fm.ActivateAction("new"))
	require.Equal(t, ModeList, fm.mode)
}

func TestFilterModalEligibleHunterDraftAndRefresh(t *testing.T) {
	fm := clickableFilterManager()
	fm.SetAvailableHunters([]HunterSelectorItem{
		{HunterID: "generic"},
		{HunterID: "voip-a", Capabilities: &management.HunterCapabilities{FilterTypes: []string{"sip_user"}}},
		{HunterID: "dns", Capabilities: &management.HunterCapabilities{FilterTypes: []string{"dns_domain"}}},
		{HunterID: "voip-b", Capabilities: &management.HunterCapabilities{FilterTypes: []string{"sip_user"}}},
	})
	fm.ActivateAction("new")
	fm.formState.patternInput.SetValue("draft")
	fm.formState.descInput.SetValue("keep description")
	fm.formState.targetHunters = []string{"voip-b"}
	clickFilterTarget(t, &fm, "form-targets")
	require.NotContains(t, fm.ModalOptions().Content, "generic")
	fm.Update(tea.KeyMsg{Type: tea.KeySpace})
	require.ElementsMatch(t, []string{"voip-a", "voip-b"}, fm.hunterDraft)
	require.Equal(t, []string{"voip-b"}, fm.formState.targetHunters)
	clickFilterTarget(t, &fm, "cancel")
	require.Equal(t, []string{"voip-b"}, fm.formState.targetHunters)
	require.Equal(t, "draft", fm.formState.patternInput.Value())
	require.Equal(t, "keep description", fm.formState.descInput.Value())
	fm.ActivateAction("form-targets")
	clickFilterTarget(t, &fm, "hunters-all")
	require.ElementsMatch(t, []string{"voip-a", "voip-b"}, fm.hunterDraft)
	clickFilterTarget(t, &fm, "hunter:voip-a")
	fm.Update(tea.KeyMsg{Type: tea.KeyDown})
	require.Equal(t, "voip-b", fm.selectedHunterID())
	fm.SetAvailableHunters([]HunterSelectorItem{{HunterID: "voip-b", Capabilities: &management.HunterCapabilities{FilterTypes: []string{"sip_user"}}}})
	require.Equal(t, "voip-b", fm.selectedHunterID())
	require.Equal(t, []string{"voip-b"}, fm.hunterDraft)
	clickFilterTarget(t, &fm, "hunters-confirm")
	require.False(t, fm.selectingHunters)
	require.Equal(t, []string{"voip-b"}, fm.formState.targetHunters)
}

func TestFilterModalNestedConfirmationAndAsyncResult(t *testing.T) {
	fm := clickableFilterManager()
	clickFilterTarget(t, &fm, "delete")
	require.True(t, fm.confirmDialog.IsActive())
	require.NotNil(t, fm.ActiveModal())
	fm.pending = true
	fm.Update(FilterOperationResultMsg{Success: true, Operation: "toggle"})
	require.False(t, fm.pending)
	require.True(t, fm.confirmDialog.IsActive())
	fm.Dismiss()
	require.False(t, fm.confirmDialog.IsActive())
	require.True(t, fm.active)
	require.Len(t, fm.allFilters, 2)
}

func TestFilterModalScrollTargetsAfterFiltering(t *testing.T) {
	fm := clickableFilterManager()
	filters := make([]*management.Filter, 30)
	for i := range filters {
		filters[i] = &management.Filter{Id: fmt.Sprint(i), Pattern: fmt.Sprintf("filter-%02d", i), Type: management.FilterType_FILTER_BPF}
	}
	fm.SetFilters(filters)
	fm.SetSize(65, 20)
	fm.modalState.Scroll = 12
	layout := LayoutModal(fm.ModalOptions())
	require.False(t, layout.Fallback)
	for _, hit := range layout.Hits {
		if strings.HasPrefix(hit.ID, "filter:") {
			fm.Update(tea.MouseMsg{X: hit.Bounds.Min.X + 6, Y: hit.Bounds.Min.Y, Button: tea.MouseButtonLeft, Action: tea.MouseActionPress})
			require.Equal(t, strings.TrimPrefix(hit.ID, "filter:"), fm.GetSelectedFilter().Id)
			return
		}
	}
	t.Fatal("no scrolled row targets")
}

func TestFilterModalSearchFocusTracksKeyboardModes(t *testing.T) {
	fm := clickableFilterManager()
	fm.ActivateAction("filter:two")
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	require.True(t, fm.searchMode)
	require.Equal(t, "search", fm.modalState.Focus)
	require.True(t, fm.searchInput.Focused())
	fm.Update(tea.KeyMsg{Type: tea.KeyTab})
	require.Equal(t, "type", fm.modalState.Focus)
	require.False(t, fm.searchMode)
	clickFilterTarget(t, &fm, "search")
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("two")})
	fm.Update(tea.KeyMsg{Type: tea.KeyEnter})
	require.False(t, fm.searchMode)
	require.False(t, fm.searchInput.Focused())
	require.Equal(t, "filter-list", fm.modalState.Focus)
	require.Equal(t, "two", fm.searchInput.Value())
	fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("/")})
	fm.Update(tea.KeyMsg{Type: tea.KeyEsc})
	require.Equal(t, "filter-list", fm.modalState.Focus)
	require.Empty(t, fm.searchInput.Value())
	require.True(t, fm.active)
}

func TestFilterModalControlShortcutsFromFocusedButtons(t *testing.T) {
	for _, key := range []string{"/", "t", "e"} {
		t.Run(key, func(t *testing.T) {
			fm := clickableFilterManager()
			fm.modalState.Focus = "cancel"
			fm.HandleModalFocus("cancel")
			fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(key)})
			require.True(t, fm.active)
			switch key {
			case "/":
				require.True(t, fm.searchMode)
				require.Equal(t, "search", fm.modalState.Focus)
			case "t":
				require.NotNil(t, fm.filterByType)
				require.Equal(t, "type", fm.modalState.Focus)
			case "e":
				require.NotNil(t, fm.filterByEnabled)
				require.Equal(t, "status", fm.modalState.Focus)
			}
		})
	}
	for _, key := range []tea.KeyType{tea.KeyCtrlT, tea.KeyCtrlE} {
		t.Run(fmt.Sprint(key), func(t *testing.T) {
			fm := clickableFilterManager()
			fm.ActivateAction("new")
			fm.formState.patternInput.SetValue("udp")
			fm.modalState.Focus = "save"
			fm.HandleModalFocus("save")
			beforeType, beforeEnabled := fm.formState.filterType, fm.formState.enabled
			// An ordinary character does not edit the blurred pattern field.
			fm.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("x")})
			require.Equal(t, "udp", fm.formState.patternInput.Value())
			fm.Update(tea.KeyMsg{Type: key})
			if key == tea.KeyCtrlT {
				require.NotEqual(t, beforeType, fm.formState.filterType)
				require.Equal(t, "form-type", fm.modalState.Focus)
			} else {
				require.NotEqual(t, beforeEnabled, fm.formState.enabled)
				require.Equal(t, "form-enabled", fm.modalState.Focus)
			}
			require.Equal(t, "udp", fm.formState.patternInput.Value())
			require.False(t, fm.pending)
		})
	}
}

func TestFilterModalArrowFocusRemainsVisibleInShortTerminal(t *testing.T) {
	fm := clickableFilterManager()
	fm.SetSize(80, 10)
	fm.ActivateAction("new")
	for _, direction := range []tea.KeyType{tea.KeyDown, tea.KeyUp} {
		for i := 0; i < 4; i++ {
			fm.Update(tea.KeyMsg{Type: direction})
			layout := LayoutModal(fm.ModalOptions())
			require.False(t, layout.Fallback)
			visible := false
			for _, hit := range layout.Hits {
				if hit.ID == fm.modalState.Focus {
					visible = true
				}
			}
			require.True(t, visible, "focused %s is clipped at scroll %d", fm.modalState.Focus, layout.ContentOffset)
		}
	}
}
