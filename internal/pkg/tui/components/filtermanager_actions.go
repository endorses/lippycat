//go:build tui || all

package components

import (
	"fmt"
	"image"
	"slices"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/components/filtermanager"
)

// ActiveModal exposes only the top layer to the shared host.
func (fm *FilterManager) ActiveModal() Modal {
	if fm.confirmDialog.IsActive() {
		return &fm.confirmDialog
	}
	return nil
}

func (fm *FilterManager) eligibleHunters() []filtermanager.HunterSelectorItem {
	if fm.formState == nil {
		return nil
	}
	return filtermanager.FilterHuntersByCapability(fm.availableHunters, fm.formState.filterType)
}
func (fm *FilterManager) selectedHunterID() string {
	hunters := fm.eligibleHunters()
	if fm.hunterCursor >= 0 && fm.hunterCursor < len(hunters) {
		return hunters[fm.hunterCursor].HunterID
	}
	return ""
}
func (fm *FilterManager) reconcileHunterCursor(id string) {
	hunters := fm.eligibleHunters()
	fm.hunterCursor = min(fm.hunterCursor, max(0, len(hunters)-1))
	for i, h := range hunters {
		if h.HunterID == id {
			fm.hunterCursor = i
			break
		}
	}
	// Retain only available, eligible pending choices. The parent draft is unchanged until Confirm.
	fm.hunterDraft = slices.DeleteFunc(fm.hunterDraft, func(id string) bool {
		return !slices.ContainsFunc(hunters, func(h filtermanager.HunterSelectorItem) bool { return h.HunterID == id })
	})
}
func (fm *FilterManager) beginHunterSelection() {
	if fm.formState == nil {
		return
	}
	fm.hunterDraft = slices.Clone(fm.formState.targetHunters)
	fm.hunterCursor = 0
	fm.reconcileHunterCursor("")
	fm.selectingHunters = true
	fm.modalState.Reset()
}
func (fm *FilterManager) toggleHunter(id string) {
	if id == "" {
		return
	}
	if i := slices.Index(fm.hunterDraft, id); i >= 0 {
		fm.hunterDraft = slices.Delete(fm.hunterDraft, i, i+1)
	} else {
		fm.hunterDraft = append(fm.hunterDraft, id)
	}
}

// ModalOptions builds content and content-local hit regions together, without mutating View state.
func (fm *FilterManager) ModalOptions() ModalRenderOptions {
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.ModalOptions()
	}
	opts := ModalRenderOptions{ID: "filters-list", Title: "Filter Management — " + fm.targetNode, Width: fm.width, Height: fm.height, ModalWidth: 80, Theme: fm.theme, State: &fm.modalState, Footer: "↑/↓ Navigate · Tab Focus"}
	width := ModalContentWidth(opts)
	var lines []string
	row := func(id, text string, focusable bool) {
		y := len(lines)
		text = ansi.Truncate(strings.ReplaceAll(text, "\n", " "), width, "…")
		if fm.modalState.Focus == id {
			text = lipgloss.NewStyle().Bold(true).Underline(true).Render(text)
		}
		lines = append(lines, text)
		if id != "" {
			opts.Targets = append(opts.Targets, ModalTarget{ID: id, Bounds: image.Rect(0, y, width, y+1), Focusable: focusable})
		}
	}
	action := func(id, label, key string, disabled bool, kind ButtonKind) {
		opts.Actions = append(opts.Actions, ModalAction{ID: id, Label: label, Shortcut: key, Disabled: disabled, Kind: kind})
	}
	if fm.selectingHunters && fm.formState != nil {
		opts.ID = "filters-hunters"
		opts.Title = "Select Target Hunters"
		hunters := fm.eligibleHunters()
		row("", "Choose eligible hunters; an empty target list means all compatible hunters.", false)
		opts.Targets = append(opts.Targets, ModalTarget{ID: "hunter-list", Bounds: image.Rect(0, 1+fm.hunterCursor, width, 2+fm.hunterCursor), Focusable: len(hunters) > 0})
		for i, h := range hunters {
			check := "[ ]"
			if slices.Contains(fm.hunterDraft, h.HunterID) {
				check = "[✓]"
			}
			text := fmt.Sprintf("%s %s (%s)", check, h.HunterID, h.Hostname)
			if i == fm.hunterCursor {
				text = lipgloss.NewStyle().Foreground(fm.theme.SelectionFg).Background(fm.theme.SelectionBg).Render(ansi.Truncate(text, width, "…"))
			}
			row("hunter:"+h.HunterID, text, false)
		}
		if len(hunters) == 0 {
			row("", "No compatible hunters available", false)
		}
		action("hunters-all", "All", "a", len(hunters) == 0, ButtonNormal)
		action("hunters-none", "None", "n", len(fm.hunterDraft) == 0, ButtonNormal)
		action("hunters-confirm", "Confirm", "Enter", false, ButtonPrimary)
		action("cancel", "Cancel", "Esc", false, ButtonNormal)
	} else if fm.formState != nil && fm.mode != ModeList {
		opts.ID = "filters-editor"
		opts.Title = "Add Filter"
		if fm.mode == ModeEdit {
			opts.Title = "Edit Filter"
		}
		row("pattern", "Pattern: "+fm.formState.patternInput.View(), true)
		row("description", "Description: "+fm.formState.descInput.View(), true)
		row("form-type", "Type: ◀ "+filtermanager.AbbreviateType(fm.formState.filterType)+" ▶", true)
		enabled := "[ ] Disabled"
		if fm.formState.enabled {
			enabled = "[✓] Enabled"
		}
		row("form-enabled", "Status: "+enabled, true)
		targets := "All compatible hunters"
		if len(fm.formState.targetHunters) > 0 {
			targets = strings.Join(fm.formState.targetHunters, ", ")
		}
		row("form-targets", "Targets: "+targets+"  [Select]", true)
		action("save", "Save", "Ctrl+S", fm.pending, ButtonPrimary)
		action("cancel", "Cancel", "Esc", false, ButtonNormal)
	} else {
		search := fm.searchInput.Value()
		if fm.searchMode {
			search = fm.searchInput.View()
		}
		row("search", "Search: "+search, true)
		typeName := "All"
		if fm.filterByType != nil {
			typeName = filtermanager.AbbreviateType(*fm.filterByType)
		}
		row("type", "Type: ◀ "+typeName+" ▶", true)
		status := "All"
		if fm.filterByEnabled != nil {
			if *fm.filterByEnabled {
				status = "Enabled"
			} else {
				status = "Disabled"
			}
		}
		row("status", "Status: ◀ "+status+" ▶", true)
		row("", "", false)
		start := len(lines)
		opts.Targets = append(opts.Targets, ModalTarget{ID: "filter-list", Bounds: image.Rect(0, start+max(0, fm.filterList.Index()), width, start+max(0, fm.filterList.Index())+1), Focusable: true})
		for i, f := range fm.filteredFilters {
			check := "[ ]"
			if f.Enabled {
				check = "[✓]"
			}
			text := fmt.Sprintf("%s %s · %s", check, filtermanager.AbbreviateType(f.Type), f.Pattern)
			if i == fm.filterList.Index() {
				text = lipgloss.NewStyle().Foreground(fm.theme.SelectionFg).Background(fm.theme.SelectionBg).Render(ansi.Truncate(text, width, "…"))
			}
			y := len(lines)
			row("filter:"+f.Id, text, false)
			opts.Targets = append(opts.Targets, ModalTarget{ID: "toggle:" + f.Id, Bounds: image.Rect(0, y, min(3, width), y+1), Disabled: fm.pending})
		}
		if fm.loading {
			row("", "Loading filters…", false)
		} else if len(fm.filteredFilters) == 0 {
			row("", "No matching filters", false)
		}
		action("new", "New", "n", fm.pending, ButtonNormal)
		action("edit", "Edit", "Enter", fm.pending || fm.GetSelectedFilter() == nil, ButtonPrimary)
		action("delete", "Delete", "d", fm.pending || fm.GetSelectedFilter() == nil, ButtonDanger)
		action("clear-search", "Clear search", "", fm.searchInput.Value() == "", ButtonNormal)
		if fm.searchMode {
			action("keep-search", "Keep search", "Enter", false, ButtonNormal)
		}
		action("cancel", "Close", "Esc", false, ButtonNormal)
	}
	if fm.pending {
		row("", "Operation pending…", false)
	}
	if fm.statusText != "" {
		row("", fm.statusText, false)
	}
	opts.Content = strings.Join(lines, "\n")
	return opts
}

func (fm *FilterManager) HandleModalFocus(id string) tea.Cmd {
	fm.searchInput.Blur()
	if fm.formState != nil {
		fm.formState.patternInput.Blur()
		fm.formState.descInput.Blur()
		fields := []string{"pattern", "description", "form-type", "form-enabled", "form-targets"}
		fm.formState.activeField = slices.Index(fields, id)
		fm.updateFormFieldFocus()
	} else if id == "search" {
		fm.EnterSearchMode()
	} else {
		fm.ExitSearchMode()
	}
	return nil
}

func (fm *FilterManager) HandleModalAction(id string) tea.Cmd { return fm.ActivateAction(id) }

// ActivateAction is shared by keys, content controls, and buttons.
func (fm *FilterManager) ActivateAction(id string) tea.Cmd {
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.HandleModalAction(id)
	}
	if id == "cancel" {
		fm.modalState.Reset()
		if fm.selectingHunters {
			fm.selectingHunters = false
			fm.hunterDraft = nil
			fm.formState.activeField = 4
			fm.modalState.Focus = "form-targets"
			return nil
		}
		if fm.mode != ModeList {
			fm.formState = nil
			fm.mode = ModeList
			return nil
		}
		return fm.Dismiss()
	}
	if fm.selectingHunters {
		switch id {
		case "hunters-all":
			fm.hunterDraft = nil
			for _, h := range fm.eligibleHunters() {
				fm.hunterDraft = append(fm.hunterDraft, h.HunterID)
			}
		case "hunters-none":
			fm.hunterDraft = nil
		case "hunters-confirm":
			fm.formState.targetHunters = slices.Clone(fm.hunterDraft)
			fm.selectingHunters = false
			fm.modalState.Reset()
			fm.formState.activeField = 4
			fm.modalState.Focus = "form-targets"
		default:
			if strings.HasPrefix(id, "hunter:") {
				for i, h := range fm.eligibleHunters() {
					if "hunter:"+h.HunterID == id {
						fm.hunterCursor = i
						fm.modalState.Focus = "hunter-list"
						fm.toggleHunter(h.HunterID)
						break
					}
				}
			}
		}
		return nil
	}
	if fm.mode != ModeList {
		switch id {
		case "save":
			return fm.saveFilter()
		case "form-type":
			fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, true, fm.availableHunters)
		case "form-enabled":
			fm.formState.enabled = !fm.formState.enabled
		case "form-targets":
			fm.beginHunterSelection()
		}
		return nil
	}
	switch id {
	case "new":
		if !fm.pending {
			fm.initializeAddForm()
			fm.modalState.Reset()
			fm.modalState.Focus = "pattern"
		}
	case "edit":
		if !fm.pending {
			if f := fm.GetSelectedFilter(); f != nil {
				fm.initializeEditForm(f)
				fm.modalState.Reset()
				fm.modalState.Focus = "pattern"
			}
		}
	case "delete":
		if !fm.pending {
			if f := fm.GetSelectedFilter(); f != nil {
				fm.confirmDialog.Show(ConfirmDialogOptions{Type: ConfirmDialogDanger, Title: "Delete Filter", Message: "Delete this filter?", Details: []string{"Pattern: " + f.Pattern, "Type: " + f.Type.String()}, ConfirmText: "Delete", CancelText: "Cancel", UserData: f})
			}
		}
	case "toggle":
		return fm.toggleFilterEnabled()
	case "search":
		fm.EnterSearchMode()
	case "clear-search":
		fm.searchInput.SetValue("")
		fm.applyFilters()
	case "keep-search":
		fm.ExitSearchMode()
	case "type":
		fm.CycleTypeFilter()
	case "status":
		fm.CycleEnabledFilter()
	default:
		for i, f := range fm.filteredFilters {
			if id == "filter:"+f.Id || id == "toggle:"+f.Id {
				fm.filterList.Select(i)
				fm.ExitSearchMode()
				fm.modalState.Focus = "filter-list"
				if id == "toggle:"+f.Id {
					return fm.toggleFilterEnabled()
				}
				break
			}
		}
	}
	return nil
}

func (fm *FilterManager) ensureVisible() {
	y := 4 + fm.filterList.Index()
	if fm.selectingHunters {
		y = 1 + fm.hunterCursor
	}
	layout := LayoutModal(fm.ModalOptions())
	if y < fm.modalState.Scroll {
		fm.modalState.Scroll = y
	}
	if y >= fm.modalState.Scroll+layout.ContentHeight {
		fm.modalState.Scroll = max(0, y-layout.ContentHeight+1)
	}
}

// ModalShortcut handles declared non-text shortcuts while a button has focus.
// Ordinary characters remain consumed by the shared action bar, so they cannot
// leak into the last edited text field.
func (fm *FilterManager) ModalShortcut(msg tea.KeyMsg) (tea.Cmd, bool) {
	if fm.confirmDialog.IsActive() || fm.selectingHunters {
		return nil, false
	}
	id := ""
	if fm.mode == ModeList {
		switch msg.String() {
		case "/":
			id = "search"
		case "t":
			id = "type"
		case "e":
			id = "status"
		case "q":
			return fm.ActivateAction("cancel"), true
		}
	} else if fm.formState != nil {
		switch msg.String() {
		case "ctrl+t":
			id = "form-type"
		case "ctrl+e":
			id = "form-enabled"
		}
	}
	if id == "" {
		return nil, false
	}
	fm.modalState.Focus = id
	focusCmd := fm.HandleModalFocus(id)
	actionCmd := fm.ActivateAction(id)
	EnsureModalTargetVisible(fm.ModalOptions(), id)
	return tea.Batch(focusCmd, actionCmd), true
}
