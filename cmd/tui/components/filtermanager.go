//go:build tui || all
// +build tui all

package components

import (
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components/filtermanager"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// FilterManagerMode represents the current mode of the filter manager
type FilterManagerMode int

const (
	ModeList FilterManagerMode = iota
	ModeAdd
	ModeEdit
)

// NodeType represents the type of node (processor or hunter)
type NodeType int

const (
	NodeTypeProcessor NodeType = iota
	NodeTypeHunter
)

// FilterManager manages filter CRUD operations
type FilterManager struct {
	// Data
	allFilters      []*management.Filter
	filteredFilters []*management.Filter

	// UI components
	filterList    list.Model
	searchInput   textinput.Model
	confirmDialog ConfirmDialog

	// State
	active           bool
	mode             FilterManagerMode
	targetNode       string // processor addr or hunter ID (for display)
	processorAddr    string // actual processor address (for gRPC calls)
	targetType       NodeType
	searchMode       bool
	filterByType     *management.FilterType
	filterByEnabled  *bool
	loading          bool
	availableHunters []filtermanager.HunterSelectorItem // Available hunters for target selection
	selectingHunters bool                               // Whether we're in hunter selection mode

	// Form state (for Add/Edit mode)
	formState *FilterFormState

	// UI
	theme  themes.Theme
	width  int
	height int
}

// FilterFormState holds state for add/edit form
type FilterFormState struct {
	filterID      string
	filterType    management.FilterType
	patternInput  textinput.Model
	descInput     textinput.Model
	enabled       bool
	targetHunters []string
	activeField   int
}

// NewFilterManager creates a new filter manager
func NewFilterManager() FilterManager {
	// Create search input
	searchInput := textinput.New()
	searchInput.Placeholder = "Search filters..."
	searchInput.CharLimit = 100

	// Create list with empty items initially
	delegate := filtermanager.NewFilterDelegate(themes.Solarized())
	filterList := list.New([]list.Item{}, delegate, 0, 0)
	filterList.Title = "Filters"
	filterList.SetShowStatusBar(true)
	filterList.SetShowHelp(false)
	filterList.SetFilteringEnabled(false) // We handle filtering ourselves

	confirmDialog := NewConfirmDialog()

	return FilterManager{
		allFilters:      make([]*management.Filter, 0),
		filteredFilters: make([]*management.Filter, 0),
		filterList:      filterList,
		searchInput:     searchInput,
		confirmDialog:   confirmDialog,
		active:          false,
		mode:            ModeList,
		searchMode:      false,
		theme:           themes.Solarized(),
	}
}

// SetTheme updates the theme
func (fm *FilterManager) SetTheme(theme themes.Theme) {
	fm.theme = theme
	// Update delegate theme
	delegate := filtermanager.NewFilterDelegate(theme)
	fm.filterList.SetDelegate(delegate)
	// Update confirm dialog theme
	fm.confirmDialog.SetTheme(theme)
}

// SetSize updates the size
func (fm *FilterManager) SetSize(width, height int) {
	fm.width = width
	fm.height = height

	// Calculate modal width (same logic as RenderModal)
	modalWidth := width * 7 / 10
	if modalWidth > 80 {
		modalWidth = 80
	}
	if modalWidth < 60 {
		modalWidth = 60
	}
	if modalWidth > width-4 {
		modalWidth = width - 4
	}

	// Modal has padding(1,2) = 4 chars, and content uses Width(modalWidth-4)
	// So actual content area is modalWidth - 4
	contentWidth := modalWidth - 4

	// List takes the full content width
	listWidth := contentWidth
	listHeight := max(height-15, 5) // Account for title, search bar, footer

	fm.filterList.SetSize(listWidth, listHeight)
	fm.confirmDialog.SetSize(width, height)
}

// Activate shows the filter manager for a specific node
func (fm *FilterManager) Activate(targetNode string, processorAddr string, targetType NodeType) {
	fm.active = true
	fm.targetNode = targetNode
	fm.processorAddr = processorAddr
	fm.targetType = targetType
	fm.mode = ModeList
	fm.searchMode = false
	fm.searchInput.SetValue("")
	fm.loading = true

	// Reset filters
	fm.filterByType = nil
	fm.filterByEnabled = nil

	fm.applyFilters()
}

// Deactivate hides the filter manager
func (fm *FilterManager) Deactivate() {
	fm.active = false
	fm.searchMode = false
}

// IsActive returns whether the filter manager is active
func (fm *FilterManager) IsActive() bool {
	return fm.active
}

// SetFilters sets the list of filters
func (fm *FilterManager) SetFilters(filters []*management.Filter) {
	fm.allFilters = filters
	fm.loading = false
	fm.applyFilters()
}

// SetAvailableHunters sets the list of available hunters for target selection
func (fm *FilterManager) SetAvailableHunters(hunters []HunterSelectorItem) {
	// Convert to filtermanager.HunterSelectorItem
	fmHunters := make([]filtermanager.HunterSelectorItem, len(hunters))
	for i, h := range hunters {
		fmHunters[i] = filtermanager.HunterSelectorItem{
			HunterID: h.HunterID,
			Hostname: h.Hostname,
		}
	}
	fm.availableHunters = fmHunters
}

// applyFilters applies search and filter criteria
func (fm *FilterManager) applyFilters() {
	// Use the pure function from filtermanager package
	result := filtermanager.ApplyFilters(filtermanager.StateParams{
		AllFilters:      fm.allFilters,
		SearchQuery:     fm.searchInput.Value(),
		FilterByType:    fm.filterByType,
		FilterByEnabled: fm.filterByEnabled,
	})

	fm.filteredFilters = result.FilteredFilters

	// Convert to list items
	items := make([]list.Item, len(fm.filteredFilters))
	for i, filter := range fm.filteredFilters {
		items[i] = filtermanager.FilterItem{Filter: filter}
	}

	fm.filterList.SetItems(items)

	// Update status bar
	fm.updateStatusBar()
}

// updateStatusBar updates the list status bar
func (fm *FilterManager) updateStatusBar() {
	if fm.loading {
		fm.filterList.StatusMessageLifetime = 0
		fm.filterList.NewStatusMessage("Loading filters...")
	} else {
		result := filtermanager.ApplyFilters(filtermanager.StateParams{
			AllFilters:      fm.allFilters,
			SearchQuery:     fm.searchInput.Value(),
			FilterByType:    fm.filterByType,
			FilterByEnabled: fm.filterByEnabled,
		})
		fm.filterList.NewStatusMessage(result.StatusMessage)
	}
}

// EnterSearchMode activates search mode
func (fm *FilterManager) EnterSearchMode() {
	fm.searchMode = true
	fm.searchInput.Focus()
}

// ExitSearchMode deactivates search mode
func (fm *FilterManager) ExitSearchMode() {
	fm.searchMode = false
	fm.searchInput.Blur()
}

// CycleTypeFilter cycles through filter type options
func (fm *FilterManager) CycleTypeFilter() {
	result := filtermanager.CycleTypeFilter(filtermanager.CycleTypeFilterParams{
		CurrentType: fm.filterByType,
		Forward:     true,
	})
	fm.filterByType = result.NewType
	fm.applyFilters()
}

// CycleTypeFilterBackward cycles through filter type options (backward)
func (fm *FilterManager) CycleTypeFilterBackward() {
	result := filtermanager.CycleTypeFilter(filtermanager.CycleTypeFilterParams{
		CurrentType: fm.filterByType,
		Forward:     false,
	})
	fm.filterByType = result.NewType
	fm.applyFilters()
}

// CycleEnabledFilter cycles through enabled filter options (forward)
func (fm *FilterManager) CycleEnabledFilter() {
	result := filtermanager.CycleEnabledFilter(filtermanager.CycleEnabledFilterParams{
		CurrentEnabled: fm.filterByEnabled,
		Forward:        true,
	})
	fm.filterByEnabled = result.NewEnabled
	fm.applyFilters()
}

// CycleEnabledFilterBackward cycles through enabled filter options (backward)
func (fm *FilterManager) CycleEnabledFilterBackward() {
	result := filtermanager.CycleEnabledFilter(filtermanager.CycleEnabledFilterParams{
		CurrentEnabled: fm.filterByEnabled,
		Forward:        false,
	})
	fm.filterByEnabled = result.NewEnabled
	fm.applyFilters()
}

// JumpToTop jumps to the first filter in the list
func (fm *FilterManager) JumpToTop() {
	if len(fm.filteredFilters) > 0 {
		fm.filterList.Select(0)
	}
}

// JumpToBottom jumps to the last filter in the list
func (fm *FilterManager) JumpToBottom() {
	if len(fm.filteredFilters) > 0 {
		fm.filterList.Select(len(fm.filteredFilters) - 1)
	}
}

// PageUp moves up one page in the list
func (fm *FilterManager) PageUp() {
	pageSize := fm.filterList.Height()
	if pageSize <= 0 {
		pageSize = 10
	}

	currentIndex := fm.filterList.Index()
	newIndex := max(0, currentIndex-pageSize)
	fm.filterList.Select(newIndex)
}

// PageDown moves down one page in the list
func (fm *FilterManager) PageDown() {
	pageSize := fm.filterList.Height()
	if pageSize <= 0 {
		pageSize = 10
	}

	currentIndex := fm.filterList.Index()
	newIndex := currentIndex + pageSize
	maxIndex := len(fm.filteredFilters) - 1
	if newIndex > maxIndex {
		newIndex = maxIndex
	}
	fm.filterList.Select(newIndex)
}

// GetSelectedFilter returns the currently selected filter
func (fm *FilterManager) GetSelectedFilter() *management.Filter {
	if len(fm.filteredFilters) == 0 {
		return nil
	}

	index := fm.filterList.Index()
	if index < 0 || index >= len(fm.filteredFilters) {
		return nil
	}

	return fm.filteredFilters[index]
}

// toggleFilterEnabled toggles the enabled state of the selected filter
func (fm *FilterManager) toggleFilterEnabled() tea.Cmd {
	selectedFilter := fm.GetSelectedFilter()
	if selectedFilter == nil {
		return nil
	}

	// Use pure function to calculate new state
	result := filtermanager.ToggleFilterEnabled(filtermanager.ToggleFilterEnabledParams{
		Filter: selectedFilter,
	})

	// Update local state
	selectedFilter.Enabled = result.NewEnabled
	fm.filterList.NewStatusMessage(result.StatusMessage)
	fm.applyFilters()

	// Return command to persist change via gRPC
	return func() tea.Msg {
		return FilterOperationMsg{
			Operation:      "toggle",
			ProcessorAddr:  fm.processorAddr,
			Filter:         selectedFilter,
			TargetNodeType: fm.targetType,
		}
	}
}

// Update handles key events and messages
func (fm *FilterManager) Update(msg tea.Msg) tea.Cmd {
	if !fm.active {
		return nil
	}

	// Check if confirm dialog is active first
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.Update(msg)
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle hunter selection mode
		if fm.selectingHunters {
			return fm.handleHunterSelectionMode(msg)
		}

		// Handle add/edit form mode
		if fm.mode == ModeAdd || fm.mode == ModeEdit {
			return fm.handleFormMode(msg)
		}

		// Handle search mode
		if fm.searchMode {
			return fm.handleSearchMode(msg)
		}

		// Handle list mode
		return fm.handleListMode(msg)

	case ConfirmDialogResult:
		// Handle confirmation dialog result
		return fm.handleConfirmResult(msg)

	case FilterOperationResultMsg:
		// Handle gRPC operation results
		return fm.handleOperationResult(msg)
	}

	return nil
}

// handleOperationResult handles the result of a filter operation
func (fm *FilterManager) handleOperationResult(msg FilterOperationResultMsg) tea.Cmd {
	statusMsg := filtermanager.FormatOperationResult(filtermanager.FormatOperationResultParams{
		Success:        msg.Success,
		Operation:      msg.Operation,
		FilterPattern:  msg.FilterPattern,
		Error:          msg.Error,
		HuntersUpdated: msg.HuntersUpdated,
	})
	fm.filterList.NewStatusMessage(statusMsg)
	return nil
}

// handleSearchMode handles keyboard input in search mode
func (fm *FilterManager) handleSearchMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		fm.searchInput.SetValue("")
		fm.ExitSearchMode()
		fm.applyFilters()
		return nil

	case "enter":
		fm.ExitSearchMode()
		return nil

	case "up", "down":
		var cmd tea.Cmd
		fm.filterList, cmd = fm.filterList.Update(msg)
		return cmd

	default:
		var cmd tea.Cmd
		fm.searchInput, cmd = fm.searchInput.Update(msg)
		fm.applyFilters()
		return cmd
	}
}

// handleListMode handles keyboard input in list mode
func (fm *FilterManager) handleListMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "q":
		fm.Deactivate()
		return nil

	case "/":
		fm.EnterSearchMode()
		return nil

	case "t":
		fm.CycleTypeFilter()
		return nil

	case "e":
		fm.CycleEnabledFilter()
		return nil

	case "left":
		fm.CycleTypeFilterBackward()
		return nil

	case "right":
		fm.CycleTypeFilter()
		return nil

	case "shift+left":
		fm.CycleEnabledFilterBackward()
		return nil

	case "shift+right":
		fm.CycleEnabledFilter()
		return nil

	case "g":
		fm.JumpToTop()
		return nil

	case "G":
		fm.JumpToBottom()
		return nil

	case "pgup":
		fm.PageUp()
		return nil

	case "pgdown":
		fm.PageDown()
		return nil

	case "n":
		fm.initializeAddForm()
		return nil

	case "enter":
		selectedFilter := fm.GetSelectedFilter()
		if selectedFilter != nil {
			fm.initializeEditForm(selectedFilter)
		}
		return nil

	case "d":
		selectedFilter := fm.GetSelectedFilter()
		if selectedFilter != nil {
			// Build details for confirmation
			details := []string{
				"Pattern: " + selectedFilter.Pattern,
				"Type: " + selectedFilter.Type.String(),
			}
			if selectedFilter.Description != "" {
				details = append(details, "Description: "+selectedFilter.Description)
			}

			// Show confirmation dialog
			fm.confirmDialog.Show(ConfirmDialogOptions{
				Type:        ConfirmDialogDanger,
				Title:       "Delete Filter",
				Message:     "Are you sure you want to delete this filter?",
				Details:     details,
				ConfirmText: "y",
				CancelText:  "n",
				UserData:    selectedFilter,
			})
		}
		return nil

	case " ":
		return fm.toggleFilterEnabled()

	default:
		var cmd tea.Cmd
		fm.filterList, cmd = fm.filterList.Update(msg)
		return cmd
	}
}

// handleHunterSelectionMode handles keyboard input in hunter selection mode
func (fm *FilterManager) handleHunterSelectionMode(msg tea.KeyMsg) tea.Cmd {
	if fm.formState == nil {
		fm.selectingHunters = false
		return nil
	}

	switch msg.String() {
	case "up", "k":
		if len(fm.availableHunters) > 0 {
			currentIdx := fm.formState.activeField
			if currentIdx > 0 {
				fm.formState.activeField--
			}
		}
		return nil

	case "down", "j":
		if len(fm.availableHunters) > 0 {
			currentIdx := fm.formState.activeField
			if currentIdx < len(fm.availableHunters)-1 {
				fm.formState.activeField++
			}
		}
		return nil

	case " ":
		if len(fm.availableHunters) > 0 {
			hunterID := fm.availableHunters[fm.formState.activeField].HunterID
			found := false
			for i, id := range fm.formState.targetHunters {
				if id == hunterID {
					fm.formState.targetHunters = slices.Delete(fm.formState.targetHunters, i, i+1)
					found = true
					break
				}
			}
			if !found {
				fm.formState.targetHunters = append(fm.formState.targetHunters, hunterID)
			}
		}
		return nil

	case "a":
		fm.formState.targetHunters = make([]string, 0, len(fm.availableHunters))
		for _, hunter := range fm.availableHunters {
			fm.formState.targetHunters = append(fm.formState.targetHunters, hunter.HunterID)
		}
		return nil

	case "n":
		fm.formState.targetHunters = []string{}
		return nil

	case "enter":
		fm.selectingHunters = false
		fm.formState.activeField = 4
		return nil

	case "esc":
		fm.selectingHunters = false
		fm.formState.activeField = 4
		return nil

	default:
		return nil
	}
}

// handleConfirmResult handles the result from the confirmation dialog
func (fm *FilterManager) handleConfirmResult(msg ConfirmDialogResult) tea.Cmd {
	if !msg.Confirmed {
		// User cancelled
		return nil
	}

	// User confirmed - check what action we're confirming
	if msg.UserData != nil {
		if filter, ok := msg.UserData.(*management.Filter); ok {
			// Delete the filter
			return fm.deleteFilter(filter)
		}
	}

	return nil
}

// deleteFilter deletes the specified filter
func (fm *FilterManager) deleteFilter(filter *management.Filter) tea.Cmd {
	if filter == nil {
		return nil
	}

	// Use pure function to delete filter
	result := filtermanager.DeleteFilter(filtermanager.DeleteFilterParams{
		Filter:     filter,
		AllFilters: fm.allFilters,
	})

	filterID := filter.Id
	fm.allFilters = result.UpdatedFilters
	fm.filterList.NewStatusMessage(result.StatusMessage)
	fm.applyFilters()

	// Return command to persist deletion via gRPC
	return func() tea.Msg {
		return FilterOperationMsg{
			Operation:      "delete",
			ProcessorAddr:  fm.processorAddr,
			FilterID:       filterID,
			TargetNodeType: fm.targetType,
		}
	}
}

// initializeAddForm initializes the form for adding a new filter
func (fm *FilterManager) initializeAddForm() {
	patternInput := textinput.New()
	patternInput.Placeholder = "e.g., alice@example.com"
	patternInput.CharLimit = 200
	patternInput.Width = 60
	patternInput.Focus()

	descInput := textinput.New()
	descInput.Placeholder = "Optional description"
	descInput.CharLimit = 500
	descInput.Width = 60

	fm.formState = &FilterFormState{
		filterID:      "",
		filterType:    management.FilterType_FILTER_SIP_USER,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       true,
		targetHunters: []string{},
		activeField:   0,
	}

	fm.mode = ModeAdd
}

// initializeEditForm initializes the form for editing an existing filter
func (fm *FilterManager) initializeEditForm(filter *management.Filter) {
	patternInput := textinput.New()
	patternInput.SetValue(filter.Pattern)
	patternInput.CharLimit = 200
	patternInput.Width = 60
	patternInput.Focus()

	descInput := textinput.New()
	descInput.SetValue(filter.Description)
	descInput.CharLimit = 500
	descInput.Width = 60

	fm.formState = &FilterFormState{
		filterID:      filter.Id,
		filterType:    filter.Type,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       filter.Enabled,
		targetHunters: slices.Clone(filter.TargetHunters),
		activeField:   0,
	}

	fm.mode = ModeEdit
}

// handleFormMode handles keyboard input in add/edit form mode
func (fm *FilterManager) handleFormMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		fm.formState = nil
		fm.mode = ModeList
		return nil

	case "s":
		if fm.formState != nil && fm.formState.activeField == 4 {
			fm.selectingHunters = true
			fm.formState.activeField = 0
			return nil
		}
		if fm.formState != nil && (fm.formState.activeField == 0 || fm.formState.activeField == 1) {
			var cmd tea.Cmd
			switch fm.formState.activeField {
			case 0:
				fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			case 1:
				fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
			}
			return cmd
		}
		return nil

	case "enter", "ctrl+s":
		return fm.saveFilter()

	case "down", "tab":
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField + 1) % 5
			fm.updateFormFieldFocus()
		}
		return nil

	case "up", "shift+tab":
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField - 1 + 5) % 5
			fm.updateFormFieldFocus()
		}
		return nil

	case "left":
		if fm.formState != nil && (fm.formState.activeField == 0 || fm.formState.activeField == 1) {
			var cmd tea.Cmd
			switch fm.formState.activeField {
			case 0:
				fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			case 1:
				fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
			}
			return cmd
		}
		if fm.formState != nil {
			switch fm.formState.activeField {
			case 2:
				fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, false)
			case 3:
				fm.formState.enabled = !fm.formState.enabled
			}
		}
		return nil

	case "right":
		if fm.formState != nil && (fm.formState.activeField == 0 || fm.formState.activeField == 1) {
			var cmd tea.Cmd
			switch fm.formState.activeField {
			case 0:
				fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			case 1:
				fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
			}
			return cmd
		}
		if fm.formState != nil {
			switch fm.formState.activeField {
			case 2:
				fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, true)
			case 3:
				fm.formState.enabled = !fm.formState.enabled
			}
		}
		return nil

	case "ctrl+t":
		if fm.formState != nil {
			fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, true)
		}
		return nil

	case "ctrl+e":
		if fm.formState != nil {
			fm.formState.enabled = !fm.formState.enabled
		}
		return nil

	default:
		if fm.formState != nil {
			var cmd tea.Cmd
			switch fm.formState.activeField {
			case 0:
				fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			case 1:
				fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
			}
			return cmd
		}
		return nil
	}
}

// updateFormFieldFocus updates which form field is focused
func (fm *FilterManager) updateFormFieldFocus() {
	if fm.formState == nil {
		return
	}

	fm.formState.patternInput.Blur()
	fm.formState.descInput.Blur()

	switch fm.formState.activeField {
	case 0:
		fm.formState.patternInput.Focus()
	case 1:
		fm.formState.descInput.Focus()
	}
}

// saveFilter saves the current form (add or update)
func (fm *FilterManager) saveFilter() tea.Cmd {
	if fm.formState == nil {
		fm.mode = ModeList
		return nil
	}

	// Validate pattern
	pattern := strings.TrimSpace(fm.formState.patternInput.Value())
	validationResult := filtermanager.ValidateFilter(filtermanager.ValidateFilterParams{
		Pattern:     pattern,
		Description: strings.TrimSpace(fm.formState.descInput.Value()),
		Type:        fm.formState.filterType,
	})

	if !validationResult.Valid {
		fm.filterList.NewStatusMessage(validationResult.ErrorMessage)
		return nil
	}

	var operation string
	var filter *management.Filter

	if fm.mode == ModeAdd {
		// Create new filter
		operation = "create"
		createResult := filtermanager.CreateFilter(filtermanager.CreateFilterParams{
			Pattern:       pattern,
			Description:   strings.TrimSpace(fm.formState.descInput.Value()),
			Type:          fm.formState.filterType,
			Enabled:       fm.formState.enabled,
			TargetHunters: fm.formState.targetHunters,
			AllFilters:    fm.allFilters,
		})

		filter = createResult.Filter
		fm.allFilters = createResult.UpdatedFilters
		fm.filterList.NewStatusMessage(createResult.StatusMessage)

	} else if fm.mode == ModeEdit {
		// Update existing filter
		operation = "update"
		updateResult := filtermanager.UpdateFilter(filtermanager.UpdateFilterParams{
			FilterID:      fm.formState.filterID,
			Pattern:       pattern,
			Description:   strings.TrimSpace(fm.formState.descInput.Value()),
			Type:          fm.formState.filterType,
			Enabled:       fm.formState.enabled,
			TargetHunters: fm.formState.targetHunters,
			AllFilters:    fm.allFilters,
		})

		if !updateResult.Found {
			fm.formState = nil
			fm.mode = ModeList
			fm.filterList.NewStatusMessage(updateResult.StatusMessage)
			return nil
		}

		filter = updateResult.Filter
		fm.allFilters = updateResult.UpdatedFilters
		fm.filterList.NewStatusMessage(updateResult.StatusMessage)
	}

	// Return to list mode
	fm.formState = nil
	fm.mode = ModeList
	fm.applyFilters()

	// Return command to persist via gRPC
	return func() tea.Msg {
		return FilterOperationMsg{
			Operation:      operation,
			ProcessorAddr:  fm.processorAddr,
			Filter:         filter,
			TargetNodeType: fm.targetType,
		}
	}
}

// View renders the filter manager using unified modal
func (fm *FilterManager) View() string {
	if !fm.active {
		return ""
	}

	// Show confirm dialog if active
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.View()
	}

	// Show hunter selection if in that mode
	if fm.selectingHunters {
		return fm.renderHunterSelection()
	}

	// Show add/edit form if in form mode
	if fm.mode == ModeAdd || fm.mode == ModeEdit {
		return fm.renderFilterForm()
	}

	var content strings.Builder

	// Render search bar
	searchBar := filtermanager.RenderSearchBar(filtermanager.RenderSearchBarParams{
		SearchMode:      fm.searchMode,
		SearchValue:     fm.searchInput.Value(),
		FilterByType:    fm.filterByType,
		FilterByEnabled: fm.filterByEnabled,
		Theme:           fm.theme,
	})

	// If in search mode, append the actual input view
	if fm.searchMode {
		searchBar += fm.searchInput.View()
	}

	content.WriteString(searchBar)
	content.WriteString("\n\n")

	// Render filter list or loading state
	if fm.loading {
		loadingStyle := lipgloss.NewStyle().
			Foreground(fm.theme.Foreground).
			Italic(true)
		content.WriteString(loadingStyle.Render("Loading filters..."))
	} else {
		content.WriteString(fm.filterList.View())
	}

	// Build footer based on mode
	var footer string
	if fm.searchMode {
		footer = "Type to search  ↑/↓: Navigate  Enter: Keep search  Esc: Clear"
	} else {
		footer = "/: Search  ←/→: Type  ⇧←/⇧→: Status  g/G: Top/Bottom  PgUp/PgDn: Page  Space: Toggle  n: New  Enter: Edit  d: Delete  Esc: Close"
	}

	// Build title
	nodeDesc := fm.targetNode
	if fm.targetType == NodeTypeProcessor {
		nodeDesc = "Processor: " + nodeDesc
	} else {
		nodeDesc = "Hunter: " + nodeDesc
	}

	return RenderModal(ModalRenderOptions{
		Title:      "🔧 Filter Management - " + nodeDesc,
		Content:    content.String(),
		Footer:     footer,
		Width:      fm.width,
		Height:     fm.height,
		Theme:      fm.theme,
		ModalWidth: 0,
	})
}

// renderHunterSelection renders the hunter selection UI
func (fm *FilterManager) renderHunterSelection() string {
	if fm.formState == nil {
		return ""
	}

	// Calculate modal width
	modalWidth := 70
	if modalWidth > fm.width-4 {
		modalWidth = fm.width - 4
	}

	content := filtermanager.RenderHunterSelection(filtermanager.RenderHunterSelectionParams{
		AvailableHunters: fm.availableHunters,
		SelectedHunters:  fm.formState.targetHunters,
		CursorIndex:      fm.formState.activeField,
		ModalWidth:       modalWidth,
		Theme:            fm.theme,
	})

	return RenderModal(ModalRenderOptions{
		Title:      "Select Target Hunters",
		Content:    content,
		Footer:     "↑/↓: Navigate  Space: Toggle  a: All  n: None  Enter: Confirm  Esc: Cancel",
		Width:      fm.width,
		Height:     fm.height,
		Theme:      fm.theme,
		ModalWidth: modalWidth,
	})
}

// renderFilterForm renders the add/edit filter form
func (fm *FilterManager) renderFilterForm() string {
	if fm.formState == nil {
		return ""
	}

	content := filtermanager.RenderForm(filtermanager.RenderFormParams{
		FilterID:      fm.formState.filterID,
		FilterType:    fm.formState.filterType,
		PatternInput:  fm.formState.patternInput,
		DescInput:     fm.formState.descInput,
		Enabled:       fm.formState.enabled,
		TargetHunters: fm.formState.targetHunters,
		ActiveField:   fm.formState.activeField,
		IsEditMode:    fm.mode == ModeEdit,
		Theme:         fm.theme,
	})

	// Determine title and footer
	var title, footer string
	if fm.mode == ModeAdd {
		title = "➕ Add Filter"
		if fm.formState.activeField == 4 {
			footer = "↑/↓/Tab: Navigate  s: Select hunters  Enter: Save  Esc: Cancel"
		} else {
			footer = "↑/↓/Tab: Navigate  ←/→: Change Setting  Enter: Save  Esc: Cancel"
		}
	} else {
		title = "✏️  Edit Filter"
		if fm.formState.activeField == 4 {
			footer = "↑/↓/Tab: Navigate  s: Select hunters  Enter: Save  Esc: Cancel"
		} else {
			footer = "↑/↓/Tab: Navigate  ←/→: Change Setting  Enter: Save  Esc: Cancel"
		}
	}

	return RenderModal(ModalRenderOptions{
		Title:      title,
		Content:    content,
		Footer:     footer,
		Width:      fm.width,
		Height:     fm.height,
		Theme:      fm.theme,
		ModalWidth: 70,
	})
}

// FilterManagerOpenMsg is sent when filter manager should open
type FilterManagerOpenMsg struct {
	TargetNode string
	TargetType NodeType
}

// FiltersLoadedMsg is sent when filters are loaded from processor
type FiltersLoadedMsg struct {
	ProcessorAddr string
	Filters       []*management.Filter
	Err           error
}

// FilterOperationMsg is sent to request a filter operation (create/update/delete)
type FilterOperationMsg struct {
	Operation      string // "create", "update", "delete", "toggle"
	ProcessorAddr  string
	Filter         *management.Filter
	FilterID       string // For delete operations
	TargetNodeType NodeType
}

// FilterOperationResultMsg is sent when a filter operation completes
type FilterOperationResultMsg struct {
	Success        bool
	Operation      string
	FilterPattern  string
	Error          string
	HuntersUpdated uint32
}
