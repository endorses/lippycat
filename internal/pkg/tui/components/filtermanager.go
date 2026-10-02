//go:build tui || all

package components

import (
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/components/filtermanager"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
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
	pending          bool
	statusText       string
	hunterDraft      []string
	hunterCursor     int
	modalState       ModalState
	selectingHunters bool // Whether we're in hunter selection mode

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
	fm.width, fm.height = width, height
	contentWidth := ModalContentWidth(ModalRenderOptions{Width: width, ModalWidth: 80})
	fm.filterList.SetSize(max(1, contentWidth), max(1, height-15))
	fm.searchInput.Width = max(1, contentWidth-10)
	if fm.formState != nil {
		fm.formState.patternInput.Width = max(1, contentWidth-14)
		fm.formState.descInput.Width = max(1, contentWidth-14)
	}
	fm.confirmDialog.SetSize(width, height)
	fm.modalState.ResetClicks()
}

// Activate shows the filter manager for a specific node
func (fm *FilterManager) Activate(targetNode string, processorAddr string, targetType NodeType) {
	fm.modalState.Reset()
	fm.statusText = ""
	fm.active = true
	fm.targetNode = targetNode
	fm.processorAddr = processorAddr
	fm.targetType = targetType
	fm.mode = ModeList
	fm.formState = nil
	fm.selectingHunters = false
	fm.hunterDraft = nil
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

// Dismiss cancels the visible modal layer. Nested dialogs return to their
// parent; inline search belongs to the list and closes with the manager.
func (fm *FilterManager) Dismiss() tea.Cmd {
	if !fm.active {
		return nil
	}
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.Dismiss()
	}
	if fm.selectingHunters || fm.mode != ModeList {
		return fm.ActivateAction("cancel")
	}
	fm.Deactivate()
	return nil
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
			HunterID:     h.HunterID,
			Hostname:     h.Hostname,
			Capabilities: h.Capabilities,
		}
	}
	selectedID := fm.selectedHunterID()
	fm.availableHunters = fmHunters
	fm.reconcileHunterCursor(selectedID)
}

// applyFilters applies search and filter criteria
func (fm *FilterManager) applyFilters() {
	selectedID := ""
	if selected := fm.GetSelectedFilter(); selected != nil {
		selectedID = selected.Id
	}
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
	for i, filter := range fm.filteredFilters {
		if filter.Id == selectedID {
			fm.filterList.Select(i)
			break
		}
	}

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
	fm.modalState.Focus = "search"
	fm.searchInput.Focus()
	EnsureModalTargetVisible(fm.ModalOptions(), "search")
}

// ExitSearchMode deactivates search mode
func (fm *FilterManager) ExitSearchMode() {
	fm.searchMode = false
	fm.searchInput.Blur()
	if fm.modalState.Focus == "search" || fm.modalState.Focus == "keep-search" {
		fm.modalState.Focus = "filter-list"
		fm.ensureVisible()
	}
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
		fm.ensureVisible()
	}
}

// JumpToBottom jumps to the last filter in the list
func (fm *FilterManager) JumpToBottom() {
	if len(fm.filteredFilters) > 0 {
		fm.filterList.Select(len(fm.filteredFilters) - 1)
		fm.ensureVisible()
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
	fm.ensureVisible()
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
	fm.ensureVisible()
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
	if fm.pending {
		return nil
	}
	selectedFilter := fm.GetSelectedFilter()
	if selectedFilter == nil {
		return nil
	}

	if selectedFilter.Type >= management.FilterType_FILTER_RADIUS_USERNAME && selectedFilter.Type <= management.FilterType_FILTER_RADIUS_COMPOUND {
		fm.statusText = "Change RADIUS enablement and revision with lc set filter --file"
		fm.filterList.NewStatusMessage(fm.statusText)
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

	fm.pending = true
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
	if result, ok := msg.(FilterOperationResultMsg); ok {
		return fm.handleOperationResult(result)
	}
	if !fm.active {
		return nil
	}

	if cmd, handled := HandleModalInput(fm, msg); handled {
		return cmd
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
	fm.pending = false
	statusMsg := filtermanager.FormatOperationResult(filtermanager.FormatOperationResultParams{
		Success:        msg.Success,
		Operation:      msg.Operation,
		FilterPattern:  msg.FilterPattern,
		Error:          msg.Error,
		HuntersUpdated: msg.HuntersUpdated,
	})
	fm.statusText = statusMsg
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
		fm.ensureVisible()
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
	if msg.String() == "enter" || msg.String() == " " {
		if fm.modalState.Focus == "type" || fm.modalState.Focus == "status" {
			return fm.ActivateAction(fm.modalState.Focus)
		}
	}
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
		return fm.ActivateAction("new")
	case "enter":
		return fm.ActivateAction("edit")
	case "d":
		return fm.ActivateAction("delete")
	case " ":
		return fm.ActivateAction("toggle")

	default:
		var cmd tea.Cmd
		fm.filterList, cmd = fm.filterList.Update(msg)
		fm.ensureVisible()
		return cmd
	}
}

// handleHunterSelectionMode uses the same capability projection as drawing and clicks.
func (fm *FilterManager) handleHunterSelectionMode(msg tea.KeyMsg) tea.Cmd {
	if fm.formState == nil {
		fm.selectingHunters = false
		return nil
	}
	switch msg.String() {
	case "up", "k":
		fm.hunterCursor = max(0, fm.hunterCursor-1)
	case "down", "j":
		fm.hunterCursor = min(max(0, len(fm.eligibleHunters())-1), fm.hunterCursor+1)
	case " ":
		fm.toggleHunter(fm.selectedHunterID())
	case "a":
		return fm.ActivateAction("hunters-all")
	case "n":
		return fm.ActivateAction("hunters-none")
	case "enter":
		return fm.ActivateAction("hunters-confirm")
	case "esc":
		return fm.ActivateAction("cancel")
	}
	fm.ensureVisible()
	return nil
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
	if filter == nil || fm.pending {
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

	fm.pending = true
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
	fm.statusText = ""
	patternInput := textinput.New()
	patternInput.Placeholder = "e.g., alicent@example.com"
	patternInput.CharLimit = 200
	patternInput.Width = max(1, ModalContentWidth(ModalRenderOptions{Width: fm.width, ModalWidth: 80})-14)
	patternInput.Focus()

	descInput := textinput.New()
	descInput.Placeholder = "Optional description"
	descInput.CharLimit = 500
	descInput.Width = max(1, ModalContentWidth(ModalRenderOptions{Width: fm.width, ModalWidth: 80})-14)

	// Choose default filter type based on available hunters
	defaultType := management.FilterType_FILTER_BPF
	if filtermanager.HasVoIPHunters(fm.availableHunters) {
		defaultType = management.FilterType_FILTER_SIP_USER
	}

	fm.formState = &FilterFormState{
		filterID:      "",
		filterType:    defaultType,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       true,
		targetHunters: []string{},
		activeField:   0,
	}

	fm.modalState.Focus = "pattern"
	fm.modalState.Scroll = 0
	fm.mode = ModeAdd
}

// initializeEditForm initializes the form for editing an existing filter
func (fm *FilterManager) initializeEditForm(filter *management.Filter) {
	if filter.Type >= management.FilterType_FILTER_RADIUS_USERNAME && filter.Type <= management.FilterType_FILTER_RADIUS_COMPOUND {
		fm.statusText = "Edit RADIUS criteria and revisions with lc set filter --file"
		fm.filterList.NewStatusMessage(fm.statusText)
		return
	}
	fm.statusText = ""
	patternInput := textinput.New()
	patternInput.SetValue(filter.Pattern)
	patternInput.CharLimit = 200
	patternInput.Width = max(1, ModalContentWidth(ModalRenderOptions{Width: fm.width, ModalWidth: 80})-14)
	patternInput.Focus()

	descInput := textinput.New()
	descInput.SetValue(filter.Description)
	descInput.CharLimit = 500
	descInput.Width = max(1, ModalContentWidth(ModalRenderOptions{Width: fm.width, ModalWidth: 80})-14)

	fm.formState = &FilterFormState{
		filterID:      filter.Id,
		filterType:    filter.Type,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       filter.Enabled,
		targetHunters: slices.Clone(filter.TargetHunters),
		activeField:   0,
	}

	fm.modalState.Focus = "pattern"
	fm.modalState.Scroll = 0
	fm.mode = ModeEdit
}

// handleFormMode handles keyboard input in add/edit form mode
func (fm *FilterManager) handleFormMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		return fm.ActivateAction("cancel")

	case "s":
		if fm.formState != nil && fm.formState.activeField == 4 {
			fm.beginHunterSelection()
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
		return fm.ActivateAction("save")
	case " ":
		if fm.formState != nil && fm.formState.activeField == 3 {
			return fm.ActivateAction("form-enabled")
		}
		if fm.formState != nil && fm.formState.activeField == 4 {
			return fm.ActivateAction("form-targets")
		}
		if fm.formState != nil && fm.formState.activeField == 0 {
			var cmd tea.Cmd
			fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			return cmd
		}
		if fm.formState != nil && fm.formState.activeField == 1 {
			var cmd tea.Cmd
			fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
			return cmd
		}
		return nil

	case "down", "tab":
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField + 1) % 5
			fm.updateFormFieldFocus()
			fm.modalState.Focus = []string{"pattern", "description", "form-type", "form-enabled", "form-targets"}[fm.formState.activeField]
			EnsureModalTargetVisible(fm.ModalOptions(), fm.modalState.Focus)
		}
		return nil

	case "up", "shift+tab":
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField - 1 + 5) % 5
			fm.updateFormFieldFocus()
			fm.modalState.Focus = []string{"pattern", "description", "form-type", "form-enabled", "form-targets"}[fm.formState.activeField]
			EnsureModalTargetVisible(fm.ModalOptions(), fm.modalState.Focus)
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
				fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, false, fm.availableHunters)
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
				fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, true, fm.availableHunters)
			case 3:
				fm.formState.enabled = !fm.formState.enabled
			}
		}
		return nil

	case "ctrl+t":
		if fm.formState != nil {
			fm.formState.filterType = filtermanager.CycleFormFilterType(fm.formState.filterType, true, fm.availableHunters)
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
	if fm.pending {
		return nil
	}
	if fm.formState == nil {
		fm.mode = ModeList
		return nil
	}

	// Validate pattern
	pattern := strings.TrimSpace(fm.formState.patternInput.Value())
	validationResult := filtermanager.ValidateFilter(filtermanager.ValidateFilterParams{
		Pattern:          pattern,
		Description:      strings.TrimSpace(fm.formState.descInput.Value()),
		Type:             fm.formState.filterType,
		AvailableHunters: fm.availableHunters,
	})

	if !validationResult.Valid {
		fm.statusText = validationResult.ErrorMessage
		fm.filterList.NewStatusMessage(validationResult.ErrorMessage)
		return nil
	}

	fm.statusText = ""
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
	fm.modalState.Reset()
	fm.applyFilters()

	fm.pending = true
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

// View renders the visible layer using the shared geometry.
func (fm *FilterManager) View() string {
	if !fm.active {
		return ""
	}
	if fm.confirmDialog.IsActive() {
		return fm.confirmDialog.View()
	}
	return RenderModal(fm.ModalOptions())
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
