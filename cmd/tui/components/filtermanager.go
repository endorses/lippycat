//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// FilterItem wraps a management.Filter for use with bubbles list
type FilterItem struct {
	filter *management.Filter
}

// FilterValue implements list.Item
func (i FilterItem) FilterValue() string {
	// Search across pattern, description, type, and targets
	searchable := []string{
		i.filter.Pattern,
		i.filter.Description,
		i.filter.Type.String(),
		strings.Join(i.filter.TargetHunters, " "),
	}
	return strings.ToLower(strings.Join(searchable, " "))
}

// NOTE: We do NOT implement Title() and Description() from list.DefaultItem
// because that would cause DefaultDelegate to use its built-in rendering
// instead of our custom Render() method.

// FilterDelegate is a custom delegate for rendering filter items
// NOTE: We do NOT embed DefaultDelegate because it interferes with custom rendering
type FilterDelegate struct {
	theme themes.Theme
}

// NewFilterDelegate creates a new filter delegate
func NewFilterDelegate(theme themes.Theme) FilterDelegate {
	return FilterDelegate{
		theme: theme,
	}
}

// Height returns the height of a list item
func (d FilterDelegate) Height() int {
	return 1
}

// Spacing returns the spacing between list items
func (d FilterDelegate) Spacing() int {
	return 0
}

// Update handles updates for the delegate
func (d FilterDelegate) Update(msg tea.Msg, m *list.Model) tea.Cmd {
	return nil
}

// Render renders a filter item
func (d FilterDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	filterItem, ok := item.(FilterItem)
	if !ok {
		// Not a FilterItem, render nothing
		return
	}

	filter := filterItem.filter
	isSelected := index == m.Index()

	// Enabled checkbox
	checkbox := "✗"
	if filter.Enabled {
		checkbox = "✓"
	}

	// Filter type (abbreviated)
	filterType := d.abbreviateType(filter.Type)

	// Target hunters
	targets := "All hunters"
	if len(filter.TargetHunters) > 0 {
		if len(filter.TargetHunters) == 1 {
			targets = filter.TargetHunters[0]
		} else {
			targets = fmt.Sprintf("%s,+%d", filter.TargetHunters[0], len(filter.TargetHunters)-1)
		}
	}

	// Build row: [✓] | Type | Pattern | Targets
	row := fmt.Sprintf(" %s │ %-12s │ %-25s │ %s",
		checkbox,
		filterType,
		d.truncate(filter.Pattern, 25),
		d.truncate(targets, 20),
	)

	// Get available width
	availableWidth := m.Width()
	if availableWidth <= 0 {
		availableWidth = 80 // fallback
	}

	if isSelected {
		selectedStyle := lipgloss.NewStyle().
			Foreground(d.theme.SelectionFg).
			Background(d.theme.SelectionBg).
			Bold(true).
			Width(availableWidth)
		fmt.Fprint(w, selectedStyle.Render(row))
	} else {
		normalStyle := lipgloss.NewStyle().
			Foreground(d.theme.Foreground).
			Width(availableWidth)
		fmt.Fprint(w, normalStyle.Render(row))
	}
}

// abbreviateType returns abbreviated filter type name
func (d FilterDelegate) abbreviateType(t management.FilterType) string {
	switch t {
	case management.FilterType_FILTER_SIP_USER:
		return "SIP User"
	case management.FilterType_FILTER_PHONE_NUMBER:
		return "Phone"
	case management.FilterType_FILTER_IP_ADDRESS:
		return "IP Address"
	case management.FilterType_FILTER_CALL_ID:
		return "Call-ID"
	case management.FilterType_FILTER_CODEC:
		return "Codec"
	case management.FilterType_FILTER_BPF:
		return "BPF"
	default:
		return "Unknown"
	}
}

// truncate truncates a string to max length
func (d FilterDelegate) truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if max <= 3 {
		return s[:max]
	}
	return s[:max-3] + "..."
}

// FilterManagerMode represents the current mode of the filter manager
type FilterManagerMode int

const (
	ModeList FilterManagerMode = iota
	ModeAdd
	ModeEdit
	ModeDeleteConfirm
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
	filterList  list.Model
	searchInput textinput.Model

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
	deleteCandidate  *management.Filter   // Filter pending deletion confirmation
	availableHunters []HunterSelectorItem // Available hunters for target selection
	selectingHunters bool                 // Whether we're in hunter selection mode

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
	delegate := NewFilterDelegate(themes.Solarized())
	filterList := list.New([]list.Item{}, delegate, 0, 0)
	filterList.Title = "Filters"
	filterList.SetShowStatusBar(true)
	filterList.SetShowHelp(false)
	filterList.SetFilteringEnabled(false) // We handle filtering ourselves

	return FilterManager{
		allFilters:      make([]*management.Filter, 0),
		filteredFilters: make([]*management.Filter, 0),
		filterList:      filterList,
		searchInput:     searchInput,
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
	delegate := NewFilterDelegate(theme)
	fm.filterList.SetDelegate(delegate)
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
	listHeight := height - 15 // Account for title, search bar, footer
	if listHeight < 5 {
		listHeight = 5
	}

	fm.filterList.SetSize(listWidth, listHeight)
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
	fm.availableHunters = hunters
}

// applyFilters applies search and filter criteria
func (fm *FilterManager) applyFilters() {
	fm.filteredFilters = make([]*management.Filter, 0)

	searchLower := strings.ToLower(fm.searchInput.Value())

	for _, filter := range fm.allFilters {
		// Apply type filter
		if fm.filterByType != nil && filter.Type != *fm.filterByType {
			continue
		}

		// Apply enabled filter
		if fm.filterByEnabled != nil && filter.Enabled != *fm.filterByEnabled {
			continue
		}

		// Apply search filter
		if searchLower != "" {
			pattern := strings.ToLower(filter.Pattern)
			desc := strings.ToLower(filter.Description)
			typeName := strings.ToLower(filter.Type.String())
			targets := strings.ToLower(strings.Join(filter.TargetHunters, " "))

			if !strings.Contains(pattern, searchLower) &&
				!strings.Contains(desc, searchLower) &&
				!strings.Contains(typeName, searchLower) &&
				!strings.Contains(targets, searchLower) {
				continue
			}
		}

		fm.filteredFilters = append(fm.filteredFilters, filter)
	}

	// Convert to list items
	items := make([]list.Item, len(fm.filteredFilters))
	for i, filter := range fm.filteredFilters {
		items[i] = FilterItem{filter: filter}
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
		totalFilters := len(fm.allFilters)
		filteredCount := len(fm.filteredFilters)

		if totalFilters == filteredCount {
			fm.filterList.NewStatusMessage(fmt.Sprintf("%d filters", totalFilters))
		} else {
			fm.filterList.NewStatusMessage(fmt.Sprintf("Showing %d of %d filters", filteredCount, totalFilters))
		}
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
	fm.cycleTypeFilterDirection(true)
}

// CycleTypeFilterBackward cycles through filter type options (backward)
func (fm *FilterManager) CycleTypeFilterBackward() {
	fm.cycleTypeFilterDirection(false)
}

// cycleTypeFilterDirection cycles through filter types in specified direction
func (fm *FilterManager) cycleTypeFilterDirection(forward bool) {
	if forward {
		// Forward: All → SIP User → Phone → IP → Call-ID → Codec → BPF → All
		if fm.filterByType == nil {
			t := management.FilterType_FILTER_SIP_USER
			fm.filterByType = &t
		} else {
			switch *fm.filterByType {
			case management.FilterType_FILTER_SIP_USER:
				t := management.FilterType_FILTER_PHONE_NUMBER
				fm.filterByType = &t
			case management.FilterType_FILTER_PHONE_NUMBER:
				t := management.FilterType_FILTER_IP_ADDRESS
				fm.filterByType = &t
			case management.FilterType_FILTER_IP_ADDRESS:
				t := management.FilterType_FILTER_CALL_ID
				fm.filterByType = &t
			case management.FilterType_FILTER_CALL_ID:
				t := management.FilterType_FILTER_CODEC
				fm.filterByType = &t
			case management.FilterType_FILTER_CODEC:
				t := management.FilterType_FILTER_BPF
				fm.filterByType = &t
			case management.FilterType_FILTER_BPF:
				fm.filterByType = nil
			default:
				fm.filterByType = nil
			}
		}
	} else {
		// Backward: All → BPF → Codec → Call-ID → IP → Phone → SIP User → All
		if fm.filterByType == nil {
			t := management.FilterType_FILTER_BPF
			fm.filterByType = &t
		} else {
			switch *fm.filterByType {
			case management.FilterType_FILTER_BPF:
				t := management.FilterType_FILTER_CODEC
				fm.filterByType = &t
			case management.FilterType_FILTER_CODEC:
				t := management.FilterType_FILTER_CALL_ID
				fm.filterByType = &t
			case management.FilterType_FILTER_CALL_ID:
				t := management.FilterType_FILTER_IP_ADDRESS
				fm.filterByType = &t
			case management.FilterType_FILTER_IP_ADDRESS:
				t := management.FilterType_FILTER_PHONE_NUMBER
				fm.filterByType = &t
			case management.FilterType_FILTER_PHONE_NUMBER:
				t := management.FilterType_FILTER_SIP_USER
				fm.filterByType = &t
			case management.FilterType_FILTER_SIP_USER:
				fm.filterByType = nil
			default:
				fm.filterByType = nil
			}
		}
	}
	fm.applyFilters()
}

// CycleEnabledFilter cycles through enabled filter options (forward)
func (fm *FilterManager) CycleEnabledFilter() {
	fm.cycleEnabledFilterDirection(true)
}

// CycleEnabledFilterBackward cycles through enabled filter options (backward)
func (fm *FilterManager) CycleEnabledFilterBackward() {
	fm.cycleEnabledFilterDirection(false)
}

// cycleEnabledFilterDirection cycles through enabled states in specified direction
func (fm *FilterManager) cycleEnabledFilterDirection(forward bool) {
	if forward {
		// Forward: All → Enabled Only → Disabled Only → All
		if fm.filterByEnabled == nil {
			t := true
			fm.filterByEnabled = &t
		} else if *fm.filterByEnabled {
			f := false
			fm.filterByEnabled = &f
		} else {
			fm.filterByEnabled = nil
		}
	} else {
		// Backward: All → Disabled Only → Enabled Only → All
		if fm.filterByEnabled == nil {
			f := false
			fm.filterByEnabled = &f
		} else if !*fm.filterByEnabled {
			t := true
			fm.filterByEnabled = &t
		} else {
			fm.filterByEnabled = nil
		}
	}
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
	// Get current height to determine page size
	pageSize := fm.filterList.Height()
	if pageSize <= 0 {
		pageSize = 10 // Default page size
	}

	currentIndex := fm.filterList.Index()
	newIndex := currentIndex - pageSize
	if newIndex < 0 {
		newIndex = 0
	}
	fm.filterList.Select(newIndex)
}

// PageDown moves down one page in the list
func (fm *FilterManager) PageDown() {
	// Get current height to determine page size
	pageSize := fm.filterList.Height()
	if pageSize <= 0 {
		pageSize = 10 // Default page size
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

	// Toggle the enabled state locally
	selectedFilter.Enabled = !selectedFilter.Enabled

	// Show status message
	status := "disabled"
	if selectedFilter.Enabled {
		status = "enabled"
	}
	fm.filterList.NewStatusMessage(fmt.Sprintf("Filter '%s' %s", fm.truncatePattern(selectedFilter.Pattern, 30), status))

	// Refresh the view to update checkbox display
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

// truncatePattern truncates a pattern for display in status messages
func (fm *FilterManager) truncatePattern(pattern string, max int) string {
	if len(pattern) <= max {
		return pattern
	}
	if max <= 3 {
		return pattern[:max]
	}
	return pattern[:max-3] + "..."
}

// Update handles key events and messages
func (fm *FilterManager) Update(msg tea.Msg) tea.Cmd {
	if !fm.active {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle hunter selection mode
		if fm.selectingHunters {
			return fm.handleHunterSelectionMode(msg)
		}

		// Handle delete confirmation mode
		if fm.mode == ModeDeleteConfirm {
			return fm.handleDeleteConfirmMode(msg)
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

	case FilterOperationResultMsg:
		// Handle gRPC operation results
		return fm.handleOperationResult(msg)
	}

	return nil
}

// handleOperationResult handles the result of a filter operation
func (fm *FilterManager) handleOperationResult(msg FilterOperationResultMsg) tea.Cmd {
	if msg.Success {
		var statusMsg string
		switch msg.Operation {
		case "create":
			statusMsg = fmt.Sprintf("Filter '%s' created (%d hunter(s) updated)", msg.FilterPattern, msg.HuntersUpdated)
		case "update", "toggle":
			statusMsg = fmt.Sprintf("Filter '%s' updated (%d hunter(s) updated)", msg.FilterPattern, msg.HuntersUpdated)
		case "delete":
			statusMsg = fmt.Sprintf("Filter '%s' deleted (%d hunter(s) updated)", msg.FilterPattern, msg.HuntersUpdated)
		default:
			statusMsg = fmt.Sprintf("Filter operation completed (%d hunter(s) updated)", msg.HuntersUpdated)
		}
		fm.filterList.NewStatusMessage(statusMsg)
	} else {
		// Operation failed - show error
		errorMsg := fmt.Sprintf("Failed to %s filter: %s", msg.Operation, msg.Error)
		fm.filterList.NewStatusMessage(errorMsg)
		// TODO: Consider reverting optimistic local changes on failure
	}

	return nil
}

// handleSearchMode handles keyboard input in search mode
func (fm *FilterManager) handleSearchMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		// Clear search and exit search mode
		fm.searchInput.SetValue("")
		fm.ExitSearchMode()
		fm.applyFilters()
		return nil

	case "enter":
		// Keep search, exit search mode
		fm.ExitSearchMode()
		return nil

	case "up", "down":
		// Allow navigation while searching
		var cmd tea.Cmd
		fm.filterList, cmd = fm.filterList.Update(msg)
		return cmd

	default:
		// Update search input
		var cmd tea.Cmd
		fm.searchInput, cmd = fm.searchInput.Update(msg)
		fm.applyFilters() // Real-time filtering
		return cmd
	}
}

// handleListMode handles keyboard input in list mode
func (fm *FilterManager) handleListMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc", "q":
		// Close filter manager
		fm.Deactivate()
		return nil

	case "/":
		// Enter search mode (vim-style)
		fm.EnterSearchMode()
		return nil

	case "t":
		// Cycle type filter (keep for backwards compatibility)
		fm.CycleTypeFilter()
		return nil

	case "e":
		// Cycle enabled filter (keep for backwards compatibility)
		fm.CycleEnabledFilter()
		return nil

	case "left":
		// Cycle type filter backward (left arrow)
		fm.CycleTypeFilterBackward()
		return nil

	case "right":
		// Cycle type filter forward (right arrow)
		fm.CycleTypeFilter()
		return nil

	case "shift+left":
		// Cycle enabled filter backward (shift+left arrow)
		fm.CycleEnabledFilterBackward()
		return nil

	case "shift+right":
		// Cycle enabled filter forward (shift+right arrow)
		fm.CycleEnabledFilter()
		return nil

	case "g":
		// Jump to top (vim-style)
		fm.JumpToTop()
		return nil

	case "G":
		// Jump to bottom (vim-style)
		fm.JumpToBottom()
		return nil

	case "pgup":
		// Page up
		fm.PageUp()
		return nil

	case "pgdown":
		// Page down
		fm.PageDown()
		return nil

	case "n":
		// New filter
		fm.initializeAddForm()
		return nil

	case "enter":
		// Edit filter
		selectedFilter := fm.GetSelectedFilter()
		if selectedFilter != nil {
			fm.initializeEditForm(selectedFilter)
		}
		return nil

	case "d":
		// Delete filter (show confirmation)
		selectedFilter := fm.GetSelectedFilter()
		if selectedFilter != nil {
			fm.deleteCandidate = selectedFilter
			fm.mode = ModeDeleteConfirm
		}
		return nil

	case " ":
		// Toggle enabled
		return fm.toggleFilterEnabled()

	default:
		// Pass to list for navigation
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
		// Move cursor up
		if len(fm.availableHunters) > 0 {
			currentIdx := fm.formState.activeField // reuse activeField as cursor
			if currentIdx > 0 {
				fm.formState.activeField--
			}
		}
		return nil

	case "down", "j":
		// Move cursor down
		if len(fm.availableHunters) > 0 {
			currentIdx := fm.formState.activeField
			if currentIdx < len(fm.availableHunters)-1 {
				fm.formState.activeField++
			}
		}
		return nil

	case " ": // Space to toggle
		if len(fm.availableHunters) > 0 {
			hunterID := fm.availableHunters[fm.formState.activeField].HunterID
			// Check if already selected
			found := false
			for i, id := range fm.formState.targetHunters {
				if id == hunterID {
					// Remove it
					fm.formState.targetHunters = append(fm.formState.targetHunters[:i], fm.formState.targetHunters[i+1:]...)
					found = true
					break
				}
			}
			if !found {
				// Add it
				fm.formState.targetHunters = append(fm.formState.targetHunters, hunterID)
			}
		}
		return nil

	case "a": // Select all
		fm.formState.targetHunters = make([]string, 0, len(fm.availableHunters))
		for _, hunter := range fm.availableHunters {
			fm.formState.targetHunters = append(fm.formState.targetHunters, hunter.HunterID)
		}
		return nil

	case "n": // Select none
		fm.formState.targetHunters = []string{}
		return nil

	case "enter":
		// Confirm selection and return to form
		fm.selectingHunters = false
		fm.formState.activeField = 4 // Back to targets field
		return nil

	case "esc":
		// Cancel and return to form without changes
		fm.selectingHunters = false
		fm.formState.activeField = 4 // Back to targets field
		return nil

	default:
		return nil
	}
}

// handleDeleteConfirmMode handles keyboard input in delete confirmation mode
func (fm *FilterManager) handleDeleteConfirmMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "y", "Y":
		// Confirm delete
		return fm.deleteFilter()

	case "n", "N", "esc":
		// Cancel delete
		fm.deleteCandidate = nil
		fm.mode = ModeList
		return nil

	default:
		return nil
	}
}

// deleteFilter deletes the filter pending deletion
func (fm *FilterManager) deleteFilter() tea.Cmd {
	if fm.deleteCandidate == nil {
		fm.mode = ModeList
		return nil
	}

	// Find and remove the filter from allFilters locally
	filterID := fm.deleteCandidate.Id
	patternForMsg := fm.deleteCandidate.Pattern

	for i, filter := range fm.allFilters {
		if filter.Id == filterID {
			// Remove from slice
			fm.allFilters = append(fm.allFilters[:i], fm.allFilters[i+1:]...)
			break
		}
	}

	// Clear delete candidate and return to list mode
	fm.deleteCandidate = nil
	fm.mode = ModeList

	// Show status message
	fm.filterList.NewStatusMessage(fmt.Sprintf("Filter '%s' deleted", fm.truncatePattern(patternForMsg, 30)))

	// Refresh the view
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
	patternInput.Width = 50
	patternInput.Focus()

	descInput := textinput.New()
	descInput.Placeholder = "Optional description"
	descInput.CharLimit = 500
	descInput.Width = 50

	fm.formState = &FilterFormState{
		filterID:      "", // Empty for new filter
		filterType:    management.FilterType_FILTER_SIP_USER,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       true,
		targetHunters: []string{}, // Empty means all hunters
		activeField:   0,          // Start with pattern field
	}

	fm.mode = ModeAdd
}

// initializeEditForm initializes the form for editing an existing filter
func (fm *FilterManager) initializeEditForm(filter *management.Filter) {
	patternInput := textinput.New()
	patternInput.SetValue(filter.Pattern)
	patternInput.CharLimit = 200
	patternInput.Width = 50
	patternInput.Focus()

	descInput := textinput.New()
	descInput.SetValue(filter.Description)
	descInput.CharLimit = 500
	descInput.Width = 50

	fm.formState = &FilterFormState{
		filterID:      filter.Id,
		filterType:    filter.Type,
		patternInput:  patternInput,
		descInput:     descInput,
		enabled:       filter.Enabled,
		targetHunters: append([]string{}, filter.TargetHunters...), // Copy slice
		activeField:   0,
	}

	fm.mode = ModeEdit
}

// handleFormMode handles keyboard input in add/edit form mode
func (fm *FilterManager) handleFormMode(msg tea.KeyMsg) tea.Cmd {
	switch msg.String() {
	case "esc":
		// Cancel form
		fm.formState = nil
		fm.mode = ModeList
		return nil

	case "s":
		// If on targets field, open hunter selection mode
		if fm.formState != nil && fm.formState.activeField == 4 {
			fm.selectingHunters = true
			fm.formState.activeField = 0 // Reset cursor for hunter list
			return nil
		}
		return nil

	case "enter", "ctrl+s":
		// Save filter
		return fm.saveFilter()

	case "down", "tab":
		// Move to next field
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField + 1) % 5 // 5 fields total
			fm.updateFormFieldFocus()
		}
		return nil

	case "up", "shift+tab":
		// Move to previous field
		if fm.formState != nil {
			fm.formState.activeField = (fm.formState.activeField - 1 + 5) % 5
			fm.updateFormFieldFocus()
		}
		return nil

	case "left":
		// Handle left arrow based on active field
		if fm.formState != nil {
			switch fm.formState.activeField {
			case 2: // Type field - cycle backward
				fm.formState.filterType = fm.cycleFilterTypeBackward(fm.formState.filterType)
			case 3: // Status field - toggle
				fm.formState.enabled = !fm.formState.enabled
			}
		}
		return nil

	case "right":
		// Handle right arrow based on active field
		if fm.formState != nil {
			switch fm.formState.activeField {
			case 2: // Type field - cycle forward
				fm.formState.filterType = fm.cycleFilterType(fm.formState.filterType)
			case 3: // Status field - toggle
				fm.formState.enabled = !fm.formState.enabled
			}
		}
		return nil

	case "ctrl+t":
		// Cycle filter type (alternative)
		if fm.formState != nil {
			fm.formState.filterType = fm.cycleFilterType(fm.formState.filterType)
		}
		return nil

	case "ctrl+e":
		// Toggle enabled (alternative)
		if fm.formState != nil {
			fm.formState.enabled = !fm.formState.enabled
		}
		return nil

	default:
		// Update active input field
		if fm.formState != nil {
			var cmd tea.Cmd
			switch fm.formState.activeField {
			case 0: // Pattern field
				fm.formState.patternInput, cmd = fm.formState.patternInput.Update(msg)
			case 1: // Description field
				fm.formState.descInput, cmd = fm.formState.descInput.Update(msg)
				// Fields 2-4 are type, enabled, and targets - handled by special keys
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
		// Fields 2-4 don't need focus (toggle/select fields)
	}
}

// cycleFilterType cycles to the next filter type
func (fm *FilterManager) cycleFilterType(current management.FilterType) management.FilterType {
	switch current {
	case management.FilterType_FILTER_SIP_USER:
		return management.FilterType_FILTER_PHONE_NUMBER
	case management.FilterType_FILTER_PHONE_NUMBER:
		return management.FilterType_FILTER_IP_ADDRESS
	case management.FilterType_FILTER_IP_ADDRESS:
		return management.FilterType_FILTER_CALL_ID
	case management.FilterType_FILTER_CALL_ID:
		return management.FilterType_FILTER_CODEC
	case management.FilterType_FILTER_CODEC:
		return management.FilterType_FILTER_BPF
	case management.FilterType_FILTER_BPF:
		return management.FilterType_FILTER_SIP_USER
	default:
		return management.FilterType_FILTER_SIP_USER
	}
}

// cycleFilterTypeBackward cycles through filter types in reverse order
func (fm *FilterManager) cycleFilterTypeBackward(current management.FilterType) management.FilterType {
	switch current {
	case management.FilterType_FILTER_SIP_USER:
		return management.FilterType_FILTER_BPF
	case management.FilterType_FILTER_BPF:
		return management.FilterType_FILTER_CODEC
	case management.FilterType_FILTER_CODEC:
		return management.FilterType_FILTER_CALL_ID
	case management.FilterType_FILTER_CALL_ID:
		return management.FilterType_FILTER_IP_ADDRESS
	case management.FilterType_FILTER_IP_ADDRESS:
		return management.FilterType_FILTER_PHONE_NUMBER
	case management.FilterType_FILTER_PHONE_NUMBER:
		return management.FilterType_FILTER_SIP_USER
	default:
		return management.FilterType_FILTER_SIP_USER
	}
}

// saveFilter saves the current form (add or update)
func (fm *FilterManager) saveFilter() tea.Cmd {
	if fm.formState == nil {
		fm.mode = ModeList
		return nil
	}

	// Validate pattern is not empty
	pattern := strings.TrimSpace(fm.formState.patternInput.Value())
	if pattern == "" {
		fm.filterList.NewStatusMessage("Pattern cannot be empty")
		return nil
	}

	var operation string
	var filter *management.Filter

	if fm.mode == ModeAdd {
		// Create new filter
		operation = "create"
		filter = &management.Filter{
			Id:            "", // Server will assign ID
			Pattern:       pattern,
			Description:   strings.TrimSpace(fm.formState.descInput.Value()),
			Type:          fm.formState.filterType,
			Enabled:       fm.formState.enabled,
			TargetHunters: fm.formState.targetHunters,
		}

		// Add to local state optimistically
		tempFilter := &management.Filter{
			Id:            fmt.Sprintf("filter-%d", len(fm.allFilters)+1), // Temporary local ID
			Pattern:       filter.Pattern,
			Description:   filter.Description,
			Type:          filter.Type,
			Enabled:       filter.Enabled,
			TargetHunters: append([]string{}, filter.TargetHunters...),
		}
		fm.allFilters = append(fm.allFilters, tempFilter)
		fm.filterList.NewStatusMessage(fmt.Sprintf("Creating filter '%s'...", fm.truncatePattern(pattern, 30)))

	} else if fm.mode == ModeEdit {
		// Update existing filter
		operation = "update"
		for _, f := range fm.allFilters {
			if f.Id == fm.formState.filterID {
				// Update local state optimistically
				f.Pattern = pattern
				f.Description = strings.TrimSpace(fm.formState.descInput.Value())
				f.Type = fm.formState.filterType
				f.Enabled = fm.formState.enabled
				f.TargetHunters = fm.formState.targetHunters

				filter = f
				break
			}
		}

		if filter == nil {
			fm.formState = nil
			fm.mode = ModeList
			fm.filterList.NewStatusMessage("Error: filter not found")
			return nil
		}

		fm.filterList.NewStatusMessage(fmt.Sprintf("Updating filter '%s'...", fm.truncatePattern(pattern, 30)))
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

	// Show hunter selection if in that mode
	if fm.selectingHunters {
		return fm.renderHunterSelection()
	}

	// Show delete confirmation dialog if in delete confirmation mode
	if fm.mode == ModeDeleteConfirm {
		return fm.renderDeleteConfirmation()
	}

	// Show add/edit form if in form mode
	if fm.mode == ModeAdd || fm.mode == ModeEdit {
		return fm.renderFilterForm()
	}

	var content strings.Builder

	// Render search bar
	content.WriteString(fm.renderSearchBar())
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
		ModalWidth: 0, // Auto-calculate
	})
}

// renderDeleteConfirmation renders the delete confirmation dialog
func (fm *FilterManager) renderDeleteConfirmation() string {
	if fm.deleteCandidate == nil {
		return ""
	}

	var content strings.Builder

	// Warning message
	warningStyle := lipgloss.NewStyle().
		Foreground(fm.theme.ErrorColor).
		Bold(true)
	content.WriteString(warningStyle.Render("⚠️  Delete Filter"))
	content.WriteString("\n\n")

	// Question
	content.WriteString("Are you sure you want to delete this filter?\n\n")

	// Filter details - build as single block for consistent alignment
	var details strings.Builder
	details.WriteString(fmt.Sprintf("Pattern: %s\n", fm.deleteCandidate.Pattern))
	details.WriteString(fmt.Sprintf("Type: %s", fm.deleteCandidate.Type.String()))
	if fm.deleteCandidate.Description != "" {
		details.WriteString(fmt.Sprintf("\nDescription: %s", fm.deleteCandidate.Description))
	}

	detailStyle := lipgloss.NewStyle().
		Foreground(fm.theme.Foreground)
	content.WriteString(detailStyle.Render(details.String()))

	// Warning emphasis
	content.WriteString("\n\n")
	emphasisStyle := lipgloss.NewStyle().
		Foreground(fm.theme.ErrorColor).
		Italic(true)
	content.WriteString(emphasisStyle.Render("This action cannot be undone."))

	footer := "y: Confirm delete  n/Esc: Cancel"

	return RenderModal(ModalRenderOptions{
		Title:      "🗑️  Confirm Deletion",
		Content:    content.String(),
		Footer:     footer,
		Width:      fm.width,
		Height:     fm.height,
		Theme:      fm.theme,
		ModalWidth: 60,
	})
}

// renderHunterSelection renders the hunter selection UI
func (fm *FilterManager) renderHunterSelection() string {
	if fm.formState == nil {
		return ""
	}

	var content strings.Builder

	// Calculate modal width
	modalWidth := 70
	if modalWidth > fm.width-4 {
		modalWidth = fm.width - 4
	}

	// Modal has padding(1,2) = 4 chars, content uses Width(modalWidth-4)
	contentWidth := modalWidth - 4
	itemWidth := contentWidth - 2 // Account for padding

	// Styles
	itemStyle := lipgloss.NewStyle().
		Foreground(fm.theme.Foreground).
		Padding(0, 1)

	selectedStyle := lipgloss.NewStyle().
		Foreground(fm.theme.SelectionFg).
		Background(fm.theme.SelectionBg).
		Bold(true).
		Padding(0, 1).
		Width(itemWidth)

	if len(fm.availableHunters) == 0 {
		content.WriteString(itemStyle.Render("No hunters available"))
	} else {
		// Reuse activeField as cursor position
		cursorIdx := fm.formState.activeField
		if cursorIdx >= len(fm.availableHunters) {
			cursorIdx = 0
			fm.formState.activeField = 0
		}

		for i, hunter := range fm.availableHunters {
			// Check if this hunter is selected
			isSelected := false
			for _, id := range fm.formState.targetHunters {
				if id == hunter.HunterID {
					isSelected = true
					break
				}
			}

			// Checkbox
			checkbox := "[ ] "
			if isSelected {
				checkbox = "[✓] "
			}

			// Build row
			row := fmt.Sprintf("%s%s (%s)", checkbox, hunter.HunterID, hunter.Hostname)

			// Apply cursor style
			if i == cursorIdx {
				content.WriteString(selectedStyle.Render(row))
			} else {
				content.WriteString(itemStyle.Render(row))
			}
			content.WriteString("\n")
		}
	}

	return RenderModal(ModalRenderOptions{
		Title:      "Select Target Hunters",
		Content:    content.String(),
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

	var content strings.Builder

	labelStyle := lipgloss.NewStyle().
		Foreground(fm.theme.HeaderBg).
		Bold(true)
	valueStyle := lipgloss.NewStyle().
		Foreground(fm.theme.Foreground)
	activeIndicator := lipgloss.NewStyle().
		Foreground(fm.theme.SelectionBg).
		Bold(true).
		Render("→")
	inactiveIndicator := " "

	// Pattern field
	indicator := inactiveIndicator
	if fm.formState.activeField == 0 {
		indicator = activeIndicator
	}
	content.WriteString(fmt.Sprintf("%s %s\n", indicator, labelStyle.Render("Pattern:")))
	content.WriteString("  " + fm.formState.patternInput.View() + "\n\n")

	// Description field
	indicator = inactiveIndicator
	if fm.formState.activeField == 1 {
		indicator = activeIndicator
	}
	content.WriteString(fmt.Sprintf("%s %s\n", indicator, labelStyle.Render("Description:")))
	content.WriteString("  " + fm.formState.descInput.View() + "\n\n")

	// Filter type field
	indicator = inactiveIndicator
	if fm.formState.activeField == 2 {
		indicator = activeIndicator
	}
	delegate := NewFilterDelegate(fm.theme)
	typeStr := delegate.abbreviateType(fm.formState.filterType)
	content.WriteString(fmt.Sprintf("%s %s %s\n\n",
		indicator,
		labelStyle.Render("Type:"),
		valueStyle.Render(typeStr+" (Ctrl+T to cycle)")))

	// Enabled field
	indicator = inactiveIndicator
	if fm.formState.activeField == 3 {
		indicator = activeIndicator
	}
	enabledStr := "✗ Disabled"
	if fm.formState.enabled {
		enabledStr = "✓ Enabled"
	}
	content.WriteString(fmt.Sprintf("%s %s %s\n\n",
		indicator,
		labelStyle.Render("Status:"),
		valueStyle.Render(enabledStr+" (Ctrl+E to toggle)")))

	// Target hunters field
	indicator = inactiveIndicator
	if fm.formState.activeField == 4 {
		indicator = activeIndicator
	}
	targetStr := "All hunters"
	if len(fm.formState.targetHunters) > 0 {
		targetStr = strings.Join(fm.formState.targetHunters, ", ")
	}
	targetHint := ""
	if fm.formState.activeField == 4 {
		targetHint = " (press s to select)"
	}
	content.WriteString(fmt.Sprintf("%s %s %s\n",
		indicator,
		labelStyle.Render("Targets:"),
		valueStyle.Render(targetStr+targetHint)))

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
		Content:    content.String(),
		Footer:     footer,
		Width:      fm.width,
		Height:     fm.height,
		Theme:      fm.theme,
		ModalWidth: 70,
	})
}

// renderSearchBar renders the search bar with filter indicators
func (fm *FilterManager) renderSearchBar() string {
	var parts []string

	// Search input
	searchLabel := "Search: "
	if fm.searchMode {
		parts = append(parts, searchLabel+fm.searchInput.View())
	} else {
		// Show current search value if any
		searchVal := fm.searchInput.Value()
		if searchVal != "" {
			parts = append(parts, fmt.Sprintf("Search: %s", searchVal))
		} else {
			parts = append(parts, "Search: (press / to search)")
		}
	}

	// Type filter indicator
	typeFilterStr := "Type: All"
	if fm.filterByType != nil {
		delegate := NewFilterDelegate(fm.theme)
		typeFilterStr = "Type: " + delegate.abbreviateType(*fm.filterByType)
	}
	parts = append(parts, typeFilterStr)

	// Enabled filter indicator
	enabledFilterStr := "Show: All"
	if fm.filterByEnabled != nil {
		if *fm.filterByEnabled {
			enabledFilterStr = "Show: ✓ Enabled"
		} else {
			enabledFilterStr = "Show: ✗ Disabled"
		}
	}
	parts = append(parts, enabledFilterStr)

	return strings.Join(parts, "  │  ")
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
