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

// Title implements list.DefaultItem
func (i FilterItem) Title() string {
	return i.filter.Pattern
}

// Description implements list.DefaultItem
func (i FilterItem) Description() string {
	return i.filter.Description
}

// FilterDelegate is a custom delegate for rendering filter items
type FilterDelegate struct {
	list.DefaultDelegate
	theme themes.Theme
}

// NewFilterDelegate creates a new filter delegate
func NewFilterDelegate(theme themes.Theme) FilterDelegate {
	return FilterDelegate{
		DefaultDelegate: list.NewDefaultDelegate(),
		theme:           theme,
	}
}

// Render renders a filter item
func (d FilterDelegate) Render(w io.Writer, m list.Model, index int, item list.Item) {
	filterItem, ok := item.(FilterItem)
	if !ok {
		d.DefaultDelegate.Render(w, m, index, item)
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

	var str string
	if isSelected {
		selectedStyle := lipgloss.NewStyle().
			Foreground(d.theme.SelectionFg).
			Background(d.theme.SelectionBg).
			Bold(true)
		str = selectedStyle.Render(row)
	} else {
		normalStyle := lipgloss.NewStyle().
			Foreground(d.theme.Foreground)
		str = normalStyle.Render(row)
	}

	fmt.Fprint(w, str)
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
	active          bool
	mode            FilterManagerMode
	targetNode      string // processor addr or hunter ID
	targetType      NodeType
	searchMode      bool
	filterByType    *management.FilterType
	filterByEnabled *bool
	loading         bool
	deleteCandidate *management.Filter // Filter pending deletion confirmation

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

	// Reserve space for modal chrome and headers
	listWidth := width - 10   // Account for padding
	listHeight := height - 15 // Account for title, search bar, footer
	if listHeight < 5 {
		listHeight = 5
	}

	fm.filterList.SetSize(listWidth, listHeight)
}

// Activate shows the filter manager for a specific node
func (fm *FilterManager) Activate(targetNode string, targetType NodeType) {
	fm.active = true
	fm.targetNode = targetNode
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
	if fm.filterByType == nil {
		// All → SIP User
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
			// BPF → All
			fm.filterByType = nil
		default:
			fm.filterByType = nil
		}
	}
	fm.applyFilters()
}

// CycleEnabledFilter cycles through enabled filter options
func (fm *FilterManager) CycleEnabledFilter() {
	if fm.filterByEnabled == nil {
		// All → Enabled Only
		t := true
		fm.filterByEnabled = &t
	} else if *fm.filterByEnabled {
		// Enabled Only → Disabled Only
		f := false
		fm.filterByEnabled = &f
	} else {
		// Disabled Only → All
		fm.filterByEnabled = nil
	}
	fm.applyFilters()
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

	// Toggle the enabled state
	selectedFilter.Enabled = !selectedFilter.Enabled

	// TODO: Phase 6 - Call gRPC UpdateFilter RPC to persist change
	// For now, just update local state

	// Show status message
	status := "disabled"
	if selectedFilter.Enabled {
		status = "enabled"
	}
	fm.filterList.NewStatusMessage(fmt.Sprintf("Filter '%s' %s", fm.truncatePattern(selectedFilter.Pattern, 30), status))

	// Refresh the view to update checkbox display
	fm.applyFilters()

	return nil
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

// Update handles key events
func (fm *FilterManager) Update(msg tea.Msg) tea.Cmd {
	if !fm.active {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		// Handle delete confirmation mode
		if fm.mode == ModeDeleteConfirm {
			return fm.handleDeleteConfirmMode(msg)
		}

		// Handle search mode
		if fm.searchMode {
			return fm.handleSearchMode(msg)
		}

		// Handle list mode
		return fm.handleListMode(msg)
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
		// Cycle type filter
		fm.CycleTypeFilter()
		return nil

	case "e":
		// Cycle enabled filter
		fm.CycleEnabledFilter()
		return nil

	case "n":
		// New filter (TODO: Phase 5)
		return nil

	case "enter":
		// Edit filter (TODO: Phase 5)
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

	// Find and remove the filter from allFilters
	filterID := fm.deleteCandidate.Id
	patternForMsg := fm.deleteCandidate.Pattern

	for i, filter := range fm.allFilters {
		if filter.Id == filterID {
			// Remove from slice
			fm.allFilters = append(fm.allFilters[:i], fm.allFilters[i+1:]...)
			break
		}
	}

	// TODO: Phase 6 - Call gRPC DeleteFilter RPC to persist deletion
	// For now, just update local state

	// Clear delete candidate and return to list mode
	fm.deleteCandidate = nil
	fm.mode = ModeList

	// Show status message
	fm.filterList.NewStatusMessage(fmt.Sprintf("Filter '%s' deleted", fm.truncatePattern(patternForMsg, 30)))

	// Refresh the view
	fm.applyFilters()

	return nil
}

// View renders the filter manager using unified modal
func (fm *FilterManager) View() string {
	if !fm.active {
		return ""
	}

	// Show delete confirmation dialog if in delete confirmation mode
	if fm.mode == ModeDeleteConfirm {
		return fm.renderDeleteConfirmation()
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
		footer = "/: Search  t: Type filter  e: Enabled filter  Space: Toggle  n: New  Enter: Edit  d: Delete  Esc: Close"
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

	// Filter details
	content.WriteString("Are you sure you want to delete this filter?\n\n")

	detailStyle := lipgloss.NewStyle().
		Foreground(fm.theme.Foreground)
	content.WriteString(detailStyle.Render(fmt.Sprintf("Pattern: %s\n", fm.deleteCandidate.Pattern)))
	content.WriteString(detailStyle.Render(fmt.Sprintf("Type: %s\n", fm.deleteCandidate.Type.String())))
	if fm.deleteCandidate.Description != "" {
		content.WriteString(detailStyle.Render(fmt.Sprintf("Description: %s\n", fm.deleteCandidate.Description)))
	}

	content.WriteString("\n")
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

// renderSearchBar renders the search bar with filter indicators
func (fm *FilterManager) renderSearchBar() string {
	var parts []string

	// Search input
	searchLabel := "Search: "
	if fm.searchMode {
		searchLabel = "Search: "
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
}
