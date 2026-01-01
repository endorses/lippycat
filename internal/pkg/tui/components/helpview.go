//go:build tui || all
// +build tui all

package components

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/help"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// HelpSection represents a help content section
type HelpSection int

const (
	SectionKeybindings HelpSection = iota
	SectionCommands
	SectionWorkflows
)

// HelpView displays embedded markdown help documentation
type HelpView struct {
	viewport        viewport.Model
	width           int
	height          int
	theme           themes.Theme
	ready           bool
	activeSection   HelpSection
	searchMode      bool
	searchQuery     string
	searchMatches   []int // Line numbers with matches
	currentMatch    int   // Current match index
	rawContent      string
	renderedContent string
}

// NewHelpView creates a new help view
func NewHelpView() HelpView {
	return HelpView{
		width:         80,
		height:        20,
		theme:         themes.Solarized(),
		ready:         false,
		activeSection: SectionKeybindings,
		searchMode:    false,
	}
}

// SetTheme updates the theme
func (h *HelpView) SetTheme(theme themes.Theme) {
	h.theme = theme
	// Re-render content with new theme if ready
	if h.ready {
		h.loadSection(h.activeSection)
	}
}

// SetSize sets the display size
func (h *HelpView) SetSize(width, height int) {
	h.width = width
	h.height = height

	if !h.ready {
		h.viewport = viewport.New(width, height)
		h.ready = true
		h.loadSection(h.activeSection)
	} else {
		h.viewport.Width = width
		h.viewport.Height = height
	}
}

// GetActiveSection returns the current section
func (h *HelpView) GetActiveSection() HelpSection {
	return h.activeSection
}

// SetSection changes the active section
func (h *HelpView) SetSection(section HelpSection) {
	if section != h.activeSection {
		h.activeSection = section
		h.clearSearch()
		if h.ready {
			h.loadSection(section)
		}
	}
}

// IsSearchMode returns true if search mode is active
func (h *HelpView) IsSearchMode() bool {
	return h.searchMode
}

// EnterSearchMode enters search mode
func (h *HelpView) EnterSearchMode() {
	h.searchMode = true
	h.searchQuery = ""
	h.searchMatches = nil
	h.currentMatch = 0
}

// ExitSearchMode exits search mode
func (h *HelpView) ExitSearchMode() {
	h.searchMode = false
}

// GetSearchQuery returns the current search query
func (h *HelpView) GetSearchQuery() string {
	return h.searchQuery
}

// AddSearchChar adds a character to the search query
func (h *HelpView) AddSearchChar(c rune) {
	h.searchQuery += string(c)
	h.performSearch()
}

// DeleteSearchChar removes the last character from search query
func (h *HelpView) DeleteSearchChar() {
	if len(h.searchQuery) > 0 {
		h.searchQuery = h.searchQuery[:len(h.searchQuery)-1]
		h.performSearch()
	}
}

// NextMatch moves to the next search match
func (h *HelpView) NextMatch() {
	if len(h.searchMatches) == 0 {
		return
	}
	h.currentMatch = (h.currentMatch + 1) % len(h.searchMatches)
	h.scrollToMatch()
}

// PrevMatch moves to the previous search match
func (h *HelpView) PrevMatch() {
	if len(h.searchMatches) == 0 {
		return
	}
	h.currentMatch = (h.currentMatch - 1 + len(h.searchMatches)) % len(h.searchMatches)
	h.scrollToMatch()
}

// GetMatchInfo returns current match info (current, total)
func (h *HelpView) GetMatchInfo() (int, int) {
	if len(h.searchMatches) == 0 {
		return 0, 0
	}
	return h.currentMatch + 1, len(h.searchMatches)
}

// Update handles viewport messages for scrolling
func (h *HelpView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd
	h.viewport, cmd = h.viewport.Update(msg)
	return cmd
}

// View renders the help view
func (h *HelpView) View() string {
	if !h.ready {
		return ""
	}

	// Build the view with section tabs at top
	var result strings.Builder

	// Section tabs
	result.WriteString(h.renderSectionTabs())
	result.WriteString("\n")

	// Viewport content
	result.WriteString(h.viewport.View())

	return result.String()
}

// clearSearch clears search state
func (h *HelpView) clearSearch() {
	h.searchMode = false
	h.searchQuery = ""
	h.searchMatches = nil
	h.currentMatch = 0
}

// loadSection loads and renders the specified help section
func (h *HelpView) loadSection(section HelpSection) {
	var filename string
	switch section {
	case SectionKeybindings:
		filename = "keybindings.md"
	case SectionCommands:
		filename = "commands.md"
	case SectionWorkflows:
		filename = "workflows.md"
	}

	content, err := help.Files.ReadFile(filename)
	if err != nil {
		h.rawContent = "Error loading help: " + err.Error()
		h.renderedContent = h.rawContent
		h.viewport.SetContent(h.renderedContent)
		return
	}

	h.rawContent = string(content)
	h.renderMarkdown()
}

// renderMarkdown renders the raw markdown content using glamour
func (h *HelpView) renderMarkdown() {
	// Create glamour renderer with dark theme
	renderer, err := glamour.NewTermRenderer(
		glamour.WithAutoStyle(),
		glamour.WithWordWrap(h.width-4), // Leave some margin
	)
	if err != nil {
		h.renderedContent = h.rawContent
		h.viewport.SetContent(h.renderedContent)
		return
	}

	rendered, err := renderer.Render(h.rawContent)
	if err != nil {
		h.renderedContent = h.rawContent
		h.viewport.SetContent(h.renderedContent)
		return
	}

	h.renderedContent = rendered
	h.viewport.SetContent(h.renderedContent)
}

// performSearch searches for the query in rendered content
func (h *HelpView) performSearch() {
	h.searchMatches = nil
	h.currentMatch = 0

	if h.searchQuery == "" {
		return
	}

	query := strings.ToLower(h.searchQuery)
	lines := strings.Split(h.renderedContent, "\n")

	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), query) {
			h.searchMatches = append(h.searchMatches, i)
		}
	}

	if len(h.searchMatches) > 0 {
		h.scrollToMatch()
	}
}

// scrollToMatch scrolls the viewport to the current match
func (h *HelpView) scrollToMatch() {
	if len(h.searchMatches) == 0 {
		return
	}
	lineNum := h.searchMatches[h.currentMatch]
	// Center the match in the viewport
	targetLine := lineNum - h.viewport.Height/2
	if targetLine < 0 {
		targetLine = 0
	}
	h.viewport.SetYOffset(targetLine)
}

// renderSectionTabs renders the section navigation tabs
func (h *HelpView) renderSectionTabs() string {
	sections := []struct {
		key   string
		label string
	}{
		{"1", "Keybindings"},
		{"2", "Commands"},
		{"3", "Workflows"},
	}

	activeStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(h.theme.Foreground).
		Background(h.theme.InfoColor).
		Padding(0, 2)

	inactiveStyle := lipgloss.NewStyle().
		Foreground(h.theme.StatusBarFg).
		Padding(0, 2)

	keyStyle := lipgloss.NewStyle().
		Foreground(h.theme.WarningColor).
		Bold(true)

	var tabs []string
	for i, sec := range sections {
		style := inactiveStyle
		if HelpSection(i) == h.activeSection {
			style = activeStyle
		}
		tab := keyStyle.Render(sec.key) + " " + style.Render(sec.label)
		tabs = append(tabs, tab)
	}

	return strings.Join(tabs, "  ")
}
