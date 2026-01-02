//go:build tui || all
// +build tui all

package components

import (
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/glamour"
	"github.com/charmbracelet/glamour/ansi"
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
	contentLoaded   bool // True once content has been loaded
}

// HelpContentLoadedMsg is sent when help content finishes loading
type HelpContentLoadedMsg struct {
	Section         HelpSection
	RawContent      string
	RenderedContent string
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
		h.viewport = viewport.New(width, height-1)
		h.ready = true
		// Don't load content here - use LoadContentAsync() to avoid blocking
	} else {
		h.viewport.Width = width
		h.viewport.Height = height - 1
	}
}

// NeedsContentLoad returns true if content needs to be loaded
func (h *HelpView) NeedsContentLoad() bool {
	return h.ready && !h.contentLoaded
}

// LoadContentAsync returns a command that loads content asynchronously
func (h *HelpView) LoadContentAsync() tea.Cmd {
	section := h.activeSection
	width := h.width
	return func() tea.Msg {
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
			return HelpContentLoadedMsg{
				Section:         section,
				RawContent:      "Error loading help: " + err.Error(),
				RenderedContent: "Error loading help: " + err.Error(),
			}
		}

		rawContent := string(content)

		// Render markdown with glamour using Solarized colors
		renderer, err := glamour.NewTermRenderer(
			glamour.WithStyles(solarizedGlamourStyle()),
			glamour.WithWordWrap(width-4),
		)
		var renderedContent string
		if err != nil {
			renderedContent = rawContent
		} else {
			rendered, err := renderer.Render(rawContent)
			if err != nil {
				renderedContent = rawContent
			} else {
				renderedContent = rendered
			}
		}

		return HelpContentLoadedMsg{
			Section:         section,
			RawContent:      rawContent,
			RenderedContent: renderedContent,
		}
	}
}

// HandleContentLoaded processes the loaded content
func (h *HelpView) HandleContentLoaded(msg HelpContentLoadedMsg) {
	// Only apply if it's for the current section
	if msg.Section == h.activeSection {
		h.rawContent = msg.RawContent
		h.renderedContent = msg.RenderedContent
		h.viewport.SetContent(h.renderedContent)
		h.contentLoaded = true
	}
}

// GetActiveSection returns the current section
func (h *HelpView) GetActiveSection() HelpSection {
	return h.activeSection
}

// SetSection changes the active section and returns a command to load content
func (h *HelpView) SetSection(section HelpSection) tea.Cmd {
	if section != h.activeSection {
		h.activeSection = section
		h.clearSearch()
		h.contentLoaded = false // Mark for reload
		if h.ready {
			return h.LoadContentAsync()
		}
	}
	return nil
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

	// Show loading message or content (must match viewport height exactly)
	if !h.contentLoaded {
		loadingStyle := lipgloss.NewStyle().
			Foreground(h.theme.BorderColor).
			Italic(true).
			Width(h.width).
			Height(h.viewport.Height)
		result.WriteString(loadingStyle.Render("Loading help content..."))
	} else {
		result.WriteString(h.viewport.View())
	}

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
	// Create glamour renderer with Solarized colors
	renderer, err := glamour.NewTermRenderer(
		glamour.WithStyles(solarizedGlamourStyle()),
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
		Foreground(h.theme.CursorFg). // Bright (Base3) for contrast
		Background(h.theme.TLSColor). // Magenta
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

// solarizedGlamourStyle creates a glamour style using Solarized colors
// with transparent background to respect the terminal's own background
func solarizedGlamourStyle() ansi.StyleConfig {
	// Helper functions for creating pointers
	strPtr := func(s string) *string { return &s }
	boolPtr := func(b bool) *bool { return &b }
	uintPtr := func(u uint) *uint { return &u }

	// Solarized colors as hex strings
	base0 := "#839496"  // body text
	base1 := "#93a1a1"  // emphasized content
	base01 := "#586e75" // comments / secondary
	blue := "#268bd2"   // links, headings
	cyan := "#2aa198"   // code
	yellow := "#b58900" // warnings
	orange := "#cb4b16" // strong
	green := "#859900"  // lists

	return ansi.StyleConfig{
		Document: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: strPtr(base0),
			},
			Margin: uintPtr(0),
		},
		Heading: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: strPtr(blue),
				Bold:  boolPtr(true),
			},
		},
		H1: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  strPtr(blue),
				Bold:   boolPtr(true),
				Prefix: "# ",
			},
		},
		H2: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  strPtr(blue),
				Bold:   boolPtr(true),
				Prefix: "## ",
			},
		},
		H3: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  strPtr(cyan),
				Bold:   boolPtr(true),
				Prefix: "### ",
			},
		},
		H4: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  strPtr(cyan),
				Bold:   boolPtr(true),
				Prefix: "#### ",
			},
		},
		H5: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: strPtr(base1),
				Bold:  boolPtr(true),
			},
		},
		H6: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: strPtr(base1),
				Bold:  boolPtr(true),
			},
		},
		Text: ansi.StylePrimitive{
			Color: strPtr(base0),
		},
		Emph: ansi.StylePrimitive{
			Color:  strPtr(base1),
			Italic: boolPtr(true),
		},
		Strong: ansi.StylePrimitive{
			Color: strPtr(orange),
			Bold:  boolPtr(true),
		},
		BlockQuote: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color:  strPtr(base01),
				Italic: boolPtr(true),
			},
			Indent: uintPtr(2),
		},
		Code: ansi.StyleBlock{
			StylePrimitive: ansi.StylePrimitive{
				Color: strPtr(yellow),
			},
		},
		CodeBlock: ansi.StyleCodeBlock{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: strPtr(yellow),
				},
				Margin: uintPtr(1),
			},
		},
		Link: ansi.StylePrimitive{
			Color:     strPtr(blue),
			Underline: boolPtr(true),
		},
		LinkText: ansi.StylePrimitive{
			Color: strPtr(blue),
		},
		List: ansi.StyleList{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: strPtr(base0),
				},
			},
			LevelIndent: 3,
		},
		Item: ansi.StylePrimitive{
			Color:       strPtr(base0),
			BlockPrefix: "• ",
		},
		Enumeration: ansi.StylePrimitive{
			Color:       strPtr(green),
			BlockSuffix: ". ",
		},
		Task: ansi.StyleTask{
			Ticked:   "[✓] ",
			Unticked: "[ ] ",
		},
		HorizontalRule: ansi.StylePrimitive{
			Color:  strPtr(base01),
			Format: "───────────────────────────────────────────────",
		},
		Table: ansi.StyleTable{
			StyleBlock: ansi.StyleBlock{
				StylePrimitive: ansi.StylePrimitive{
					Color: strPtr(base0),
				},
			},
			CenterSeparator: strPtr("┼"),
			ColumnSeparator: strPtr("│"),
			RowSeparator:    strPtr("─"),
		},
		DefinitionTerm: ansi.StylePrimitive{
			Color: strPtr(yellow),
			Bold:  boolPtr(true),
		},
		DefinitionDescription: ansi.StylePrimitive{
			Color: strPtr(base0),
		},
	}
}
