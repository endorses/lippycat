//go:build tui || all

package components

import (
	"fmt"
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

// SetSize sets the display size and returns a command if content needs re-rendering
func (h *HelpView) SetSize(width, height int) tea.Cmd {
	widthChanged := h.width != width
	h.width = width
	h.height = height

	if !h.ready {
		h.viewport = viewport.New(width, height-1)
		h.ready = true
		// Don't load content here - use LoadContentAsync() to avoid blocking
		return nil
	}

	h.viewport.Width = width
	h.viewport.Height = height - 1

	// Re-render content when width changes (glamour word-wrap depends on width)
	if widthChanged && h.contentLoaded {
		return h.LoadContentAsync()
	}
	return nil
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

// ExitSearchMode exits search mode but keeps search results for n/N navigation
func (h *HelpView) ExitSearchMode() {
	h.searchMode = false
	// Keep searchQuery, searchMatches, currentMatch so n/N still work
	// Keep highlights in viewport
}

// ClearSearch fully clears search state and highlights
func (h *HelpView) ClearSearch() {
	h.searchMode = false
	h.searchQuery = ""
	h.searchMatches = nil
	h.currentMatch = 0
	h.viewport.SetContent(h.renderedContent)
}

// GetSearchQuery returns the current search query
func (h *HelpView) GetSearchQuery() string {
	return h.searchQuery
}

// HasActiveSearch returns true if there's an active search with results
func (h *HelpView) HasActiveSearch() bool {
	return h.searchQuery != "" && len(h.searchMatches) > 0
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
	h.viewport.SetContent(h.highlightMatches(h.renderedContent))
	h.scrollToMatch()
}

// PrevMatch moves to the previous search match
func (h *HelpView) PrevMatch() {
	if len(h.searchMatches) == 0 {
		return
	}
	h.currentMatch = (h.currentMatch - 1 + len(h.searchMatches)) % len(h.searchMatches)
	h.viewport.SetContent(h.highlightMatches(h.renderedContent))
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

	// Section tabs (or search bar if in search mode)
	if h.searchMode {
		result.WriteString(h.renderSearchBar())
	} else {
		result.WriteString(h.renderSectionTabs())
	}
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

// renderSearchBar renders the search input bar
func (h *HelpView) renderSearchBar() string {
	promptStyle := lipgloss.NewStyle().
		Foreground(h.theme.WarningColor).
		Bold(true)

	queryStyle := lipgloss.NewStyle().
		Foreground(h.theme.Foreground)

	matchStyle := lipgloss.NewStyle().
		Foreground(h.theme.BorderColor)

	prompt := promptStyle.Render("/")
	query := queryStyle.Render(h.searchQuery)
	cursor := queryStyle.Render("▏")

	var matchInfo string
	current, total := h.GetMatchInfo()
	if total > 0 {
		matchInfo = matchStyle.Render(fmt.Sprintf(" [%d/%d]", current, total))
	} else if h.searchQuery != "" {
		matchInfo = matchStyle.Render(" [no matches]")
	}

	return prompt + query + cursor + matchInfo
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
		// Restore unhighlighted content
		h.viewport.SetContent(h.renderedContent)
		return
	}

	query := strings.ToLower(h.searchQuery)
	lines := strings.Split(h.renderedContent, "\n")

	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), query) {
			h.searchMatches = append(h.searchMatches, i)
		}
	}

	// Apply highlighting to viewport
	h.viewport.SetContent(h.highlightMatches(h.renderedContent))

	if len(h.searchMatches) > 0 {
		h.scrollToMatch()
	}
}

// highlightMatches wraps search matches with highlighting
// Current match uses red background with bright text, other matches use reverse video
func (h *HelpView) highlightMatches(content string) string {
	if h.searchQuery == "" {
		return content
	}

	query := strings.ToLower(h.searchQuery)
	queryLen := len(h.searchQuery)

	// Get current match line number
	var currentLine int
	if len(h.searchMatches) > 0 {
		currentLine = h.searchMatches[h.currentMatch]
	} else {
		currentLine = -1
	}

	// Solarized colors for current match: red background (#dc322f), bright text (#fdf6e3)
	// Using 256-color mode: red=160 approximates #dc322f, white=230 approximates #fdf6e3
	// Or use true color: \x1b[48;2;220;50;47m for bg, \x1b[38;2;253;246;227m for fg
	currentStart := "\x1b[48;2;220;50;47m\x1b[38;2;253;246;227m\x1b[1m" // Red bg, bright fg, bold
	currentEnd := "\x1b[0m"                                             // Reset all

	// Other matches: reverse video
	otherStart := "\x1b[7m" // Reverse video on
	otherEnd := "\x1b[27m"  // Reverse video off

	// Process line by line to track which line we're on
	lines := strings.Split(content, "\n")
	for lineNum, line := range lines {
		lowerLine := strings.ToLower(line)
		if !strings.Contains(lowerLine, query) {
			continue
		}

		// Determine highlight style based on whether this is the current match line
		var highlightStart, highlightEnd string
		if lineNum == currentLine {
			highlightStart = currentStart
			highlightEnd = currentEnd
		} else {
			highlightStart = otherStart
			highlightEnd = otherEnd
		}

		// Replace all occurrences in this line
		var newLine strings.Builder
		lastEnd := 0
		for {
			idx := strings.Index(lowerLine[lastEnd:], query)
			if idx == -1 {
				newLine.WriteString(line[lastEnd:])
				break
			}

			matchStart := lastEnd + idx
			matchEnd := matchStart + queryLen

			newLine.WriteString(line[lastEnd:matchStart])
			newLine.WriteString(highlightStart)
			newLine.WriteString(line[matchStart:matchEnd])
			newLine.WriteString(highlightEnd)

			lastEnd = matchEnd
		}
		lines[lineNum] = newLine.String()
	}

	return strings.Join(lines, "\n")
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
