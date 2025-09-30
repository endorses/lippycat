package components

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// FilterInput is a simple text input for filters
type FilterInput struct {
	value      string
	cursor     int
	prompt     string // "/" for filter, "?" for search
	theme      themes.Theme
	width      int
	active     bool
	history    []string
	historyIdx int
}

// NewFilterInput creates a new filter input
func NewFilterInput(prompt string) FilterInput {
	return FilterInput{
		value:      "",
		cursor:     0,
		prompt:     prompt,
		theme:      themes.SolarizedDark(),
		width:      80,
		active:     false,
		history:    make([]string, 0, 20),
		historyIdx: -1,
	}
}

// SetTheme updates the theme
func (f *FilterInput) SetTheme(theme themes.Theme) {
	f.theme = theme
}

// SetWidth sets the input width
func (f *FilterInput) SetWidth(width int) {
	f.width = width
}

// Activate shows the input
func (f *FilterInput) Activate() {
	f.active = true
	f.historyIdx = -1
}

// Deactivate hides the input
func (f *FilterInput) Deactivate() {
	f.active = false
}

// IsActive returns whether the input is active
func (f *FilterInput) IsActive() bool {
	return f.active
}

// Value returns the current input value
func (f *FilterInput) Value() string {
	return f.value
}

// Clear clears the input
func (f *FilterInput) Clear() {
	f.value = ""
	f.cursor = 0
}

// AddToHistory adds a value to history
func (f *FilterInput) AddToHistory(value string) {
	if value == "" {
		return
	}
	// Avoid duplicates
	for i, h := range f.history {
		if h == value {
			// Move to front
			f.history = append(f.history[:i], f.history[i+1:]...)
			break
		}
	}
	f.history = append([]string{value}, f.history...)
	// Keep last 20
	if len(f.history) > 20 {
		f.history = f.history[:20]
	}
}

// HistoryUp navigates up in history
func (f *FilterInput) HistoryUp() {
	if len(f.history) == 0 {
		return
	}
	if f.historyIdx < len(f.history)-1 {
		f.historyIdx++
		f.value = f.history[f.historyIdx]
		f.cursor = len(f.value)
	}
}

// HistoryDown navigates down in history
func (f *FilterInput) HistoryDown() {
	if f.historyIdx > 0 {
		f.historyIdx--
		f.value = f.history[f.historyIdx]
		f.cursor = len(f.value)
	} else if f.historyIdx == 0 {
		f.historyIdx = -1
		f.value = ""
		f.cursor = 0
	}
}

// InsertRune inserts a character at cursor
func (f *FilterInput) InsertRune(r rune) {
	f.value = f.value[:f.cursor] + string(r) + f.value[f.cursor:]
	f.cursor++
}

// Backspace deletes the character before cursor
func (f *FilterInput) Backspace() {
	if f.cursor > 0 {
		f.value = f.value[:f.cursor-1] + f.value[f.cursor:]
		f.cursor--
	}
}

// Delete deletes the character at cursor
func (f *FilterInput) Delete() {
	if f.cursor < len(f.value) {
		f.value = f.value[:f.cursor] + f.value[f.cursor+1:]
	}
}

// CursorLeft moves cursor left
func (f *FilterInput) CursorLeft() {
	if f.cursor > 0 {
		f.cursor--
	}
}

// CursorRight moves cursor right
func (f *FilterInput) CursorRight() {
	if f.cursor < len(f.value) {
		f.cursor++
	}
}

// CursorHome moves cursor to start
func (f *FilterInput) CursorHome() {
	f.cursor = 0
}

// CursorEnd moves cursor to end
func (f *FilterInput) CursorEnd() {
	f.cursor = len(f.value)
}

// View renders the filter input
func (f *FilterInput) View() string {
	if !f.active {
		return ""
	}

	// Focus-aware border style
	borderStyle := lipgloss.RoundedBorder()
	borderColor := f.theme.InfoColor

	containerStyle := lipgloss.NewStyle().
		Border(borderStyle).
		BorderForeground(borderColor).
		Padding(0, 1).
		Width(f.width - 4)

	inputStyle := lipgloss.NewStyle().
		Foreground(f.theme.Foreground).
		Background(f.theme.Background)

	promptStyle := lipgloss.NewStyle().
		Foreground(f.theme.InfoColor).
		Bold(true)

	// Build the input line with cursor
	displayValue := f.value
	cursorStyle := lipgloss.NewStyle().
		Foreground(f.theme.SelectionFg).
		Background(f.theme.InfoColor)

	if f.cursor < len(f.value) {
		// Show cursor in the middle of text
		before := f.value[:f.cursor]
		at := string(f.value[f.cursor])
		after := ""
		if f.cursor+1 < len(f.value) {
			after = f.value[f.cursor+1:]
		}
		displayValue = before + cursorStyle.Render(at) + after
	} else {
		// Show cursor at end
		displayValue = f.value + cursorStyle.Render(" ")
	}

	input := promptStyle.Render(f.prompt) + " " + inputStyle.Render(displayValue)

	return containerStyle.Render(input)
}