//go:build tui || all

package components

import (
	"image"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// ButtonKind describes an action's visual emphasis, independently of focus.
type ButtonKind int

const (
	ButtonNormal ButtonKind = iota
	ButtonPrimary
	ButtonDanger
)

// ModalAction is an explicit action, not a parsed keyboard hint.
type ModalAction struct {
	ID, Label, Shortcut string
	Keys                []string // Additional contextual keyboard aliases.
	Disabled            bool
	Kind                ButtonKind
}

// ModalTarget identifies content cells. Bounds use unwrapped content coordinates.
// Focusable targets participate in Tab traversal; row targets can remain mouse-only.
type ModalTarget struct {
	ID                  string
	Bounds              image.Rectangle
	Focusable, Disabled bool
}

// ModalState owns interaction state. Rendering only reads this state.
type ModalState struct {
	Focus         string
	Scroll        int
	context       string
	clickID       string
	clickTime     time.Time
	width, height int
}

func (s *ModalState) Reset()       { *s = ModalState{} }
func (s *ModalState) ResetClicks() { s.clickID = ""; s.clickTime = time.Time{} }

// DoubleClick requires two presses on the same stable target. Callers reset it
// when the list identity or selection context changes.
func (s *ModalState) DoubleClick(id string, now time.Time) bool {
	double := id != "" && id == s.clickID && !s.clickTime.IsZero() && !now.Before(s.clickTime) && now.Sub(s.clickTime) <= 400*time.Millisecond
	s.clickID, s.clickTime = id, now
	if double {
		s.ResetClicks()
	}
	return double
}

type actionBarLayout struct {
	lines []string
	hits  []ModalTarget
}

func layoutActionBar(actions []ModalAction, focus string, width int, theme themes.Theme) actionBarLayout {
	var layout actionBarLayout
	if width < 5 {
		return layout
	}
	line, x, y := "", 0, 0
	for _, action := range actions {
		label := action.Label
		if action.Shortcut != "" && ansi.StringWidth(label+" · "+action.Shortcut)+4 <= width {
			label += " · " + action.Shortcut
		}
		label = ansi.Truncate(label, width-4, "…")
		// Filled surfaces include the padding in both rendering and hit testing.
		// Keep every state the same size so focusing a button cannot move it.
		left, right := "  ", "  "
		style := lipgloss.NewStyle().Background(theme.BorderColor).Foreground(theme.Background)
		if action.Kind == ButtonPrimary {
			style = style.Background(theme.InfoColor).Bold(true)
		}
		if action.Kind == ButtonDanger {
			style = style.Background(theme.ErrorColor).Bold(true)
		}
		if action.Disabled {
			style = lipgloss.NewStyle().Background(theme.StatusBarBg).Foreground(theme.StatusBarFg).Strikethrough(true)
		} else if action.ID == focus {
			left = "▸ "
			style = style.Background(theme.SelectionBg).Foreground(theme.SelectionFg).Bold(true).Underline(true)
		}
		text := left + label + right
		cells := ansi.StringWidth(text)
		if x > 0 && x+1+cells > width {
			layout.lines = append(layout.lines, line, "")
			line, x = "", 0
			y += 2
		}
		if x > 0 {
			line += " "
			x++
		}
		layout.hits = append(layout.hits, ModalTarget{ID: action.ID, Bounds: image.Rect(x, y, x+cells, y+1), Focusable: true, Disabled: action.Disabled})
		line += style.Render(text)
		x += cells
	}
	if line != "" {
		layout.lines = append(layout.lines, line)
	}
	return layout
}

func fitModalLine(text string, width int) string {
	text = ansi.Truncate(text, max(0, width), "")
	return text + strings.Repeat(" ", max(0, width-ansi.StringWidth(text)))
}
