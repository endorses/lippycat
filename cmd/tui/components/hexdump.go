package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HexDumpView displays a hex/ASCII dump of packet data
type HexDumpView struct {
	viewport viewport.Model
	data     []byte
	width    int
	height   int
	theme    themes.Theme
	ready    bool
	cursor   int // Current line cursor for highlighting
}

// NewHexDumpView creates a new hex dump view
func NewHexDumpView() HexDumpView {
	return HexDumpView{
		width:  40,
		height: 20,
		theme:  themes.Solarized(),
		ready:  false,
		cursor: 0,
	}
}

// SetTheme updates the theme
func (h *HexDumpView) SetTheme(theme themes.Theme) {
	h.theme = theme
}

// SetData sets the data to display
func (h *HexDumpView) SetData(data []byte) {
	h.data = data
	h.cursor = 0 // Reset cursor when data changes
	if h.ready {
		h.viewport.SetContent(h.renderContent())
		h.viewport.GotoTop()
	}
}

// SetSize sets the display size
func (h *HexDumpView) SetSize(width, height int) {
	h.width = width
	h.height = height

	// Account for border (2), padding (2), and title + spacing (3)
	viewportHeight := height - 7
	if viewportHeight < 5 {
		viewportHeight = 5
	}

	if !h.ready {
		h.viewport = viewport.New(width-4, viewportHeight)
		h.ready = true
		if h.data != nil {
			h.viewport.SetContent(h.renderContent())
		}
	} else {
		h.viewport.Width = width - 4
		h.viewport.Height = viewportHeight
	}
}

// Update handles viewport messages for scrolling
func (h *HexDumpView) Update(msg tea.Msg) tea.Cmd {
	if !h.ready {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if h.cursor > 0 {
				h.cursor--
				h.viewport.LineUp(1)
			}
			return nil
		case "down", "j":
			maxLines := (len(h.data) + 15) / 16
			if h.cursor < maxLines-1 {
				h.cursor++
				h.viewport.LineDown(1)
			}
			return nil
		case "pgup":
			h.cursor -= h.viewport.Height
			if h.cursor < 0 {
				h.cursor = 0
			}
			h.viewport.SetContent(h.renderContent())
			return nil
		case "pgdown":
			maxLines := (len(h.data) + 15) / 16
			h.cursor += h.viewport.Height
			if h.cursor >= maxLines {
				h.cursor = maxLines - 1
			}
			h.viewport.SetContent(h.renderContent())
			return nil
		case "home":
			h.cursor = 0
			h.viewport.GotoTop()
			return nil
		case "end":
			maxLines := (len(h.data) + 15) / 16
			h.cursor = maxLines - 1
			h.viewport.GotoBottom()
			return nil
		}
	}

	var cmd tea.Cmd
	h.viewport, cmd = h.viewport.Update(msg)
	return cmd
}

// View renders the hex dump view
func (h *HexDumpView) View(focused bool) string {
	if !h.ready {
		return ""
	}

	borderColor := h.theme.BorderColor
	if focused {
		borderColor = h.theme.InfoColor // Solarized blue when focused
	}

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(h.width - 4)

	if h.data == nil || len(h.data) == 0 {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center)
		content := emptyStyle.Render("No packet data")
		return borderStyle.Render(content)
	}

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(h.theme.InfoColor)

	title := titleStyle.Render(fmt.Sprintf("Hex Dump (%d bytes)", len(h.data)))

	return borderStyle.Render(title + "\n\n" + h.viewport.View())
}

// renderContent generates the hex dump content
func (h *HexDumpView) renderContent() string {
	if h.data == nil || len(h.data) == 0 {
		return ""
	}

	var sb strings.Builder

	// Style for hex bytes
	hexStyle := lipgloss.NewStyle().Foreground(h.theme.Foreground)
	// Style for ASCII
	asciiStyle := lipgloss.NewStyle().Foreground(h.theme.SuccessColor)
	// Style for offset
	offsetStyle := lipgloss.NewStyle().Foreground(h.theme.HeaderFg).Bold(true)
	// Style for selected line
	selectedStyle := lipgloss.NewStyle().
		Foreground(h.theme.SelectionBg).
		Reverse(true).
		Bold(true)

	lineNum := 0
	for offset := 0; offset < len(h.data); offset += 16 {
		isSelected := lineNum == h.cursor

		// Offset column
		if isSelected {
			sb.WriteString(selectedStyle.Render(fmt.Sprintf("%04x", offset)))
		} else {
			sb.WriteString(offsetStyle.Render(fmt.Sprintf("%04x", offset)))
		}
		sb.WriteString("  ")

		// Hex column (16 bytes per line)
		hexPart := ""
		asciiPart := ""
		for i := 0; i < 16; i++ {
			if offset+i < len(h.data) {
				b := h.data[offset+i]
				hexPart += fmt.Sprintf("%02x ", b)

				// ASCII representation
				if b >= 32 && b <= 126 {
					asciiPart += string(b)
				} else {
					asciiPart += "."
				}
			} else {
				hexPart += "   "
				asciiPart += " "
			}

			// Add extra space after 8 bytes for readability
			if i == 7 {
				hexPart += " "
			}
		}

		if isSelected {
			sb.WriteString(selectedStyle.Render(hexPart))
			sb.WriteString(" ")
			sb.WriteString(selectedStyle.Render(asciiPart))
		} else {
			sb.WriteString(hexStyle.Render(hexPart))
			sb.WriteString(" ")
			sb.WriteString(asciiStyle.Render(asciiPart))
		}

		sb.WriteString("\n")
		lineNum++
	}

	return sb.String()
}
