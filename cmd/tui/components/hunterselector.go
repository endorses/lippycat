//go:build tui || all
// +build tui all

package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HunterSelectorItem represents a hunter available for subscription
type HunterSelectorItem struct {
	HunterID   string
	Hostname   string
	Interfaces []string
	Status     management.HunterStatus
	RemoteAddr string
	Selected   bool // Whether this hunter is currently selected for subscription
}

// HunterSelector provides a UI for selecting which hunters to subscribe to
type HunterSelector struct {
	hunters       []HunterSelectorItem
	cursorIndex   int  // Current cursor position
	active        bool // Whether modal is visible
	loading       bool // Whether we're loading hunter list
	processorAddr string
	theme         themes.Theme
	width         int
	height        int
}

// NewHunterSelector creates a new hunter selector
func NewHunterSelector() HunterSelector {
	return HunterSelector{
		hunters:     []HunterSelectorItem{},
		cursorIndex: 0,
		active:      false,
		loading:     false,
		theme:       themes.Solarized(),
	}
}

// SetTheme sets the color theme
func (hs *HunterSelector) SetTheme(theme themes.Theme) {
	hs.theme = theme
}

// SetSize sets the dimensions
func (hs *HunterSelector) SetSize(width, height int) {
	hs.width = width
	hs.height = height
}

// Activate shows the hunter selector and starts loading hunters
func (hs *HunterSelector) Activate(processorAddr string) {
	hs.active = true
	hs.loading = true
	hs.processorAddr = processorAddr
}

// Deactivate hides the hunter selector
func (hs *HunterSelector) Deactivate() {
	hs.active = false
	hs.loading = false
}

// IsActive returns whether the selector is visible
func (hs *HunterSelector) IsActive() bool {
	return hs.active
}

// SetHunters updates the list of available hunters (called when list is loaded)
func (hs *HunterSelector) SetHunters(hunters []HunterSelectorItem) {
	hs.hunters = hunters
	hs.loading = false
	// Reset cursor if out of bounds
	if hs.cursorIndex >= len(hs.hunters) {
		hs.cursorIndex = 0
	}
}

// GetSelectedHunterIDs returns the list of hunter IDs that are selected
func (hs *HunterSelector) GetSelectedHunterIDs() []string {
	selected := make([]string, 0)
	for _, hunter := range hs.hunters {
		if hunter.Selected {
			selected = append(selected, hunter.HunterID)
		}
	}
	return selected
}

// Update handles key events
func (hs *HunterSelector) Update(msg tea.Msg) tea.Cmd {
	if !hs.active {
		return nil
	}

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if hs.cursorIndex > 0 {
				hs.cursorIndex--
			}
		case "down", "j":
			if hs.cursorIndex < len(hs.hunters)-1 {
				hs.cursorIndex++
			}
		case " ": // Space to toggle selection
			if hs.cursorIndex >= 0 && hs.cursorIndex < len(hs.hunters) {
				hs.hunters[hs.cursorIndex].Selected = !hs.hunters[hs.cursorIndex].Selected
			}
		case "a": // Select all
			for i := range hs.hunters {
				hs.hunters[i].Selected = true
			}
		case "n": // Select none
			for i := range hs.hunters {
				hs.hunters[i].Selected = false
			}
		case "enter":
			// Confirm selection and close
			hs.Deactivate()
			return func() tea.Msg {
				return HunterSelectionConfirmedMsg{
					ProcessorAddr:     hs.processorAddr,
					SelectedHunterIDs: hs.GetSelectedHunterIDs(),
				}
			}
		case "esc":
			// Cancel selection
			hs.Deactivate()
		}
	}

	return nil
}

// View renders the hunter selector
func (hs *HunterSelector) View() string {
	if !hs.active {
		return ""
	}

	// Modal dimensions
	modalWidth := 80
	if modalWidth > hs.width-4 {
		modalWidth = hs.width - 4
	}
	if modalWidth < 60 {
		modalWidth = 60
	}

	// Modal styles
	titleStyle := lipgloss.NewStyle().
		Foreground(hs.theme.HeaderBg).
		Bold(true).
		Padding(0, 1).
		Width(modalWidth - 4)

	itemStyle := lipgloss.NewStyle().
		Foreground(hs.theme.Foreground).
		Padding(0, 1).
		Width(modalWidth - 4)

	selectedStyle := lipgloss.NewStyle().
		Foreground(hs.theme.SelectionFg).
		Background(hs.theme.SelectionBg).
		Bold(true).
		Padding(0, 1).
		Width(modalWidth - 4)

	descStyle := lipgloss.NewStyle().
		Foreground(hs.theme.StatusBarFg).
		Italic(true).
		Width(modalWidth - 4)

	modalStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(hs.theme.InfoColor).
		Padding(1, 2).
		Width(modalWidth)

	// Build content
	var content strings.Builder
	content.WriteString(titleStyle.Render("Select Hunters to Subscribe"))
	content.WriteString("\n\n")

	if hs.loading {
		content.WriteString(itemStyle.Render("Loading hunters..."))
	} else if len(hs.hunters) == 0 {
		content.WriteString(descStyle.Render("No hunters available on this processor."))
	} else {
		for i, hunter := range hs.hunters {
			// Checkbox indicator
			checkbox := "[ ] "
			if hunter.Selected {
				checkbox = "[✓] "
			}

			// Status icon - only apply color if NOT cursor-selected (to avoid breaking background)
			var statusIcon string
			if i == hs.cursorIndex {
				// When selected, use plain icon without color styling
				statusIcon = "●"
			} else {
				// When not selected, apply status color
				switch hunter.Status {
				case management.HunterStatus_STATUS_HEALTHY:
					statusIcon = lipgloss.NewStyle().Foreground(hs.theme.SuccessColor).Render("●")
				case management.HunterStatus_STATUS_WARNING:
					statusIcon = lipgloss.NewStyle().Foreground(hs.theme.WarningColor).Render("●")
				case management.HunterStatus_STATUS_ERROR:
					statusIcon = lipgloss.NewStyle().Foreground(hs.theme.ErrorColor).Render("●")
				default:
					statusIcon = lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Render("●")
				}
			}

			// Build single-line display: [✓] ● hunter-id (hostname)
			// Keep it simple and on one line
			line := checkbox + statusIcon + " " + hunter.HunterID
			if hunter.Hostname != "" && hunter.Hostname != hunter.RemoteAddr {
				line += " (" + hunter.Hostname + ")"
			} else if hunter.RemoteAddr != "" {
				line += " (" + hunter.RemoteAddr + ")"
			}

			// Apply cursor style
			if i == hs.cursorIndex {
				content.WriteString(selectedStyle.Render(line))
				// Show interfaces on separate line when cursor is on this item
				if len(hunter.Interfaces) > 0 {
					content.WriteString("\n")
					interfacesStr := "  Interfaces: " + strings.Join(hunter.Interfaces, ", ")
					content.WriteString(descStyle.Render(interfacesStr))
				}
			} else {
				content.WriteString(itemStyle.Render(line))
			}
			content.WriteString("\n")
		}
	}

	content.WriteString("\n")
	content.WriteString(descStyle.Render("↑/↓: Navigate  Space: Toggle  a: All  n: None  Enter: Confirm  Esc: Cancel"))

	return modalStyle.Render(content.String())
}

// HunterSelectionConfirmedMsg is sent when user confirms hunter selection
type HunterSelectionConfirmedMsg struct {
	ProcessorAddr     string
	SelectedHunterIDs []string
}

// LoadHuntersFromProcessorMsg is sent to request loading hunters from a processor
type LoadHuntersFromProcessorMsg struct {
	ProcessorAddr string
}

// HuntersLoadedMsg is sent when hunters are loaded from processor
type HuntersLoadedMsg struct {
	ProcessorAddr string
	Hunters       []HunterSelectorItem
}
