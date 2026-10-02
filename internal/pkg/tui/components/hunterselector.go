//go:build tui || all

package components

import (
	"github.com/charmbracelet/x/ansi"
	"image"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// HunterSelectorItem represents a hunter available for subscription
type HunterSelectorItem struct {
	HunterID     string
	Hostname     string
	Interfaces   []string
	Status       management.HunterStatus
	RemoteAddr   string
	Selected     bool // Whether this hunter is currently selected for subscription
	Capabilities *management.HunterCapabilities
}

// HunterSelector provides a UI for selecting which hunters to subscribe to
type HunterSelector struct {
	modalState    ModalState
	rowOffset     int
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
	hs.keepSelectedVisible()
}

// Activate shows the hunter selector and starts loading hunters
func (hs *HunterSelector) Activate(processorAddr string) {
	hs.modalState.Reset()
	hs.rowOffset = 0
	hs.active = true
	hs.loading = true
	hs.processorAddr = processorAddr
}

// Deactivate hides the hunter selector
func (hs *HunterSelector) Deactivate() {
	hs.active = false
	hs.loading = false
}

// Dismiss closes the modal without applying the hunter selection.
func (hs *HunterSelector) Dismiss() tea.Cmd {
	hs.Deactivate()
	return nil
}

// IsActive returns whether the selector is visible
func (hs *HunterSelector) IsActive() bool {
	return hs.active
}

// SetHunters updates the list of available hunters (called when list is loaded)
func (hs *HunterSelector) SetHunters(hunters []HunterSelectorItem) {
	selected := make(map[string]bool)
	cursorID := ""
	if !hs.loading {
		for _, hunter := range hs.hunters {
			selected[hunter.HunterID] = hunter.Selected
		}
		if hs.cursorIndex >= 0 && hs.cursorIndex < len(hs.hunters) {
			cursorID = hs.hunters[hs.cursorIndex].HunterID
		}
	}
	hs.hunters = append([]HunterSelectorItem(nil), hunters...)
	hs.cursorIndex = 0
	for i := range hs.hunters {
		if value, ok := selected[hs.hunters[i].HunterID]; ok {
			hs.hunters[i].Selected = value
		}
		if hs.hunters[i].HunterID == cursorID {
			hs.cursorIndex = i
		}
	}
	hs.loading = false
	hs.keepSelectedVisible()
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

	if cmd, handled := HandleModalInput(hs, msg); handled {
		return cmd
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if hs.cursorIndex > 0 {
				hs.cursorIndex--
				hs.keepSelectedVisible()
			}
		case "down", "j":
			if hs.cursorIndex < len(hs.hunters)-1 {
				hs.cursorIndex++
				hs.keepSelectedVisible()
			}
		case " ": // Space shares the checkbox action path.
			if hs.cursorIndex >= 0 && hs.cursorIndex < len(hs.hunters) {
				return hs.HandleModalAction("hunter:" + hs.hunters[hs.cursorIndex].HunterID)
			}
		case "a":
			return hs.HandleModalAction("all")
		case "n":
			return hs.HandleModalAction("none")
		case "enter":
			return hs.HandleModalAction("confirm")
		case "esc":
			// Cancel selection
			hs.Deactivate()
		}
	}

	return nil
}

// View renders the hunter subscription selector.
func (hs *HunterSelector) View() string {
	if !hs.active {
		return ""
	}
	return RenderModal(hs.ModalOptions())
}

func (hs *HunterSelector) baseModalOptions() ModalRenderOptions {
	return ModalRenderOptions{ID: "hunter-subscriptions", Title: "Select Hunters to Subscribe", Footer: "↑/↓: Navigate  Space: Toggle", Width: hs.width, Height: hs.height, Theme: hs.theme, ModalWidth: 80, State: &hs.modalState,
		Actions: []ModalAction{{ID: "all", Label: "All", Shortcut: "a", Disabled: hs.loading || len(hs.hunters) == 0}, {ID: "none", Label: "None", Shortcut: "n", Disabled: hs.loading || len(hs.hunters) == 0}, {ID: "confirm", Label: "Confirm", Shortcut: "Enter", Kind: ButtonPrimary, Disabled: hs.loading}, {ID: "cancel", Label: "Cancel", Shortcut: "Esc"}}}
}

func (hs *HunterSelector) visibleRows() int {
	opts := hs.baseModalOptions()
	opts.Content = strings.Repeat("\n", len(hs.hunters)+2)
	return max(1, min(len(hs.hunters), LayoutModal(opts).ContentHeight-2))
}

func (hs *HunterSelector) ModalOptions() ModalRenderOptions {
	opts := hs.baseModalOptions()
	if hs.loading {
		opts.Content = "Loading hunters..."
		return opts
	}
	if len(hs.hunters) == 0 {
		opts.Content = "No hunters available on this processor."
		return opts
	}
	width := ModalContentWidth(opts)
	rows := hs.visibleRows()
	start := min(hs.rowOffset, max(0, len(hs.hunters)-rows))
	opts.Targets = []ModalTarget{{ID: "list", Bounds: image.Rect(0, 0, width, rows), Focusable: true}}
	var content strings.Builder
	for i := start; i < min(len(hs.hunters), start+rows); i++ {
		hunter := hs.hunters[i]
		checkbox := "[ ]"
		if hunter.Selected {
			checkbox = "[✓]"
		}
		mode := "Generic"
		if hunter.Capabilities != nil {
			for _, ft := range hunter.Capabilities.FilterTypes {
				if ft == "sip_user" {
					mode = "VoIP"
					break
				}
			}
		}
		line := checkbox + " ● " + hunter.HunterID + " [" + mode + "]"
		if hunter.Hostname != "" {
			line += " (" + hunter.Hostname + ")"
		} else if hunter.RemoteAddr != "" {
			line += " (" + hunter.RemoteAddr + ")"
		}
		style := lipgloss.NewStyle().Foreground(hs.theme.Foreground).Width(width)
		if i == hs.cursorIndex {
			style = style.Foreground(hs.theme.SelectionFg).Background(hs.theme.SelectionBg).Bold(true)
		}
		content.WriteString(style.Render(ansi.Truncate(line, width, "…")) + "\n")
		opts.Targets = append(opts.Targets, ModalTarget{ID: "hunter:" + hunter.HunterID, Bounds: image.Rect(0, i-start, width, i-start+1)})
	}
	content.WriteString("\n")
	if hs.cursorIndex >= 0 && hs.cursorIndex < len(hs.hunters) {
		content.WriteString(ansi.Truncate("Interfaces: "+strings.Join(hs.hunters[hs.cursorIndex].Interfaces, ", "), width, "…"))
	}
	opts.Content = content.String()
	return opts
}

func (hs *HunterSelector) keepSelectedVisible() {
	rows := hs.visibleRows()
	if hs.cursorIndex < hs.rowOffset {
		hs.rowOffset = hs.cursorIndex
	}
	if hs.cursorIndex >= hs.rowOffset+rows {
		hs.rowOffset = hs.cursorIndex - rows + 1
	}
}

func (hs *HunterSelector) ScrollModal(delta int) tea.Cmd {
	hs.rowOffset = max(0, min(hs.rowOffset+delta, len(hs.hunters)-hs.visibleRows()))
	return nil
}

func (hs *HunterSelector) HandleModalFocus(string) tea.Cmd { return nil }

func (hs *HunterSelector) HandleModalAction(id string) tea.Cmd {
	if !hs.active {
		return nil
	}
	if id == "cancel" {
		return hs.Dismiss()
	}
	if hs.loading {
		return nil
	}
	switch id {
	case "all", "none":
		for i := range hs.hunters {
			hs.hunters[i].Selected = id == "all"
		}
	case "confirm":
		ids := hs.GetSelectedHunterIDs()
		addr := hs.processorAddr
		hs.Deactivate()
		return func() tea.Msg { return HunterSelectionConfirmedMsg{ProcessorAddr: addr, SelectedHunterIDs: ids} }
	default:
		if strings.HasPrefix(id, "hunter:") {
			for i := range hs.hunters {
				if "hunter:"+hs.hunters[i].HunterID == id {
					hs.cursorIndex = i
					hs.hunters[i].Selected = !hs.hunters[i].Selected
					hs.modalState.Focus = "list"
					break
				}
			}
		}
	}
	return nil
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

// ScrollModalAt limits wheel scrolling to the list, excluding its description.
func (hs *HunterSelector) ScrollModalAt(delta, x, y int) tea.Cmd {
	if y >= 0 && y < hs.visibleRows() {
		return hs.ScrollModal(delta)
	}
	return nil
}
