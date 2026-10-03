//go:build tui || all

package components

import (
	"image"
	"strconv"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// Protocol represents a selectable protocol
type Protocol struct {
	Name        string
	BPFFilter   string // BPF filter expression for this protocol
	Description string
	Icon        string
}

// ProtocolSelector provides a UI for selecting protocol filters
type ProtocolSelector struct {
	modalState ModalState
	rowOffset  int
	protocols  []Protocol
	selected   int
	active     bool
	theme      themes.Theme
	width      int
	height     int
}

// NewProtocolSelector creates a new protocol selector
func NewProtocolSelector() ProtocolSelector {
	protocols := []Protocol{
		{Name: "All", BPFFilter: "", Description: "Show all protocols", Icon: "🌐"},
		{Name: "VoIP (SIP/RTP)", BPFFilter: "has:voip", Description: "SIP signaling and RTP media", Icon: "📞"},
		{Name: "DNS", BPFFilter: "port 53", Description: "Domain name system", Icon: "🔍"},
		{Name: "HTTP", BPFFilter: "port 80 or port 8080", Description: "Hypertext transfer protocol", Icon: "🌐"},
		{Name: "HTTPS/TLS", BPFFilter: "port 443", Description: "Encrypted HTTP traffic", Icon: "🔒"},
		{Name: "Email", BPFFilter: "port 25 or port 587 or port 465 or port 110 or port 143", Description: "Email protocols (SMTP, POP3, IMAP)", Icon: "📧"},
		{Name: "ICMP", BPFFilter: "icmp", Description: "Internet control message protocol", Icon: "📡"},
		{Name: "TCP", BPFFilter: "tcp", Description: "Transmission control protocol", Icon: "🔗"},
		{Name: "UDP", BPFFilter: "udp", Description: "User datagram protocol", Icon: "📦"},
	}

	return ProtocolSelector{
		protocols: protocols,
		selected:  0,
		active:    false,
		theme:     themes.Solarized(),
	}
}

// SetTheme sets the color theme
func (ps *ProtocolSelector) SetTheme(theme themes.Theme) {
	ps.theme = theme
}

// SetSize sets the dimensions
func (ps *ProtocolSelector) SetSize(width, height int) {
	ps.modalState.ResetClicks()
	ps.width = width
	ps.height = height
	ps.keepSelectedVisible()
}

// Activate shows the protocol selector
func (ps *ProtocolSelector) Activate() {
	ps.modalState.Reset()
	ps.rowOffset = 0
	ps.active = true
}

// Deactivate hides the protocol selector
func (ps *ProtocolSelector) Deactivate() {
	ps.modalState.ResetClicks()
	ps.active = false
}

// Dismiss closes the modal without applying the selected protocol.
func (ps *ProtocolSelector) Dismiss() tea.Cmd {
	ps.Deactivate()
	return nil
}

// IsActive returns whether the selector is visible
func (ps *ProtocolSelector) IsActive() bool {
	return ps.active
}

// GetSelected returns the currently selected protocol
func (ps *ProtocolSelector) GetSelected() Protocol {
	if ps.selected >= 0 && ps.selected < len(ps.protocols) {
		return ps.protocols[ps.selected]
	}
	return ps.protocols[0] // Default to "All"
}

// Update handles key events
func (ps *ProtocolSelector) Update(msg tea.Msg) tea.Cmd {
	if !ps.active {
		return nil
	}

	if cmd, handled := HandleModalInput(ps, msg); handled {
		return cmd
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if ps.selected > 0 {
				ps.selected--
				ps.keepSelectedVisible()
			}
		case "down", "j":
			if ps.selected < len(ps.protocols)-1 {
				ps.selected++
				ps.keepSelectedVisible()
			}
		case "enter":
			return ps.HandleModalAction("apply")
		case "esc", "p":
			// Cancel selection
			ps.Deactivate()
		}
	}

	return nil
}

// View renders the protocol selector using shared modal geometry.
func (ps *ProtocolSelector) View() string {
	if !ps.active {
		return ""
	}
	return RenderModal(ps.ModalOptions())
}

func (ps *ProtocolSelector) baseModalOptions() ModalRenderOptions {
	return ModalRenderOptions{ID: "protocols", Title: "Select Protocol", Footer: "↑/↓: Navigate", Width: ps.width, Height: ps.height, Theme: ps.theme, ModalWidth: 60, State: &ps.modalState,
		Actions: []ModalAction{{ID: "apply", Label: "Apply", Shortcut: "Enter", Kind: ButtonPrimary}, {ID: "cancel", Keys: []string{"p"}, Label: "Cancel", Shortcut: "Esc"}}}
}

func (ps *ProtocolSelector) visibleRows() int {
	opts := ps.baseModalOptions()
	opts.Content = strings.Repeat("\n", len(ps.protocols)+2)
	return max(1, min(len(ps.protocols), LayoutModal(opts).ContentHeight-2))
}

func (ps *ProtocolSelector) ModalOptions() ModalRenderOptions {
	opts := ps.baseModalOptions()
	rows := ps.visibleRows()
	width := ModalContentWidth(opts)
	start := min(ps.rowOffset, max(0, len(ps.protocols)-rows))
	var content strings.Builder
	opts.Targets = []ModalTarget{{ID: "list", Bounds: image.Rect(0, 0, width, rows), Focusable: true}}
	for i := start; i < min(len(ps.protocols), start+rows); i++ {
		proto := ps.protocols[i]
		style := lipgloss.NewStyle().Foreground(ps.theme.Foreground).Width(width)
		if i == ps.selected {
			style = style.Foreground(ps.theme.SelectionFg).Background(ps.theme.SelectionBg).Bold(true)
		}
		content.WriteString(style.Render(ansi.Truncate(" "+proto.Icon+" "+proto.Name, width, "…")))
		content.WriteString("\n")
		opts.Targets = append(opts.Targets, ModalTarget{ID: "protocol:" + strconv.Itoa(i), Bounds: image.Rect(0, i-start, width, i-start+1)})
	}
	content.WriteString("\n")
	content.WriteString(lipgloss.NewStyle().Foreground(ps.theme.StatusBarFg).Italic(true).Render(ansi.Truncate(ps.GetSelected().Description, width, "…")))
	opts.Content = content.String()
	return opts
}

func (ps *ProtocolSelector) keepSelectedVisible() {
	ps.modalState.ResetClicks()
	rows := ps.visibleRows()
	if ps.selected < ps.rowOffset {
		ps.rowOffset = ps.selected
	}
	if ps.selected >= ps.rowOffset+rows {
		ps.rowOffset = ps.selected - rows + 1
	}
}

func (ps *ProtocolSelector) ScrollModal(delta int) tea.Cmd {
	ps.modalState.ResetClicks()
	ps.rowOffset = max(0, min(ps.rowOffset+delta, len(ps.protocols)-ps.visibleRows()))
	return nil
}

func (ps *ProtocolSelector) HandleModalFocus(string) tea.Cmd { return nil }

func (ps *ProtocolSelector) HandleModalAction(id string) tea.Cmd {
	if !ps.active {
		return nil
	}
	switch id {
	case "cancel":
		return ps.Dismiss()
	case "apply":
		selected := ps.GetSelected()
		ps.Deactivate()
		return func() tea.Msg { return ProtocolSelectedMsg{Protocol: selected} }
	}
	if strings.HasPrefix(id, "protocol:") {
		i, err := strconv.Atoi(strings.TrimPrefix(id, "protocol:"))
		if err == nil {
			return ps.selectProtocolAt(i, time.Now())
		}
	}
	return nil
}

// ProtocolSelectedMsg is sent when a protocol is selected
type ProtocolSelectedMsg struct {
	Protocol Protocol
}

// selectProtocolAt keeps double-click identity and timing deterministic in tests.
func (ps *ProtocolSelector) selectProtocolAt(i int, now time.Time) tea.Cmd {
	if i < 0 || i >= len(ps.protocols) {
		return nil
	}
	ps.selected = i
	ps.modalState.Focus = "list"
	if ps.modalState.DoubleClick("protocol:"+strconv.Itoa(i), now) {
		return ps.HandleModalAction("apply")
	}
	return nil
}

// ScrollModalAt limits wheel scrolling to the list, excluding its description.
func (ps *ProtocolSelector) ScrollModalAt(delta, x, y int) tea.Cmd {
	if y >= 0 && y < ps.visibleRows() {
		return ps.ScrollModal(delta)
	}
	return nil
}
