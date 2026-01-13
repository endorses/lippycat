//go:build tui || all

package components

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
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
	protocols []Protocol
	selected  int
	active    bool
	theme     themes.Theme
	width     int
	height    int
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
	ps.width = width
	ps.height = height
}

// Activate shows the protocol selector
func (ps *ProtocolSelector) Activate() {
	ps.active = true
}

// Deactivate hides the protocol selector
func (ps *ProtocolSelector) Deactivate() {
	ps.active = false
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

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "up", "k":
			if ps.selected > 0 {
				ps.selected--
			}
		case "down", "j":
			if ps.selected < len(ps.protocols)-1 {
				ps.selected++
			}
		case "enter":
			// Selection confirmed - deactivate and return selected protocol
			ps.Deactivate()
			return func() tea.Msg {
				return ProtocolSelectedMsg{Protocol: ps.GetSelected()}
			}
		case "esc", "p":
			// Cancel selection
			ps.Deactivate()
		}
	}

	return nil
}

// View renders the protocol selector using the unified modal component
func (ps *ProtocolSelector) View() string {
	if !ps.active {
		return ""
	}

	// Styles for content
	itemStyle := lipgloss.NewStyle().
		Foreground(ps.theme.Foreground).
		Padding(0, 1)

	selectedStyle := lipgloss.NewStyle().
		Foreground(ps.theme.SelectionFg).
		Background(ps.theme.SelectionBg).
		Bold(true).
		Padding(0, 1)

	descStyle := lipgloss.NewStyle().
		Foreground(ps.theme.StatusBarFg).
		Italic(true)

	// Build content
	var content strings.Builder

	for i, proto := range ps.protocols {
		var line string
		if i == ps.selected {
			line = selectedStyle.Render(proto.Icon + " " + proto.Name)
			content.WriteString(line)
			content.WriteString("\n")
			content.WriteString(descStyle.Render("  " + proto.Description))
		} else {
			line = itemStyle.Render(proto.Icon + " " + proto.Name)
			content.WriteString(line)
		}
		content.WriteString("\n")
	}

	// Use unified modal rendering
	return RenderModal(ModalRenderOptions{
		Title:      "Select Protocol",
		Content:    content.String(),
		Footer:     "↑/↓: Navigate  Enter: Select  Esc: Cancel",
		Width:      ps.width,
		Height:     ps.height,
		Theme:      ps.theme,
		ModalWidth: 60,
	})
}

// ProtocolSelectedMsg is sent when a protocol is selected
type ProtocolSelectedMsg struct {
	Protocol Protocol
}
