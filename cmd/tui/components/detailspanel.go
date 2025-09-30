package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// DetailsPanel displays detailed information about a selected packet
type DetailsPanel struct {
	packet *PacketDisplay
	width  int
	height int
	theme  themes.Theme
}

// NewDetailsPanel creates a new details panel
func NewDetailsPanel() DetailsPanel {
	return DetailsPanel{
		packet: nil,
		width:  40,
		height: 20,
		theme:  themes.SolarizedDark(),
	}
}

// SetTheme updates the theme
func (d *DetailsPanel) SetTheme(theme themes.Theme) {
	d.theme = theme
}

// SetPacket sets the packet to display
func (d *DetailsPanel) SetPacket(packet *PacketDisplay) {
	d.packet = packet
}

// SetSize sets the display size
func (d *DetailsPanel) SetSize(width, height int) {
	d.width = width
	d.height = height
}

// View renders the details panel
func (d *DetailsPanel) View() string {
	// Ensure minimum width
	contentWidth := d.width - 4
	if contentWidth < 20 {
		contentWidth = 20
	}

	borderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(d.theme.BorderColor).
		Padding(1, 2).
		Width(contentWidth).
		Height(d.height - 2)

	titleStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(d.theme.InfoColor).
		MarginBottom(1)

	labelStyle := lipgloss.NewStyle().
		Foreground(d.theme.HeaderFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(d.theme.Foreground)

	if d.packet == nil {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center)
		content := emptyStyle.Render("Select a packet to view details")
		return borderStyle.Render(content)
	}

	var details strings.Builder
	details.WriteString(titleStyle.Render("Packet Details"))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Timestamp: "))
	details.WriteString(valueStyle.Render(d.packet.Timestamp.Format("15:04:05.000000")))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Protocol: "))
	protocolStyle := valueStyle.Copy().Foreground(d.getProtocolColor(d.packet.Protocol))
	details.WriteString(protocolStyle.Render(d.packet.Protocol))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Source: "))
	srcAddr := fmt.Sprintf("%s:%s", d.packet.SrcIP, d.packet.SrcPort)
	if len(srcAddr) > contentWidth-10 {
		srcAddr = srcAddr[:contentWidth-13] + "..."
	}
	details.WriteString(valueStyle.Render(srcAddr))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Destination: "))
	dstAddr := fmt.Sprintf("%s:%s", d.packet.DstIP, d.packet.DstPort)
	if len(dstAddr) > contentWidth-10 {
		dstAddr = dstAddr[:contentWidth-13] + "..."
	}
	details.WriteString(valueStyle.Render(dstAddr))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Length: "))
	details.WriteString(valueStyle.Render(fmt.Sprintf("%d bytes", d.packet.Length)))
	details.WriteString("\n\n")

	details.WriteString(labelStyle.Render("Info: "))
	// Word wrap info if it's too long
	wrapWidth := contentWidth - 6 // Account for padding and label
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	infoLines := d.wordWrap(d.packet.Info, wrapWidth)
	for i, line := range infoLines {
		if i > 0 {
			details.WriteString("\n      ")
		}
		details.WriteString(valueStyle.Render(line))
	}

	return borderStyle.Render(details.String())
}

// getProtocolColor returns the theme color for a protocol
func (d *DetailsPanel) getProtocolColor(protocol string) lipgloss.Color {
	switch protocol {
	case "TCP":
		return d.theme.TCPColor
	case "UDP":
		return d.theme.UDPColor
	case "SIP":
		return d.theme.SIPColor
	case "RTP":
		return d.theme.RTPColor
	case "DNS":
		return d.theme.DNSColor
	case "HTTP", "HTTPS":
		return d.theme.HTTPColor
	case "TLS", "SSL":
		return d.theme.TLSColor
	case "ICMP":
		return d.theme.ICMPColor
	default:
		return d.theme.Foreground
	}
}

// wordWrap wraps text to fit within maxWidth
func (d *DetailsPanel) wordWrap(text string, maxWidth int) []string {
	if len(text) <= maxWidth {
		return []string{text}
	}

	var lines []string
	var currentLine string

	words := strings.Fields(text)
	for _, word := range words {
		if len(currentLine)+len(word)+1 <= maxWidth {
			if currentLine != "" {
				currentLine += " "
			}
			currentLine += word
		} else {
			if currentLine != "" {
				lines = append(lines, currentLine)
			}
			currentLine = word
		}
	}

	if currentLine != "" {
		lines = append(lines, currentLine)
	}

	return lines
}