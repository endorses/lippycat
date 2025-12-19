//go:build tui || all
// +build tui all

package components

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
)

// DetailsPanel displays detailed information about a selected packet
type DetailsPanel struct {
	viewport viewport.Model
	packet   *PacketDisplay
	width    int
	height   int
	theme    themes.Theme
	ready    bool
}

// NewDetailsPanel creates a new details panel
func NewDetailsPanel() DetailsPanel {
	return DetailsPanel{
		packet: nil,
		width:  40,
		height: 20,
		theme:  themes.Solarized(),
		ready:  false,
	}
}

// SetTheme updates the theme
func (d *DetailsPanel) SetTheme(theme themes.Theme) {
	d.theme = theme
}

// SetPacket sets the packet to display
func (d *DetailsPanel) SetPacket(packet *PacketDisplay) {
	// Only update if packet actually changed
	packetChanged := false
	if d.packet == nil && packet != nil {
		packetChanged = true
	} else if d.packet != nil && packet == nil {
		packetChanged = true
	} else if d.packet != nil && packet != nil {
		// Compare timestamps to detect if it's a different packet
		if !d.packet.Timestamp.Equal(packet.Timestamp) {
			packetChanged = true
		}
	}

	d.packet = packet

	// Update viewport content when packet changes
	if d.ready && packetChanged {
		d.viewport.SetContent(d.renderContent())
		d.viewport.GotoTop()
	}
}

// SetSize sets the display size
func (d *DetailsPanel) SetSize(width, height int) {
	d.width = width
	d.height = height

	// Account for border (2) and padding (2)
	viewportHeight := height - 4
	if viewportHeight < 5 {
		viewportHeight = 5
	}

	// Width accounting: border (2) + padding left/right (4) = 6 total
	// Ensure minimum width for hex dump (72 chars: offset(4) + spaces(2) + hex(49) + space(1) + ascii(16))
	viewportWidth := width - 6
	if viewportWidth < 72 {
		viewportWidth = 72
	}

	if !d.ready {
		d.viewport = viewport.New(viewportWidth, viewportHeight)
		d.ready = true
		if d.packet != nil {
			d.viewport.SetContent(d.renderContent())
		}
	} else {
		d.viewport.Width = viewportWidth
		d.viewport.Height = viewportHeight
	}
}

// Update handles viewport messages for scrolling
func (d *DetailsPanel) Update(msg tea.Msg) tea.Cmd {
	if !d.ready {
		return nil
	}
	var cmd tea.Cmd
	d.viewport, cmd = d.viewport.Update(msg)
	return cmd
}

// View renders the details panel
func (d *DetailsPanel) View(focused bool) string {
	if !d.ready {
		return ""
	}

	borderColor := d.theme.BorderColor
	borderType := lipgloss.RoundedBorder()
	if focused {
		borderColor = d.theme.SelectionBg   // Cyan when focused
		borderType = lipgloss.ThickBorder() // Heavy box characters when focused
	}

	borderStyle := lipgloss.NewStyle().
		Border(borderType).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(d.width).
		Height(d.height - 2)

	if d.packet == nil {
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center)
		content := emptyStyle.Render("Select a packet to view details")
		return borderStyle.Render(content)
	}

	return borderStyle.Render(d.viewport.View())
}

// renderContent generates the combined packet details and hex dump content
func (d *DetailsPanel) renderContent() string {
	if d.packet == nil {
		return ""
	}

	contentWidth := d.width - 8
	if contentWidth < 20 {
		contentWidth = 20
	}

	labelStyle := lipgloss.NewStyle().
		Foreground(d.theme.StatusBarFg).
		Bold(true)

	valueStyle := lipgloss.NewStyle().
		Foreground(d.theme.StatusBarFg)

	sectionStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(d.theme.InfoColor)

	var content strings.Builder

	// Packet Details Section
	content.WriteString(sectionStyle.Render("📋 Packet Details"))
	content.WriteString("\n\n")

	content.WriteString(labelStyle.Render("Timestamp: "))
	content.WriteString(valueStyle.Render(d.packet.Timestamp.Format("2006-01-02 15:04:05.000000")))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Protocol: "))
	protocolStyle := valueStyle.Foreground(d.getProtocolColor(d.packet.Protocol))
	content.WriteString(protocolStyle.Render(d.packet.Protocol))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Origin: "))
	captureSource := fmt.Sprintf("%s / %s", d.packet.NodeID, d.packet.Interface)
	content.WriteString(valueStyle.Render(captureSource))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Source: "))
	srcAddr := fmt.Sprintf("%s:%s", d.packet.SrcIP, d.packet.SrcPort)
	if len(srcAddr) > contentWidth-10 {
		srcAddr = srcAddr[:contentWidth-13] + "..."
	}
	content.WriteString(valueStyle.Render(srcAddr))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Destination: "))
	dstAddr := fmt.Sprintf("%s:%s", d.packet.DstIP, d.packet.DstPort)
	if len(dstAddr) > contentWidth-10 {
		dstAddr = dstAddr[:contentWidth-13] + "..."
	}
	content.WriteString(valueStyle.Render(dstAddr))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Length: "))
	content.WriteString(valueStyle.Render(fmt.Sprintf("%d bytes", d.packet.Length)))
	content.WriteString("\n")

	content.WriteString(labelStyle.Render("Info: "))
	// Word wrap info if it's too long
	wrapWidth := contentWidth - 6 // Account for padding and label
	if wrapWidth < 20 {
		wrapWidth = 20
	}
	infoLines := d.wordWrap(d.packet.Info, wrapWidth)
	for i, line := range infoLines {
		if i > 0 {
			content.WriteString("\n      ")
		}
		content.WriteString(valueStyle.Render(line))
	}

	// VoIP Details Section (only for VoIP protocols)
	if d.packet.VoIPData != nil {
		content.WriteString("\n\n")
		content.WriteString(sectionStyle.Render("📞 VoIP Details"))
		content.WriteString("\n\n")

		if d.packet.VoIPData.CallID != "" {
			content.WriteString(labelStyle.Render("Call-ID: "))
			content.WriteString(valueStyle.Render(d.packet.VoIPData.CallID))
			content.WriteString("\n")
		}

		if d.packet.VoIPData.Method != "" {
			content.WriteString(labelStyle.Render("Method: "))
			content.WriteString(valueStyle.Render(d.packet.VoIPData.Method))
			content.WriteString("\n")
		}

		if d.packet.VoIPData.User != "" {
			content.WriteString(labelStyle.Render("User: "))
			content.WriteString(valueStyle.Render(d.packet.VoIPData.User))
			content.WriteString("\n")
		}

		if d.packet.VoIPData.FromTag != "" {
			content.WriteString(labelStyle.Render("From-Tag: "))
			content.WriteString(valueStyle.Render(d.packet.VoIPData.FromTag))
			content.WriteString("\n")
		}

		if d.packet.VoIPData.ToTag != "" {
			content.WriteString(labelStyle.Render("To-Tag: "))
			content.WriteString(valueStyle.Render(d.packet.VoIPData.ToTag))
			content.WriteString("\n")
		}

		if d.packet.VoIPData.IsRTP {
			content.WriteString(labelStyle.Render("SSRC: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("0x%08x", d.packet.VoIPData.SSRC)))
			content.WriteString("\n")

			if d.packet.VoIPData.Codec != "" {
				content.WriteString(labelStyle.Render("Codec: "))
				content.WriteString(valueStyle.Render(d.packet.VoIPData.Codec))
				content.WriteString("\n")
			}

			content.WriteString(labelStyle.Render("Seq: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%d", d.packet.VoIPData.SeqNumber)))
			content.WriteString("\n")
		}
	}

	// Hex Dump Section
	content.WriteString("\n\n")
	content.WriteString(sectionStyle.Render("🔍 Hex Dump"))
	content.WriteString("\n\n")

	if d.packet.RawData != nil && len(d.packet.RawData) > 0 {
		content.WriteString(d.renderHexDump(d.packet.RawData))
	} else {
		content.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("No raw packet data available"))
	}

	return content.String()
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

// renderHexDump renders a hex/ASCII dump of the packet data
func (d *DetailsPanel) renderHexDump(data []byte) string {
	if data == nil || len(data) == 0 {
		return ""
	}

	var sb strings.Builder

	// Solarized color palette for hex columns
	columnColors := []lipgloss.Color{
		lipgloss.Color("#b58900"), // yellow
		lipgloss.Color("#cb4b16"), // orange
		lipgloss.Color("#dc322f"), // red
		lipgloss.Color("#d33682"), // magenta
		lipgloss.Color("#6c71c4"), // violet
		lipgloss.Color("#268bd2"), // blue
		lipgloss.Color("#2aa198"), // cyan
		lipgloss.Color("#859900"), // green
	}

	// Create styles for each column
	var columnStyles [8]lipgloss.Style
	for i := range 8 {
		columnStyles[i] = lipgloss.NewStyle().Foreground(columnColors[i])
	}

	// Style for ASCII
	asciiStyle := lipgloss.NewStyle().Foreground(d.theme.StatusBarFg)
	// Style for offset
	offsetStyle := lipgloss.NewStyle().Foreground(d.theme.StatusBarFg).Bold(true)

	for offset := 0; offset < len(data); offset += 16 {
		// Offset column
		sb.WriteString(offsetStyle.Render(fmt.Sprintf("%04x", offset)))
		sb.WriteString("  ")

		// Hex column (16 bytes per line)
		asciiPart := ""
		for i := 0; i < 16; i++ {
			if offset+i < len(data) {
				b := data[offset+i]

				// Apply color based on column (repeating pattern every 8 bytes)
				colorIndex := i % 8
				hexByte := fmt.Sprintf("%02x ", b)
				sb.WriteString(columnStyles[colorIndex].Render(hexByte))

				// ASCII representation
				if b >= 32 && b <= 126 {
					asciiPart += string(b)
				} else {
					asciiPart += "."
				}
			} else {
				sb.WriteString("   ")
				asciiPart += " "
			}

			// Add extra space after 8 bytes for readability
			if i == 7 {
				sb.WriteString(" ")
			}
		}

		sb.WriteString(" ")
		sb.WriteString(asciiStyle.Render(asciiPart))
		sb.WriteString("\n")
	}

	return sb.String()
}
