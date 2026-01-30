//go:build tui || all

package components

import (
	"fmt"
	"net"
	"strings"
	"unicode"

	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// DecryptedDataGetter is a callback function type for retrieving decrypted TLS data.
// It takes source/destination IP and port and returns client and server decrypted data.
type DecryptedDataGetter func(srcIP, dstIP, srcPort, dstPort string) (clientData, serverData []byte)

// DetailsPanel displays detailed information about a selected packet
type DetailsPanel struct {
	viewport            viewport.Model
	packet              *PacketDisplay
	width               int
	height              int
	theme               themes.Theme
	ready               bool
	decryptedDataGetter DecryptedDataGetter // Callback to get decrypted TLS data
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

// SetDecryptedDataGetter sets the callback for retrieving decrypted TLS data
func (d *DetailsPanel) SetDecryptedDataGetter(getter DecryptedDataGetter) {
	d.decryptedDataGetter = getter
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

	// Layer Summary Section (parsed from raw packet data)
	if layerSummary := d.renderLayerSummary(contentWidth); layerSummary != "" {
		content.WriteString("\n\n")
		content.WriteString(layerSummary)
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

	// DNS Details Section (only for DNS packets)
	if d.packet.DNSData != nil {
		content.WriteString("\n\n")
		content.WriteString(sectionStyle.Render("🔍 DNS Details"))
		content.WriteString("\n\n")

		// Transaction ID
		content.WriteString(labelStyle.Render("Transaction ID: "))
		content.WriteString(valueStyle.Render(fmt.Sprintf("0x%04x", d.packet.DNSData.TransactionID)))
		content.WriteString("\n")

		// Query/Response indicator
		content.WriteString(labelStyle.Render("Type: "))
		if d.packet.DNSData.IsResponse {
			content.WriteString(valueStyle.Render("Response"))
		} else {
			content.WriteString(valueStyle.Render("Query"))
		}
		content.WriteString("\n")

		// Query name and type
		if d.packet.DNSData.QueryName != "" {
			content.WriteString(labelStyle.Render("Query: "))
			content.WriteString(valueStyle.Render(d.packet.DNSData.QueryName))
			content.WriteString("\n")
		}

		if d.packet.DNSData.QueryType != "" {
			content.WriteString(labelStyle.Render("Record Type: "))
			content.WriteString(valueStyle.Render(d.packet.DNSData.QueryType))
			content.WriteString("\n")
		}

		// Response-specific fields
		if d.packet.DNSData.IsResponse {
			content.WriteString(labelStyle.Render("Response Code: "))
			responseStyle := valueStyle
			if d.packet.DNSData.ResponseCode != "NOERROR" {
				responseStyle = lipgloss.NewStyle().Foreground(d.theme.ErrorColor)
			}
			content.WriteString(responseStyle.Render(d.packet.DNSData.ResponseCode))
			content.WriteString("\n")

			// Response time if correlated
			if d.packet.DNSData.CorrelatedQuery && d.packet.DNSData.QueryResponseTimeMs > 0 {
				content.WriteString(labelStyle.Render("Response Time: "))
				content.WriteString(valueStyle.Render(fmt.Sprintf("%d ms", d.packet.DNSData.QueryResponseTimeMs)))
				content.WriteString("\n")
			}
		}

		// Flags
		var flags []string
		if d.packet.DNSData.Authoritative {
			flags = append(flags, "AA")
		}
		if d.packet.DNSData.Truncated {
			flags = append(flags, "TC")
		}
		if d.packet.DNSData.RecursionDesired {
			flags = append(flags, "RD")
		}
		if d.packet.DNSData.RecursionAvailable {
			flags = append(flags, "RA")
		}
		if len(flags) > 0 {
			content.WriteString(labelStyle.Render("Flags: "))
			content.WriteString(valueStyle.Render(strings.Join(flags, ", ")))
			content.WriteString("\n")
		}

		// Answers (for responses)
		if len(d.packet.DNSData.Answers) > 0 {
			content.WriteString(labelStyle.Render("Answers:\n"))
			for _, answer := range d.packet.DNSData.Answers {
				content.WriteString("  ")
				content.WriteString(valueStyle.Render(fmt.Sprintf("%s %s %s (TTL: %d)",
					answer.Name, answer.Type, answer.Data, answer.TTL)))
				content.WriteString("\n")
			}
		}

		// Tunneling detection warning
		if d.packet.DNSData.TunnelingScore > 0.5 {
			content.WriteString("\n")
			warningStyle := lipgloss.NewStyle().
				Foreground(d.theme.WarningColor).
				Bold(true)
			content.WriteString(warningStyle.Render("⚠ Potential DNS Tunneling Detected"))
			content.WriteString("\n")
			content.WriteString(labelStyle.Render("Tunneling Score: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%.2f", d.packet.DNSData.TunnelingScore)))
			content.WriteString("\n")
			content.WriteString(labelStyle.Render("Entropy Score: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%.2f", d.packet.DNSData.EntropyScore)))
			content.WriteString("\n")
		}
	}

	// TLS Details Section (only for TLS handshakes)
	if d.packet.TLSData != nil {
		content.WriteString("\n\n")
		content.WriteString(sectionStyle.Render("🔐 TLS Details"))
		content.WriteString("\n\n")

		// Handshake type
		content.WriteString(labelStyle.Render("Handshake: "))
		content.WriteString(valueStyle.Render(d.packet.TLSData.HandshakeType))
		content.WriteString("\n")

		// TLS Version
		content.WriteString(labelStyle.Render("Version: "))
		versionStyle := valueStyle
		// Warn about old TLS versions
		if d.packet.TLSData.Version == "TLS 1.0" || d.packet.TLSData.Version == "TLS 1.1" || strings.HasPrefix(d.packet.TLSData.Version, "SSL") {
			versionStyle = lipgloss.NewStyle().Foreground(d.theme.WarningColor)
		}
		content.WriteString(versionStyle.Render(d.packet.TLSData.Version))
		content.WriteString("\n")

		// SNI (Server Name Indication)
		if d.packet.TLSData.SNI != "" {
			content.WriteString(labelStyle.Render("SNI: "))
			content.WriteString(valueStyle.Render(d.packet.TLSData.SNI))
			content.WriteString("\n")
		}

		// JA3 Fingerprint (ClientHello)
		if d.packet.TLSData.JA3Fingerprint != "" {
			content.WriteString(labelStyle.Render("JA3: "))
			content.WriteString(valueStyle.Render(d.packet.TLSData.JA3Fingerprint))
			content.WriteString("\n")
		}

		// JA3S Fingerprint (ServerHello)
		if d.packet.TLSData.JA3SFingerprint != "" {
			content.WriteString(labelStyle.Render("JA3S: "))
			content.WriteString(valueStyle.Render(d.packet.TLSData.JA3SFingerprint))
			content.WriteString("\n")
		}

		// JA4 Fingerprint
		if d.packet.TLSData.JA4Fingerprint != "" {
			content.WriteString(labelStyle.Render("JA4: "))
			content.WriteString(valueStyle.Render(d.packet.TLSData.JA4Fingerprint))
			content.WriteString("\n")
		}

		// Cipher suites for ClientHello
		if len(d.packet.TLSData.CipherSuites) > 0 {
			content.WriteString(labelStyle.Render("Cipher Suites: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%d offered", len(d.packet.TLSData.CipherSuites))))
			content.WriteString("\n")
		}

		// Selected cipher for ServerHello
		if d.packet.TLSData.IsServer && d.packet.TLSData.SelectedCipher != 0 {
			content.WriteString(labelStyle.Render("Selected Cipher: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("0x%04X", d.packet.TLSData.SelectedCipher)))
			content.WriteString("\n")
		}

		// ALPN protocols
		if len(d.packet.TLSData.ALPNProtocols) > 0 {
			content.WriteString(labelStyle.Render("ALPN: "))
			content.WriteString(valueStyle.Render(strings.Join(d.packet.TLSData.ALPNProtocols, ", ")))
			content.WriteString("\n")
		}

		// Handshake time (if correlated)
		if d.packet.TLSData.CorrelatedPeer && d.packet.TLSData.HandshakeTimeMs > 0 {
			content.WriteString(labelStyle.Render("Handshake Time: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%d ms", d.packet.TLSData.HandshakeTimeMs)))
			content.WriteString("\n")
		}

		// Risk score warning
		if d.packet.TLSData.RiskScore > 0.5 {
			content.WriteString("\n")
			warningStyle := lipgloss.NewStyle().
				Foreground(d.theme.WarningColor).
				Bold(true)
			content.WriteString(warningStyle.Render("⚠ Security Risk Detected"))
			content.WriteString("\n")
			content.WriteString(labelStyle.Render("Risk Score: "))
			content.WriteString(valueStyle.Render(fmt.Sprintf("%.0f%%", d.packet.TLSData.RiskScore*100)))
			content.WriteString("\n")
		}
	}

	// Decrypted Data Section (for TLS-encrypted traffic with keylog)
	if d.decryptedDataGetter != nil && d.packet.Protocol == "TLS" {
		clientData, serverData := d.decryptedDataGetter(d.packet.SrcIP, d.packet.DstIP, d.packet.SrcPort, d.packet.DstPort)
		if len(clientData) > 0 || len(serverData) > 0 {
			content.WriteString("\n\n")
			decryptedStyle := lipgloss.NewStyle().
				Bold(true).
				Foreground(d.theme.SuccessColor)
			content.WriteString(decryptedStyle.Render("🔓 Decrypted Content"))
			content.WriteString("\n\n")

			if len(clientData) > 0 {
				content.WriteString(labelStyle.Render("Client → Server:\n"))
				content.WriteString(d.renderDecryptedContent(clientData, contentWidth))
				content.WriteString("\n")
			}

			if len(serverData) > 0 {
				if len(clientData) > 0 {
					content.WriteString("\n")
				}
				content.WriteString(labelStyle.Render("Server → Client:\n"))
				content.WriteString(d.renderDecryptedContent(serverData, contentWidth))
				content.WriteString("\n")
			}
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

// renderDecryptedContent renders decrypted TLS data as text with syntax highlighting
// for HTTP and other text-based protocols, or falls back to hex dump for binary data.
func (d *DetailsPanel) renderDecryptedContent(data []byte, maxWidth int) string {
	if len(data) == 0 {
		return ""
	}

	// Limit display size to avoid overwhelming the UI
	const maxDisplaySize = 4096
	displayData := data
	truncated := false
	if len(data) > maxDisplaySize {
		displayData = data[:maxDisplaySize]
		truncated = true
	}

	// Check if data is printable text (HTTP, etc.)
	isPrintable := true
	nonPrintableCount := 0
	for _, b := range displayData[:min(len(displayData), 512)] {
		if b < 32 && b != '\n' && b != '\r' && b != '\t' {
			nonPrintableCount++
		}
	}
	// Allow up to 5% non-printable characters (for binary-like text protocols)
	if nonPrintableCount > len(displayData[:min(len(displayData), 512)])/20 {
		isPrintable = false
	}

	var sb strings.Builder

	if isPrintable {
		// Render as formatted text
		textStyle := lipgloss.NewStyle().Foreground(d.theme.StatusBarFg)
		httpMethodStyle := lipgloss.NewStyle().Foreground(d.theme.HTTPColor).Bold(true)
		httpHeaderStyle := lipgloss.NewStyle().Foreground(d.theme.InfoColor)

		lines := strings.Split(string(displayData), "\n")
		for i, line := range lines {
			// Limit line count
			if i >= 50 {
				sb.WriteString(textStyle.Render("... (truncated)"))
				break
			}

			// Trim carriage returns
			line = strings.TrimSuffix(line, "\r")

			// Truncate long lines
			if len(line) > maxWidth {
				line = line[:maxWidth-3] + "..."
			}

			// Highlight HTTP request/response lines
			if strings.HasPrefix(line, "GET ") || strings.HasPrefix(line, "POST ") ||
				strings.HasPrefix(line, "PUT ") || strings.HasPrefix(line, "DELETE ") ||
				strings.HasPrefix(line, "HEAD ") || strings.HasPrefix(line, "OPTIONS ") ||
				strings.HasPrefix(line, "HTTP/") {
				sb.WriteString(httpMethodStyle.Render(line))
			} else if strings.Contains(line, ":") && !strings.HasPrefix(line, " ") && len(line) < 100 {
				// Likely an HTTP header
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 && isHTTPHeaderName(parts[0]) {
					sb.WriteString(httpHeaderStyle.Render(parts[0] + ":"))
					sb.WriteString(textStyle.Render(parts[1]))
				} else {
					sb.WriteString(textStyle.Render(line))
				}
			} else {
				sb.WriteString(textStyle.Render(line))
			}
			sb.WriteString("\n")
		}
	} else {
		// Render as hex dump for binary data
		sb.WriteString(d.renderHexDump(displayData))
	}

	if truncated {
		sb.WriteString(lipgloss.NewStyle().
			Foreground(d.theme.WarningColor).
			Render(fmt.Sprintf("\n... (showing %d of %d bytes)", maxDisplaySize, len(data))))
	}

	return sb.String()
}

// isHTTPHeaderName checks if a string looks like an HTTP header name
func isHTTPHeaderName(s string) bool {
	if len(s) == 0 || len(s) > 50 {
		return false
	}
	for _, c := range s {
		if !unicode.IsLetter(c) && c != '-' {
			return false
		}
	}
	return true
}

// renderLayerSummary renders a compact protocol layer summary showing the packet's
// layer stack (Ethernet → IPv4 → TCP → HTTP) with key fields from each layer.
func (d *DetailsPanel) renderLayerSummary(contentWidth int) string {
	if d.packet == nil || d.packet.RawData == nil || len(d.packet.RawData) == 0 {
		return ""
	}

	// Determine the decoder based on LinkType
	var decoder gopacket.Decoder
	switch d.packet.LinkType {
	case layers.LinkTypeEthernet:
		decoder = layers.LayerTypeEthernet
	case layers.LinkTypeRaw, layers.LinkTypeIPv4:
		decoder = layers.LayerTypeIPv4
	case layers.LinkTypeIPv6:
		decoder = layers.LayerTypeIPv6
	case layers.LinkTypeLinuxSLL:
		decoder = layers.LayerTypeLinuxSLL
	default:
		// Unknown link type, skip layer summary
		return ""
	}

	// Parse the packet
	packet := gopacket.NewPacket(d.packet.RawData, decoder, gopacket.DecodeOptions{
		Lazy:   true,
		NoCopy: true,
	})

	var sb strings.Builder

	// Layer colors
	linkColor := lipgloss.Color("#657b83")      // gray (base00)
	networkColor := lipgloss.Color("#268bd2")   // blue
	transportColor := lipgloss.Color("#2aa198") // cyan
	appColor := lipgloss.Color("#859900")       // green

	linkStyle := lipgloss.NewStyle().Foreground(linkColor)
	networkStyle := lipgloss.NewStyle().Foreground(networkColor)
	transportStyle := lipgloss.NewStyle().Foreground(transportColor)
	appStyle := lipgloss.NewStyle().Foreground(appColor)
	labelStyle := lipgloss.NewStyle().Foreground(d.theme.StatusBarFg).Bold(true)

	// Section header with line filling available width
	headerText := "─── Layers "
	remainingWidth := contentWidth - len(headerText)
	if remainingWidth < 0 {
		remainingWidth = 0
	}
	header := headerText + strings.Repeat("─", remainingWidth)
	sb.WriteString(lipgloss.NewStyle().Foreground(d.theme.InfoColor).Render(header))
	sb.WriteString("\n")

	// Link layer (Ethernet, Linux SLL, etc.)
	if eth := packet.Layer(layers.LayerTypeEthernet); eth != nil {
		ethLayer := eth.(*layers.Ethernet)
		line := fmt.Sprintf("%-10s %s → %s", "Ethernet", ethLayer.SrcMAC, ethLayer.DstMAC)
		// Add EtherType if not IP
		if ethLayer.EthernetType != layers.EthernetTypeIPv4 && ethLayer.EthernetType != layers.EthernetTypeIPv6 {
			line += fmt.Sprintf("  [%s]", ethLayer.EthernetType)
		}
		sb.WriteString(labelStyle.Render("Ethernet  "))
		sb.WriteString(linkStyle.Render(fmt.Sprintf("%s → %s", ethLayer.SrcMAC, ethLayer.DstMAC)))
		sb.WriteString("\n")
	} else if sll := packet.Layer(layers.LayerTypeLinuxSLL); sll != nil {
		sllLayer := sll.(*layers.LinuxSLL)
		sb.WriteString(labelStyle.Render("LinuxSLL  "))
		sb.WriteString(linkStyle.Render(fmt.Sprintf("%s", net.HardwareAddr(sllLayer.Addr[:sllLayer.AddrLen]))))
		sb.WriteString("\n")
	}

	// VLAN layer (802.1Q) if present
	if vlan := packet.Layer(layers.LayerTypeDot1Q); vlan != nil {
		vlanLayer := vlan.(*layers.Dot1Q)
		sb.WriteString(labelStyle.Render("VLAN      "))
		sb.WriteString(linkStyle.Render(fmt.Sprintf("ID=%d  Pri=%d", vlanLayer.VLANIdentifier, vlanLayer.Priority)))
		sb.WriteString("\n")
	}

	// Network layer (IPv4 or IPv6)
	if ipv4 := packet.Layer(layers.LayerTypeIPv4); ipv4 != nil {
		ip := ipv4.(*layers.IPv4)
		info := fmt.Sprintf("%s → %s  TTL=%d", ip.SrcIP, ip.DstIP, ip.TTL)
		// Add fragment info if fragmented
		if ip.Flags&layers.IPv4MoreFragments != 0 || ip.FragOffset != 0 {
			info += fmt.Sprintf("  Frag(ID=%d,Off=%d)", ip.Id, ip.FragOffset)
		}
		sb.WriteString(labelStyle.Render("IPv4      "))
		sb.WriteString(networkStyle.Render(info))
		sb.WriteString("\n")
	} else if ipv6 := packet.Layer(layers.LayerTypeIPv6); ipv6 != nil {
		ip := ipv6.(*layers.IPv6)
		sb.WriteString(labelStyle.Render("IPv6      "))
		sb.WriteString(networkStyle.Render(fmt.Sprintf("%s → %s  Hop=%d", ip.SrcIP, ip.DstIP, ip.HopLimit)))
		sb.WriteString("\n")
	}

	// Transport layer (TCP, UDP, ICMP)
	if tcp := packet.Layer(layers.LayerTypeTCP); tcp != nil {
		tcpLayer := tcp.(*layers.TCP)
		flags := d.formatTCPFlags(tcpLayer)
		info := fmt.Sprintf("%d → %d  %s Seq=%d", tcpLayer.SrcPort, tcpLayer.DstPort, flags, tcpLayer.Seq)
		if tcpLayer.ACK {
			info += fmt.Sprintf(" Ack=%d", tcpLayer.Ack)
		}
		sb.WriteString(labelStyle.Render("TCP       "))
		sb.WriteString(transportStyle.Render(info))
		sb.WriteString("\n")
	} else if udp := packet.Layer(layers.LayerTypeUDP); udp != nil {
		udpLayer := udp.(*layers.UDP)
		sb.WriteString(labelStyle.Render("UDP       "))
		sb.WriteString(transportStyle.Render(fmt.Sprintf("%d → %d  Len=%d", udpLayer.SrcPort, udpLayer.DstPort, udpLayer.Length)))
		sb.WriteString("\n")
	} else if icmp4 := packet.Layer(layers.LayerTypeICMPv4); icmp4 != nil {
		icmpLayer := icmp4.(*layers.ICMPv4)
		info := fmt.Sprintf("Type=%d Code=%d", icmpLayer.TypeCode.Type(), icmpLayer.TypeCode.Code())
		// Add ID/Seq for echo request/reply
		if icmpLayer.TypeCode.Type() == layers.ICMPv4TypeEchoRequest || icmpLayer.TypeCode.Type() == layers.ICMPv4TypeEchoReply {
			info += fmt.Sprintf("  ID=%d Seq=%d", icmpLayer.Id, icmpLayer.Seq)
		}
		sb.WriteString(labelStyle.Render("ICMPv4    "))
		sb.WriteString(transportStyle.Render(info))
		sb.WriteString("\n")
	} else if icmp6 := packet.Layer(layers.LayerTypeICMPv6); icmp6 != nil {
		icmpLayer := icmp6.(*layers.ICMPv6)
		sb.WriteString(labelStyle.Render("ICMPv6    "))
		sb.WriteString(transportStyle.Render(fmt.Sprintf("Type=%d Code=%d", icmpLayer.TypeCode.Type(), icmpLayer.TypeCode.Code())))
		sb.WriteString("\n")
	}

	// Application layer - build a meaningful summary from protocol-specific metadata
	if d.packet.Protocol != "" && d.packet.Protocol != "TCP" && d.packet.Protocol != "UDP" && d.packet.Protocol != "ICMP" {
		info := d.getApplicationLayerInfo()
		if info != "" {
			maxInfoLen := contentWidth - 12 // Account for label width
			if maxInfoLen < 20 {
				maxInfoLen = 20
			}
			if len(info) > maxInfoLen {
				info = info[:maxInfoLen-3] + "..."
			}
			sb.WriteString(labelStyle.Render(fmt.Sprintf("%-10s", d.packet.Protocol)))
			sb.WriteString(appStyle.Render(info))
			sb.WriteString("\n")
		}
	}

	return sb.String()
}

// getApplicationLayerInfo extracts a meaningful one-liner for the application layer
// from protocol-specific metadata, avoiding redundant display of the protocol name.
func (d *DetailsPanel) getApplicationLayerInfo() string {
	// Try protocol-specific metadata first
	if d.packet.HTTPData != nil {
		if d.packet.HTTPData.Method != "" && d.packet.HTTPData.Path != "" {
			return fmt.Sprintf("%s %s", d.packet.HTTPData.Method, d.packet.HTTPData.Path)
		}
		if d.packet.HTTPData.StatusCode > 0 {
			return fmt.Sprintf("%d %s", d.packet.HTTPData.StatusCode, d.packet.HTTPData.StatusReason)
		}
	}
	if d.packet.DNSData != nil {
		qType := "Query"
		if d.packet.DNSData.IsResponse {
			qType = "Response"
		}
		if d.packet.DNSData.QueryName != "" {
			return fmt.Sprintf("%s %s %s", qType, d.packet.DNSData.QueryType, d.packet.DNSData.QueryName)
		}
	}
	if d.packet.TLSData != nil {
		if d.packet.TLSData.SNI != "" {
			return fmt.Sprintf("%s → %s", d.packet.TLSData.HandshakeType, d.packet.TLSData.SNI)
		}
		if d.packet.TLSData.HandshakeType != "" {
			return d.packet.TLSData.HandshakeType
		}
	}
	if d.packet.VoIPData != nil {
		if d.packet.VoIPData.IsRTP {
			return fmt.Sprintf("SSRC=0x%08x Seq=%d", d.packet.VoIPData.SSRC, d.packet.VoIPData.SeqNumber)
		}
		if d.packet.VoIPData.Method != "" {
			if d.packet.VoIPData.User != "" {
				return fmt.Sprintf("%s %s", d.packet.VoIPData.Method, d.packet.VoIPData.User)
			}
			return d.packet.VoIPData.Method
		}
	}
	if d.packet.EmailData != nil {
		if d.packet.EmailData.Command != "" {
			return d.packet.EmailData.Command
		}
	}

	// Fall back to Info field, but only if it's not just the protocol name repeated
	info := strings.TrimSpace(d.packet.Info)
	if info != "" && !strings.EqualFold(info, d.packet.Protocol) {
		return info
	}

	// No meaningful info available
	return ""
}

// formatTCPFlags formats TCP flags into a bracketed string like [SYN,ACK]
func (d *DetailsPanel) formatTCPFlags(tcp *layers.TCP) string {
	var flags []string
	if tcp.SYN {
		flags = append(flags, "SYN")
	}
	if tcp.ACK {
		flags = append(flags, "ACK")
	}
	if tcp.FIN {
		flags = append(flags, "FIN")
	}
	if tcp.RST {
		flags = append(flags, "RST")
	}
	if tcp.PSH {
		flags = append(flags, "PSH")
	}
	if tcp.URG {
		flags = append(flags, "URG")
	}
	if tcp.ECE {
		flags = append(flags, "ECE")
	}
	if tcp.CWR {
		flags = append(flags, "CWR")
	}
	if len(flags) == 0 {
		return "[]"
	}
	return "[" + strings.Join(flags, ",") + "]"
}
