//go:build tui || all

package components

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/muesli/termenv"
	"github.com/stretchr/testify/require"
)

// Preserve the old packet pane renderer to guard the extracted style lifecycle.
func legacyPacketPane(p *PacketList, focused bool, detailsVisible bool) string {
	// Store detailsVisible for column width calculations
	if p.detailsVisible != detailsVisible {
		p.detailsVisible = detailsVisible
		p.sizeChanged = true // Force recalculation of column widths
	}

	// Calculate the space available for content inside the box
	// Box overhead: 2 (border) + 2 (vertical padding) = 4
	// So the content height should be p.height - 3 to match details panel
	contentHeight := p.height - 3

	// The content includes header (2 lines) + packet lines
	// So available lines for packets = contentHeight - 2
	availableForPackets := contentHeight - p.headerHeight

	var sb strings.Builder

	if len(p.packets) == 0 {
		sb.WriteString(p.renderHeader())
		sb.WriteString("\n")
		sb.WriteString(lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Render("No packets captured yet..."))

		// Fill remaining space
		for i := 1; i < availableForPackets; i++ {
			sb.WriteString("\n")
		}
	} else {
		// Render header
		sb.WriteString(p.renderHeader())
		sb.WriteString("\n")

		// Calculate visible range based on available space
		visibleLines := availableForPackets
		if visibleLines < 1 {
			visibleLines = 1
		}

		start := p.offset
		end := p.offset + visibleLines

		if end > len(p.packets) {
			end = len(p.packets)
		}

		// Render visible packets
		for i := start; i < end; i++ {
			line := p.renderPacket(i, i == p.cursor)
			sb.WriteString(line)
			if i < end-1 {
				sb.WriteString("\n")
			}
		}

		// Fill remaining space to maintain consistent box size
		linesRendered := end - start
		for i := linesRendered; i < visibleLines; i++ {
			if i > 0 || linesRendered > 0 {
				sb.WriteString("\n")
			}
			// Empty line for padding
		}
	}

	// Wrap in border - the height should match our total height minus margins
	// When details are hidden, always show unfocused (gray with rounded borders)
	// When details are visible, show focused state based on focused parameter
	borderColor := p.theme.BorderColor
	borderType := lipgloss.RoundedBorder()
	if focused && detailsVisible {
		borderColor = p.theme.SelectionBg   // Cyan when focused
		borderType = lipgloss.ThickBorder() // Heavy box characters when focused
	}

	// Adaptive width: when details hidden, use full width (width - 2)
	// When details visible (split mode), use width with padding (width - 4)
	borderWidth := p.width - 4
	if !detailsVisible {
		borderWidth = p.width - 2
	}

	borderStyle := lipgloss.NewStyle().
		Border(borderType).
		BorderForeground(borderColor).
		Padding(1, 2).
		Width(borderWidth).
		Height(contentHeight)

	return borderStyle.Render(sb.String())
}

func TestPacketListSharedPaneStylesLegacyEquivalence(t *testing.T) {
	previous := lipgloss.ColorProfile()
	lipgloss.SetColorProfile(termenv.TrueColor)
	t.Cleanup(func() { lipgloss.SetColorProfile(previous) })
	actual, control := NewPacketList(), NewPacketList()
	alternate := themes.Solarized()
	alternate.BorderColor, alternate.SelectionBg = "#aa22ff", "#11bb22"
	for _, theme := range []themes.Theme{themes.Solarized(), alternate, themes.Solarized()} {
		actual.SetTheme(theme)
		control.SetTheme(theme)
		for _, width := range []int{40, 80, 160} {
			for _, height := range []int{6, 12, 40} {
				actual.SetSize(width, height)
				control.SetSize(width, height)
				for _, empty := range []bool{true, false} {
					var packets []PacketDisplay
					if !empty {
						for i, protocol := range []string{"TCP", "UDP", "DNS", "HTTP", "TLS", "unknown"} {
							packets = append(packets, PacketDisplay{Timestamp: time.Unix(int64(i), 0), Protocol: protocol, SrcIP: "192.0.2.1", DstIP: "198.51.100.2", Info: fmt.Sprintf("packet %d", i)})
						}
					}
					actual.SetPackets(packets)
					control.SetPackets(packets)
					for _, details := range []bool{false, true, false} {
						for _, focused := range []bool{false, true, false} {
							require.Equal(t, legacyPacketPane(&control, focused, details), actual.View(focused, details))
						}
					}
				}
			}
		}
	}
}
