package components

import (
	"fmt"
	// "os" // Only needed for debug logging - uncomment if enabling DEBUG logs
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HunterInfo represents a hunter node for display
type HunterInfo struct {
	ID              string
	Hostname        string
	RemoteAddr      string
	Status          management.HunterStatus
	ConnectedAt     int64
	LastHeartbeat   int64
	PacketsCaptured uint64
	PacketsMatched  uint64
	PacketsForwarded uint64
	PacketsDropped  uint64
	ActiveFilters   uint32
	Interfaces      []string
	ProcessorAddr   string // Address of processor this hunter belongs to
}

// ProcessorInfo represents a processor node
type ProcessorInfo struct {
	Address string
	Hunters []HunterInfo
}

// AddNodeMsg is sent when user wants to add a node
type AddNodeMsg struct {
	Address string // host:port
}

// NodesView displays connected hunter nodes in a tree view grouped by processor
type NodesView struct {
	processors    []ProcessorInfo // Grouped by processor
	hunters       []HunterInfo    // Flat list for backward compatibility
	selectedIndex int             // -1 means input is focused/editing, >= 0 means hunter is selected
	width         int
	height        int
	theme         themes.Theme
	scrollOffset  int
	nodeInput     textinput.Model // Input field for node address
	editing       bool            // Whether input is in edit mode (red border)

	// Mouse click regions
	inputStartLine int // Line number where input field starts
	inputEndLine   int // Line number where input field ends
	hunterLines    map[int]int // Map of line number -> hunter index

	// Double-click detection
	lastClickTime time.Time // Track when input was last clicked for double-click detection
}

// NewNodesView creates a new nodes view component
func NewNodesView() NodesView {
	ti := textinput.New()
	ti.Placeholder = "Press Enter to add a node..."
	ti.CharLimit = 256
	ti.Width = 50
	ti.Blur() // Start unfocused

	return NodesView{
		hunters:       []HunterInfo{},
		selectedIndex: -1, // Start with input focused (no hunters initially)
		width:         80,
		height:        20,
		theme:         themes.SolarizedDark(),
		scrollOffset:  0,
		nodeInput:     ti,
		editing:       false,
		hunterLines:   make(map[int]int),
	}
}

// SetTheme updates the theme
func (n *NodesView) SetTheme(theme themes.Theme) {
	n.theme = theme
}

// SetSize updates the view dimensions
func (n *NodesView) SetSize(width, height int) {
	n.width = width
	n.height = height
}

// SetHunters updates the hunter list and groups by processor
func (n *NodesView) SetHunters(hunters []HunterInfo) {
	n.hunters = hunters

	// Group hunters by processor address
	processorMap := make(map[string][]HunterInfo)
	for _, hunter := range hunters {
		addr := hunter.ProcessorAddr
		if addr == "" {
			addr = "Direct" // Hunters without processor (direct connections)
		}
		processorMap[addr] = append(processorMap[addr], hunter)
	}

	// Convert map to slice
	n.processors = make([]ProcessorInfo, 0, len(processorMap))
	for addr, hunterList := range processorMap {
		n.processors = append(n.processors, ProcessorInfo{
			Address: addr,
			Hunters: hunterList,
		})
	}

	// Reset selection if out of bounds
	if n.selectedIndex >= len(n.hunters) {
		n.selectedIndex = 0
	}
}

// GetHunterCount returns the number of hunters
func (n *NodesView) GetHunterCount() int {
	return len(n.hunters)
}

// GetProcessorCount returns the number of processors
func (n *NodesView) GetProcessorCount() int {
	return len(n.processors)
}

// SelectNext moves selection to next hunter or from input to first hunter
func (n *NodesView) SelectNext() {
	if len(n.hunters) == 0 {
		return
	}

	// If input is focused (selectedIndex = -1), move to first hunter
	if n.selectedIndex == -1 {
		n.editing = false
		n.nodeInput.Blur()
		n.selectedIndex = 0
		n.adjustScroll()
		return
	}

	// Otherwise, move to next hunter
	n.selectedIndex = (n.selectedIndex + 1) % len(n.hunters)
	n.adjustScroll()
}

// SelectPrevious moves selection to previous hunter or from first hunter to input
func (n *NodesView) SelectPrevious() {
	if len(n.hunters) == 0 {
		// No hunters, but allow focusing input
		if n.selectedIndex != -1 {
			n.selectedIndex = -1
			n.editing = false
			n.nodeInput.Blur()
		}
		return
	}

	// If already at input (selectedIndex = -1), do nothing
	if n.selectedIndex == -1 {
		return
	}

	// If at first hunter, move to input field (focused but not editing)
	if n.selectedIndex == 0 {
		n.selectedIndex = -1
		n.editing = false
		n.nodeInput.Blur()
		return
	}

	// Otherwise, move to previous hunter
	n.selectedIndex = n.selectedIndex - 1
	n.adjustScroll()
}

// Update handles key presses and mouse events
func (n *NodesView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// DEBUG: Uncomment to trace NodesView mouse event handling
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "    -> NodesView.Update: Y=%d Type=%v\n", msg.Y, msg.Type)
		// 	f.Close()
		// }
		return n.handleMouseClick(msg)
	case tea.KeyMsg:
		// Check if input is focused (selectedIndex = -1)
		if n.selectedIndex == -1 {
			if n.editing {
				// In edit mode - handle input field keys
				switch msg.String() {
				case "enter":
					// Submit node address
					addr := n.nodeInput.Value()
					if addr != "" {
						n.nodeInput.SetValue("")
						n.editing = false
						n.nodeInput.Blur()
						return func() tea.Msg {
							return AddNodeMsg{Address: addr}
						}
					}
					// If empty, just exit edit mode (stay focused)
					n.editing = false
					n.nodeInput.Blur()
					return nil
				case "esc":
					// Cancel editing, stay focused
					n.editing = false
					n.nodeInput.Blur()
					n.nodeInput.SetValue("")
					return nil
				default:
					// Pass other keys to input field
					n.nodeInput, cmd = n.nodeInput.Update(msg)
					return cmd
				}
			} else {
				// Input is focused but not editing - enter key starts editing
				if msg.String() == "enter" {
					n.editing = true
					n.nodeInput.Focus()
					n.nodeInput.SetValue("")
					return nil
				}
			}
		}
	}

	return nil
}

// IsEditing returns whether the input field is in edit mode
func (n *NodesView) IsEditing() bool {
	return n.editing
}

// getColumnWidths returns responsive column widths based on available width
func (n *NodesView) getColumnWidths() (idCol, hostCol, statusCol, uptimeCol, capturedCol, forwardedCol, filtersCol int) {
	// Account for spacing between columns (7 columns = 6 spaces)
	availableWidth := n.width - 2 // Account for left/right padding

	// Minimum widths
	minIdCol := 8
	minHostCol := 8
	minStatusCol := 7
	minUptimeCol := 6
	minCapturedCol := 8
	minForwardedCol := 9
	minFiltersCol := 7

	// Preferred widths
	idCol = 15
	hostCol = 20
	statusCol = 8
	uptimeCol = 10
	capturedCol = 10
	forwardedCol = 10
	filtersCol = 8

	// Calculate total preferred width
	totalPreferred := idCol + hostCol + statusCol + uptimeCol + capturedCol + forwardedCol + filtersCol

	// If we have enough space, use preferred widths
	if totalPreferred <= availableWidth {
		return
	}

	// Otherwise, start with minimum widths
	idCol = minIdCol
	hostCol = minHostCol
	statusCol = minStatusCol
	uptimeCol = minUptimeCol
	capturedCol = minCapturedCol
	forwardedCol = minForwardedCol
	filtersCol = minFiltersCol

	minTotal := idCol + hostCol + statusCol + uptimeCol + capturedCol + forwardedCol + filtersCol

	// If even minimum doesn't fit, use minimum and let it overflow
	if minTotal >= availableWidth {
		return
	}

	// Distribute remaining space proportionally to ID and Hostname
	remaining := availableWidth - minTotal
	extra := remaining / 2
	idCol += extra
	hostCol += remaining - extra

	return
}

// adjustScroll adjusts scroll offset to keep selected item visible
func (n *NodesView) adjustScroll() {
	visibleRows := n.height - 3 // Header + borders
	if n.selectedIndex < n.scrollOffset {
		n.scrollOffset = n.selectedIndex
	}
	if n.selectedIndex >= n.scrollOffset+visibleRows {
		n.scrollOffset = n.selectedIndex - visibleRows + 1
	}
}

// GetSelectedHunter returns the currently selected hunter
func (n *NodesView) GetSelectedHunter() *HunterInfo {
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		return &n.hunters[n.selectedIndex]
	}
	return nil
}

// View renders the nodes view
// renderTreeView renders the processors and hunters in a tree structure with table columns
func (n *NodesView) renderTreeView(b *strings.Builder, linesRendered *int) {
	processorStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(n.theme.InfoColor)

	selectedStyle := lipgloss.NewStyle().
		Foreground(n.theme.SelectionBg).
		Reverse(true).
		Bold(true)

	// Calculate column widths
	idCol, hostCol, _, uptimeCol, capturedCol, forwardedCol, filtersCol := n.getColumnWidths()

	// Tree prefix is fixed width
	treeCol := 6 // "  ├─ " or "  └─ "

	// Calculate max rows available
	maxRows := n.height - *linesRendered - 1

	rowIndex := 0
	for _, proc := range n.processors {
		// Save the starting line for this processor's hunters (before headers)
		// This is where clicks should be tracked, even though headers are rendered
		huntersStartLine := *linesRendered

		// Processor header
		procLine := fmt.Sprintf("📡 Processor: %s (%d hunters)", proc.Address, len(proc.Hunters))
		b.WriteString(processorStyle.Render(procLine) + "\n")
		rowIndex++

		if rowIndex >= maxRows {
			break
		}

		// Table header for hunters under this processor
		// Add tree structure continuation to header
		treePrefix := "  │  "
		headerLine := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
			treeCol, treePrefix,
			1, "S", // Status
			idCol, "Hunter ID",
			hostCol, "IP Address",
			uptimeCol, "Uptime",
			capturedCol, "Captured",
			forwardedCol, "Forwarded",
			filtersCol, "Filters",
		)
		headerStyle := lipgloss.NewStyle().
			Foreground(n.theme.Foreground).
			Bold(true)
		b.WriteString(headerStyle.Render(headerLine) + "\n")
		rowIndex++

		if rowIndex >= maxRows {
			break
		}

		// Track actual visual line count (including headers)
		*linesRendered = huntersStartLine + rowIndex

		// Render hunters under this processor in table format
		for i, hunter := range proc.Hunters {
			isLast := i == len(proc.Hunters)-1
			prefix := "  ├─ "
			if isLast {
				prefix = "  └─ "
			}

			// Status indicator - use different icons for better visibility when selected
			var statusIcon string
			var statusColor lipgloss.Color
			switch hunter.Status {
			case management.HunterStatus_STATUS_HEALTHY:
				statusIcon = "●"
				statusColor = n.theme.SuccessColor
			case management.HunterStatus_STATUS_WARNING:
				statusIcon = "●"
				statusColor = n.theme.WarningColor
			case management.HunterStatus_STATUS_ERROR:
				statusIcon = "✗"
				statusColor = n.theme.ErrorColor
			case management.HunterStatus_STATUS_STOPPING:
				statusIcon = "●"
				statusColor = lipgloss.Color("240")
			default:
				statusIcon = "●"
				statusColor = n.theme.SuccessColor
			}

			// Calculate global hunter index
			globalIndex := 0
			found := false
			for _, p := range n.processors {
				for _, h := range p.Hunters {
					if h.ID == hunter.ID && h.ProcessorAddr == hunter.ProcessorAddr {
						found = true
						break
					}
					globalIndex++
				}
				if found {
					break
				}
			}

			// Calculate uptime
			var uptimeStr string
			if hunter.ConnectedAt > 0 {
				uptime := time.Now().UnixNano() - hunter.ConnectedAt
				uptimeStr = formatDuration(uptime)
			} else {
				uptimeStr = "-"
			}

			// Format table columns
			idStr := truncateString(hunter.ID, idCol)
			hostnameStr := truncateString(hunter.Hostname, hostCol)
			capturedStr := formatPacketNumber(hunter.PacketsCaptured)
			forwardedStr := formatPacketNumber(hunter.PacketsForwarded)
			filtersStr := fmt.Sprintf("%d", hunter.ActiveFilters)

			// Track this hunter's line position for mouse clicks
			// Use huntersStartLine + hunter index within this processor to make headers clickable
			n.hunterLines[huntersStartLine+i] = globalIndex

			// Build the line differently based on selection
			if globalIndex == n.selectedIndex {
				// For selected row: build plain text line, then apply full-width background
				hunterLine := fmt.Sprintf("%-*s %s %-*s %-*s %-*s %-*s %-*s %-*s",
					treeCol, prefix,
					statusIcon,
					idCol, idStr,
					hostCol, hostnameStr,
					uptimeCol, uptimeStr,
					capturedCol, capturedStr,
					forwardedCol, forwardedStr,
					filtersCol, filtersStr,
				)
				// Render with full-width background
				renderedRow := selectedStyle.Width(n.width).Render(hunterLine)
				b.WriteString(renderedRow + "\n")
			} else {
				// For non-selected: style the status icon separately
				statusStyled := lipgloss.NewStyle().Foreground(statusColor).Render(statusIcon)
				hunterLine := fmt.Sprintf("%-*s %s %-*s %-*s %-*s %-*s %-*s %-*s",
					treeCol, prefix,
					statusStyled,
					idCol, idStr,
					hostCol, hostnameStr,
					uptimeCol, uptimeStr,
					capturedCol, capturedStr,
					forwardedCol, forwardedStr,
					filtersCol, filtersStr,
				)
				b.WriteString(hunterLine + "\n")
			}

			*linesRendered++
			rowIndex++

			if rowIndex >= maxRows {
				break
			}
		}

		if rowIndex >= maxRows {
			break
		}

		// Add blank line after processor group
		b.WriteString("\n")
		*linesRendered++
		rowIndex++

		if rowIndex >= maxRows {
			break
		}
	}
}

func (n *NodesView) View() string {
	var b strings.Builder

	// Reset mouse click regions
	n.hunterLines = make(map[int]int)

	// Count lines as we build to ensure we fill exactly n.height
	linesRendered := 0

	// Label and input at top (like Settings tab style)
	labelStyle := lipgloss.NewStyle().
		Foreground(n.theme.InfoColor).
		Bold(true)

	// Track input field position (include the label)
	n.inputStartLine = linesRendered

	b.WriteString(labelStyle.Render("Add Node:") + "\n")
	linesRendered++ // Label line

	// Input border color logic (same as settings page):
	// - Red when editing (n.editing = true)
	// - Blue when focused but not editing (selectedIndex = -1 && !editing)
	// - Gray when unfocused (selectedIndex >= 0)
	var borderColor lipgloss.Color
	if n.editing {
		borderColor = n.theme.FocusedBorderColor // Red when editing
	} else if n.selectedIndex == -1 {
		borderColor = n.theme.InfoColor // Blue when focused but not editing
	} else {
		borderColor = n.theme.BorderColor // Gray when unfocused
	}

	inputWithBorder := lipgloss.NewStyle().
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(borderColor).
		Padding(0, 1).
		Width(n.width - 4)

	b.WriteString(inputWithBorder.Render(n.nodeInput.View()) + "\n\n")
	linesRendered += 3 // Input box with border (top border + content + bottom border)
	n.inputEndLine = linesRendered - 1 // End line is before the blank lines
	linesRendered += 2 // Two newlines after input

	if len(n.hunters) == 0 {
		// Empty state
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center)

		b.WriteString(emptyStyle.Render("No nodes connected") + "\n\n")
		linesRendered += 2 // Text line + blank line

		b.WriteString(emptyStyle.Render("Type an address above and press Enter to add a node") + "\n\n")
		linesRendered += 2 // Text line + blank line

		b.WriteString(emptyStyle.Render("Or start a hunter with:") + "\n")
		linesRendered += 1

		b.WriteString(emptyStyle.Render("  lippycat hunt --processor <processor-addr>") + "\n")
		linesRendered += 1
	} else if len(n.processors) > 0 {
		// Tree view: Group hunters by processor
		n.renderTreeView(&b, &linesRendered)
	} else {
		// Get responsive column widths
		idCol, hostCol, statusCol, uptimeCol, capturedCol, forwardedCol, filtersCol := n.getColumnWidths()

		// Table header
		header := fmt.Sprintf(
			" %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
			idCol, "Hunter ID",
			hostCol, "IP Address",
			statusCol, "Status",
			uptimeCol, "Uptime",
			capturedCol, "Captured",
			forwardedCol, "Forwarded",
			filtersCol, "Filters",
		)

		headerStyle := lipgloss.NewStyle().
			Bold(true).
			Foreground(n.theme.InfoColor)

		b.WriteString(headerStyle.Render(header) + "\n")
		linesRendered++ // Header line

		// Separator
		sepStyle := lipgloss.NewStyle().Foreground(n.theme.BorderColor)
		separator := sepStyle.Render(strings.Repeat("─", n.width))
		b.WriteString(separator + "\n")
		linesRendered++ // Separator line

		// Calculate how many rows we can show
		// We need to leave room for: footer(1) + optionally scroll_indicator(1)
		maxRows := n.height - linesRendered - 1 // Reserve 1 for footer
		endIndex := n.scrollOffset + maxRows
		if endIndex > len(n.hunters) {
			endIndex = len(n.hunters)
		}

		for i := n.scrollOffset; i < endIndex; i++ {
			hunter := n.hunters[i]

			// Status color
			statusStyle := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)
			var statusText string
			switch hunter.Status {
			case management.HunterStatus_STATUS_HEALTHY:
				statusStyle = statusStyle.Foreground(n.theme.SuccessColor)
				statusText = "HEALTHY"
			case management.HunterStatus_STATUS_WARNING:
				statusStyle = statusStyle.Foreground(n.theme.WarningColor)
				statusText = "WARNING"
			case management.HunterStatus_STATUS_ERROR:
				statusStyle = statusStyle.Foreground(n.theme.ErrorColor)
				statusText = "ERROR"
			case management.HunterStatus_STATUS_STOPPING:
				statusStyle = statusStyle.Foreground(lipgloss.Color("240"))
				statusText = "STOPPING"
			}

			// Calculate uptime
			uptime := ""
			if hunter.ConnectedAt > 0 {
				duration := time.Since(time.Unix(0, hunter.ConnectedAt))
				if duration.Hours() >= 1 {
					uptime = fmt.Sprintf("%.0fh %.0fm", duration.Hours(), duration.Minutes()-duration.Hours()*60)
				} else if duration.Minutes() >= 1 {
					uptime = fmt.Sprintf("%.0fm %.0fs", duration.Minutes(), duration.Seconds()-duration.Minutes()*60)
				} else {
					uptime = fmt.Sprintf("%.0fs", duration.Seconds())
				}
			}

			// Format row string first (without styles)
			row := fmt.Sprintf(
				" %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
				idCol, truncateString(hunter.ID, idCol),
				hostCol, truncateString(hunter.Hostname, hostCol),
				statusCol, statusText,
				uptimeCol, uptime,
				capturedCol, formatPacketNumber(hunter.PacketsCaptured),
				forwardedCol, formatPacketNumber(hunter.PacketsForwarded),
				filtersCol, fmt.Sprintf("%d", hunter.ActiveFilters),
			)

			// Apply style to entire row
			if i == n.selectedIndex {
				// Use same selection style as packet list (foreground + reverse)
				rowStyle := lipgloss.NewStyle().
					Foreground(n.theme.SelectionBg).
					Reverse(true).
					Bold(true)

				// Render with style and ensure it spans full width
				renderedRow := rowStyle.Render(row)
				rowLen := lipgloss.Width(renderedRow)
				if rowLen < n.width {
					padding := n.width - rowLen
					renderedRow += rowStyle.Render(strings.Repeat(" ", padding))
				}
				b.WriteString(renderedRow + "\n")
			} else {
				// Normal row - apply status color to status column only
				// For simplicity, just render the row as-is
				b.WriteString(row + "\n")
			}
			linesRendered++
		}
	}

	// Calculate padding to fill remaining space
	// Total should be: linesRendered + padding = n.height
	paddingLines := n.height - linesRendered
	if paddingLines < 0 {
		paddingLines = 0
	}

	if paddingLines > 0 {
		b.WriteString(strings.Repeat("\n", paddingLines))
	}

	return b.String()
}

// truncateString truncates a string to maxLen with ellipsis
func truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}

// formatPacketNumber formats a packet count with K/M/G suffixes
func formatPacketNumber(n uint64) string {
	if n >= 1000000000 {
		return fmt.Sprintf("%.1fG", float64(n)/1000000000)
	}
	if n >= 1000000 {
		return fmt.Sprintf("%.1fM", float64(n)/1000000)
	}
	if n >= 1000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%d", n)
}

// formatDuration formats a duration in nanoseconds to human-readable string
func formatDuration(ns int64) string {
	d := time.Duration(ns)
	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm", hours, minutes)
	}
	if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

// handleMouseClick handles mouse click events
func (n *NodesView) handleMouseClick(msg tea.MouseMsg) tea.Cmd {
	// DEBUG: Uncomment to trace detailed click handling (useful for debugging click regions)
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "      -> handleMouseClick: Y=%d Type=%v\n", msg.Y, msg.Type)
	// 	f.Close()
	// }

	// Only handle left button press events
	if msg.Button != tea.MouseButtonLeft || msg.Action != tea.MouseActionPress {
		// DEBUG: Uncomment to see why clicks are being filtered
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "      -> Not MouseLeft, returning\n")
		// 	f.Close()
		// }
		return nil
	}

	// Adjust Y coordinate to be relative to content area (header=2, tabs=4, so content starts at Y=6)
	contentStartY := 6
	clickY := msg.Y - contentStartY

	// DEBUG: Uncomment to see computed click positions and tracked regions
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "      -> clickY=%d inputStart=%d inputEnd=%d hunterLines=%v\n",
	// 		clickY, n.inputStartLine, n.inputEndLine, n.hunterLines)
	// 	f.Close()
	// }

	// Exit edit mode if clicking outside the input field
	if n.editing && (clickY < n.inputStartLine || clickY > n.inputEndLine) {
		n.editing = false
		n.nodeInput.Blur()
		n.nodeInput.SetValue("")
	}

	// Check if clicked on input field
	if clickY >= n.inputStartLine && clickY <= n.inputEndLine {
		// DEBUG: Uncomment to confirm input field clicks
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "      -> CLICKED ON INPUT FIELD\n")
		// 	f.Close()
		// }

		now := time.Now()
		const doubleClickThreshold = 500 * time.Millisecond

		// Check if this is a double-click (second click within 500ms)
		if n.selectedIndex == -1 && !n.editing &&
		   now.Sub(n.lastClickTime) < doubleClickThreshold {
			// Double-click detected - start editing
			n.editing = true
			n.nodeInput.Focus()
			n.nodeInput.SetValue("")
			return nil
		}

		// Single click - just focus input (don't start editing)
		n.selectedIndex = -1
		n.editing = false
		n.nodeInput.Blur()
		n.lastClickTime = now
		return nil
	}

	// Check if clicked on a hunter row
	if hunterIndex, ok := n.hunterLines[clickY]; ok {
		// DEBUG: Uncomment to confirm hunter row clicks
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "      -> CLICKED ON HUNTER %d\n", hunterIndex)
		// 	f.Close()
		// }
		// Select this hunter
		n.selectedIndex = hunterIndex
		n.editing = false
		n.nodeInput.Blur()
		n.adjustScroll()
		return nil
	}

	// DEBUG: Uncomment to see when clicks don't match any region
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "      -> NO MATCH for click\n")
	// 	f.Close()
	// }

	return nil
}
