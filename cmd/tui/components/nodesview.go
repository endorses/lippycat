package components

import (
	"fmt"
	"sort"

	// "os" // Only needed for debug logging - uncomment if enabling DEBUG logs
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
)

// HunterInfo represents a hunter node for display
type HunterInfo struct {
	ID               string
	Hostname         string
	RemoteAddr       string
	Status           management.HunterStatus
	ConnectedAt      int64
	LastHeartbeat    int64
	PacketsCaptured  uint64
	PacketsMatched   uint64
	PacketsForwarded uint64
	PacketsDropped   uint64
	ActiveFilters    uint32
	Interfaces       []string
	ProcessorAddr    string // Address of processor this hunter belongs to
}

// ProcessorInfo represents a processor node
type ProcessorInfo struct {
	Address     string
	ProcessorID string // ID of the processor
	Hunters     []HunterInfo
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
	nodeInput     textinput.Model // Input field for node address
	editing       bool            // Whether input is in edit mode (red border)
	viewport      viewport.Model  // Viewport for scrolling
	ready         bool            // Whether viewport is initialized

	// Mouse click regions
	inputStartLine int         // Line number where input field starts
	inputEndLine   int         // Line number where input field ends
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
		theme:         themes.Solarized(),
		nodeInput:     ti,
		editing:       false,
		ready:         false,
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

	// Calculate viewport height (subtract space for input field)
	// Input section takes: 1 (label) + 3 (input with border) + 2 (spacing) = 6 lines
	// Add 1 line to push footer down to match other tabs
	inputSectionHeight := 6
	viewportHeight := height - inputSectionHeight + 1
	if viewportHeight < 1 {
		viewportHeight = 1
	}

	if !n.ready {
		n.viewport = viewport.New(width, viewportHeight)
		n.ready = true
		// Set initial content if we already have data
		n.updateViewportContent()
	} else {
		n.viewport.Width = width
		n.viewport.Height = viewportHeight
	}
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

	// Update viewport content
	n.updateViewportContent()
}

// SetHuntersAndProcessors updates both the hunter list and ensures all processors are shown
func (n *NodesView) SetHuntersAndProcessors(hunters []HunterInfo, processorAddrs []string) {
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

	// Ensure all connected processors are in the map (even with 0 hunters)
	for _, addr := range processorAddrs {
		if _, exists := processorMap[addr]; !exists {
			processorMap[addr] = []HunterInfo{} // Empty hunter list for this processor
		}
	}

	// Convert map to slice and sort processors alphabetically by address
	n.processors = make([]ProcessorInfo, 0, len(processorMap))
	for addr, hunterList := range processorMap {
		// Sort hunters by hunter ID within each processor
		sort.Slice(hunterList, func(i, j int) bool {
			return hunterList[i].ID < hunterList[j].ID
		})

		n.processors = append(n.processors, ProcessorInfo{
			Address: addr,
			Hunters: hunterList,
		})
	}

	// Sort processors alphabetically by address
	sort.Slice(n.processors, func(i, j int) bool {
		return n.processors[i].Address < n.processors[j].Address
	})

	// Reset selection if out of bounds
	if n.selectedIndex >= len(n.hunters) {
		n.selectedIndex = 0
	}

	// Update viewport content
	n.updateViewportContent()
}

// SetProcessors updates the processor list directly with ProcessorInfo
func (n *NodesView) SetProcessors(processors []ProcessorInfo) {
	// Flatten all hunters from all processors
	allHunters := make([]HunterInfo, 0)
	for _, proc := range processors {
		allHunters = append(allHunters, proc.Hunters...)
	}
	n.hunters = allHunters

	// Sort processors alphabetically by address
	sort.Slice(processors, func(i, j int) bool {
		return processors[i].Address < processors[j].Address
	})
	n.processors = processors

	// Reset selection if out of bounds
	if n.selectedIndex >= len(n.hunters) {
		n.selectedIndex = 0
	}

	// Update viewport content
	n.updateViewportContent()
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
		n.updateViewportContent() // Refresh to show selection
		return
	}

	// Otherwise, move to next hunter
	n.selectedIndex = (n.selectedIndex + 1) % len(n.hunters)
	n.updateViewportContent() // Refresh to show selection
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
		n.updateViewportContent() // Refresh to show selection change
		return
	}

	// Otherwise, move to previous hunter
	n.selectedIndex = n.selectedIndex - 1
	n.updateViewportContent() // Refresh to show selection
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
		// Pass mouse events to viewport for scrolling (if not handling clicks)
		clickCmd := n.handleMouseClick(msg)
		if clickCmd != nil {
			return clickCmd
		}
		// Let viewport handle scroll wheel
		n.viewport, cmd = n.viewport.Update(msg)
		return cmd

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
		} else {
			// Hunter is selected - pass keyboard events to viewport for scrolling
			n.viewport, cmd = n.viewport.Update(msg)
			return cmd
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

// GetSelectedHunter returns the currently selected hunter
func (n *NodesView) GetSelectedHunter() *HunterInfo {
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		return &n.hunters[n.selectedIndex]
	}
	return nil
}

// updateViewportContent updates the viewport with current content
func (n *NodesView) updateViewportContent() {
	if !n.ready {
		return
	}
	n.viewport.SetContent(n.renderContent())
}

// renderContent renders the tree view content as a string for the viewport
func (n *NodesView) renderContent() string {
	var b strings.Builder

	// Reset mouse click regions
	n.hunterLines = make(map[int]int)

	if len(n.processors) == 0 && len(n.hunters) == 0 {
		// Empty state - no processors and no hunters
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Align(lipgloss.Center)

		b.WriteString(emptyStyle.Render("No nodes connected") + "\n\n")
		b.WriteString(emptyStyle.Render("Type an address above and press Enter to add a node") + "\n\n")
		b.WriteString(emptyStyle.Render("Or start a hunter with:") + "\n")
		b.WriteString(emptyStyle.Render("  lippycat hunt --processor <processor-addr>") + "\n")
		return b.String()
	}

	if len(n.processors) > 0 {
		// Tree view: Group hunters by processor
		n.renderTreeView(&b)
	} else {
		// Flat view (if no processors but have hunters)
		n.renderFlatView(&b)
	}

	return b.String()
}

// renderTreeView renders the processors and hunters in a tree structure with table columns
func (n *NodesView) renderTreeView(b *strings.Builder) {
	linesRendered := 0
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

	for _, proc := range n.processors {
		// Processor header with ID (if available)
		var procLine string
		if proc.ProcessorID != "" {
			procLine = fmt.Sprintf("📡 Processor: %s [%s] (%d hunters)", proc.Address, proc.ProcessorID, len(proc.Hunters))
		} else {
			procLine = fmt.Sprintf("📡 Processor: %s (%d hunters)", proc.Address, len(proc.Hunters))
		}
		b.WriteString(processorStyle.Render(procLine) + "\n")
		linesRendered++

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
		linesRendered++

		// Render hunters under this processor in table format
		if len(proc.Hunters) == 0 {
			// No hunters for this processor - show empty state
			emptyStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))
			emptyLine := fmt.Sprintf("  └─  (no hunters connected)")
			b.WriteString(emptyStyle.Render(emptyLine) + "\n")
			linesRendered++
		}

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
			// Current line is linesRendered (before we increment it)
			n.hunterLines[linesRendered] = globalIndex

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

			linesRendered++
		}

		// Add blank line after processor group
		b.WriteString("\n")
		linesRendered++
	}
}

// renderFlatView renders hunters in a flat table (no processors grouping)
func (n *NodesView) renderFlatView(b *strings.Builder) {
	// This is a fallback case - shouldn't normally be used with current architecture
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

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(n.theme.BorderColor)
	separator := sepStyle.Render(strings.Repeat("─", n.width))
	b.WriteString(separator + "\n")

	// Render all hunters
	for i, hunter := range n.hunters {
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

		// Format row string
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
			rowStyle := lipgloss.NewStyle().
				Foreground(n.theme.SelectionBg).
				Reverse(true).
				Bold(true)

			renderedRow := rowStyle.Render(row)
			rowLen := lipgloss.Width(renderedRow)
			if rowLen < n.width {
				padding := n.width - rowLen
				renderedRow += rowStyle.Render(strings.Repeat(" ", padding))
			}
			b.WriteString(renderedRow + "\n")
		} else {
			b.WriteString(row + "\n")
		}
	}
}

func (n *NodesView) View() string {
	if !n.ready {
		return ""
	}

	var b strings.Builder

	// Track input field position for mouse clicks
	// Line 0: "Add Node:" label (not clickable)
	// Lines 1-3: Bordered input box (clickable)
	n.inputStartLine = 0
	n.inputEndLine = 2

	// Label and input at top
	labelStyle := lipgloss.NewStyle().
		Foreground(n.theme.InfoColor).
		Bold(true)

	b.WriteString(labelStyle.Render("Add Node:") + "\n")

	// Input border color logic
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

	// Render viewport with scrollable content
	b.WriteString(n.viewport.View())

	return b.String()
}

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

	// Input field occupies lines 0-3 (label + bordered input)
	// Line 0: "Add Node:" label
	// Lines 1-3: Bordered input (top border, content, bottom border)
	// The two \n after input are part of the viewport content, not the input field
	inputFieldHeight := 4

	// DEBUG: Uncomment to see computed click positions and tracked regions
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "      -> clickY=%d inputStart=%d inputEnd=%d viewport.YOffset=%d hunterLines=%v\n",
	// 		clickY, n.inputStartLine, n.inputEndLine, n.viewport.YOffset, n.hunterLines)
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

	// Check if clicked on a hunter row within the viewport
	if clickY > n.inputEndLine {
		// Click is below input field - it's in the viewport area
		// Calculate the line within the viewport content
		viewportClickY := clickY - inputFieldHeight
		// Add viewport scroll offset to get the actual content line
		contentLineY := viewportClickY + n.viewport.YOffset

		// DEBUG: Uncomment to see viewport click calculation
		// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		// 	fmt.Fprintf(f, "      -> viewportClickY=%d contentLineY=%d\n", viewportClickY, contentLineY)
		// 	f.Close()
		// }

		if hunterIndex, ok := n.hunterLines[contentLineY]; ok {
			// DEBUG: Uncomment to confirm hunter row clicks
			// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			// 	fmt.Fprintf(f, "      -> CLICKED ON HUNTER %d\n", hunterIndex)
			// 	f.Close()
			// }
			// Select this hunter
			n.selectedIndex = hunterIndex
			n.editing = false
			n.nodeInput.Blur()
			n.updateViewportContent() // Refresh to show selection
			return nil
		}
	}

	// DEBUG: Uncomment to see when clicks don't match any region
	// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
	// 	fmt.Fprintf(f, "      -> NO MATCH for click\n")
	// 	f.Close()
	// }

	return nil
}
