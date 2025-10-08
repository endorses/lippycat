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
	processors            []ProcessorInfo // Grouped by processor
	hunters               []HunterInfo    // Flat list for backward compatibility
	selectedIndex         int             // -1 means input is focused/editing, >= 0 means hunter is selected
	selectedProcessorAddr string          // Non-empty means a processor is selected (instead of hunter)
	width                 int
	height                int
	theme         themes.Theme
	nodeInput     textinput.Model // Input field for node address
	editing       bool            // Whether input is in edit mode (red border)
	viewport      viewport.Model  // Viewport for scrolling
	ready         bool            // Whether viewport is initialized
	viewMode      string          // "table" or "graph" - current view mode

	// Mouse click regions
	inputStartLine  int         // Line number where input field starts
	inputEndLine    int         // Line number where input field ends
	hunterLines     map[int]int // Map of line number -> hunter index (for table view)
	processorLines  map[int]int // Map of line number -> processor index (for table view)

	// Graph view click regions
	hunterBoxRegions []struct {
		startLine   int
		endLine     int
		startCol    int
		endCol      int
		hunterIndex int
	}
	processorBoxRegions []struct {
		startLine       int
		endLine         int
		startCol        int
		endCol          int
		processorAddr   string
	}

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
		hunters:               []HunterInfo{},
		selectedIndex:         -1, // Start with input focused (no hunters initially)
		selectedProcessorAddr: "",
		width:                 80,
		height:                20,
		theme:                 themes.Solarized(),
		nodeInput:             ti,
		editing:               false,
		ready:                 false,
		viewMode:              "table", // Start with table view
		hunterLines:           make(map[int]int),
		processorLines:        make(map[int]int),
	}
}

// SetTheme updates the theme
func (n *NodesView) SetTheme(theme themes.Theme) {
	n.theme = theme
}

// ToggleView switches between table and graph view modes
func (n *NodesView) ToggleView() {
	if n.viewMode == "table" {
		n.viewMode = "graph"
	} else {
		n.viewMode = "table"
	}
	n.updateViewportContent()
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
	// Sort processors alphabetically by address
	sort.Slice(processors, func(i, j int) bool {
		return processors[i].Address < processors[j].Address
	})

	// Sort hunters within each processor by ID for consistent ordering
	for i := range processors {
		sort.Slice(processors[i].Hunters, func(a, b int) bool {
			return processors[i].Hunters[a].ID < processors[i].Hunters[b].ID
		})
	}

	n.processors = processors

	// Flatten all hunters from all processors (maintaining sorted order)
	allHunters := make([]HunterInfo, 0)
	for _, proc := range processors {
		allHunters = append(allHunters, proc.Hunters...)
	}
	n.hunters = allHunters

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

// SelectNext moves selection following tree structure: processor → its hunters → next processor → its hunters
func (n *NodesView) SelectNext() {
	// If input is focused, move to first processor
	if n.selectedIndex == -1 && n.selectedProcessorAddr == "" {
		n.editing = false
		n.nodeInput.Blur()

		if len(n.processors) > 0 {
			n.selectedProcessorAddr = n.processors[0].Address
		}
		n.updateViewportContent()
		return
	}

	// If a processor is selected, move to its first hunter or next processor
	if n.selectedProcessorAddr != "" {
		// Find current processor
		var currentProc *ProcessorInfo
		currentProcIdx := -1
		for i, proc := range n.processors {
			if proc.Address == n.selectedProcessorAddr {
				currentProc = &n.processors[i]
				currentProcIdx = i
				break
			}
		}

		if currentProc != nil && len(currentProc.Hunters) > 0 {
			// Move to first hunter of this processor
			n.selectedProcessorAddr = ""
			// Find global index of this hunter
			n.selectedIndex = n.getGlobalHunterIndex(currentProc.Hunters[0].ID, currentProc.Address)
		} else {
			// No hunters, move to next processor or wrap to input
			if currentProcIdx < len(n.processors)-1 {
				n.selectedProcessorAddr = n.processors[currentProcIdx+1].Address
			} else {
				// Last processor, wrap to input
				n.selectedProcessorAddr = ""
				n.selectedIndex = -1
			}
		}
		n.updateViewportContent()
		return
	}

	// If a hunter is selected, move to next hunter of same processor or next processor
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		currentHunter := n.hunters[n.selectedIndex]

		// Find which processor this hunter belongs to and its position
		for procIdx, proc := range n.processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					// Found the hunter, check if there's a next hunter in this processor
					if hunterIdx < len(proc.Hunters)-1 {
						// Move to next hunter in same processor
						n.selectedIndex = n.getGlobalHunterIndex(proc.Hunters[hunterIdx+1].ID, proc.Address)
					} else {
						// Last hunter of this processor, move to next processor or wrap
						n.selectedIndex = -1
						if procIdx < len(n.processors)-1 {
							n.selectedProcessorAddr = n.processors[procIdx+1].Address
						} else {
							// Last processor, wrap to input
							n.selectedProcessorAddr = ""
						}
					}
					n.updateViewportContent()
					return
				}
			}
		}
	}
}

// getGlobalHunterIndex finds the global index of a hunter by ID and processor address
func (n *NodesView) getGlobalHunterIndex(hunterID string, processorAddr string) int {
	for i, hunter := range n.hunters {
		if hunter.ID == hunterID && hunter.ProcessorAddr == processorAddr {
			return i
		}
	}
	return 0
}

// SelectPrevious moves selection following tree structure in reverse: hunters ← processor ← previous processor
func (n *NodesView) SelectPrevious() {
	// If at input, wrap to last hunter of last processor (or last processor if it has no hunters)
	if n.selectedIndex == -1 && n.selectedProcessorAddr == "" {
		if len(n.processors) > 0 {
			lastProc := n.processors[len(n.processors)-1]
			if len(lastProc.Hunters) > 0 {
				// Move to last hunter of last processor
				lastHunter := lastProc.Hunters[len(lastProc.Hunters)-1]
				n.selectedIndex = n.getGlobalHunterIndex(lastHunter.ID, lastProc.Address)
			} else {
				// Last processor has no hunters, select the processor itself
				n.selectedProcessorAddr = lastProc.Address
			}
		}
		n.updateViewportContent()
		return
	}

	// If a processor is selected, move to previous processor's last hunter or previous processor
	if n.selectedProcessorAddr != "" {
		// Find current processor index
		currentProcIdx := -1
		for i, proc := range n.processors {
			if proc.Address == n.selectedProcessorAddr {
				currentProcIdx = i
				break
			}
		}

		if currentProcIdx > 0 {
			// Move to previous processor's last hunter (or the processor if no hunters)
			prevProc := n.processors[currentProcIdx-1]
			n.selectedProcessorAddr = ""
			if len(prevProc.Hunters) > 0 {
				lastHunter := prevProc.Hunters[len(prevProc.Hunters)-1]
				n.selectedIndex = n.getGlobalHunterIndex(lastHunter.ID, prevProc.Address)
			} else {
				// Previous processor has no hunters, select it
				n.selectedProcessorAddr = prevProc.Address
			}
		} else {
			// First processor, move to input
			n.selectedProcessorAddr = ""
			n.selectedIndex = -1
		}
		n.updateViewportContent()
		return
	}

	// If a hunter is selected, move to previous hunter or to processor
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		currentHunter := n.hunters[n.selectedIndex]

		// Find which processor this hunter belongs to and its position
		for _, proc := range n.processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					if hunterIdx > 0 {
						// Move to previous hunter in same processor
						n.selectedIndex = n.getGlobalHunterIndex(proc.Hunters[hunterIdx-1].ID, proc.Address)
					} else {
						// First hunter of this processor, move to the processor itself
						n.selectedIndex = -1
						n.selectedProcessorAddr = proc.Address
					}
					n.updateViewportContent()
					return
				}
			}
		}
	}
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
		// Check if input is focused (selectedIndex = -1 and no processor selected)
		if n.selectedIndex == -1 && n.selectedProcessorAddr == "" {
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
	n.processorLines = make(map[int]int)

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

	// Render based on view mode
	if n.viewMode == "graph" {
		// Graph view: Box drawing visualization
		n.renderGraphView(&b)
	} else {
		// Table view: Tree structure with table columns
		if len(n.processors) > 0 {
			n.renderTreeView(&b)
		} else {
			// Flat view (if no processors but have hunters)
			n.renderFlatView(&b)
		}
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

	for procIdx, proc := range n.processors {
		// Track this processor's line position for mouse clicks
		n.processorLines[linesRendered] = procIdx

		// Processor header with ID (if available)
		var procLine string
		if proc.ProcessorID != "" {
			procLine = fmt.Sprintf("📡 Processor: %s [%s] (%d hunters)", proc.Address, proc.ProcessorID, len(proc.Hunters))
		} else {
			procLine = fmt.Sprintf("📡 Processor: %s (%d hunters)", proc.Address, len(proc.Hunters))
		}

		// Apply selection styling if this processor is selected
		if n.selectedProcessorAddr == proc.Address {
			b.WriteString(selectedStyle.Width(n.width).Render(procLine) + "\n")
		} else {
			b.WriteString(processorStyle.Render(procLine) + "\n")
		}
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

// renderGraphView renders the processors and hunters in a graph-like visualization using box drawing characters
func (n *NodesView) renderGraphView(b *strings.Builder) {
	// Reset click regions for graph view
	n.hunterBoxRegions = make([]struct {
		startLine   int
		endLine     int
		startCol    int
		endCol      int
		hunterIndex int
	}, 0)
	n.processorBoxRegions = make([]struct {
		startLine     int
		endLine       int
		startCol      int
		endCol        int
		processorAddr string
	}, 0)

	// Style for processor and hunter boxes
	processorStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(n.theme.InfoColor)

	hunterStyle := lipgloss.NewStyle().
		Foreground(n.theme.Foreground)

	selectedStyle := lipgloss.NewStyle().
		Foreground(n.theme.SelectionBg).
		Reverse(true).
		Bold(true)

	// Sort processors consistently before rendering
	sortedProcs := make([]ProcessorInfo, len(n.processors))
	copy(sortedProcs, n.processors)
	sort.Slice(sortedProcs, func(i, j int) bool {
		return sortedProcs[i].Address < sortedProcs[j].Address
	})

	// Track current line number for click region tracking
	currentLine := 0

	// Calculate the maximum number of hunters across all processors
	maxHunters := 0
	for _, proc := range sortedProcs {
		if len(proc.Hunters) > maxHunters {
			maxHunters = len(proc.Hunters)
		}
	}

	// Calculate responsive box widths based on terminal width
	// Adjust box sizes and spacing to fit available width
	processorBoxWidth := 40
	hunterBoxWidth := 28
	hunterSpacing := 8

	if maxHunters > 0 {
		// Calculate required width for current settings
		requiredWidth := maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

		// If it doesn't fit, scale down
		if requiredWidth > n.width {
			// Try smaller boxes first
			hunterBoxWidth = 24
			requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

			if requiredWidth > n.width {
				// Still doesn't fit - reduce spacing
				hunterSpacing = 4
				requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

				if requiredWidth > n.width {
					// Still doesn't fit - make boxes even smaller
					hunterBoxWidth = 20
					requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

					if requiredWidth > n.width {
						// Last resort - minimal spacing
						hunterSpacing = 2
						// Calculate minimum possible box width
						availableWidth := n.width - (maxHunters-1)*hunterSpacing - 20
						hunterBoxWidth = availableWidth / maxHunters
						if hunterBoxWidth < 18 {
							hunterBoxWidth = 18 // Absolute minimum
						}
					}
				}
			}

			// Also scale down processor box if needed
			if processorBoxWidth > n.width-20 {
				processorBoxWidth = n.width - 20
				if processorBoxWidth < 30 {
					processorBoxWidth = 30
				}
			}
		}
	}

	renderWidth := n.width

	// Render each processor and its hunters
	for procIdx, proc := range sortedProcs {
		// Ensure hunters are sorted consistently within this processor
		sortedHunters := make([]HunterInfo, len(proc.Hunters))
		copy(sortedHunters, proc.Hunters)
		sort.Slice(sortedHunters, func(i, j int) bool {
			return sortedHunters[i].ID < sortedHunters[j].ID
		})
		proc.Hunters = sortedHunters
		if procIdx > 0 {
			// Add spacing between processor groups
			b.WriteString("\n\n")
			currentLine += 2
		}

		// Processor box
		var procLines []string
		procHeader := fmt.Sprintf("Processor-%d", procIdx+1)
		if proc.ProcessorID != "" {
			procHeader = proc.ProcessorID
		}
		procLines = append(procLines, procHeader)
		procLines = append(procLines, proc.Address)

		// Determine if processor is selected
		isProcessorSelected := n.selectedProcessorAddr == proc.Address

		// Render processor box (centered) with selection styling
		// In graph view, we want to change border color (like hunters), not text color
		processorBox := n.renderProcessorBox(procLines, processorBoxWidth, processorStyle, isProcessorSelected)

		// Center the processor box
		centerPos := (renderWidth - processorBoxWidth) / 2
		if centerPos < 0 {
			centerPos = 0
		}

		// Track click region for processor box
		processorStartLine := currentLine
		processorBoxLines := strings.Split(processorBox, "\n")
		n.processorBoxRegions = append(n.processorBoxRegions, struct {
			startLine     int
			endLine       int
			startCol      int
			endCol        int
			processorAddr string
		}{
			startLine:     processorStartLine,
			endLine:       processorStartLine + len(processorBoxLines) - 1,
			startCol:      centerPos,
			endCol:        centerPos + processorBoxWidth,
			processorAddr: proc.Address,
		})

		for _, line := range processorBoxLines {
			b.WriteString(strings.Repeat(" ", centerPos))
			b.WriteString(line)
			b.WriteString("\n")
			currentLine++
		}

		// Draw connection lines from processor to hunters
		if len(proc.Hunters) > 0 {
			// Draw downward arrow from processor
			arrowPos := centerPos + processorBoxWidth/2
			b.WriteString(strings.Repeat(" ", arrowPos))
			b.WriteString("│\n")
			currentLine++

			// Calculate positions for hunters (distribute horizontally)
			totalHuntersWidth := len(proc.Hunters)*hunterBoxWidth + (len(proc.Hunters)-1)*hunterSpacing
			startPos := (renderWidth - totalHuntersWidth) / 2
			if startPos < 0 {
				startPos = 0
			}

			// Draw horizontal line connecting to hunters
			if len(proc.Hunters) > 1 {
				firstHunterCenter := startPos + hunterBoxWidth/2
				lastHunterCenter := startPos + (len(proc.Hunters)-1)*(hunterBoxWidth+hunterSpacing) + hunterBoxWidth/2
				lineStart := firstHunterCenter
				lineEnd := lastHunterCenter

				// Check if we have an odd number of hunters (3+)
				// In this case, the middle hunter aligns with the processor center
				hasOddHunters := len(proc.Hunters) >= 3 && len(proc.Hunters)%2 == 1

				// Draw the horizontal connector line
				for i := 0; i < renderWidth; i++ {
					if i == centerPos+processorBoxWidth/2 {
						// If odd number of hunters, use cross (┼) since vertical lines align
						// Otherwise use upward branch (┴)
						if hasOddHunters {
							b.WriteString("┼")
						} else {
							b.WriteString("┴")
						}
					} else if i >= lineStart && i <= lineEnd {
						if i == firstHunterCenter {
							b.WriteString("╭")
						} else if i == lastHunterCenter {
							b.WriteString("╮")
						} else {
							// Check if this is a hunter center position
							isHunterCenter := false
							for hIdx := 1; hIdx < len(proc.Hunters)-1; hIdx++ {
								hunterCenter := startPos + hIdx*(hunterBoxWidth+hunterSpacing) + hunterBoxWidth/2
								if i == hunterCenter {
									b.WriteString("┬")
									isHunterCenter = true
									break
								}
							}
							if !isHunterCenter {
								b.WriteString("─")
							}
						}
					} else {
						b.WriteString(" ")
					}
				}
				b.WriteString("\n")
				currentLine++

				// Draw vertical lines down to hunter boxes
				for i := 0; i < renderWidth; i++ {
					isHunterCenter := false
					for hIdx := 0; hIdx < len(proc.Hunters); hIdx++ {
						hunterCenter := startPos + hIdx*(hunterBoxWidth+hunterSpacing) + hunterBoxWidth/2
						if i == hunterCenter {
							b.WriteString("│")
							isHunterCenter = true
							break
						}
					}
					if !isHunterCenter {
						b.WriteString(" ")
					}
				}
				b.WriteString("\n")
				currentLine++
			} else {
				// Single hunter - just a straight line
				linePos := centerPos + processorBoxWidth/2
				b.WriteString(strings.Repeat(" ", linePos))
				b.WriteString("│\n")
				currentLine++
			}

			// Render hunter boxes
			type HunterBoxContent struct {
				HeaderLines []string
				BodyLines   []string
			}
			hunterBoxContents := make([]HunterBoxContent, 0)
			for hIdx, hunter := range proc.Hunters {
				var headerLines []string
				var bodyLines []string

				// Hunter header (centered, bold)
				hunterName := fmt.Sprintf("Hunter-%d", hIdx+1)
				if hunter.ID != "" {
					hunterName = hunter.ID
					if len(hunterName) > hunterBoxWidth-2 {
						hunterName = hunterName[:hunterBoxWidth-5] + "..."
					}
				}
				headerLines = append(headerLines, hunterName)

				// IP address (shortened) (centered, bold)
				ip := hunter.Hostname
				if len(ip) > hunterBoxWidth-2 {
					ip = ip[:hunterBoxWidth-5] + "..."
				}
				headerLines = append(headerLines, ip)

				// Body content (left-aligned, not bold, with aligned values)
				const labelWidth = 10 // Width for label column

				// Interface
				iface := "any"
				if len(hunter.Interfaces) > 0 {
					iface = hunter.Interfaces[0]
				}
				bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Interface:", truncateString(iface, hunterBoxWidth-labelWidth-2)))

				// Uptime
				var uptimeStr string
				if hunter.ConnectedAt > 0 {
					uptime := time.Now().UnixNano() - hunter.ConnectedAt
					uptimeStr = formatDuration(uptime)
				} else {
					uptimeStr = "-"
				}
				bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Uptime:", uptimeStr))

				// Captured
				bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Captured:", formatPacketNumber(hunter.PacketsCaptured)))

				// Forwarded
				bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Forwarded:", formatPacketNumber(hunter.PacketsForwarded)))

				// Filters
				bodyLines = append(bodyLines, fmt.Sprintf("%-*s %d", labelWidth, "Filters:", hunter.ActiveFilters))

				hunterBoxContents = append(hunterBoxContents, HunterBoxContent{
					HeaderLines: headerLines,
					BodyLines:   bodyLines,
				})
			}

			// Render hunter boxes line by line (so they align horizontally)
			// First, render all boxes
			renderedBoxes := make([][]string, len(hunterBoxContents))
			for hIdx, content := range hunterBoxContents {
				// Calculate global hunter index for selection
				globalIndex := 0
				found := false
				for _, p := range n.processors {
					for _, h := range p.Hunters {
						if h.ID == proc.Hunters[hIdx].ID && h.ProcessorAddr == proc.Hunters[hIdx].ProcessorAddr {
							found = true
							break
						}
						globalIndex++
					}
					if found {
						break
					}
				}

				var boxStyle lipgloss.Style
				isSelected := globalIndex == n.selectedIndex
				if isSelected {
					boxStyle = selectedStyle
				} else {
					boxStyle = hunterStyle
				}

				// Get status color for this hunter
				hunter := proc.Hunters[hIdx]
				box := n.renderHunterBox(content.HeaderLines, content.BodyLines, hunterBoxWidth, boxStyle, isSelected, hunter.Status)
				renderedBoxes[hIdx] = strings.Split(box, "\n")
			}

			// Render boxes side by side
			maxBoxLines := 0
			for _, box := range renderedBoxes {
				if len(box) > maxBoxLines {
					maxBoxLines = len(box)
				}
			}

			// Track click regions for each hunter box
			hunterStartLine := currentLine
			for hIdx := 0; hIdx < len(renderedBoxes); hIdx++ {
				// Calculate global hunter index
				globalIndex := 0
				found := false
				for _, p := range n.processors {
					for _, h := range p.Hunters {
						if h.ID == proc.Hunters[hIdx].ID && h.ProcessorAddr == proc.Hunters[hIdx].ProcessorAddr {
							found = true
							break
						}
						globalIndex++
					}
					if found {
						break
					}
				}

				// Calculate horizontal position
				var startCol int
				if hIdx == 0 {
					startCol = startPos
				} else {
					startCol = startPos + hIdx*(hunterBoxWidth+hunterSpacing)
				}
				endCol := startCol + hunterBoxWidth

				// Register click region
				n.hunterBoxRegions = append(n.hunterBoxRegions, struct {
					startLine   int
					endLine     int
					startCol    int
					endCol      int
					hunterIndex int
				}{
					startLine:   hunterStartLine,
					endLine:     hunterStartLine + maxBoxLines - 1,
					startCol:    startCol,
					endCol:      endCol,
					hunterIndex: globalIndex,
				})
			}

			for lineIdx := 0; lineIdx < maxBoxLines; lineIdx++ {
				for hIdx := 0; hIdx < len(renderedBoxes); hIdx++ {
					// Add spacing before this hunter
					if hIdx > 0 {
						b.WriteString(strings.Repeat(" ", hunterSpacing))
					} else {
						b.WriteString(strings.Repeat(" ", startPos))
					}

					// Render this line of the hunter box
					if lineIdx < len(renderedBoxes[hIdx]) {
						b.WriteString(renderedBoxes[hIdx][lineIdx])
					} else {
						// Pad with spaces if this box has fewer lines
						b.WriteString(strings.Repeat(" ", hunterBoxWidth))
					}
				}
				b.WriteString("\n")
				currentLine++
			}
		} else {
			// No hunters for this processor
			b.WriteString("\n")
			currentLine++
			emptyStyle := lipgloss.NewStyle().
				Foreground(lipgloss.Color("240"))
			emptyLine := emptyStyle.Render("(no hunters connected)")
			b.WriteString(strings.Repeat(" ", centerPos))
			b.WriteString(emptyLine)
			b.WriteString("\n")
			currentLine++
		}
	}
}

// renderBox renders a box with rounded corners around the given lines
func (n *NodesView) renderBox(lines []string, width int, style lipgloss.Style) string {
	var b strings.Builder

	// Top border
	b.WriteString("╭")
	b.WriteString(strings.Repeat("─", width-2))
	b.WriteString("╮")
	b.WriteString("\n")

	// Content lines
	for _, line := range lines {
		// Truncate or pad to fit width
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString("│ ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(style.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" │")
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString("╰")
	b.WriteString(strings.Repeat("─", width-2))
	b.WriteString("╯")

	return b.String()
}

// renderProcessorBox renders a processor box with optional selection highlighting
func (n *NodesView) renderProcessorBox(lines []string, width int, style lipgloss.Style, isSelected bool) string {
	var b strings.Builder

	// For selected boxes, use cyan border and normal text colors
	// For unselected boxes, use default theme colors
	var borderStyle lipgloss.Style
	var contentStyle lipgloss.Style
	var topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical string

	if isSelected {
		// Selected: cyan border with heavy/bold box characters
		borderStyle = lipgloss.NewStyle().Foreground(n.theme.SelectionBg)
		contentStyle = style
		topLeft = "┏"
		topRight = "┓"
		bottomLeft = "┗"
		bottomRight = "┛"
		horizontal = "━"
		vertical = "┃"
	} else {
		// Unselected: gray border with light rounded box characters
		borderStyle = lipgloss.NewStyle().Foreground(n.theme.Foreground)
		contentStyle = style
		topLeft = "╭"
		topRight = "╮"
		bottomLeft = "╰"
		bottomRight = "╯"
		horizontal = "─"
		vertical = "│"
	}

	// Top border
	b.WriteString(borderStyle.Render(topLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(topRight))
	b.WriteString("\n")

	// Content lines
	for _, line := range lines {
		// Truncate or pad to fit width
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(contentStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString(borderStyle.Render(bottomLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(bottomRight))

	return b.String()
}

// renderHunterBox renders a hunter box with centered bold headers and left-aligned body
func (n *NodesView) renderHunterBox(headerLines []string, bodyLines []string, width int, baseStyle lipgloss.Style, isSelected bool, status management.HunterStatus) string {
	var b strings.Builder

	// Determine status color for header text
	var statusColor lipgloss.Color
	switch status {
	case management.HunterStatus_STATUS_HEALTHY:
		statusColor = n.theme.SuccessColor
	case management.HunterStatus_STATUS_WARNING:
		statusColor = n.theme.WarningColor
	case management.HunterStatus_STATUS_ERROR:
		statusColor = n.theme.ErrorColor
	case management.HunterStatus_STATUS_STOPPING:
		statusColor = lipgloss.Color("240")
	default:
		statusColor = n.theme.SuccessColor
	}

	// For selected boxes, use cyan border and status-colored text
	// For unselected boxes, use default border and status-colored text
	var borderStyle lipgloss.Style
	var headerStyle lipgloss.Style
	var bodyStyle lipgloss.Style
	var topLeft, topRight, bottomLeft, bottomRight, horizontal, vertical string

	if isSelected {
		// Selected: cyan border with heavy/bold box characters, status-colored header text
		borderStyle = lipgloss.NewStyle().Foreground(n.theme.SelectionBg)
		headerStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		bodyStyle = lipgloss.NewStyle().Foreground(n.theme.Foreground).Bold(false)
		topLeft = "┏"
		topRight = "┓"
		bottomLeft = "┗"
		bottomRight = "┛"
		horizontal = "━"
		vertical = "┃"
	} else {
		// Unselected: normal border with light rounded box characters, status-colored header text
		borderStyle = lipgloss.NewStyle().Foreground(n.theme.Foreground)
		headerStyle = lipgloss.NewStyle().Foreground(statusColor).Bold(true)
		bodyStyle = baseStyle.Bold(false)
		topLeft = "╭"
		topRight = "╮"
		bottomLeft = "╰"
		bottomRight = "╯"
		horizontal = "─"
		vertical = "│"
	}

	// Top border
	b.WriteString(borderStyle.Render(topLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(topRight))
	b.WriteString("\n")

	// Header lines (centered and bold)
	for _, line := range headerLines {
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4
		leftPad := padding / 2
		rightPad := padding - leftPad

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(strings.Repeat(" ", leftPad))
		b.WriteString(headerStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", rightPad))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Empty line separator between header and body
	b.WriteString(borderStyle.Render(vertical))
	b.WriteString(" ")
	b.WriteString(strings.Repeat(" ", width-4))
	b.WriteString(" ")
	b.WriteString(borderStyle.Render(vertical))
	b.WriteString("\n")

	// Body lines (left-aligned, not bold)
	for _, line := range bodyLines {
		displayLine := line
		if len(displayLine) > width-4 {
			displayLine = displayLine[:width-7] + "..."
		}
		padding := width - len(displayLine) - 4

		b.WriteString(borderStyle.Render(vertical))
		b.WriteString(" ")
		b.WriteString(bodyStyle.Render(displayLine))
		b.WriteString(strings.Repeat(" ", padding))
		b.WriteString(" ")
		b.WriteString(borderStyle.Render(vertical))
		b.WriteString("\n")
	}

	// Bottom border
	b.WriteString(borderStyle.Render(bottomLeft))
	b.WriteString(borderStyle.Render(strings.Repeat(horizontal, width-2)))
	b.WriteString(borderStyle.Render(bottomRight))

	return b.String()
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

	// Input border color and style logic
	var borderColor lipgloss.Color
	var borderStyle lipgloss.Border
	if n.editing {
		borderColor = n.theme.FocusedBorderColor // Red when editing
		borderStyle = lipgloss.ThickBorder()     // Heavy box characters when editing
	} else if n.selectedIndex == -1 && n.selectedProcessorAddr == "" {
		borderColor = n.theme.SelectionBg    // Cyan when focused but not editing
		borderStyle = lipgloss.ThickBorder() // Heavy box characters when focused
	} else {
		borderColor = n.theme.BorderColor       // Gray when unfocused
		borderStyle = lipgloss.RoundedBorder() // Light rounded characters when unfocused
	}

	inputWithBorder := lipgloss.NewStyle().
		BorderStyle(borderStyle).
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
		if n.selectedIndex == -1 && n.selectedProcessorAddr == "" && !n.editing &&
			now.Sub(n.lastClickTime) < doubleClickThreshold {
			// Double-click detected - start editing
			n.editing = true
			n.nodeInput.Focus()
			n.nodeInput.SetValue("")
			return nil
		}

		// Single click - just focus input (don't start editing)
		n.selectedIndex = -1
		n.selectedProcessorAddr = "" // Clear processor selection
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

		// Check graph view click regions first (if in graph view)
		if n.viewMode == "graph" {
			clickX := msg.X

			// Check processor box clicks first
			for _, region := range n.processorBoxRegions {
				if contentLineY >= region.startLine && contentLineY <= region.endLine &&
					clickX >= region.startCol && clickX <= region.endCol {
					// DEBUG: Uncomment to confirm processor box clicks
					// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
					// 	fmt.Fprintf(f, "      -> CLICKED ON PROCESSOR BOX %s (X=%d Y=%d)\n", region.processorAddr, clickX, contentLineY)
					// 	f.Close()
					// }
					// Select this processor
					n.selectedProcessorAddr = region.processorAddr
					n.selectedIndex = -1 // Deselect hunters
					n.editing = false
					n.nodeInput.Blur()
					n.updateViewportContent() // Refresh to show selection
					return nil
				}
			}

			// Check hunter box clicks
			for _, region := range n.hunterBoxRegions {
				if contentLineY >= region.startLine && contentLineY <= region.endLine &&
					clickX >= region.startCol && clickX <= region.endCol {
					// DEBUG: Uncomment to confirm hunter box clicks
					// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
					// 	fmt.Fprintf(f, "      -> CLICKED ON HUNTER BOX %d (X=%d Y=%d)\n", region.hunterIndex, clickX, contentLineY)
					// 	f.Close()
					// }
					// Select this hunter
					n.selectedIndex = region.hunterIndex
					n.selectedProcessorAddr = "" // Deselect processors
					n.editing = false
					n.nodeInput.Blur()
					n.updateViewportContent() // Refresh to show selection
					return nil
				}
			}
		}

		// Check table view processor lines
		if procIdx, ok := n.processorLines[contentLineY]; ok {
			// DEBUG: Uncomment to confirm processor row clicks
			// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			// 	fmt.Fprintf(f, "      -> CLICKED ON PROCESSOR %d\n", procIdx)
			// 	f.Close()
			// }
			// Select this processor
			n.selectedProcessorAddr = n.processors[procIdx].Address
			n.selectedIndex = -1 // Deselect hunters
			n.editing = false
			n.nodeInput.Blur()
			n.updateViewportContent() // Refresh to show selection
			return nil
		}

		// Check table view hunter lines
		if hunterIndex, ok := n.hunterLines[contentLineY]; ok {
			// DEBUG: Uncomment to confirm hunter row clicks
			// if f, err := os.OpenFile("/tmp/lippycat-mouse-debug.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
			// 	fmt.Fprintf(f, "      -> CLICKED ON HUNTER %d\n", hunterIndex)
			// 	f.Close()
			// }
			// Select this hunter
			n.selectedIndex = hunterIndex
			n.selectedProcessorAddr = "" // Deselect processors
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
