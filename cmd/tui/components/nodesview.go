//go:build tui || all
// +build tui all

package components

import (
	"sort"

	// "os" // Only needed for debug logging - uncomment if enabling DEBUG logs
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/components/nodesview"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Type alias for backward compatibility within TUI
// HunterInfo is now defined in internal/pkg/types to enable sharing
type HunterInfo = types.HunterInfo

// Type alias for ProcessorConnectionState from nodesview package
type ProcessorConnectionState = nodesview.ProcessorConnectionState

const (
	ProcessorConnectionStateUnknown      = nodesview.ProcessorConnectionStateUnknown
	ProcessorConnectionStateDisconnected = nodesview.ProcessorConnectionStateDisconnected
	ProcessorConnectionStateConnecting   = nodesview.ProcessorConnectionStateConnecting
	ProcessorConnectionStateConnected    = nodesview.ProcessorConnectionStateConnected
	ProcessorConnectionStateFailed       = nodesview.ProcessorConnectionStateFailed
)

// ProcessorInfo represents a processor node
type ProcessorInfo struct {
	Address         string
	ProcessorID     string                     // ID of the processor
	Status          management.ProcessorStatus // Status of the processor (when connected)
	ConnectionState ProcessorConnectionState   // Connection state (disconnected, connecting, connected, failed)
	TLSInsecure     bool                       // True if connection is insecure (no TLS)
	UpstreamAddr    string                     // Address of upstream processor (if hierarchical)
	Hunters         []HunterInfo               // Hunters subscribed to by this TUI client (filtered)
	TotalHunters    int                        // Total hunters connected to this processor (all hunters)
}

// AddNodeMsg is sent when user wants to add a node
type AddNodeMsg struct {
	Address string // host:port
}

// NodesView displays connected hunter nodes in a tree view grouped by processor
type NodesView struct {
	processors            []ProcessorInfo // Grouped by processor
	hunters               []HunterInfo    // Flat list for backward compatibility
	selectedIndex         int             // -1 means nothing selected, >= 0 means hunter is selected
	selectedProcessorAddr string          // Non-empty means a processor is selected (instead of hunter)
	width                 int
	height                int
	theme                 themes.Theme
	nodeInput             textinput.Model // Input field for node address (used in modal)
	showModal             bool            // Whether add node modal is visible
	viewport              viewport.Model  // Viewport for scrolling
	ready                 bool            // Whether viewport is initialized
	viewMode              string          // "table" or "graph" - current view mode

	// Mouse click regions
	hunterLines    map[int]int // Map of line number -> hunter index (for table view)
	processorLines map[int]int // Map of line number -> processor index (for table view)

	// Graph view click regions
	hunterBoxRegions []struct {
		startLine   int
		endLine     int
		startCol    int
		endCol      int
		hunterIndex int
	}
	processorBoxRegions []struct {
		startLine     int
		endLine       int
		startCol      int
		endCol        int
		processorAddr string
	}

	// Graph view navigation memory
	lastSelectedHunterIndex map[string]int // Map of processor address -> last selected hunter index (0-based within that processor)

	// Viewport scrolling
	selectedNodeLine int // Line position of currently selected node in rendered content (-1 if no selection)
}

// NewNodesView creates a new nodes view component
func NewNodesView() NodesView {
	ti := textinput.New()
	ti.Placeholder = "e.g., localhost:50051"
	ti.CharLimit = 256
	ti.Width = 50

	return NodesView{
		hunters:                 []HunterInfo{},
		selectedIndex:           -1, // Start with nothing selected
		selectedProcessorAddr:   "",
		width:                   80,
		height:                  20,
		theme:                   themes.Solarized(),
		nodeInput:               ti,
		showModal:               false,
		ready:                   false,
		viewMode:                "table", // Start with table view
		hunterLines:             make(map[int]int),
		processorLines:          make(map[int]int),
		lastSelectedHunterIndex: make(map[string]int),
		selectedNodeLine:        -1,
	}
}

// SetTheme updates the theme
func (n *NodesView) SetTheme(theme themes.Theme) {
	n.theme = theme
}

// ShowAddNodeModal shows the add node modal
func (n *NodesView) ShowAddNodeModal() {
	n.showModal = true
	n.nodeInput.Focus()
	n.nodeInput.SetValue("")
}

// HideAddNodeModal hides the add node modal
func (n *NodesView) HideAddNodeModal() {
	n.showModal = false
	n.nodeInput.Blur()
	n.nodeInput.SetValue("")
}

// IsModalOpen returns whether the add node modal is open
func (n *NodesView) IsModalOpen() bool {
	return n.showModal
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

	// Use full height for viewport (hints moved to context-aware footer)
	viewportHeight := max(1, height)

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
			Address:      addr,
			Hunters:      hunterList,
			TotalHunters: len(hunterList),
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
			Address:      addr,
			Hunters:      hunterList,
			TotalHunters: len(hunterList),
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

	// Validate and adjust selection after update
	if n.selectedIndex >= 0 {
		// A hunter was selected - check if it still exists
		if n.selectedIndex >= len(n.hunters) {
			// Selected hunter disappeared - move selection to first processor
			n.selectedIndex = -1
			if len(n.processors) > 0 {
				n.selectedProcessorAddr = n.processors[0].Address
			} else {
				n.selectedProcessorAddr = ""
			}
		}
	} else if n.selectedProcessorAddr != "" {
		// Processor selected - verify it still exists
		found := false
		for _, proc := range n.processors {
			if proc.Address == n.selectedProcessorAddr {
				found = true
				break
			}
		}
		if !found {
			// Selected processor disappeared
			n.selectedProcessorAddr = ""
			n.selectedIndex = -1
		}
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
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectNext(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// SelectPrevious moves selection following tree structure in reverse: hunters ← processor ← previous processor
func (n *NodesView) SelectPrevious() {
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectPrevious(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// GetViewMode returns the current view mode ("table" or "graph")
func (n *NodesView) GetViewMode() string {
	return n.viewMode
}

// SelectUp moves selection up in graph mode (vertical navigation through hierarchy)
func (n *NodesView) SelectUp() {
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectUp(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// SelectDown moves selection down in graph mode (vertical navigation through hierarchy)
func (n *NodesView) SelectDown() {
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectDown(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// SelectLeft moves selection left in graph mode (horizontal navigation within same processor)
func (n *NodesView) SelectLeft() {
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectLeft(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// SelectRight moves selection right in graph mode (horizontal navigation within same processor)
func (n *NodesView) SelectRight() {
	params := nodesview.NavigationParams{
		Processors:              convertProcessorInfos(n.processors),
		Hunters:                 n.hunters,
		SelectedIndex:           n.selectedIndex,
		SelectedProcessorAddr:   n.selectedProcessorAddr,
		LastSelectedHunterIndex: n.lastSelectedHunterIndex,
	}
	result := nodesview.SelectRight(params)
	n.selectedIndex = result.SelectedIndex
	n.selectedProcessorAddr = result.SelectedProcessorAddr
	n.lastSelectedHunterIndex = result.LastSelectedHunterIndex
	n.updateViewportContent()
}

// Update handles key presses and mouse events
func (n *NodesView) Update(msg tea.Msg) tea.Cmd {
	var cmd tea.Cmd

	switch msg := msg.(type) {
	case tea.MouseMsg:
		// If modal is open, don't handle mouse events on the underlying content
		if n.showModal {
			return nil
		}
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
		// Handle modal input if modal is open
		if n.showModal {
			switch msg.String() {
			case "enter":
				// Submit node address
				addr := n.nodeInput.Value()
				if addr != "" {
					n.HideAddNodeModal()
					return func() tea.Msg {
						return AddNodeMsg{Address: addr}
					}
				}
				// If empty, just close modal
				n.HideAddNodeModal()
				return nil
			case "esc":
				// Cancel and close modal
				n.HideAddNodeModal()
				return nil
			default:
				// Pass other keys to input field
				n.nodeInput, cmd = n.nodeInput.Update(msg)
				return cmd
			}
		}

		// Normal mode - pass keyboard events to viewport for scrolling
		n.viewport, cmd = n.viewport.Update(msg)
		return cmd
	}

	return nil
}

// IsEditing returns whether the add node modal is open (for compatibility)
func (n *NodesView) IsEditing() bool {
	return n.showModal
}

// GetSelectedHunter returns the currently selected hunter
func (n *NodesView) GetSelectedHunter() *HunterInfo {
	if n.selectedIndex >= 0 && n.selectedIndex < len(n.hunters) {
		return &n.hunters[n.selectedIndex]
	}
	return nil
}

// GetSelectedProcessorAddr returns the address of the currently selected processor (or empty if hunter selected)
func (n *NodesView) GetSelectedProcessorAddr() string {
	return n.selectedProcessorAddr
}

// GetHuntersForProcessor returns the list of hunters for a given processor address
func (n *NodesView) GetHuntersForProcessor(processorAddr string) []HunterInfo {
	for _, proc := range n.processors {
		if proc.Address == processorAddr {
			return proc.Hunters
		}
	}
	return []HunterInfo{}
}

// updateViewportContent updates the viewport with current content
func (n *NodesView) updateViewportContent() {
	if !n.ready {
		return
	}
	n.viewport.SetContent(n.renderContent())
	n.scrollToSelection()
}

// scrollToSelection scrolls the viewport to keep the selected node visible
func (n *NodesView) scrollToSelection() {
	if n.selectedNodeLine < 0 {
		return // No selection
	}

	viewportHeight := n.viewport.Height
	if viewportHeight <= 0 {
		return
	}

	if n.viewMode == "graph" {
		// Graph mode: center the selected node vertically
		targetOffset := max(0, n.selectedNodeLine-viewportHeight/2)
		// Don't scroll past the end of content
		maxOffset := max(0, n.viewport.TotalLineCount()-viewportHeight)
		if targetOffset > maxOffset {
			targetOffset = maxOffset
		}
		n.viewport.SetYOffset(targetOffset)
	} else {
		// Table mode: minimal scrolling - just keep selection visible
		currentOffset := n.viewport.YOffset
		visibleStart := currentOffset
		visibleEnd := currentOffset + viewportHeight - 1

		// If selection is above visible area, scroll up to show it
		if n.selectedNodeLine < visibleStart {
			n.viewport.SetYOffset(n.selectedNodeLine)
		} else if n.selectedNodeLine > visibleEnd {
			// If selection is below visible area, scroll down to show it
			newOffset := max(0, n.selectedNodeLine-viewportHeight+1)
			n.viewport.SetYOffset(newOffset)
		}
		// Otherwise, selection is already visible - don't scroll
	}
}

// convertProcessorInfos converts local ProcessorInfo to nodesview.ProcessorInfo
func convertProcessorInfos(procs []ProcessorInfo) []nodesview.ProcessorInfo {
	result := make([]nodesview.ProcessorInfo, len(procs))
	for i, proc := range procs {
		result[i] = nodesview.ProcessorInfo{
			Address:         proc.Address,
			ProcessorID:     proc.ProcessorID,
			Status:          proc.Status,
			ConnectionState: proc.ConnectionState,
			TLSInsecure:     proc.TLSInsecure,  // Preserve TLS security status
			UpstreamAddr:    proc.UpstreamAddr, // Preserve upstream processor address
			Hunters:         proc.Hunters,
			TotalHunters:    proc.TotalHunters,
		}
	}
	return result
}

// renderContent renders the tree view content as a string for the viewport
func (n *NodesView) renderContent() string {
	var b strings.Builder

	// Reset mouse click regions and selection tracking
	n.hunterLines = make(map[int]int)
	n.processorLines = make(map[int]int)
	n.selectedNodeLine = -1

	if len(n.processors) == 0 && len(n.hunters) == 0 {
		// Empty state - no processors and no hunters
		emptyStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240"))

		// Create content block
		var emptyContent strings.Builder
		emptyContent.WriteString("No nodes connected\n\n")
		emptyContent.WriteString("Press 'a' to add a node\n\n")
		emptyContent.WriteString("Or start a hunter with:\n")
		emptyContent.WriteString("lc hunt --processor <processor-addr>")

		content := emptyContent.String()

		// Center the content block vertically and horizontally like graph view
		lines := strings.Split(content, "\n")

		// Calculate vertical centering
		contentHeight := len(lines)
		viewportHeight := n.viewport.Height
		verticalPadding := max(0, (viewportHeight-contentHeight)/2)

		// Add vertical padding
		for range verticalPadding {
			b.WriteString("\n")
		}

		// Render each line centered horizontally
		for _, line := range lines {
			if line != "" {
				lineWidth := len(line)
				centerPos := max(0, (n.width-lineWidth)/2)
				b.WriteString(strings.Repeat(" ", centerPos))
				b.WriteString(emptyStyle.Render(line))
			}
			b.WriteString("\n")
		}

		return b.String()
	}

	// Render based on view mode
	if n.viewMode == "graph" {
		// Graph view: Box drawing visualization
		params := nodesview.GraphViewParams{
			Processors:              convertProcessorInfos(n.processors),
			Hunters:                 n.hunters,
			SelectedIndex:           n.selectedIndex,
			SelectedProcessorAddr:   n.selectedProcessorAddr,
			Width:                   n.width,
			Height:                  n.height,
			Theme:                   n.theme,
			LastSelectedHunterIndex: n.lastSelectedHunterIndex,
		}
		result := nodesview.RenderGraphView(params)
		b.WriteString(result.Content)
		n.selectedNodeLine = result.SelectedNodeLine

		// Update click regions from result
		n.hunterBoxRegions = make([]struct {
			startLine   int
			endLine     int
			startCol    int
			endCol      int
			hunterIndex int
		}, len(result.HunterBoxRegions))
		for i, region := range result.HunterBoxRegions {
			n.hunterBoxRegions[i] = struct {
				startLine   int
				endLine     int
				startCol    int
				endCol      int
				hunterIndex int
			}{
				startLine:   region.StartLine,
				endLine:     region.EndLine,
				startCol:    region.StartCol,
				endCol:      region.EndCol,
				hunterIndex: region.HunterIndex,
			}
		}

		n.processorBoxRegions = make([]struct {
			startLine     int
			endLine       int
			startCol      int
			endCol        int
			processorAddr string
		}, len(result.ProcessorBoxRegions))
		for i, region := range result.ProcessorBoxRegions {
			n.processorBoxRegions[i] = struct {
				startLine     int
				endLine       int
				startCol      int
				endCol        int
				processorAddr string
			}{
				startLine:     region.StartLine,
				endLine:       region.EndLine,
				startCol:      region.StartCol,
				endCol:        region.EndCol,
				processorAddr: region.ProcessorAddr,
			}
		}
	} else {
		// Table view: Tree structure with table columns
		if len(n.processors) > 0 {
			// Use extracted table view rendering
			params := nodesview.TableViewParams{
				Processors:            convertProcessorInfos(n.processors),
				Hunters:               n.hunters,
				SelectedIndex:         n.selectedIndex,
				SelectedProcessorAddr: n.selectedProcessorAddr,
				Width:                 n.width,
				Theme:                 n.theme,
				HunterLines:           n.hunterLines,
				ProcessorLines:        n.processorLines,
			}
			content, selectedLine := nodesview.RenderTreeView(params)
			b.WriteString(content)
			n.selectedNodeLine = selectedLine
		} else {
			// Flat view (if no processors but have hunters)
			params := nodesview.TableViewParams{
				Processors:            nil,
				Hunters:               n.hunters,
				SelectedIndex:         n.selectedIndex,
				SelectedProcessorAddr: "",
				Width:                 n.width,
				Theme:                 n.theme,
				HunterLines:           n.hunterLines,
				ProcessorLines:        n.processorLines,
			}
			content, selectedLine := nodesview.RenderFlatView(params)
			b.WriteString(content)
			n.selectedNodeLine = selectedLine
		}
	}

	content := b.String()

	// In graph mode, center the content vertically if it's shorter than viewport
	if n.viewMode == "graph" && n.ready {
		contentLines := strings.Count(content, "\n")
		viewportHeight := n.viewport.Height

		if viewportHeight > 0 && contentLines < viewportHeight {
			// Calculate top padding to center content
			topPadding := (viewportHeight - contentLines) / 2

			// Prepend empty lines
			paddingStr := strings.Repeat("\n", topPadding)
			content = paddingStr + content

			// Adjust all line tracking by the padding offset
			if n.selectedNodeLine >= 0 {
				n.selectedNodeLine += topPadding
			}

			// Adjust hunter lines map
			newHunterLines := make(map[int]int)
			for line, hunterIdx := range n.hunterLines {
				newHunterLines[line+topPadding] = hunterIdx
			}
			n.hunterLines = newHunterLines

			// Adjust processor lines map
			newProcessorLines := make(map[int]int)
			for line, procIdx := range n.processorLines {
				newProcessorLines[line+topPadding] = procIdx
			}
			n.processorLines = newProcessorLines

			// Adjust hunter box regions
			for i := range n.hunterBoxRegions {
				n.hunterBoxRegions[i].startLine += topPadding
				n.hunterBoxRegions[i].endLine += topPadding
			}

			// Adjust processor box regions
			for i := range n.processorBoxRegions {
				n.processorBoxRegions[i].startLine += topPadding
				n.processorBoxRegions[i].endLine += topPadding
			}
		}
	}

	return content
}

func (n *NodesView) View() string {
	if !n.ready {
		return ""
	}

	// Just return viewport (hints now in context-aware footer)
	return n.viewport.View()
}

// RenderModal renders the add node modal if it's open (for top-level overlay)
func (n *NodesView) RenderModal(width, height int) string {
	if !n.showModal {
		return ""
	}
	return n.renderAddNodeModal(width, height)
}

// renderAddNodeModal renders the add node modal using the unified modal component
func (n *NodesView) renderAddNodeModal(width, height int) string {
	// Calculate modal dimensions
	modalWidth := 60
	if modalWidth > width-4 {
		modalWidth = width - 4
	}
	if modalWidth < 40 {
		modalWidth = 40
	}

	// Build content
	var content strings.Builder

	// Input label
	labelStyle := lipgloss.NewStyle().
		Foreground(n.theme.Foreground).
		Padding(0, 1).
		MarginTop(1)
	content.WriteString(labelStyle.Render("Address (host:port):"))
	content.WriteString("\n")

	// Input field
	inputStyle := lipgloss.NewStyle().
		Padding(0, 1)
	content.WriteString(inputStyle.Render(n.nodeInput.View()))

	// Use unified modal rendering
	return RenderModal(ModalRenderOptions{
		Title:      "Add Node",
		Content:    content.String(),
		Footer:     "Enter: confirm | Esc: cancel",
		Width:      width,
		Height:     height,
		Theme:      n.theme,
		ModalWidth: modalWidth,
	})
}

// handleMouseClick handles mouse click events
func (n *NodesView) handleMouseClick(msg tea.MouseMsg) tea.Cmd {
	// Convert internal box regions to the format expected by the pure function
	hunterBoxRegions := make([]nodesview.HunterBoxRegion, len(n.hunterBoxRegions))
	for i, region := range n.hunterBoxRegions {
		hunterBoxRegions[i] = nodesview.HunterBoxRegion{
			StartLine:   region.startLine,
			EndLine:     region.endLine,
			StartCol:    region.startCol,
			EndCol:      region.endCol,
			HunterIndex: region.hunterIndex,
		}
	}

	processorBoxRegions := make([]nodesview.ProcessorBoxRegion, len(n.processorBoxRegions))
	for i, region := range n.processorBoxRegions {
		processorBoxRegions[i] = nodesview.ProcessorBoxRegion{
			StartLine:     region.startLine,
			EndLine:       region.endLine,
			StartCol:      region.startCol,
			EndCol:        region.endCol,
			ProcessorAddr: region.processorAddr,
		}
	}

	// Call the pure function to handle the click
	result := nodesview.HandleMouseClick(nodesview.MouseClickParams{
		ViewMode:            n.viewMode,
		MouseMsg:            msg,
		ViewportYOffset:     n.viewport.YOffset,
		HunterLines:         n.hunterLines,
		ProcessorLines:      n.processorLines,
		HunterBoxRegions:    hunterBoxRegions,
		ProcessorBoxRegions: processorBoxRegions,
		Processors:          convertProcessorInfos(n.processors),
	})

	// Apply the result if the click was handled
	if result.WasHandled {
		n.selectedIndex = result.SelectedIndex
		n.selectedProcessorAddr = result.SelectedProcessorAddr
		n.updateViewportContent() // Refresh to show selection
	}

	return nil
}
