//go:build tui || all

package nodesview

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ProcessorInfo represents a processor node (local definition to avoid import cycles)
type ProcessorInfo struct {
	Address           string
	ProcessorID       string
	Status            management.ProcessorStatus
	ConnectionState   ProcessorConnectionState
	TLSInsecure       bool   // True if connection is insecure (no TLS)
	UpstreamAddr      string // Address of upstream processor (if hierarchical)
	Hunters           []types.HunterInfo
	TotalHunters      int                 // Total hunters connected to this processor (all hunters)
	HierarchyDepth    int                 // Depth in hierarchy (0 = root, 1 = first level downstream, etc., -1 = unknown)
	ProcessorPath     []string            // Full path from root to this processor
	EstimatedLatency  int                 // Estimated operation latency in ms (-1 if unknown)
	Reachable         bool                // Whether this processor is reachable for management operations
	UnreachableReason string              // Reason why processor is unreachable (empty if reachable)
	NodeType          management.NodeType // TAP captures locally, PROCESSOR receives from hunters
	CaptureInterfaces []string            // Interfaces being captured (TAP only)
}

// TableViewParams contains all parameters needed for rendering table views
type TableViewParams struct {
	Changes               map[NodeKey]NodeChanges
	Quiet                 bool
	Processors            []ProcessorInfo
	Hunters               []types.HunterInfo
	SelectedIndex         int
	SelectedProcessorAddr string
	Width                 int
	Theme                 themes.Theme
	HunterLines           map[int]int // Output: line -> hunter index mapping
	ProcessorLines        map[int]int // Output: line -> processor index mapping
}

// processorWithDepth annotates a processor with its depth and tree position info
type processorWithDepth struct {
	ProcessorInfo
	Depth         int  // How deep in tree (0 = root)
	IsLastSibling bool // Is this the last child of its parent?
}

// buildProcessorHierarchy builds a hierarchical processor structure with depth information
func buildProcessorHierarchy(processors []ProcessorInfo) []processorWithDepth {
	if len(processors) == 0 {
		return nil
	}

	// Build parent -> children map
	childrenMap := make(map[string][]ProcessorInfo)
	var roots []ProcessorInfo

	for _, proc := range processors {
		if proc.UpstreamAddr == "" {
			roots = append(roots, proc)
		} else {
			childrenMap[proc.UpstreamAddr] = append(childrenMap[proc.UpstreamAddr], proc)
		}
	}

	// Sort roots alphabetically
	sort.Slice(roots, func(i, j int) bool {
		return roots[i].Address < roots[j].Address
	})

	// Sort children of each parent alphabetically
	for parent := range childrenMap {
		children := childrenMap[parent]
		sort.Slice(children, func(i, j int) bool {
			return children[i].Address < children[j].Address
		})
		childrenMap[parent] = children
	}

	// Recursively build hierarchy with depth tracking
	var result []processorWithDepth
	var addProcessorWithChildren func(proc ProcessorInfo, depth int, isLast bool)
	addProcessorWithChildren = func(proc ProcessorInfo, depth int, isLast bool) {
		result = append(result, processorWithDepth{
			ProcessorInfo: proc,
			Depth:         depth,
			IsLastSibling: isLast,
		})
		// Add children recursively
		if children, hasChildren := childrenMap[proc.Address]; hasChildren {
			for i, child := range children {
				isLastChild := (i == len(children)-1)
				addProcessorWithChildren(child, depth+1, isLastChild)
			}
		}
	}

	// Add all root processors and their children
	for i, root := range roots {
		isLastRoot := (i == len(roots)-1)
		addProcessorWithChildren(root, 0, isLastRoot)
	}

	return result
}

// RenderTreeView renders processors and hunters in a tree structure with table columns
// Returns the rendered content and the line number where the selected node is rendered (-1 if none)
func RenderTreeView(params TableViewParams) (string, int) {
	var b strings.Builder
	linesRendered := 0
	selectedNodeLine := -1

	processorStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(params.Theme.InfoColor)

	selectedStyle := lipgloss.NewStyle().
		Foreground(params.Theme.SelectionFg).
		Background(params.Theme.SelectionBg).
		Bold(true)

	// Calculate column widths

	// Build hierarchical processor structure (same as graph view)
	sortedProcs := buildProcessorHierarchy(params.Processors)

	// Build map to track which processors are parents (have downstream processors)
	parentProcessors := make(map[string]bool)
	for _, proc := range sortedProcs {
		if proc.UpstreamAddr != "" {
			parentProcessors[proc.UpstreamAddr] = true
		}
	}

	// Track which ancestors still have pending siblings (for tree lines)
	// This is used to determine which vertical lines (│) need to be drawn
	ancestorHasPendingSiblings := make(map[int]bool) // depth -> has pending siblings

	for procIdx, proc := range sortedProcs {
		// Update ancestor tracking - check if there are more siblings at this depth
		if proc.Depth > 0 {
			// Check if this processor's parent has more children after this one
			hasSiblingAfter := false
			for i := procIdx + 1; i < len(sortedProcs); i++ {
				if sortedProcs[i].UpstreamAddr == proc.UpstreamAddr {
					hasSiblingAfter = true
					break
				}
			}
			ancestorHasPendingSiblings[proc.Depth-1] = hasSiblingAfter || !proc.IsLastSibling
		}

		// Track this processor's line position for mouse clicks
		// Find the original index in params.Processors for click mapping
		originalIdx := 0
		for i, p := range params.Processors {
			if p.Address == proc.Address {
				originalIdx = i
				break
			}
		}
		params.ProcessorLines[linesRendered] = originalIdx

		// Status indicator for processor - prioritize connection state over reported status
		var statusIcon string
		var statusColor lipgloss.Color

		// First check connection state (takes precedence)
		switch proc.ConnectionState {
		case ProcessorConnectionStateDisconnected:
			statusIcon = "○"                    // Empty circle for disconnected
			statusColor = lipgloss.Color("240") // Gray
		case ProcessorConnectionStateConnecting:
			statusIcon = "◐"                   // Half-filled circle for connecting
			statusColor = lipgloss.Color("11") // Cyan/blue
		case ProcessorConnectionStateFailed:
			statusIcon = "✗"                      // X for failed
			statusColor = params.Theme.ErrorColor // Red
		case ProcessorConnectionStateConnected:
			// When connected, use the processor's reported status
			switch proc.Status {
			case management.ProcessorStatus_PROCESSOR_HEALTHY:
				statusIcon = "●"
				statusColor = params.Theme.SuccessColor
			case management.ProcessorStatus_PROCESSOR_WARNING:
				statusIcon = "●"
				statusColor = params.Theme.WarningColor
			case management.ProcessorStatus_PROCESSOR_ERROR:
				statusIcon = "✗"
				statusColor = params.Theme.ErrorColor
			default:
				statusIcon = "●"
				statusColor = params.Theme.SuccessColor
			}
		case ProcessorConnectionStateUnknown:
			// Unknown state (auto-discovered from hierarchy) - filled circle in Solarized base0
			statusIcon = "●"
			statusColor = lipgloss.Color("#839496") // Solarized base0
		default:
			// Fallback - empty circle
			statusIcon = "○"
			statusColor = lipgloss.Color("240")
		}

		// Security indicator (🔒 for secure TLS, 🚫 for insecure)
		var securityIcon string
		if proc.TLSInsecure {
			securityIcon = "🚫"
		} else {
			securityIcon = "🔒"
		}

		// Processor header with ID (if available) - add tree prefix for child processors
		var procLine string

		// Gray style for tree prefix (matching hunter tree prefixes)
		treePrefixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))

		// Build tree prefix with proper depth and continuation lines
		var treePrefix string
		if proc.Depth > 0 {
			// Build prefix with ancestor continuation lines
			for d := 0; d < proc.Depth-1; d++ {
				if ancestorHasPendingSiblings[d] {
					treePrefix += "│ "
				} else {
					treePrefix += "  "
				}
			}
			// Add branch connector
			if proc.IsLastSibling {
				treePrefix += "└─ "
			} else {
				treePrefix += "├─ "
			}
		}

		change := params.Changes[NodeKey{ProcessorAddr: proc.Address}]
		isSelected := params.SelectedProcessorAddr == proc.Address
		if isSelected {
			selectedNodeLine = linesRendered
		}
		depthIndicator := ""
		if proc.HierarchyDepth >= 0 {
			depthIndicator = fmt.Sprintf("[L%d]", proc.HierarchyDepth)
			if proc.HierarchyDepth > 7 {
				depthIndicator += "⚠"
			}
		}
		if !proc.Reachable && proc.ConnectionState == ProcessorConnectionStateFailed {
			depthIndicator += "✗"
		}
		procLine = fmt.Sprintf(" %s %s 📡 %s %s", securityIcon, depthIndicator, buildNodeTypeBadge(proc.NodeType, proc.CaptureInterfaces), proc.Address)
		if proc.ProcessorID != "" {
			procLine += " [" + proc.ProcessorID + "]"
		}
		procLine += fmt.Sprintf(" (%d hunters)", proc.TotalHunters)
		procLine = withChangeLabel(procLine, change.Label, max(0, params.Width-lipgloss.Width(treePrefix)-1))
		procLine = changeAccent(procLine, change.Label != "", params.Quiet, params.Theme)
		statusStyled := statusCell(statusIcon, statusColor, change.StatusChanged, params.Quiet)
		rowStyle := processorStyle
		if isSelected {
			rowStyle = selectedStyle
		}
		b.WriteString(treePrefixStyle.Render(treePrefix) + renderTableRow(statusStyled+procLine, rowStyle) + "\n")
		linesRendered++

		// Show unreachable reason if processor is not reachable (only for failed connections)
		if !proc.Reachable && proc.ConnectionState == ProcessorConnectionStateFailed && proc.UnreachableReason != "" {
			unreachableStyle := lipgloss.NewStyle().Foreground(params.Theme.ErrorColor).Faint(true)
			unreachableLine := fmt.Sprintf("    ⚠ Unreachable: %s", proc.UnreachableReason)
			b.WriteString(unreachableStyle.Render(unreachableLine) + "\n")
			linesRendered++
		}

		// Only show hunter table if this processor has hunters or is a parent with no downstream processors
		hasHunters := len(proc.Hunters) > 0
		isParent := parentProcessors[proc.Address]

		if hasHunters || !isParent {
			// Table header for hunters under this processor
			// Build header prefix with proper depth and alignment
			var headerTreePrefix string
			for d := 0; d < proc.Depth; d++ {
				if ancestorHasPendingSiblings[d] {
					headerTreePrefix += "│ "
				} else {
					headerTreePrefix += "  "
				}
			}
			// Align with the position of the processor's status icon
			// For child processors, we have "├─ ●", so add "│" at the same indent level
			// For root processors, we have "●" at position 0, so add "│  " directly
			if proc.Depth > 0 {
				headerTreePrefix += " │  " // 1 space to align after "├─ ", then "│  "
			} else {
				headerTreePrefix += "│  " // Root level: just vertical continuation
			}

			// Style the tree prefix in gray, rest of header in bold
			treePrefixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
			headerTreePrefixStyled := treePrefixStyle.Render(headerTreePrefix)
			widths := nodeTableWidths(params.Width-lipgloss.Width(headerTreePrefix), false)
			headerLine := nodeTableLine(widths, "S", "Hunter ID", "Mode", "IP Address", "Uptime", "CPU", "RAM", "Captured", "Forwarded", "Filters")
			headerStyle := lipgloss.NewStyle().
				Foreground(params.Theme.Foreground).
				Bold(true)
			b.WriteString(headerTreePrefixStyled + headerStyle.Render(TruncateString(headerLine, max(0, params.Width-lipgloss.Width(headerTreePrefix)))) + "\n")
			linesRendered++

			// Render hunters under this processor in table format
			if len(proc.Hunters) == 0 {
				// No hunters for this processor - show empty state only if not a parent
				if !isParent {
					emptyStyle := lipgloss.NewStyle().
						Foreground(lipgloss.Color("240"))
					// Build empty line prefix with proper alignment
					var emptyPrefix string
					for d := 0; d < proc.Depth; d++ {
						if ancestorHasPendingSiblings[d] {
							emptyPrefix += "│ "
						} else {
							emptyPrefix += "  "
						}
					}
					// Align with hunter position (1 space after depth prefix, then └─)
					if proc.Depth > 0 {
						emptyPrefix += " └─  "
					} else {
						emptyPrefix += "└─  "
					}
					emptyLine := fmt.Sprintf("%s(no hunters connected)", emptyPrefix)
					b.WriteString(emptyStyle.Render(emptyLine) + "\n")
					linesRendered++
				}
			}
		}

		for i, hunter := range proc.Hunters {
			isLast := i == len(proc.Hunters)-1
			// Build prefix with proper depth and ancestor lines, aligned with status icon
			var prefix string
			for d := 0; d < proc.Depth; d++ {
				if ancestorHasPendingSiblings[d] {
					prefix += "│ "
				} else {
					prefix += "  "
				}
			}
			// Add alignment spacing and branch connector for hunter
			// Need to align with the processor's status icon position
			if proc.Depth > 0 {
				prefix += " " // 1 space to align after "├─ " (├ + ─ = 2 chars, then space)
			}
			// Add branch connector for hunter
			if isLast {
				prefix += "└─ "
			} else {
				prefix += "├─ "
			}

			// Status indicator - use different icons for better visibility when selected
			var statusIcon string
			var statusColor lipgloss.Color
			switch hunter.Status {
			case management.HunterStatus_STATUS_HEALTHY:
				statusIcon = "●"
				statusColor = params.Theme.SuccessColor
			case management.HunterStatus_STATUS_WARNING:
				statusIcon = "●"
				statusColor = params.Theme.WarningColor
			case management.HunterStatus_STATUS_ERROR:
				statusIcon = "✗"
				statusColor = params.Theme.ErrorColor
			case management.HunterStatus_STATUS_STOPPING:
				statusIcon = "●"
				statusColor = lipgloss.Color("240")
			default:
				statusIcon = "●"
				statusColor = params.Theme.SuccessColor
			}

			// Calculate global hunter index
			globalIndex := 0
			found := false
			for _, p := range params.Processors {
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
				uptimeStr = FormatDuration(uptime)
			} else {
				uptimeStr = "-"
			}

			widths := nodeTableWidths(params.Width-lipgloss.Width(prefix), false)
			change := params.Changes[NodeKey{ProcessorAddr: proc.Address, HunterID: hunter.ID}]
			cpu, memory, captured, forwarded, filters, change := hunterMetricValues(hunter, change, widths[9])
			isSelected := globalIndex == params.SelectedIndex
			if isSelected {
				selectedNodeLine = linesRendered
			}
			params.HunterLines[linesRendered] = globalIndex
			status := statusCell(statusIcon, statusColor, change.StatusChanged, params.Quiet)
			id := withChangeLabel(hunter.ID, change.Label, widths[1])
			row := nodeTableLine(widths,
				status+activityMarker(change.Activity),
				changeAccent(id, change.Label != "", params.Quiet, params.Theme),
				GetHunterModeBadge(hunter.Capabilities, params.Theme), hunter.Hostname, uptimeStr,
				resourceAccent(metricText(cpu, change.CPU, widths[5]), change.CPU, params.Quiet, params.Theme),
				resourceAccent(metricText(memory, change.Memory, widths[6]), change.Memory, params.Quiet, params.Theme),
				cellAccent(fitCell(captured, widths[7]), change.CapturedChanged, params.Quiet, params.Theme.SuccessColor),
				cellAccent(fitCell(forwarded, widths[8]), change.ForwardedChanged, params.Quiet, params.Theme.SuccessColor),
				changeAccent(filters, change.FiltersChanged, params.Quiet, params.Theme))
			row = TruncateString(row, max(0, params.Width-lipgloss.Width(prefix)))
			if isSelected {
				row = renderTableRow(row, selectedStyle)
			}
			b.WriteString(treePrefixStyle.Render(prefix) + row + "\n")

			linesRendered++
		}

		// Handle spacing after processor group
		if procIdx+1 < len(sortedProcs) {
			nextProc := sortedProcs[procIdx+1]

			if nextProc.UpstreamAddr == proc.Address {
				// Next processor is a child of this one - add continuation line
				var continuationLine string
				// Build prefix up to this processor's level
				for d := 0; d < proc.Depth; d++ {
					if ancestorHasPendingSiblings[d] {
						continuationLine += "│ "
					} else {
						continuationLine += "  "
					}
				}
				// Add the vertical line at this processor's branch level
				continuationLine += "│"
				treePrefixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
				b.WriteString(treePrefixStyle.Render(continuationLine) + "\n")
				linesRendered++
			} else if !proc.IsLastSibling && proc.Depth > 0 {
				// This processor has siblings - add vertical continuation line for the PARENT's level
				// The line connects the parent to its next child (this proc's sibling)
				var continuationLine string
				// Build prefix up to parent's level (proc.Depth - 1)
				for d := 0; d < proc.Depth-1; d++ {
					if ancestorHasPendingSiblings[d] {
						continuationLine += "│ "
					} else {
						continuationLine += "  "
					}
				}
				// Add the vertical line at parent's branch level
				continuationLine += "│"
				treePrefixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
				b.WriteString(treePrefixStyle.Render(continuationLine) + "\n")
				linesRendered++
			} else {
				// Add blank line between processor groups
				b.WriteString("\n")
				linesRendered++
			}
		} else {
			// Last processor - add blank line
			b.WriteString("\n")
			linesRendered++
		}
	}

	return b.String(), selectedNodeLine
}

// RenderFlatView renders hunters in a flat table without processor grouping
// Returns the rendered content and the line number where the selected node is rendered (-1 if none)
func RenderFlatView(params TableViewParams) (string, int) {
	var b strings.Builder
	selectedNodeLine := -1

	widths := nodeTableWidths(params.Width, true)
	header := nodeTableLine(widths, "Status", "Hunter ID", "", "IP Address", "Uptime", "CPU", "RAM", "Captured", "Forwarded", "Filters")

	headerStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(params.Theme.InfoColor)

	b.WriteString(headerStyle.Render(TruncateString(header, params.Width)) + "\n")

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(params.Theme.BorderColor)
	separator := sepStyle.Render(strings.Repeat("─", params.Width))
	b.WriteString(separator + "\n")

	// Render all hunters
	for i, hunter := range params.Hunters {
		// Status color
		var statusColor lipgloss.Color
		var statusText string
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			statusColor = params.Theme.SuccessColor
			statusText = "HEALTHY"
		case management.HunterStatus_STATUS_WARNING:
			statusColor = params.Theme.WarningColor
			statusText = "WARNING"
		case management.HunterStatus_STATUS_ERROR:
			statusColor = params.Theme.ErrorColor
			statusText = "ERROR"
		case management.HunterStatus_STATUS_STOPPING:
			statusColor = lipgloss.Color("240")
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

		change := params.Changes[NodeKey{ProcessorAddr: hunter.ProcessorAddr, HunterID: hunter.ID}]
		cpu, memory, captured, forwarded, filters, change := hunterMetricValues(hunter, change, widths[9])
		isSelected := i == params.SelectedIndex
		row := nodeTableLine(widths,
			statusCell(statusText, statusColor, change.StatusChanged, params.Quiet)+activityMarker(change.Activity),
			changeAccent(withChangeLabel(hunter.ID, change.Label, widths[1]), change.Label != "", params.Quiet, params.Theme),
			"", hunter.Hostname, uptime,
			resourceAccent(metricText(cpu, change.CPU, widths[5]), change.CPU, params.Quiet, params.Theme),
			resourceAccent(metricText(memory, change.Memory, widths[6]), change.Memory, params.Quiet, params.Theme),
			cellAccent(fitCell(captured, widths[7]), change.CapturedChanged, params.Quiet, params.Theme.SuccessColor),
			cellAccent(fitCell(forwarded, widths[8]), change.ForwardedChanged, params.Quiet, params.Theme.SuccessColor),
			changeAccent(filters, change.FiltersChanged, params.Quiet, params.Theme))
		row = TruncateString(row, params.Width)

		// Apply style to entire row
		if isSelected {
			selectedNodeLine = i + 2 // Account for header and separator lines

			rowStyle := lipgloss.NewStyle().
				Foreground(params.Theme.SelectionFg).
				Background(params.Theme.SelectionBg).
				Bold(true)

			renderedRow := renderTableRow(row, rowStyle)
			rowLen := lipgloss.Width(renderedRow)
			if rowLen < params.Width {
				padding := params.Width - rowLen
				renderedRow += rowStyle.Render(strings.Repeat(" ", padding))
			}
			b.WriteString(renderedRow + "\n")
		} else {
			b.WriteString(row + "\n")
		}
	}

	return b.String(), selectedNodeLine
}

// buildNodeTypeBadge returns a badge string for the node type.
// For TAP nodes, includes the capture interfaces (e.g., "[TAP] eth0")
// For PROCESSOR nodes, returns "[PROC]"
func buildNodeTypeBadge(nodeType management.NodeType, captureInterfaces []string) string {
	if nodeType == management.NodeType_NODE_TYPE_TAP {
		badge := "[TAP]"
		if len(captureInterfaces) > 0 {
			badge += " " + strings.Join(captureInterfaces, ",")
		}
		return badge
	}
	return "[PROC]"
}
