//go:build tui || all
// +build tui all

package nodesview

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// ProcessorInfo represents a processor node (local definition to avoid import cycles)
type ProcessorInfo struct {
	Address         string
	ProcessorID     string
	Status          management.ProcessorStatus
	ConnectionState ProcessorConnectionState
	TLSInsecure     bool   // True if connection is insecure (no TLS)
	UpstreamAddr    string // Address of upstream processor (if hierarchical)
	Hunters         []types.HunterInfo
	TotalHunters    int // Total hunters connected to this processor (all hunters)
}

// TableViewParams contains all parameters needed for rendering table views
type TableViewParams struct {
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
		Foreground(params.Theme.SelectionBg).
		Reverse(true).
		Bold(true)

	// Calculate column widths
	calc := ColumnWidthCalculator{Width: params.Width}
	idCol, hostCol, _, uptimeCol, capturedCol, forwardedCol, filtersCol := calc.GetColumnWidths()

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

		// Determine if this processor is a child (has upstream)
		isChildProcessor := proc.Depth > 0

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

		// Apply selection styling if this processor is selected
		if params.SelectedProcessorAddr == proc.Address {
			selectedNodeLine = linesRendered
			if isChildProcessor {
				// Child processor - show with tree branch (gray) before status icon
				// Even when selected, keep tree prefix gray
				treePrefixRendered := treePrefixStyle.Render(treePrefix)
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s [%s] (%d hunters)", statusIcon, securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s (%d hunters)", statusIcon, securityIcon, proc.Address, proc.TotalHunters)
				}
				// Combine gray prefix with selected line
				b.WriteString(treePrefixRendered + selectedStyle.Render(procLine) + "\n")
			} else {
				// Root processor - no tree prefix
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s [%s] (%d hunters)", statusIcon, securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s (%d hunters)", statusIcon, securityIcon, proc.Address, proc.TotalHunters)
				}
				b.WriteString(selectedStyle.Width(params.Width).Render(procLine) + "\n")
			}
		} else {
			// Style the status icon with color separately
			statusStyled := lipgloss.NewStyle().Foreground(statusColor).Render(statusIcon)

			if isChildProcessor {
				// Child processor - gray tree prefix, then colored status icon
				treePrefixRendered := treePrefixStyle.Render(treePrefix)
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf(" %s 📡 Processor: %s [%s] (%d hunters)", securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf(" %s 📡 Processor: %s (%d hunters)", securityIcon, proc.Address, proc.TotalHunters)
				}
				b.WriteString(treePrefixRendered + statusStyled + processorStyle.Render(procLine) + "\n")
			} else {
				// Root processor - no tree prefix
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf(" %s 📡 Processor: %s [%s] (%d hunters)", securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf(" %s 📡 Processor: %s (%d hunters)", securityIcon, proc.Address, proc.TotalHunters)
				}
				b.WriteString(statusStyled + processorStyle.Render(procLine) + "\n")
			}
		}
		linesRendered++

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
			headerLine := fmt.Sprintf("%-1s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
				"S", // Status
				idCol, "Hunter ID",
				8, "Mode", // Mode column (Generic/VoIP)
				hostCol, "IP Address",
				uptimeCol, "Uptime",
				capturedCol, "Captured",
				forwardedCol, "Forwarded",
				filtersCol, "Filters",
			)
			headerStyle := lipgloss.NewStyle().
				Foreground(params.Theme.Foreground).
				Bold(true)
			b.WriteString(headerTreePrefixStyled + headerStyle.Render(headerLine) + "\n")
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

			// Format table columns
			idStr := TruncateString(hunter.ID, idCol)
			hostnameStr := TruncateString(hunter.Hostname, hostCol)
			capturedStr := FormatPacketNumber(hunter.PacketsCaptured)
			forwardedStr := FormatPacketNumber(hunter.PacketsForwarded)
			filtersStr := fmt.Sprintf("%d", hunter.ActiveFilters)

			// Determine mode (VoIP or Generic)
			modeStr := "Generic"
			if IsVoIPHunter(hunter.Capabilities) {
				modeStr = "VoIP"
			}

			// Track this hunter's line position for mouse clicks
			// Current line is linesRendered (before we increment it)
			params.HunterLines[linesRendered] = globalIndex

			// Style tree prefix in gray
			treePrefixStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
			prefixStyled := treePrefixStyle.Render(prefix)

			// Build the line differently based on selection
			if globalIndex == params.SelectedIndex {
				selectedNodeLine = linesRendered
				// For selected row: build plain text line, then apply full-width background
				// Prefix is styled gray separately, status is 1 char, then space before next column
				hunterLine := fmt.Sprintf("%-1s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
					statusIcon,
					idCol, idStr,
					8, modeStr,
					hostCol, hostnameStr,
					uptimeCol, uptimeStr,
					capturedCol, capturedStr,
					forwardedCol, forwardedStr,
					filtersCol, filtersStr,
				)
				// Combine gray prefix with selected line
				renderedRow := prefixStyled + selectedStyle.Render(hunterLine)
				b.WriteString(renderedRow + "\n")
			} else {
				// For non-selected: style the status icon and prefix separately
				statusStyled := lipgloss.NewStyle().Foreground(statusColor).Render(statusIcon)
				// Prefix is styled gray separately, status is colored, then space before next column
				hunterLine := fmt.Sprintf("%-1s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
					statusStyled,
					idCol, idStr,
					8, modeStr,
					hostCol, hostnameStr,
					uptimeCol, uptimeStr,
					capturedCol, capturedStr,
					forwardedCol, forwardedStr,
					filtersCol, filtersStr,
				)
				b.WriteString(prefixStyled + hunterLine + "\n")
			}

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

	// This is a fallback case - shouldn't normally be used with current architecture
	// Get responsive column widths
	calc := ColumnWidthCalculator{Width: params.Width}
	idCol, hostCol, statusCol, uptimeCol, capturedCol, forwardedCol, filtersCol := calc.GetColumnWidths()

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
		Foreground(params.Theme.InfoColor)

	b.WriteString(headerStyle.Render(header) + "\n")

	// Separator
	sepStyle := lipgloss.NewStyle().Foreground(params.Theme.BorderColor)
	separator := sepStyle.Render(strings.Repeat("─", params.Width))
	b.WriteString(separator + "\n")

	// Render all hunters
	for i, hunter := range params.Hunters {
		// Status color
		statusStyle := lipgloss.NewStyle().PaddingLeft(1).PaddingRight(1)
		var statusText string
		switch hunter.Status {
		case management.HunterStatus_STATUS_HEALTHY:
			statusStyle = statusStyle.Foreground(params.Theme.SuccessColor)
			statusText = "HEALTHY"
		case management.HunterStatus_STATUS_WARNING:
			statusStyle = statusStyle.Foreground(params.Theme.WarningColor)
			statusText = "WARNING"
		case management.HunterStatus_STATUS_ERROR:
			statusStyle = statusStyle.Foreground(params.Theme.ErrorColor)
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
			idCol, TruncateString(hunter.ID, idCol),
			hostCol, TruncateString(hunter.Hostname, hostCol),
			statusCol, statusText,
			uptimeCol, uptime,
			capturedCol, FormatPacketNumber(hunter.PacketsCaptured),
			forwardedCol, FormatPacketNumber(hunter.PacketsForwarded),
			filtersCol, fmt.Sprintf("%d", hunter.ActiveFilters),
		)

		// Apply style to entire row
		if i == params.SelectedIndex {
			selectedNodeLine = i + 2 // Account for header and separator lines

			rowStyle := lipgloss.NewStyle().
				Foreground(params.Theme.SelectionBg).
				Reverse(true).
				Bold(true)

			renderedRow := rowStyle.Render(row)
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
