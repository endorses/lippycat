//go:build tui || all
// +build tui all

package nodesview

import (
	"fmt"
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

// buildProcessorHierarchy builds a hierarchical processor structure (upstream first, then downstream)
// This matches the graph view's sorting algorithm
func buildProcessorHierarchy(processors []ProcessorInfo) []ProcessorInfo {
	if len(processors) == 0 {
		return processors
	}

	processedAddrs := make(map[string]bool)
	sortedProcs := make([]ProcessorInfo, 0, len(processors))

	// Build address -> processor map for quick lookup
	procMap := make(map[string]ProcessorInfo)
	for _, proc := range processors {
		procMap[proc.Address] = proc
	}

	// First pass: Add processors that have upstreams (leaf/intermediate processors)
	var leafProcs []ProcessorInfo
	for _, proc := range processors {
		if proc.UpstreamAddr != "" {
			leafProcs = append(leafProcs, proc)
			processedAddrs[proc.Address] = true
		}
	}

	// Second pass: For each leaf processor, add its upstream chain
	for _, proc := range leafProcs {
		upstream := proc.UpstreamAddr
		upstreamChain := []ProcessorInfo{}
		for upstream != "" {
			if processedAddrs[upstream] {
				break
			}
			if upstreamProc, exists := procMap[upstream]; exists {
				upstreamChain = append(upstreamChain, upstreamProc)
				processedAddrs[upstream] = true
				upstream = upstreamProc.UpstreamAddr
			} else {
				break
			}
		}
		// Add upstream chain in reverse order (top-level first)
		for i := len(upstreamChain) - 1; i >= 0; i-- {
			sortedProcs = append(sortedProcs, upstreamChain[i])
		}
		sortedProcs = append(sortedProcs, proc)
	}

	// Third pass: Add any remaining processors without upstream connections (standalone processors)
	for _, proc := range processors {
		if !processedAddrs[proc.Address] {
			sortedProcs = append(sortedProcs, proc)
		}
	}

	return sortedProcs
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

	// Tree prefix is fixed width
	treeCol := 6 // "  ├─ " or "  └─ "

	// Build hierarchical processor structure (same as graph view)
	sortedProcs := buildProcessorHierarchy(params.Processors)

	// Build map to track which processors are parents (have downstream processors)
	parentProcessors := make(map[string]bool)
	for _, proc := range sortedProcs {
		if proc.UpstreamAddr != "" {
			parentProcessors[proc.UpstreamAddr] = true
		}
	}

	for _, proc := range sortedProcs {
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
		isChildProcessor := proc.UpstreamAddr != ""

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

		// Apply selection styling if this processor is selected
		if params.SelectedProcessorAddr == proc.Address {
			selectedNodeLine = linesRendered
			if isChildProcessor {
				// Child processor - show with tree branch (gray) before status icon
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf("  └─ %s %s 📡 Processor: %s [%s] (%d hunters)", statusIcon, securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf("  └─ %s %s 📡 Processor: %s (%d hunters)", statusIcon, securityIcon, proc.Address, proc.TotalHunters)
				}
			} else {
				// Root processor - no tree prefix
				if proc.ProcessorID != "" {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s [%s] (%d hunters)", statusIcon, securityIcon, proc.Address, proc.ProcessorID, proc.TotalHunters)
				} else {
					procLine = fmt.Sprintf("%s %s 📡 Processor: %s (%d hunters)", statusIcon, securityIcon, proc.Address, proc.TotalHunters)
				}
			}
			b.WriteString(selectedStyle.Width(params.Width).Render(procLine) + "\n")
		} else {
			// Style the status icon with color separately
			statusStyled := lipgloss.NewStyle().Foreground(statusColor).Render(statusIcon)

			if isChildProcessor {
				// Child processor - gray tree prefix, then colored status icon
				treePrefixRendered := treePrefixStyle.Render("  └─ ")
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
			// Add tree structure continuation to header with proper indentation
			var headerTreePrefix string
			if isChildProcessor {
				headerTreePrefix = "     │  " // Indent under child processor
			} else {
				headerTreePrefix = "  │  " // No indent for root processor
			}
			headerLine := fmt.Sprintf("%-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
				treeCol+2, headerTreePrefix,
				1, "S", // Status
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
			b.WriteString(headerStyle.Render(headerLine) + "\n")
			linesRendered++

			// Render hunters under this processor in table format
			if len(proc.Hunters) == 0 {
				// No hunters for this processor - show empty state only if not a parent
				if !isParent {
					emptyStyle := lipgloss.NewStyle().
						Foreground(lipgloss.Color("240"))
					var emptyLine string
					if isChildProcessor {
						emptyLine = fmt.Sprintf("     └─  (no hunters connected)")
					} else {
						emptyLine = fmt.Sprintf("  └─  (no hunters connected)")
					}
					b.WriteString(emptyStyle.Render(emptyLine) + "\n")
					linesRendered++
				}
			}
		}

		for i, hunter := range proc.Hunters {
			isLast := i == len(proc.Hunters)-1
			var prefix string
			if isChildProcessor {
				// Hunters under child processor - extra indentation
				prefix = "     ├─ "
				if isLast {
					prefix = "     └─ "
				}
			} else {
				// Hunters under root processor - normal indentation
				prefix = "  ├─ "
				if isLast {
					prefix = "  └─ "
				}
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

			// Build the line differently based on selection
			if globalIndex == params.SelectedIndex {
				selectedNodeLine = linesRendered
				// For selected row: build plain text line, then apply full-width background
				hunterLine := fmt.Sprintf("%-*s %s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
					treeCol, prefix,
					statusIcon,
					idCol, idStr,
					8, modeStr,
					hostCol, hostnameStr,
					uptimeCol, uptimeStr,
					capturedCol, capturedStr,
					forwardedCol, forwardedStr,
					filtersCol, filtersStr,
				)
				// Render with full-width background
				renderedRow := selectedStyle.Width(params.Width).Render(hunterLine)
				b.WriteString(renderedRow + "\n")
			} else {
				// For non-selected: style the status icon separately
				statusStyled := lipgloss.NewStyle().Foreground(statusColor).Render(statusIcon)
				hunterLine := fmt.Sprintf("%-*s %s %-*s %-*s %-*s %-*s %-*s %-*s %-*s",
					treeCol, prefix,
					statusStyled,
					idCol, idStr,
					8, modeStr,
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
