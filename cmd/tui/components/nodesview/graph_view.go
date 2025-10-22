//go:build tui || all
// +build tui all

package nodesview

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/endorses/lippycat/cmd/tui/themes"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// HunterBoxRegion represents a clickable hunter box region in graph view
type HunterBoxRegion struct {
	StartLine   int
	EndLine     int
	StartCol    int
	EndCol      int
	HunterIndex int
}

// ProcessorBoxRegion represents a clickable processor box region in graph view
type ProcessorBoxRegion struct {
	StartLine     int
	EndLine       int
	StartCol      int
	EndCol        int
	ProcessorAddr string
}

// GraphViewParams contains all parameters needed for rendering graph views
type GraphViewParams struct {
	Processors              []ProcessorInfo
	Hunters                 []types.HunterInfo
	SelectedIndex           int
	SelectedProcessorAddr   string
	Width                   int
	Height                  int
	Theme                   themes.Theme
	LastSelectedHunterIndex map[string]int // Map of processor address -> last selected hunter index
}

// GraphViewResult contains the results from rendering the graph view
type GraphViewResult struct {
	Content             string
	SelectedNodeLine    int
	HunterBoxRegions    []HunterBoxRegion
	ProcessorBoxRegions []ProcessorBoxRegion
}

// RenderGraphView renders the processors and hunters in a graph-like visualization using box drawing characters
func RenderGraphView(params GraphViewParams) GraphViewResult {
	var b strings.Builder

	// Initialize result
	result := GraphViewResult{
		SelectedNodeLine:    -1,
		HunterBoxRegions:    make([]HunterBoxRegion, 0),
		ProcessorBoxRegions: make([]ProcessorBoxRegion, 0),
	}

	// Style for processor and hunter boxes
	processorStyle := lipgloss.NewStyle().
		Bold(true).
		Foreground(params.Theme.InfoColor)

	hunterStyle := lipgloss.NewStyle().
		Foreground(params.Theme.Foreground)

	selectedStyle := lipgloss.NewStyle().
		Foreground(params.Theme.SelectionBg).
		Reverse(true).
		Bold(true)

	// Build hierarchical processor structure
	// Map to track which processors have been placed
	processedAddrs := make(map[string]bool)
	sortedProcs := make([]ProcessorInfo, 0, len(params.Processors))

	// Build address -> processor map for quick lookup
	procMap := make(map[string]ProcessorInfo)
	for _, proc := range params.Processors {
		procMap[proc.Address] = proc
	}

	// First pass: Add processors that have upstreams (leaf/intermediate processors)
	// These are the processors we're actively connected to
	var leafProcs []ProcessorInfo
	for _, proc := range params.Processors {
		if proc.UpstreamAddr != "" {
			leafProcs = append(leafProcs, proc)
			processedAddrs[proc.Address] = true
		}
	}
	// Sort leaf processors alphabetically for consistency
	sort.Slice(leafProcs, func(i, j int) bool {
		return leafProcs[i].Address < leafProcs[j].Address
	})

	// Second pass: For each leaf processor, add its upstream chain (if not already added)
	for _, proc := range leafProcs {
		// Walk up the upstream chain and collect processors
		upstream := proc.UpstreamAddr
		upstreamChain := []ProcessorInfo{}
		for upstream != "" {
			if processedAddrs[upstream] {
				break // Already added
			}
			if upstreamProc, exists := procMap[upstream]; exists {
				upstreamChain = append(upstreamChain, upstreamProc)
				processedAddrs[upstream] = true
				upstream = upstreamProc.UpstreamAddr
			} else {
				break // Upstream not in our list
			}
		}
		// Add upstream chain in reverse order (top-level first)
		for i := len(upstreamChain) - 1; i >= 0; i-- {
			sortedProcs = append(sortedProcs, upstreamChain[i])
		}
		// Add the leaf processor
		sortedProcs = append(sortedProcs, proc)
	}

	// Third pass: Add any remaining processors that weren't part of a hierarchy
	for _, proc := range params.Processors {
		if !processedAddrs[proc.Address] {
			sortedProcs = append(sortedProcs, proc)
		}
	}

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
		if requiredWidth > params.Width {
			// Try smaller boxes first
			hunterBoxWidth = 24
			requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

			if requiredWidth > params.Width {
				// Still doesn't fit - reduce spacing
				hunterSpacing = 4
				requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

				if requiredWidth > params.Width {
					// Still doesn't fit - make boxes even smaller
					hunterBoxWidth = 20
					requiredWidth = maxHunters*hunterBoxWidth + (maxHunters-1)*hunterSpacing + 20

					if requiredWidth > params.Width {
						// Last resort - minimal spacing
						hunterSpacing = 2
						// Calculate minimum possible box width
						availableWidth := params.Width - (maxHunters-1)*hunterSpacing - 20
						hunterBoxWidth = availableWidth / maxHunters
						if hunterBoxWidth < 18 {
							hunterBoxWidth = 18 // Absolute minimum
						}
					}
				}
			}

			// Also scale down processor box if needed
			if processorBoxWidth > params.Width-20 {
				processorBoxWidth = params.Width - 20
				if processorBoxWidth < 30 {
					processorBoxWidth = 30
				}
			}
		}
	}

	renderWidth := params.Width

	// Render each processor and its hunters
	for procIdx, proc := range sortedProcs {
		// Ensure hunters are sorted consistently within this processor
		sortedHunters := make([]types.HunterInfo, len(proc.Hunters))
		copy(sortedHunters, proc.Hunters)
		sort.Slice(sortedHunters, func(i, j int) bool {
			return sortedHunters[i].ID < sortedHunters[j].ID
		})
		proc.Hunters = sortedHunters

		// Draw connection to upstream processor if this processor has an upstream
		if procIdx > 0 {
			// Check if this processor should connect to the previous one (upstream)
			if proc.UpstreamAddr != "" && sortedProcs[procIdx-1].Address == proc.UpstreamAddr {
				// Draw connection line from previous processor (upstream) to this one
				centerPos := max(0, (renderWidth-processorBoxWidth)/2)
				arrowPos := centerPos + processorBoxWidth/2
				b.WriteString(strings.Repeat(" ", arrowPos))
				b.WriteString("│\n")
				currentLine++
				b.WriteString(strings.Repeat(" ", arrowPos))
				b.WriteString("│\n")
				currentLine++
			} else {
				// No upstream connection - add spacing between processor groups
				b.WriteString("\n\n")
				currentLine += 2
			}
		}

		// Processor box
		var procLines []string
		// Use ProcessorID if available, otherwise use address as identifier
		procHeader := proc.Address
		if proc.ProcessorID != "" {
			procHeader = proc.ProcessorID
		}
		procLines = append(procLines, procHeader)
		// Only add address line if different from header
		if proc.ProcessorID != "" {
			procLines = append(procLines, proc.Address)
		}

		// Add upstream indicator if this processor forwards to another
		if proc.UpstreamAddr != "" {
			procLines = append(procLines, "↑ [upstream]")
		}

		// Determine if processor is selected
		isProcessorSelected := params.SelectedProcessorAddr == proc.Address

		// Render processor box (centered) with selection styling and status
		processorBox := RenderProcessorBox(procLines, processorBoxWidth, processorStyle, isProcessorSelected, proc.ConnectionState, proc.Status, params.Theme)

		// Center the processor box
		centerPos := max(0, (renderWidth-processorBoxWidth)/2)

		// Track click region for processor box
		processorStartLine := currentLine
		processorBoxLines := strings.Split(processorBox, "\n")

		// Track selected processor line for scrolling (use middle of box)
		if isProcessorSelected {
			result.SelectedNodeLine = processorStartLine + len(processorBoxLines)/2
		}
		result.ProcessorBoxRegions = append(result.ProcessorBoxRegions, ProcessorBoxRegion{
			StartLine:     processorStartLine,
			EndLine:       processorStartLine + len(processorBoxLines) - 1,
			StartCol:      centerPos,
			EndCol:        centerPos + processorBoxWidth,
			ProcessorAddr: proc.Address,
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
			startPos := max(0, (renderWidth-totalHuntersWidth)/2)

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

				// Mode badge (centered, bold)
				modeBadge := GetHunterModeBadge(hunter.Capabilities, params.Theme)
				headerLines = append(headerLines, modeBadge)

				// Body content - use condensed format for narrow boxes, labeled format for wider boxes
				const minWidthForLabels = 26 // Minimum width needed for labels
				const labelWidth = 10        // Width for label column when labels are shown

				// Interface(s) - show all interfaces
				iface := "any"
				ifaceLabel := "Interface:"
				if len(hunter.Interfaces) > 0 {
					iface = strings.Join(hunter.Interfaces, ", ")
					if len(hunter.Interfaces) > 1 {
						ifaceLabel = "Interfaces:"
					}
				}

				// Uptime
				var uptimeStr string
				if hunter.ConnectedAt > 0 {
					uptime := time.Now().UnixNano() - hunter.ConnectedAt
					uptimeStr = FormatDuration(uptime)
				} else {
					uptimeStr = "-"
				}

				// Captured and Forwarded
				capturedStr := FormatPacketNumber(hunter.PacketsCaptured)
				forwardedStr := FormatPacketNumber(hunter.PacketsForwarded)

				if hunterBoxWidth < minWidthForLabels {
					// Condensed format without labels for narrow boxes
					bodyLines = append(bodyLines, TruncateString(iface, hunterBoxWidth-4))
					bodyLines = append(bodyLines, uptimeStr)
					bodyLines = append(bodyLines, fmt.Sprintf("%s/%s", forwardedStr, capturedStr))
					bodyLines = append(bodyLines, fmt.Sprintf("%d", hunter.ActiveFilters))
				} else {
					// Full format with aligned labels for wider boxes
					bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, ifaceLabel, TruncateString(iface, hunterBoxWidth-labelWidth-2)))
					bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Uptime:", uptimeStr))
					bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Captured:", capturedStr))
					bodyLines = append(bodyLines, fmt.Sprintf("%-*s %s", labelWidth, "Forwarded:", forwardedStr))
					bodyLines = append(bodyLines, fmt.Sprintf("%-*s %d", labelWidth, "Filters:", hunter.ActiveFilters))
				}

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
				for _, p := range params.Processors {
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
				isSelected := globalIndex == params.SelectedIndex
				if isSelected {
					boxStyle = selectedStyle
				} else {
					boxStyle = hunterStyle
				}

				// Get status color for this hunter
				hunter := proc.Hunters[hIdx]
				box := RenderHunterBox(content.HeaderLines, content.BodyLines, hunterBoxWidth, boxStyle, isSelected, hunter.Status, params.Theme)
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
				for _, p := range params.Processors {
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

				// Track selected hunter line for scrolling (use middle of box)
				if globalIndex == params.SelectedIndex {
					result.SelectedNodeLine = hunterStartLine + maxBoxLines/2
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
				result.HunterBoxRegions = append(result.HunterBoxRegions, HunterBoxRegion{
					StartLine:   hunterStartLine,
					EndLine:     hunterStartLine + maxBoxLines - 1,
					StartCol:    startCol,
					EndCol:      endCol,
					HunterIndex: globalIndex,
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
			// Only show "no hunters" message if this is a standalone processor (no upstream/downstream)
			// For hierarchical processors, omit the message to keep the visual flow clean
			hasDownstream := false
			for _, p := range sortedProcs {
				if p.UpstreamAddr == proc.Address {
					hasDownstream = true
					break
				}
			}

			if !hasDownstream && proc.UpstreamAddr == "" {
				// Standalone processor with no hunters - show message
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

	result.Content = b.String()
	return result
}
