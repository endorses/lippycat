//go:build tui || all

package nodesview

import (
	tea "github.com/charmbracelet/bubbletea"
)

// MouseClickParams contains all parameters needed for handling mouse clicks
type MouseClickParams struct {
	ViewMode            string               // "table" or "graph"
	MouseMsg            tea.MouseMsg         // The mouse event
	ViewportYOffset     int                  // Current viewport Y offset
	HunterLines         map[int]int          // Map of line number -> hunter index (for table view)
	ProcessorLines      map[int]int          // Map of line number -> processor index (for table view)
	HunterBoxRegions    []HunterBoxRegion    // Hunter click regions (for graph view)
	ProcessorBoxRegions []ProcessorBoxRegion // Processor click regions (for graph view)
	Processors          []ProcessorInfo      // Processor list (for table view selection)
}

// MouseClickResult contains the result of handling a mouse click
type MouseClickResult struct {
	SelectedIndex         int    // -1 means nothing selected, >= 0 means hunter is selected
	SelectedProcessorAddr string // Non-empty means a processor is selected (instead of hunter)
	WasHandled            bool   // true if click was on a selectable region
	// Hunter identification for proper lookup (graph view)
	SelectedHunterID       string // Hunter ID for lookup in global hunters list
	SelectedHunterProcAddr string // Processor address the selected hunter belongs to
}

// HandleMouseClick processes mouse click events and determines what was clicked.
// This is a pure function that doesn't modify any state - it returns the new selection state.
//
// The function handles:
// - Graph view: Processor boxes and hunter boxes
// - Table view: Processor rows and hunter rows
//
// Returns MouseClickResult with the new selection state and whether the click was handled.
func HandleMouseClick(params MouseClickParams) MouseClickResult {
	result := MouseClickResult{
		SelectedIndex:         -1,
		SelectedProcessorAddr: "",
		WasHandled:            false,
	}

	// Only handle left button press events
	if params.MouseMsg.Button != tea.MouseButtonLeft || params.MouseMsg.Action != tea.MouseActionPress {
		return result
	}

	// Adjust Y coordinate to be relative to content area (header=2, tabs=4, but one less line, so content starts at Y=5)
	contentStartY := 5
	clickY := params.MouseMsg.Y - contentStartY

	// Since we removed the input field, viewport starts at clickY=0
	// Add viewport scroll offset to get the actual content line
	contentLineY := clickY + params.ViewportYOffset

	// Check graph view click regions first (if in graph view)
	if params.ViewMode == "graph" {
		clickX := params.MouseMsg.X

		// Check processor box clicks first
		for _, region := range params.ProcessorBoxRegions {
			if contentLineY >= region.StartLine && contentLineY <= region.EndLine &&
				clickX >= region.StartCol && clickX <= region.EndCol {
				// Select this processor
				result.SelectedProcessorAddr = region.ProcessorAddr
				result.SelectedIndex = -1 // Deselect hunters
				result.WasHandled = true
				return result
			}
		}

		// Check hunter box clicks
		for _, region := range params.HunterBoxRegions {
			if contentLineY >= region.StartLine && contentLineY <= region.EndLine &&
				clickX >= region.StartCol && clickX <= region.EndCol {
				// Select this hunter - include ID for proper lookup
				result.SelectedIndex = region.HunterIndex
				result.SelectedProcessorAddr = "" // Deselect processors
				result.SelectedHunterID = region.HunterID
				result.SelectedHunterProcAddr = region.ProcessorAddr
				result.WasHandled = true
				return result
			}
		}
	}

	// Check table view processor lines
	if procIdx, ok := params.ProcessorLines[contentLineY]; ok {
		// Select this processor
		result.SelectedProcessorAddr = params.Processors[procIdx].Address
		result.SelectedIndex = -1 // Deselect hunters
		result.WasHandled = true
		return result
	}

	// Check table view hunter lines
	if hunterIndex, ok := params.HunterLines[contentLineY]; ok {
		// Select this hunter
		result.SelectedIndex = hunterIndex
		result.SelectedProcessorAddr = "" // Deselect processors
		result.WasHandled = true
		return result
	}

	return result
}
