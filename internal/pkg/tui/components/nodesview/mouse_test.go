//go:build tui || all
// +build tui all

package nodesview

import (
	"testing"

	tea "github.com/charmbracelet/bubbletea"
)

func TestHandleMouseClick_NotLeftButton_NotHandled(t *testing.T) {
	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			Button: tea.MouseButtonRight,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset: 0,
		HunterLines:     make(map[int]int),
		ProcessorLines:  make(map[int]int),
	}

	result := HandleMouseClick(params)

	if result.WasHandled {
		t.Error("Expected right button click to not be handled")
	}
}

func TestHandleMouseClick_NotPress_NotHandled(t *testing.T) {
	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionRelease,
		},
		ViewportYOffset: 0,
		HunterLines:     make(map[int]int),
		ProcessorLines:  make(map[int]int),
	}

	result := HandleMouseClick(params)

	if result.WasHandled {
		t.Error("Expected release action to not be handled")
	}
}

func TestHandleMouseClick_TableView_ProcessorLine(t *testing.T) {
	// Create test data
	processors := createTestProcessors(2, 2)

	// Map line 5 to processor index 1
	processorLines := map[int]int{
		5: 1,
	}

	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			X:      10,
			Y:      10, // Content area starts at Y=5, so line 5 in content
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset: 0,
		ProcessorLines:  processorLines,
		HunterLines:     make(map[int]int),
		Processors:      processors,
	}

	result := HandleMouseClick(params)

	if !result.WasHandled {
		t.Error("Expected click on processor line to be handled")
	}
	if result.SelectedProcessorAddr != "proc2" {
		t.Errorf("Expected processor 'proc2' selected, got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestHandleMouseClick_TableView_HunterLine(t *testing.T) {
	// Map line 7 to hunter index 2
	hunterLines := map[int]int{
		7: 2,
	}

	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			X:      10,
			Y:      12, // Content line 7 (12 - 5 content offset)
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset: 0,
		HunterLines:     hunterLines,
		ProcessorLines:  make(map[int]int),
	}

	result := HandleMouseClick(params)

	if !result.WasHandled {
		t.Error("Expected click on hunter line to be handled")
	}
	if result.SelectedIndex != 2 {
		t.Errorf("Expected hunter index 2, got %d", result.SelectedIndex)
	}
	if result.SelectedProcessorAddr != "" {
		t.Errorf("Expected no processor selected, got '%s'", result.SelectedProcessorAddr)
	}
}

func TestHandleMouseClick_TableView_WithScroll(t *testing.T) {
	// Test clicking with viewport scrolled down
	hunterLines := map[int]int{
		15: 5, // Line 15 in content maps to hunter 5
	}

	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			X:      10,
			Y:      10, // Y=10 in viewport
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset: 10, // Viewport scrolled down 10 lines
		HunterLines:     hunterLines,
		ProcessorLines:  make(map[int]int),
	}

	result := HandleMouseClick(params)

	// Click Y=10 with offset 10 = content line 15
	if !result.WasHandled {
		t.Error("Expected click with scroll to be handled")
	}
	if result.SelectedIndex != 5 {
		t.Errorf("Expected hunter index 5, got %d", result.SelectedIndex)
	}
}

func TestHandleMouseClick_GraphView_ProcessorBox(t *testing.T) {
	// Create processor box region
	processorRegions := []ProcessorBoxRegion{
		{
			StartLine:     10,
			EndLine:       15,
			StartCol:      20,
			EndCol:        50,
			ProcessorAddr: "proc1",
		},
	}

	params := MouseClickParams{
		ViewMode: "graph",
		MouseMsg: tea.MouseMsg{
			X:      30, // Within box horizontally
			Y:      10, // Y=10 in viewport, content starts at Y=5, so clickY=5, contentLineY=10 with offset 5
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset:     5,
		ProcessorBoxRegions: processorRegions,
		HunterBoxRegions:    []HunterBoxRegion{},
	}

	result := HandleMouseClick(params)

	if !result.WasHandled {
		t.Error("Expected click on processor box to be handled")
	}
	if result.SelectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestHandleMouseClick_GraphView_HunterBox(t *testing.T) {
	// Create hunter box region
	hunterRegions := []HunterBoxRegion{
		{
			StartLine:   20,
			EndLine:     30,
			StartCol:    10,
			EndCol:      40,
			HunterIndex: 3,
		},
	}

	params := MouseClickParams{
		ViewMode: "graph",
		MouseMsg: tea.MouseMsg{
			X:      25, // Within box horizontally
			Y:      30, // Within box vertically (25 in content = 30 viewport with offset 5)
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset:     5,
		ProcessorBoxRegions: []ProcessorBoxRegion{},
		HunterBoxRegions:    hunterRegions,
	}

	result := HandleMouseClick(params)

	if !result.WasHandled {
		t.Error("Expected click on hunter box to be handled")
	}
	if result.SelectedIndex != 3 {
		t.Errorf("Expected hunter index 3, got %d", result.SelectedIndex)
	}
	if result.SelectedProcessorAddr != "" {
		t.Errorf("Expected no processor selected, got '%s'", result.SelectedProcessorAddr)
	}
}

func TestHandleMouseClick_GraphView_OutsideBoxes_NotHandled(t *testing.T) {
	params := MouseClickParams{
		ViewMode: "graph",
		MouseMsg: tea.MouseMsg{
			X:      100,
			Y:      100,
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset:     0,
		ProcessorBoxRegions: []ProcessorBoxRegion{},
		HunterBoxRegions:    []HunterBoxRegion{},
	}

	result := HandleMouseClick(params)

	if result.WasHandled {
		t.Error("Expected click outside boxes to not be handled")
	}
}

func TestHandleMouseClick_TableView_NoMatch_NotHandled(t *testing.T) {
	params := MouseClickParams{
		ViewMode: "table",
		MouseMsg: tea.MouseMsg{
			X:      10,
			Y:      50,
			Button: tea.MouseButtonLeft,
			Action: tea.MouseActionPress,
		},
		ViewportYOffset: 0,
		HunterLines:     make(map[int]int),
		ProcessorLines:  make(map[int]int),
	}

	result := HandleMouseClick(params)

	if result.WasHandled {
		t.Error("Expected click on empty area to not be handled")
	}
}
