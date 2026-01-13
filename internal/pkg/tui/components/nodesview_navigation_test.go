//go:build tui || all

package components

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// createTestNodesView creates a NodesView with test data for navigation testing
func createTestNodesView(processorCount, huntersPerProc int) NodesView {
	nv := NewNodesView()
	nv.viewMode = "list" // Start in list mode
	nv.width = 800
	nv.height = 600

	// Create test processors with hunters
	for i := 0; i < processorCount; i++ {
		procAddr := "proc" + string(rune('1'+i))

		// Create hunters for this processor
		hunters := make([]HunterInfo, 0, huntersPerProc)
		for j := 0; j < huntersPerProc; j++ {
			hunter := types.HunterInfo{
				ID:            string(rune('A'+i)) + string(rune('1'+j)),
				ProcessorAddr: procAddr,
				Hostname:      "host" + string(rune('1'+j)),
				Status:        management.HunterStatus_STATUS_HEALTHY,
			}
			hunters = append(hunters, hunter)
			nv.hunters = append(nv.hunters, hunter)
		}

		proc := ProcessorInfo{
			Address:         procAddr,
			ProcessorID:     "processor-" + string(rune('1'+i)),
			Status:          management.ProcessorStatus_PROCESSOR_HEALTHY,
			ConnectionState: ProcessorConnectionStateConnected,
			Hunters:         hunters,
			TotalHunters:    len(hunters),
		}
		nv.processors = append(nv.processors, proc)
	}

	return nv
}

// TestNavigate_SelectUp verifies SelectUp() uses the navigate helper correctly
func TestNavigate_SelectUp(t *testing.T) {
	nv := createTestNodesView(2, 2)

	// Start with first hunter selected
	nv.selectedIndex = 0
	nv.selectedProcessorAddr = ""

	// Move up (should select parent processor)
	nv.SelectUp()

	if nv.selectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1' selected, got '%s'", nv.selectedProcessorAddr)
	}
	if nv.selectedIndex != -1 {
		t.Errorf("Expected selectedIndex -1, got %d", nv.selectedIndex)
	}
	if nv.lastSelectedHunterIndex["proc1"] != 0 {
		t.Errorf("Expected to remember hunter index 0 for proc1, got %d", nv.lastSelectedHunterIndex["proc1"])
	}
}

// TestNavigate_SelectDown verifies SelectDown() uses the navigate helper correctly
func TestNavigate_SelectDown(t *testing.T) {
	nv := createTestNodesView(2, 2)

	// Start with nothing selected
	nv.selectedIndex = -1
	nv.selectedProcessorAddr = ""

	// Move down (should select first processor)
	nv.SelectDown()

	if nv.selectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1' selected, got '%s'", nv.selectedProcessorAddr)
	}

	// Move down again (should select first hunter of proc1)
	nv.SelectDown()

	if nv.selectedIndex != 0 {
		t.Errorf("Expected hunter index 0, got %d", nv.selectedIndex)
	}
	if nv.selectedProcessorAddr != "" {
		t.Errorf("Expected no processor selected, got '%s'", nv.selectedProcessorAddr)
	}
}

// TestNavigate_SelectLeft verifies SelectLeft() uses the navigate helper correctly
func TestNavigate_SelectLeft(t *testing.T) {
	nv := createTestNodesView(1, 3)

	// Start with second hunter selected
	nv.selectedIndex = 1
	nv.selectedProcessorAddr = ""

	// Move left (should select first hunter)
	nv.SelectLeft()

	if nv.selectedIndex != 0 {
		t.Errorf("Expected hunter index 0, got %d", nv.selectedIndex)
	}
	if nv.lastSelectedHunterIndex["proc1"] != 0 {
		t.Errorf("Expected to remember hunter index 0, got %d", nv.lastSelectedHunterIndex["proc1"])
	}
}

// TestNavigate_SelectRight verifies SelectRight() uses the navigate helper correctly
func TestNavigate_SelectRight(t *testing.T) {
	nv := createTestNodesView(1, 3)

	// Start with first hunter selected
	nv.selectedIndex = 0
	nv.selectedProcessorAddr = ""

	// Move right (should select second hunter)
	nv.SelectRight()

	if nv.selectedIndex != 1 {
		t.Errorf("Expected hunter index 1, got %d", nv.selectedIndex)
	}
	if nv.lastSelectedHunterIndex["proc1"] != 1 {
		t.Errorf("Expected to remember hunter index 1, got %d", nv.lastSelectedHunterIndex["proc1"])
	}

	// Move right again (should select third hunter)
	nv.SelectRight()

	if nv.selectedIndex != 2 {
		t.Errorf("Expected hunter index 2, got %d", nv.selectedIndex)
	}
}

// TestNavigate_GraphMode verifies navigation works correctly in graph mode with filtering
func TestNavigate_GraphMode(t *testing.T) {
	nv := createTestNodesView(2, 2)
	nv.viewMode = "graph"
	// Set graph view target to first processor (required for graph mode)
	nv.graphViewTargetAddr = "proc1"

	// In graph mode, navigation should still work correctly
	// Start with first processor's first hunter selected
	nv.selectedIndex = 0
	nv.selectedProcessorAddr = ""

	// Move up (should select the parent processor)
	nv.SelectUp()

	if nv.selectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1' selected in graph mode, got '%s'", nv.selectedProcessorAddr)
	}
}

// TestPrepareNavigationData_ListMode verifies data preparation in list mode
func TestPrepareNavigationData_ListMode(t *testing.T) {
	nv := createTestNodesView(2, 2)
	nv.viewMode = "list"
	nv.selectedIndex = 1

	data := nv.prepareNavigationData()

	if len(data.processors) != 2 {
		t.Errorf("Expected 2 processors, got %d", len(data.processors))
	}
	if len(data.hunters) != 4 {
		t.Errorf("Expected 4 hunters, got %d", len(data.hunters))
	}
	if data.selectedIndex != 1 {
		t.Errorf("Expected selectedIndex 1, got %d", data.selectedIndex)
	}
}

// TestNavigate_BoundaryConditions verifies navigation at boundaries
func TestNavigate_BoundaryConditions(t *testing.T) {
	nv := createTestNodesView(2, 2)

	// Test moving left from first hunter (should stay at first)
	nv.selectedIndex = 0
	nv.SelectLeft()
	if nv.selectedIndex != 0 {
		t.Errorf("Expected to stay at index 0, got %d", nv.selectedIndex)
	}

	// Test moving right from last hunter of processor (should stay at last)
	nv.selectedIndex = 1 // Last hunter of first processor
	nv.SelectRight()
	if nv.selectedIndex != 1 {
		t.Errorf("Expected to stay at index 1, got %d", nv.selectedIndex)
	}
}

// TestNavigate_MultipleDirections verifies navigation sequence
func TestNavigate_MultipleDirections(t *testing.T) {
	nv := createTestNodesView(2, 2)

	// Start from nothing
	nv.selectedIndex = -1
	nv.selectedProcessorAddr = ""

	// Down to first processor
	nv.SelectDown()
	if nv.selectedProcessorAddr != "proc1" {
		t.Errorf("Step 1: Expected proc1, got %s", nv.selectedProcessorAddr)
	}

	// Down to first hunter
	nv.SelectDown()
	if nv.selectedIndex != 0 {
		t.Errorf("Step 2: Expected hunter 0, got %d", nv.selectedIndex)
	}

	// Right to second hunter
	nv.SelectRight()
	if nv.selectedIndex != 1 {
		t.Errorf("Step 3: Expected hunter 1, got %d", nv.selectedIndex)
	}

	// Up to processor
	nv.SelectUp()
	if nv.selectedProcessorAddr != "proc1" {
		t.Errorf("Step 4: Expected proc1, got %s", nv.selectedProcessorAddr)
	}

	// Down back to hunter (should remember last selected hunter)
	nv.SelectDown()
	if nv.selectedIndex != 1 {
		t.Errorf("Step 5: Expected to return to hunter 1, got %d", nv.selectedIndex)
	}
}
