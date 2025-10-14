//go:build tui || all
// +build tui all

package nodesview

import (
	"testing"

	"github.com/endorses/lippycat/api/gen/management"
	"github.com/endorses/lippycat/internal/pkg/types"
)

// Helper function to create test processors
func createTestProcessors(count int, huntersPerProc int) []ProcessorInfo {
	processors := make([]ProcessorInfo, count)
	for i := 0; i < count; i++ {
		hunters := make([]types.HunterInfo, huntersPerProc)
		for j := 0; j < huntersPerProc; j++ {
			hunters[j] = types.HunterInfo{
				ID:            string(rune('A'+i)) + string(rune('1'+j)),
				ProcessorAddr: "proc" + string(rune('1'+i)),
				Hostname:      "host" + string(rune('1'+j)),
				Status:        management.HunterStatus_STATUS_HEALTHY,
			}
		}
		processors[i] = ProcessorInfo{
			Address:         "proc" + string(rune('1'+i)),
			ProcessorID:     "processor-" + string(rune('1'+i)),
			Status:          management.ProcessorStatus_PROCESSOR_HEALTHY,
			ConnectionState: ProcessorConnectionStateConnected,
			Hunters:         hunters,
		}
	}
	return processors
}

// Helper function to flatten hunters from processors
func flattenHunters(processors []ProcessorInfo) []types.HunterInfo {
	var hunters []types.HunterInfo
	for _, proc := range processors {
		hunters = append(hunters, proc.Hunters...)
	}
	return hunters
}

func TestSelectNext_FromNothing_SelectsFirstProcessor(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectNext(params)

	if result.SelectedProcessorAddr != "proc1" {
		t.Errorf("Expected first processor 'proc1', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestSelectNext_FromProcessor_SelectsFirstHunter(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "proc1",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectNext(params)

	if result.SelectedProcessorAddr != "" {
		t.Errorf("Expected no processor selected, got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != 0 {
		t.Errorf("Expected first hunter (index 0), got %d", result.SelectedIndex)
	}
}

func TestSelectNext_FromFirstHunter_SelectsSecondHunter(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           0, // First hunter
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectNext(params)

	if result.SelectedIndex != 1 {
		t.Errorf("Expected second hunter (index 1), got %d", result.SelectedIndex)
	}
}

func TestSelectNext_FromLastHunterOfProcessor_SelectsNextProcessor(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           1, // Last hunter of first processor
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectNext(params)

	if result.SelectedProcessorAddr != "proc2" {
		t.Errorf("Expected next processor 'proc2', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestSelectNext_FromLastProcessor_WrapsToNothing(t *testing.T) {
	processors := createTestProcessors(2, 0) // No hunters
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "proc2", // Last processor
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectNext(params)

	if result.SelectedProcessorAddr != "" {
		t.Errorf("Expected no selection, got processor '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestSelectPrevious_FromNothing_SelectsLastHunter(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectPrevious(params)

	// Should select last hunter of last processor (index 3)
	if result.SelectedIndex != 3 {
		t.Errorf("Expected last hunter (index 3), got %d", result.SelectedIndex)
	}
}

func TestSelectPrevious_FromFirstHunter_SelectsProcessor(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           0, // First hunter of first processor
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectPrevious(params)

	if result.SelectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
}

func TestSelectPrevious_FromProcessor_SelectsPreviousProcessorLastHunter(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "proc2", // Second processor
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectPrevious(params)

	// Should select last hunter of first processor (index 1)
	if result.SelectedIndex != 1 {
		t.Errorf("Expected hunter index 1, got %d", result.SelectedIndex)
	}
}

func TestSelectUp_FromHunter_SelectsParentProcessor(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           0, // First hunter
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectUp(params)

	if result.SelectedProcessorAddr != "proc1" {
		t.Errorf("Expected processor 'proc1', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
	// Should remember which hunter was selected
	if result.LastSelectedHunterIndex["proc1"] != 0 {
		t.Errorf("Expected to remember hunter index 0, got %d", result.LastSelectedHunterIndex["proc1"])
	}
}

func TestSelectDown_FromProcessor_SelectsFirstHunter(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           -1,
		SelectedProcessorAddr:   "proc1",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectDown(params)

	if result.SelectedIndex != 0 {
		t.Errorf("Expected first hunter (index 0), got %d", result.SelectedIndex)
	}
	if result.SelectedProcessorAddr != "" {
		t.Errorf("Expected no processor selected, got '%s'", result.SelectedProcessorAddr)
	}
}

func TestSelectDown_FromHunter_SelectsNextProcessor(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           0, // First hunter of first processor
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectDown(params)

	if result.SelectedProcessorAddr != "proc2" {
		t.Errorf("Expected processor 'proc2', got '%s'", result.SelectedProcessorAddr)
	}
	if result.SelectedIndex != -1 {
		t.Errorf("Expected SelectedIndex -1, got %d", result.SelectedIndex)
	}
	// Should remember which hunter was selected
	if result.LastSelectedHunterIndex["proc1"] != 0 {
		t.Errorf("Expected to remember hunter index 0, got %d", result.LastSelectedHunterIndex["proc1"])
	}
}

func TestSelectLeft_FromSecondHunter_SelectsFirstHunter(t *testing.T) {
	processors := createTestProcessors(1, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           1, // Second hunter
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectLeft(params)

	if result.SelectedIndex != 0 {
		t.Errorf("Expected first hunter (index 0), got %d", result.SelectedIndex)
	}
	if result.LastSelectedHunterIndex["proc1"] != 0 {
		t.Errorf("Expected to remember hunter index 0, got %d", result.LastSelectedHunterIndex["proc1"])
	}
}

func TestSelectRight_FromFirstHunter_SelectsSecondHunter(t *testing.T) {
	processors := createTestProcessors(1, 2)
	hunters := flattenHunters(processors)

	params := NavigationParams{
		Processors:              processors,
		Hunters:                 hunters,
		SelectedIndex:           0, // First hunter
		SelectedProcessorAddr:   "",
		LastSelectedHunterIndex: make(map[string]int),
	}

	result := SelectRight(params)

	if result.SelectedIndex != 1 {
		t.Errorf("Expected second hunter (index 1), got %d", result.SelectedIndex)
	}
	if result.LastSelectedHunterIndex["proc1"] != 1 {
		t.Errorf("Expected to remember hunter index 1, got %d", result.LastSelectedHunterIndex["proc1"])
	}
}

func TestGetGlobalHunterIndex_FindsCorrectIndex(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	// Find second hunter of second processor (should be index 3)
	index := GetGlobalHunterIndex(hunters, "B2", "proc2")

	if index != 3 {
		t.Errorf("Expected index 3, got %d", index)
	}
}

func TestGetGlobalHunterIndex_NotFound_ReturnsZero(t *testing.T) {
	processors := createTestProcessors(2, 2)
	hunters := flattenHunters(processors)

	index := GetGlobalHunterIndex(hunters, "nonexistent", "proc1")

	if index != 0 {
		t.Errorf("Expected index 0 for not found, got %d", index)
	}
}
