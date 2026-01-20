//go:build tui || all

package nodesview

import (
	"github.com/endorses/lippycat/internal/pkg/types"
)

// NavigationParams contains the current navigation state
type NavigationParams struct {
	Processors              []ProcessorInfo
	Hunters                 []types.HunterInfo
	SelectedIndex           int    // -1 means nothing selected, >= 0 means hunter is selected
	SelectedProcessorAddr   string // Non-empty means a processor is selected
	LastSelectedHunterIndex map[string]int
}

// NavigationResult contains the new navigation state after an operation
type NavigationResult struct {
	SelectedIndex           int
	SelectedProcessorAddr   string
	LastSelectedHunterIndex map[string]int
}

// SelectNext moves selection following tree structure: processor → its hunters → next processor → its hunters
func SelectNext(params NavigationParams) NavigationResult {
	// If nothing selected, move to first processor
	if params.SelectedIndex == -1 && params.SelectedProcessorAddr == "" {
		if len(params.Processors) > 0 {
			return NavigationResult{
				SelectedIndex:           -1,
				SelectedProcessorAddr:   params.Processors[0].Address,
				LastSelectedHunterIndex: params.LastSelectedHunterIndex,
			}
		}
		return NavigationResult{
			SelectedIndex:           -1,
			SelectedProcessorAddr:   "",
			LastSelectedHunterIndex: params.LastSelectedHunterIndex,
		}
	}

	// If a processor is selected, move to its first hunter or next processor
	if params.SelectedProcessorAddr != "" {
		// Find current processor
		var currentProc *ProcessorInfo
		currentProcIdx := -1
		for i, proc := range params.Processors {
			if proc.Address == params.SelectedProcessorAddr {
				currentProc = &params.Processors[i]
				currentProcIdx = i
				break
			}
		}

		if currentProc != nil && len(currentProc.Hunters) > 0 {
			// Move to first hunter of this processor
			newIndex := GetGlobalHunterIndex(params.Hunters, currentProc.Hunters[0].ID, currentProc.Hunters[0].ProcessorAddr)
			return NavigationResult{
				SelectedIndex:           newIndex,
				SelectedProcessorAddr:   "",
				LastSelectedHunterIndex: params.LastSelectedHunterIndex,
			}
		} else {
			// No hunters, move to next processor or wrap to nothing
			if currentProcIdx < len(params.Processors)-1 {
				return NavigationResult{
					SelectedIndex:           -1,
					SelectedProcessorAddr:   params.Processors[currentProcIdx+1].Address,
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			} else {
				// Last processor, wrap to nothing selected
				return NavigationResult{
					SelectedIndex:           -1,
					SelectedProcessorAddr:   "",
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
		}
	}

	// If a hunter is selected, move to next hunter of same processor or next processor
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and its position
		for procIdx, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					// Found the hunter, check if there's a next hunter in this processor
					if hunterIdx < len(proc.Hunters)-1 {
						// Move to next hunter in same processor
						newIndex := GetGlobalHunterIndex(params.Hunters, proc.Hunters[hunterIdx+1].ID, proc.Hunters[hunterIdx+1].ProcessorAddr)
						return NavigationResult{
							SelectedIndex:           newIndex,
							SelectedProcessorAddr:   "",
							LastSelectedHunterIndex: params.LastSelectedHunterIndex,
						}
					} else {
						// Last hunter of this processor, move to next processor or wrap to nothing
						if procIdx < len(params.Processors)-1 {
							return NavigationResult{
								SelectedIndex:           -1,
								SelectedProcessorAddr:   params.Processors[procIdx+1].Address,
								LastSelectedHunterIndex: params.LastSelectedHunterIndex,
							}
						} else {
							// Last processor, wrap to nothing selected
							return NavigationResult{
								SelectedIndex:           -1,
								SelectedProcessorAddr:   "",
								LastSelectedHunterIndex: params.LastSelectedHunterIndex,
							}
						}
					}
				}
			}
		}
	}

	// Fallback: no change
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// SelectPrevious moves selection following tree structure in reverse: hunters ← processor ← previous processor
func SelectPrevious(params NavigationParams) NavigationResult {
	// If nothing selected, wrap to last processor's last hunter (or last processor if no hunters)
	if params.SelectedIndex == -1 && params.SelectedProcessorAddr == "" {
		if len(params.Processors) > 0 {
			lastProc := params.Processors[len(params.Processors)-1]
			// If last processor has hunters, select its last hunter
			if len(lastProc.Hunters) > 0 {
				lastHunter := lastProc.Hunters[len(lastProc.Hunters)-1]
				newIndex := GetGlobalHunterIndex(params.Hunters, lastHunter.ID, lastHunter.ProcessorAddr)
				return NavigationResult{
					SelectedIndex:           newIndex,
					SelectedProcessorAddr:   "",
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
			// No hunters, select the processor itself
			return NavigationResult{
				SelectedIndex:           -1,
				SelectedProcessorAddr:   lastProc.Address,
				LastSelectedHunterIndex: params.LastSelectedHunterIndex,
			}
		}
		return NavigationResult{
			SelectedIndex:           -1,
			SelectedProcessorAddr:   "",
			LastSelectedHunterIndex: params.LastSelectedHunterIndex,
		}
	}

	// If a processor is selected, move to previous processor's last hunter or previous processor
	if params.SelectedProcessorAddr != "" {
		// Find current processor index
		currentProcIdx := -1
		for i, proc := range params.Processors {
			if proc.Address == params.SelectedProcessorAddr {
				currentProcIdx = i
				break
			}
		}

		if currentProcIdx > 0 {
			// Move to previous processor's last hunter (or the processor if no hunters)
			prevProc := params.Processors[currentProcIdx-1]
			if len(prevProc.Hunters) > 0 {
				lastHunter := prevProc.Hunters[len(prevProc.Hunters)-1]
				newIndex := GetGlobalHunterIndex(params.Hunters, lastHunter.ID, lastHunter.ProcessorAddr)
				return NavigationResult{
					SelectedIndex:           newIndex,
					SelectedProcessorAddr:   "",
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			} else {
				// Previous processor has no hunters, select it
				return NavigationResult{
					SelectedIndex:           -1,
					SelectedProcessorAddr:   prevProc.Address,
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
		} else {
			// First processor, wrap to nothing selected
			return NavigationResult{
				SelectedIndex:           -1,
				SelectedProcessorAddr:   "",
				LastSelectedHunterIndex: params.LastSelectedHunterIndex,
			}
		}
	}

	// If a hunter is selected, move to previous hunter or to processor
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and its position
		for _, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					if hunterIdx > 0 {
						// Move to previous hunter in same processor
						newIndex := GetGlobalHunterIndex(params.Hunters, proc.Hunters[hunterIdx-1].ID, proc.Hunters[hunterIdx-1].ProcessorAddr)
						return NavigationResult{
							SelectedIndex:           newIndex,
							SelectedProcessorAddr:   "",
							LastSelectedHunterIndex: params.LastSelectedHunterIndex,
						}
					} else {
						// First hunter of this processor, move to the processor itself
						return NavigationResult{
							SelectedIndex:           -1,
							SelectedProcessorAddr:   proc.Address,
							LastSelectedHunterIndex: params.LastSelectedHunterIndex,
						}
					}
				}
			}
		}
	}

	// Fallback: no change
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// SelectUp moves selection up in graph mode (vertical navigation through hierarchy)
func SelectUp(params NavigationParams) NavigationResult {
	// If nothing selected, do nothing
	if params.SelectedIndex == -1 && params.SelectedProcessorAddr == "" {
		return NavigationResult{
			SelectedIndex:           params.SelectedIndex,
			SelectedProcessorAddr:   params.SelectedProcessorAddr,
			LastSelectedHunterIndex: params.LastSelectedHunterIndex,
		}
	}

	// If a hunter is selected, move up to its parent processor
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and the hunter's local index
		for _, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					// Remember this hunter's position for this processor
					updatedLastSelected := make(map[string]int)
					for k, v := range params.LastSelectedHunterIndex {
						updatedLastSelected[k] = v
					}
					updatedLastSelected[proc.Address] = hunterIdx

					// Move to the parent processor
					return NavigationResult{
						SelectedIndex:           -1,
						SelectedProcessorAddr:   proc.Address,
						LastSelectedHunterIndex: updatedLastSelected,
					}
				}
			}
		}
	}

	// If a processor is selected, move up to the previous processor's last selected hunter (or the processor itself if no hunters)
	if params.SelectedProcessorAddr != "" {
		// Find current processor index
		currentProcIdx := -1
		for i, proc := range params.Processors {
			if proc.Address == params.SelectedProcessorAddr {
				currentProcIdx = i
				break
			}
		}

		if currentProcIdx > 0 {
			// Move to previous processor's hunters (using remembered index) or processor itself
			prevProc := params.Processors[currentProcIdx-1]
			if len(prevProc.Hunters) > 0 {
				// Check if we have a remembered hunter index for this processor
				hunterIdx, exists := params.LastSelectedHunterIndex[prevProc.Address]
				if !exists || hunterIdx >= len(prevProc.Hunters) {
					hunterIdx = 0 // Default to first hunter
				}
				newIndex := GetGlobalHunterIndex(params.Hunters, prevProc.Hunters[hunterIdx].ID, prevProc.Hunters[hunterIdx].ProcessorAddr)
				return NavigationResult{
					SelectedIndex:           newIndex,
					SelectedProcessorAddr:   "",
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			} else {
				// Previous processor has no hunters, select the processor itself
				return NavigationResult{
					SelectedIndex:           -1,
					SelectedProcessorAddr:   prevProc.Address,
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
		}
	}

	// Fallback: no change
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// SelectDown moves selection down in graph mode (vertical navigation through hierarchy)
func SelectDown(params NavigationParams) NavigationResult {
	// If nothing selected, select first processor
	if params.SelectedIndex == -1 && params.SelectedProcessorAddr == "" {
		if len(params.Processors) > 0 {
			return NavigationResult{
				SelectedIndex:           -1,
				SelectedProcessorAddr:   params.Processors[0].Address,
				LastSelectedHunterIndex: params.LastSelectedHunterIndex,
			}
		}
		return NavigationResult{
			SelectedIndex:           -1,
			SelectedProcessorAddr:   "",
			LastSelectedHunterIndex: params.LastSelectedHunterIndex,
		}
	}

	// If a processor is selected, move down to its hunters (using remembered index) or next processor
	if params.SelectedProcessorAddr != "" {
		// Find current processor
		currentProcIdx := -1
		var currentProc *ProcessorInfo
		for i, proc := range params.Processors {
			if proc.Address == params.SelectedProcessorAddr {
				currentProcIdx = i
				currentProc = &params.Processors[i]
				break
			}
		}

		if currentProc != nil {
			if len(currentProc.Hunters) > 0 {
				// Move to remembered hunter (or first hunter if not remembered)
				hunterIdx, exists := params.LastSelectedHunterIndex[currentProc.Address]
				if !exists || hunterIdx >= len(currentProc.Hunters) {
					hunterIdx = 0 // Default to first hunter
				}
				newIndex := GetGlobalHunterIndex(params.Hunters, currentProc.Hunters[hunterIdx].ID, currentProc.Hunters[hunterIdx].ProcessorAddr)
				return NavigationResult{
					SelectedIndex:           newIndex,
					SelectedProcessorAddr:   "",
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
			// Current processor has no hunters, move to next processor
			if currentProcIdx < len(params.Processors)-1 {
				return NavigationResult{
					SelectedIndex:           -1,
					SelectedProcessorAddr:   params.Processors[currentProcIdx+1].Address,
					LastSelectedHunterIndex: params.LastSelectedHunterIndex,
				}
			}
		}
	}

	// If a hunter is selected, move down to next processor
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and save the hunter's position
		for procIdx, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					// Remember this hunter's position
					updatedLastSelected := make(map[string]int)
					for k, v := range params.LastSelectedHunterIndex {
						updatedLastSelected[k] = v
					}
					updatedLastSelected[proc.Address] = hunterIdx

					// Move to next processor
					if procIdx < len(params.Processors)-1 {
						return NavigationResult{
							SelectedIndex:           -1,
							SelectedProcessorAddr:   params.Processors[procIdx+1].Address,
							LastSelectedHunterIndex: updatedLastSelected,
						}
					}
					return NavigationResult{
						SelectedIndex:           params.SelectedIndex,
						SelectedProcessorAddr:   params.SelectedProcessorAddr,
						LastSelectedHunterIndex: updatedLastSelected,
					}
				}
			}
		}
	}

	// Fallback: no change
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// SelectLeft moves selection left in graph mode (horizontal navigation within same processor)
func SelectLeft(params NavigationParams) NavigationResult {
	// Only works on hunters (horizontal navigation between hunters of same processor)
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and its position
		for _, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					if hunterIdx > 0 {
						// Move to previous hunter in same processor
						newHunterIdx := hunterIdx - 1
						newIndex := GetGlobalHunterIndex(params.Hunters, proc.Hunters[newHunterIdx].ID, proc.Hunters[newHunterIdx].ProcessorAddr)

						// Remember this new position
						updatedLastSelected := make(map[string]int)
						for k, v := range params.LastSelectedHunterIndex {
							updatedLastSelected[k] = v
						}
						updatedLastSelected[proc.Address] = newHunterIdx

						return NavigationResult{
							SelectedIndex:           newIndex,
							SelectedProcessorAddr:   "",
							LastSelectedHunterIndex: updatedLastSelected,
						}
					}
					return NavigationResult{
						SelectedIndex:           params.SelectedIndex,
						SelectedProcessorAddr:   params.SelectedProcessorAddr,
						LastSelectedHunterIndex: params.LastSelectedHunterIndex,
					}
				}
			}
		}
	}

	// Do nothing for processors or empty selection
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// SelectRight moves selection right in graph mode (horizontal navigation within same processor)
func SelectRight(params NavigationParams) NavigationResult {
	// Only works on hunters (horizontal navigation between hunters of same processor)
	if params.SelectedIndex >= 0 && params.SelectedIndex < len(params.Hunters) {
		currentHunter := params.Hunters[params.SelectedIndex]

		// Find which processor this hunter belongs to and its position
		for _, proc := range params.Processors {
			for hunterIdx, hunter := range proc.Hunters {
				if hunter.ID == currentHunter.ID && hunter.ProcessorAddr == currentHunter.ProcessorAddr {
					if hunterIdx < len(proc.Hunters)-1 {
						// Move to next hunter in same processor
						newHunterIdx := hunterIdx + 1
						newIndex := GetGlobalHunterIndex(params.Hunters, proc.Hunters[newHunterIdx].ID, proc.Hunters[newHunterIdx].ProcessorAddr)

						// Remember this new position
						updatedLastSelected := make(map[string]int)
						for k, v := range params.LastSelectedHunterIndex {
							updatedLastSelected[k] = v
						}
						updatedLastSelected[proc.Address] = newHunterIdx

						return NavigationResult{
							SelectedIndex:           newIndex,
							SelectedProcessorAddr:   "",
							LastSelectedHunterIndex: updatedLastSelected,
						}
					}
					return NavigationResult{
						SelectedIndex:           params.SelectedIndex,
						SelectedProcessorAddr:   params.SelectedProcessorAddr,
						LastSelectedHunterIndex: params.LastSelectedHunterIndex,
					}
				}
			}
		}
	}

	// Do nothing for processors or empty selection
	return NavigationResult{
		SelectedIndex:           params.SelectedIndex,
		SelectedProcessorAddr:   params.SelectedProcessorAddr,
		LastSelectedHunterIndex: params.LastSelectedHunterIndex,
	}
}

// GetGlobalHunterIndex finds the global index of a hunter by ID and processor address
func GetGlobalHunterIndex(hunters []types.HunterInfo, hunterID string, processorAddr string) int {
	for i, hunter := range hunters {
		if hunter.ID == hunterID && hunter.ProcessorAddr == processorAddr {
			return i
		}
	}
	return 0
}
